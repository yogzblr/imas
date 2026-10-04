// Command farmerbus is imas's NATS bus process: the half of what used to be
// a single "farmer" binary that's meant to run in the DMZ (see
// docs/design/imas-fork-roadmap.md workstream C). It embeds nothing but the
// NATS server itself — no PXC, no object storage, no API server, no
// sprout-facing business logic — so that a compromise of this process
// (the one directly reachable from sprouts on the public side of the
// network) exposes as little as possible. The core process (cmd/farmer)
// dials this bus outbound, like any other NATS client, from a non-DMZ
// network segment; it never needs a connection back into the DMZ.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/certs"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"

	nats_server "github.com/nats-io/nats-server/v2/server"
)

// envHealthPort, when set, starts the /healthz and /readyz probe listener.
const envHealthPort = "IMAS_BUS_HEALTH_PORT"

var (
	// srvMu guards the s package global, read by the shutdown path in main
	// and written/read by handleSIGHUP concurrently.
	srvMu     sync.Mutex
	s         *nats_server.Server
	GitCommit string
	Tag       string
)

func setNATSServer(v *nats_server.Server) {
	srvMu.Lock()
	s = v
	srvMu.Unlock()
}

func getNATSServer() *nats_server.Server {
	srvMu.Lock()
	defer srvMu.Unlock()
	return s
}

func main() {
	// Config is loaded here, not in an init(): LoadConfig creates
	// /etc/imas, which a package test (run unprivileged) can't do.
	config.LoadConfig("farmer")
	log.SetLogLevel(config.LogLevel)
	fmt.Printf("Starting Farmer Bus on %s:%s\n", config.FarmerInterface, config.FarmerBusPort)
	defer log.Flush()
	pki.SetupPKIFarmer()
	if err := certs.GenCert(); err != nil {
		log.Fatalf("failed to generate TLS certificates: %v", err)
	}
	RunNATSServer()

	// ctx is cancelled on SIGINT/SIGTERM, driving a graceful shutdown of
	// the NATS server.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if hp := os.Getenv(envHealthPort); hp != "" {
		addr := net.JoinHostPort(config.FarmerInterface, hp)
		if err := serveHealth(ctx, addr, getBusNode().Ready); err != nil {
			log.Fatalf("failed to start the health listener on %s: %v", addr, err)
		}
	}
	sighupDone := make(chan struct{})
	go handleSIGHUP(ctx, sighupDone)

	<-ctx.Done()
	stop()
	log.Info("Shutdown signal received, stopping bus...")
	// Stop the SIGHUP handler first so it can't reload concurrently with
	// the shutdown below (bounded, with a warning).
	select {
	case <-sighupDone:
	case <-time.After(20 * time.Second):
		log.Warn("timed out waiting for SIGHUP handler to stop")
	}
	if node := getBusNode(); node != nil {
		node.Shutdown()
	}
	log.Info("Farmer bus stopped")
}

// RunNATSServer starts the embedded NATS server that is this binary's
// entire job. Unlike the pre-split cmd/farmer/main.go, it does not call
// pki.ReloadNKeys(): that call's push (see internal/pki/resolver.go)
// recomputes sprout User JWTs and the tenant Account's revocation list from
// PXC-backed accept/deny/reject state — state this DMZ-side process has no
// business holding a database connection to.
//
// pki.ConfigureBusNats seeds the resolver with nothing but a SYS bootstrap
// Account JWT that any SYS Account JWT core signs outranks; the bus mints
// no tenant Account (internal/pki/busauth.go). It learns every Account
// from core, which pushes them all whenever its SYS connection connects
// or reconnects and pushes each change as it happens, over the network to
// $SYS.REQ.CLAIMS.UPDATE; a clustered node also pulls them from its peers
// (fence.go). No restart or local reload is needed on this side for an
// ACL change.
func RunNATSServer() {
	opts, sysUser := pki.ConfigureBusNats()
	cl, err := clusterConfigFromEnv(os.Getenv, os.ReadFile)
	if err != nil {
		log.Fatalf("invalid bus cluster configuration: %v", err)
	}
	node, err := startBus(opts, sysUser, cl, defaultFenceTiming)
	if err != nil {
		log.Panicf("Unable to start NATS Server: %v", err)
	}
	setNATSServer(node.srv)
	setBusNode(node)
	pki.SetNATSServer(node.srv)
	if cl != nil {
		log.Infof("NATS bus started as node %q of cluster %q (%d nodes); clients are refused until the fence lifts", cl.ServerName, cl.Name, cl.Size())
	} else {
		log.Info("NATS bus started")
	}
}

// busNode is one running bus: the server and, when clustered, its fence.
type busNode struct {
	srv   *nats_server.Server
	fence *fence
}

// Ready reports whether the node should receive client traffic.
func (n *busNode) Ready() bool {
	if n == nil || n.srv == nil || !n.srv.Running() {
		return false
	}
	return n.fence == nil || !n.fence.Fenced()
}

// Shutdown stops the fence, then the server.
func (n *busNode) Shutdown() {
	if n.fence != nil {
		n.fence.stop()
	}
	n.srv.Shutdown()
}

var (
	nodeMu  sync.Mutex
	curNode *busNode
)

func setBusNode(n *busNode) { nodeMu.Lock(); curNode = n; nodeMu.Unlock() }
func getBusNode() *busNode  { nodeMu.Lock(); defer nodeMu.Unlock(); return curNode }

// startBus starts the embedded server from opts (pki.ConfigureBusNats's
// output). With cl non-nil it adds authenticated routes (cluster.go) and a
// fence (fence.go) that keeps clients out until this node has quorum and
// has synced its resolver from its peers.
func startBus(opts nats_server.Options, sysUser pki.BusSysUser, cl *clusterConfig, timing fenceTiming) (*busNode, error) {
	var f *fence
	if cl != nil {
		if err := applyCluster(&opts, cl); err != nil {
			return nil, err
		}
		f = newFence(cl.Size(), timing)
		if err := f.install(&opts); err != nil {
			return nil, err
		}
	}
	srv, err := nats_server.NewServer(&opts)
	if err != nil || srv == nil {
		return nil, fmt.Errorf("no NATS Server object returned: %v", err)
	}
	var natsLogger log.Logger
	srv.SetLogger(natsLogger, true, true)
	go srv.Start()
	// Wait for accept loop(s) to be started
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		return nil, errors.New("NATS server did not start listening")
	}
	if f != nil {
		if err := f.start(srv, sysUser); err != nil {
			srv.Shutdown()
			return nil, err
		}
	}
	return &busNode{srv: srv, fence: f}, nil
}

// handleSIGHUP reloads the NATS server's configuration (picking up rotated
// TLS certificates) on SIGHUP. Auth/ACL changes don't need this: they
// arrive live over the network from the core process's ReloadNKeys push
// (see resolver.go) — the entire point of the decentralized JWT model's
// resolver-push mechanism is that this process never needs to be told to
// reload for that.
func handleSIGHUP(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
		}
		// Re-check cancellation: the select above may have chosen the sighup
		// case even though shutdown was also requested.
		if ctx.Err() != nil {
			return
		}
		log.Info("Received SIGHUP, reloading NATS bus configuration...")
		if srv := getNATSServer(); srv != nil {
			if err := srv.Reload(); err != nil {
				log.Errorf("Failed to reload NATS server: %v", err)
			} else {
				log.Info("NATS server reloaded successfully")
			}
		}
	}
}
