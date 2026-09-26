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
	"fmt"
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

func init() {
	config.LoadConfig("farmer")
	log.SetLogLevel(config.LogLevel)
}

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
	config.LoadConfig("farmer")
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
	if srv := getNATSServer(); srv != nil {
		srv.Shutdown()
	}
	log.Info("Farmer bus stopped")
}

// RunNATSServer starts the embedded NATS server that is this binary's
// entire job. Unlike the pre-split cmd/farmer/main.go, it does not call
// pki.ReloadNKeys(): that call's push (see internal/pki/resolver.go)
// recomputes sprout User JWTs and the tenant Account's revocation list from
// PXC-backed accept/deny/reject state — state this DMZ-side process has no
// business holding a database connection to. pki.ConfigureNats() seeds the
// resolver directly from whatever Account JWTs already exist on disk (or
// bootstraps a fresh trust chain, on first boot); from then on, the core
// process (cmd/farmer) is what keeps that state current here, over the
// network, via its own ReloadNKeys push to $SYS.REQ.CLAIMS.UPDATE — no
// restart or local reload needed on this side for an ACL change.
func RunNATSServer() {
	opts := pki.ConfigureNats()
	srv, err := nats_server.NewServer(&opts)
	if err != nil || srv == nil {
		log.Panicf("No NATS Server object returned: %v", err)
	}
	// Run server in Go routine.
	go srv.Start()
	var natsLogger log.Logger
	srv.SetLogger(natsLogger, true, true)
	// Wait for accept loop(s) to be started
	if !srv.ReadyForConnections(10 * time.Second) {
		log.Panicf("Unable to start NATS Server")
	}
	setNATSServer(srv)
	pki.SetNATSServer(srv)
	log.Info("NATS bus started")
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
