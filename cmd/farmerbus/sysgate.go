package main

// The single-node gate: a bus node without a cluster serves no client
// before its account loader has loaded the SYS Account JWT (security
// review 2026-10, L14). FLAG FOR SECURITY REVIEW.
//
// The node starts with nothing but the trust's bootstrap SYS Account JWT
// (pki.LoadBusNats), which carries none of the revocations core has since
// put on the SYS account, for example a rotated-out SaaS API key. A
// clustered node is held back by its fence (fence.go) until it has synced
// from its peers; a single node has no peers, so until this gate opens it
// refuses every TLS handshake on the client port that does not come from
// the loopback address (its own pod: the account loader sidecar, which
// dials 127.0.0.1) and every websocket handshake, and /readyz reports 503.
//
// The gate opens once the loader's /readyz answers 200: the loader is
// ready only once the node holds every Account in the accounts bucket,
// the SYS account first among them (internal/accountloader's loadOnce).
// It stays open after that: the loader's readiness is the end of its
// initial load, and every later change reaches the node from the loader
// or core as it happens.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	nats_server "github.com/nats-io/nats-server/v2/server"

	log "github.com/yogzblr/imas/internal/log"
)

// envLoaderReadyURL is the account loader's readiness endpoint, on the
// loopback address: http://127.0.0.1:<loader health port>/readyz.
// Required for a single-node bus.
const envLoaderReadyURL = "IMAS_BUS_LOADER_READY_URL"

// errNoSysReady is a single-node bus started with no way to tell that its
// SYS Account JWT is loaded.
var errNoSysReady = fmt.Errorf("farmerbus: a single-node bus needs %s, its account loader's /readyz on the loopback address (http://127.0.0.1:<port>/readyz): it serves no client before the loader has loaded the SYS account", envLoaderReadyURL)

// errSysNotLoaded is the handshake error while the gate is closed.
var errSysNotLoaded = errors.New("farmerbus: the SYS account is not loaded yet; try again")

// loaderReadyProbe returns a check that is true while the account loader
// at rawURL reports ready. The URL must be plain http on a loopback IP:
// the loader is in this pod, and nothing else may open the gate.
func loaderReadyProbe(rawURL string) (func() bool, error) {
	if rawURL == "" {
		return nil, errNoSysReady
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("farmerbus: %s=%q: %v", envLoaderReadyURL, rawURL, err)
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.Port() == "" || u.User != nil {
		return nil, fmt.Errorf("farmerbus: %s=%q: want http://127.0.0.1:<port>/readyz (plain http, a loopback IP and a port)", envLoaderReadyURL, rawURL)
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	target := u.String()
	return func() bool {
		resp, err := client.Get(target)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, nil
}

// isLoopbackAddr reports whether addr is a loopback TCP address.
func isLoopbackAddr(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

type sysGate struct {
	ready    func() bool
	isLocal  func(net.Addr) bool
	interval time.Duration

	open     atomic.Bool
	started  atomic.Bool
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// newSysGate returns a closed gate that polls ready every interval;
// isLocal nil means isLoopbackAddr.
func newSysGate(ready func() bool, isLocal func(net.Addr) bool, interval time.Duration) *sysGate {
	if isLocal == nil {
		isLocal = isLoopbackAddr
	}
	return &sysGate{ready: ready, isLocal: isLocal, interval: interval, stopCh: make(chan struct{}), doneCh: make(chan struct{})}
}

// Open reports whether the gate admits every client.
func (g *sysGate) Open() bool { return g.open.Load() }

// install wires the gate into the client and websocket listeners' TLS.
// Call before nats_server.NewServer. On the client port it is
// GetConfigForClient, which sees the peer's address; nats-server leaves
// that hook to its caller there. On the websocket port, where
// nats-server sets GetConfigForClient itself, it is VerifyConnection, and
// it refuses every handshake while closed: only Envoy uses that port.
func (g *sysGate) install(opts *nats_server.Options) error {
	if opts.TLSConfig == nil {
		return errors.New("sysgate: the client port has no TLS config")
	}
	prev := opts.TLSConfig.GetConfigForClient
	opts.TLSConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if !g.open.Load() && (hello.Conn == nil || !g.isLocal(hello.Conn.RemoteAddr())) {
			return nil, errSysNotLoaded
		}
		if prev != nil {
			return prev(hello)
		}
		return nil, nil
	}
	if opts.Websocket.TLSConfig != nil {
		next := opts.Websocket.TLSConfig.VerifyConnection
		opts.Websocket.TLSConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if !g.open.Load() {
				return errSysNotLoaded
			}
			if next != nil {
				return next(cs)
			}
			return nil
		}
	}
	return nil
}

// start polls ready until it is true, then opens the gate for good.
func (g *sysGate) start() {
	g.started.Store(true)
	log.Infof("farmerbus: refusing clients other than the account loader until it has loaded the SYS account")
	go func() {
		defer close(g.doneCh)
		t := time.NewTicker(g.interval)
		defer t.Stop()
		for {
			if g.ready() {
				g.open.Store(true)
				log.Infof("farmerbus: the account loader has loaded the SYS account; accepting clients")
				return
			}
			select {
			case <-g.stopCh:
				return
			case <-t.C:
			}
		}
	}()
}

func (g *sysGate) stop() {
	g.stopOnce.Do(func() {
		close(g.stopCh)
		if g.started.Load() {
			<-g.doneCh
		}
	})
}
