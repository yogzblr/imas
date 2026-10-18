package main

// The simulated sprouts. Each one is a nats.go connection made the way
// cmd/sprout's ConnectSprout makes it (pinned-CA TLS, User JWT and NKey
// seed, enrolled addresses so discovered servers are ignored, unlimited
// reconnects with internal/natsretry's full-jitter backoff), and once
// connected does what natsInit does on the bus: announces itself,
// publishes its facts, and subscribes to the same seven subjects; and,
// as startHeartbeat does, publishes its heartbeat at connect and then
// every heartbeat interval.
//
// Only test.ping and facts.request are answered (test.ping with the
// sprout's own handler, internal/ingredients/test.SPing; facts.request
// with the sprout's facts, sealed as at connect). The other
// subscriptions exist so that the bus carries the same interest per
// connection as for a real sprout; a message on them is counted and
// dropped.
//
// To fit tens of thousands of connections in one process, subscriptions
// deliver into one shared channel (ChanSubscribe) drained by a small
// worker pool, instead of one goroutine per subscription as a callback
// subscription would start. A real sprout has its own process per host.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/natsretry"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// sproutSubjects are the subjects cmd/sprout's natsInit subscribes to
// for sprout id, in its order.
func sproutSubjects(id string) []string {
	return []string{
		"imas.sprouts." + id + ".facts.request",
		"imas.sprouts." + id + ".cmd.run",
		"imas.sprouts." + id + ".test.ping",
		cook.CookSubject(id),
		cook.NudgeSubject(id),
		"imas.sprouts." + id + ".boxkey.rotate",
		"imas.sprouts." + id + ".shell.start",
	}
}

// pingSubject is the lightest subject a sprout registers: test.ping.
func pingSubject(id string) string { return "imas.sprouts." + id + ".test.ping" }

type fleetOptions struct {
	Servers        []string
	TLS            *tls.Config
	ReconnectBase  time.Duration
	ReconnectCap   time.Duration
	ConnectTimeout time.Duration
	SourceIPs      []net.IP
	// Facts is published once per sprout at connect, sealed (its
	// SproutID set to the sprout's), and answers facts.request; nil
	// publishes none.
	Facts   *facts.SystemFacts
	Workers int
	// HeartbeatInterval is how often each sprout publishes its heartbeat
	// (pki.SproutHeartbeatSubject, body heartbeat.ConnID), as
	// heartbeat.RunSprout does every heartbeat.Interval; 0 sends none.
	HeartbeatInterval time.Duration
}

// fleet is every simulated sprout of one generator.
type fleet struct {
	opts    fleetOptions
	creds   []sproutCred
	backoff *natsretry.Backoff
	msgs    chan *nats.Msg

	mu    sync.Mutex
	conns []*nats.Conn

	idxOnce sync.Once
	byID    map[string]int

	live      []atomic.Bool
	liveCount atomic.Int64

	// Connect phase.
	connectOK     atomic.Int64
	connectFailed atomic.Int64
	reasonsMu     sync.Mutex
	reasons       map[string]int
	connectSeries *series

	// Disconnect and reconnect events, at any time.
	disconnects       atomic.Int64
	reconnects        atomic.Int64
	firstDisconnectNS atomic.Int64
	lastReconnectNS   atomic.Int64
	reconnectSeries   *series
	attemptSeries     *series

	// Messages handled.
	pings, factsReqs, inert, slowConsumers atomic.Int64
	// Facts sealed: how many, their plaintext and sealed bytes, and the
	// time spent sealing (factsCost).
	factsSealed, factsPlainBytes, factsSealedBytes, factsSealNanos atomic.Int64
	// Heartbeats published, and publishes that failed.
	heartbeats, heartbeatErrors atomic.Int64
}

func newFleet(creds []sproutCred, opts fleetOptions) *fleet {
	if opts.Workers <= 0 {
		opts.Workers = 4 * runtime.GOMAXPROCS(0)
	}
	return &fleet{
		opts:            opts,
		creds:           creds,
		backoff:         natsretry.New(opts.ReconnectBase, opts.ReconnectCap, nil),
		msgs:            make(chan *nats.Msg, 64*1024),
		conns:           make([]*nats.Conn, len(creds)),
		live:            make([]atomic.Bool, len(creds)),
		reasons:         map[string]int{},
		connectSeries:   newSeries(),
		reconnectSeries: newSeries(),
		attemptSeries:   newSeries(),
	}
}

// startWorkers answers sprout-bound messages until ctx is done.
func (f *fleet) startWorkers(ctx context.Context) {
	for range f.opts.Workers {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case m := <-f.msgs:
					f.handle(m)
				}
			}
		}()
	}
}

func (f *fleet) handle(m *nats.Msg) {
	switch {
	case strings.HasSuffix(m.Subject, ".test.ping"):
		// cmd/sprout's test.ping handler.
		var ping apitypes.PingPong
		_ = json.NewDecoder(bytes.NewBuffer(m.Data)).Decode(&ping)
		pong, _ := test.SPing(ping)
		b, _ := json.Marshal(pong)
		_ = m.Respond(b)
		f.pings.Add(1)
	case strings.HasSuffix(m.Subject, ".facts.request"):
		id := strings.TrimSuffix(strings.TrimPrefix(m.Subject, "imas.sprouts."), ".facts.request")
		if c, ok := f.credByID(id); ok && f.opts.Facts != nil {
			if data, err := f.sealFacts(c); err == nil {
				r := nats.NewMsg(m.Reply)
				r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
				r.Data = data
				_ = m.RespondMsg(r)
			}
		}
		f.factsReqs.Add(1)
	default:
		f.inert.Add(1)
	}
}

// sealFacts seals the fleet's facts as c's report, the way cmd/sprout's
// sealedFactsMsg does, and counts what it cost (factsCost).
func (f *fleet) sealFacts(c sproutCred) ([]byte, error) {
	if c.Box.Priv == nil || c.Box.TenantPub == nil {
		return nil, fmt.Errorf("sprout %s has no box key to seal its facts with", c.ID)
	}
	sf := *f.opts.Facts
	sf.SproutID = c.ID
	start := time.Now()
	plain, err := json.Marshal(sf)
	if err != nil {
		return nil, err
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeFacts, c.Box.TenantID, c.ID, "", json.RawMessage(plain))
	if err != nil {
		return nil, err
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: c.Box.TenantPub, Priv: c.Box.Priv}})
	if err != nil {
		return nil, err
	}
	f.factsSealNanos.Add(int64(time.Since(start)))
	f.factsSealed.Add(1)
	f.factsPlainBytes.Add(int64(len(plain)))
	f.factsSealedBytes.Add(int64(len(data)))
	return data, nil
}

// credByID finds sprout id's credentials.
func (f *fleet) credByID(id string) (sproutCred, bool) {
	f.idxOnce.Do(func() {
		f.byID = make(map[string]int, len(f.creds))
		for i, c := range f.creds {
			f.byID[c.ID] = i
		}
	})
	i, ok := f.byID[id]
	if !ok {
		return sproutCred{}, false
	}
	return f.creds[i], true
}

// factsCost is what sealing the fleet's facts cost, per message.
func (f *fleet) factsCost() *factsResult {
	n := f.factsSealed.Load()
	if n == 0 {
		return nil
	}
	plain, sealed := f.factsPlainBytes.Load()/n, f.factsSealedBytes.Load()/n
	return &factsResult{
		Messages: n, PlainBytes: plain, SealedBytes: sealed, OverheadBytes: sealed - plain,
		SealMicros: float64(f.factsSealNanos.Load()) / float64(n) / 1e3,
	}
}

func (f *fleet) setLive(i int, v bool) {
	if f.live[i].Swap(v) != v {
		if v {
			f.liveCount.Add(1)
		} else {
			f.liveCount.Add(-1)
		}
	}
}

// Live is the number of sprouts connected now.
func (f *fleet) Live() int { return int(f.liveCount.Load()) }

// randomLive returns the index of a connected sprout, or -1 if it found
// none in a few tries.
func (f *fleet) randomLive() int {
	for range 16 {
		i := rand.IntN(len(f.creds))
		if f.live[i].Load() {
			return i
		}
	}
	return -1
}

// conn is sprout i's connection, nil before its first connect.
func (f *fleet) conn(i int) *nats.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns[i]
}

func (f *fleet) natsOptions(i int) []nats.Option {
	c := f.creds[i]
	opts := []nats.Option{
		// pki.LoadSproutBus.
		nats.Secure(f.opts.TLS),
		nats.UserJWTAndSeed(c.JWT, c.Seed),
		nats.IgnoreDiscoveredServers(),
		// cmd/sprout's ConnectSprout.
		nats.MaxReconnects(-1),
		nats.CustomReconnectDelay(func(attempt int) time.Duration {
			f.attemptSeries.Add(time.Now(), 1)
			return f.backoff.Delay(attempt)
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, _ error) {
			now := time.Now().UnixNano()
			f.firstDisconnectNS.CompareAndSwap(0, now)
			f.disconnects.Add(1)
			f.setLive(i, false)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			now := time.Now()
			f.reconnects.Add(1)
			f.lastReconnectNS.Store(now.UnixNano())
			f.reconnectSeries.Add(now, 1)
			f.setLive(i, true)
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrSlowConsumer) {
				f.slowConsumers.Add(1)
			}
		}),
		nats.Timeout(f.opts.ConnectTimeout),
	}
	if c.Gateway != "" {
		// pki.LoadSproutBus: over wss:// (Envoy) the gateway JWT goes as
		// a bearer token on every websocket handshake. Envoy refuses a
		// reconnect once it has expired; the harness does not refresh it.
		h := http.Header{"Authorization": []string{"Bearer " + c.Gateway}}
		opts = append(opts, nats.WebSocketConnectionHeaders(h))
	}
	if len(f.opts.SourceIPs) > 0 {
		ip := f.opts.SourceIPs[i%len(f.opts.SourceIPs)]
		opts = append(opts, nats.SetCustomDialer(&net.Dialer{
			Timeout:   f.opts.ConnectTimeout,
			LocalAddr: &net.TCPAddr{IP: ip},
		}))
	}
	return opts
}

// connectOne makes sprout i's first connection and does natsInit's bus
// work on it.
func (f *fleet) connectOne(i int) error {
	nc, err := nats.Connect(strings.Join(f.opts.Servers, ","), f.natsOptions(i)...)
	if err != nil {
		return err
	}
	id := f.creds[i].ID
	for _, subj := range sproutSubjects(id) {
		if _, err := nc.ChanSubscribe(subj, f.msgs); err != nil {
			nc.Close()
			return fmt.Errorf("subscribing to %s: %w", subj, err)
		}
	}
	startup := config.Startup{SproutID: id}
	startup.Version.Arch = runtime.GOARCH
	startup.Version.Compiler = runtime.Version()
	startup.Version.Tag = "loadtest"
	b, _ := json.Marshal(startup)
	if err := nc.Publish("imas.sprouts.announce."+id, b); err != nil {
		nc.Close()
		return err
	}
	if f.opts.Facts != nil {
		data, err := f.sealFacts(f.creds[i])
		if err != nil {
			nc.Close()
			return err
		}
		m := nats.NewMsg("imas.sprouts." + id + ".facts")
		m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		m.Data = data
		if err := nc.PublishMsg(m); err != nil {
			nc.Close()
			return err
		}
	}
	// RunSprout's first heartbeat, at connect.
	if f.opts.HeartbeatInterval > 0 {
		if err := f.beat(nc, id); err != nil {
			nc.Close()
			return err
		}
	}
	// Surface a permissions violation now rather than as a silent drop.
	if err := nc.FlushTimeout(f.opts.ConnectTimeout); err != nil {
		nc.Close()
		return err
	}
	if err := nc.LastError(); err != nil {
		nc.Close()
		return err
	}
	f.mu.Lock()
	f.conns[i] = nc
	f.mu.Unlock()
	f.setLive(i, true)
	return nil
}

// beat publishes sprout id's heartbeat on nc, the way heartbeat.RunSprout
// does: its own subject, the connection's ID as the body.
func (f *fleet) beat(nc *nats.Conn, id string) error {
	var body []byte
	if cid, err := nc.GetClientID(); err == nil {
		body = []byte(heartbeat.ConnID(nc.ConnectedServerId(), cid))
	}
	if err := nc.Publish(pki.SproutHeartbeatSubject(id), body); err != nil {
		f.heartbeatErrors.Add(1)
		return err
	}
	f.heartbeats.Add(1)
	return nil
}

// heartbeatTick is how often startHeartbeats wakes to publish the next
// share of the fleet's heartbeats.
const heartbeatTick = 100 * time.Millisecond

// startHeartbeats publishes every connected sprout's heartbeat once per
// HeartbeatInterval until ctx is done, spread evenly over the interval
// (each tick takes the heartbeats now due, round robin), so the bus
// sees the steady rate a fleet that connected over time produces, not a
// burst per interval. One goroutine for the fleet, not one per sprout,
// for the reason the subscriptions share a channel. A sprout that is
// disconnected is skipped, as RunSprout skips a tick; its reconnect is a
// CONNECT for farmer. It does nothing when HeartbeatInterval is 0.
func (f *fleet) startHeartbeats(ctx context.Context) {
	if f.opts.HeartbeatInterval <= 0 || len(f.creds) == 0 {
		return
	}
	tick := min(heartbeatTick, f.opts.HeartbeatInterval)
	// The fleet's heartbeats per nanosecond: each sprout once per interval.
	rate := float64(len(f.creds)) / float64(f.opts.HeartbeatInterval)
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		start := time.Now()
		next := 0
		var sent int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			// Publish what is due since start and not yet sent, so the
			// rate holds whatever the fleet size (no per-tick minimum)
			// and a tick the ticker dropped is made up on the next.
			due := int64(rate * float64(time.Since(start)))
			for ; sent < due; sent++ {
				i := next
				next = (next + 1) % len(f.creds)
				if !f.live[i].Load() {
					continue
				}
				if nc := f.conn(i); nc != nil {
					_ = f.beat(nc, f.creds[i].ID)
				}
			}
		}
	}()
}

// connectResult is what the connect phase measured.
type connectResult struct {
	Target         int            `json:"target"`
	Connected      int            `json:"connected"`
	FailedAttempts int            `json:"failed_attempts"`
	NotConnected   int            `json:"not_connected"`
	Reasons        map[string]int `json:"failure_reasons,omitempty"`
	Seconds        float64        `json:"seconds"`
	RatePerSec     float64        `json:"rate_per_sec"`
	PeakPerSec     int            `json:"peak_per_sec"`
	Series         *series        `json:"series"`
}

// connectAll opens every sprout's connection, paced at rate per second
// (0: as fast as workers allow), retrying a failed sprout up to retries
// more times after the natsretry delay a real sprout would wait.
func (f *fleet) connectAll(ctx context.Context, rate float64, workers, retries int) connectResult {
	n := len(f.creds)
	jobs := make(chan int)
	start := time.Now()
	var lastOK atomic.Int64
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				for attempt := 1; ; attempt++ {
					err := f.connectOne(i)
					if err == nil {
						now := time.Now()
						f.connectOK.Add(1)
						f.connectSeries.Add(now, 1)
						lastOK.Store(now.UnixNano())
						break
					}
					f.connectFailed.Add(1)
					f.recordReason(err)
					if attempt > retries || ctx.Err() != nil {
						break
					}
					select {
					case <-ctx.Done():
					case <-time.After(f.backoff.Delay(attempt)):
					}
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		if rate > 0 {
			if d := time.Until(start.Add(time.Duration(float64(i) / rate * float64(time.Second)))); d > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(d):
				}
			}
		}
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	res := connectResult{
		Target:         n,
		Connected:      int(f.connectOK.Load()),
		FailedAttempts: int(f.connectFailed.Load()),
		Series:         f.connectSeries,
	}
	res.NotConnected = n - res.Connected
	f.reasonsMu.Lock()
	if len(f.reasons) > 0 {
		res.Reasons = map[string]int{}
		for k, v := range f.reasons {
			res.Reasons[k] = v
		}
	}
	f.reasonsMu.Unlock()
	if l := lastOK.Load(); l > 0 {
		res.Seconds = time.Unix(0, l).Sub(start).Seconds()
		if res.Seconds > 0 {
			res.RatePerSec = float64(res.Connected) / res.Seconds
		}
	}
	res.PeakPerSec = f.connectSeries.Peak()
	return res
}

// recordReason buckets a connect error into a short, low-cardinality
// reason.
func (f *fleet) recordReason(err error) {
	f.reasonsMu.Lock()
	f.reasons[connectReason(err)]++
	f.reasonsMu.Unlock()
}

func connectReason(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, nats.ErrAuthorization), strings.Contains(err.Error(), "Authorization Violation"):
		return "authorization violation"
	case errors.Is(err, nats.ErrMaxConnectionsExceeded), strings.Contains(err.Error(), "maximum connections exceeded"):
		return "maximum connections exceeded"
	case strings.Contains(err.Error(), "tls error: EOF"),
		strings.Contains(err.Error(), "first record does not look like a TLS handshake"):
		// A bus at its connection limit (busmaxconnections, 65,536 by
		// default) sends a plaintext -ERR after its INFO and closes. On
		// its TLS-only listener the client is mid-upgrade by then: it
		// reads the -ERR as a bad TLS record, or sees only the close.
		return "refused during TLS (a bus at its connection limit does this)"
	case errors.Is(err, nats.ErrNoServers):
		return "no servers available"
	case errors.Is(err, nats.ErrTimeout), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection refused"
	case strings.Contains(err.Error(), "Permissions Violation"):
		return "permissions violation"
	case strings.Contains(err.Error(), "tls:"), strings.Contains(err.Error(), "x509:"):
		return "tls"
	case strings.Contains(err.Error(), "too many open files"):
		return "too many open files"
	case strings.Contains(err.Error(), "cannot assign requested address"):
		return "out of local ports"
	default:
		return "other: " + truncate(err.Error(), 80)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// resetEvents forgets disconnects and reconnects seen so far, so a
// restart window counts only its own.
func (f *fleet) resetEvents() {
	f.firstDisconnectNS.Store(0)
	f.lastReconnectNS.Store(0)
	f.disconnects.Store(0)
	f.reconnects.Store(0)
}

// Close closes every connection.
func (f *fleet) Close() {
	f.mu.Lock()
	conns := append([]*nats.Conn(nil), f.conns...)
	f.mu.Unlock()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256)
	for _, nc := range conns {
		if nc == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			// Silence the handlers: a close is not a disconnect to count.
			nc.SetDisconnectErrHandler(nil)
			nc.Close()
			<-sem
		}()
	}
	wg.Wait()
}
