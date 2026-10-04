package main

// The simulated sprouts. Each one is a nats.go connection made the way
// cmd/sprout's ConnectSprout makes it (pinned-CA TLS, User JWT and NKey
// seed, enrolled addresses so discovered servers are ignored, unlimited
// reconnects with internal/natsretry's full-jitter backoff), and once
// connected does what natsInit does on the bus: announces itself,
// publishes its facts, and subscribes to the same seven subjects.
//
// Only test.ping and facts.request are answered (test.ping with the
// sprout's own handler, internal/ingredients/test.SPing). The other
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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/natsretry"
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
	// Facts is published once per sprout at connect and answers
	// facts.request; nil publishes none.
	Facts   []byte
	Workers int
}

// fleet is every simulated sprout of one generator.
type fleet struct {
	opts    fleetOptions
	creds   []sproutCred
	backoff *natsretry.Backoff
	msgs    chan *nats.Msg

	mu    sync.Mutex
	conns []*nats.Conn

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
		_ = m.Respond(f.opts.Facts)
		f.factsReqs.Add(1)
	default:
		f.inert.Add(1)
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

// randomLive returns the ID of a connected sprout, or "" if it found none
// in a few tries.
func (f *fleet) randomLive() string {
	for range 16 {
		i := rand.IntN(len(f.creds))
		if f.live[i].Load() {
			return f.creds[i].ID
		}
	}
	return ""
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
		if err := nc.Publish("imas.sprouts."+id+".facts", f.opts.Facts); err != nil {
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
