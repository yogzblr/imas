package main

// The latency probes. Against the local bus the requester plays core: a
// few connections with core's per-tenant User shape, sending test.ping to
// random connected sprouts at a fixed rate, the request core's FPing
// makes (internal/ingredients/test). Each round trip is requester -> bus
// -> sprout -> bus -> requester; core's own work (the API, RBAC, PXC) is
// not in it.
//
// Against a deployed bus the harness holds no trust key, so it has no
// User that may publish to a sprout's subjects (only farmer's own
// per-tenant User may, signed by a tenant key farmer keeps in OpenBao).
// There the probe is the bus round trip from a random sprout's own
// connection instead: a NATS PING answered by the bus node the sprout is
// connected to (rttProbe), the one leg of test.ping's path a sprout's
// grants can exercise. The report names which probe ran.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
)

type requester struct {
	conns []*nats.Conn
	next  atomic.Uint64
}

func newRequester(servers []string, tlsCfg *tls.Config, tf *tenantFixture, n int) (*requester, error) {
	r := &requester{}
	for i := range max(n, 1) {
		nc, err := nats.Connect(strings.Join(servers, ","),
			nats.Secure(tlsCfg),
			nats.UserJWTAndSeed(tf.coreJWT, tf.coreSeed),
			nats.IgnoreDiscoveredServers(),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(500*time.Millisecond),
			nats.Name(fmt.Sprintf("imas-loadtest-core-%d", i)),
		)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("requester connection %d: %w", i, err)
		}
		r.conns = append(r.conns, nc)
	}
	return r, nil
}

// probeTestPing and probeBusRTT name the two probes in a result.
const (
	probeTestPing = "test.ping"
	probeBusRTT   = "bus-rtt"
)

// errBadPong is a test.ping reply that isn't a pong.
var errBadPong = errors.New("reply is not a pong")

// pinger is a latency probe: pick chooses a connected sprout and returns
// the probe to send it, or false when it found none.
type pinger interface {
	pick(f *fleet) (probe func(timeout time.Duration) error, ok bool)
}

// pick sends test.ping to a random connected sprout, as core does.
func (r *requester) pick(f *fleet) (func(time.Duration) error, bool) {
	i := f.randomLive()
	if i < 0 {
		return nil, false
	}
	id := f.creds[i].ID
	return func(timeout time.Duration) error {
		m, err := r.conn().Request(pingSubject(id), pingPayload, timeout)
		if err != nil {
			return err
		}
		var pong apitypes.PingPong
		if json.Unmarshal(m.Data, &pong) != nil || !pong.Pong {
			return errBadPong
		}
		return nil
	}, true
}

var pingPayload, _ = json.Marshal(apitypes.PingPong{Ping: true})

// rttProbe measures the bus round trip from a random connected sprout's
// own connection: a NATS PING, flushed, and the bus's PONG.
type rttProbe struct{}

func (rttProbe) pick(f *fleet) (func(time.Duration) error, bool) {
	i := f.randomLive()
	if i < 0 {
		return nil, false
	}
	nc := f.conn(i)
	if nc == nil {
		return nil, false
	}
	return func(timeout time.Duration) error { return nc.FlushTimeout(timeout) }, true
}

func (r *requester) conn() *nats.Conn {
	return r.conns[r.next.Add(1)%uint64(len(r.conns))]
}

func (r *requester) Close() {
	for _, nc := range r.conns {
		nc.Close()
	}
}

// latencyResult is one ping window.
type latencyResult struct {
	Label        string  `json:"label"`
	Seconds      float64 `json:"seconds"`
	TargetRate   float64 `json:"target_rate_per_sec"`
	Sent         int64   `json:"sent"`
	OK           int64   `json:"ok"`
	Timeouts     int64   `json:"timeouts"`
	NoResponders int64   `json:"no_responders"`
	Errors       int64   `json:"errors"`
	Skipped      int64   `json:"skipped"`
	Hist         *hist   `json:"hist"`
	// Filled from Hist by summarize, in milliseconds.
	P50  float64 `json:"p50_ms"`
	P95  float64 `json:"p95_ms"`
	P99  float64 `json:"p99_ms"`
	Max  float64 `json:"max_ms"`
	Mean float64 `json:"mean_ms"`
}

func (l *latencyResult) summarize() {
	if l.Hist == nil {
		l.Hist = &hist{}
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	l.P50, l.P95, l.P99 = ms(l.Hist.Quantile(0.50)), ms(l.Hist.Quantile(0.95)), ms(l.Hist.Quantile(0.99))
	l.Max, l.Mean = ms(l.Hist.Max()), ms(l.Hist.Mean())
}

// failed is every ping that got no reply.
func (l *latencyResult) failed() int64 { return l.Timeouts + l.NoResponders + l.Errors }

// pingWindow sends p's probe at rate per second for d, at most
// concurrency in flight (a tick finding them all busy is skipped and
// counted, not queued, so a slow bus can't hide behind a growing queue).
func pingWindow(ctx context.Context, label string, p pinger, f *fleet, d time.Duration, rate float64, concurrency int, timeout time.Duration) *latencyResult {
	res := &latencyResult{Label: label, TargetRate: rate, Hist: &hist{}}
	var sent, ok, timeouts, noResp, errs, skipped atomic.Int64
	sem := make(chan struct{}, max(concurrency, 1))
	var wg sync.WaitGroup
	start := time.Now()
	end := start.Add(d)
	interval := time.Duration(float64(time.Second) / max(rate, 0.001))
	for i := 0; ; i++ {
		at := start.Add(time.Duration(i) * interval)
		if !at.Before(end) || ctx.Err() != nil {
			break
		}
		if w := time.Until(at); w > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(w):
			}
		}
		probe, found := p.pick(f)
		if !found {
			skipped.Add(1)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			skipped.Add(1)
			continue
		}
		wg.Add(1)
		sent.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			t0 := time.Now()
			err := probe(timeout)
			rtt := time.Since(t0)
			switch {
			case err == nil:
				res.Hist.Record(rtt)
				ok.Add(1)
			case errors.Is(err, nats.ErrTimeout):
				timeouts.Add(1)
			case errors.Is(err, nats.ErrNoResponders):
				noResp.Add(1)
			default:
				errs.Add(1)
			}
		}()
	}
	wg.Wait()
	res.Seconds = time.Since(start).Seconds()
	res.Sent, res.OK, res.Timeouts = sent.Load(), ok.Load(), timeouts.Load()
	res.NoResponders, res.Errors, res.Skipped = noResp.Load(), errs.Load(), skipped.Load()
	res.summarize()
	return res
}
