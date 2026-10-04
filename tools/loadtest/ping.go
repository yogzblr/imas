package main

// The requester plays core: a few connections with core's per-tenant User
// shape, sending test.ping to random connected sprouts at a fixed rate,
// the request core's FPing makes (internal/ingredients/test). Each round
// trip is requester -> bus -> sprout -> bus -> requester; core's own work
// (the API, RBAC, PXC) is not in it.

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

// pingWindow sends test.ping at rate per second for d, at most
// concurrency in flight (a tick finding them all busy is skipped and
// counted, not queued, so a slow bus can't hide behind a growing queue).
func pingWindow(ctx context.Context, label string, r *requester, f *fleet, d time.Duration, rate float64, concurrency int, timeout time.Duration) *latencyResult {
	res := &latencyResult{Label: label, TargetRate: rate, Hist: &hist{}}
	var sent, ok, timeouts, noResp, errs, skipped atomic.Int64
	sem := make(chan struct{}, max(concurrency, 1))
	var wg sync.WaitGroup
	ping, _ := json.Marshal(apitypes.PingPong{Ping: true})
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
		id := f.randomLive()
		if id == "" {
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
			m, err := r.conn().Request(pingSubject(id), ping, timeout)
			rtt := time.Since(t0)
			switch {
			case err == nil:
				var pong apitypes.PingPong
				if json.Unmarshal(m.Data, &pong) != nil || !pong.Pong {
					errs.Add(1)
					return
				}
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
