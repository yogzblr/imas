package main

import (
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"
)

func TestHistBucketsAreContiguous(t *testing.T) {
	prev := -1
	for us := uint64(0); us < 1<<20; us++ {
		i := histIndex(us)
		if i != prev && i != prev+1 {
			t.Fatalf("index jumps from %d to %d at %dµs", prev, i, us)
		}
		if us > histUpper(i) {
			t.Fatalf("%dµs above its bucket's upper bound %d", us, histUpper(i))
		}
		if i > 0 && us <= histUpper(i-1) {
			t.Fatalf("%dµs also fits bucket %d", us, i-1)
		}
		prev = i
	}
	if histIndex(math.MaxUint64) != histBuckets-1 {
		t.Error("huge values must land in the last bucket")
	}
}

func TestHistQuantiles(t *testing.T) {
	h := &hist{}
	for i := 1; i <= 10000; i++ {
		h.Record(time.Duration(i) * 100 * time.Microsecond) // 0.1ms .. 1000ms
	}
	for _, c := range []struct {
		q    float64
		want time.Duration
	}{{0.5, 500 * time.Millisecond}, {0.95, 950 * time.Millisecond}, {0.99, 990 * time.Millisecond}} {
		got := h.Quantile(c.q)
		if rel := math.Abs(float64(got-c.want)) / float64(c.want); rel > 0.02 {
			t.Errorf("q%.2f = %s, want %s within 2%%", c.q, got, c.want)
		}
	}
	if h.Max() != time.Second || h.Count() != 10000 {
		t.Errorf("max %s count %d", h.Max(), h.Count())
	}
	if (&hist{}).Quantile(0.99) != 0 {
		t.Error("empty hist quantile")
	}
}

func TestHistJSONAndMerge(t *testing.T) {
	a, b := &hist{}, &hist{}
	for i := range 100 {
		a.Record(time.Duration(i) * time.Millisecond)
		b.Record(time.Duration(i+100) * time.Millisecond)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	back := &hist{}
	if err := json.Unmarshal(raw, back); err != nil {
		t.Fatal(err)
	}
	if back.Count() != 100 || back.Quantile(0.5) != a.Quantile(0.5) || back.Max() != a.Max() {
		t.Fatalf("round trip: count %d p50 %s/%s", back.Count(), back.Quantile(0.5), a.Quantile(0.5))
	}
	back.Merge(b)
	if back.Count() != 200 || back.Max() != b.Max() {
		t.Fatalf("merge: count %d max %s", back.Count(), back.Max())
	}
	if p := back.Quantile(0.75); p < 148*time.Millisecond || p > 152*time.Millisecond {
		t.Errorf("merged p75 %s, want ~150ms", p)
	}
	if err := json.Unmarshal([]byte(`{"buckets":{"999999":1}}`), &hist{}); err == nil {
		t.Error("out-of-range bucket accepted")
	}
}

func TestSeries(t *testing.T) {
	s := newSeries()
	base := time.Unix(1_700_000_000, 0)
	s.Add(base, 3)
	s.Add(base.Add(300*time.Millisecond), 2)
	s.Add(base.Add(time.Second), 4)
	s.Add(base.Add(5*time.Second), 9)
	if s.Peak() != 9 || s.PeakBetween(base, base.Add(2*time.Second)) != 5 || s.SumBetween(base, base.Add(time.Second)) != 9 {
		t.Fatalf("peak %d, peak in window %d, sum %d", s.Peak(), s.PeakBetween(base, base.Add(2*time.Second)), s.SumBetween(base, base.Add(time.Second)))
	}
	raw, _ := json.Marshal(s.Between(base, base.Add(time.Second)))
	back := newSeries()
	if err := json.Unmarshal(raw, back); err != nil {
		t.Fatal(err)
	}
	back.Merge(s)
	if back.Peak() != 10 { // 5 + 5 in the first second
		t.Errorf("merged peak %d, want 10", back.Peak())
	}
}

func TestParseProc(t *testing.T) {
	stat := "4242 (my (odd) proc) S 1 4242 4242 0 -1 4194560 100 0 0 0 1234 567 0 0 20 0 8 0 100 1000 200 18446744073709551615"
	ticks, err := parseStatTicks(stat)
	if err != nil || ticks != 1234+567 {
		t.Errorf("parseStatTicks = %d, %v", ticks, err)
	}
	if _, err := parseStatTicks("4242 (x) S 1 2"); err == nil {
		t.Error("short stat accepted")
	}
	rss, err := parseStatusRSS("Name:\tx\nVmPeak:\t 999 kB\nVmRSS:\t    2048 kB\n")
	if err != nil || rss != 2048*1024 {
		t.Errorf("parseStatusRSS = %d, %v", rss, err)
	}
	if _, err := parseStatusRSS("Name:\tx\n"); err == nil {
		t.Error("status without VmRSS accepted")
	}
	// This process, for real, where there is a /proc.
	if _, rss, err := readProc(os.Getpid()); err == nil && rss <= 0 {
		t.Errorf("readProc(self) RSS = %d", rss)
	}
}

func TestBytesPerConn(t *testing.T) {
	s := []procSample{{RSSBytes: 100 << 20}, {RSSBytes: 150 << 20}, {RSSBytes: 140 << 20}}
	if got := bytesPerConn(s, 1000); got != (50<<20)/1000 {
		t.Errorf("bytesPerConn = %d", got)
	}
	if bytesPerConn(nil, 10) != 0 || bytesPerConn(s, 0) != 0 {
		t.Error("empty inputs")
	}
}

func TestEvaluate(t *testing.T) {
	lat := func(label string, p99 float64, sent, failed int64) *latencyResult {
		return &latencyResult{Label: label, P99: p99, Sent: sent, OK: sent - failed, Timeouts: failed}
	}
	th := thresholds{MaxP99: 300 * time.Millisecond, MaxPingFailRatio: 0.01, MaxFullReconnect: time.Minute}
	r := &result{Connect: connectResult{Target: 10, Connected: 10}, Hold: lat("hold", 12, 1000, 5),
		Restart: &restartResult{Disconnected: 10, FullReconnectSeconds: 30}}
	r.evaluate(th)
	if !r.passed() {
		t.Fatalf("should pass: %+v", r.Checks)
	}
	for name, mut := range map[string]func(*result){
		"slow p99":         func(r *result) { r.Hold.P99 = 301 },
		"pings lost":       func(r *result) { r.Hold.Timeouts, r.Hold.OK = 20, 980 },
		"no pings":         func(r *result) { r.Hold.OK = 0 },
		"not connected":    func(r *result) { r.Connect.NotConnected = 1 },
		"not reconnected":  func(r *result) { r.Restart.NotReconnected = 1 },
		"slow reconnect":   func(r *result) { r.Restart.FullReconnectSeconds = 61 },
		"never full":       func(r *result) { r.Restart.FullReconnectSeconds = 0 },
		"no disconnect":    func(r *result) { r.Restart.Disconnected = 0 },
		"after-window p99": func(r *result) { r.After = lat("after restart", 400, 10, 0) },
	} {
		c := *r
		h, rr := *r.Hold, *r.Restart
		c.Hold, c.Restart = &h, &rr
		mut(&c)
		c.evaluate(th)
		if c.passed() {
			t.Errorf("%s: passed", name)
		}
	}
}

func TestMergeResults(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	mk := func(gen string, connected int, first, full time.Time, lat time.Duration) *result {
		h := &hist{}
		for range 100 {
			h.Record(lat)
		}
		rec := newSeries()
		rec.Add(first.Add(time.Second), connected)
		cs := newSeries()
		cs.Add(base, connected)
		l := &latencyResult{Label: "hold", Sent: 100, OK: 100, TargetRate: 50, Hist: h}
		l.summarize()
		return &result{
			Generators: []string{gen}, Mode: "external", Sprouts: connected,
			Connect: connectResult{Target: connected, Connected: connected, Seconds: 10, Series: cs},
			Hold:    l,
			Restart: &restartResult{Mode: "observe", LiveBefore: connected, Disconnected: connected / 2, Reconnected: connected / 2,
				FirstDisconnectAt: first, FullReconnectAt: full, Reconnects: rec, AttemptSeries: newSeries()},
			Bus: []serverStats{{Name: "bus-0", Samples: make([]varzSample, len(gen))}},
		}
	}
	a := mk("gen-a", 1000, base.Add(10*time.Second), base.Add(40*time.Second), 2*time.Millisecond)
	b := mk("gen-bb", 3000, base.Add(9*time.Second), base.Add(45*time.Second), 20*time.Millisecond)
	b.Restart.Mode = "cmd"
	m := mergeResults([]*result{a, b})
	if m.Sprouts != 4000 || m.Connect.Connected != 4000 || m.Connect.RatePerSec != 400 || m.Connect.PeakPerSec != 4000 {
		t.Errorf("connect: %+v", m.Connect)
	}
	if m.Hold.Sent != 200 || m.Hold.TargetRate != 100 || m.Hold.P99 < 19 || m.Hold.P50 > 3 {
		t.Errorf("hold: %+v", m.Hold)
	}
	if m.Restart.Mode != "cmd" || m.Restart.FullReconnectSeconds != 36 || m.Restart.PeakReconnectPerSec != 3000 || m.Restart.LiveBefore != 4000 {
		t.Errorf("restart: %+v", m.Restart)
	}
	if len(m.Bus) != 1 || len(m.Bus[0].Samples) != len("gen-bb") {
		t.Errorf("bus: kept %+v", m.Bus)
	}
	// Survives a JSON round trip, as merge reads files.
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back result
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Hold.Hist.Count() != 100 || back.Restart.Reconnects.Peak() != 1000 {
		t.Errorf("round trip lost data: %+v", back.Hold)
	}
}
