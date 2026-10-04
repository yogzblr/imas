package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// requirement10 is docs/design/requirements.md item 10: a NATS response
// to a sprout in under 300 ms.
const requirement10 = 300 * time.Millisecond

// result is one run's (or, merged, several generators') measurements. It
// is what -json writes and merge reads.
type result struct {
	Generators []string  `json:"generators"`
	Mode       string    `json:"mode"`
	Servers    []string  `json:"servers"`
	Sprouts    int       `json:"sprouts"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Connect connectResult  `json:"connect"`
	Hold    *latencyResult `json:"hold"`
	// HoldDrops is sprouts that lost their connection during the hold,
	// when nothing was restarted.
	HoldDrops int            `json:"hold_drops"`
	Restart   *restartResult `json:"restart,omitempty"`
	After     *latencyResult `json:"after_restart,omitempty"`

	Bus   []serverStats `json:"bus"`
	Procs []procStats   `json:"procs"`
	// GeneratorBytesPerConn is the generator's peak RSS over the sprouts
	// it held: what to size a load generator by.
	GeneratorBytesPerConn int64 `json:"generator_bytes_per_conn,omitempty"`

	SproutHandledPings int64 `json:"sprout_handled_pings"`
	SlowConsumers      int64 `json:"client_slow_consumers"`

	Checks []check `json:"checks"`
}

// restartResult is the bus restart window: the Phase 2 exit criterion in
// docs/design/imas-1m-scale-plan.md.
type restartResult struct {
	Mode        string    `json:"mode"`
	TriggeredAt time.Time `json:"triggered_at"`
	// BusDownSeconds is how long the local bus was stopped (its exit and
	// restart until ready), 0 when the restart was not ours to time.
	BusDownSeconds float64 `json:"bus_down_seconds,omitempty"`

	LiveBefore        int       `json:"live_before"`
	Disconnected      int       `json:"disconnected"`
	Reconnected       int       `json:"reconnected"`
	NotReconnected    int       `json:"not_reconnected"`
	FirstDisconnectAt time.Time `json:"first_disconnect_at"`
	FullReconnectAt   time.Time `json:"full_reconnect_at"`
	// FullReconnectSeconds is first disconnect to the moment every
	// sprout live before the restart was live again; 0 if that never
	// happened within the timeout.
	FullReconnectSeconds float64 `json:"full_reconnect_seconds"`
	PeakReconnectPerSec  int     `json:"peak_reconnects_per_sec"`
	PeakAttemptsPerSec   int     `json:"peak_attempts_per_sec"`
	Attempts             int     `json:"attempts"`
	Reconnects           *series `json:"reconnects"`
	AttemptSeries        *series `json:"attempt_series"`
	Note                 string  `json:"note,omitempty"`
}

// thresholds gate the exit status. A zero limit is not checked, except
// where noted.
type thresholds struct {
	MaxP99            time.Duration
	MaxNotConnected   int // always checked
	MaxPingFailRatio  float64
	MaxFullReconnect  time.Duration
	MaxNotReconnected int // checked when there was a restart
}

type check struct {
	Name  string `json:"name"`
	Limit string `json:"limit"`
	Value string `json:"value"`
	Pass  bool   `json:"pass"`
}

func (r *result) evaluate(th thresholds) {
	r.Checks = nil
	add := func(name, limit, value string, pass bool) {
		r.Checks = append(r.Checks, check{Name: name, Limit: limit, Value: value, Pass: pass})
	}
	add("sprouts not connected", fmt.Sprintf("<= %d", th.MaxNotConnected), fmt.Sprint(r.Connect.NotConnected),
		r.Connect.NotConnected <= th.MaxNotConnected)
	for _, l := range []*latencyResult{r.Hold, r.After} {
		if l == nil {
			continue
		}
		if l.OK == 0 {
			add(l.Label+": pings answered", "> 0", "0", false)
			continue
		}
		if th.MaxP99 > 0 {
			add(l.Label+": ping p99", "<= "+th.MaxP99.String(), fmtMS(l.P99), l.P99 <= ms(th.MaxP99))
		}
		if th.MaxPingFailRatio > 0 || l.failed() > 0 {
			ratio := float64(l.failed()) / float64(max(l.Sent, 1))
			add(l.Label+": pings unanswered", fmt.Sprintf("<= %.2f%%", th.MaxPingFailRatio*100),
				fmt.Sprintf("%.2f%% (%d of %d)", ratio*100, l.failed(), l.Sent), ratio <= th.MaxPingFailRatio)
		}
	}
	if rr := r.Restart; rr != nil {
		add("restart: sprouts not reconnected", fmt.Sprintf("<= %d", th.MaxNotReconnected), fmt.Sprint(rr.NotReconnected),
			rr.Disconnected > 0 && rr.NotReconnected <= th.MaxNotReconnected)
		if th.MaxFullReconnect > 0 {
			ok := rr.FullReconnectSeconds > 0 && rr.FullReconnectSeconds <= th.MaxFullReconnect.Seconds()
			add("restart: time to full reconnect", "<= "+th.MaxFullReconnect.String(), fmt.Sprintf("%.1fs", rr.FullReconnectSeconds), ok)
		}
	}
}

func (r *result) passed() bool {
	for _, c := range r.Checks {
		if !c.Pass {
			return false
		}
	}
	return true
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fmtMS(v float64) string { return fmt.Sprintf("%.1fms", v) }

func fmtBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

// writeText prints the human-readable report.
func (r *result) writeText(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("")
	p("imas load test: %d sprouts, %s bus %s, generator(s) %s", r.Sprouts, r.Mode, strings.Join(r.Servers, ","), strings.Join(r.Generators, ","))
	p("")
	c := r.Connect
	p("(a) connect")
	p("    connected      %d of %d (%d never connected)", c.Connected, c.Target, c.NotConnected)
	p("    rate           %.0f/s over %.1fs, peak %d/s", c.RatePerSec, c.Seconds, c.PeakPerSec)
	p("    failed tries   %d", c.FailedAttempts)
	for _, k := range sortedKeys(c.Reasons) {
		p("                   %6d  %s", c.Reasons[k], k)
	}
	if r.Restart == nil {
		p("    dropped during hold  %d", r.HoldDrops)
	}
	p("")
	p("(b) test.ping round trip (requirement 10: %s)", requirement10)
	for _, l := range []*latencyResult{r.Hold, r.After} {
		if l == nil {
			continue
		}
		verdict := "within"
		if l.OK == 0 || l.P99 > ms(requirement10) {
			verdict = "OVER"
		}
		p("    %-14s p50 %s  p95 %s  p99 %s  max %s  (%s 300 ms at p99)", l.Label, fmtMS(l.P50), fmtMS(l.P95), fmtMS(l.P99), fmtMS(l.Max), verdict)
		p("    %-14s %d sent at %.0f/s target over %.0fs: %d answered, %d timed out, %d no responders, %d errors, %d skipped",
			"", l.Sent, l.TargetRate, l.Seconds, l.OK, l.Timeouts, l.NoResponders, l.Errors, l.Skipped)
	}
	p("")
	if rr := r.Restart; rr != nil {
		p("(c) bus restart (%s)", rr.Mode)
		if rr.BusDownSeconds > 0 {
			p("    bus down       %.2fs (stop until ready again)", rr.BusDownSeconds)
		}
		p("    disconnected   %d of %d live", rr.Disconnected, rr.LiveBefore)
		if rr.FullReconnectSeconds > 0 {
			p("    full reconnect %.2fs after the first disconnect", rr.FullReconnectSeconds)
		} else {
			p("    full reconnect NOT reached: %d still disconnected", rr.NotReconnected)
		}
		p("    peak rate      %d reconnects/s, %d reconnect attempts/s (%d attempts in all)", rr.PeakReconnectPerSec, rr.PeakAttemptsPerSec, rr.Attempts)
		if rr.Note != "" {
			p("    note           %s", rr.Note)
		}
		p("")
	}
	p("(d) resources")
	if len(r.Bus) == 0 {
		p("    bus varz       none received")
	}
	for _, s := range r.Bus {
		p("    bus %-10s mem peak %s (last %s), cpu peak %.0f%% %s, conns peak %d, subs peak %d, slow consumers %d",
			s.Name, fmtBytes(s.MemMaxBytes), fmtBytes(s.MemLastBytes), s.CPUMaxPct, fmtPhases(s.CPUMaxByPhase), s.ConnectionsMax, s.SubsMax, s.SlowConsumers)
	}
	for _, s := range r.Procs {
		p("    %-14s rss peak %s, cpu peak %.0f%% %s", s.Label, fmtBytes(s.RSSMaxBytes), s.CPUMaxPct, fmtPhases(s.CPUMaxByPhase))
	}
	if r.GeneratorBytesPerConn > 0 {
		p("    generator      about %s more RSS per sprout connection held", fmtBytes(r.GeneratorBytesPerConn))
	}
	p("    core           %s", coreNote(r.Procs))
	p("")
	p("checks")
	for _, c := range r.Checks {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		}
		p("    %s  %-38s %-22s limit %s", mark, c.Name, c.Value, c.Limit)
	}
	p("")
}

func coreNote(procs []procStats) string {
	for _, p := range procs {
		if p.Label == "core" {
			return "see the core row above"
		}
	}
	return "not measured: core exposes no metrics endpoint; pass -proc core=<pid> when it runs on this host (docs/loadtest.md)"
}

func fmtPhases(m map[string]float64) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", k, m[k]))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func readResult(path string) (*result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// mergeResults combines the results of several load generators run
// against the same bus at the same time: counts add, latency histograms
// and per-second series merge (series assume synchronised clocks), the
// restart window runs from the earliest first disconnect to the latest
// full reconnect, and bus samples are kept per node from whichever
// generator saw the most of them.
func mergeResults(rs []*result) *result {
	out := &result{Mode: rs[0].Mode, Servers: rs[0].Servers}
	out.Connect.Series = newSeries()
	holdH, afterH := &hist{}, &hist{}
	var hold, after *latencyResult
	var rr *restartResult
	bus := map[string]serverStats{}
	var endSec float64
	for _, r := range rs {
		out.Generators = append(out.Generators, r.Generators...)
		out.Sprouts += r.Sprouts
		if out.StartedAt.IsZero() || r.StartedAt.Before(out.StartedAt) {
			out.StartedAt = r.StartedAt
		}
		if r.FinishedAt.After(out.FinishedAt) {
			out.FinishedAt = r.FinishedAt
		}
		c := r.Connect
		out.Connect.Target += c.Target
		out.Connect.Connected += c.Connected
		out.Connect.FailedAttempts += c.FailedAttempts
		out.Connect.NotConnected += c.NotConnected
		for k, v := range c.Reasons {
			if out.Connect.Reasons == nil {
				out.Connect.Reasons = map[string]int{}
			}
			out.Connect.Reasons[k] += v
		}
		out.Connect.Series.Merge(c.Series)
		endSec = max(endSec, c.Seconds)
		out.HoldDrops += r.HoldDrops
		out.SproutHandledPings += r.SproutHandledPings
		out.SlowConsumers += r.SlowConsumers
		hold = mergeLatency(hold, r.Hold, holdH)
		after = mergeLatency(after, r.After, afterH)
		if r.Restart != nil {
			rr = mergeRestart(rr, r.Restart)
		}
		for _, s := range r.Bus {
			if cur, ok := bus[s.Name]; !ok || len(s.Samples) > len(cur.Samples) {
				bus[s.Name] = s
			}
		}
		for _, p := range r.Procs {
			p.Label = strings.Join(r.Generators, ",") + ":" + p.Label
			out.Procs = append(out.Procs, p)
		}
	}
	// The generators ran their connect phases side by side: the merged
	// rate is every connection over the longest phase.
	out.Connect.Seconds = endSec
	if endSec > 0 {
		out.Connect.RatePerSec = float64(out.Connect.Connected) / endSec
	}
	out.Connect.PeakPerSec = out.Connect.Series.Peak()
	out.Hold, out.After, out.Restart = hold, after, rr
	if rr != nil {
		rr.PeakReconnectPerSec = rr.Reconnects.Peak()
		rr.PeakAttemptsPerSec = rr.AttemptSeries.Peak()
		if rr.NotReconnected == 0 && !rr.FullReconnectAt.IsZero() {
			rr.FullReconnectSeconds = rr.FullReconnectAt.Sub(rr.FirstDisconnectAt).Seconds()
		} else {
			rr.FullReconnectSeconds = 0
		}
	}
	for _, k := range sortedKeys(bus) {
		out.Bus = append(out.Bus, bus[k])
	}
	return out
}

func mergeLatency(acc, l *latencyResult, h *hist) *latencyResult {
	if l == nil {
		return acc
	}
	if acc == nil {
		acc = &latencyResult{Label: l.Label, Hist: h}
	}
	acc.Seconds = max(acc.Seconds, l.Seconds)
	acc.TargetRate += l.TargetRate
	acc.Sent += l.Sent
	acc.OK += l.OK
	acc.Timeouts += l.Timeouts
	acc.NoResponders += l.NoResponders
	acc.Errors += l.Errors
	acc.Skipped += l.Skipped
	h.Merge(l.Hist)
	acc.summarize()
	return acc
}

func mergeRestart(acc, r *restartResult) *restartResult {
	if acc == nil {
		acc = &restartResult{Mode: r.Mode, TriggeredAt: r.TriggeredAt, Reconnects: newSeries(), AttemptSeries: newSeries()}
	}
	if r.Mode != "observe" {
		acc.Mode, acc.TriggeredAt, acc.BusDownSeconds = r.Mode, r.TriggeredAt, r.BusDownSeconds
	}
	acc.LiveBefore += r.LiveBefore
	acc.Disconnected += r.Disconnected
	acc.Reconnected += r.Reconnected
	acc.NotReconnected += r.NotReconnected
	acc.Attempts += r.Attempts
	if !r.FirstDisconnectAt.IsZero() && (acc.FirstDisconnectAt.IsZero() || r.FirstDisconnectAt.Before(acc.FirstDisconnectAt)) {
		acc.FirstDisconnectAt = r.FirstDisconnectAt
	}
	if r.FullReconnectAt.After(acc.FullReconnectAt) {
		acc.FullReconnectAt = r.FullReconnectAt
	}
	acc.Reconnects.Merge(r.Reconnects)
	acc.AttemptSeries.Merge(r.AttemptSeries)
	if r.Note != "" {
		acc.Note = strings.TrimPrefix(acc.Note+"; "+r.Note, "; ")
	}
	return acc
}
