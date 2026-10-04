package main

// Resource metrics. Neither cmd/farmerbus nor cmd/farmer exposes a
// metrics endpoint (no NATS HTTP monitor port, no Prometheus), so this
// reads what exists:
//
//   - every bus node's varz (resident memory, CPU, connections,
//     subscriptions, slow consumers) over the SYS account, from
//     $SYS.REQ.SERVER.PING.VARZ, which every node in a cluster answers;
//   - /proc for processes on this host: the generator itself, the local
//     bus, and any process named with -proc (core run beside the
//     generator, for instance). Linux only.
//
// Core on another host or in Kubernetes is out of reach; docs/loadtest.md
// says what to watch there instead.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nats "github.com/nats-io/nats.go"
)

const varzSubject = "$SYS.REQ.SERVER.PING.VARZ"

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat's CPU times. It is
// 100 on every mainstream Linux build; reading it needs sysconf, and so
// CGO.
const clockTicks = 100

type varzSample struct {
	At            time.Time `json:"at"`
	Phase         string    `json:"phase"`
	MemBytes      int64     `json:"mem_bytes"`
	CPUPct        float64   `json:"cpu_pct"`
	Cores         int       `json:"cores"`
	Connections   int       `json:"connections"`
	Subscriptions uint32    `json:"subscriptions"`
	SlowConsumers int64     `json:"slow_consumers"`
	Routes        int       `json:"routes"`
}

type procSample struct {
	At       time.Time `json:"at"`
	Phase    string    `json:"phase"`
	RSSBytes int64     `json:"rss_bytes"`
	CPUPct   float64   `json:"cpu_pct"`
}

// procTarget is a process to sample; PID is re-read each time because the
// local bus gets a new one when it restarts.
type procTarget struct {
	Label string
	PID   func() int

	lastPID   int
	lastTicks uint64
	lastAt    time.Time
}

type sampler struct {
	sys      *nats.Conn
	interval time.Duration

	mu      sync.Mutex
	phase   string
	servers map[string][]varzSample
	procs   map[string][]procSample
	targets []*procTarget
}

// connectSys opens the long-lived SYS account connection that reads
// varz. Like core's own SYS connection, it pushes the load-test Account
// again whenever it reconnects (core's PushAllAccounts), so a bus node
// that restarts on an empty volume learns it back.
func connectSys(servers []string, tlsCfg *tls.Config, tr *trust, accountJWT string, logf func(string, ...any)) (*nats.Conn, error) {
	return nats.Connect(strings.Join(servers, ","),
		nats.Secure(tlsCfg),
		nats.UserJWTAndSeed(tr.sysUserJWT, tr.sysUserSeed),
		nats.IgnoreDiscoveredServers(),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(250*time.Millisecond),
		nats.Name("imas-loadtest-sys"),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			go func() {
				if err := publishClaimsUpdate(nc, accountJWT); err != nil {
					logf("re-pushing the load-test Account after a SYS reconnect: %v", err)
				}
			}()
		}),
	)
}

func newSampler(sys *nats.Conn, interval time.Duration, targets []*procTarget) *sampler {
	return &sampler{sys: sys, interval: interval, servers: map[string][]varzSample{}, procs: map[string][]procSample{}, targets: targets}
}

func (s *sampler) SetPhase(p string) {
	s.mu.Lock()
	s.phase = p
	s.mu.Unlock()
}

// Run samples every interval until ctx is done.
func (s *sampler) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.SampleOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SampleOnce()
		}
	}
}

func (s *sampler) SampleOnce() {
	s.mu.Lock()
	phase := s.phase
	s.mu.Unlock()
	now := time.Now()
	vz := s.varz(min(s.interval, 2*time.Second))
	var ps []struct {
		label string
		ps    procSample
	}
	for _, t := range s.targets {
		if smp, ok := t.sample(now); ok {
			smp.Phase = phase
			ps = append(ps, struct {
				label string
				ps    procSample
			}{t.Label, smp})
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, v := range vz {
		v.At, v.Phase = now, phase
		s.servers[name] = append(s.servers[name], v)
	}
	for _, p := range ps {
		s.procs[p.label] = append(s.procs[p.label], p.ps)
	}
}

// varz asks every bus node for its varz and collects the answers that
// arrive within wait.
func (s *sampler) varz(wait time.Duration) map[string]varzSample {
	out := map[string]varzSample{}
	if s.sys == nil || !s.sys.IsConnected() {
		return out
	}
	inbox := s.sys.NewRespInbox()
	sub, err := s.sys.SubscribeSync(inbox)
	if err != nil {
		return out
	}
	defer sub.Unsubscribe()
	if err := s.sys.PublishRequest(varzSubject, inbox, nil); err != nil {
		return out
	}
	deadline := time.Now().Add(wait)
	for {
		m, err := sub.NextMsg(time.Until(deadline))
		if err != nil {
			return out
		}
		var resp struct {
			Server struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			} `json:"server"`
			Data *struct {
				Mem           int64   `json:"mem"`
				CPU           float64 `json:"cpu"`
				Cores         int     `json:"cores"`
				Connections   int     `json:"connections"`
				Subscriptions uint32  `json:"subscriptions"`
				SlowConsumers int64   `json:"slow_consumers"`
				Routes        int     `json:"routes"`
			} `json:"data"`
		}
		if json.Unmarshal(m.Data, &resp) != nil || resp.Data == nil {
			continue
		}
		name := resp.Server.Name
		if name == "" {
			name = resp.Server.ID
		}
		out[name] = varzSample{
			MemBytes: resp.Data.Mem, CPUPct: resp.Data.CPU, Cores: resp.Data.Cores,
			Connections: resp.Data.Connections, Subscriptions: resp.Data.Subscriptions,
			SlowConsumers: resp.Data.SlowConsumers, Routes: resp.Data.Routes,
		}
	}
}

// sample reads one /proc sample. CPU is the average since the previous
// sample of the same PID, in percent of one core; the first sample of a
// PID has none.
func (t *procTarget) sample(now time.Time) (procSample, bool) {
	pid := t.PID()
	if pid <= 0 {
		return procSample{}, false
	}
	ticks, rss, err := readProc(pid)
	if err != nil {
		return procSample{}, false
	}
	smp := procSample{At: now, RSSBytes: rss, CPUPct: -1}
	if pid == t.lastPID && !t.lastAt.IsZero() && ticks >= t.lastTicks {
		if dt := now.Sub(t.lastAt).Seconds(); dt > 0 {
			smp.CPUPct = float64(ticks-t.lastTicks) / clockTicks / dt * 100
		}
	}
	t.lastPID, t.lastTicks, t.lastAt = pid, ticks, now
	return smp, true
}

// readProc returns a process's user+system CPU time in clock ticks and
// its resident set size in bytes.
func readProc(pid int) (ticks uint64, rss int64, err error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	ticks, err = parseStatTicks(string(stat))
	if err != nil {
		return 0, 0, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	rss, err = parseStatusRSS(string(status))
	return ticks, rss, err
}

// parseStatTicks returns utime+stime from a /proc/<pid>/stat line. The
// command name (field 2) may hold spaces and parentheses, so fields are
// counted from the last ')'.
func parseStatTicks(stat string) (uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed stat line")
	}
	f := strings.Fields(stat[i+1:])
	// f[0] is field 3 (state); utime and stime are fields 14 and 15.
	if len(f) < 13 {
		return 0, fmt.Errorf("short stat line")
	}
	u, err := strconv.ParseUint(f[11], 10, 64)
	if err != nil {
		return 0, err
	}
	s, err := strconv.ParseUint(f[12], 10, 64)
	if err != nil {
		return 0, err
	}
	return u + s, nil
}

func parseStatusRSS(status string) (int64, error) {
	for line := range strings.SplitSeq(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			f := strings.Fields(rest)
			if len(f) < 1 {
				break
			}
			kb, err := strconv.ParseInt(f[0], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}
	return 0, fmt.Errorf("no VmRSS in status")
}

// serverStats and procStats are the per-node and per-process summaries
// in the result.
type serverStats struct {
	Name           string             `json:"name"`
	Samples        []varzSample       `json:"samples"`
	MemMaxBytes    int64              `json:"mem_max_bytes"`
	MemLastBytes   int64              `json:"mem_last_bytes"`
	CPUMaxPct      float64            `json:"cpu_max_pct"`
	CPUMaxByPhase  map[string]float64 `json:"cpu_max_pct_by_phase"`
	ConnectionsMax int                `json:"connections_max"`
	SubsMax        uint32             `json:"subscriptions_max"`
	SlowConsumers  int64              `json:"slow_consumers_last"`
}

type procStats struct {
	Label         string             `json:"label"`
	Samples       []procSample       `json:"samples"`
	RSSMaxBytes   int64              `json:"rss_max_bytes"`
	CPUMaxPct     float64            `json:"cpu_max_pct"`
	CPUMaxByPhase map[string]float64 `json:"cpu_max_pct_by_phase"`
}

func (s *sampler) Summary() ([]serverStats, []procStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var srv []serverStats
	for name, smp := range s.servers {
		st := serverStats{Name: name, Samples: smp, CPUMaxByPhase: map[string]float64{}}
		for _, v := range smp {
			st.MemMaxBytes = max(st.MemMaxBytes, v.MemBytes)
			st.CPUMaxPct = max(st.CPUMaxPct, v.CPUPct)
			st.CPUMaxByPhase[v.Phase] = max(st.CPUMaxByPhase[v.Phase], v.CPUPct)
			st.ConnectionsMax = max(st.ConnectionsMax, v.Connections)
			st.SubsMax = max(st.SubsMax, v.Subscriptions)
			st.MemLastBytes, st.SlowConsumers = v.MemBytes, v.SlowConsumers
		}
		srv = append(srv, st)
	}
	sort.Slice(srv, func(i, j int) bool { return srv[i].Name < srv[j].Name })
	var pr []procStats
	for label, smp := range s.procs {
		st := procStats{Label: label, Samples: smp, CPUMaxByPhase: map[string]float64{}}
		for _, v := range smp {
			st.RSSMaxBytes = max(st.RSSMaxBytes, v.RSSBytes)
			st.CPUMaxPct = max(st.CPUMaxPct, v.CPUPct)
			if v.CPUPct >= 0 {
				st.CPUMaxByPhase[v.Phase] = max(st.CPUMaxByPhase[v.Phase], v.CPUPct)
			}
		}
		pr = append(pr, st)
	}
	sort.Slice(pr, func(i, j int) bool { return pr[i].Label < pr[j].Label })
	return srv, pr
}
