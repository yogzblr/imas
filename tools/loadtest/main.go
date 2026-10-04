// Command loadtest is imas's load and latency harness (SCALE.3): it opens
// N simulated sprout connections to a bus and
//
//	(a) holds them, reporting the connect rate and the failures;
//	(b) measures the test.ping round trip as p50, p95 and p99, against
//	    requirement 10's 300 ms;
//	(c) restarts a bus node mid-run and reports the time to full
//	    reconnect and the peak reconnect rate (the Phase 2 exit criterion
//	    of docs/design/imas-1m-scale-plan.md);
//	(d) reports bus and core memory and CPU from the metrics available.
//
// Without -servers it starts its own one-node bus as a child process.
// -smoke is the CI preset. docs/loadtest.md is the manual: how to run at
// 10k and 100k, several generators, and what a result does and does not
// prove.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/natsretry"
)

func main() {
	if os.Getenv(envRole) == roleBus {
		if err := runBusNode(); err != nil {
			fmt.Fprintln(os.Stderr, "loadtest bus node:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "merge" {
		os.Exit(runMerge(os.Args[2:]))
	}
	os.Exit(runMain(os.Args[1:]))
}

// options is every flag of a run.
type options struct {
	Smoke bool

	Sprouts             int
	Servers             string
	CAFile              string
	OperatorSigningSeed string
	SysAccountSeed      string
	Tenant              string
	IDPrefix            string
	LockOut             bool

	ConnectRate    float64
	ConnectWorkers int
	ConnectRetries int
	ConnectTimeout time.Duration
	ReconnectBase  time.Duration
	ReconnectCap   time.Duration
	SourceIPs      string
	Facts          bool

	Hold            time.Duration
	PingRate        float64
	PingConcurrency int
	PingTimeout     time.Duration
	Requesters      int

	Restart          string
	RestartCmd       string
	RestartSignal    string
	RestartDowntime  time.Duration
	RestartWait      time.Duration
	ReconnectTimeout time.Duration
	Settle           time.Duration
	After            time.Duration

	SampleInterval time.Duration
	Procs          procFlags
	JSON           string
	WorkDir        string
	BusHost        string
	BusPort        int
	BusTrace       bool
	BusMaxConn     int
	Deadline       time.Duration

	MaxP99            time.Duration
	MaxNotConnected   int
	MaxPingFailRatio  float64
	MaxFullReconnect  time.Duration
	MaxNotReconnected int
}

// procFlags is the repeatable -proc label=pid.
type procFlags []struct {
	Label string
	PID   int
}

func (p *procFlags) String() string { return fmt.Sprint(*p) }

func (p *procFlags) Set(v string) error {
	label, pid, ok := strings.Cut(v, "=")
	n, err := strconv.Atoi(pid)
	if !ok || label == "" || err != nil || n <= 0 {
		return fmt.Errorf("want label=pid, got %q", v)
	}
	*p = append(*p, struct {
		Label string
		PID   int
	}{label, n})
	return nil
}

func defineFlags(fs *flag.FlagSet, o *options) {
	fs.BoolVar(&o.Smoke, "smoke", false, "CI preset: 200 sprouts on a local bus, one restart, generous thresholds (flags given explicitly still win)")

	fs.IntVar(&o.Sprouts, "sprouts", 1000, "simulated sprout connections this generator opens")
	fs.StringVar(&o.Servers, "servers", "", "comma-separated bus URLs (tls://host:4222); empty starts a local one-node bus")
	fs.StringVar(&o.CAFile, "ca", "", "with -servers: PEM CA the bus certificates chain to")
	fs.StringVar(&o.OperatorSigningSeed, "operator-signing-seed-file", "", "with -servers: the operator signing seed (IMAS_NATS_OPERATOR_SIGNING_SEED_FILE)")
	fs.StringVar(&o.SysAccountSeed, "sys-account-seed-file", "", "with -servers: the SYS account seed (IMAS_NATS_SYS_ACCOUNT_SEED_FILE)")
	fs.StringVar(&o.Tenant, "tenant", "", "load-test tenant (Account) name; default loadtest-<random>")
	fs.StringVar(&o.IDPrefix, "id-prefix", "", "sprout ID prefix; IDs are <prefix>-<n>; default lt<random>")
	fs.BoolVar(&o.LockOut, "lockout", true, "with -servers: lock the load-test Account out when done, as a tenant deprovision does")

	fs.Float64Var(&o.ConnectRate, "connect-rate", 0, "new connections per second during the ramp; 0 for as fast as -connect-workers allow")
	fs.IntVar(&o.ConnectWorkers, "connect-workers", 128, "connections dialled in parallel during the ramp")
	fs.IntVar(&o.ConnectRetries, "connect-retries", 2, "retries for a sprout whose first connect fails, after the sprout's backoff delay")
	fs.DurationVar(&o.ConnectTimeout, "connect-timeout", 10*time.Second, "dial, TLS and CONNECT timeout per attempt")
	fs.DurationVar(&o.ReconnectBase, "reconnect-base", natsretry.DefaultBase, "the sprout's busreconnectbase")
	fs.DurationVar(&o.ReconnectCap, "reconnect-cap", natsretry.DefaultCap, "the sprout's busreconnectcap")
	fs.StringVar(&o.SourceIPs, "source-ips", "", "comma-separated local IPs to spread connections over (more than ~28k per destination needs several)")
	fs.BoolVar(&o.Facts, "facts", true, "publish this host's facts once per sprout at connect, as a sprout does")

	fs.DurationVar(&o.Hold, "hold", 60*time.Second, "how long to hold the connections while measuring test.ping")
	fs.Float64Var(&o.PingRate, "ping-rate", 100, "test.ping requests per second during each latency window")
	fs.IntVar(&o.PingConcurrency, "ping-concurrency", 512, "most test.ping requests in flight")
	fs.DurationVar(&o.PingTimeout, "ping-timeout", 5*time.Second, "test.ping reply timeout")
	fs.IntVar(&o.Requesters, "requesters", 4, "requester connections playing core")

	fs.StringVar(&o.Restart, "restart", "", "none, local (restart the local bus), cmd (run -restart-cmd) or observe (another generator restarts); default local with a local bus, else none")
	fs.StringVar(&o.RestartCmd, "restart-cmd", "", "with -restart cmd: shell command that restarts a bus node, e.g. 'kubectl -n imas delete pod imas-nats-0'")
	fs.StringVar(&o.RestartSignal, "restart-signal", "term", "with -restart local: term (graceful, as a pod delete) or kill")
	fs.DurationVar(&o.RestartDowntime, "restart-downtime", 0, "with -restart local: how long the bus stays down before it starts again")
	fs.DurationVar(&o.RestartWait, "restart-wait", 2*time.Minute, "how long to wait for the first disconnect after triggering (or, observing, for one to happen)")
	fs.DurationVar(&o.ReconnectTimeout, "reconnect-timeout", 10*time.Minute, "how long to wait for every sprout to reconnect")
	fs.DurationVar(&o.Settle, "settle", 2*time.Second, "how long every sprout must stay connected for the reconnect to count as full")
	fs.DurationVar(&o.After, "after", 30*time.Second, "latency window after the restart; 0 to skip")

	fs.DurationVar(&o.SampleInterval, "sample-interval", 5*time.Second, "how often to sample bus varz and /proc")
	fs.Var(&o.Procs, "proc", "label=pid of a local process to sample from /proc, e.g. core=1234 (repeatable)")
	fs.StringVar(&o.JSON, "json", "", "write the full result as JSON here (input to 'loadtest merge')")
	fs.StringVar(&o.WorkDir, "workdir", "", "local bus working directory (certificates, seeds, bus.log); default a new temporary one")
	fs.StringVar(&o.BusHost, "bus-host", "127.0.0.1", "local bus listen address")
	fs.IntVar(&o.BusPort, "bus-port", 0, "local bus port; 0 picks a free one")
	fs.IntVar(&o.BusMaxConn, "bus-max-connections", 0, "local bus: its busmaxconnections (0 for nats-server's default of 65,536)")
	fs.BoolVar(&o.BusTrace, "bus-trace", true, "local bus: NATS debug and trace logging on, as cmd/farmerbus sets it; false to measure what it costs")
	fs.DurationVar(&o.Deadline, "deadline", 0, "abort the whole run after this long; 0 for none")

	fs.DurationVar(&o.MaxP99, "max-p99", requirement10, "fail if a window's test.ping p99 is above this (requirement 10); 0 to report only")
	fs.IntVar(&o.MaxNotConnected, "max-not-connected", 0, "fail if more sprouts than this never connected")
	fs.Float64Var(&o.MaxPingFailRatio, "max-ping-fail-ratio", 0.001, "fail if a larger share of test.ping requests got no reply")
	fs.DurationVar(&o.MaxFullReconnect, "max-full-reconnect", 0, "fail if the full reconnect took longer; 0 to report only")
	fs.IntVar(&o.MaxNotReconnected, "max-not-reconnected", 0, "fail if more sprouts than this were still disconnected at -reconnect-timeout")
}

// smokePreset is what -smoke sets, for flags not given explicitly. The
// thresholds are deliberately loose: a shared CI runner proves the
// harness and the restart path work, not that the bus is fast.
var smokePreset = map[string]string{
	"sprouts":             "200",
	"hold":                "20s",
	"ping-rate":           "50",
	"after":               "10s",
	"restart":             "local",
	"restart-downtime":    "2s",
	"settle":              "1s",
	"sample-interval":     "2s",
	"reconnect-timeout":   "90s",
	"restart-wait":        "30s",
	"deadline":            "170s",
	"max-p99":             "1s",
	"max-ping-fail-ratio": "0.01",
	"max-full-reconnect":  "60s",
}

func parseOptions(args []string) (*options, error) {
	fs := flag.NewFlagSet("loadtest", flag.ContinueOnError)
	o := &options{}
	defineFlags(fs, o)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: loadtest [flags]\n       loadtest merge [-json out.json] result.json...\n\nSee docs/loadtest.md.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if o.Smoke {
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		for _, name := range sortedKeys(smokePreset) {
			if !set[name] {
				if err := fs.Set(name, smokePreset[name]); err != nil {
					return nil, err
				}
			}
		}
	}
	return o, o.validate()
}

func (o *options) validate() error {
	if o.Sprouts < 1 {
		return errors.New("-sprouts must be at least 1")
	}
	if o.Servers != "" && (o.CAFile == "" || o.OperatorSigningSeed == "" || o.SysAccountSeed == "") {
		return errors.New("-servers needs -ca, -operator-signing-seed-file and -sys-account-seed-file")
	}
	if o.Restart == "" {
		o.Restart = "none"
		if o.Servers == "" {
			o.Restart = "local"
		}
	}
	switch o.Restart {
	case "none", "observe":
	case "local":
		if o.Servers != "" {
			return errors.New("-restart local needs the local bus (no -servers); use -restart cmd")
		}
	case "cmd":
		if o.RestartCmd == "" {
			return errors.New("-restart cmd needs -restart-cmd")
		}
	default:
		return fmt.Errorf("-restart %q: want none, local, cmd or observe", o.Restart)
	}
	if o.RestartSignal != "term" && o.RestartSignal != "kill" {
		return fmt.Errorf("-restart-signal %q: want term or kill", o.RestartSignal)
	}
	if o.IDPrefix != "" && !validPrefix(o.IDPrefix) {
		return fmt.Errorf("-id-prefix %q: use letters, digits and '-', starting with a letter", o.IDPrefix)
	}
	if o.BusMaxConn < 0 {
		return errors.New("-bus-max-connections must not be negative")
	}
	if o.PingRate <= 0 {
		return errors.New("-ping-rate must be positive")
	}
	return nil
}

func validPrefix(p string) bool {
	if p == "" || !(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z') {
		return false
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s  %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, a...))
}

func runMain(args []string) int {
	o, err := parseOptions(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if o.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Deadline)
		defer cancel()
	}
	res, err := run(ctx, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		return 1
	}
	res.writeText(os.Stdout)
	if o.JSON != "" {
		if err := writeJSON(o.JSON, res); err != nil {
			fmt.Fprintln(os.Stderr, "loadtest:", err)
			return 1
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "loadtest: run cut short:", context.Cause(ctx))
		return 1
	}
	if !res.passed() {
		return 1
	}
	return 0
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func runMerge(args []string) int {
	fs := flag.NewFlagSet("loadtest merge", flag.ContinueOnError)
	out := fs.String("json", "", "write the merged result as JSON here")
	o := &options{}
	fs.DurationVar(&o.MaxP99, "max-p99", requirement10, "as for a run")
	fs.IntVar(&o.MaxNotConnected, "max-not-connected", 0, "as for a run")
	fs.Float64Var(&o.MaxPingFailRatio, "max-ping-fail-ratio", 0.001, "as for a run")
	fs.DurationVar(&o.MaxFullReconnect, "max-full-reconnect", 0, "as for a run")
	fs.IntVar(&o.MaxNotReconnected, "max-not-reconnected", 0, "as for a run")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "loadtest merge: no result files")
		return 2
	}
	var rs []*result
	for _, p := range fs.Args() {
		r, err := readResult(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "loadtest merge:", err)
			return 1
		}
		rs = append(rs, r)
	}
	m := mergeResults(rs)
	m.evaluate(o.thresholds())
	m.writeText(os.Stdout)
	if *out != "" {
		if err := writeJSON(*out, m); err != nil {
			fmt.Fprintln(os.Stderr, "loadtest merge:", err)
			return 1
		}
	}
	if !m.passed() {
		return 1
	}
	return 0
}

func (o *options) thresholds() thresholds {
	return thresholds{
		MaxP99: o.MaxP99, MaxNotConnected: o.MaxNotConnected, MaxPingFailRatio: o.MaxPingFailRatio,
		MaxFullReconnect: o.MaxFullReconnect, MaxNotReconnected: o.MaxNotReconnected,
	}
}

// run is one generator's whole run.
func run(ctx context.Context, o *options) (*result, error) {
	host, _ := os.Hostname()
	if o.Tenant == "" {
		o.Tenant = "loadtest-" + randomHex(4)
	}
	if o.IDPrefix == "" {
		o.IDPrefix = "lt" + randomHex(3)
	}
	res := &result{Generators: []string{host}, Sprouts: o.Sprouts, StartedAt: time.Now()}

	// Trust chain and bus.
	var (
		tr      *trust
		servers []string
		pool    *x509.CertPool
		bus     *localBus
		err     error
	)
	if o.Servers == "" {
		res.Mode = "local"
		dir := o.WorkDir
		if dir == "" {
			if dir, err = os.MkdirTemp("", "imas-loadtest-"); err != nil {
				return nil, err
			}
			defer os.RemoveAll(dir)
		} else if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		var seeds seedFiles
		if tr, seeds, err = newLocalTrust(dir); err != nil {
			return nil, fmt.Errorf("generating the trust chain: %w", err)
		}
		if bus, pool, err = newLocalBus(dir, o.BusHost, o.BusPort, seeds, o.BusTrace); err != nil {
			return nil, err
		}
		bus.maxConn = o.BusMaxConn
		defer bus.Close()
		logf("starting the local bus (%s, log in %s/bus.log)", bus.URL(), dir)
		if err := bus.Start(ctx); err != nil {
			return nil, err
		}
		servers = []string{bus.URL()}
	} else {
		res.Mode = "external"
		if tr, err = loadTrust(o.OperatorSigningSeed, o.SysAccountSeed); err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate in %s", o.CAFile)
		}
		for _, s := range strings.Split(o.Servers, ",") {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
	}
	res.Servers = servers
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	// Fixture identities.
	tf, err := tr.newTenant(o.Tenant)
	if err != nil {
		return nil, err
	}
	logf("minting %d sprout identities in tenant %s (Account %s)", o.Sprouts, tf.name, tf.accountPub)
	t0 := time.Now()
	creds, err := tf.mintSprouts(o.IDPrefix, o.Sprouts)
	if err != nil {
		return nil, err
	}
	if err := pkiSanity(creds[0]); err != nil {
		return nil, err
	}
	logf("minted in %s", time.Since(t0).Round(time.Millisecond))
	logf("pushing the load-test Account to %s", strings.Join(servers, ","))
	if err := tr.pushAccount(servers, tlsCfg, tf.accountJWT); err != nil {
		return nil, fmt.Errorf("pushing the load-test Account: %w", err)
	}
	if o.Servers != "" && o.LockOut {
		defer func() {
			locked, err := tf.lockedOutJWT(tr)
			if err == nil {
				err = tr.pushAccount(servers, tlsCfg, locked)
			}
			if err != nil {
				logf("WARNING: could not lock the load-test Account %s out: %v", tf.accountPub, err)
			} else {
				logf("locked the load-test Account out")
			}
		}()
	}

	sys, err := connectSys(servers, tlsCfg, tr, tf.accountJWT, logf)
	if err != nil {
		return nil, fmt.Errorf("SYS connection: %w", err)
	}
	defer sys.Close()
	targets := []*procTarget{{Label: "generator", PID: os.Getpid}}
	if bus != nil {
		targets = append(targets, &procTarget{Label: "bus (local)", PID: bus.PID})
	}
	for _, p := range o.Procs {
		targets = append(targets, &procTarget{Label: p.Label, PID: func() int { return p.PID }})
	}
	smp := newSampler(sys, o.SampleInterval, targets)
	smp.SetPhase("idle")
	sctx, stopSampler := context.WithCancel(ctx)
	samplerDone := make(chan struct{})
	go func() { smp.Run(sctx); close(samplerDone) }()
	defer func() { stopSampler(); <-samplerDone }()

	// Fleet.
	fo := fleetOptions{
		Servers: servers, TLS: tlsCfg,
		ReconnectBase: o.ReconnectBase, ReconnectCap: o.ReconnectCap,
		ConnectTimeout: o.ConnectTimeout,
	}
	if o.Facts {
		fo.Facts = factsPayload()
	}
	if o.SourceIPs != "" {
		for _, s := range strings.Split(o.SourceIPs, ",") {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				return nil, fmt.Errorf("-source-ips: %q is not an IP", s)
			}
			fo.SourceIPs = append(fo.SourceIPs, ip)
		}
	}
	fl := newFleet(creds, fo)
	wctx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	fl.startWorkers(wctx)
	defer fl.Close()

	// (a) connect and hold.
	smp.SetPhase("connect")
	logf("connecting %d sprouts (rate %s, %d workers)", o.Sprouts, rateString(o.ConnectRate), o.ConnectWorkers)
	res.Connect = fl.connectAll(ctx, o.ConnectRate, o.ConnectWorkers, o.ConnectRetries)
	logf("connected %d of %d in %.1fs (%.0f/s)", res.Connect.Connected, res.Connect.Target, res.Connect.Seconds, res.Connect.RatePerSec)
	if res.Connect.Connected == 0 {
		res.FinishedAt = time.Now()
		res.evaluate(o.thresholds())
		return res, nil
	}

	req, err := newRequester(servers, tlsCfg, tf, o.Requesters)
	if err != nil {
		return nil, err
	}
	defer req.Close()

	// (b) latency while holding.
	smp.SetPhase("hold")
	fl.resetEvents()
	logf("holding for %s, test.ping at %.0f/s", o.Hold, o.PingRate)
	res.Hold = pingWindow(ctx, "hold", req, fl, o.Hold, o.PingRate, o.PingConcurrency, o.PingTimeout)
	res.HoldDrops = int(fl.disconnects.Load())
	logf("hold: p50 %.1fms p95 %.1fms p99 %.1fms, %d of %d answered", res.Hold.P50, res.Hold.P95, res.Hold.P99, res.Hold.OK, res.Hold.Sent)

	// (c) restart.
	if o.Restart != "none" && ctx.Err() == nil {
		smp.SetPhase("restart")
		res.Restart = restartWindow(ctx, o, fl, bus)
		if o.After > 0 && ctx.Err() == nil && res.Restart.NotReconnected == 0 {
			waitConnected(ctx, req, 30*time.Second)
			smp.SetPhase("after")
			logf("after the restart: test.ping for %s", o.After)
			res.After = pingWindow(ctx, "after restart", req, fl, o.After, o.PingRate, o.PingConcurrency, o.PingTimeout)
			logf("after: p50 %.1fms p95 %.1fms p99 %.1fms, %d of %d answered", res.After.P50, res.After.P95, res.After.P99, res.After.OK, res.After.Sent)
		}
	}

	// (d) resources.
	stopSampler()
	<-samplerDone
	smp.SampleOnce()
	res.Bus, res.Procs = smp.Summary()
	for _, p := range res.Procs {
		if p.Label == "generator" {
			res.GeneratorBytesPerConn = bytesPerConn(p.Samples, res.Connect.Connected)
		}
	}
	res.SproutHandledPings = fl.pings.Load()
	res.SlowConsumers = fl.slowConsumers.Load()
	res.FinishedAt = time.Now()
	res.evaluate(o.thresholds())
	return res, nil
}

func rateString(r float64) string {
	if r <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%.0f/s", r)
}

// factsPayload is this host's facts, collected once: the size of the
// facts a real sprout publishes at startup.
func factsPayload() []byte {
	b, _ := json.Marshal(facts.Collect())
	return b
}

// waitConnected waits until every requester connection is up again.
func waitConnected(ctx context.Context, r *requester, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		all := true
		for _, nc := range r.conns {
			all = all && nc.IsConnected()
		}
		if all {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// restartWindow triggers (or, observing, waits for) a bus restart and
// measures the fleet's way back.
func restartWindow(ctx context.Context, o *options, fl *fleet, bus *localBus) *restartResult {
	fl.resetEvents()
	rr := &restartResult{Mode: o.Restart, LiveBefore: fl.Live()}
	windowStart := time.Now()
	rr.TriggeredAt = windowStart
	switch o.Restart {
	case "local":
		sig := syscall.SIGTERM
		if o.RestartSignal == "kill" {
			sig = syscall.SIGKILL
		}
		logf("restarting the local bus (SIG%s, down for at least %s)", strings.ToUpper(o.RestartSignal), o.RestartDowntime)
		if err := bus.Stop(sig); err != nil {
			rr.Note = "stopping the bus: " + err.Error()
		}
		select {
		case <-ctx.Done():
		case <-time.After(o.RestartDowntime):
		}
		if err := bus.Start(ctx); err != nil {
			rr.Note = strings.TrimPrefix(rr.Note+"; starting the bus: "+err.Error(), "; ")
			return finishRestart(rr, fl, windowStart)
		}
		rr.BusDownSeconds = time.Since(windowStart).Seconds()
	case "cmd":
		logf("restarting a bus node: %s", o.RestartCmd)
		cctx, cancel := context.WithTimeout(ctx, o.RestartWait)
		out, err := exec.CommandContext(cctx, "sh", "-c", o.RestartCmd).CombinedOutput()
		cancel()
		if err != nil {
			rr.Note = fmt.Sprintf("-restart-cmd failed: %v: %s", err, truncate(strings.TrimSpace(string(out)), 200))
		}
	case "observe":
		rr.TriggeredAt = time.Time{}
		logf("waiting up to %s for another generator's bus restart", o.RestartWait)
	}

	// The first disconnect.
	deadline := windowStart.Add(o.RestartWait)
	for fl.firstDisconnectNS.Load() == 0 {
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			rr.Note = strings.TrimPrefix(rr.Note+"; no sprout disconnected", "; ")
			return finishRestart(rr, fl, windowStart)
		}
		time.Sleep(20 * time.Millisecond)
	}
	logf("%d sprouts disconnected; waiting up to %s for all %d to reconnect", fl.disconnects.Load(), o.ReconnectTimeout, rr.LiveBefore)

	// Full reconnect: every sprout live before is live again, and stays
	// so for -settle (a rolling restart can take a node down twice).
	deadline = time.Now().Add(o.ReconnectTimeout)
	var fullSince time.Time
	lastLog := time.Now()
	for ctx.Err() == nil && time.Now().Before(deadline) {
		if fl.Live() >= rr.LiveBefore {
			if fullSince.IsZero() {
				fullSince = time.Now()
			}
			if time.Since(fullSince) >= o.Settle {
				rr.FullReconnectAt = time.Unix(0, fl.lastReconnectNS.Load())
				break
			}
		} else {
			fullSince = time.Time{}
		}
		if time.Since(lastLog) >= 5*time.Second {
			logf("  %d of %d live", fl.Live(), rr.LiveBefore)
			lastLog = time.Now()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return finishRestart(rr, fl, windowStart)
}

func finishRestart(rr *restartResult, fl *fleet, windowStart time.Time) *restartResult {
	end := time.Now()
	rr.Disconnected = int(fl.disconnects.Load())
	rr.Reconnected = int(fl.reconnects.Load())
	rr.NotReconnected = max(rr.LiveBefore-fl.Live(), 0)
	if ns := fl.firstDisconnectNS.Load(); ns > 0 {
		rr.FirstDisconnectAt = time.Unix(0, ns)
	}
	if !rr.FullReconnectAt.IsZero() && !rr.FirstDisconnectAt.IsZero() {
		rr.FullReconnectSeconds = rr.FullReconnectAt.Sub(rr.FirstDisconnectAt).Seconds()
	}
	rr.Reconnects = fl.reconnectSeries.Between(windowStart, end)
	rr.AttemptSeries = fl.attemptSeries.Between(windowStart, end)
	rr.PeakReconnectPerSec = rr.Reconnects.Peak()
	rr.PeakAttemptsPerSec = rr.AttemptSeries.Peak()
	rr.Attempts = rr.AttemptSeries.SumBetween(windowStart, end)
	if rr.FullReconnectSeconds > 0 {
		logf("full reconnect %.2fs after the first disconnect; peak %d reconnects/s", rr.FullReconnectSeconds, rr.PeakReconnectPerSec)
	} else {
		logf("full reconnect not reached: %d still disconnected", rr.NotReconnected)
	}
	return rr
}

// bytesPerConn is the generator's RSS growth from its first sample, taken
// before any sprout connected, to its peak, over the sprouts it held.
func bytesPerConn(samples []procSample, conns int) int64 {
	if len(samples) == 0 || conns == 0 {
		return 0
	}
	var peak int64
	for _, s := range samples {
		peak = max(peak, s.RSSBytes)
	}
	return max(peak-samples[0].RSSBytes, 0) / int64(conns)
}
