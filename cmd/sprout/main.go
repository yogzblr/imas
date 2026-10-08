package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/yogzblr/imas/internal/log"

	certs "github.com/yogzblr/imas/internal/certs"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/ingredients/selfupdate"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/natsretry"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/shell"

	nats "github.com/nats-io/nats.go"

	"github.com/taigrr/jety"
)

// setupSprout prepares the config, PKI and logging for runSprout. It used
// to be init(); it runs from main so the service commands, which don't
// need it, don't write the config directory and can run unelevated.
func setupSprout() {
	// Before LoadConfig writes the config file (it can hold the join
	// token): a no-op outside Windows.
	secureErr := config.SecureSproutConfigRoot()
	// Under the Windows SCM, which discards stderr, log to a file below
	// the config root from here on, so a failure above is recorded too.
	startServiceLog()
	if secureErr != nil {
		log.Fatalf("failed to secure the config directory: %v", secureErr)
	}
	config.LoadConfig("sprout")
	log.SetLogLevel(config.LogLevel)
	setNATSLogMinLevel(jety.GetString(natsLogMinLevelKey))
	sproutID = pki.GetSproutID()
	createConfigRoot()
	pki.SetupPKISprout()
	cook.NewRecipeCooker = ingredients.NewRecipeCooker
}

// natsLogMinLevelKey is the sprout config key for the lowest log level
// shipped over the bus (log.SetNATSMinLevel). Unset, it is info: Trace
// and Debug stay in the local log (security review 2026-10, H4).
const natsLogMinLevelKey = "natslogminlevel"

// setNATSLogMinLevel applies the natslogminlevel setting, keeping the
// default (log.DefaultNATSMinLevel) for an empty or unknown value.
func setNATSLogMinLevel(v string) {
	if v == "" {
		log.SetNATSMinLevel(log.DefaultNATSMinLevel)
		return
	}
	l, err := log.ParseLevel(v)
	if err != nil {
		log.Warnf("%s %q is not a log level; shipping logs from %s", natsLogMinLevelKey, v, "info")
		l = log.DefaultNATSMinLevel
	}
	log.SetNATSMinLevel(l)
}

var (
	BuildTime string
	GitCommit string
	Tag       string
	sproutID  string
)

func main() {
	joinToken := flag.String("join-token", "",
		"join token for first-time enrollment; overrides "+config.EnvJoinToken+" and the config file's jointoken. "+
			"Visible to other local users in the process list, so prefer the environment variable or config file")
	flag.Usage = usage
	flag.Parse()
	if cmd := flag.Arg(0); serviceCommands[cmd] {
		os.Exit(serviceCommand(cmd, *joinToken))
	}
	setupSprout()
	// Under the Windows SCM, the service handler drives the loop: the
	// SCM's Stop/Shutdown cancels its context. See service_windows.go.
	if runAsService(func(ctx context.Context) { runSprout(ctx, *joinToken, false) }) {
		return
	}
	runSprout(context.Background(), *joinToken, true)
}

// serviceCommands manage the Windows service (service_windows.go). Other
// positional arguments are ignored, as before.
var serviceCommands = map[string]bool{"install": true, "uninstall": true, "start": true, "stop": true, "status": true}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: %s [flags] [install|uninstall|start|stop|status]\n\n", os.Args[0])
	fmt.Fprint(out, serviceCommandsHelp)
	fmt.Fprint(out, "\nFlags:\n")
	flag.PrintDefaults()
}

// serviceCommand runs one of serviceCommands and returns the exit code.
func serviceCommand(cmd, joinToken string) int {
	if flag.NArg() > 1 {
		return serviceCommandFailed(cmd, fmt.Errorf("unexpected arguments %q", flag.Args()[1:]))
	}
	if joinToken != "" {
		// A service is started without it, and saving it in the
		// service's command line would expose it.
		return serviceCommandFailed(cmd, fmt.Errorf("-join-token only applies to a sprout started from this "+
			"command line; for the service, set jointoken in the config file or %s", config.EnvJoinToken))
	}
	return runServiceCommand(cmd)
}

func serviceCommandFailed(cmd string, err error) int {
	fmt.Fprintf(os.Stderr, "imas-sprout %s: %v\n", cmd, err)
	return 1
}

// runSprout is the sprout's main loop. It returns once parent is cancelled
// or, if handleSignals, on SIGINT/SIGTERM, after waiting up to 10s for the
// NATS connection to close. Fatal errors still exit the process.
//
// A Windows service must not handle signals: Go turns CTRL_LOGOFF_EVENT,
// which Windows sends to services whenever any user logs off, into
// SIGTERM for a process that listens for it, so the sprout would stop
// (cleanly, so the SCM's failure actions wouldn't restart it) on every
// logoff. The SCM's Stop and Shutdown controls cover it instead.
func runSprout(parent context.Context, joinToken string, handleSignals bool) {
	if err := os.MkdirAll(config.CacheDir, 0o755); err != nil {
		log.Fatalf("failed to create cache directory %s: %v", config.CacheDir, err)
	}
	config.LoadConfig("sprout")
	config.SetJoinTokenFromFlag(joinToken)
	defer log.Flush()
	// The release tag goreleaser links in (-X main.Tag=v<version>): the
	// version the selfupdate ingredient refuses downgrades and
	// min_sprout_version against.
	selfupdate.SetRunningVersion(Tag)
	// Reported in facts, which a fleet update's wave gate reads to see
	// this sprout back on its new version (design doc §2.3).
	facts.SetSproutVersion(Tag)
	if err := certs.GenNKey(false); err != nil {
		log.Fatalf("failed to generate sprout NKey: %v", err)
	}
	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		log.Fatalf("failed to generate sprout X25519 key: %v", err)
	}
	if g := config.SproutBoxKeyPrevGrace; g > 0 && g < pki.MinSproutBoxKeyPrevGrace {
		log.Warnf("sproutboxkeyprevgrace %s is shorter than a farmer payload can stay in flight; using %s", g, pki.MinSproutBoxKeyPrevGrace)
	}
	var ctx context.Context
	var stop context.CancelFunc
	if handleSignals {
		ctx, stop = signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	} else {
		ctx, stop = context.WithCancel(parent)
	}
	defer stop()
	rootCARetryDelay := jety.GetDuration("rootca_retry_delay")
	// Retried rather than fatal: a DMZ install's CA may be provisioned
	// after the service starts. Each distinct error is logged at Warn so
	// a sprout stuck here is visible; repeats of it drop to Debug.
	var lastRootCAErr string
	for err := pki.LoadRootCA("sprout"); err != nil; err = pki.LoadRootCA("sprout") {
		if msg := err.Error(); msg != lastRootCAErr {
			log.Warnf("cannot load the root CA, retrying every %s: %v", rootCARetryDelay, err)
			lastRootCAErr = msg
		} else {
			log.Debugf("cannot load the root CA: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(rootCARetryDelay):
		}
	}
	enrollRetryDelay := jety.GetDuration("enroll_retry_delay")
	enrolledID, err := pki.EnsureEnrolled(ctx, config.JoinToken, sproutID, sproutPub, enrollRetryDelay)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Fatalf("enrollment: %v", err)
	}
	if enrolledID != sproutID {
		log.Noticef("farmer assigned sprout ID %q (requested %q)", enrolledID, sproutID)
		config.SetSproutID(enrolledID)
		sproutID = enrolledID
	}
	// Enrollment is fully persisted (EnsureEnrolled only returns once the
	// User JWT, written last, is on disk), so the join token has no use
	// left: every later call is a proof-of-possession replay or refresh.
	// This also covers a sprout that crashed between persisting and
	// clearing on an earlier start.
	if src, err := config.ClearJoinToken(); err != nil {
		log.Errorf("enrolled, but failed to delete the join token from the config file: %v", err)
	} else if src != config.JoinTokenFromNone {
		log.Warnf("enrolled; the join token came from the %s, which the sprout can't clear itself: remove it there", src)
	}
	if _, err := pki.LoadGatewayJWT(); err != nil {
		// Not fatal: the refresher below replaces a missing token first.
		// The sealed refresh needs no gateway JWT, only the box key and
		// the pins enrollment wrote.
		log.Warnf("no persisted gateway JWT: %v", err)
	}
	go func() {
		// A refresher error means farmer's tenant X25519 key, tenant ID or
		// sprout ID no longer matches the one pinned at enrollment, or the
		// sprout can't make a sealed refresh at all: a pin or its box key
		// is missing (pki.IsFatalRefreshError). There is no NKey-signed
		// fallback (J.2); the sprout must be re-enrolled. Exit non-zero so
		// the service manager records a failure and monitoring alerts; a
		// log line alone would go unnoticed while the gateway JWT expires.
		// A refresh farmer merely refuses is retried, not fatal: the
		// refusal is unauthenticated.
		if err := pki.RunGatewayJWTRefresher(ctx, sproutID, enrollRetryDelay); err != nil {
			log.Fatalf("gateway JWT refresh: %v", err)
		}
	}()
	done := make(chan struct{})
	go ConnectSprout(ctx, done)
	<-ctx.Done()
	stop()
	log.Info("Shutdown signal received, stopping sprout...")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Warn("timed out waiting for NATS client to close")
	}
}

func createConfigRoot() {
	ConfigRoot := config.ConfigRoot
	_, err := os.Stat(ConfigRoot)
	if err == nil {
		return
	}
	if os.IsNotExist(err) {
		err = os.MkdirAll(ConfigRoot, os.ModePerm)
		if err != nil {
			log.Panicf("failed to create config directory: %v", err)
		}
	} else {
		log.Panicf("unexpected error checking config directory: %v", err)
	}
}

func ConnectSprout(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	var connectionAttempts atomic.Int64
	jobLogDir := config.JobLogDir
	jobLogTTL := config.JobLogTTL
	// The enrolled nats_urls (or the busurls pin, or the legacy
	// FarmerBusURL), with the User JWT + NKey seed, SproutRootCA-pinned
	// TLS and gateway JWT options. See pki.LoadSproutBus.
	bus, err := pki.LoadSproutBus()
	if err != nil {
		log.Panicf("failed to load bus connection settings: %v", err)
	}
	log.Infof("connecting to the bus at %s (from %s)", strings.Join(bus.Servers, ", "), bus.Source)
	// Full-jitter exponential backoff instead of a fixed wait, so a fleet
	// that lost the bus together (a bus restart) doesn't come back in
	// step. nats.go restarts the attempt count after every successful
	// connect. See internal/natsretry.
	backoff := natsretry.New(config.BusReconnectBase, config.BusReconnectCap, nil)
	if backoff.Base() != config.BusReconnectBase || backoff.Cap() != config.BusReconnectCap {
		log.Warnf("busreconnectbase %s and busreconnectcap %s: using %s and %s (non-positive values take the default, and the cap is at least the base)",
			config.BusReconnectBase, config.BusReconnectCap, backoff.Base(), backoff.Cap())
	}
	connectOpts := []nats.Option{
		nats.MaxReconnects(-1),
		// nats.go waits this long once per pass over the bus addresses
		// (with a single address, before every attempt), passing the
		// pass number within the current outage.
		nats.CustomReconnectDelay(func(attempt int) time.Duration {
			d := backoff.Delay(attempt)
			log.Debugf("bus reconnect %d in %s", attempt, d)
			return d
		}),
		nats.DisconnectHandler(func(_ *nats.Conn) {
			log.Debugf("Reconnecting to Farmer, attempt: %d\n", connectionAttempts.Add(1))
		}),
		// A push sent while disconnected is lost; catch up from the
		// staged copy (cook.SyncStagedRecipe).
		nats.ReconnectHandler(func(_ *nats.Conn) {
			go syncStagedRecipe(ctx, cook.SyncOnReconnect)
		}),
	}
	nc, err := bus.Connect(connectOpts...)
	for attempt := 1; err != nil; attempt++ {
		wait := backoff.Delay(attempt)
		log.Warnf("bus connect failed, retrying in %s: %v", wait.Round(time.Millisecond), err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		nc, err = bus.Connect(connectOpts...)
	}
	log.Debugf("Successfully connected to the Farmer")

	// Ship logs over this same authenticated connection: a separate dial to
	// FarmerBusURL has neither the User JWT nor the enrolled addresses.
	if !pki.SproutUserJWTGrantsLogs(bus.UserJWT, sproutID) {
		log.Warnf("not shipping logs to the bus: this sprout's User JWT has no grant for %s.>; farmer re-mints it, and it takes effect after the next refresh and restart", pki.SproutLogSubjectPrefix(sproutID))
	} else if err := log.UseNATSConn(nc, pki.SproutLogSubjectPrefix(sproutID)); err != nil {
		log.Errorf("Failed to attach log-nats backend to the bus connection: %v", err)
	}
	// A User JWT minted before sproutPermissions carried the grant: until
	// then nats-server drops the submission, and a rotation farmer
	// triggers never completes (harmlessly; see boxkey.go).
	if submit := pki.SproutBoxKeySubmitSubject(sproutID); bus.UserJWT != "" && !userJWTGrantsPub(bus.UserJWT, submit) {
		log.Warnf("farmer-triggered payload-encryption key rotation can't complete: this sprout's User JWT has no publish grant for %s; farmer re-mints it, and it takes effect after the next refresh and restart", submit)
	}

	// Sealed shell's s2f frames need this grant (J.5); a JWT minted
	// before it can't publish them until a refresh and restart.
	if grant := shell.SproutOutSubjectPrefix(sproutID) + ".>"; bus.UserJWT != "" && !userJWTGrantsPub(bus.UserJWT, grant) {
		log.Warnf("shell sessions to this sprout can't work yet: its User JWT has no publish grant for %s.>; farmer re-mints it, and it takes effect after the next refresh and restart", shell.SproutOutSubjectPrefix(sproutID))
	}
	pol := shellPolicyFromConfig()
	shell.SetSproutPolicy(pol)
	if pol.Disabled {
		log.Noticef("interactive shell is disabled on this sprout (disableshell)")
	}

	test.RegisterNatsConn(nc)
	cmd.RegisterNatsConn(nc)
	cook.RegisterNatsConn(nc)
	err = natsInit(ctx, nc)
	if err != nil {
		log.Panicf("Error with natsInit: %v", err)
	}
	// After natsInit's subscriptions, so a push arriving during the pull
	// is seen and wins over it.
	go syncStagedRecipe(ctx, cook.SyncOnStartup)
	// Keeps farmer's "connected" key for this sprout fresh while the
	// connection stays up (internal/heartbeat); stops with ctx.
	startHeartbeat(ctx, nc, bus.UserJWT)
	// Expire old local job logs written by cook runs on this sprout.
	jobs.StartSproutReaper(ctx, jobLogDir, jobLogTTL)
	<-ctx.Done()
	if shellServer != nil {
		shellServer.CloseAll()
		_ = nc.FlushTimeout(2 * time.Second)
	}
	nc.Close()
}
