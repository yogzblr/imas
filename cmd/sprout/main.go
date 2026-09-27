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
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/ingredients/selfupdate"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/pki"

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
	sproutID = pki.GetSproutID()
	createConfigRoot()
	pki.SetupPKISprout()
	cook.NewRecipeCooker = ingredients.NewRecipeCooker
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
	if err := certs.GenNKey(false); err != nil {
		log.Fatalf("failed to generate sprout NKey: %v", err)
	}
	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		log.Fatalf("failed to generate sprout X25519 key: %v", err)
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
		log.Warnf("no persisted gateway JWT: %v", err)
	}
	go func() {
		// A refresher error means farmer's tenant X25519 key no longer
		// matches the one pinned at enrollment, or the pin is missing
		// (pki.ErrTenantKeyMismatch, pki.ErrTenantKeyNotPinned). Exit non-zero so the
		// service manager records a failure and monitoring alerts; a log
		// line alone would go unnoticed while the gateway JWT expires.
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
	connectOpts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second * 15),
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
	for err != nil {
		log.Warnf("bus connect failed, retrying in 15s: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 15):
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

	test.RegisterNatsConn(nc)
	cmd.RegisterNatsConn(nc)
	cook.RegisterNatsConn(nc)
	// The selfupdate ingredient fetches imas-fleet-signing's live key set
	// over this same SproutRootCA-pinned connection.
	selfupdate.RegisterNatsConn(nc)
	err = natsInit(ctx, nc)
	if err != nil {
		log.Panicf("Error with natsInit: %v", err)
	}
	// After natsInit's subscriptions, so a push arriving during the pull
	// is seen and wins over it.
	go syncStagedRecipe(ctx, cook.SyncOnStartup)
	// Expire old local job logs written by cook runs on this sprout.
	jobs.StartSproutReaper(ctx, jobLogDir, jobLogTTL)
	<-ctx.Done()
	nc.Close()
}
