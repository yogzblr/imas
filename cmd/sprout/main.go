package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
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

func init() {
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
	flag.Parse()
	if err := os.MkdirAll(config.CacheDir, 0o755); err != nil {
		log.Fatalf("failed to create cache directory %s: %v", config.CacheDir, err)
	}
	config.LoadConfig("sprout")
	config.SetJoinTokenFromFlag(*joinToken)
	defer log.Flush()
	if err := certs.GenNKey(false); err != nil {
		log.Fatalf("failed to generate sprout NKey: %v", err)
	}
	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		log.Fatalf("failed to generate sprout X25519 key: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rootCARetryDelay := jety.GetDuration("rootca_retry_delay")
	for err := pki.LoadRootCA("sprout"); err != nil; err = pki.LoadRootCA("sprout") {
		log.Debugf("Error with RootCA: %v", err)
		time.Sleep(rootCARetryDelay)
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
	var err error
	SproutRootCA := config.SproutRootCA
	FarmerInterface := config.FarmerInterface
	FarmerBusURL := config.FarmerBusURL
	// Capture job-log settings before the local tls.Config below shadows the
	// config package identifier.
	jobLogDir := config.JobLogDir
	jobLogTTL := config.JobLogTTL
	// Operator-mode nats-server needs the NATS User JWT from enrollment
	// alongside the NKey seed that signs the CONNECT nonce, the same
	// pairing the repo's bus integration tests connect with.
	userJWT, err := pki.LoadSproutUserJWT()
	if err != nil {
		log.Panicf("failed to load NATS User JWT: %v", err)
	}
	seed, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		log.Panicf("failed to load NKey seed: %v", err)
	}
	opt := nats.UserJWTAndSeed(userJWT, strings.TrimSpace(string(seed)))
	// Presents the current gateway JWT to Envoy's jwt_authn on each
	// websocket handshake. Only consulted when the bus URL is ws(s)://.
	wsAuth := nats.WebSocketConnectionHeadersHandler(pki.GatewayJWTHeaders)
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(SproutRootCA)
	if err != nil || rootPEM == nil {
		log.Panicf("nats: error loading or parsing rootCA file: %v", err)
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %q", SproutRootCA)
	}
	config := &tls.Config{
		ServerName: FarmerInterface,
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	connectOpts := []nats.Option{
		nats.Secure(config), opt, wsAuth,
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
	nc, err := nats.Connect(FarmerBusURL, connectOpts...)
	for err != nil {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 15):
		}
		nc, err = nats.Connect(FarmerBusURL, connectOpts...)
	}
	log.Debugf("Successfully connected to the Farmer")

	if err := log.ConnectNATS(FarmerBusURL); err != nil {
		log.Errorf("Failed to connect log-nats backend: %v", err)
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
