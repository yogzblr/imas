// Command farmerbus-loader is the account loader sidecar of a bus node
// (docs/briefs/P21-slice2-bus-loader.md §3). It reads Account JWTs from
// the accounts bucket with a read-only credential and pushes them into
// its own bus node over localhost, and reports ready only once the node
// holds every account. It ships in the farmerbus image as a second
// binary; farmerbus itself stays free of object storage.
//
// It reads its own environment (IMAS_LOADER_*) and never loads the
// farmer config. FLAG FOR SECURITY REVIEW.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountloader"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

var (
	GitCommit string
	Tag       string
)

// Environment (brief §4.5). The trust directory is the slice 1 NATS trust
// ConfigMap mount (internal/pki/natstrust.go), under its own variable name.
const (
	envS3Endpoint      = "IMAS_LOADER_S3_ENDPOINT"
	envS3UseSSL        = "IMAS_LOADER_S3_USE_SSL"
	envS3Bucket        = "IMAS_LOADER_S3_BUCKET"
	envS3KeyIDFile     = "IMAS_LOADER_S3_ACCESS_KEY_ID_FILE"
	envS3SecretFile    = "IMAS_LOADER_S3_SECRET_ACCESS_KEY_FILE"
	envNATSURL         = "IMAS_LOADER_NATS_URL"
	envNATSServerName  = "IMAS_LOADER_NATS_SERVER_NAME"
	envCAFile          = "IMAS_LOADER_CA_FILE"
	envSysUserJWTFile  = "IMAS_LOADER_SYS_USER_JWT_FILE"
	envSysUserSeedFile = "IMAS_LOADER_SYS_USER_SEED_FILE"
	envEventSubject    = "IMAS_LOADER_EVENT_SUBJECT"
	envReconcile       = "IMAS_LOADER_RECONCILE_INTERVAL"
	envFullResync      = "IMAS_LOADER_FULL_RESYNC_INTERVAL"
	envPushConcurrency = "IMAS_LOADER_PUSH_CONCURRENCY"
	envPushRate        = "IMAS_LOADER_PUSH_RATE"
	envHealthPort      = "IMAS_LOADER_HEALTH_PORT"
	envTrustDir        = "IMAS_NATS_TRUST_DIR"

	defaultNATSURL    = "tls://127.0.0.1:4222"
	defaultHealthPort = "8081"
	defaultTrustDir   = "/var/run/imas/nats-trust"

	// Trust file names, as internal/pki/natstrust.go writes them. The
	// loader does not import internal/pki: that pulls in internal/config.
	trustOperatorPub        = "operator.pub"
	trustOperatorSigningPub = "operator-signing.pub"
	trustSysAccountPub      = "sys-account.pub"
)

// settings is the parsed environment.
type settings struct {
	S3Endpoint      string
	S3UseSSL        bool
	S3Bucket        string
	S3KeyIDFile     string
	S3SecretFile    string
	NATSURL         string
	NATSServerName  string
	CAFile          string
	SysUserJWTFile  string
	SysUserSeedFile string
	TrustDir        string
	EventSubject    string
	Reconcile       time.Duration
	FullResync      time.Duration
	PushConcurrency int
	PushRate        float64
	HealthPort      string
}

func parseEnv(getenv func(string) string) (settings, error) {
	s := settings{
		S3Endpoint:      getenv(envS3Endpoint),
		S3Bucket:        getenv(envS3Bucket),
		S3KeyIDFile:     getenv(envS3KeyIDFile),
		S3SecretFile:    getenv(envS3SecretFile),
		NATSURL:         or(getenv(envNATSURL), defaultNATSURL),
		NATSServerName:  getenv(envNATSServerName),
		CAFile:          getenv(envCAFile),
		SysUserJWTFile:  getenv(envSysUserJWTFile),
		SysUserSeedFile: getenv(envSysUserSeedFile),
		TrustDir:        or(getenv(envTrustDir), defaultTrustDir),
		EventSubject:    or(getenv(envEventSubject), accountloader.DefaultEventSubject),
		HealthPort:      or(getenv(envHealthPort), defaultHealthPort),
	}
	var errs []error
	for name, v := range map[string]string{
		envS3Endpoint: s.S3Endpoint, envS3Bucket: s.S3Bucket,
		envS3KeyIDFile: s.S3KeyIDFile, envS3SecretFile: s.S3SecretFile,
		envNATSServerName: s.NATSServerName, envCAFile: s.CAFile,
		envSysUserJWTFile: s.SysUserJWTFile, envSysUserSeedFile: s.SysUserSeedFile,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	if strings.Contains(s.S3Endpoint, "://") {
		errs = append(errs, fmt.Errorf("%s is host:port, without a scheme", envS3Endpoint))
	}
	var err error
	if s.S3UseSSL, err = parseBool(getenv(envS3UseSSL), true); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", envS3UseSSL, err))
	}
	if s.Reconcile, err = parseDuration(getenv(envReconcile), accountloader.DefaultReconcileInterval); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", envReconcile, err))
	}
	if s.FullResync, err = parseDuration(getenv(envFullResync), accountloader.DefaultFullResyncInterval); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", envFullResync, err))
	}
	if s.PushConcurrency, err = parsePositiveInt(getenv(envPushConcurrency), accountloader.DefaultPushConcurrency); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", envPushConcurrency, err))
	}
	if s.PushRate, err = parseRate(getenv(envPushRate), accountloader.DefaultPushRate); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", envPushRate, err))
	}
	if p, err := strconv.Atoi(s.HealthPort); err != nil || p < 1 || p > 65535 {
		errs = append(errs, fmt.Errorf("%s: %q is not a port", envHealthPort, s.HealthPort))
	}
	return s, errors.Join(errs...)
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func parseBool(v string, def bool) (bool, error) {
	if v == "" {
		return def, nil
	}
	return strconv.ParseBool(v)
}

func parseDuration(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q is not positive", v)
	}
	return d, nil
}

func parsePositiveInt(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	if n < 1 {
		return 0, fmt.Errorf("%q is not positive", v)
	}
	return n, nil
}

// parseRate reads a push rate as "200" or "200/s".
func parseRate(v string, def float64) (float64, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseFloat(strings.TrimSuffix(v, "/s"), 64)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("%q is not positive", v)
	}
	return n, nil
}

// trust is what the loader needs from the NATS trust ConfigMap.
type trust struct {
	Operators  []string // operator and operator signing public keys
	SysAccount string
}

func loadTrust(dir string) (trust, error) {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("reading trust %s: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	var t trust
	for _, name := range []string{trustOperatorPub, trustOperatorSigningPub} {
		k, err := read(name)
		if err != nil {
			return trust{}, err
		}
		if !nkeys.IsValidPublicOperatorKey(k) {
			return trust{}, fmt.Errorf("trust %s is not an operator public key", name)
		}
		t.Operators = append(t.Operators, k)
	}
	sys, err := read(trustSysAccountPub)
	if err != nil {
		return trust{}, err
	}
	if !nkeys.IsValidPublicAccountKey(sys) {
		return trust{}, fmt.Errorf("trust %s is not an account public key", trustSysAccountPub)
	}
	t.SysAccount = sys
	return t, nil
}

func tlsConfig(caFile, serverName string) (*tls.Config, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caFile)
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
}

// openStore re-reads the credential files on every call, so a rotated
// Secret is picked up when the source re-opens the store.
func openStore(s settings) func() (*objectstore.Store, error) {
	return func() (*objectstore.Store, error) {
		id, err := os.ReadFile(s.S3KeyIDFile)
		if err != nil {
			return nil, err
		}
		secret, err := os.ReadFile(s.S3SecretFile)
		if err != nil {
			return nil, err
		}
		return objectstore.Open(objectstore.Config{
			Endpoint:        s.S3Endpoint,
			AccessKeyID:     strings.TrimSpace(string(id)),
			SecretAccessKey: strings.TrimSpace(string(secret)),
			UseSSL:          s.S3UseSSL,
			Bucket:          s.S3Bucket,
		})
	}
}

// healthMux serves /healthz (the process runs), /readyz (the initial load
// is complete) and /status (the loader's state, no JWTs).
func healthMux(ready func() bool, status func() accountloader.Status) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status())
	})
	return mux
}

func serveHealth(ctx context.Context, port string, mux http.Handler) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("", port))
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()
	go func() {
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("farmerbus-loader: health server: %v", err)
		}
	}()
	return nil
}

func main() {
	code := run()
	log.Flush()
	os.Exit(code)
}

func run() int {
	log.Infof("Starting farmerbus-loader %s (%s)", Tag, GitCommit)
	s, err := parseEnv(os.Getenv)
	if err != nil {
		log.Errorf("farmerbus-loader: %v", err)
		return 2
	}
	tr, err := loadTrust(s.TrustDir)
	if err != nil {
		log.Errorf("farmerbus-loader: %v", err)
		return 2
	}
	tlsCfg, err := tlsConfig(s.CAFile, s.NATSServerName)
	if err != nil {
		log.Errorf("farmerbus-loader: CA %s: %v", s.CAFile, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The node's reconnect handler needs the loader, which needs the node.
	var loader atomic.Pointer[accountloader.Loader]
	node, err := accountloader.DialNode(accountloader.NATSConfig{
		URL:          s.NATSURL,
		TLS:          tlsCfg,
		UserJWTFile:  s.SysUserJWTFile,
		UserSeedFile: s.SysUserSeedFile,
		OnReconnect: func() {
			if l := loader.Load(); l != nil {
				l.NodeReconnected()
			}
		},
	})
	if err != nil {
		log.Errorf("farmerbus-loader: %v", err)
		return 1
	}
	defer node.Close()
	l, err := accountloader.New(accountloader.Config{
		Source:             accountloader.NewStoreSource(openStore(s)),
		Node:               node,
		Trusted:            tr.Operators,
		SysAccount:         tr.SysAccount,
		EventSubject:       s.EventSubject,
		ReconcileInterval:  s.Reconcile,
		FullResyncInterval: s.FullResync,
		PushConcurrency:    s.PushConcurrency,
		PushRate:           s.PushRate,
	})
	if err != nil {
		log.Errorf("farmerbus-loader: %v", err)
		return 1
	}
	loader.Store(l)
	if err := serveHealth(ctx, s.HealthPort, healthMux(l.Ready, l.Status)); err != nil {
		log.Errorf("farmerbus-loader: health listener on port %s: %v", s.HealthPort, err)
		return 1
	}
	if err := l.Run(ctx); err != nil {
		log.Errorf("farmerbus-loader: %v", err)
		return 1
	}
	log.Info("farmerbus-loader stopped")
	return 0
}
