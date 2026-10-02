// Command fleetreleaser is the only process that signs sprout releases.
// It is a stateless internal HTTPS service: POST /v1/sign takes one
// manifest entry (version, OS, arch, file name, SHA-256 and minimum
// sprout version), validates it with internal/fleetsign, refuses a
// version at or below its configured floor, signs the
// fleetsign.Manifest canonical string (the fleetsign.MessageDomain tag,
// then version|os|arch|file_name|checksum_sha256|min_sprout_version) with
// the OpenBao Transit key imas-fleet-signing (Ed25519), and returns
// {"signature": "v<key version>:<base64>"}. See
// docs/design/cloudxp-machine-manager-api-design.md §2.5.
//
// It has no database access. Its only caller is saasapi's operator-plane
// release registration (POST /v1/operator/fleet-releases), which stores
// the signed rows in saas.fleet_versions; saasapi is the only writer of
// the saas schema.
//
// Why a separate binary rather than a saasapi endpoint or a library:
// saasapi writes saas.fleet_versions. If the same process could also
// sign, anyone who got code execution in saasapi (or its OpenBao
// credentials) could mint a release every sprout would install with no
// further check. Here the two powers sit with different identities:
// saasapi and farmer get read-only Transit access to the key (verify,
// read public key), and this binary gets sign, behind its own format and
// version-floor rules.
//
// Callers authenticate with a bearer token read from a mounted Secret
// file (IMAS_FLEETRELEASER_CALLER_TOKEN_FILE, plus an optional previous
// token during rotation). The listener is TLS only. See
// deploy/fleetreleaser/README.md for why a token rather than mTLS.
//
// FLAG FOR SECURITY REVIEW: the split is only as good as the OpenBao
// policies in deploy/fleetreleaser/ and the custody of the caller token.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/yogzblr/imas/internal/log"
)

// Service configuration, all read once at startup. A change (a rotated
// token, a new certificate, a raised floor) takes effect on restart, as
// with saasapi's own secrets (Reloader rolls the Deployment).
const (
	// EnvListenAddr is the HTTPS listen address. Default ":8443".
	EnvListenAddr = "IMAS_FLEETRELEASER_LISTEN_ADDR"
	// EnvTLSCertFile and EnvTLSKeyFile are the listener's certificate
	// chain and key (PEM). Both required: there is no plain-HTTP mode.
	EnvTLSCertFile = "IMAS_FLEETRELEASER_TLS_CERT_FILE"
	EnvTLSKeyFile  = "IMAS_FLEETRELEASER_TLS_KEY_FILE"
	// EnvCallerTokenFile is the path of the mounted Secret file holding
	// the bearer token saasapi presents. Required.
	EnvCallerTokenFile = "IMAS_FLEETRELEASER_CALLER_TOKEN_FILE"
	// EnvCallerTokenPreviousFile optionally names the previous token,
	// still accepted while saasapi's replicas pick up a rotation.
	EnvCallerTokenPreviousFile = "IMAS_FLEETRELEASER_CALLER_TOKEN_PREVIOUS_FILE"
	// EnvVersionFloor is the version at or below which nothing is
	// signed, canonical semver with a leading 'v' (e.g. "v2.4.0").
	// Required; "v0.0.0" allows every valid version.
	EnvVersionFloor = "IMAS_FLEETRELEASER_VERSION_FLOOR"
)

const defaultListenAddr = ":8443"

func main() {
	os.Exit(run(os.Getenv))
}

// config is the service's configuration from the environment.
type config struct {
	listenAddr string
	certFile   string
	keyFile    string
	tokens     [][]byte
	floor      string
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		listenAddr: getenv(EnvListenAddr),
		certFile:   getenv(EnvTLSCertFile),
		keyFile:    getenv(EnvTLSKeyFile),
		floor:      getenv(EnvVersionFloor),
	}
	if c.listenAddr == "" {
		c.listenAddr = defaultListenAddr
	}
	if c.certFile == "" || c.keyFile == "" {
		return config{}, fmt.Errorf("%s and %s are required: fleetreleaser serves TLS only", EnvTLSCertFile, EnvTLSKeyFile)
	}
	if !validFloor(c.floor) {
		return config{}, fmt.Errorf("%s=%q: want a canonical semver version with a leading 'v', e.g. v2.4.0", EnvVersionFloor, c.floor)
	}
	path := getenv(EnvCallerTokenFile)
	if path == "" {
		return config{}, fmt.Errorf("%s is required", EnvCallerTokenFile)
	}
	tok, err := readCallerToken(path)
	if err != nil {
		return config{}, err
	}
	c.tokens = append(c.tokens, tok)
	if path := getenv(EnvCallerTokenPreviousFile); path != "" {
		prev, err := readCallerToken(path)
		if err != nil {
			return config{}, err
		}
		c.tokens = append(c.tokens, prev)
	}
	return c, nil
}

// run returns the process exit code: 2 for a configuration error, 1 when
// the server fails, 0 after a clean shutdown on SIGINT/SIGTERM.
func run(getenv func(string) string) int {
	cfg, err := loadConfig(getenv)
	if err != nil {
		log.Errorf("fleetreleaser: %v", err)
		return 2
	}
	signer, err := newTransitClientFromEnv()
	if err != nil {
		log.Errorf("%v", err)
		return 2
	}
	cert, err := tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
	if err != nil {
		log.Errorf("fleetreleaser: loading TLS certificate: %v", err)
		return 2
	}

	// Fail fast on an OpenBao identity that can't read the key, or a key
	// that isn't Ed25519. (Whether it can sign shows on the first request:
	// Transit has no dry-run sign.)
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, err = signer.keySet(startCtx)
	cancel()
	if err != nil {
		log.Errorf("fleetreleaser: reading Transit key %s: %v", signer.keyName, err)
		return 1
	}

	svc := &signService{signer: signer, tokens: cfg.tokens, floor: cfg.floor}
	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           svc.handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Infof("fleetreleaser: signing with Transit key %s, version floor %s, listening on %s (TLS)",
			signer.keyName, cfg.floor, cfg.listenAddr)
		errc <- srv.ListenAndServeTLS("", "")
	}()
	select {
	case err := <-errc:
		log.Errorf("fleetreleaser: server failed: %v", err)
		return 1
	case <-ctx.Done():
	}
	log.Info("fleetreleaser: shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Errorf("fleetreleaser: shutdown: %v", err)
	}
	return 0
}
