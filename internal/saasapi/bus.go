package saasapi

// The SaaS API's NATS connection to farmer — the transport for the
// internal.tenant.* and internal.sprout.action control-plane subjects
// (design doc §2.2). This service
// connects as its own narrowly-scoped User under the bus's SYS Account;
// see docs/design/imas-internal-api-account.md for why, and for exactly
// which subjects that User may use (FLAG FOR SECURITY REVIEW).

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
)

// busQueueGroup is the queue group every saasapi replica's result
// subscriptions share, so each internal.tenant.{de,}provisioned.{job_id}
// result is applied by exactly one replica — the same discipline farmer's
// natsCoreQueueGroup applies to requests.
const busQueueGroup = "imas-saasapi"

// bus is the connection dispatchProvisioning/dispatchDeprovisioning
// publish through and dispatchBatch sends internal.sprout.action requests
// on, set once at startup via SetBus — the same injection pattern SetDB
// uses. Nil means "not connected": dispatch logs and leaves the outbox row
// pending (or the action item queued).
var bus *nats.Conn

// SetBus installs the NATS connection dispatch publishes through. Call
// once at startup, after ConnectBus.
func SetBus(nc *nats.Conn) { bus = nc }

// ErrBusNotConfigured means one of the SAASAPI_NATS_* settings is missing.
var ErrBusNotConfigured = errors.New("saasapi: NATS connection not configured")

// validateBusCredential checks the seed/JWT pair before dialing, so a
// half-rotated Secret (new seed, stale JWT, or vice versa) fails at boot
// with a clear message instead of a generic authorization error from the
// bus.
func validateBusCredential(seed, userJWT string) error {
	kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(seed)))
	if err != nil {
		return fmt.Errorf("saasapi: SAASAPI_NATS_NKEY_SEED_FILE does not hold a valid NKey seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return err
	}
	if nkeys.Prefix(pub) != nkeys.PrefixByteUser {
		return fmt.Errorf("saasapi: SAASAPI_NATS_NKEY_SEED_FILE does not hold a User seed")
	}
	uc, err := jwt.DecodeUserClaims(strings.TrimSpace(userJWT))
	if err != nil {
		return fmt.Errorf("saasapi: SAASAPI_NATS_USER_JWT is not a valid NATS User JWT: %w", err)
	}
	if uc.Subject != pub {
		return fmt.Errorf("saasapi: SAASAPI_NATS_USER_JWT was issued to %s, but the seed in SAASAPI_NATS_NKEY_SEED_FILE is %s — the seed and JWT are from different credentials", uc.Subject, pub)
	}
	// The JWT expires (pki.EnvSaaSAPIUserJWTTTL, default 24h); the
	// publisher's refresh CronJob writes a new one well before that, and
	// ESO plus Reloader restart this service with it. An expired one
	// means that chain is broken: say so rather than let the bus refuse
	// it with a generic authorization error.
	if uc.Expires != 0 && !time.Now().Before(time.Unix(uc.Expires, 0)) {
		return fmt.Errorf("saasapi: SAASAPI_NATS_USER_JWT expired at %s: the SaaS API credential publisher (its refresh CronJob) renews it, and ESO delivers it", time.Unix(uc.Expires, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// ConnectBus dials farmer's bus with this service's credential.
//
// Boot posture (see the design doc's "SaaS API boot posture: fail
// closed"): the first connection attempt is not retried here — a
// misconfigured or unreachable bus at startup is returned as an error for
// main to treat as fatal, letting Kubernetes' restart backoff do the
// retrying rather than serving POST /tenants with no way to dispatch.
// Once connected, the connection reconnects indefinitely, so a bus
// restart doesn't permanently sever it.
//
// It also loads this service's box key and platform pin
// (SAASAPI_BOX_PRIV_FILE, SAASAPI_PLATFORM_BOX_PUB) and installs them
// (SetControlPlaneBox) before dialing: farmer accepts only sealed
// internal.* requests, and this service accepts only sealed answers
// (sealedbus.go, J.4), so a connection without them could do nothing but
// fail. Missing or unreadable keys are a startup error.
func ConnectBus(cfg Config) (*nats.Conn, error) {
	if cfg.NATSURL == "" || cfg.NATSCAFile == "" || cfg.NATSNKeySeedFile == "" || cfg.NATSUserJWT == "" {
		return nil, fmt.Errorf("%w: SAASAPI_NATS_URL, SAASAPI_NATS_CA_FILE, SAASAPI_NATS_NKEY_SEED_FILE and SAASAPI_NATS_USER_JWT (or SAASAPI_NATS_USER_JWT_FILE) are all required", ErrBusNotConfigured)
	}
	seedBytes, err := os.ReadFile(cfg.NATSNKeySeedFile)
	if err != nil {
		return nil, fmt.Errorf("saasapi: reading SAASAPI_NATS_NKEY_SEED_FILE: %w", err)
	}
	seed := strings.TrimSpace(string(seedBytes))
	if err := validateBusCredential(seed, cfg.NATSUserJWT); err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile(cfg.NATSCAFile)
	if err != nil {
		return nil, fmt.Errorf("saasapi: reading SAASAPI_NATS_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("saasapi: no certificates found in SAASAPI_NATS_CA_FILE %s", cfg.NATSCAFile)
	}
	box, err := loadControlPlaneBox(cfg)
	if err != nil {
		return nil, err
	}
	creds, err := newBusCredential(seed, cfg.NATSUserJWT, cfg.NATSUserJWTFile)
	if err != nil {
		return nil, err
	}
	nc, err := nats.Connect(cfg.NATSURL,
		nats.Name("imas-saasapi"),
		// Request-reply (internal.sprout.action) replies arrive on this
		// prefix: it's the only inbox this service's NATS User may
		// subscribe to, and the only one farmer will reply on
		// (controlplane.SaaSAPIInboxPrefix).
		nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix),
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWT(creds.userJWT, creds.sign),
		nats.Timeout(10*time.Second),
		nats.RetryOnFailedConnect(false),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil { // nil on an intentional Close/Drain
				log.Warnf("saasapi: disconnected from NATS bus: %v", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Infof("saasapi: reconnected to NATS bus at %s", nc.ConnectedUrl())
		}),
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			subject := ""
			if sub != nil {
				subject = sub.Subject
			}
			log.Errorf("saasapi: NATS async error (subscription %q): %v", subject, err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("saasapi: connecting to NATS bus %s: %w", cfg.NATSURL, err)
	}
	SetControlPlaneBox(box)
	if cfg.NATSUserJWTFile != "" {
		go creds.watch(nc, busJWTWatchInterval)
	}
	return nc, nil
}

// busJWTWatchInterval is how often a SAASAPI_NATS_USER_JWT_FILE is checked
// for a refreshed JWT. The kubelet updates a mounted Secret within about a
// minute of ESO changing it; the refresh lands a third of the JWT's
// lifetime before it expires.
var busJWTWatchInterval = 30 * time.Second

// busCredential is this service's NATS User credential: the seed, and the
// JWT, re-read from its file (when one is configured) at every
// (re)connect, so an expiring JWT is replaced without a restart.
type busCredential struct {
	kp   nkeys.KeyPair
	seed string
	file string

	mu   sync.Mutex
	good string // the last JWT that validated
	used string // the JWT the current connection presented
}

func newBusCredential(seed, initial, file string) (*busCredential, error) {
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("saasapi: SAASAPI_NATS_NKEY_SEED_FILE does not hold a valid NKey seed: %w", err)
	}
	return &busCredential{kp: kp, seed: seed, file: file, good: strings.TrimSpace(initial)}, nil
}

// load re-reads the JWT file and returns the JWT to present: the file's
// when it validates against the seed (validateBusCredential), otherwise
// the last good one, so a half-written or mismatched file never breaks a
// connection that still has a valid JWT.
func (c *busCredential) load() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == "" {
		return c.good
	}
	b, err := os.ReadFile(c.file)
	if err != nil {
		log.Warnf("saasapi: reading SAASAPI_NATS_USER_JWT_FILE, keeping the JWT in use: %v", err)
		return c.good
	}
	next := strings.TrimSpace(string(b))
	if next == c.good {
		return c.good
	}
	if err := validateBusCredential(c.seed, next); err != nil {
		log.Warnf("saasapi: SAASAPI_NATS_USER_JWT_FILE holds an unusable JWT, keeping the one in use: %v", err)
		return c.good
	}
	c.good = next
	return c.good
}

// userJWT is the nats.UserJWTHandler: called at every (re)connect.
func (c *busCredential) userJWT() (string, error) {
	j := c.load()
	c.mu.Lock()
	c.used = j
	c.mu.Unlock()
	return j, nil
}

func (c *busCredential) sign(nonce []byte) ([]byte, error) { return c.kp.Sign(nonce) }

// watch checks the JWT file every interval and, when it holds a valid JWT
// other than the one the connection presented, reconnects so the new one
// is used before the old one expires. It ends when nc is closed.
func (c *busCredential) watch(nc *nats.Conn, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if nc.IsClosed() {
			return
		}
		next := c.load()
		c.mu.Lock()
		changed := next != c.used
		c.mu.Unlock()
		if !changed {
			continue
		}
		log.Infof("saasapi: SAASAPI_NATS_USER_JWT_FILE holds a new JWT; reconnecting to the bus with it")
		if err := nc.ForceReconnect(); err != nil {
			log.Warnf("saasapi: reconnecting with the refreshed NATS JWT: %v", err)
		}
	}
}
