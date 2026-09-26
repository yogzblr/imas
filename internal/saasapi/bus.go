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
func ConnectBus(cfg Config) (*nats.Conn, error) {
	if cfg.NATSURL == "" || cfg.NATSCAFile == "" || cfg.NATSNKeySeedFile == "" || cfg.NATSUserJWT == "" {
		return nil, fmt.Errorf("%w: SAASAPI_NATS_URL, SAASAPI_NATS_CA_FILE, SAASAPI_NATS_NKEY_SEED_FILE and SAASAPI_NATS_USER_JWT are all required", ErrBusNotConfigured)
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
	nc, err := nats.Connect(cfg.NATSURL,
		nats.Name("imas-saasapi"),
		// Request-reply (internal.sprout.action) replies arrive on this
		// prefix: it's the only inbox this service's NATS User may
		// subscribe to, and the only one farmer will reply on
		// (controlplane.SaaSAPIInboxPrefix).
		nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix),
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWTAndSeed(strings.TrimSpace(cfg.NATSUserJWT), seed),
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
	return nc, nil
}
