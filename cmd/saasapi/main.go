// Command saasapi runs the external, customer/cloud-platform-facing SaaS API
// service described in docs/design/imas-machine-manager-api-design.md.
// It is a separate binary from farmer/sprout/imas: it owns the `saas`
// schema in the shared PXC cluster and talks to farmer only over
// privileged internal NATS subjects (§2.2), as its own narrowly-scoped
// User under the bus's SYS Account — see
// docs/design/imas-internal-api-account.md and internal/saasapi/bus.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/heartbeat"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/saasapi"
)

func main() {
	cfg, err := saasapi.LoadConfig()
	if err != nil {
		log.Fatalf("saasapi: invalid configuration: %v", err)
	}

	db, err := saasapi.OpenDB(cfg.DSN)
	if err != nil {
		log.Fatalf("saasapi: failed to open saas schema: %v", err)
	}
	// cmd/migrate owns the schema (design doc §4.1a). Wait, retrying with
	// backoff, until it's at the version this build needs: on install the
	// migration Job runs after this pod starts, and during an upgrade a
	// pod can start before the hook finishes.
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("saasapi: failed to open saas schema: %v", err)
	}
	if err := migrations.WaitForSchema(context.Background(), sqlDB, migrations.Saas, log.Warnf); err != nil {
		log.Fatalf("saasapi: saas schema: %v", err)
	}
	log.Infof("saasapi: saas schema is at the version this build needs (%d)", migrations.Saas.Latest())
	saasapi.SetDB(db)

	// Fail closed on Valkey when it's configured: a pod that silently
	// fell back to per-pod limiting for its whole life would quietly
	// multiply the limit by the replica count. Once running, a Valkey
	// error on an individual request falls back to this pod's own limit
	// instead (see saasapi.NewValkeyLimiter). Client-side caching is off:
	// neither the limiter nor heartbeat.IsOnline reads a cacheable value.
	var vc valkey.Client
	if len(cfg.ValkeyAddrs) > 0 {
		vc, err = valkey.NewClient(valkey.ClientOption{InitAddress: cfg.ValkeyAddrs, DisableCache: true})
		if err != nil {
			log.Fatalf("saasapi: failed to connect to Valkey at %v: %v", cfg.ValkeyAddrs, err)
		}
		defer vc.Close()
	}
	initHeartbeatClient(vc)

	// Before NewRouter, which wires the limiter in effect at that moment
	// into POST .../enrollment-keys.
	if err := saasapi.SetEnrollmentKeyRateLimit(cfg.EnrollmentKeyRateLimit, cfg.EnrollmentKeyRateBurst, vc); err != nil {
		log.Fatalf("saasapi: %v", err)
	}
	scope := "per pod (SAASAPI_VALKEY_ADDRS unset)"
	if vc != nil {
		scope = "across all pods via Valkey"
	}
	log.Infof("saasapi: enrollment-key issuance limited to %g req/s per tenant, burst %d, %s",
		cfg.EnrollmentKeyRateLimit, cfg.EnrollmentKeyRateBurst, scope)

	// Tenant recipe upload (SAASAPI_RECIPES_*, IMAS_RECIPE_*). Before
	// NewRouter, which wires the recipe roles and write limiter in effect
	// at that moment. Recipes configured but unusable (an unreadable
	// secret key file, a render limit out of range) stop saasapi rather
	// than leave the routes answering 503.
	if err := saasapi.ConfigureRecipes(cfg.Recipes, vc); err != nil {
		log.Fatalf("saasapi: %v", err)
	}

	// A background context: the JWKS cache's auto-refresh goroutine
	// (see NewAuthConfig) should live for the whole process, not just
	// until shutdown starts.
	authCfg, err := saasapi.NewAuthConfig(context.Background(),
		cfg.InternalAuthSecretCurrent, cfg.InternalAuthSecretPrevious,
		cfg.KeycloakJWKSURL, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		log.Fatalf("saasapi: failed to configure auth: %v", err)
	}
	saasapi.SetAuthConfig(authCfg)

	// Fail closed on the NATS connection (see ConnectBus's doc comment and
	// the design doc's "SaaS API boot posture"): unlike farmer's
	// per-tenant connections, this is the single connection every async
	// tenant operation depends on, and a replica that accepted POST
	// /tenants without it would leave tenants pending with nothing to move
	// them forward. Kubernetes' restart backoff is the retry loop.
	nc, err := saasapi.ConnectBus(cfg)
	if err != nil {
		log.Fatalf("saasapi: failed to connect to the NATS bus: %v", err)
	}
	if err := saasapi.StartProvisioningResultListener(nc); err != nil {
		log.Fatalf("saasapi: failed to subscribe to provisioning results: %v", err)
	}
	saasapi.SetBus(nc)
	log.Infof("saasapi: connected to the NATS bus at %s", nc.ConnectedUrl())

	// Record the key this replica runs with in
	// saas.saasapi_credential_state, after the bus accepted it and before
	// serving: a rotation moves the previous key to prev_pub, which farmer
	// revokes on the SYS Account (pki.EnsureSaaSAPICredential). Fail
	// closed: a replica still on a rotated-out seed must restart and pick
	// up the current one rather than serve with a key being revoked.
	recordCtx, cancelRecord := context.WithTimeout(context.Background(), recordCredentialTimeout)
	err = recordBusCredential(recordCtx, pki.NewSaaSAPICredentialRecorder(db), cfg.NATSUserJWT, sleepCtx)
	cancelRecord()
	if err != nil {
		log.Fatalf("saasapi: %v", err)
	}

	// Plain HTTP: TLS termination is assumed to happen at the gateway
	// (Envoy, workstream H) in front of this service, consistent with the
	// design doc's architecture diagram (§0) showing cloud platforms/tenants
	// reaching the SaaS API over REST without this binary owning certs.
	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      saasapi.RejectUncleanPaths(newRouter(cfg)),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
	// The operator plane is the exception: its own HTTPS listener, never
	// behind the gateway (design doc §2.5). Nil when it's off.
	opSrv, err := newOperatorServer(cfg)
	if err != nil {
		log.Fatalf("saasapi: failed to start the operator plane: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// After SetDB, SetBus and newRouter (which installed the sweeper's
	// settings): the outbox sweeper re-dispatches work no live process is
	// dispatching, on every replica, under row leases
	// (SAASAPI_OUTBOX_*, internal/saasapi/sweeper.go).
	waitSweeper := saasapi.StartOutboxSweeper(ctx)
	serveErr := serve(ctx, srv, opSrv, 15*time.Second)
	stop()
	waitSweeper()

	// After both HTTP servers have stopped (no more dispatches): Drain flushes
	// any buffered publishes and lets in-flight result handlers finish
	// before closing. It's asynchronous, so wait (bounded) for the close.
	if err := nc.Drain(); err != nil {
		log.Errorf("saasapi: draining NATS connection: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); !nc.IsClosed() && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
	if serveErr != nil {
		log.Fatalf("saasapi: %v", serveErr)
	}
	log.Info("saasapi: stopped")
}

// newRouter builds the HTTP router with cfg's feature flags applied. The
// fleet update dispatch flag must be set before saasapi.NewRouter, which
// registers POST .../sprouts/updates and GET .../sprouts/updates/{batch_id}
// only if the flag is on at that moment (SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED,
// default off). The wave gate's clock-skew margin is set with it
// (SAASAPI_FLEET_UPDATE_CLOCK_SKEW, default 30s), and so are the outbox
// settings whose lease TTL every dispatch the handlers start uses
// (SAASAPI_OUTBOX_*).
func newRouter(cfg saasapi.Config) *http.ServeMux {
	saasapi.SetFleetUpdateDispatchEnabled(cfg.FleetUpdateDispatchEnabled)
	saasapi.SetFleetUpdateClockSkew(cfg.FleetUpdateClockSkew)
	saasapi.SetOutboxSweeperSettings(cfg.OutboxSweeper)
	return saasapi.NewRouter()
}

// newOperatorServer builds the operator-plane HTTPS server (release
// registration, design doc §2.5) when SAASAPI_OPERATOR_LISTEN_ADDR is
// set, and returns nil when it isn't. Call it after saasapi.SetDB: its
// handlers use the database.
func newOperatorServer(cfg saasapi.Config) (*http.Server, error) {
	if cfg.OperatorListenAddr == "" {
		return nil, nil
	}
	return saasapi.NewOperatorServer(cfg)
}

// runServer runs one server's ListenAndServe (passed as run) and returns
// its result. Tests replace it to delay a server's start; it's run as is
// in production.
var runServer = func(_ *http.Server, run func() error) error { return run() }

// serve runs the tenant API server and, if operator isn't nil, the
// operator-plane server next to it, until ctx is done or either one
// fails (a listener that can't bind, say). Then it shuts both down
// together, giving in-flight requests up to shutdownTimeout, and returns
// the failure, or nil after a clean shutdown.
//
// serve returns only once every server goroutine has exited. Shutdown
// alone isn't enough: one that runs before a goroutine reaches
// net.Listen has no listener to close, and that goroutine then binds the
// port and only closes it when Serve sees the shutdown, after Shutdown
// has returned.
func serve(ctx context.Context, tenant, operator *http.Server, shutdownTimeout time.Duration) error {
	errc := make(chan error, 2)
	var running sync.WaitGroup
	running.Go(func() {
		log.Infof("saasapi: listening on %s", tenant.Addr)
		if err := runServer(tenant, tenant.ListenAndServe); !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("server failed: %w", err)
		}
	})
	servers := []*http.Server{tenant}
	if operator != nil {
		servers = append(servers, operator)
		running.Go(func() {
			log.Infof("saasapi: operator plane listening on %s (HTTPS)", operator.Addr)
			// The certificate is already in operator.TLSConfig.
			err := runServer(operator, func() error { return operator.ListenAndServeTLS("", "") })
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("operator plane server failed: %w", err)
			}
		})
	}

	var err error
	select {
	case <-ctx.Done():
		log.Info("saasapi: shutdown signal received")
	case err = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Go(func() {
			if err := s.Shutdown(shutdownCtx); err != nil {
				log.Errorf("saasapi: shutting down the server on %s: %v", s.Addr, err)
			}
		})
	}
	wg.Wait()
	// Each ListenAndServe returns promptly once its server is shutting
	// down: Shutdown closed its listener, or Serve refuses the one it
	// opened afterwards.
	running.Wait()
	return err
}

// initHeartbeatClient points internal/heartbeat at the same Valkey client
// the enrollment-key limiter uses, so heartbeat.IsOnline — which fills
// the `connected` field of GET .../sprouts?asset_ids= (§1.4) — reads the
// live keys farmer's heartbeat listener writes. It's the saasapi counterpart of
// cmd/farmer's initValkeyClient. SAASAPI_VALKEY_ADDRS must therefore
// name the Valkey farmer writes heartbeats to. With it unset, vc is nil
// and heartbeat is left unwired: IsOnline reports false for every sprout,
// i.e. `connected: false`.
func initHeartbeatClient(vc valkey.Client) {
	if vc != nil {
		heartbeat.SetClient(vc)
	}
}

const (
	// recordCredentialTimeout bounds recording this replica's NATS key at
	// boot: longer than the rotation lease's TTL, so a replica that waits
	// out another's lapsed lease still gets its turn.
	recordCredentialTimeout = 45 * time.Second
	// recordCredentialRetry is the wait between attempts while another
	// replica holds the rotation lease.
	recordCredentialRetry = time.Second
)

// credentialRecorder is the part of *pki.SaaSAPICredentialRecorder boot
// uses.
type credentialRecorder interface {
	Record(ctx context.Context, pub string) (*pki.SaaSAPICredentialState, bool, error)
}

// recordBusCredential records the public key of userJWT, this replica's
// NATS User credential, as the SaaS API's current key, retrying while
// another replica holds the rotation lease (pki.ErrSaaSAPICredentialBusy)
// until ctx ends. Any other error, a key already rotated out included,
// is returned.
func recordBusCredential(ctx context.Context, rec credentialRecorder, userJWT string, sleep func(context.Context, time.Duration) error) error {
	uc, err := jwt.DecodeUserClaims(strings.TrimSpace(userJWT))
	if err != nil {
		return fmt.Errorf("recording the NATS credential: SAASAPI_NATS_USER_JWT: %w", err)
	}
	for {
		st, rotated, err := rec.Record(ctx, uc.Subject)
		switch {
		case err == nil:
			if rotated && st.PrevPub != "" {
				log.Infof("saasapi: recorded NATS key %s, rotated from %s (version %d); farmer revokes the previous key at its next boot", st.CurrentPub, st.PrevPub, st.Version)
			} else if rotated {
				log.Infof("saasapi: recorded NATS key %s", st.CurrentPub)
			}
			return nil
		case !errors.Is(err, pki.ErrSaaSAPICredentialBusy):
			return fmt.Errorf("recording the NATS credential %s: %w", uc.Subject, err)
		}
		if serr := sleep(ctx, recordCredentialRetry); serr != nil {
			return fmt.Errorf("recording the NATS credential %s: another replica held the rotation lease until the deadline: %w", uc.Subject, err)
		}
	}
}

// sleepCtx waits d, or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
