// Command saasapi runs the external, customer/CloudXP-facing SaaS API
// service described in docs/design/cloudxp-machine-manager-api-design.md.
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

	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/heartbeat"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/migrations"
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

	// Before NewOperatorServer, whose registration handler verifies every
	// signature against this key source.
	keys, err := fleetKeySource(cfg)
	if err != nil {
		log.Fatalf("saasapi: %v", err)
	}
	if keys != nil {
		saasapi.SetFleetKeySource(keys)
		log.Infof("saasapi: fleet signing key source configured (read-only, Transit key %s)", keys.KeyName())
	}

	// Plain HTTP: TLS termination is assumed to happen at the gateway
	// (Envoy, workstream H) in front of this service, consistent with the
	// design doc's architecture diagram (§0) showing CloudXP/tenants
	// reaching the SaaS API over REST without this binary owning certs.
	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      newRouter(cfg),
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
	serveErr := serve(ctx, srv, opSrv, 15*time.Second)
	stop()

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
// default off).
func newRouter(cfg saasapi.Config) *http.ServeMux {
	saasapi.SetFleetUpdateDispatchEnabled(cfg.FleetUpdateDispatchEnabled)
	return saasapi.NewRouter()
}

// fleetKeySource builds saasapi's READ-ONLY view of the
// imas-fleet-signing Transit key (IMAS_FLEETSIGN_OPENBAO_*, design doc
// §2.5). POST .../sprouts/updates verifies each catalog row against it,
// and the operator plane's release registration verifies every signature
// fleetreleaser returns against it before storing one. It is nil when
// neither fleet update dispatch nor the operator plane is on, and an
// error when either is on but it isn't configured: a replica that
// accepted rollouts or registrations it couldn't verify would refuse
// every one of them anyway. The token must carry only the
// imas-fleet-verify policy — saasapi already writes saas.fleet_versions
// and must never also be able to sign it (deploy/fleetreleaser/README.md).
func fleetKeySource(cfg saasapi.Config) (*fleetsign.TransitKeySource, error) {
	var needs []string
	if cfg.FleetUpdateDispatchEnabled {
		needs = append(needs, "fleet update dispatch")
	}
	if cfg.OperatorListenAddr != "" {
		needs = append(needs, "the operator plane")
	}
	if len(needs) == 0 {
		return nil, nil
	}
	src, err := fleetsign.NewTransitKeySourceFromEnv()
	if err != nil {
		return nil, fmt.Errorf("%s is enabled but the fleet signing key isn't configured: %w", strings.Join(needs, " and "), err)
	}
	return src, nil
}

// newOperatorServer builds the operator-plane HTTPS server (release
// registration, design doc §2.5) when SAASAPI_OPERATOR_LISTEN_ADDR is
// set, and returns nil when it isn't. Call it after saasapi.SetDB and
// saasapi.SetFleetKeySource: its handlers use both.
func newOperatorServer(cfg saasapi.Config) (*http.Server, error) {
	if cfg.OperatorListenAddr == "" {
		return nil, nil
	}
	return saasapi.NewOperatorServer(cfg)
}

// serve runs the tenant API server and, if operator isn't nil, the
// operator-plane server next to it, until ctx is done or either one
// fails (a listener that can't bind, say). Then it shuts both down
// together, giving in-flight requests up to shutdownTimeout, and returns
// the failure, or nil after a clean shutdown.
func serve(ctx context.Context, tenant, operator *http.Server, shutdownTimeout time.Duration) error {
	errc := make(chan error, 2)
	go func() {
		log.Infof("saasapi: listening on %s", tenant.Addr)
		if err := tenant.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("server failed: %w", err)
		}
	}()
	servers := []*http.Server{tenant}
	if operator != nil {
		servers = append(servers, operator)
		go func() {
			log.Infof("saasapi: operator plane listening on %s (HTTPS)", operator.Addr)
			// The certificate is already in operator.TLSConfig.
			if err := operator.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("operator plane server failed: %w", err)
			}
		}()
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
