// Command farmer is imas's core process: the API server, job/facts/cook
// subscribers, and all sprout-facing business logic. It is one of two
// deployables that make up what used to be a single "farmer" binary (see
// docs/design/imas-fork-roadmap.md workstream C) — the other is cmd/farmerbus,
// the NATS bus process meant to run in the DMZ. Core never embeds a bus of
// its own: it dials config.FarmerBusURL like any other NATS client, the same
// way it always has, and is meant to run outbound-only from a non-DMZ
// network segment.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/api"
	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/certs"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/fleetkeys"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/natsapi"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/pxc"
	"github.com/yogzblr/imas/internal/rbac"
	"github.com/yogzblr/imas/internal/saasapicred"
	"github.com/yogzblr/imas/internal/tenantconn"

	nats "github.com/nats-io/nats.go"
	valkey "github.com/valkey-io/valkey-go"
	"gorm.io/gorm"
)

var (
	// srvMu guards the apiServer package global, read by the shutdown path
	// in main and written/read by handleSIGHUP concurrently.
	srvMu         sync.Mutex
	apiServer     *http.Server
	heartbeatConn *nats.Conn
	GitCommit     string
	Tag           string
)

func setAPIServer(v *http.Server) {
	srvMu.Lock()
	apiServer = v
	srvMu.Unlock()
}

func getAPIServer() *http.Server {
	srvMu.Lock()
	defer srvMu.Unlock()
	return apiServer
}

func setHeartbeatConn(v *nats.Conn) {
	srvMu.Lock()
	heartbeatConn = v
	srvMu.Unlock()
}

func getHeartbeatConn() *nats.Conn {
	srvMu.Lock()
	defer srvMu.Unlock()
	return heartbeatConn
}

// tenantConns holds every tenant's live NATS connection — one per tenant,
// including the legacy tenant (pki.CurrentTenantID()) under its own entry
// like any other — per docs/design/imas-tenant-context-threading.md's
// Option A, plus every tenant still retrying its first connect. It has its
// own lock (see internal/tenantconn), separate from srvMu above, since it's
// read/written from ConnectFarmer's own goroutines (boot-time enumeration,
// pki.OnTenantProvisioned/OnTenantDeprovisioned callbacks) and GET /ready
// independently of the API server/heartbeat state srvMu protects.
var tenantConns = tenantconn.NewRegistry()

// legacyTenantReady latches true once ConnectFarmer's boot-time connection
// for the legacy tenant is up and registered. GET /ready gates on it; see
// handlers.GetReady for why it's a one-way latch rather than live state.
var legacyTenantReady atomic.Bool

// readinessTenantStats is what GET /ready reports per-tenant NATS state
// from (handlers.SetTenantConnStats).
func readinessTenantStats() handlers.TenantConnStats {
	connected, total := tenantConns.Counts()
	return handlers.TenantConnStats{
		LegacyReady: legacyTenantReady.Load(),
		Connected:   connected,
		Total:       total,
	}
}

func main() {
	// Loaded here rather than in init(), so this package's tests don't
	// read or create the system farmer config (/etc/imas/farmer).
	config.LoadConfig("farmer")
	log.SetLogLevel(config.LogLevel)
	// One-shot subcommands run before any server initialization (storage,
	// Valkey, OpenBao PKI/Transit clients): they need only the config and
	// PKI directory loaded above. See internal/saasapicred.
	if len(os.Args) > 1 && os.Args[1] == saasapicred.Command {
		code := saasapicred.Run(os.Args[2:], os.Stderr)
		log.Flush()
		os.Exit(code)
	}
	fmt.Printf("Starting Farmer (core) with bus URL %s\n", config.FarmerBusURL)
	defer log.Flush()
	initStorage()
	recipeStore := initRecipeStore()
	jobStore := initJobStore()
	initGatewaySigner()
	initFleetKeySource()
	initHeartbeatClient()
	props.LoadStaticProps(config.StaticProps())
	loadCohortRegistry()
	createConfigRoot()
	initAuditLogger()
	loadAuthPolicy()
	pki.SetupPKIFarmer()
	if err := certs.GenCert(); err != nil {
		log.Fatalf("failed to generate TLS certificates: %v", err)
	}
	if err := certs.GenNKey(true); err != nil {
		log.Fatalf("failed to generate farmer NKey: %v", err)
	}
	// Sync/push the current sprout accept/deny/reject state to the bus's
	// resolver over the network (see internal/pki/nats.go's ReloadNKeys and
	// resolver.go). This process never embeds a NATS server (pki.NatsServer
	// stays nil here), so the push is the only way this state ever reaches
	// the bus — the same mechanism a SIGHUP or an Accept/Deny call triggers
	// later. It's also what mints this farmer's own User JWT (see
	// pki.FarmerUserJWT, used by ConnectFarmer below) onto disk. A failure
	// here is logged, not fatal: it just means the bus doesn't have the
	// latest state yet, which a later SIGHUP or accept/deny call can still
	// push successfully (e.g. if the bus process hasn't finished starting).
	if err := pki.ReloadNKeys(); err != nil {
		log.Errorf("Failed to push NATS auth state to the bus: %v", err)
	}
	// Mint (or confirm) the SaaS API's own NATS credential — a scoped User
	// under the SYS Account (docs/design/imas-internal-api-account.md) —
	// and persist it to pki.SaaSAPIUserJWTPath() for delivery to the
	// saasapi Deployment. Not fatal: an error here is either a failed push
	// of a key-rotation revocation (retried at the next boot; the new
	// credential is already minted) or a bootstrap problem that
	// ReloadNKeys above will have surfaced too.
	if _, _, err := pki.EnsureSaaSAPICredential(); err != nil {
		log.Errorf("SaaS API NATS credential: %v", err)
	}

	// ctx is cancelled on SIGINT/SIGTERM, driving a graceful shutdown of the
	// cohort refresher, job reaper, every tenant's NATS connection, and the
	// API server. Created here (before StartAPIServer) rather than further
	// down, so the tenant-provisioning hooks below — which spawn goroutines
	// bound to it — are registered before the API server can accept its
	// first enrollment request (POST /v1/enroll is what can trigger
	// ReloadNKeysForTenant's lazy provisioning path).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if recipeStore != nil {
		go waitForObjectStore(ctx, recipeStore, "recipe", config.S3Bucket)
	}
	if jobStore != nil {
		go waitForObjectStore(ctx, jobStore, "job", config.S3JobBucket)
	}
	// See docs/design/imas-tenant-context-threading.md's Option A: a
	// newly-provisioned tenant (explicit ProvisionTenant, or enroll.go's
	// lazy ReloadNKeysForTenant path) gets its own dedicated NATS
	// connection and full registration set opened at runtime; a
	// deprovisioned tenant's connection is closed and its registrations
	// torn down (closing the *nats.Conn tears down every subscription
	// registered on it in one call — no separate unsubscribe bookkeeping
	// needed).
	pki.OnTenantProvisioned(func(tenantID string) { connectTenantWithRetry(ctx, tenantID) })
	pki.OnTenantDeprovisioned(disconnectTenant)
	handlers.SetTenantConnStats(readinessTenantStats)

	StartAPIServer()
	natsapi.StartCohortRefresher(ctx, config.CohortRefreshInterval)
	farmerDone := make(chan struct{})
	sighupDone := make(chan struct{})
	go ConnectFarmer(ctx, farmerDone)
	go handleSIGHUP(ctx, sighupDone)

	<-ctx.Done()
	stop()
	log.Info("Shutdown signal received, stopping farmer...")
	// Stop the SIGHUP handler first so it can't restart the API server
	// concurrently with the shutdown below (bounded, with a warning).
	select {
	case <-sighupDone:
	case <-time.After(20 * time.Second):
		log.Warn("timed out waiting for SIGHUP handler to stop")
	}
	// Wait for ConnectFarmer to close the NATS client (bounded).
	select {
	case <-farmerDone:
	case <-time.After(10 * time.Second):
		log.Warn("timed out waiting for NATS client to close")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if srv := getAPIServer(); srv != nil {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Errorf("API server shutdown error: %v", err)
		}
	}
	if nc := getHeartbeatConn(); nc != nil {
		nc.Close()
	}
	log.Info("Farmer (core) stopped")
}

// initStorage opens the shared PXC connection PKI, props/facts, and RBAC
// read and write through (see internal/pxc, and each package's own
// store.go) — read-through, no in-memory cache, so every farmer replica
// agrees on the same state. This fixes the cross-replica divergence bug
// props/store.go had under its old per-process in-memory cache (see
// docs/design/imas-fork-roadmap.md workstream A).
//
// tenant_id scoping (workstream A.1, FLAG FOR SECURITY REVIEW): every
// query in props/pki/rbac's stores includes tenant_id in the same WHERE
// clause as the row's own key — see their store.go doc comments for the
// current seam (config.FarmerOrganization) and why it isn't yet a
// per-request value.
//
// jobs owns farmer.job_status, the tenant-keyed cook job-status index the
// SaaS API polls (internal/jobs/status_index.go). Indexing is off until
// jobs.SetDB is called, so it's migrated and installed here with the rest.
func initStorage() {
	db, err := pxc.OpenDB(config.PXCDSN, storageModels()...)
	if err != nil {
		log.Fatalf("failed to open PXC farmer schema: %v", err)
	}
	installStorage(db)
}

// storageModels is every GORM model in the farmer schema, migrated in one
// AutoMigrate call by initStorage.
func storageModels() []any {
	models := append(append(props.Models(), pki.Models()...), rbac.Models()...)
	return append(models, jobs.Models()...)
}

// installStorage hands the migrated farmer-schema handle to every package
// that reads or writes through it.
func installStorage(db *gorm.DB) {
	props.SetDB(db)
	pki.SetDB(db)
	rbac.SetDB(db)
	jobs.SetDB(db)
	// Needs the index above: a job is dated by its job_status row.
	jobs.SetReconcileWindow(config.JobReconcileWindow)
	if w := config.JobReconcileWindow; w > 0 {
		log.Noticef("jobs: not recording jobs that start more than %s after dispatch (%s)", w, config.EnvJobReconcileWindow)
	}
	handlers.SetReadinessDB(db)
}

// initRecipeStore opens the object-storage backend recipes are read from
// (see internal/objectstore, internal/cook/store.go) — farmer's old
// local-disk basepath doesn't survive horizontal scaling, since any core
// replica needs to be able to serve any recipe. Git remains the source of
// truth; syncing a merged commit into this bucket is a deploy-time
// concern, not something farmer does at runtime.
//
// The object store is never a reason for farmer to exit or wait. Open
// makes no network calls, so the store is installed immediately and
// returned for waitForObjectStore to check in the background. Until it's
// reachable, recipe requests fail individually, then succeed without a
// restart. If it isn't configured at all, this logs, returns nil, and
// recipe requests fail with "recipe store not configured".
func initRecipeStore() *objectstore.Store {
	store, err := objectstore.Open(objectstore.Config{
		Endpoint:        config.S3Endpoint,
		AccessKeyID:     config.S3AccessKeyID,
		SecretAccessKey: config.S3SecretAccessKey,
		UseSSL:          config.S3UseSSL,
		Bucket:          config.S3Bucket,
	})
	if err != nil {
		log.Errorf("recipe object store not configured (recipe requests will fail until it is): %v", err)
		return nil
	}
	cook.SetStore(store)
	handlers.SetRecipeStore(store)
	return store
}

// initJobStore opens the object-storage backend farmer's job logs are
// written to and read from (see internal/jobs/store.go). Local disk
// (config.JobLogDir) doesn't survive horizontal scaling: a job-status
// query can land on any core replica, so they all need the same job data.
//
// It connects with the recipe store's endpoint and credentials but to its
// own bucket, config.S3JobBucket. The two must differ, because GET /files/
// serves any key in the recipe bucket to any authenticated caller, and job
// logs in that bucket would be readable across sprouts and tenants. A
// missing or shared job bucket is handled like a missing recipe store:
// logged, never fatal, and job events are dropped and job queries fail
// with "job store not configured" until it's fixed.
func initJobStore() *objectstore.Store {
	if config.S3JobBucket != "" && config.S3JobBucket == config.S3Bucket {
		log.Errorf("job object store not configured: job bucket %q must not be the recipe bucket (GET /files/ serves every key in the recipe bucket)", config.S3JobBucket)
		return nil
	}
	store, err := objectstore.Open(objectstore.Config{
		Endpoint:        config.S3Endpoint,
		AccessKeyID:     config.S3AccessKeyID,
		SecretAccessKey: config.S3SecretAccessKey,
		UseSSL:          config.S3UseSSL,
		Bucket:          config.S3JobBucket,
	})
	if err != nil {
		log.Errorf("job object store not configured (job events will be dropped and job requests will fail until it is): %v", err)
		return nil
	}
	jobs.SetStore(store)
	return store
}

// waitForObjectStore checks an object store with exponential backoff
// (objectstore.DefaultRetryPolicy, about 90s) and logs the outcome, so an
// unreachable store or missing bucket shows up in the logs at boot rather
// than on first use. It only reports: it doesn't block anything, and
// giving up changes nothing about how requests are served. It stops
// quietly when ctx (farmer's shutdown context) is cancelled. what names
// the store in log lines ("recipe", "job").
func waitForObjectStore(ctx context.Context, store *objectstore.Store, what, bucket string) {
	policy := objectstore.DefaultRetryPolicy()
	policy.OnRetry = func(attempt int, wait time.Duration, err error) {
		log.Errorf("%s object store not ready (attempt %d/%d), retrying in %s: %v", what, attempt, policy.MaxAttempts, wait.Round(time.Millisecond), err)
	}
	if err := store.WaitReady(ctx, policy); err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Errorf("%s object store still unreachable after retries (%s requests will fail until it's back): %v", what, what, err)
		return
	}
	log.Infof("Connected to %s object store %s (bucket %s)", what, config.S3Endpoint, bucket)
}

// initGatewaySigner wires up the OpenBao Transit-backed signer for
// gateway JWTs (internal/gatewayjwt) — the standard alg:EdDSA companion
// token Envoy's jwt_authn validates, alongside the native NATS User JWT
// workstream B already mints. Deliberately not fatal if unconfigured
// (see EnvOpenBaoAddr etc. in internal/gatewayjwt/obtransit.go): existing
// deployments/dev setups without IMAS_GATEWAY_OPENBAO_* set should still
// start farmer normally — POST /v1/enroll fails closed
// (pki.ErrEnrollmentFailed) rather than farmer refusing to boot, until an
// operator configures OpenBao Transit for this key.
func initGatewaySigner() {
	signer, err := gatewayjwt.NewGatewaySigner(config.GatewayTransitKeyName)
	if err != nil {
		log.Errorf("gateway JWT signer not configured (POST /v1/enroll will fail until it is): %v", err)
		return
	}
	pki.SetGatewaySigner(signer)
	handlers.SetGatewaySigner(signer)
	log.Info("Gateway JWT signer configured")
}

// initFleetKeySource wires up farmer's READ-ONLY view of the
// imas-fleet-signing Transit key (internal/fleetsign, design doc §2.5):
// served ungated as a JWKS, served live to sprouts on
// imas.sprouts.<id>.fleetsigningkeys (internal/fleetkeys — what a sprout
// actually verifies releases against), returned in POST /v1/enroll as a
// bootstrap-only key, and used to re-verify a release before a
// self_update is dispatched. The token behind IMAS_FLEETSIGN_OPENBAO_* must carry only
// deploy/fleetreleaser/policies/imas-fleet-verify.hcl; farmer never signs
// releases (cmd/fleetreleaser does). Not fatal if unconfigured, like
// initGatewaySigner: POST /v1/enroll and self_update fail closed instead.
func initFleetKeySource() {
	src, err := fleetsign.NewTransitKeySourceFromEnv()
	if err != nil {
		log.Errorf("fleet signing key not configured (POST /v1/enroll and self_update will fail until it is): %v", err)
		return
	}
	handlers.SetFleetKeySource(src)
	natsapi.SetFleetKeySource(src)
	fleetkeys.SetKeySource(src)
	log.Infof("Fleet signing key source configured (read-only, Transit key %s)", src.KeyName())
}

// initHeartbeatClient connects the Valkey client connection-state reads
// and writes through (see internal/heartbeat). The $SYS event listener
// itself is registered separately, by initSystemAccountListeners, once the bus
// is reachable.
func initHeartbeatClient() {
	addrs := strings.Split(config.ValkeyAddrs, ",")
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: addrs})
	if err != nil {
		log.Errorf("failed to connect to Valkey at %v: %v", addrs, err)
		return
	}
	heartbeat.SetClient(client)
	handlers.SetReadinessValkey(client)
}

// initSystemAccountListeners opens farmer's one persistent SYS-account
// connection (pki.ConnectSystemAccount) and registers everything that
// listens on it:
//   - the heartbeat listener: the bus's own $SYS.ACCOUNT.*.CONNECT/
//     DISCONNECT events, maintained as Valkey heartbeat keys (replacing the
//     old synchronous ping-based probeSprout);
//   - the SaaS API's tenant-provisioning bridge: internal.tenant.provision/
//     deprovision (natsapi.RegisterTenantProvisioning), platform-level
//     control-plane subjects that live in the SYS Account — see
//     docs/design/imas-internal-api-account.md.
//
// This dials the bus over the network like any other client, so it works
// whether the bus is a separate process/host (as it is here) or embedded
// locally. The connection retries its initial connect and reconnects
// indefinitely: with provisioning on it, a bus that's briefly unreachable
// at boot (or an outage longer than nats.go's default reconnect budget)
// must not leave farmer permanently without these subscriptions —
// subscriptions registered before the first successful connect are sent
// once it connects.
func initSystemAccountListeners() {
	nc, err := pki.ConnectSystemAccount(
		nats.Name("imas-farmer-sys-listener"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(5*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warnf("SYS listener connection lost (heartbeat, tenant provisioning): %v", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info("SYS listener connection re-established")
		}),
	)
	if err != nil {
		log.Errorf("failed to connect the SYS listener to the bus: %v", err)
		return
	}
	if err := heartbeat.RegisterListener(nc); err != nil {
		log.Errorf("failed to register heartbeat listener: %v", err)
		nc.Close()
		return
	}
	if err := natsapi.RegisterTenantProvisioning(nc); err != nil {
		log.Errorf("failed to register tenant provisioning handlers: %v", err)
		nc.Close()
		return
	}
	setHeartbeatConn(nc)
	log.Info("SYS listeners registered (heartbeat, tenant provisioning)")
}

func initAuditLogger() {
	auditDir := config.AuditLogDir
	if auditDir == "" {
		auditDir = "/var/log/imas/audit"
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		log.Errorf("Failed to initialize audit logger at %s: %v", auditDir, err)
		return
	}
	audit.SetGlobal(logger)
	audit.SetIdentityResolver(auth.WhoAmI)
	level := audit.ParseLevel(config.AuditLevel)
	audit.SetLevel(level)
	log.Infof("Audit logging enabled: %s (level: %s)", auditDir, level)
}

func loadAuthPolicy() {
	if auth.DangerouslyAllowRoot() {
		log.Warn("WARNING: dangerously_allow_root is enabled — ALL auth checks are bypassed. Do not use in production!")
	}

	if err := auth.LoadPolicy(); err != nil {
		log.Errorf("Failed to load auth policy: %v", err)
	} else {
		roles := auth.ListRoles()
		users := auth.ListAllUsers()
		log.Infof("Auth policy loaded: %d role(s), %d user(s)", len(roles), len(users))
	}
}

func loadCohortRegistry() {
	registry, err := rbac.LoadCohortsFromConfig()
	if err != nil {
		log.Errorf("Failed to load cohort config: %v", err)
		registry = rbac.NewRegistry()
	}
	if err := registry.ValidateReferences(); err != nil {
		log.Errorf("Cohort reference validation failed: %v", err)
	}
	natsapi.SetCohortRegistry(registry)
	names := registry.List()
	if len(names) > 0 {
		log.Infof("Loaded %d cohort(s): %v", len(names), names)
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

// StartAPIServer starts the farmer's HTTPS server. It handles PKI
// bootstrap (certificate distribution and NKey registration), file
// serving for recipe downloads (farmer:// scheme), and a health
// endpoint for monitoring and automated tooling.
func StartAPIServer() {
	CertFile := config.CertFile
	FarmerInterface := config.FarmerInterface
	FarmerAPIPort := config.FarmerAPIPort
	KeyFile := config.KeyFile
	r := api.NewRouter(CertFile)
	srv := &http.Server{
		Addr:         FarmerInterface + ":" + FarmerAPIPort,
		WriteTimeout: config.APIWriteTimeout,
		ReadTimeout:  config.APIReadTimeout,
		IdleTimeout:  config.APIIdleTimeout,
		Handler:      r,
	}
	setAPIServer(srv)
	go func() {
		if err := srv.ListenAndServeTLS(CertFile, KeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server failed: %v", err)
		}
	}()

	log.Tracef("API server started on %s\n", FarmerInterface+":"+FarmerAPIPort)
}

// handleSIGHUP listens for SIGHUP signals and reloads the API server and
// the NATS auth state this core process pushes to the bus. This allows
// certificate rotation and configuration changes to take effect without a
// full restart. Unlike the bus process's own SIGHUP handler
// (cmd/farmerbus), there's no embedded NATS server here to reload.
func handleSIGHUP(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
		}
		// Re-check cancellation: the select above may have chosen the sighup
		// case even though shutdown was also requested. Don't start a new
		// server if we're shutting down.
		if ctx.Err() != nil {
			return
		}
		log.Info("Received SIGHUP, reloading...")

		// Recompute and push NATS auth state (picks up new sprout keys,
		// config changes) to the bus's resolver.
		if err := pki.ReloadNKeys(); err != nil {
			log.Errorf("Failed to push NATS auth state to the bus: %v", err)
		} else {
			log.Info("NATS auth state pushed to the bus successfully")
		}

		// Gracefully shut down the API server and restart it
		// so it picks up any new TLS certificates
		if srv := getAPIServer(); srv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Errorf("Failed to gracefully shut down API server: %v", err)
			}
			cancel()
			log.Info("API server shut down, restarting...")
		}

		// Reload config before restarting the API server
		config.LoadConfig("farmer")
		props.ClearStaticProps()
		props.LoadStaticProps(config.StaticProps())
		loadCohortRegistry()
		loadAuthPolicy()
		// Don't restart the API server if shutdown was requested while we
		// were reloading.
		if ctx.Err() != nil {
			return
		}
		StartAPIServer()
		log.Info("Servers reloaded successfully")
	}
}

// dialTenantBus opens one NATS connection authenticated as farmer's own
// User identity under tenantID's Account (pki.FarmerUserJWTForTenant),
// blocking until connected, ctx is cancelled, or every reconnect attempt is
// exhausted. See docs/design/imas-tenant-context-threading.md's Option A:
// farmer holds one such connection per tenant instead of a single
// process-global one.
func dialTenantBus(ctx context.Context, tenantID string) (*nats.Conn, error) {
	var connectionAttempts atomic.Int64
	connectionAttempts.Store(1)
	maxFarmerReconnect := 30
	RootCA := config.RootCA
	BusURL := config.FarmerBusURL
	FarmerInterface := config.FarmerInterface
	if FarmerInterface == "0.0.0.0" {
		FarmerInterface = "localhost"
	}
	// Authenticate as the User identity this tenant's Account granted farmer
	// (see internal/pki/jwtauth-design.md): the User JWT minted by
	// ReloadNKeys/ReloadNKeysForTenant/ProvisionTenant, plus this farmer's
	// own NKey seed (the same seed for every tenant — see
	// pki.FarmerUserJWTForTenant's doc comment on why one NKey can hold
	// distinct User JWTs under many Accounts). A bare NKey connect (the
	// pre-JWT-auth shape) can't satisfy a server configured with
	// TrustedOperators/an account resolver — it has no account to belong to
	// without a JWT.
	farmerJWT, err := pki.FarmerUserJWTForTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("farmer User JWT not found for tenant %s (ReloadNKeys/ReloadNKeysForTenant/ProvisionTenant must mint it before connecting to the bus): %w", tenantID, err)
	}
	farmerSeed, err := os.ReadFile(config.NKeyFarmerPrivFile)
	if err != nil {
		return nil, err
	}
	opt := nats.UserJWTAndSeed(farmerJWT, string(farmerSeed))
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if err != nil || rootPEM == nil {
		return nil, fmt.Errorf("nats: error loading or parsing rootCA file: %w", err)
	}
	if ok := certPool.AppendCertsFromPEM(rootPEM); !ok {
		log.Errorf("nats: failed to parse root certificate from %v", RootCA)
	}

	tlsCfg := &tls.Config{
		ServerName: FarmerInterface,
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	log.Debugf("Attempting to pair farmer to the NATS bus for tenant %s.", tenantID)
	nc, err := nats.Connect(BusURL,
		nats.Secure(tlsCfg),
		opt,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(maxFarmerReconnect),
		nats.ReconnectWait(time.Second*15),
		nats.DisconnectHandler(func(_ *nats.Conn) {
			log.Warnf("WARN: Reconnecting farmer to NATS bus for tenant %s, attempt: %d\n", tenantID, connectionAttempts.Add(1))
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connect error for tenant %s: %w", tenantID, err)
	}
	if nc == nil {
		return nil, fmt.Errorf("nil NATS connection for tenant %s", tenantID)
	}
	for !nc.IsConnected() {
		attempts := connectionAttempts.Add(1)
		log.Debugf("Attempting to pair farmer to NATS bus for tenant %s (attempt %d/%d).", tenantID, attempts, maxFarmerReconnect)
		if attempts >= int64(maxFarmerReconnect) {
			nc.Close()
			return nil, fmt.Errorf("failed to connect tenant %s to NATS %d times", tenantID, attempts)
		}
		select {
		case <-ctx.Done():
			nc.Close()
			return nil, ctx.Err()
		case <-time.After(time.Second * 15):
		}
	}
	log.Debugf("Successfully joined farmer to NATS bus for tenant %s", tenantID)
	return nc, nil
}

// registerTenantHandlers boots tenantID's full registration set on nc:
// every RegisterNatsConn-style ingredient registration plus
// natsapi.Subscribe, each bound to tenantID (docs/design/
// imas-tenant-context-threading.md's Option A). Records nc in tenantConns
// on success so it can be closed later (process shutdown, or
// disconnectTenant on deprovisioning).
func registerTenantHandlers(nc *nats.Conn, tenantID string) error {
	if _, err := nc.Subscribe("imas.sprouts.announce.>", func(m *nats.Msg) {
		log.Infof("Received a join event (tenant %s): %s\n", tenantID, string(m.Data))
	}); err != nil {
		log.Errorf("Got an error on Subscribe (tenant %s): %+v\n", tenantID, err)
	}

	test.RegisterFarmerNatsConn(tenantID, nc)
	cmd.RegisterFarmerNatsConn(tenantID, nc)
	cook.RegisterFarmerNatsConn(tenantID, nc)
	jobs.RegisterNatsConn(tenantID, nc)
	facts.RegisterFarmerListener(tenantID, nc)
	if err := fleetkeys.RegisterFarmerListener(tenantID, nc); err != nil {
		log.Errorf("%v", err)
	}

	if err := natsapi.Subscribe(nc, tenantID); err != nil {
		return fmt.Errorf("failed to subscribe NATS API handlers for tenant %s: %w", tenantID, err)
	}
	log.Infof("NATS API handlers registered for tenant %s", tenantID)
	tenantConns.Set(tenantID, nc)
	return nil
}

// connectTenantWithRetry connects tenantID's NATS connection and boots its
// registrations, retrying with exponential backoff on failure instead of
// blocking farmer startup or any other tenant's connection. See point 5 of
// docs/design/imas-tenant-context-threading.md: only the legacy tenant's
// connection is load-bearing enough to fail farmer startup outright (it's
// what every existing single-tenant deployment, the HTTP admin API, and the
// CLI all depend on); every dynamically-provisioned tenant instead degrades
// independently — a tenant stuck retrying just can't be reached until the
// retry succeeds, the same "not misattributed, genuinely unreachable"
// ceiling this whole effort is about, now scoped to one tenant instead of
// every tenant but one. This same policy applies whether the tenant was
// enumerated at boot (ConnectFarmer) or provisioned at runtime
// (pki.OnTenantProvisioned) — deliberately consistent between the two, per
// the design doc's "don't leave this undecided or inconsistent" ask.
func connectTenantWithRetry(ctx context.Context, tenantID string) {
	// Counted in GET /ready's tenants_total from here on, so a tenant that
	// never manages to connect still shows up as the one that isn't.
	tenantConns.MarkPending(tenantID)
	backoff := 5 * time.Second
	const maxBackoff = 5 * time.Minute
	for {
		if ctx.Err() != nil {
			return
		}
		nc, err := dialTenantBus(ctx, tenantID)
		if err == nil {
			if regErr := registerTenantHandlers(nc, tenantID); regErr != nil {
				log.Errorf("tenant %s: %v", tenantID, regErr)
				nc.Close()
			} else {
				log.Infof("Connected farmer to NATS bus for tenant %s", tenantID)
				return
			}
		} else {
			log.Errorf("tenant %s: failed to connect to NATS bus, retrying in %s: %v", tenantID, backoff, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// disconnectTenant closes tenantID's NATS connection and removes it from
// every package that registered outbound state for it — the deprovisioning
// counterpart to connectTenantWithRetry. Closing the underlying *nats.Conn
// tears down every subscription registered on it (natsapi's routes, the
// box-key listener, cook/jobs/facts's listeners) in one call, so no
// separate unsubscribe bookkeeping is needed to avoid leaked goroutines or
// subscriptions.
func disconnectTenant(tenantID string) {
	nc := tenantConns.Remove(tenantID)
	if nc == nil {
		return
	}
	nc.Close()
	test.UnregisterFarmerNatsConn(tenantID)
	cmd.UnregisterFarmerNatsConn(tenantID)
	cook.UnregisterFarmerNatsConn(tenantID)
	natsapi.ClearNatsConn(tenantID)
	log.Infof("Disconnected farmer's NATS connection for tenant %s (deprovisioned)", tenantID)
}

// ConnectFarmer connects the legacy tenant's NATS connection (fatal on
// failure, matching this function's pre-existing behavior — see
// connectTenantWithRetry's doc comment), then opens one additional
// connection for every other already-provisioned tenant found in PXC, and
// finally wires up cmd/farmer/main.go's runtime provisioning/deprovisioning
// hooks (registered in main, before this is called, so a race with an
// enrollment arriving immediately isn't possible) so tenants provisioned
// later in this process's lifetime get connected too. See
// docs/design/imas-tenant-context-threading.md's Option A.
func ConnectFarmer(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	if err := log.ConnectNATS(config.FarmerBusURL); err != nil {
		log.Errorf("Failed to connect log-nats backend: %v", err)
	}

	// Set version info once, process-wide — not tenant-scoped.
	natsapi.SetBuildVersion(config.Version{
		Arch:      runtime.GOOS,
		Compiler:  runtime.Version(),
		GitCommit: GitCommit,
		Tag:       Tag,
	})

	legacyTenant := pki.CurrentTenantID()
	tenantConns.MarkPending(legacyTenant)
	nc, err := dialTenantBus(ctx, legacyTenant)
	if err != nil {
		log.Fatalf("Failed to connect farmer to NATS bus for the legacy tenant %s: %v", legacyTenant, err)
	}
	if err := registerTenantHandlers(nc, legacyTenant); err != nil {
		log.Fatalf("%v", err)
	}
	legacyTenantReady.Store(true)

	// Now that the legacy tenant's connection is up, register the SYS
	// listeners (heartbeat and tenant provisioning, on their own, separate
	// SYS-account connection) — process-wide, not per-tenant: the SYS
	// account already observes every tenant's CONNECT/DISCONNECT events
	// regardless of which Account a connection authenticated into (see
	// internal/heartbeat's own doc comment), and tenant provisioning is a
	// platform-level operation, so one listener is all this ever needs.
	initSystemAccountListeners()

	ids, err := pki.ListProvisionedTenantIDs()
	if err != nil {
		log.Errorf("Failed to list provisioned tenants for connection bootstrap: %v", err)
	}
	for _, id := range ids {
		// Defensive, not load-bearing: ListProvisionedTenantIDs only ever
		// returns pki_tenants rows, and the legacy tenant
		// (pki.CurrentTenantID()) never gets one of those — see
		// pki.GetTenantAccountPub's own doc comment. This guards only
		// against a dynamically-provisioned tenant ID that happens to
		// collide with the legacy tenant's string (IsValidTenantID doesn't
		// forbid that), which would otherwise try to open a second,
		// redundant connection already covered by dialTenantBus above.
		// This is a different "is this the legacy tenant" question from
		// internal/pki's own reloadNKeysFor (pki.go) — that one picks
		// which on-disk JWT layout/sync path to use (the flat legacy path
		// vs. tenants/<id>/) and deliberately stays a separate check (see
		// its own doc comment on why collapsing it would orphan the legacy
		// tenant's sprouts) — not something this connection-bootstrap loop
		// should also decide.
		if id == legacyTenant {
			continue
		}
		go connectTenantWithRetry(ctx, id)
	}

	// Start the job log reaper to expire old jobs — process-wide, not
	// per-tenant: job storage (the job object store) isn't tenant-
	// partitioned (see internal/jobs.RegisterNatsConn's own doc comment).
	jobs.NewStore().StartReaperCtx(ctx, config.JobLogTTL)

	<-ctx.Done()
	for _, c := range tenantConns.All() {
		c.Close()
	}
}
