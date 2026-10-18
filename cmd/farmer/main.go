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
	"encoding/json"
	"errors"
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
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/natsapi"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/pxc"
	"github.com/yogzblr/imas/internal/rbac"
	"github.com/yogzblr/imas/internal/saasapicred"
	"github.com/yogzblr/imas/internal/tenantconn"
	"github.com/yogzblr/imas/internal/valkeyconn"

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

// tenantRegistry is farmer's one source of tenant NATS connections: every
// package that sends to a tenant's bus gets them from its Get, which dials
// lazily (installConnGetter); none keeps a connection of its own. It holds
// every tenant's live NATS connection — one per tenant, including the
// legacy tenant (pki.CurrentTenantID()) under its own entry
// like any other — per docs/design/imas-tenant-context-threading.md's
// Option A, plus every tenant still retrying its first connect. It has its
// own lock (see internal/tenantconn), separate from srvMu above, since it's
// read/written from ConnectFarmer's own goroutines (boot-time enumeration,
// bus CONNECT events, pki.OnTenantProvisioned/OnTenantDeprovisioned
// callbacks, the idle sweeper) and GET /ready independently of the API
// server/heartbeat state srvMu protects. main replaces this empty one with
// newTenantRegistry's before anything dials.
var tenantRegistry = tenantconn.New(tenantconn.Config{})

// Tenant bus idle policy (docs/briefs/P21-slice3-farmer-saasapi-state.md
// §4.5, owner decision 3). A tenant connection is closed once it has been
// unused for the idle TTL and has seen no sprout heartbeat for the
// heartbeat window; the next use dials it again.
const (
	envTenantConnIdleTTL             = "IMAS_TENANT_CONN_IDLE_TTL"
	envTenantConnHeartbeatWindow     = "IMAS_TENANT_CONN_HEARTBEAT_WINDOW"
	defaultTenantConnIdleTTL         = 10 * time.Minute
	defaultTenantConnHeartbeatWindow = 15 * time.Minute
	// tenantSweepInterval is how often idle tenant connections are looked
	// for, so one closes at most this long after it became idle.
	tenantSweepInterval = time.Minute
)

// durationEnv reads a positive duration (time.ParseDuration syntax) from
// the environment variable name, or def when it is unset or empty.
func durationEnv(name string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", name, v, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s=%q: must be positive", name, v)
	}
	return d, nil
}

// newTenantRegistry builds farmer's tenant connection registry from the
// IMAS_TENANT_CONN_* settings, stopping farmer if one is invalid, with dial
// (dialTenant; tests pass their own) as its dialer. A connection that
// closes on its own, including one the NATS client gave up on, is
// redialled at once by connectTenantWithRetry (until ctx ends).
func newTenantRegistry(ctx context.Context, dial tenantconn.Dialer) *tenantconn.Registry {
	idleTTL, err := durationEnv(envTenantConnIdleTTL, defaultTenantConnIdleTTL)
	if err != nil {
		log.Fatalf("tenant bus idle TTL: %v", err)
	}
	window, err := durationEnv(envTenantConnHeartbeatWindow, defaultTenantConnHeartbeatWindow)
	if err != nil {
		log.Fatalf("tenant bus heartbeat window: %v", err)
	}
	log.Noticef("tenant buses: connect on first use, close after %s unused with no sprout heartbeat for %s (%s, %s)",
		idleTTL, window, envTenantConnIdleTTL, envTenantConnHeartbeatWindow)
	return tenantconn.New(tenantconn.Config{
		Dial:            dial,
		IdleTTL:         idleTTL,
		HeartbeatWindow: window,
		OnClosed: func(tenantID string) {
			if ctx.Err() != nil {
				return
			}
			log.Warnf("tenant %s: NATS connection closed; reconnecting", tenantID)
			connectTenantWithRetry(ctx, tenantID)
		},
	})
}

// installConnGetter hands g, the tenant registry, to every package that
// sends to a tenant's bus. Each calls g.Get on every use, so a tenant
// whose connection the idle sweeper closed is dialled again by its next
// cook, command, ping or API call instead of failing as "not connected".
func installConnGetter(g tenantconn.ConnGetter) {
	natsapi.SetConnGetter(g)
	cook.SetFarmerConnGetter(g)
	cmd.SetFarmerConnGetter(g)
	test.SetFarmerConnGetter(g)
}

// legacyTenantReady latches true once ConnectFarmer's boot-time connection
// for the legacy tenant is up and registered. GET /ready gates on it; see
// handlers.GetReady for why it's a one-way latch rather than live state.
var legacyTenantReady atomic.Bool

// readinessTenantStats is what GET /ready reports per-tenant NATS state
// from (handlers.SetTenantConnStats).
func readinessTenantStats() handlers.TenantConnStats {
	connected, total := tenantRegistry.Counts()
	return handlers.TenantConnStats{
		LegacyReady: legacyTenantReady.Load(),
		Connected:   connected,
		Total:       total,
	}
}

func main() {
	if code, ok := runPreConfigSubcommand(os.Args[1:], os.Stdout, os.Stderr); ok {
		os.Exit(code)
	}
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
	// stdout carries only audit JSON lines (initAuditLogger); this goes
	// to stderr with the rest of the terminal log.
	fmt.Fprintf(os.Stderr, "Starting Farmer (core) with bus URL %s\n", config.FarmerBusURL)
	defer log.Flush()
	initRecipeLimits()
	initStorage()
	recipeStore := initRecipeStore()
	jobStore := initJobStore()
	initGatewaySigner()
	initValkeyClient()
	props.LoadStaticProps(config.StaticProps())
	loadCohortRegistry()
	requireConfigRoot()
	initAuditLogger()
	loadAuthPolicy()
	// Fail fast without NATS signing: the trust ConfigMap must be mounted,
	// OpenBao Transit reachable, and its platform keys the trust's.
	if err := pki.CheckNATSAuth(context.Background()); err != nil {
		log.Fatalf("NATS signing is not usable: %v", err)
	}
	// Every Account JWT push writes the accounts bucket first, for the
	// bus nodes' loaders (docs/briefs/P21-slice2-bus-loader.md §7):
	// installed before anything below pushes.
	initAccountPublisher()
	if err := certs.GenCert(); err != nil {
		log.Fatalf("failed to generate TLS certificates: %v", err)
	}
	// Every replica authenticates as the same NATS user: farmer's NKey is
	// the shared Secret at IMAS_FARMER_NKEY_SEED_FILE, never generated.
	if err := checkFarmerNKey(); err != nil {
		log.Fatalf("farmer NKey: %v", err)
	}
	// Sync/push the current sprout accept/deny/reject state to the bus's
	// resolver over the network (see internal/pki/nats.go's ReloadNKeys and
	// resolver.go). This process never embeds a NATS server (pki.NatsServer
	// stays nil here), so the push is the only way this state ever reaches
	// the bus — the same mechanism a SIGHUP or an Accept/Deny call triggers
	// later. It writes no file: the Account JWT is held in memory and
	// kept in the accounts bucket, and farmer's own User JWT
	// (pki.FarmerUserJWTForTenant, used by dialTenantBus below) is signed
	// on first use. A failure here is logged, not fatal: it just means the bus doesn't have the
	// latest state yet, which a later SIGHUP or accept/deny call can still
	// push successfully (e.g. if the bus process hasn't finished starting).
	if err := pki.ReloadNKeys(); err != nil {
		log.Errorf("Failed to push NATS auth state to the bus: %v", err)
	}
	// Mint the SaaS API's own NATS credential — a scoped User under the
	// SYS Account (docs/design/imas-internal-api-account.md) — and revoke
	// the key saasapi rotated out, read from saas.saasapi_credential_state
	// (prev_pub). The JWT reaches the saasapi Deployment through the
	// publish-saasapi-credential Job, not from here. Not fatal: this logs
	// and carries on. A failed push of a key-rotation revocation still
	// mints the credential and is retried at the next boot; any other
	// error (NATS auth bootstrap, the SaaS API seed, the SYS Account JWT)
	// means no credential was minted this boot.
	if _, _, err := pki.EnsureSaaSAPICredential(); err != nil {
		log.Errorf("SaaS API NATS credential: %v", err)
	}
	// Repair the accounts bucket from what this replica now holds (a
	// lost write, a bucket rollback). Not fatal: PushAllAccounts runs it
	// again on every bus (re)connect.
	reconcileCtx, cancelReconcile := context.WithTimeout(context.Background(), time.Minute)
	if err := pki.ReconcileAccounts(reconcileCtx); err != nil {
		log.Errorf("Reconciling the accounts bucket: %v", err)
	}
	cancelReconcile()

	// ctx is cancelled on SIGINT/SIGTERM, driving a graceful shutdown of the
	// cohort refresher, job reaper, every tenant's NATS connection, and the
	// API server. Created here (before StartAPIServer) rather than further
	// down, so the tenant-provisioning hooks below — which spawn goroutines
	// bound to it — are registered before the API server can accept its
	// first enrollment request (POST /v1/enroll is what can trigger
	// ReloadNKeysForTenant's lazy provisioning path).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The periodic relock of deprovisioned tenants (L11): a bad interval
	// stops farmer rather than run without it.
	relockInterval, err := pki.TenantRelockInterval()
	if err != nil {
		log.Fatalf("tenant relock: %v", err)
	}
	tenantRegistry = newTenantRegistry(ctx, dialTenant)
	installConnGetter(tenantRegistry)
	if recipeStore != nil {
		go waitForObjectStore(ctx, recipeStore, "recipe", config.S3Bucket)
	}
	if jobStore != nil {
		go waitForObjectStore(ctx, jobStore, "job", config.S3JobBucket)
	}
	// See docs/design/imas-tenant-context-threading.md's Option A: a
	// newly-provisioned tenant (explicit ProvisionTenant, or enroll.go's
	// lazy ReloadNKeysForTenant path) gets its own dedicated NATS
	// connection and full registration set opened at runtime on the
	// replica that provisioned it (every other replica connects it on the
	// first bus CONNECT into the tenant's Account: see
	// connectOnBusClientConnect); a deprovisioned tenant's connection is
	// closed and its registrations torn down (closing the *nats.Conn tears
	// down every subscription registered on it in one call — no separate
	// unsubscribe bookkeeping needed).
	pki.OnTenantProvisioned(func(tenantID string) { connectTenantWithRetry(ctx, tenantID) })
	pki.OnTenantDeprovisioned(disconnectTenant)
	handlers.SetTenantConnStats(readinessTenantStats)

	StartAPIServer()
	natsapi.StartCohortRefresher(ctx, config.CohortRefreshInterval)
	pki.StartTenantRelocker(ctx, relockInterval)
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
// jobs.SetDB is called, so it's installed here with the rest.
//
// The schema is cmd/migrate's (internal/migrations, design doc §4.1a);
// farmer never creates or alters a table. It waits here, retrying with
// backoff, until the schema is at the version this build needs: on
// install the migration Job runs after farmer starts, and during an
// upgrade a pod can start before the hook finishes.
func initStorage() {
	db, err := pxc.OpenDB(config.PXCDSN)
	if err != nil {
		log.Fatalf("failed to open PXC farmer schema: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to open PXC farmer schema: %v", err)
	}
	if err := migrations.WaitForSchema(context.Background(), sqlDB, migrations.Farmer, log.Warnf); err != nil {
		log.Fatalf("farmer schema: %v", err)
	}
	log.Noticef("farmer schema is at the version this build needs (%d)", migrations.Farmer.Latest())
	installStorage(db)
}

// storageModels is every GORM model in the farmer schema, for this
// package's tests to create in sqlite. PXC's schema comes from cmd/migrate.
func storageModels() []any { return pxc.Models() }

// initRecipeLimits installs the recipe template render limits from the
// farmer chart's farmer.recipes.templateLimits (config.RecipeLimits, the
// IMAS_RECIPE_* variables), stopping farmer if one is out of range.
func initRecipeLimits() {
	if err := installRecipeLimits(config.RecipeLimits); err != nil {
		log.Fatalf("recipe template limits (IMAS_RECIPE_*): %v", err)
	}
	cur := cook.CurrentRenderLimits()
	log.Noticef("recipes: templates limited to %d source bytes, %d rendered bytes, %d bytes per value, %s, %d range iterations per render; %s, %d rendered bytes, %d range iterations and %d includes per cook",
		cur.MaxSourceBytes, cur.MaxRenderedBytes, cur.MaxValueBytes, cur.RenderTimeout, cur.MaxRangeIterations,
		cur.CookRenderTimeout, cur.CookMaxRenderedBytes, cur.CookMaxRangeIterations, cur.MaxIncludes)
}

// installRecipeLimits hands l to cook.SetRenderLimits.
func installRecipeLimits(l config.RecipeTemplateLimits) error {
	return cook.SetRenderLimits(cook.RenderLimits{
		MaxSourceBytes:         l.MaxSourceBytes,
		MaxRenderedBytes:       l.MaxRenderedBytes,
		MaxValueBytes:          l.MaxValueBytes,
		RenderTimeout:          l.RenderTimeout,
		MaxRangeIterations:     l.MaxRangeIterations,
		CookRenderTimeout:      l.CookRenderTimeout,
		CookMaxRenderedBytes:   l.CookMaxRenderedBytes,
		CookMaxRangeIterations: l.CookMaxRangeIterations,
		MaxIncludes:            l.MaxIncludes,
	})
}

// installStorage hands the farmer-schema handle to every package
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
	natsapi.SetRecipeStore(store)
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

// initAccountPublisher installs the accounts bucket publisher
// (pki.SetAccountPublisher) from config.AccountStore. The accounts bucket
// is required: the bus keeps no Account across a restart, and a bus node
// started empty loads every Account from the bucket, so a farmer pushing
// to the bus without writing the bucket would lose every Account at the
// next bus node restart. Farmer always has a bus to push to
// (config.FarmerBusURL defaults to farmerinterface:farmerbusport), so no
// bucket, no endpoint, a bucket that is not its own or no write
// credential of its own stops farmer. The only path without a publisher
// is internal/pki's in-process test bus, which never runs this.
func initAccountPublisher() {
	acc := config.AccountStore
	if err := checkAccountStore(acc, os.Getenv(pki.SproutJWTBucketEnv)); err != nil {
		log.Fatalf("accounts bucket: %v", err)
	}
	store, err := objectstore.Open(objectstore.Config{
		Endpoint:        acc.Endpoint,
		AccessKeyID:     acc.AccessKeyID,
		SecretAccessKey: acc.SecretAccessKey,
		UseSSL:          acc.UseSSL,
		Bucket:          acc.Bucket,
	})
	if err != nil {
		log.Fatalf("accounts bucket: %v", err)
	}
	p, err := pki.NewAccountPublisher(store, acc.EventSubject)
	if err != nil {
		log.Fatalf("accounts bucket: %v", err)
	}
	pki.SetAccountPublisher(p)
	log.Infof("Account JWTs are published to bucket %s at %s (event %s)", acc.Bucket, acc.Endpoint, acc.EventSubject)
}

// checkAccountStore checks the accounts bucket is configured and its
// own: a bucket on an endpoint, separate from the recipe, job and sprout
// JWT buckets, and a separate credential from farmer's object store one
// (§4.5).
func checkAccountStore(acc config.AccountStoreConfig, sproutJWTBucket string) error {
	switch {
	case acc.Bucket == "":
		return fmt.Errorf("no accounts bucket: set %s (the bus keeps no Account across a restart; its loaders read them from this bucket)", config.EnvAccountsS3Bucket)
	case acc.Endpoint == "":
		return fmt.Errorf("no endpoint: set %s or IMAS_S3_ENDPOINT", config.EnvAccountsS3Endpoint)
	case acc.AccessKeyID == "" || acc.SecretAccessKey == "":
		return fmt.Errorf("no write credential: set %s and %s", config.EnvAccountsS3AccessKeyID, config.EnvAccountsS3SecretAccessKey)
	case acc.AccessKeyID == config.S3AccessKeyID:
		return errors.New("the accounts bucket credential must not be farmer's object store credential (IMAS_S3_ACCESS_KEY_ID)")
	}
	for _, other := range []string{config.S3Bucket, config.S3JobBucket, sproutJWTBucket} {
		if other != "" && acc.Bucket == other {
			return fmt.Errorf("bucket %q is also the recipe, job or sprout JWT bucket; the accounts bucket must be its own", acc.Bucket)
		}
	}
	return nil
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

// initValkeyClient connects the Valkey client that connection-state
// heartbeats (internal/heartbeat) and the enrollment/refresh replay cache
// (internal/pki's replaycache.go) read and write through. The $SYS event
// listener itself is registered separately, by initSystemAccountListeners,
// once the bus is reachable. Not fatal if Valkey is unreachable, but
// POST /v1/enroll and /v1/refresh fail closed without it, and /health
// reports the missing client. It authenticates with the password from
// IMAS_VALKEY_PASSWORD_FILE and uses TLS with IMAS_VALKEY_TLS
// (config.ValkeyOptions; LoadConfig already refused unusable settings),
// then warns if Valkey may evict keys (valkeyconn.CheckEviction).
func initValkeyClient() {
	addrs := strings.Split(config.ValkeyAddrs, ",")
	client, err := valkey.NewClient(config.ValkeyOptions.ClientOption(addrs))
	if err != nil {
		log.Errorf("failed to connect to Valkey at %v (%v; POST /v1/enroll and /v1/refresh will fail until it is reachable): %v", addrs, config.ValkeyOptions, err)
		return
	}
	log.Infof("Valkey client connected to %v (%v)", addrs, config.ValkeyOptions)
	valkeyconn.CheckEviction(context.Background(), client, log.Warnf)
	heartbeat.SetClient(client)
	// A sprout that is denied, rejected, unaccepted or deleted loses its
	// Valkey acceptance marker and presence key at once, on every replica.
	pki.OnSproutLeftAccepted(heartbeat.Invalidate)
	pki.SetReplayCacheClient(client)
	handlers.SetReadinessValkey(client)
}

// farmerLogSubject is the SYS Account subject prefix farmer publishes its
// log entries under, one subject per level: imas.logs.farmer.<LEVEL>.
const farmerLogSubject = "imas.logs.farmer"

// initSystemAccountListeners opens farmer's one persistent SYS-account
// connection (pki.ConnectSystemAccount) and registers everything that
// listens on it:
//   - the heartbeat listener: the bus's own $SYS.ACCOUNT.*.CONNECT/
//     DISCONNECT events, maintained as Valkey heartbeat keys (replacing the
//     old synchronous ping-based probeSprout);
//   - the SaaS API's tenant-provisioning bridge: internal.tenant.provision/
//     deprovision (natsapi.RegisterTenantProvisioning), platform-level
//     control-plane subjects that live in the SYS Account — see
//     docs/design/imas-internal-api-account.md;
//   - farmer's own log shipping (log.UseNATSConn), on farmerLogSubject;
//   - lazy tenant connects: every replica connects a tenant when a client
//     connects into that tenant's Account (connectOnBusClientConnect).
//
// Farmer's logs go to the SYS Account, not a tenant's: they are
// process-wide and name every tenant's sprouts, so publishing them into
// any one tenant Account (the legacy tenant's connection included) would
// show that tenant's admins every other tenant's activity.
//
// This dials the bus over the network like any other client, so it works
// whether the bus is a separate process/host (as it is here) or embedded
// locally. The connection retries its initial connect and reconnects
// indefinitely: with provisioning on it, a bus that's briefly unreachable
// at boot (or an outage longer than nats.go's default reconnect budget)
// must not leave farmer permanently without these subscriptions —
// subscriptions registered before the first successful connect are sent
// once it connects.
func initSystemAccountListeners(ctx context.Context) {
	nc, err := pki.ConnectSystemAccount(
		nats.Name("imas-farmer-sys-listener"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(5*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warnf("SYS listener connection lost (heartbeat, tenant provisioning): %v", err)
		}),
		// Every (re)connection to the bus pushes all Account JWTs: the
		// bus mints none of its own (internal/pki/busauth.go), so a bus
		// that restarted on an empty volume, or a new cluster, learns
		// every tenant, revocation and lock-out from this.
		nats.ConnectHandler(func(_ *nats.Conn) {
			go pushAllAccounts("connected")
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info("SYS listener connection re-established")
			go pushAllAccounts("reconnected")
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
	farmerPub := farmerNKeyPublic()
	if _, err := nc.Subscribe(busConnectSubject, func(m *nats.Msg) {
		connectOnBusClientConnect(ctx, m.Data, farmerPub)
	}); err != nil {
		log.Errorf("failed to subscribe to bus CONNECT events (tenants will connect only at boot, on provisioning and on reconnect): %v", err)
	}
	setHeartbeatConn(nc)
	log.Info("SYS listeners registered (heartbeat, tenant provisioning)")
	if err := log.UseNATSConn(nc, farmerLogSubject); err != nil {
		log.Errorf("Failed to attach log-nats backend to the SYS connection: %v", err)
	}
}

// pushAccountsUntilAccepted calls push until it succeeds or ctx ends,
// waiting `every` between attempts.
func pushAccountsUntilAccepted(ctx context.Context, push func() (int, error), every time.Duration) {
	for {
		n, err := push()
		if err == nil {
			log.Infof("Pushed all %d Account JWTs to the bus", n)
			return
		}
		log.Warnf("Pushing all Account JWTs to the bus (%d accepted so far): %v; retrying in %s", n, err, every)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// pushAllAccounts runs pki.PushAllAccounts after the SYS listener
// connected or reconnected to the bus. A failure is logged: the next
// reconnect, and every accept/deny or provisioning push, tries again.
func pushAllAccounts(why string) {
	n, err := pki.PushAllAccounts()
	if err != nil {
		log.Errorf("SYS listener %s: pushing all Account JWTs to the bus: %d accepted, errors: %v", why, n, err)
		return
	}
	log.Infof("SYS listener %s: pushed all %d Account JWTs to the bus", why, n)
}

// initAuditLogger sends audit records to stdout as JSON lines, for the
// log shipper; nothing is written to a file (see internal/audit).
func initAuditLogger() {
	audit.SetGlobal(audit.NewLogger(os.Stdout))
	level := audit.ParseLevel(config.AuditLevel)
	audit.SetLevel(level)
	log.Infof("Audit logging to stdout (level: %s)", level)
}

func loadAuthPolicy() {
	// auth.LoadPolicy warns if the config still sets a removed key, such
	// as dangerously_allow_root, which is ignored and bypasses nothing.
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

// requireConfigRoot stops farmer when the config root is missing or not
// a directory. Farmer never creates it: the root filesystem is read-only
// and the config arrives as a mounted ConfigMap.
func requireConfigRoot() {
	if err := checkConfigRoot(config.ConfigRoot); err != nil {
		log.Fatalf("%v", err)
	}
}

func checkConfigRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("config root %s: %w", root, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("config root %s is not a directory", root)
	}
	return nil
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

// maxFarmerReconnect is no longer a limit: a tenant connection reconnects
// forever (MaxReconnects(-1)). It is only how many failed attempts in a row
// pass before each warning that the tenant still isn't connected.
const maxFarmerReconnect = 30

// tenantBusReconnectWait is the pause between reconnect attempts.
const tenantBusReconnectWait = 15 * time.Second

// tenantBusOptions are the nats.Connect options of tenantID's connection
// besides its address: TLS, farmer's credential (auth), retry of the first
// connect, reconnecting forever, and onClosed as the ClosedHandler, so the
// registry forgets a connection that closed for good (an auth error nats.go
// gives up on, or Close) and the next use dials again.
func tenantBusOptions(tenantID string, tlsCfg *tls.Config, auth nats.Option, onClosed func(*nats.Conn)) []nats.Option {
	var failed atomic.Int64
	return []nats.Option{
		nats.Secure(tlsCfg),
		auth,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(tenantBusReconnectWait),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warnf("Farmer lost its NATS bus connection for tenant %s, reconnecting: %v", tenantID, err)
		}),
		nats.ReconnectErrHandler(func(_ *nats.Conn, err error) {
			if n := failed.Add(1); n%maxFarmerReconnect == 0 {
				log.Warnf("Farmer still not connected to the NATS bus for tenant %s after %d attempts, still retrying: %v", tenantID, n, err)
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			failed.Store(0)
			log.Infof("Farmer reconnected to the NATS bus for tenant %s", tenantID)
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			log.Debugf("Farmer's NATS connection for tenant %s closed", tenantID)
			if onClosed != nil {
				onClosed(c)
			}
		}),
	}
}

// dialTenantBus opens one NATS connection authenticated as farmer's own
// User identity under tenantID's Account (pki.FarmerUserJWTForTenant),
// blocking until connected, ctx is cancelled, or the connection is closed
// for good. See docs/design/imas-tenant-context-threading.md's Option A:
// farmer holds one such connection per tenant instead of a single
// process-global one. There is no attempt limit: the bus being away for a
// long time only delays the connection.
func dialTenantBus(ctx context.Context, tenantID string, onClosed func(*nats.Conn)) (*nats.Conn, error) {
	RootCA := config.RootCA
	BusURL := config.FarmerBusURL
	// Not config.FarmerInterface: that is this process's API bind
	// address, which in Kubernetes is 0.0.0.0 or a pod IP, while the bus
	// is a separate Service whose certificate carries its DNS name.
	busServerName := config.BusTLSServerName()
	// Authenticate as the User identity this tenant's Account granted farmer
	// (see internal/pki/jwtauth-design.md): the User JWT this replica signs
	// with the tenant's signing key on first use and holds in memory, plus
	// this farmer's own NKey seed (the same seed for every tenant — see
	// pki.FarmerUserJWTForTenant's doc comment on why one NKey can hold
	// distinct User JWTs under many Accounts). A bare NKey connect (the
	// pre-JWT-auth shape) can't satisfy a server configured with
	// TrustedOperators/an account resolver — it has no account to belong to
	// without a JWT.
	farmerJWT, err := pki.FarmerUserJWTForTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("signing farmer's User JWT for tenant %s: %w", tenantID, err)
	}
	farmerSeed, err := farmerNKeySeed()
	if err != nil {
		return nil, err
	}
	opt := nats.UserJWTAndSeed(farmerJWT, farmerSeed)
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if err != nil || rootPEM == nil {
		return nil, fmt.Errorf("nats: error loading or parsing rootCA file: %w", err)
	}
	if ok := certPool.AppendCertsFromPEM(rootPEM); !ok {
		log.Errorf("nats: failed to parse root certificate from %v", RootCA)
	}

	tlsCfg := &tls.Config{
		ServerName: busServerName,
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	log.Debugf("Attempting to pair farmer to the NATS bus for tenant %s.", tenantID)
	nc, err := nats.Connect(BusURL, tenantBusOptions(tenantID, tlsCfg, opt, onClosed)...)
	if err != nil {
		return nil, fmt.Errorf("connect error for tenant %s: %w", tenantID, err)
	}
	if nc == nil {
		return nil, fmt.Errorf("nil NATS connection for tenant %s", tenantID)
	}
	// RetryOnFailedConnect: nats.Connect returns at once, reconnecting in
	// the background, so wait here for the first connect.
	for !nc.IsConnected() {
		if nc.IsClosed() {
			return nil, fmt.Errorf("NATS connection for tenant %s closed before it connected: %v", tenantID, nc.LastError())
		}
		select {
		case <-ctx.Done():
			nc.Close()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	log.Debugf("Successfully joined farmer to NATS bus for tenant %s", tenantID)
	return nc, nil
}

// dialTenant is the registry's dialer (tenantconn.Dialer): it connects
// tenantID's bus and boots its registrations on the new connection.
func dialTenant(ctx context.Context, tenantID string, onClosed func(*nats.Conn)) (*nats.Conn, error) {
	nc, err := dialTenantBus(ctx, tenantID, onClosed)
	if err != nil {
		return nil, err
	}
	if err := registerTenantHandlers(nc, tenantID); err != nil {
		nc.Close()
		return nil, err
	}
	return nc, nil
}

// registerTenantHandlers boots tenantID's full subscription set on nc:
// the job, facts and heartbeat listeners plus natsapi.Subscribe, each
// bound to tenantID (docs/design/imas-tenant-context-threading.md's
// Option A). It runs once per new connection (the registry's dialer), so
// a tenant reconnected after an idle close gets the same set again on its
// new connection. Nothing here hands nc to a package for sending: senders
// ask the registry (installConnGetter).
func registerTenantHandlers(nc *nats.Conn, tenantID string) error {
	if _, err := nc.Subscribe("imas.sprouts.announce.>", func(m *nats.Msg) {
		log.Infof("Received a join event (tenant %s): %s\n", tenantID, string(m.Data))
	}); err != nil {
		log.Errorf("Got an error on Subscribe (tenant %s): %+v\n", tenantID, err)
	}

	jobs.RegisterNatsConn(tenantID, nc)
	facts.RegisterFarmerListener(tenantID, nc)

	// Sprouts' periodic heartbeat keeps their Valkey "connected" key fresh
	// (CONNECT sets it once; internal/heartbeat).
	if err := heartbeat.RegisterTenant(nc, tenantID); err != nil {
		return fmt.Errorf("failed to subscribe sprout heartbeats for tenant %s: %w", tenantID, err)
	}
	if err := watchTenantActivity(nc, tenantID, tenantRegistry); err != nil {
		return err
	}

	if err := natsapi.Subscribe(nc, tenantID); err != nil {
		return fmt.Errorf("failed to subscribe NATS API handlers for tenant %s: %w", tenantID, err)
	}
	log.Infof("NATS API handlers registered for tenant %s", tenantID)
	return nil
}

// watchTenantActivity subscribes nc, outside the queue groups so every
// replica sees each message, to what keeps tenantID's connection open in
// r (tenantconn.Registry.Sweep):
//   - sprout heartbeats, which keep it open while the tenant's sprouts are
//     online (owner decision 3);
//   - NATS API requests (natsapi.SubjectPrefix), which count as use, so a
//     long-lived CLI session on a tenant with no sprouts online isn't
//     closed under it after the idle TTL.
//
// Only the arrival counts: no message is read, and a tenant's own clients
// can at most keep their own tenant's connection open.
func watchTenantActivity(nc *nats.Conn, tenantID string, r *tenantconn.Registry) error {
	if _, err := nc.Subscribe(pki.SproutHeartbeatSubjectPattern, func(*nats.Msg) {
		r.TouchHeartbeat(tenantID)
	}); err != nil {
		return fmt.Errorf("failed to watch sprout heartbeats for tenant %s: %w", tenantID, err)
	}
	if _, err := nc.Subscribe(natsapi.SubjectPrefix+">", func(*nats.Msg) {
		r.Touch(tenantID)
	}); err != nil {
		return fmt.Errorf("failed to watch NATS API requests for tenant %s: %w", tenantID, err)
	}
	return nil
}

// connectTenantWithRetry connects tenantID's NATS connection and boots its
// registrations, retrying with exponential backoff on failure instead of
// blocking farmer startup or any other tenant's connection. See point 5 of
// docs/design/imas-tenant-context-threading.md: only the legacy tenant's
// connection is load-bearing enough to fail farmer startup outright (it's
// what every existing single-tenant deployment, the HTTP admin API, and the
// CLI all depend on); every other tenant instead degrades independently —
// a tenant stuck retrying just can't be reached until the retry succeeds.
// The same policy applies however the tenant came to be wanted: found at
// boot, provisioned at runtime (pki.OnTenantProvisioned), a client
// connecting into its Account, or its connection closing. One loop runs
// per tenant: a tenant already connected or already retrying is left to
// that. The loop stops if the tenant is dropped (deprovisioned).
func connectTenantWithRetry(ctx context.Context, tenantID string) {
	// Counted in GET /ready's tenants_total from here on, so a tenant that
	// never manages to connect still shows up as the one that isn't.
	if !tenantRegistry.MarkPending(tenantID) {
		return
	}
	backoff := 5 * time.Second
	const maxBackoff = 5 * time.Minute
	for {
		if ctx.Err() != nil {
			return
		}
		_, err := tenantRegistry.Get(ctx, tenantID)
		if err == nil {
			log.Infof("Connected farmer to NATS bus for tenant %s", tenantID)
			return
		}
		if errors.Is(err, tenantconn.ErrDropped) || !tenantRegistry.Pending(tenantID) {
			return
		}
		log.Errorf("tenant %s: failed to connect to NATS bus, retrying in %s: %v", tenantID, backoff, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if !tenantRegistry.Pending(tenantID) {
			return
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// disconnectTenant closes tenantID's NATS connection on deprovisioning —
// the counterpart to connectTenantWithRetry. A connect in progress for the
// tenant stops too.
func disconnectTenant(tenantID string) {
	if tenantRegistry.Drop(tenantID) {
		log.Infof("Disconnected farmer's NATS connection for tenant %s (deprovisioned)", tenantID)
	}
}

// sweepIdleTenants closes idle tenant connections every interval until ctx
// ends (tenantconn.Registry.Sweep).
func sweepIdleTenants(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, id := range tenantRegistry.Sweep() {
			log.Infof("Closed farmer's idle NATS connection for tenant %s (reconnects on next use)", id)
		}
	}
}

// busConnectSubject is the bus's per-Account client CONNECT event, which
// the SYS listener connection sees for every Account.
const busConnectSubject = "$SYS.ACCOUNT.*.CONNECT"

// busConnectEvent is the part of nats-server's ConnectEventMsg this file
// reads: the client's authenticated user public key and its Account's
// public key.
type busConnectEvent struct {
	Client struct {
		User    string `json:"user"`
		Account string `json:"acc"`
	} `json:"client"`
}

// tenantForBusConnect returns the tenant whose Account a client just
// connected into, from a CONNECT event. ok is false for a malformed event,
// farmer's own connection (user farmerPub; it would otherwise make every
// replica connect every tenant any one replica connects), and an Account
// that tenantFor (pki.TenantIDForAccountPub) does not know as a tenant,
// such as the SYS Account.
func tenantForBusConnect(data []byte, farmerPub string, tenantFor func(accountPub string) (string, error)) (string, bool) {
	var ev busConnectEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return "", false
	}
	if ev.Client.Account == "" || (farmerPub != "" && ev.Client.User == farmerPub) {
		return "", false
	}
	tenantID, err := tenantFor(ev.Client.Account)
	if err != nil {
		return "", false
	}
	return tenantID, true
}

// connectOnBusClientConnect connects a tenant on this replica when a
// client (a sprout coming online, a CLI user) connects into its Account,
// so every replica joins the tenant's queue groups before the client's
// requests arrive. A tenant already connected counts it as use.
func connectOnBusClientConnect(ctx context.Context, data []byte, farmerPub string) {
	tenantID, ok := tenantForBusConnect(data, farmerPub, pki.TenantIDForAccountPub)
	if !ok || tenantRegistry.Touch(tenantID) {
		return
	}
	go connectTenantWithRetry(ctx, tenantID)
}

// farmerNKeyPublic is the public key of farmer's NKey seed, the user every
// farmer connection authenticates as; "" (logged) if it can't be read.
func farmerNKeyPublic() string {
	pub, err := certs.GetPubNKey(true)
	if err != nil {
		log.Errorf("farmer's NKey: %v", err)
		return ""
	}
	return pub
}

// checkFarmerNKey fails unless farmer's NKey seed is mounted and is a
// user key. It only reads: the seed is a read-only Secret mount.
func checkFarmerNKey() error {
	kp, err := certs.LoadFarmerNKey()
	if err != nil {
		return err
	}
	kp.Wipe()
	return nil
}

// farmerNKeySeed is farmer's NKey seed, for a bus connection.
func farmerNKeySeed() (string, error) {
	kp, err := certs.LoadFarmerNKey()
	if err != nil {
		return "", err
	}
	defer kp.Wipe()
	seed, err := kp.Seed()
	if err != nil {
		return "", err
	}
	return string(seed), nil
}

// tenantHasAcceptedSprouts reports whether tenantID has any accepted
// sprout in PXC. Only those tenants are connected at boot: a sprout
// already online when this replica starts sends no new CONNECT, so its
// tenant has to be connected for its heartbeats to be seen at all.
var tenantHasAcceptedSprouts = func(tenantID string) bool {
	return len(pki.GetNKeysByType(tenantID, "accepted").Sprouts) > 0
}

// ConnectFarmer connects the legacy tenant's NATS connection (fatal on
// failure, matching this function's pre-existing behavior — see
// connectTenantWithRetry's doc comment) and keeps it open for the life of
// the process. Every other tenant connects lazily: at boot only the
// provisioned tenants with accepted sprouts (bootTenants), afterwards on a
// client CONNECT into the tenant's Account, on provisioning, or when its
// connection closes; and each closes again once idle (sweepIdleTenants).
// See docs/design/imas-tenant-context-threading.md's Option A and
// docs/briefs/P21-slice3-farmer-saasapi-state.md §4.5.
func ConnectFarmer(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	// Set version info once, process-wide — not tenant-scoped.
	natsapi.SetBuildVersion(config.Version{
		Arch:      runtime.GOOS,
		Compiler:  runtime.Version(),
		GitCommit: GitCommit,
		Tag:       Tag,
	})

	legacyTenant := pki.CurrentTenantID()
	tenantRegistry.Keep(legacyTenant)
	tenantRegistry.MarkPending(legacyTenant)
	// The bus mints no Account JWTs of its own (internal/pki/busauth.go):
	// a bus that started on an empty volume knows the legacy tenant only
	// once core pushes it, and the SYS listener that pushes on every
	// (re)connect is registered only after this dial succeeds. So keep
	// pushing everything until it lands, while the dial retries.
	pushCtx, stopPushing := context.WithCancel(ctx)
	go pushAccountsUntilAccepted(pushCtx, pki.PushAllAccounts, 15*time.Second)
	_, err := tenantRegistry.Get(ctx, legacyTenant)
	stopPushing()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Fatalf("Failed to connect farmer to NATS bus for the legacy tenant %s: %v", legacyTenant, err)
	}
	legacyTenantReady.Store(true)

	// Now that the legacy tenant's connection is up, register the SYS
	// listeners (heartbeat and tenant provisioning, on their own, separate
	// SYS-account connection) — process-wide, not per-tenant: the SYS
	// account already observes every tenant's CONNECT/DISCONNECT events
	// regardless of which Account a connection authenticated into (see
	// internal/heartbeat's own doc comment), and tenant provisioning is a
	// platform-level operation, so one listener is all this ever needs.
	initSystemAccountListeners(ctx)

	// Re-sync every provisioned tenant's Account (its revocations, from
	// PXC) before connecting: ReloadNKeys above covers only the legacy
	// tenant. Sprout User JWTs pick up a newer permission set where they
	// are served (pki.MintOrReuseUserJWT). Not fatal.
	if err := pki.ResyncProvisionedTenants(); err != nil {
		log.Errorf("Failed to re-sync provisioned tenants' NATS auth state: %v", err)
	}

	ids, err := pki.ListProvisionedTenantIDs()
	if err != nil {
		log.Errorf("Failed to list provisioned tenants for connection bootstrap: %v", err)
	}
	for _, id := range bootTenants(ids, legacyTenant, tenantHasAcceptedSprouts) {
		go connectTenantWithRetry(ctx, id)
	}
	go sweepIdleTenants(ctx, tenantSweepInterval)

	// Start the job log reaper to expire old jobs. One reaper per process,
	// not per tenant connection: the job object store is one bucket whose
	// keys are partitioned by tenant (jobs/<tenant>/<sprout>/<jid>/...), and
	// the reaper reads each job's tenant from its keys and expires it by
	// its own full key (see internal/jobs/store.go, "Tenant safety").
	jobs.NewStore().StartReaperCtx(ctx, config.JobLogTTL)

	<-ctx.Done()
	closeTenantBuses(tenantRegistry.All())
}

// bootTenants is which provisioned tenants ConnectFarmer connects at boot:
// those with accepted sprouts (hasSprouts), since only they can have
// sprouts online already. The legacy tenant is skipped: it is connected on
// its own, and a provisioned tenant ID that collides with its string
// (IsValidTenantID doesn't forbid that) must not get a second entry. This
// is a different "is this the legacy tenant" question from internal/pki's
// own reloadNKeysFor (pki.go), which picks the JWT sync path and
// deliberately stays a separate check.
func bootTenants(ids []string, legacyTenant string, hasSprouts func(string) bool) []string {
	var out []string
	for _, id := range ids {
		if id == legacyTenant || !hasSprouts(id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

// closeShellSessions is natsapi.CloseShellSessions, swappable in tests.
var closeShellSessions = natsapi.CloseShellSessions

// shellShutdownTimeout bounds how long farmer's stop waits for its shell
// sessions to end. main waits 10 s for ConnectFarmer, so this stays under.
var shellShutdownTimeout = 5 * time.Second

// closeTenantBuses is farmer's stop for the tenant buses. Shell sessions
// end first, while the connections they relay over are still open, so the
// CLI and the sprout get a sealed CLOSE with farmer-shutdown rather than
// noticing peer-lost 45 s later. A session opened after that (the routes
// stay subscribed until Close) still ends with peer-lost.
func closeTenantBuses(conns []*nats.Conn) {
	endShellSessions(shellShutdownTimeout)
	for _, c := range conns {
		c.Close()
	}
}

// endShellSessions runs closeShellSessions, waiting at most timeout for
// it: a stuck session must not hold up the rest of farmer's stop.
func endShellSessions(timeout time.Duration) {
	// Read here, not in the goroutine, which may outlive this call.
	closeAll := closeShellSessions
	done := make(chan struct{})
	go func() {
		defer close(done)
		closeAll()
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Warnf("timed out after %s waiting for shell sessions to end", timeout)
	}
}
