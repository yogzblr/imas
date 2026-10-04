package saasapi

// End-to-end coverage for the tenant provisioning bridge
// (docs/design/imas-internal-api-account.md), with nothing in the chain
// mocked:
//
//   POST /v1/tenants (real router, real two-layer Auth)
//     -> saas.tenants row (pending) + saas.provisioning_jobs outbox row
//     -> dispatchProvisioning publishes internal.tenant.provision, over a
//        real TLS NATS connection authenticated with the SaaS API's scoped
//        SYS-Account credential (pki.EnsureSaaSAPICredential)
//     -> a real embedded nats-server configured by pki.ConfigureNats
//        (operator/SYS/resolver — the production auth shape)
//     -> farmer's natsapi.RegisterTenantProvisioning handler, on farmer's
//        SYS connection, calls the real pki.ProvisionTenant (tenant row,
//        Account keys/JWT on disk, resolver push)
//     -> farmer publishes internal.tenant.provisioned.{job_id}
//     -> StartProvisioningResultListener applies it: job succeeded,
//        tenant pending -> active in the saas schema
//     -> GET /v1/tenants/{id}/status (real router) reports it.
//
// It also proves the side effect is real, not just the status flip: the
// new tenant's Account is live on the bus (farmer's per-tenant User JWT
// connects under it), and after DELETE it's gone again.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/natsapi"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// e2eEnv is one fully wired SaaS API + bus + farmer handler stack.
type e2eEnv struct {
	mux        *http.ServeMux
	auth       *testAuthEnv
	saasDB     *gorm.DB
	farmerSYS  *nats.Conn
	farmerSeed []byte
}

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	env := &e2eEnv{}

	// saas schema. One connection: the result listener writes from its
	// own goroutine, and SQLite's shared-cache in-memory mode would
	// otherwise report "table is locked" under concurrent writers.
	env.saasDB = newTestDB(t)
	if sqlDB, err := env.saasDB.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	env.auth = newTestAuthEnv(t)
	env.mux = NewRouter()

	// farmer schema (pki's store), distinct from the saas one.
	pkiDB, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:e2e_pki_%d?mode=memory&cache=shared", time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening pki test db: %v", err)
	}
	if err := pkiDB.AutoMigrate(pki.Models()...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	if sqlDB, err := pkiDB.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	pki.SetDB(pkiDB)
	t.Cleanup(func() { pki.SetDB(nil) })

	// Farmer's on-disk PKI, TLS material, and NKey — the config values
	// pki.ConfigureNats/ProvisionTenant/ConnectSystemAccount read.
	tmp := t.TempDir()
	config.FarmerPKI = filepath.Join(tmp, "pki") + "/"
	config.FarmerInterface = "127.0.0.1"
	// -1, not "0": nats-server maps Port 0 to the default 4222, which
	// collides with other packages' test buses under a parallel
	// `go test ./...`. -1 is nats-server's RANDOM_PORT.
	config.FarmerBusPort = "-1"
	config.FarmerWSPort = ""
	config.FarmerOrganization = "imas-e2e"
	config.RootCA = filepath.Join(tmp, "rootca.pem")
	config.CertFile = filepath.Join(tmp, "cert.pem")
	config.KeyFile = filepath.Join(tmp, "key.pem")
	writeE2ECerts(t, tmp)

	farmerKP, _ := nkeys.CreateUser()
	farmerPub, _ := farmerKP.PublicKey()
	env.farmerSeed, _ = farmerKP.Seed()
	config.NKeyFarmerPubFile = filepath.Join(tmp, "farmer.pub")
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(farmerPub), 0o600); err != nil {
		t.Fatalf("writing farmer pub key: %v", err)
	}

	// The bus, configured exactly as farmerbus configures it.
	opts := pki.ConfigureNats()
	srv, err := nats_server.NewServer(&opts)
	if err != nil {
		t.Fatalf("creating NATS server: %v", err)
	}
	srv.SetLogger(e2eNoopLogger{}, false, false)
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("NATS server did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	addr := srv.Addr().(*net.TCPAddr)
	config.FarmerBusURL = fmt.Sprintf("127.0.0.1:%d", addr.Port)

	// Farmer's side: its SYS listener connection with the real handlers.
	env.farmerSYS, err = pki.ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	t.Cleanup(env.farmerSYS.Close)
	if err := natsapi.RegisterTenantProvisioning(env.farmerSYS); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	if err := env.farmerSYS.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// The SaaS API's side: the credential farmer minted, delivered the
	// way the saasapi Deployment gets it (Config from env), connected and
	// listening exactly as cmd/saasapi/main.go does.
	userJWT, seed, err := pki.EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}
	t.Setenv("SAASAPI_NATS_URL", "nats://"+config.FarmerBusURL)
	t.Setenv("SAASAPI_NATS_CA_FILE", config.RootCA)
	// The seed arrives as a file — the Secret mounted as a volume.
	seedFile := filepath.Join(t.TempDir(), "nkey.seed")
	if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
		t.Fatalf("writing seed file: %v", err)
	}
	t.Setenv("SAASAPI_NATS_NKEY_SEED_FILE", seedFile)
	t.Setenv("SAASAPI_NATS_USER_JWT", userJWT)
	setupE2EControlPlaneKeys(t)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	nc, err := ConnectBus(cfg)
	if err != nil {
		t.Fatalf("ConnectBus: %v", err)
	}
	t.Cleanup(nc.Close)
	if err := StartProvisioningResultListener(nc); err != nil {
		t.Fatalf("StartProvisioningResultListener: %v", err)
	}
	SetBus(nc)
	t.Cleanup(func() { SetBus(nil) })
	return env
}

// setupE2EControlPlaneKeys is J.4's key material, made the production
// way: farmer's control-plane keygen Job writes the platform key and the
// SaaS API box key into OpenBao (here a mock); farmer reads the platform
// key and the SaaS API's public key from there; the SaaS API gets its
// private key as a file and the platform public key as a pin
// (SAASAPI_BOX_PRIV_FILE, SAASAPI_PLATFORM_BOX_PUB), as its External
// Secret would deliver them. Farmer's cluster-wide claims go to a Valkey
// stand-in.
func setupE2EControlPlaneKeys(t *testing.T) {
	t.Helper()
	bao := tenantboxtest.Start(t)
	pki.InvalidatePlatformBoxKeys()
	t.Cleanup(pki.InvalidatePlatformBoxKeys)
	t.Setenv(pki.EnvCPBoxOpenBaoAddr, bao.URL)
	t.Setenv(pki.EnvCPBoxOpenBaoAuthMethod, "token")
	t.Setenv(pki.EnvCPBoxOpenBaoToken, tenantboxtest.Token)
	t.Setenv(pki.EnvCPBoxOpenBaoKVPath, tenantboxtest.BasePath)
	if _, err := pki.EnsureControlPlaneBoxKeys(t.Context()); err != nil {
		t.Fatalf("control-plane keygen: %v", err)
	}
	saas := bao.Versions(tenantboxtest.BasePath + "/saasapi-box")[0].Data
	pubs := bao.Versions(tenantboxtest.BasePath + "/controlplane-pub")[0].Data
	privFile := filepath.Join(t.TempDir(), "saasapi-box.key")
	if err := os.WriteFile(privFile, []byte(saas["priv"]), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAASAPI_BOX_PRIV_FILE", privFile)
	t.Setenv("SAASAPI_PLATFORM_BOX_PUB", pubs["platform_pub"])
	observer, err := pki.LoadSaaSAPIBox(privFile, pubs["platform_pub"])
	if err != nil {
		t.Fatal(err)
	}
	key := func(path, field string) *[32]byte {
		raw, err := base64.StdEncoding.DecodeString(bao.Versions(tenantboxtest.BasePath + path)[0].Data[field])
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s %s: %v", path, field, err)
		}
		var k [32]byte
		copy(k[:], raw)
		return &k
	}
	e2eKeys.farmer = []payloadbox.KeyPair{{PeerPub: key("/controlplane-pub", "saasapi_box_pub"), Priv: key("/platform", "priv")}}
	e2eKeys.observer = observer
	// ConnectBus installs the box it loads; put the package's test box
	// back afterwards.
	t.Cleanup(func() { SetControlPlaneBox(testKeys.saasBox()) })

	mr := miniredis.RunT(t)
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vc.Close)
	pki.SetReplayCacheClient(vc)
	t.Cleanup(func() { pki.SetReplayCacheClient(nil) })
}

// observe subscribes farmer's SYS connection (not a queue member, so it
// sees a copy of every message) to subject.
func (e *e2eEnv) observe(t *testing.T, subject string) *nats.Subscription {
	t.Helper()
	sub, err := e.farmerSYS.SubscribeSync(subject)
	if err != nil {
		t.Fatalf("observing %s: %v", subject, err)
	}
	if err := e.farmerSYS.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return sub
}

func (e *e2eEnv) do(t *testing.T, method, path, tenantID, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	e.auth.setAuthHeaders(r, tenantID)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func (e *e2eEnv) createTenant(t *testing.T, name string) string {
	t.Helper()
	w := e.do(t, "POST", "/v1/tenants", "no-tenant-path-param", fmt.Sprintf(`{"name":%q}`, name))
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/tenants: status %d, body %s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Status != TenantStatusPending {
		t.Fatalf("POST /v1/tenants returned status %q, want pending", resp.Status)
	}
	return resp.TenantID
}

// waitForStatus polls GET /v1/tenants/{id}/status until it leaves from.
func (e *e2eEnv) waitForStatus(t *testing.T, tenantID string, from TenantStatus) tenantStatusResponse {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		w := e.do(t, "GET", "/v1/tenants/"+tenantID+"/status", tenantID, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET status: %d %s", w.Code, w.Body.String())
		}
		var resp tenantStatusResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding status: %v", err)
		}
		if resp.Status != from {
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatalf("tenant %s still %s after 15s", tenantID, from)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (e *e2eEnv) jobFor(t *testing.T, tenantID string, jobType ProvisioningJobType) ProvisioningJob {
	t.Helper()
	var job ProvisioningJob
	if err := e.saasDB.Where("tenant_id = ? AND type = ?", tenantID, jobType).First(&job).Error; err != nil {
		t.Fatalf("loading %s job for %s: %v", jobType, tenantID, err)
	}
	return job
}

func nextJSON[T any](t *testing.T, sub *nats.Subscription, what string) (T, string) {
	t.Helper()
	var v T
	msg, err := sub.NextMsg(10 * time.Second)
	if err != nil {
		t.Fatalf("expected %s: %v", what, err)
	}
	// On the bus it is ciphertext (J.4): opened here with the keys the
	// keygen Job wrote, the way its receiver opens it.
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 || !isEnvelope(msg.Data) {
		t.Fatalf("%s is not sealed on the bus: %v %s", what, msg.Header, msg.Data)
	}
	if err := json.Unmarshal(e2eOpen(t, msg), &v); err != nil {
		t.Fatalf("decoding %s: %v", what, err)
	}
	return v, msg.Subject
}

// isEnvelope reports whether data is a payloadbox envelope.
func isEnvelope(data []byte) bool {
	var env payloadbox.Envelope
	return json.Unmarshal(data, &env) == nil && env.V == payloadbox.Version && len(env.Copies) > 0
}

// e2eKeys is what setupE2EControlPlaneKeys made, for the test to open
// what it observes on the bus.
var e2eKeys struct {
	farmer   []payloadbox.KeyPair // (saasapi box pub, platform priv)
	observer *pki.SaaSAPIBox      // the SaaS API's keys, its own replay guard
}

// e2eOpen opens msg as its receiver would: a request as farmer, a result
// as the SaaS API.
func e2eOpen(t *testing.T, msg *nats.Msg) json.RawMessage {
	t.Helper()
	if w, ok := pki.SaaSAPIRequestWire(msg.Subject); ok {
		_, body, err := payloadbox.OpenCall(msg.Data, e2eKeys.farmer, payloadbox.CallExpect{
			Purpose: w.Purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
			Method: w.Method, Subject: w.Subject,
		})
		if err != nil {
			t.Fatalf("opening the request on %s as farmer: %v", msg.Subject, err)
		}
		return body.Params
	}
	deprovision := strings.HasPrefix(msg.Subject, controlplane.SubjectTenantDeprovisionedPrefix)
	prefix := controlplane.SubjectTenantProvisionedPrefix
	if deprovision {
		prefix = controlplane.SubjectTenantDeprovisionedPrefix
	}
	jobID, _ := controlplane.JobIDFromSubject(msg.Subject, prefix)
	body, err := e2eKeys.observer.OpenTenantResult(deprovision, jobID, msg.Subject, msg.Data)
	if err != nil {
		t.Fatalf("opening the result on %s as the SaaS API: %v", msg.Subject, err)
	}
	return body.Params
}

// dialTenantAccountAsFarmer connects with farmer's User JWT under
// tenantID's own Account — the dedicated per-tenant connection
// cmd/farmer/main.go's dialTenantBus opens. It succeeds only if
// ProvisionTenant really minted that Account and pushed it to the bus.
func (e *e2eEnv) dialTenantAccountAsFarmer(t *testing.T, tenantID string) error {
	t.Helper()
	farmerJWT, err := pki.FarmerUserJWTForTenant(tenantID)
	if err != nil {
		return err
	}
	rootPEM, _ := os.ReadFile(config.RootCA)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	nc, err := nats.Connect(config.FarmerBusURL,
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWTAndSeed(farmerJWT, string(e.farmerSeed)),
		nats.Timeout(5*time.Second),
		nats.NoReconnect(),
	)
	if err != nil {
		return err
	}
	nc.Close()
	return nil
}

func TestProvisioningBridge_EndToEnd_PendingToActiveToOffboarded(t *testing.T) {
	env := newE2EEnv(t)
	requests := env.observe(t, controlplane.SubjectTenantProvision)
	results := env.observe(t, controlplane.SubjectTenantProvisionedWildcard)

	tenantID := env.createTenant(t, "Acme Bank")
	job := env.jobFor(t, tenantID, ProvisioningJobProvision)

	// dispatchProvisioning really published, carrying the job's ID.
	req, _ := nextJSON[controlplane.TenantProvisionRequest](t, requests, "an internal.tenant.provision request")
	if req.JobID != job.ID || req.TenantID != tenantID || req.Name != "Acme Bank" {
		t.Fatalf("published request %+v doesn't match job %s / tenant %s", req, job.ID, tenantID)
	}

	// Farmer's handler ran the real ProvisionTenant and published a result.
	res, subject := nextJSON[controlplane.TenantResult](t, results, "an internal.tenant.provisioned result")
	if subject != controlplane.ProvisionedSubject(job.ID) {
		t.Fatalf("result published on %s, want %s", subject, controlplane.ProvisionedSubject(job.ID))
	}
	if res.Status != controlplane.StatusActive || res.ErrorCode != "" {
		t.Fatalf("farmer reported %+v, want active", res)
	}

	// saasapi's subscriber applied it: pending -> active in the saas schema.
	status := env.waitForStatus(t, tenantID, TenantStatusPending)
	if status.Status != TenantStatusActive {
		t.Fatalf("tenant status = %q (last_error %q), want active", status.Status, status.LastError)
	}
	var tenant Tenant
	if err := env.saasDB.First(&tenant, "id = ?", tenantID).Error; err != nil || tenant.Status != TenantStatusActive {
		t.Fatalf("saas.tenants row = %+v, err %v; want active", tenant, err)
	}
	job = env.jobFor(t, tenantID, ProvisioningJobProvision)
	if job.Status != ProvisioningJobSucceeded || job.Attempts != 1 || job.LastError != "" {
		t.Fatalf("provisioning job = %+v, want succeeded after 1 attempt", job)
	}

	// The side effect is real: pki registered the tenant, and its Account
	// is live on the bus.
	ids, err := pki.ListProvisionedTenantIDs()
	if err != nil {
		t.Fatalf("ListProvisionedTenantIDs: %v", err)
	}
	if !contains(ids, tenantID) {
		t.Fatalf("pki doesn't list %s as provisioned: %v", tenantID, ids)
	}
	if err := env.dialTenantAccountAsFarmer(t, tenantID); err != nil {
		t.Fatalf("expected farmer to connect under the new tenant's Account: %v", err)
	}

	// Offboarding: DELETE -> internal.tenant.deprovision -> real
	// pki.DeprovisionTenant -> offboarded, and the Account is dead on the
	// bus.
	deprovResults := env.observe(t, controlplane.SubjectTenantDeprovisionedWildcard)
	if w := env.do(t, "DELETE", "/v1/tenants/"+tenantID, tenantID, ""); w.Code != http.StatusAccepted {
		t.Fatalf("DELETE: status %d, body %s", w.Code, w.Body.String())
	}
	dres, _ := nextJSON[controlplane.TenantResult](t, deprovResults, "an internal.tenant.deprovisioned result")
	if dres.Status != controlplane.StatusOffboarded {
		t.Fatalf("farmer reported %+v, want offboarded", dres)
	}
	if status := env.waitForStatus(t, tenantID, TenantStatusOffboarding); status.Status != TenantStatusOffboarded {
		t.Fatalf("tenant status = %q (last_error %q), want offboarded", status.Status, status.LastError)
	}
	if djob := env.jobFor(t, tenantID, ProvisioningJobDeprovision); djob.Status != ProvisioningJobSucceeded {
		t.Fatalf("deprovisioning job = %+v, want succeeded", djob)
	}
	if err := env.dialTenantAccountAsFarmer(t, tenantID); err == nil {
		t.Fatal("expected the deprovisioned tenant's Account to be rejected by the bus")
	}
}

// TestProvisioningBridge_EndToEnd_FarmerFailureMovesTenantToFailed makes
// the real pki.ProvisionTenant fail — a regular file squatting where the
// per-tenant Account directory tree must be created, so MkdirAll fails
// even when running as root — and checks the failure makes it all the way
// back: the tenant ends up failed with an error recorded, not pending
// forever. It also checks that the underlying error, whose text names a
// farmer filesystem path, never reaches the bus, the saas schema, or the
// external status response — only the fixed public message does.
func TestProvisioningBridge_EndToEnd_FarmerFailureMovesTenantToFailed(t *testing.T) {
	env := newE2EEnv(t)
	blocker := filepath.Join(config.FarmerPKI, "nats-auth", "tenants")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("planting blocker file: %v", err)
	}
	results := env.observe(t, controlplane.SubjectTenantProvisionedWildcard)

	tenantID := env.createTenant(t, "Doomed Co")
	job := env.jobFor(t, tenantID, ProvisioningJobProvision)

	msg, err := results.NextMsg(10 * time.Second)
	if err != nil {
		t.Fatalf("expected an internal.tenant.provisioned result: %v", err)
	}
	assertNoInternalDetail(t, "the published result", string(msg.Data))
	opened := e2eOpen(t, msg)
	// Not even inside the box: only the fixed code crosses the boundary.
	assertNoInternalDetail(t, "the opened result", string(opened))
	var res controlplane.TenantResult
	if err := json.Unmarshal(opened, &res); err != nil {
		t.Fatalf("decoding result: %v", err)
	}
	if msg.Subject != controlplane.ProvisionedSubject(job.ID) || res.Status != controlplane.StatusFailed || res.ErrorCode != controlplane.ErrorInternal {
		t.Fatalf("farmer reported %+v on %s, want failed/internal_error", res, msg.Subject)
	}

	status := env.waitForStatus(t, tenantID, TenantStatusPending)
	if status.Status != TenantStatusFailed {
		t.Fatalf("tenant status = %q, want failed", status.Status)
	}
	want := publicJobError(job.ID, controlplane.ErrorInternal)
	if status.LastError != want {
		t.Fatalf("GET status last_error = %q, want %q", status.LastError, want)
	}
	assertNoInternalDetail(t, "GET status last_error", status.LastError)
	job = env.jobFor(t, tenantID, ProvisioningJobProvision)
	if job.Status != ProvisioningJobFailed || job.LastError != want {
		t.Fatalf("provisioning job = %+v, want failed with %q", job, want)
	}
	assertNoInternalDetail(t, "saas.provisioning_jobs.last_error", job.LastError)
}

// TestProvisioningBridge_EndToEnd_DeleteNeverProvisionedTenant: a tenant
// whose provisioning failed before farmer recorded anything (here, a
// corrupted operator seed makes the real pki.ProvisionTenant fail before
// it writes a pki_tenants row) is offboarded on DELETE — the real
// pki.DeprovisionTenant finds nothing to tear down, and GET status answers
// 200 with the fixed warning message rather than leaving it stuck in
// offboarding.
func TestProvisioningBridge_EndToEnd_DeleteNeverProvisionedTenant(t *testing.T) {
	env := newE2EEnv(t)
	operatorSeed := filepath.Join(config.FarmerPKI, "nats-auth", "operator.nk")
	good, err := os.ReadFile(operatorSeed)
	if err != nil {
		t.Fatalf("reading operator seed: %v", err)
	}
	if err := os.WriteFile(operatorSeed, []byte("not-a-seed"), 0o600); err != nil {
		t.Fatalf("corrupting operator seed: %v", err)
	}

	tenantID := env.createTenant(t, "Never Provisioned Co")
	if status := env.waitForStatus(t, tenantID, TenantStatusPending); status.Status != TenantStatusFailed {
		t.Fatalf("tenant status = %q, want failed", status.Status)
	}
	if ids, _ := pki.ListProvisionedTenantIDs(); contains(ids, tenantID) {
		t.Fatal("expected farmer to have recorded nothing for the tenant")
	}

	if err := os.WriteFile(operatorSeed, good, 0o600); err != nil {
		t.Fatalf("restoring operator seed: %v", err)
	}
	deprovResults := env.observe(t, controlplane.SubjectTenantDeprovisionedWildcard)
	if w := env.do(t, "DELETE", "/v1/tenants/"+tenantID, tenantID, ""); w.Code != http.StatusAccepted {
		t.Fatalf("DELETE: status %d, body %s", w.Code, w.Body.String())
	}
	dres, _ := nextJSON[controlplane.TenantResult](t, deprovResults, "an internal.tenant.deprovisioned result")
	if dres.Status != controlplane.StatusOffboarded || dres.WarningCode != controlplane.WarningTenantNotProvisioned {
		t.Fatalf("farmer reported %+v, want offboarded with tenant_not_provisioned", dres)
	}

	status := env.waitForStatus(t, tenantID, TenantStatusOffboarding)
	want := controlplane.PublicWarningMessage(controlplane.WarningTenantNotProvisioned)
	if status.Status != TenantStatusOffboarded || status.Warning != want || status.LastError != "" {
		t.Fatalf("GET status = %+v, want offboarded with warning %q", status, want)
	}
}

// TestProvisioningBridge_EndToEnd_DeleteWhileProvisioningIsRejected: with
// farmer's handler not answering, the tenant stays pending, and DELETE is
// refused with 409 rather than racing a deprovision against the in-flight
// provision.
func TestProvisioningBridge_EndToEnd_DeleteWhileProvisioningIsRejected(t *testing.T) {
	env := newE2EEnv(t)
	// Take farmer's handler off the bus so the provision stays in flight.
	env.farmerSYS.Close()

	tenantID := env.createTenant(t, "In Flight Co")
	w := env.do(t, "DELETE", "/v1/tenants/"+tenantID, tenantID, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "provisioning_in_progress") {
		t.Fatalf("DELETE: status %d, body %s; want 409 provisioning_in_progress", w.Code, w.Body.String())
	}
	var n int64
	env.saasDB.Model(&ProvisioningJob{}).Where("tenant_id = ? AND type = ?", tenantID, ProvisioningJobDeprovision).Count(&n)
	if n != 0 {
		t.Fatalf("expected no deprovision job, found %d", n)
	}
}

// assertNoInternalDetail fails if s carries the farmer-side error detail
// the failure test provokes (its text: "mkdir <FarmerPKI>/nats-auth/tenants:
// not a directory").
func assertNoInternalDetail(t *testing.T, where, s string) {
	t.Helper()
	for _, leak := range []string{"not a directory", "mkdir", "nats-auth", config.FarmerPKI} {
		if strings.Contains(s, leak) {
			t.Fatalf("%s leaked internal error detail (%q): %s", where, leak, s)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

type e2eNoopLogger struct{}

func (e2eNoopLogger) Noticef(string, ...any) {}
func (e2eNoopLogger) Warnf(string, ...any)   {}
func (e2eNoopLogger) Fatalf(string, ...any)  {}
func (e2eNoopLogger) Errorf(string, ...any)  {}
func (e2eNoopLogger) Debugf(string, ...any)  {}
func (e2eNoopLogger) Tracef(string, ...any)  {}

// writeE2ECerts writes a throwaway CA and a 127.0.0.1 server certificate
// for the embedded bus (the same shape internal/pki's own test scaffolding
// generates).
func writeE2ECerts(t *testing.T, dir string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"imas-e2e"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA: %v", err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"imas-e2e"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTmpl, &caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}
	leafPriv, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	for path, block := range map[string]*pem.Block{
		filepath.Join(dir, "rootca.pem"): {Type: "CERTIFICATE", Bytes: caDER},
		filepath.Join(dir, "cert.pem"):   {Type: "CERTIFICATE", Bytes: leafDER},
		filepath.Join(dir, "key.pem"):    {Type: "PRIVATE KEY", Bytes: leafPriv},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
}
