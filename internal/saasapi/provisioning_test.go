package saasapi

// Unit coverage for provisioning.go/bus.go's edge cases. The happy and
// failure paths through the whole real chain are in
// provisioning_e2e_test.go; these pin the state-machine guards and
// validation that the end-to-end test doesn't naturally hit.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
)

func seedTenantAndJob(t *testing.T, gdb *gorm.DB, status TenantStatus, jobType ProvisioningJobType) (Tenant, ProvisioningJob) {
	t.Helper()
	tid, _ := newID("t_")
	tenant := Tenant{ID: tid, Name: "Acme", Status: status}
	if err := gdb.Create(&tenant).Error; err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	job, err := enqueueProvisioningJob(gdb, tid, jobType)
	if err != nil {
		t.Fatalf("enqueueing job: %v", err)
	}
	return tenant, *job
}

func reload(t *testing.T, gdb *gorm.DB, tenantID, jobID string) (Tenant, ProvisioningJob) {
	t.Helper()
	var tenant Tenant
	var job ProvisioningJob
	if err := gdb.First(&tenant, "id = ?", tenantID).Error; err != nil {
		t.Fatalf("reloading tenant: %v", err)
	}
	if err := gdb.First(&job, "id = ?", jobID).Error; err != nil {
		t.Fatalf("reloading job: %v", err)
	}
	return tenant, job
}

func TestApplyProvisioningResult_DeprovisionFailureKeepsOffboarding(t *testing.T) {
	gdb := newTestDB(t)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusOffboarding, ProvisioningJobDeprovision)

	err := applyProvisioningResult(ProvisioningJobDeprovision, controlplane.TenantResult{
		JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorInternal,
	})
	if err != nil {
		t.Fatalf("applyProvisioningResult: %v", err)
	}
	gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID)
	if gotTenant.Status != TenantStatusOffboarding {
		t.Fatalf("tenant status = %q, want offboarding", gotTenant.Status)
	}
	wantErr := publicJobError(job.ID, controlplane.ErrorInternal)
	if gotJob.Status != ProvisioningJobFailed || gotJob.LastError != wantErr {
		t.Fatalf("job = %+v, want failed with %q", gotJob, wantErr)
	}
	// GetTenantStatus surfaces it.
	w := doRequest(t, GetTenantStatus, "GET", "/v1/tenants/"+tenant.ID+"/status", map[string]string{"tenant_id": tenant.ID}, nil)
	var resp tenantStatusResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != TenantStatusOffboarding || resp.LastError != wantErr {
		t.Fatalf("GET status = %+v", resp)
	}
}

// A provision success that arrives after the tenant was already moved to
// offboarding (DELETE raced provisioning) must not resurrect it as active.
func TestApplyProvisioningResult_LateProvisionSuccessDoesNotResurrect(t *testing.T) {
	gdb := newTestDB(t)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusOffboarding, ProvisioningJobProvision)

	if err := applyProvisioningResult(ProvisioningJobProvision, controlplane.TenantResult{
		JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusActive,
	}); err != nil {
		t.Fatalf("applyProvisioningResult: %v", err)
	}
	gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID)
	if gotTenant.Status != TenantStatusOffboarding {
		t.Fatalf("tenant status = %q, want it left offboarding", gotTenant.Status)
	}
	if gotJob.Status != ProvisioningJobSucceeded {
		t.Fatalf("job status = %q, want succeeded", gotJob.Status)
	}
}

func TestApplyProvisioningResult_DuplicateIsNoOp(t *testing.T) {
	gdb := newTestDB(t)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	ok := controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusActive}
	if err := applyProvisioningResult(ProvisioningJobProvision, ok); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// A later, contradictory duplicate must not flip anything.
	dup := controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorInternal}
	if err := applyProvisioningResult(ProvisioningJobProvision, dup); err != nil {
		t.Fatalf("duplicate apply: %v", err)
	}
	gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID)
	if gotTenant.Status != TenantStatusActive || gotJob.Status != ProvisioningJobSucceeded || gotJob.LastError != "" {
		t.Fatalf("tenant %q / job %+v changed by a duplicate result", gotTenant.Status, gotJob)
	}
}

func TestApplyProvisioningResult_RejectsMismatches(t *testing.T) {
	gdb := newTestDB(t)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	other, _ := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)

	cases := map[string]struct {
		jobType ProvisioningJobType
		res     controlplane.TenantResult
	}{
		"result names a different tenant":         {ProvisioningJobProvision, controlplane.TenantResult{JobID: job.ID, TenantID: other.ID, Status: controlplane.StatusActive}},
		"deprovision result for a provision job":  {ProvisioningJobDeprovision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusOffboarded}},
		"offboarded status on a provision result": {ProvisioningJobProvision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusOffboarded}},
		"unknown status":                          {ProvisioningJobProvision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: "weird"}},
		"unknown job":                             {ProvisioningJobProvision, controlplane.TenantResult{JobID: "pj_nope", TenantID: tenant.ID, Status: controlplane.StatusActive}},
	}
	for name, c := range cases {
		if err := applyProvisioningResult(c.jobType, c.res); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID)
	if gotTenant.Status != TenantStatusPending || gotJob.Status != ProvisioningJobPending {
		t.Fatalf("a rejected result changed state: tenant %q, job %q", gotTenant.Status, gotJob.Status)
	}
	if !errors.Is(applyProvisioningResult(ProvisioningJobProvision, controlplane.TenantResult{Status: "weird"}), errUnexpectedResult) {
		t.Fatal("expected errUnexpectedResult for an unknown status")
	}
}

func TestHandleProvisioningResult_SubjectAndPayloadMustAgree(t *testing.T) {
	gdb := newTestDB(t)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	payload, _ := json.Marshal(controlplane.TenantResult{JobID: "pj_someoneelse", TenantID: tenant.ID, Status: controlplane.StatusActive})

	handleProvisioningResult(ProvisioningJobProvision, controlplane.SubjectTenantProvisionedPrefix, controlplane.ProvisionedSubject(job.ID), payload)
	handleProvisioningResult(ProvisioningJobProvision, controlplane.SubjectTenantProvisionedPrefix, controlplane.ProvisionedSubject(job.ID), []byte("{bad"))

	gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID)
	if gotTenant.Status != TenantStatusPending || gotJob.Status != ProvisioningJobPending {
		t.Fatalf("a mismatched/malformed result changed state: tenant %q, job %q", gotTenant.Status, gotJob.Status)
	}
}

// With no bus connection, CreateTenant still succeeds (the outbox row is
// the durable record) and the job is simply left pending, not counted as
// dispatched.
func TestDispatchWithoutBusLeavesJobPending(t *testing.T) {
	gdb := newTestDB(t)
	SetBus(nil)
	tenantID := mustCreateTenant(t, "No Bus Co")
	var job ProvisioningJob
	if err := gdb.First(&job, "tenant_id = ?", tenantID).Error; err != nil {
		t.Fatalf("loading job: %v", err)
	}
	if job.Status != ProvisioningJobPending || job.Attempts != 0 {
		t.Fatalf("job = %+v, want pending with 0 attempts", job)
	}
}

// TestDispatchPublishesAndCountsAttempt checks the publish shape and the
// attempts counter against a plain embedded server (the scoped-credential
// version of this runs in the end-to-end test).
func TestDispatchPublishesAndCountsAttempt(t *testing.T) {
	gdb := newTestDB(t)
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("starting NATS: %v", err)
	}
	go ns.Start()
	defer ns.Shutdown()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS not ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	SetBus(nc)
	t.Cleanup(func() { SetBus(nil) })
	sub, _ := nc.SubscribeSync(controlplane.SubjectTenantDeprovision)
	_ = nc.Flush()

	tenant, job := seedTenantAndJob(t, gdb, TenantStatusOffboarding, ProvisioningJobDeprovision)
	dispatchDeprovisioning(t.Context(), &job)

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("expected a deprovision request: %v", err)
	}
	var req controlplane.TenantDeprovisionRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.JobID != job.ID || req.TenantID != tenant.ID {
		t.Fatalf("request = %+v (err %v)", req, err)
	}
	_, got := reload(t, gdb, tenant.ID, job.ID)
	if got.Attempts != 1 || got.Status != ProvisioningJobPending {
		t.Fatalf("job = %+v, want pending with 1 attempt", got)
	}
}

func TestConnectBus_FailsClosedOnMissingOrMismatchedCredential(t *testing.T) {
	if _, err := ConnectBus(Config{}); !errors.Is(err, ErrBusNotConfigured) {
		t.Fatalf("empty config: err = %v, want ErrBusNotConfigured", err)
	}

	writeSeed := func(seed []byte) string {
		path := filepath.Join(t.TempDir(), "nkey.seed")
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			t.Fatalf("writing seed file: %v", err)
		}
		return path
	}
	userA, _ := nkeys.CreateUser()
	seedA, _ := userA.Seed()
	userB, _ := nkeys.CreateUser()
	pubB, _ := userB.PublicKey()
	acct, _ := nkeys.CreateAccount()
	jwtForB, err := jwt.NewUserClaims(pubB).Encode(acct)
	if err != nil {
		t.Fatalf("encoding JWT: %v", err)
	}
	cfg := Config{NATSURL: "nats://127.0.0.1:1", NATSCAFile: "/nonexistent", NATSNKeySeedFile: writeSeed(seedA), NATSUserJWT: jwtForB}
	if _, err := ConnectBus(cfg); err == nil || !strings.Contains(err.Error(), "different credentials") {
		t.Fatalf("expected a seed/JWT pair from different credentials to be rejected before dialing, got %v", err)
	}

	acctSeed, _ := acct.Seed()
	cfg.NATSNKeySeedFile = writeSeed(acctSeed)
	if _, err := ConnectBus(cfg); err == nil {
		t.Fatal("expected a non-User seed to be rejected")
	}

	cfg.NATSNKeySeedFile = writeSeed(seedA)
	cfg.NATSUserJWT = "not-a-jwt"
	if _, err := ConnectBus(cfg); err == nil {
		t.Fatal("expected a malformed JWT to be rejected")
	}

	cfg.NATSNKeySeedFile = filepath.Join(t.TempDir(), "missing.seed")
	if _, err := ConnectBus(cfg); err == nil || !strings.Contains(err.Error(), "SAASAPI_NATS_NKEY_SEED_FILE") {
		t.Fatalf("expected a missing seed file to be rejected, got %v", err)
	}
}

// TestLoadConfig_SeedIsReadFromFileOnly: the raw seed is never taken from
// the environment — only a path to it.
func TestLoadConfig_SeedIsReadFromFileOnly(t *testing.T) {
	t.Setenv("SAASAPI_NATS_NKEY_SEED", "SUAIGNOREDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	t.Setenv("SAASAPI_NATS_NKEY_SEED_FILE", "/run/secrets/saasapi-nats/nkey.seed")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.NATSNKeySeedFile != "/run/secrets/saasapi-nats/nkey.seed" {
		t.Fatalf("NATSNKeySeedFile = %q", cfg.NATSNKeySeedFile)
	}
}
