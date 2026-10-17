package natsapi

// S6: tenant_purge.go. The integration tests run the real steps against
// one farmer schema (sqlite), three fake buckets, a fake Valkey, the fake
// Transit and a fake accounts publisher (so the tombstone's lock-out is
// "pushed" without a bus). Two tenants hold a sprout of the same ID, the
// same property, role, cohort, job and recipe names; a third tenant's ID
// extends the purged one's. The sealed-wire tests stub the steps.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/pkitest"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/rbac"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// fakeAccountPublisher is the accounts bucket and bus as one map: what
// pushAccountUpdate would have published.
type fakeAccountPublisher struct {
	mu   sync.Mutex
	jwts map[string]string
}

func (p *fakeAccountPublisher) Publish(_ context.Context, pub, accountJWT string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwts[pub] = accountJWT
	return nil
}
func (p *fakeAccountPublisher) ReconcileAll(context.Context) error { return nil }
func (p *fakeAccountPublisher) Current(_ context.Context, pub string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwts[pub], nil
}

// purgeEnv is the farmer side of a purge test.
type purgeEnv struct {
	db                      *gorm.DB
	recipes, jobs, sproutJs *objectstoretest.Server
	mr                      *miniredis.Miniredis
	transit                 *pkitest.Transit
	bao                     *tenantboxtest.Server
	publisher               *fakeAccountPublisher
	accountPub              map[string]string
}

var purgeEnvSeq atomic.Int64

func setupPurgeEnv(t *testing.T) *purgeEnv {
	t.Helper()
	e := &purgeEnv{accountPub: map[string]string{}}
	gdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), purgeEnvSeq.Add(1))),
		&gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	models := append(append(append(append(pki.Models(), pki.SproutJWTModels()...), props.Models()...), rbac.Models()...), jobs.Models()...)
	if err := gdb.AutoMigrate(append(models, &lease.JobLease{})...); err != nil {
		t.Fatal(err)
	}
	e.db = gdb
	pki.SetDB(gdb)
	t.Cleanup(func() {
		pki.SetDB(sharedPKIDB)
		if s, err := gdb.DB(); err == nil {
			s.Close()
		}
	})
	config.FarmerOrganization = "imas-test"
	e.transit = pkitest.Farmer(t)
	e.bao = tenantboxtest.Start(t)
	e.publisher = &fakeAccountPublisher{jwts: map[string]string{}}
	pki.SetAccountPublisher(e.publisher)
	t.Cleanup(func() { pki.SetAccountPublisher(nil) })

	open := func() (*objectstoretest.Server, *objectstore.Store) {
		srv := objectstoretest.NewServer(t)
		s, err := objectstore.Open(srv.Config())
		if err != nil {
			t.Fatal(err)
		}
		return srv, s
	}
	var rs, js, ss *objectstore.Store
	e.recipes, rs = open()
	e.jobs, js = open()
	e.sproutJs, ss = open()
	cook.SetStore(rs)
	jobs.SetStore(js)
	pki.SetSproutJWTStore(ss)
	t.Cleanup(func() { cook.SetStore(nil); jobs.SetStore(nil); pki.SetSproutJWTStore(nil) })

	e.mr = miniredis.RunT(t)
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{e.mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat.SetClient(vc)
	t.Cleanup(func() { heartbeat.SetClient(nil); vc.Close() })

	for _, tenant := range []string{"t_a", "t_b", "t_ab"} {
		e.seed(t, tenant)
	}
	return e
}

// seed gives tenant one of everything, under the same names as every
// other tenant.
func (e *purgeEnv) seed(t *testing.T, tenant string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	kp, _ := nkeys.CreateAccount()
	pub, _ := kp.PublicKey()
	e.accountPub[tenant] = pub
	ac := jwt.NewAccountClaims(pub)
	ac.Name = "Customer " + tenant + " Ltd"
	op, _ := nkeys.CreateOperator()
	signed, err := ac.Encode(op)
	if err != nil {
		t.Fatal(err)
	}
	e.publisher.jwts[pub] = signed
	rows := []struct {
		table string
		row   map[string]any
	}{
		{"pki_tenants", map[string]any{"id": tenant, "name": "Customer " + tenant + " Ltd", "deleted": false, "created_at": 1, "account_pub": pub}},
		{"props", map[string]any{"tenant_id": tenant, "sprout_id": "web-01", "name": "secret-prop-name", "value": "secret-prop-value", "static": true, "expiry": now}},
		{"pki_nkeys", map[string]any{"tenant_id": tenant, "sprout_id": "web-01", "nkey": "U" + tenant, "state": "accepted"}},
		{"pki_revoked_nkeys", map[string]any{"tenant_id": tenant, "nkey": "UOLD", "sprout_id": "web-01", "revoked_at": 1}},
		{"pki_sprout_box_keys", map[string]any{"tenant_id": tenant, "sprout_id": "web-01", "pub": "box-" + tenant, "state": "revoked"}},
		{"sprout_user_jwt", map[string]any{"tenant_id": tenant, "sprout_id": "web-01", "updated_at": now}},
		{"auth_users", map[string]any{"tenant_id": tenant, "user_id": "UADMIN", "role_name": "admin", "created_at": now}},
		{"auth_cli_box_keys", map[string]any{"tenant_id": tenant, "user_id": "UADMIN", "pub": "cli-" + tenant, "status": "retired", "created_at": now}},
		{"rbac_roles", map[string]any{"tenant_id": tenant, "name": "admin"}},
		{"rbac_user_roles", map[string]any{"tenant_id": tenant, "pubkey": "UADMIN", "role_name": "admin"}},
		{"rbac_cohorts", map[string]any{"tenant_id": tenant, "name": "web", "type": "static"}},
		{"job_status", map[string]any{"tenant_id": tenant, "sprout_id": "web-01", "jid": "j1", "status": "done", "updated_at": now}},
	}
	for _, r := range rows {
		if err := e.db.Table(r.table).Create(r.row).Error; err != nil {
			t.Fatalf("seeding %s for %s: %v", r.table, tenant, err)
		}
	}
	for _, o := range []struct {
		srv *objectstoretest.Server
		key string
	}{
		{e.recipes, "tenants/" + tenant + "/recipes/secret-recipe-name.imas"},
		{e.recipes, "tenants/" + tenant + "/recipe-audit/2026-10-17/a.json"},
		{e.recipes, "sprouts/" + tenant + "/web-01/recipe.json"},
		{e.jobs, "jobs/" + tenant + "/web-01/j1/meta.json"},
		{e.sproutJs, tenant + "/web-01/abc.jwt"},
	} {
		s, err := objectstore.Open(o.srv.Config())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, o.key, []byte("content of "+tenant)); err != nil {
			t.Fatal(err)
		}
	}
	e.mr.Set("imas:heartbeat:{"+tenant+":web-01}", "1")
	e.mr.Set("imas:accepted:{"+tenant+":web-01}", "1")
	e.transit.Fake.NewKey(natskeys.TenantSigningKey(tenant))
	e.transit.Fake.NewKey(natskeys.TenantAccountKey(tenant))
	e.bao.SeedKeypair(t, tenantboxtest.TenantPath(tenant), nil)
}

// offboard marks tenant deprovisioned in pki_tenants and soft-deletes its
// keys, as DeprovisionTenant leaves it.
func (e *purgeEnv) offboard(t *testing.T, tenant string) {
	t.Helper()
	if err := e.db.Table("pki_tenants").Where("id = ?", tenant).Update("deleted", true).Error; err != nil {
		t.Fatal(err)
	}
}

// state is everything a tenant has, as sorted lines.
func (e *purgeEnv) state(t *testing.T, tenant string) []string {
	t.Helper()
	var out []string
	for _, table := range append(slices.Clone(tenantpurge.FarmerTables), "pki_tenants") {
		col := "tenant_id"
		if table == "pki_tenants" {
			col = "id"
		}
		var rows []map[string]any
		if err := e.db.Table(table).Where(col+" = ?", tenant).Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			delete(r, "expiry")
			delete(r, "updated_at")
			delete(r, "created_at")
			out = append(out, fmt.Sprintf("db %s %v", table, r))
		}
	}
	for name, srv := range map[string]*objectstoretest.Server{"recipes": e.recipes, "jobs": e.jobs, "sprout_jwts": e.sproutJs} {
		for _, k := range srv.Keys() {
			if strings.HasPrefix(k, tenant+"/") || strings.Contains(k, "/"+tenant+"/") {
				out = append(out, "object "+name+" "+k)
			}
		}
	}
	for _, k := range e.mr.Keys() {
		if strings.Contains(k, "{"+tenant+":") {
			out = append(out, "valkey "+k)
		}
	}
	for _, name := range []string{natskeys.TenantSigningKey(tenant), natskeys.TenantAccountKey(tenant)} {
		if e.transit.Fake.Has(name) {
			out = append(out, "transit "+name)
		}
	}
	if e.bao.Has(tenantboxtest.TenantPath(tenant)) {
		out = append(out, "kv "+tenantboxtest.TenantPath(tenant))
	}
	if j := e.publisher.jwts[e.accountPub[tenant]]; j != "" {
		ac, err := jwt.DecodeAccountClaims(j)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("account name=%s conn=%d", ac.Name, ac.Limits.Conn))
	}
	slices.Sort(out)
	return out
}

// tombstone is what must be left of a purged tenant.
func (e *purgeEnv) tombstone(tenant string) []string {
	return []string{
		fmt.Sprintf("account name=%s conn=0", tenant),
		fmt.Sprintf("db pki_tenants map[account_pub:%s deleted:1 id:%s name:%s]", e.accountPub[tenant], tenant, tenant),
	}
}

func purgeReq(tenant string) controlplane.TenantPurgeRequest {
	return controlplane.TenantPurgeRequest{JobID: "pj_purge_" + tenant, TenantID: tenant, Trigger: controlplane.PurgeTriggerRetention}
}

// captureAudit routes the platform audit log into a buffer.
func captureAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := audit.Global()
	audit.SetGlobal(audit.NewLogger(&buf))
	t.Cleanup(func() { audit.SetGlobal(prev) })
	return &buf
}

func TestTenantPurge_ErasesOnlyItsTenant(t *testing.T) {
	e := setupPurgeEnv(t)
	auditLog := captureAudit(t)
	beforeB, beforeAB := e.state(t, "t_b"), e.state(t, "t_ab")
	e.offboard(t, "t_a")

	res, ran := runTenantPurge(context.Background(), purgeReq("t_a"))
	if !ran || res.Status != controlplane.StatusPurged || res.ErrorCode != "" || res.FailedStep != "" {
		t.Fatalf("purge result %+v (ran %v)", res, ran)
	}
	for _, c := range []string{"valkey.heartbeat", "valkey.accepted", "objects.recipes", "objects.staged_recipes", "objects.jobs", "objects.sprout_jwts"} {
		want := int64(1)
		if c == "objects.recipes" {
			want = 2
		}
		if res.Counts[c] != want {
			t.Errorf("count %s = %d, want %d (%v)", c, res.Counts[c], want, res.Counts)
		}
	}
	for _, table := range tenantpurge.FarmerTables {
		if res.Counts["db."+table] != 1 {
			t.Errorf("count db.%s = %d, want 1", table, res.Counts["db."+table])
		}
	}
	if res.Counts["transit.keys"] != 2 {
		t.Errorf("transit.keys = %d", res.Counts["transit.keys"])
	}
	if res.Counts["kv.tenant_box_keys"] != 1 {
		t.Errorf("kv.tenant_box_keys = %d", res.Counts["kv.tenant_box_keys"])
	}
	if got, want := e.state(t, "t_a"), e.tombstone("t_a"); !slices.Equal(got, want) {
		t.Errorf("t_a after the purge:\n%s\nwant only the tombstone:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := e.state(t, "t_b"); !slices.Equal(got, beforeB) {
		t.Errorf("t_b changed:\n%s\nbefore:\n%s", strings.Join(got, "\n"), strings.Join(beforeB, "\n"))
	}
	if got := e.state(t, "t_ab"); !slices.Equal(got, beforeAB) {
		t.Errorf("t_ab changed:\n%s\nbefore:\n%s", strings.Join(got, "\n"), strings.Join(beforeAB, "\n"))
	}
	if !e.mr.Exists("imas:heartbeat:{t_b:web-01}") {
		t.Error("t_b's heartbeat key is gone")
	}

	// One audit entry, counts and identifiers only.
	line := strings.TrimSpace(auditLog.String())
	if strings.Count(line, "\n") != 0 || line == "" {
		t.Fatalf("want exactly one audit line, got %q", line)
	}
	var entry struct {
		Action  string     `json:"action"`
		Success bool       `json:"success"`
		Params  purgeAudit `json:"params"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Action != "internal.tenant.purge" || !entry.Success || entry.Params.TenantID != "t_a" || entry.Params.JobID != "pj_purge_t_a" ||
		entry.Params.Trigger != "retention" || entry.Params.Counts["objects.recipes"] != 2 || entry.Params.Counts["kv.tenant_box_keys"] != 1 || entry.Params.Status != "purged" {
		t.Errorf("audit entry %+v", entry)
	}
	for _, leak := range []string{"secret-recipe-name", "secret-prop", "web-01", "content of", "Customer", "UOLD", "box-t_a", "cli-t_a", "tenants/", e.accountPub["t_a"]} {
		if strings.Contains(line, leak) {
			t.Errorf("audit entry carries %q: %s", leak, line)
		}
	}

	// Purged again: nothing left to delete, and success.
	res, ran = runTenantPurge(context.Background(), purgeReq("t_a"))
	if !ran || res.Status != controlplane.StatusPurged {
		t.Fatalf("second purge %+v", res)
	}
	for k, n := range res.Counts {
		if n != 0 {
			t.Errorf("second purge deleted %d in %s", n, k)
		}
	}
	if got, want := e.state(t, "t_a"), e.tombstone("t_a"); !slices.Equal(got, want) {
		t.Errorf("t_a after the second purge: %v", got)
	}
}

// A run stopped after each step in turn (the next one fails) leaves the
// tenant locked out; run again, it ends in the same state as an
// uninterrupted run.
func TestTenantPurge_ResumesAfterEachStep(t *testing.T) {
	for i, step := range controlplane.PurgeSteps {
		t.Run(step, func(t *testing.T) {
			e := setupPurgeEnv(t)
			beforeB := e.state(t, "t_b")
			e.offboard(t, "t_a")
			orig := purge
			t.Cleanup(func() { purge = orig })
			boom := errors.New("injected failure at " + step)
			failing := orig
			switch step {
			case controlplane.PurgeStepValkey:
				failing.valkey = func(context.Context, string) (map[string]int64, error) { return nil, boom }
			case controlplane.PurgeStepDB:
				failing.db = func(context.Context, string) (map[string]int64, error) { return nil, boom }
			case controlplane.PurgeStepTombstone:
				failing.tombstone = func(context.Context, string) error { return boom }
			case controlplane.PurgeStepObjects:
				failing.objects = func(context.Context, string) (map[string]int64, error) { return nil, boom }
			case controlplane.PurgeStepKV:
				failing.kv = func(context.Context, string) (map[string]int64, error) { return nil, boom }
			case controlplane.PurgeStepTransit:
				failing.transit = func(context.Context, string) (map[string]int64, error) { return nil, boom }
			}
			purge = failing
			res, ran := runTenantPurge(context.Background(), purgeReq("t_a"))
			if !ran || res.Status != controlplane.StatusFailed || res.ErrorCode != controlplane.ErrorPurgeIncomplete || res.FailedStep != step {
				t.Fatalf("interrupted purge %+v", res)
			}
			// The steps before it ran; the tenant stays locked out.
			if i > 0 && e.mr.Exists("imas:heartbeat:{t_a:web-01}") {
				t.Error("the Valkey step before the failure did not run")
			}
			if row := e.state(t, "t_a"); !slices.ContainsFunc(row, func(s string) bool { return strings.HasPrefix(s, "db pki_tenants") && strings.Contains(s, "deleted:1") }) {
				t.Errorf("t_a is no longer marked deleted after an interrupted purge: %v", row)
			}
			purge = orig
			res, ran = runTenantPurge(context.Background(), purgeReq("t_a"))
			if !ran || res.Status != controlplane.StatusPurged {
				t.Fatalf("resumed purge %+v", res)
			}
			if got, want := e.state(t, "t_a"), e.tombstone("t_a"); !slices.Equal(got, want) {
				t.Errorf("t_a after the resumed purge:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if got := e.state(t, "t_b"); !slices.Equal(got, beforeB) {
				t.Errorf("t_b changed: %v", got)
			}
		})
	}
}

// The guards: nothing is deleted for an invalid ID, the legacy current
// tenant, a tenant pki_tenants doesn't show deprovisioned (live, or with
// no row), or an unknown trigger; each is audited as a refusal.
func TestTenantPurge_GuardsDeleteNothing(t *testing.T) {
	e := setupPurgeEnv(t)
	auditLog := captureAudit(t)
	before := map[string][]string{}
	for _, tenant := range []string{"t_a", "t_b", "t_ab"} {
		before[tenant] = e.state(t, tenant)
	}
	for _, c := range []struct {
		name string
		req  controlplane.TenantPurgeRequest
		code controlplane.ErrorCode
	}{
		{"invalid id", controlplane.TenantPurgeRequest{JobID: "pj_1", TenantID: "t_a/../t_b", Trigger: "operator"}, controlplane.ErrorInvalidTenantID},
		{"legacy tenant", controlplane.TenantPurgeRequest{JobID: "pj_2", TenantID: "imas-test", Trigger: "operator"}, controlplane.ErrorPurgeRefused},
		{"live tenant", controlplane.TenantPurgeRequest{JobID: "pj_3", TenantID: "t_a", Trigger: "operator"}, controlplane.ErrorPurgeRefused},
		{"no pki row", controlplane.TenantPurgeRequest{JobID: "pj_4", TenantID: "t_unknown", Trigger: "operator"}, controlplane.ErrorPurgeRefused},
		{"unknown trigger", controlplane.TenantPurgeRequest{JobID: "pj_5", TenantID: "t_b", Trigger: "manual"}, controlplane.ErrorPurgeRefused},
	} {
		if c.name == "unknown trigger" {
			e.offboard(t, "t_b")
		}
		res, ran := runTenantPurge(context.Background(), c.req)
		if !ran || res.Status != controlplane.StatusFailed || res.ErrorCode != c.code || res.FailedStep != "" {
			t.Errorf("%s: %+v", c.name, res)
		}
		for k, n := range res.Counts {
			if n != 0 {
				t.Errorf("%s: deleted %d in %s", c.name, n, k)
			}
		}
	}
	e.db.Table("pki_tenants").Where("id = ?", "t_b").Update("deleted", false)
	for tenant, want := range before {
		if got := e.state(t, tenant); !slices.Equal(got, want) {
			t.Errorf("%s changed by a refused purge:\n%s", tenant, strings.Join(got, "\n"))
		}
	}
	if n := strings.Count(strings.TrimSpace(auditLog.String()), "\n") + 1; n != 5 || !strings.Contains(auditLog.String(), "nothing deleted") {
		t.Errorf("want 5 refusal audit entries, got %d: %s", n, auditLog.String())
	}
}

// A copy of the request arriving while another replica holds the
// tenant's purge lease runs nothing and answers nothing.
func TestTenantPurge_OneReplicaAtATime(t *testing.T) {
	e := setupPurgeEnv(t)
	e.offboard(t, "t_a")
	l := lease.New(e.db, nil)
	if err := e.db.Create(&lease.JobLease{Name: purgeLeaseName("t_a")}).Error; err != nil {
		t.Fatal(err)
	}
	if ok, err := l.Acquire(context.Background(), lease.JobLeases, []any{purgeLeaseName("t_a")}, "other-replica", time.Minute); err != nil || !ok {
		t.Fatalf("taking the lease: %v %v", ok, err)
	}
	before := e.state(t, "t_a")
	if _, ran := runTenantPurge(context.Background(), purgeReq("t_a")); ran {
		t.Fatal("a purge ran while another replica held the tenant's lease")
	}
	if got := e.state(t, "t_a"); !slices.Equal(got, before) {
		t.Errorf("t_a changed: %v", got)
	}
	if _, err := l.Release(context.Background(), lease.JobLeases, []any{purgeLeaseName("t_a")}, "other-replica"); err != nil {
		t.Fatal(err)
	}
	if res, ran := runTenantPurge(context.Background(), purgeReq("t_a")); !ran || res.Status != controlplane.StatusPurged {
		t.Fatalf("purge after the lease was released: %+v %v", res, ran)
	}
}

// stubPurge replaces every step with one that counts its calls.
func stubPurge(t *testing.T) *atomic.Int32 {
	t.Helper()
	orig := purge
	t.Cleanup(func() { purge = orig })
	var calls atomic.Int32
	count := func(context.Context, string) (map[string]int64, error) {
		calls.Add(1)
		return map[string]int64{"db.props": 3}, nil
	}
	purge = purgeOps{
		check:     func(string) error { return nil },
		valkey:    count,
		db:        count,
		tombstone: func(context.Context, string) error { calls.Add(1); return nil },
		objects:   count,
		kv:        count,
		transit:   count,
		runLeased: func(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
			return true, fn(ctx)
		},
	}
	return &calls
}

// The sealed subject: a genuine request is purged and answered sealed on
// its job's subject; plaintext, forged, moved and replayed requests run
// nothing and get no answer.
func TestTenantPurge_SealedWire(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	calls := stubPurge(t)
	if err := registerSaaSAPIHandlers(nc, newSealedAPI()); err != nil {
		t.Fatal(err)
	}
	results, _ := nc.SubscribeSync("internal.tenant.*.*")
	_ = nc.Flush()
	req := controlplane.TenantPurgeRequest{JobID: "pj_p1", TenantID: "t_a", Trigger: controlplane.PurgeTriggerOperator}

	plain := nats.NewMsg(controlplane.SubjectTenantPurge)
	plain.Data = mustJSON(t, req)
	publishMsg(t, nc, plain)
	forged, _, err := sealedSaaSAPIMsg(impostorSaaSAPI(t, saas), controlplane.SubjectTenantPurge, req)
	if err != nil {
		t.Fatal(err)
	}
	publishMsg(t, nc, forged)
	moved, _ := saas.sealedMsg(t, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_p1", TenantID: "t_a"})
	moved.Subject = controlplane.SubjectTenantPurge
	publishMsg(t, nc, moved)
	asUser, _ := saas.sealedMsg(t, controlplane.SubjectTenantPurge, req)
	asUser.Header.Set(payloadbox.PrincipalHeader, "AUSER")
	publishMsg(t, nc, asUser)
	expectNoMsg(t, results, "a forged purge request")
	if calls.Load() != 0 {
		t.Fatalf("a forged purge request ran %d steps", calls.Load())
	}

	genuine := publishSealed(t, saas, nc, controlplane.SubjectTenantPurge, req)
	msg, err := results.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != controlplane.PurgedSubject("pj_p1") {
		t.Fatalf("result on %s", msg.Subject)
	}
	if string(msg.Data) == "" || strings.Contains(string(msg.Data), "purged") {
		t.Fatal("the result is not sealed")
	}
	res, err := saas.openTenantResult(controlplane.TenantJobPurge, "pj_p1", msg)
	if err != nil || res.Status != controlplane.StatusPurged || res.JobID != "pj_p1" || res.TenantID != "t_a" || res.Counts["db.props"] != 15 {
		t.Fatalf("result %+v, %v", res, err)
	}
	if _, err := saas.openTenantResult(controlplane.TenantJobDeprovision, "pj_p1", msg); err == nil {
		t.Error("a purge result opened as a deprovision result")
	}
	ran := calls.Load()
	for range 3 {
		publishMsg(t, nc, genuine)
	}
	expectNoMsg(t, results, "a replayed purge request")
	if calls.Load() != ran {
		t.Fatalf("a replayed purge request ran again")
	}

	// A malformed or job-less request is dropped.
	publishSealed(t, saas, nc, controlplane.SubjectTenantPurge, controlplane.TenantPurgeRequest{JobID: "pj.bad", TenantID: "t_a", Trigger: "operator"})
	publishSealed(t, saas, nc, controlplane.SubjectTenantPurge, "not an object")
	expectNoMsg(t, results, "a malformed purge request")
}

// The KV step deletes the tenant's keypair, every version, and nothing
// of another tenant's; a failed delete fails the step, and running it
// again finishes it.
func TestPurgeTenantKV(t *testing.T) {
	e := setupPurgeEnv(t)
	e.bao.FailMetadataDeletes = 1
	if _, err := purgeTenantKV(context.Background(), "t_a"); err == nil {
		t.Fatal("a failed KV delete was reported a success")
	}
	if !e.bao.Has(tenantboxtest.TenantPath("t_a")) {
		t.Fatal("the keypair went although the delete failed")
	}
	counts, err := purgeTenantKV(context.Background(), "t_a")
	if err != nil || counts["kv.tenant_box_keys"] != 1 {
		t.Fatalf("purgeTenantKV = %v, %v", counts, err)
	}
	for tenant, want := range map[string]bool{"t_a": false, "t_ab": true, "t_b": true} {
		if got := e.bao.Has(tenantboxtest.TenantPath(tenant)); got != want {
			t.Errorf("%s keypair present = %v, want %v", tenant, got, want)
		}
	}
	if counts, err := purgeTenantKV(context.Background(), "t_a"); err != nil || counts["kv.tenant_box_keys"] != 0 {
		t.Errorf("purgeTenantKV again = %v, %v", counts, err)
	}
}
