package saasapi

// End to end through a purge (S6), nothing in the chain mocked but the
// stores: a tenant provisioned, given data in every farmer store,
// offboarded, then purged on an operator's request. The SaaS API seals
// internal.tenant.purge, farmer's real handler runs the real erasure
// (Valkey, the farmer schema, the tombstone's lock-out pushed to the real
// bus, the buckets, the tenant's KV keypair, the Transit keys) and
// answers sealed, and saasapi deletes its own rows and records the
// tenant purged.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/rbac"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

func TestProvisioningBridge_EndToEnd_OffboardedToPurged(t *testing.T) {
	env := newE2EEnv(t)
	prev := tenantPurgeSettings
	t.Cleanup(func() { SetTenantPurgeSettings(prev) })
	SetTenantPurgeSettings(DefaultTenantPurgeSettings())
	if err := env.farmerDB.AutoMigrate(append(append(append(append(pki.SproutJWTModels(), props.Models()...), rbac.Models()...), jobs.Models()...), &lease.JobLease{})...); err != nil {
		t.Fatal(err)
	}
	stores := map[string]*objectstoretest.Server{}
	for _, name := range []string{"recipes", "jobs", "sprout_jwts"} {
		srv := objectstoretest.NewServer(t)
		s, err := objectstore.Open(srv.Config())
		if err != nil {
			t.Fatal(err)
		}
		stores[name] = srv
		switch name {
		case "recipes":
			cook.SetStore(s)
		case "jobs":
			jobs.SetStore(s)
		default:
			pki.SetSproutJWTStore(s)
		}
	}
	t.Cleanup(func() { cook.SetStore(nil); jobs.SetStore(nil); pki.SetSproutJWTStore(nil) })
	mr := miniredis.RunT(t)
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat.SetClient(vc)
	t.Cleanup(func() { heartbeat.SetClient(nil); vc.Close() })

	tenantID := env.createTenant(t, "Purge Me Ltd")
	if st := env.waitForStatus(t, tenantID, TenantStatusPending); st.Status != TenantStatusActive {
		t.Fatalf("status %+v", st)
	}
	ctx := context.Background()
	for _, stmt := range []string{
		"INSERT INTO props (tenant_id, sprout_id, name, value, static, expiry) VALUES (?, 'web-01', 'p', 'v', 1, CURRENT_TIMESTAMP)",
		"INSERT INTO job_status (tenant_id, sprout_id, jid, status, updated_at) VALUES (?, 'web-01', 'j1', 'done', CURRENT_TIMESTAMP)",
		"INSERT INTO rbac_roles (tenant_id, name) VALUES (?, 'admin')",
	} {
		if err := env.farmerDB.Exec(stmt, tenantID).Error; err != nil {
			t.Fatal(err)
		}
	}
	for name, key := range map[string]string{
		"recipes":     "tenants/" + tenantID + "/recipes/web.imas",
		"jobs":        "jobs/" + tenantID + "/web-01/j1/meta.json",
		"sprout_jwts": tenantID + "/web-01/abc.jwt",
	} {
		s, _ := objectstore.Open(stores[name].Config())
		if err := s.Put(ctx, key, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	mr.Set("imas:heartbeat:{"+tenantID+":web-01}", "1")
	env.bao.SeedKeypair(t, tenantboxtest.TenantPath(tenantID), nil)
	seedSaasRows(t, env.saasDB, tenantID)

	if w := env.do(t, "DELETE", "/v1/tenants/"+tenantID, tenantID, ""); w.Code != http.StatusAccepted {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body)
	}
	st := env.waitForStatus(t, tenantID, TenantStatusOffboarding)
	if st.Status != TenantStatusOffboarded || st.PurgeAfter == nil || st.PurgeAfter.Before(time.Now().Add(719*time.Hour)) {
		t.Fatalf("after offboarding: %+v", st)
	}

	results := env.observe(t, controlplane.SubjectTenantPurgedWildcard)
	op := (&operatorPlane{tokens: [][]byte{[]byte(testOperatorToken)}}).handler()
	code, body := operatorDo(t, op, testOperatorToken, http.MethodPost, "/v1/operator/tenants/"+tenantID+"/purge", nil)
	if code != http.StatusAccepted {
		t.Fatalf("operator purge: %d %v", code, body)
	}
	msg, err := results.NextMsg(20 * time.Second)
	if err != nil {
		t.Fatalf("no purge result: %v", err)
	}
	if strings.Contains(string(msg.Data), tenantID) {
		t.Fatal("the purge result is not sealed")
	}
	if st := env.waitForStatus(t, tenantID, TenantStatusOffboarded); st.Status != TenantStatusPurged || st.LastError != "" {
		t.Fatalf("after the purge: %+v", st)
	}

	for _, table := range tenantpurge.FarmerTables {
		var n int64
		env.farmerDB.Table(table).Where("tenant_id = ?", tenantID).Count(&n)
		if n != 0 {
			t.Errorf("farmer.%s still has %d rows", table, n)
		}
	}
	for name, srv := range stores {
		for _, k := range srv.Keys() {
			if strings.Contains(k, tenantID) {
				t.Errorf("%s still holds %s", name, k)
			}
		}
	}
	if mr.Exists("imas:heartbeat:{" + tenantID + ":web-01}") {
		t.Error("the heartbeat key is still there")
	}
	for _, name := range []string{natskeys.TenantSigningKey(tenantID), natskeys.TenantAccountKey(tenantID)} {
		if env.transit.Fake.Has(name) {
			t.Errorf("Transit key %s not destroyed", name)
		}
	}
	if env.bao.Has(tenantboxtest.TenantPath(tenantID)) {
		t.Error("the tenant's keypair is still in OpenBao KV")
	}
	for table, n := range saasRowCounts(t, env.saasDB, tenantID) {
		if n != 0 {
			t.Errorf("saas.%s still has %d rows", table, n)
		}
	}
	var tenant Tenant
	env.saasDB.First(&tenant, "id = ?", tenantID)
	if tenant.Name != "" || tenant.Status != TenantStatusPurged {
		t.Errorf("saas tenant row %+v", tenant)
	}
	// The tombstone keeps it out.
	if err := env.dialTenantAccountAsFarmer(t, tenantID); err == nil {
		t.Error("the purged tenant's Account is accepted by the bus")
	}
	if err := pki.ProvisionTenant(tenantID, "again"); err == nil {
		t.Error("the purged tenant was provisioned again")
	}
}
