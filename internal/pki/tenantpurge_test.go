package pki

// S6: the farmer-side purge of an offboarded tenant (tenantpurge.go),
// against the in-process bus, the fake Transit and a fake sprout JWT
// bucket. Two tenants hold a sprout of the same ID; purging one leaves
// the other untouched.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/pki/tenantboxtest"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// createOtherFarmerTables makes the farmer-schema tables this package's
// test database lacks (they belong to props, auth's are already there,
// rbac and jobs) with the tenant_id column the purge deletes by.
func createOtherFarmerTables(t *testing.T) {
	t.Helper()
	have := map[string]bool{}
	for _, m := range append(Models(), &sproutUserJWTRow{}) {
		stmt := db.Model(m).Statement
		if err := stmt.Parse(m); err != nil {
			t.Fatal(err)
		}
		have[stmt.Schema.Table] = true
	}
	for _, table := range tenantpurge.FarmerTables {
		if have[table] {
			continue
		}
		if err := db.Exec("CREATE TABLE `" + table + "` (tenant_id TEXT NOT NULL, sprout_id TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '')").Error; err != nil {
			t.Fatal(err)
		}
	}
}

func tenantRows(t *testing.T, tenantID string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, table := range tenantpurge.FarmerTables {
		var n int64
		if err := db.Table(table).Where("tenant_id = ?", tenantID).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

func TestCheckTenantPurgeable(t *testing.T) {
	setupTestPKI(t)
	if _, err := insertTenantRowIfAbsent(tenantRow{ID: "t_live", Name: "Live", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := insertTenantRowIfAbsent(tenantRow{ID: "t_gone", Name: "Gone", Deleted: true, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id   string
		want error
	}{
		{"", ErrTenantIDInvalid},
		{"t/../x", ErrTenantIDInvalid},
		{config.FarmerOrganization, ErrTenantPurgeRefused},
		{"t_never", ErrTenantPurgeRefused},
		{"t_live", ErrTenantPurgeRefused},
		{"t_gone", nil},
	} {
		if err := CheckTenantPurgeable(c.id); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("CheckTenantPurgeable(%q) = %v, want %v", c.id, err, c.want)
		}
	}
	// Every purge entry point re-checks it and deletes nothing.
	ctx := context.Background()
	if _, err := DestroyTenantKeys(ctx, "t_live"); !errors.Is(err, ErrTenantPurgeRefused) {
		t.Errorf("DestroyTenantKeys of a live tenant: %v", err)
	}
	if _, err := DestroyTenantKeys(ctx, config.FarmerOrganization); !errors.Is(err, ErrTenantPurgeRefused) {
		t.Errorf("DestroyTenantKeys of the legacy tenant: %v", err)
	}
	if err := ScrubTenantTombstone(ctx, "t_live"); !errors.Is(err, ErrTenantPurgeRefused) {
		t.Errorf("ScrubTenantTombstone of a live tenant: %v", err)
	}
	if row, _ := getTenantRow("t_live"); row.Name != "Live" {
		t.Errorf("a refused scrub renamed the row: %q", row.Name)
	}
}

func TestPurgeTenant_ErasesOneTenantOnly(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()
	bucket := useTestSproutJWTStore(t)
	createOtherFarmerTables(t)
	ctx := context.Background()

	// Two tenants, each with a sprout named web-01, the same property,
	// role, cohort and job names.
	seeds := map[string][]byte{}
	for _, tenant := range []string{"t_a", "t_b"} {
		if err := ProvisionTenant(tenant, "Tenant "+tenant); err != nil {
			t.Fatalf("ProvisionTenant(%s): %v", tenant, err)
		}
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		seeds[tenant], _ = kp.Seed()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenant, SproutID: "web-01", NKey: pub, State: stateAccepted}); err != nil {
			t.Fatal(err)
		}
		if err := ReloadNKeysForTenant(tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := sproutUserJWTForTest(tenant, "web-01"); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"props", "rbac_roles", "rbac_user_roles", "rbac_cohorts", "job_status"} {
			if err := db.Exec("INSERT INTO `"+table+"` (tenant_id, sprout_id, name) VALUES (?, 'web-01', 'same')", tenant).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Exec("INSERT INTO pki_revoked_nkeys (tenant_id, nkey, sprout_id, revoked_at) VALUES (?, 'UOLD', 'web-01', 1)", tenant).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("INSERT INTO pki_cli_admin_keys (tenant_id, nkey, granted_at) VALUES (?, 'UADMIN', 1)", tenant).Error; err != nil {
			t.Fatal(err)
		}
	}
	jwtB, _ := sproutUserJWTForTest("t_b", "web-01")
	before := tenantRows(t, "t_b")
	bucketB := 0
	for _, k := range bucket.Keys() {
		if strings.HasPrefix(k, "t_b/") {
			bucketB++
		}
	}

	if err := DeprovisionTenant("t_a"); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	if err := CheckTenantPurgeable("t_a"); err != nil {
		t.Fatalf("CheckTenantPurgeable after deprovision: %v", err)
	}

	run := func() map[string]int64 {
		t.Helper()
		if err := ScrubTenantTombstone(ctx, "t_a"); err != nil {
			t.Fatalf("ScrubTenantTombstone: %v", err)
		}
		counts, err := PurgeTenantRows(ctx, "t_a", 2)
		if err != nil {
			t.Fatalf("PurgeTenantRows: %v", err)
		}
		n, err := PurgeTenantSproutJWTs(ctx, "t_a", 2)
		if err != nil {
			t.Fatalf("PurgeTenantSproutJWTs: %v", err)
		}
		counts["objects.sprout_jwts"] = n
		n, err = DestroyTenantKeys(ctx, "t_a")
		if err != nil {
			t.Fatalf("DestroyTenantKeys = %d, %v", n, err)
		}
		counts["transit.keys"] = n
		return counts
	}
	counts := run()
	if counts["db.pki_nkeys"] != 1 || counts["db.sprout_user_jwt"] != 1 || counts["db.props"] != 1 || counts["objects.sprout_jwts"] != 1 || counts["transit.keys"] != 2 {
		t.Errorf("counts %v", counts)
	}

	// Tenant A: nothing left but the tombstone.
	for table, n := range tenantRows(t, "t_a") {
		if n != 0 {
			t.Errorf("t_a still has %d rows in %s", n, table)
		}
	}
	for _, k := range bucket.Keys() {
		if strings.HasPrefix(k, "t_a/") {
			t.Errorf("t_a's sprout JWT object %s left", k)
		}
	}
	for _, name := range []string{natskeys.TenantSigningKey("t_a"), natskeys.TenantAccountKey("t_a")} {
		if testTransit.Fake.Has(name) {
			t.Errorf("Transit key %s not destroyed", name)
		}
	}
	row, err := getTenantRow("t_a")
	if err != nil || !row.Deleted || row.Name != "t_a" || row.AccountPub == "" {
		t.Fatalf("t_a's tombstone row %+v, %v: want deleted, named by its ID, Account kept", row, err)
	}
	locked, err := jwt.DecodeAccountClaims(heldTenantAccountJWT(t, "t_a"))
	if err != nil {
		t.Fatal(err)
	}
	if !isLockedOut(locked) || locked.Name != "t_a" || len(locked.SigningKeys) != 0 || len(locked.Revocations) != 1 {
		t.Errorf("t_a's tombstone JWT: locked out %v, name %q, %d signing keys, revocations %v; want only the lock-out",
			isLockedOut(locked), locked.Name, len(locked.SigningKeys), locked.Revocations)
	}
	if err := ProvisionTenant("t_a", "Back again"); err == nil {
		t.Error("a purged tenant was provisioned again")
	}

	// Tenant B: untouched.
	if after := tenantRows(t, "t_b"); len(after) != len(before) {
		t.Fatalf("t_b rows %v, before %v", after, before)
	} else {
		for table, n := range before {
			if after[table] != n {
				t.Errorf("t_b's %s: %d rows, %d before", table, after[table], n)
			}
		}
	}
	got := 0
	for _, k := range bucket.Keys() {
		if strings.HasPrefix(k, "t_b/") {
			got++
		}
	}
	if got != bucketB || bucketB == 0 {
		t.Errorf("t_b's sprout JWT objects: %d, %d before", got, bucketB)
	}
	for _, name := range []string{natskeys.TenantSigningKey("t_b"), natskeys.TenantAccountKey("t_b")} {
		if !testTransit.Fake.Has(name) {
			t.Errorf("t_b's Transit key %s is gone", name)
		}
	}
	if nc, err := dialAsSprout(t, jwtB, seeds["t_b"]); err != nil {
		t.Errorf("t_b's sprout no longer connects: %v", err)
	} else {
		nc.Close()
	}

	// Again: nothing more to delete, and success.
	for k, n := range run() {
		if n != 0 {
			t.Errorf("second purge deleted %d in %s", n, k)
		}
	}
}

// The tenant's box keypair, every version, leaves OpenBao KV; another
// tenant's stays; a second purge finds nothing; a failed delete is
// returned and the retry finishes it.
func TestPurgeTenantBoxKeys(t *testing.T) {
	kv := tenantboxtest.Start(t)
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)
	kv.SeedKeypair(t, tenantboxtest.TenantPath("t_a"), nil)
	kv.SeedKeypair(t, tenantboxtest.TenantPath("t_a"), map[string]string{"origin": "rotated"})
	kv.SeedKeypair(t, tenantboxtest.TenantPath("t_ab"), nil)
	ctx := context.Background()
	n, err := PurgeTenantBoxKeys(ctx, "t_a")
	if err != nil || n != 1 {
		t.Fatalf("PurgeTenantBoxKeys = %d, %v; want 1", n, err)
	}
	if kv.Has(tenantboxtest.TenantPath("t_a")) {
		t.Error("t_a's keypair (or a version of it) is still in KV")
	}
	if !kv.Has(tenantboxtest.TenantPath("t_ab")) {
		t.Error("t_ab's keypair was deleted")
	}
	if n, err := PurgeTenantBoxKeys(ctx, "t_a"); err != nil || n != 0 {
		t.Fatalf("second purge = %d, %v", n, err)
	}
	kv.FailMetadataDeletes = 1
	kv.SeedKeypair(t, tenantboxtest.TenantPath("t_c"), nil)
	if _, err := PurgeTenantBoxKeys(ctx, "t_c"); err == nil {
		t.Error("a failed delete reported success")
	}
	if n, err := PurgeTenantBoxKeys(ctx, "t_c"); err != nil || n != 1 || kv.Has(tenantboxtest.TenantPath("t_c")) {
		t.Errorf("retried purge = %d, %v", n, err)
	}
	// A keypair that no longer parses is deleted all the same.
	kv.Put(tenantboxtest.TenantPath("t_d"), map[string]string{"pub": "not base64", "priv": "-"})
	if n, err := PurgeTenantBoxKeys(ctx, "t_d"); err != nil || n != 1 || kv.Has(tenantboxtest.TenantPath("t_d")) {
		t.Errorf("purge of a malformed keypair = %d, %v", n, err)
	}
	if _, err := PurgeTenantBoxKeys(ctx, "t c"); err == nil {
		t.Error("an invalid tenant ID was accepted")
	}
}
