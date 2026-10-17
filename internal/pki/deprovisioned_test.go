package pki

// A deprovisioned tenant fails closed on every path that issues or reads a
// sprout identity, a database error included (security review 2026-10,
// L10 and I7; docs/briefs/T-pre-azure.md T4). FLAG FOR SECURITY REVIEW.
// The gateway JWT check of /files/ and the update manifest is tested
// through the router in internal/api (TestGatewayJWT_DeprovisionedTenantRefused).

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// countSeenRelocks installs a fresh seenRelocker whose pushes are
// counted per tenant instead of reaching a bus.
func countSeenRelocks(t *testing.T) func() map[string]int {
	t.Helper()
	var mu sync.Mutex
	pushes := map[string]int{}
	origRelocker, origPush := seenRelocks, relockPush
	seenRelocks = newSeenRelocker()
	relockPush = func(tenantID string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		pushes[tenantID]++
		return true, nil
	}
	t.Cleanup(func() { seenRelocks, relockPush = origRelocker, origPush })
	return func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range pushes {
			out[k] = v
		}
		return out
	}
}

func newUserKeyPair(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return kp, pub
}

func insertTenant(t *testing.T, id string, deleted bool) {
	t.Helper()
	if err := db.Create(&tenantRow{ID: id, Name: id, Deleted: deleted, CreatedAt: time.Now().Unix()}).Error; err != nil {
		t.Fatal(err)
	}
}

func dropTable(t *testing.T, model any) {
	t.Helper()
	if err := db.Migrator().DropTable(model); err != nil {
		t.Fatal(err)
	}
}

// SproutIDAndTenantForNKey: no accepted row is ErrSproutIDNotFound and
// only that; a deprovisioned tenant is ErrTenantDeprovisioned (with a
// lock-out pushed); an NKey accepted in two tenants is refused; and a
// database error, in either lookup, is an error, never not-found.
func TestSproutIDAndTenantForNKey_FailsClosed(t *testing.T) {
	setupTestPKI(t)
	pushes := countSeenRelocks(t)
	insertTenant(t, "t_live", false)
	insertTenant(t, "t_gone", true)
	_, live := newUserKeyPair(t)
	_, gone := newUserKeyPair(t)
	_, twice := newUserKeyPair(t)
	_, pending := newUserKeyPair(t)
	for _, r := range []nkeyRow{
		{TenantID: "t_live", SproutID: "web-01", NKey: live, State: stateAccepted},
		{TenantID: "t_gone", SproutID: "web-01", NKey: gone, State: stateAccepted},
		{TenantID: "t_live", SproutID: "web-02", NKey: twice, State: stateAccepted},
		{TenantID: "t_gone", SproutID: "web-02", NKey: twice, State: stateAccepted},
		{TenantID: "t_live", SproutID: "web-03", NKey: pending, State: stateUnaccepted},
	} {
		if err := upsertNKeyRow(r); err != nil {
			t.Fatal(err)
		}
	}

	if tenant, sprout, err := SproutIDAndTenantForNKey(live); err != nil || tenant != "t_live" || sprout != "web-01" {
		t.Errorf("live tenant: %q %q %v", tenant, sprout, err)
	}
	if _, _, err := SproutIDAndTenantForNKey(pending); !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("unaccepted NKey: %v, want ErrSproutIDNotFound", err)
	}
	if _, _, err := SproutIDAndTenantForNKey(gone); !errors.Is(err, ErrTenantDeprovisioned) {
		t.Errorf("deprovisioned tenant: %v, want ErrTenantDeprovisioned", err)
	}
	if got := pushes()["t_gone"]; got != 1 {
		t.Errorf("lock-outs pushed for t_gone = %d, want 1", got)
	}
	if _, _, err := SproutIDAndTenantForNKey(twice); !errors.Is(err, errNKeyAmbiguous) {
		t.Errorf("NKey accepted in two tenants: %v, want errNKeyAmbiguous", err)
	}

	dropTable(t, &tenantRow{})
	if _, _, err := SproutIDAndTenantForNKey(live); err == nil || errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("tenant check failing: %v, want a database error", err)
	}
	dropTable(t, &nkeyRow{})
	if _, _, err := SproutIDAndTenantForNKey(live); err == nil || errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("NKey lookup failing: %v, want a database error", err)
	}
	SetDB(nil)
	if _, _, err := SproutIDAndTenantForNKey(live); err == nil || errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("no database: %v, want an error", err)
	}
}

// The tenant-keyed lookups (I7): one answer per (tenant_id, nkey), a
// second row for the pair is refused by the store, and a database error
// is not not-found.
func TestNKeyLookupInTenant(t *testing.T) {
	setupTestPKI(t)
	_, nkey := newUserKeyPair(t)
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_a", SproutID: "web-01", NKey: nkey, State: stateAccepted}); err != nil {
		t.Fatal(err)
	}
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_b", SproutID: "db-01", NKey: nkey, State: stateUnaccepted}); err != nil {
		t.Fatalf("the same NKey in another tenant: %v", err)
	}
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_a", SproutID: "web-02", NKey: nkey, State: stateRejected}); !errors.Is(err, errNKeyAmbiguous) {
		t.Errorf("a second sprout ID for an NKey in one tenant: %v, want errNKeyAmbiguous", err)
	}
	if row, err := findNKeyRowInTenant("t_a", "web-01"); err != nil || row.State != stateAccepted || row.NKey != nkey {
		t.Errorf("the refused write changed web-01: %+v, %v", row, err)
	}
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_a", SproutID: "web-01", NKey: nkey, State: stateDenied}); err != nil {
		t.Errorf("updating web-01's own row: %v", err)
	}
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_a", SproutID: "web-01", NKey: nkey, State: stateAccepted}); err != nil {
		t.Errorf("updating web-01's own row back: %v", err)
	}
	if id, err := SproutIDForNKey("t_a", nkey); err != nil || id != "web-01" {
		t.Errorf("SproutIDForNKey(t_a) = %q, %v", id, err)
	}
	if _, err := SproutIDForNKey("t_b", nkey); !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("SproutIDForNKey of an unaccepted sprout = %v, want ErrSproutIDNotFound", err)
	}
	if id, err := resolveEnrollSproutID("t_b", "another-host", nkey); err != nil || id != "db-01" {
		t.Errorf("resolveEnrollSproutID for an NKey t_b holds = %q, %v; want its sprout ID db-01", id, err)
	}
	dropTable(t, &nkeyRow{})
	if _, err := SproutIDForNKey("t_a", nkey); err == nil || errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("SproutIDForNKey with the table gone = %v, want a database error", err)
	}
	if _, err := resolveEnrollSproutID("t_a", "web-09", nkey); err == nil {
		t.Error("resolveEnrollSproutID with the table gone: no error")
	}
}

// An enrolled sprout of a deprovisioned tenant gets nothing: no sealed
// refresh opens, RefreshSprout and reissueExistingIdentity refuse and mint
// nothing, the enrollment replay is refused and spends no join-token use,
// and a join token of the tenant enrols no new host. With the tenant live
// again but its row unreadable, every one of them refuses too.
func TestDeprovisionedTenant_NoIdentityIssued(t *testing.T) {
	_, minter, store := enrollForTest(t)
	pushes := countSeenRelocks(t)
	kp, err := loadSproutNKey()
	if err != nil {
		t.Fatal(err)
	}
	nkeyPub := sproutNKeyPub(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if req, _ := sealedRefresh(t); true {
		if _, err := RefreshSprout(t.Context(), req); err != nil {
			t.Fatalf("live tenant: RefreshSprout: %v", err)
		}
	}
	store.rows["ek_2"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s2"), Expiry: time.Now().Add(time.Hour), MaxUses: 5}

	refused := func(when string) {
		t.Helper()
		calls := minter.calls
		req, _ := sealedRefresh(t)
		if _, _, err := OpenSealedRefresh(t.Context(), req.NKeyPub, req.Sealed); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("%s: OpenSealedRefresh = %v, want ErrEnrollmentFailed", when, err)
		}
		req, _ = sealedRefresh(t)
		if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("%s: RefreshSprout = %v, want ErrEnrollmentFailed", when, err)
		}
		if _, err := reissueExistingIdentity(t.Context(), "t_1", "web-01", nkeyPub, true); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("%s: reissueExistingIdentity = %v, want ErrEnrollmentFailed", when, err)
		}
		if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_2.s2", "web-01", sproutPub)); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("%s: enrollment replay = %v, want ErrEnrollmentFailed", when, err)
		}
		newKP, _ := newUserKeyPair(t)
		if _, err := Enroll(t.Context(), signedEnroll(t, newKP, "ek_2.s2", "web-02", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("%s: a new host on the tenant's join token = %v, want ErrEnrollmentFailed", when, err)
		}
		if store.rows["ek_2"].UsedCount != 0 {
			t.Errorf("%s: the join token was spent (%d uses)", when, store.rows["ek_2"].UsedCount)
		}
		if minter.calls != calls {
			t.Errorf("%s: %d gateway JWTs minted", when, minter.calls-calls)
		}
	}

	if err := markTenantDeleted("t_1"); err != nil {
		t.Fatal(err)
	}
	refused("deprovisioned")
	if got := pushes()["t_1"]; got != 1 {
		t.Errorf("lock-outs pushed for t_1 = %d, want 1 (one per tenant per %s)", got, seenRelockMinInterval)
	}

	if err := db.Model(&tenantRow{}).Where("id = ?", "t_1").Update("deleted", false).Error; err != nil {
		t.Fatal(err)
	}
	dropTable(t, &tenantRow{})
	refused("tenant row unreadable")
}

// A database error in the enrollment's first lookup refuses before the
// join token is touched (I7): it used to read as "not enrolled yet" and
// spend a use.
func TestEnroll_DatabaseErrorSpendsNoJoinToken(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	dropTable(t, &nkeyRow{})
	kp := testEnrollNKey(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("Enroll = %v, want ErrEnrollmentFailed", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("used_count = %d, want 0", store.rows["ek_1"].UsedCount)
	}
}

// acceptEnrolledNKey returns the error of a re-check after the grant's
// push that could not read the database (L10, L11): the tenant may have
// been deprovisioned meanwhile. The re-check was tried recheckAttempts
// times, with jittered, doubling waits.
func TestAcceptEnrolledNKey_ReturnsFailedRecheck(t *testing.T) {
	setupTestPKI(t)
	if _, _, _, err := ensureTenantAccount("t_g", "Tenant G", true); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	var waits []time.Duration
	origCheck, origSleep := relockIfDeleted, recheckSleep
	relockIfDeleted = func(*natsAuthMaterial, string) (string, bool, error) {
		attempts++
		return "", false, errors.New("database unavailable")
	}
	recheckSleep = func(d time.Duration) { waits = append(waits, d) }
	t.Cleanup(func() { relockIfDeleted, recheckSleep = origCheck, origSleep })

	_, nkey := newUserKeyPair(t)
	err := acceptEnrolledNKey("t_g", "web-1", nkey)
	if !errors.Is(err, errTenantRecheckFailed) {
		t.Fatalf("acceptEnrolledNKey = %v, want errTenantRecheckFailed", err)
	}
	if attempts != recheckAttempts {
		t.Errorf("%d re-checks, want %d", attempts, recheckAttempts)
	}
	if len(waits) != recheckAttempts-1 {
		t.Fatalf("waits %v, want %d", waits, recheckAttempts-1)
	}
	for i, w := range waits {
		full := recheckBackoff << i
		if w < full/2 || w > full {
			t.Errorf("wait %d = %s, want within [%s, %s]", i+1, w, full/2, full)
		}
	}
}
