package pki

import (
	"testing"
	"time"

	"gorm.io/gorm"
)

// boxKeyStates returns sproutID's box keys in tenantID as pub -> state.
func boxKeyStates(t *testing.T, tenantID, sproutID string) map[string]string {
	t.Helper()
	var rows []sproutBoxKeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Pub] = r.State
	}
	return out
}

// wantBoxKeyStates fails t unless sproutID's keys are exactly want.
func wantBoxKeyStates(t *testing.T, step, tenantID, sproutID string, want map[string]string) {
	t.Helper()
	got := boxKeyStates(t, tenantID, sproutID)
	if len(got) != len(want) {
		t.Fatalf("%s: keys = %v, want %v", step, got, want)
	}
	for pub, state := range want {
		if got[pub] != state {
			t.Fatalf("%s: keys = %v, want %v", step, got, want)
		}
	}
}

// upsertSproutBoxKeyActive's outcomes, whichever of its paths it takes: a
// first key goes in by the plain insert; the same key again, another key
// over an active one, and a revoked key brought back take the locking
// path. Exactly one key is active after each, the others revoked, and a
// key in grace is left in grace.
func testUpsertSproutBoxKeyActiveStates(t *testing.T) {
	const tenant, sprout = "t_upsert", "web-01"
	k1, k2, k3, k4 := testBoxPub(t), testBoxPub(t), testBoxPub(t), testBoxPub(t)
	upsert := func(step, pub string) {
		t.Helper()
		if err := upsertSproutBoxKeyActive(tenant, sprout, pub); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}

	upsert("first key", k1)
	wantBoxKeyStates(t, "first key", tenant, sprout, map[string]string{k1: boxKeyStateActive})

	upsert("same key again", k1)
	wantBoxKeyStates(t, "same key again", tenant, sprout, map[string]string{k1: boxKeyStateActive})

	upsert("another key", k2)
	wantBoxKeyStates(t, "another key", tenant, sprout, map[string]string{k1: boxKeyStateRevoked, k2: boxKeyStateActive})

	upsert("revoked key again", k1)
	wantBoxKeyStates(t, "revoked key again", tenant, sprout, map[string]string{k1: boxKeyStateActive, k2: boxKeyStateRevoked})

	// A rotation to k3 graces k1; an enrolment's key k4 then revokes only
	// the active one.
	if err := RotateSproutBoxKey(tenant, sprout, k3, time.Hour); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	wantBoxKeyStates(t, "rotated", tenant, sprout, map[string]string{k1: boxKeyStateGrace, k2: boxKeyStateRevoked, k3: boxKeyStateActive})
	upsert("key over a rotation", k4)
	after := map[string]string{k1: boxKeyStateGrace, k2: boxKeyStateRevoked, k3: boxKeyStateRevoked, k4: boxKeyStateActive}
	wantBoxKeyStates(t, "key over a rotation", tenant, sprout, after)

	// The same sprout ID in another tenant is another sprout: neither
	// touches the other's keys.
	if err := upsertSproutBoxKeyActive("t_other", sprout, k1); err != nil {
		t.Fatal(err)
	}
	wantBoxKeyStates(t, "other tenant", "t_other", sprout, map[string]string{k1: boxKeyStateActive})
	wantBoxKeyStates(t, "this tenant", tenant, sprout, after)
}

func TestUpsertSproutBoxKeyActive_States(t *testing.T) {
	newTestDB(t)
	testUpsertSproutBoxKeyActiveStates(t)
}

func TestMySQLUpsertSproutBoxKeyActive_States(t *testing.T) {
	setupMySQLEnrollTest(t)
	testUpsertSproutBoxKeyActiveStates(t)
}

// Two sprouts' first writes, in different tenants, don't wait on each
// other's open transactions: the box key of step 2 and the pki_nkeys row
// of step 1 both go in by a plain insert, whose insert intention lock
// doesn't block another. Before, each began with a locking read (the box
// key's revoke, pki_nkeys' SELECT ... FOR UPDATE) that matched no row on
// a first write and left a gap lock every other first write's insert
// waited on: the rig's sprouts, enrolling in the same second, deadlocked.
// With one transaction held open, that wait is a lock wait timeout here.
func TestMySQLFirstWritesDoNotWaitOnEachOther(t *testing.T) {
	setupMySQLEnrollTest(t)
	for name, write := range map[string]func(tx *gorm.DB, tenantID string) error{
		"box key": func(tx *gorm.DB, tenantID string) error {
			return upsertSproutBoxKeyActiveTx(tx, tenantID, "alma-01", testBoxPub(t))
		},
		"pki_nkeys": func(tx *gorm.DB, tenantID string) error {
			return acceptEnrolledNKeyTx(tx, nkeyRow{TenantID: tenantID, SproutID: "alma-01", NKey: testNKeyPub(t, testEnrollNKey(t)), State: stateAccepted})
		},
	} {
		t.Run(name, func(t *testing.T) {
			first := db.Begin()
			defer first.Rollback()
			if err := write(first, "t_gap_a"); err != nil {
				t.Fatalf("first write: %v", err)
			}

			second := db.Begin()
			defer second.Rollback()
			// The session's lock wait timeout, on the connection the
			// transaction holds; put back before it returns to the pool.
			if err := second.Exec("SET SESSION innodb_lock_wait_timeout = 2").Error; err != nil {
				t.Fatal(err)
			}
			defer second.Exec("SET SESSION innodb_lock_wait_timeout = DEFAULT")
			start := time.Now()
			err := write(second, "t_gap_b")
			if err != nil {
				t.Fatalf("a second tenant's first write waited on the first's open transaction and failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("a second tenant's first write took %s with the first's transaction open: it waited on a lock", d)
			}
		})
	}
}
