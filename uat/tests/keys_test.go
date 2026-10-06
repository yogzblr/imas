//go:build uat

package uattests

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func TestSmokeK1_MintKey(t *testing.T) {
	sc := harness.Begin(t, "K1")
	ctx := ctxFor(t, 3*time.Minute)
	tok := token(t, sc, 1, harness.RoleAdmin)
	tid := fleet.TenantID(1)

	sc.Step("mint a key for 2 hours and 3 uses")
	before := time.Now()
	key, err := fleet.API.MintKey(ctx, tok, tid, 2, 3)
	sc.NoErr(err, "POST enrollment-keys")
	t.Cleanup(func() { _, _ = fleet.API.RevokeKey(cleanupCtx(), tok, tid, key.KeyID) })
	if !strings.HasPrefix(key.KeyID, "ek_") {
		sc.Errorf("key_id %q doesn't start with ek_", key.KeyID)
	}
	if !strings.HasPrefix(key.RegistrationKey, key.KeyID+".") || len(key.RegistrationKey) <= len(key.KeyID)+1 {
		sc.Errorf("registration_key isn't <key_id>.<secret>")
	}
	if key.MaxUses != 3 {
		sc.Errorf("max_uses %d, want 3", key.MaxUses)
	}
	want := before.Add(2 * time.Hour)
	if d := key.ExpiresAt.Sub(want); d < -5*time.Minute || d > 5*time.Minute {
		sc.Errorf("expires_at %s, want about %s (runner clock)", key.ExpiresAt.Format(time.RFC3339), want.Format(time.RFC3339))
	}

	sc.Step("list the tenant's keys")
	list, r, err := fleet.API.ListKeys(ctx, tok, tid)
	sc.Expect(r, err, http.StatusOK, "", "GET enrollment-keys")
	k, ok := harness.FindKey(list, key.KeyID)
	if !ok {
		sc.Fatalf("the list lacks key %s", key.KeyID)
	}
	if k.State != "active" || k.UsedCount != 0 || k.MaxUses != 3 {
		sc.Errorf("listed as state=%s used=%d max=%d, want active 0 3", k.State, k.UsedCount, k.MaxUses)
	}
	if strings.Contains(string(r.Body), key.RegistrationKey[len(key.KeyID)+1:]) {
		sc.Errorf("the key list carries the secret")
	}

	sc.Step("refuse out of range values")
	for _, c := range []struct{ hours, uses int }{{0, 1}, {721, 1}, {1, 0}, {1, 10001}} {
		_, r, err := fleet.API.CreateKey(ctx, tok, tid, c.hours, c.uses)
		if err == nil && r.Status == http.StatusTooManyRequests {
			time.Sleep(6 * time.Second)
			_, r, err = fleet.API.CreateKey(ctx, tok, tid, c.hours, c.uses)
		}
		sc.Check(r, err, http.StatusBadRequest, "invalid_request", "expires_in_hours=%d max_uses=%d", c.hours, c.uses)
	}
}

func TestCoreK2_ExhaustedKeyRefused(t *testing.T) {
	sc := harness.Begin(t, "K2")
	ctx := ctxFor(t, 10*time.Minute)
	key := mintKey(t, sc, 1, 1, 1)

	sc.Step("enrol a synthetic sprout with the one-use key")
	_, first := syntheticEnroll(t, sc, key.RegistrationKey)
	if !first.OK() || first.TenantID != fleet.TenantID(1) {
		sc.Fatalf("first enrolment: %s, want 200 in tenant 1", first)
	}
	if first.HasGatewayJWT {
		sc.Errorf("step 1 answered with a gateway JWT; only the box key proof of step 2 may earn one (J.2)")
	}
	sc.Step("enrol a second synthetic sprout with the spent key")
	_, second := syntheticEnroll(t, sc, key.RegistrationKey)
	if second.Status != http.StatusUnauthorized || second.Error != "enrollment_failed" {
		sc.Errorf("second enrolment: want 401 enrollment_failed, got %s", second)
	}
	sc.Step("the key is listed exhausted")
	list, r, err := fleet.API.ListKeys(ctx, token(t, sc, 1, harness.RoleAdmin), fleet.TenantID(1))
	sc.Expect(r, err, http.StatusOK, "", "GET enrollment-keys")
	if k, ok := harness.FindKey(list, key.KeyID); !ok || k.State != "exhausted" || k.UsedCount != 1 {
		sc.Errorf("listed as %+v, want state exhausted, used_count 1", k)
	}
}

func TestCoreK3_RevokedKeyRefused(t *testing.T) {
	sc := harness.Begin(t, "K3")
	ctx := ctxFor(t, 10*time.Minute)
	tok := token(t, sc, 1, harness.RoleAdmin)
	tid := fleet.TenantID(1)
	key := mintKey(t, sc, 1, 1, 5)

	sc.Step("enrol a synthetic sprout")
	_, first := syntheticEnroll(t, sc, key.RegistrationKey)
	if !first.OK() {
		sc.Fatalf("enrolment before revocation: %s", first)
	}
	asset := linkSynthetic(t, sc, 1, first.SproutID)

	sc.Step("revoke the key")
	r, err := fleet.API.RevokeKey(ctx, tok, tid, key.KeyID)
	sc.Expect(r, err, http.StatusOK, "", "DELETE enrollment-keys/%s", key.KeyID)

	sc.Step("enrol another synthetic sprout with the revoked key")
	_, second := syntheticEnroll(t, sc, key.RegistrationKey)
	if second.Status != http.StatusUnauthorized || second.Error != "enrollment_failed" {
		sc.Errorf("want 401 enrollment_failed, got %s", second)
	}
	list, r, err := fleet.API.ListKeys(ctx, tok, tid)
	sc.Expect(r, err, http.StatusOK, "", "GET enrollment-keys")
	if k, ok := harness.FindKey(list, key.KeyID); !ok || k.State != "revoked" {
		sc.Errorf("listed as %+v, want state revoked", k)
	}

	sc.Step("the sprout enrolled before the revocation stays")
	lk, r, err := fleet.API.LookupAssets(ctx, tok, tid, []string{asset})
	sc.Expect(r, err, http.StatusOK, "", "lookup")
	if res, ok := lk.Find(asset); !ok || res.SproutID != first.SproutID || res.KeyState != "accepted" {
		sc.Errorf("the enrolled sprout after revocation: %+v (found %v), want sprout %s accepted", res, ok, first.SproutID)
	}
}

func TestCoreK4_MintRateLimited(t *testing.T) {
	sc := harness.Begin(t, "K4")
	ctx := ctxFor(t, 3*time.Minute)
	tok := token(t, sc, 2, harness.RoleAdmin)
	tid := fleet.TenantID(2)
	var minted []string
	t.Cleanup(func() {
		for _, id := range minted {
			_, _ = fleet.API.RevokeKey(cleanupCtx(), tok, tid, id)
		}
	})

	sc.Step("let the bucket refill")
	time.Sleep(6 * time.Second)
	sc.Step("mint 8 keys back to back")
	ok, limited := 0, 0
	for i := 0; i < 8; i++ {
		key, r, err := fleet.API.CreateKey(ctx, tok, tid, 1, 1)
		sc.NoErr(err, "POST enrollment-keys")
		switch {
		case r.Status == http.StatusOK:
			ok++
			minted = append(minted, key.KeyID)
		case r.Is(http.StatusTooManyRequests, "rate_limited"):
			limited++
		default:
			sc.Fatalf("request %d: %s", i+1, r)
		}
	}
	if ok < 5 {
		sc.Errorf("only %d of 8 succeeded; the burst is 5", ok)
	}
	if limited == 0 {
		sc.Errorf("all 8 succeeded; want 429 rate_limited after the burst of 5")
	}
	sc.Step("wait and mint again")
	time.Sleep(3 * time.Second)
	key, r, err := fleet.API.CreateKey(ctx, tok, tid, 1, 1)
	if sc.Check(r, err, http.StatusOK, "", "minting after the bucket refilled") {
		minted = append(minted, key.KeyID)
	}
	sc.Step("the other tenant's budget is its own")
	for i := 0; i < 6; i++ { // drain tenant 2 again
		if k, r, err := fleet.API.CreateKey(ctx, tok, tid, 1, 1); err == nil && r.Status == http.StatusOK {
			minted = append(minted, k.KeyID)
		}
	}
	tok1 := token(t, sc, 1, harness.RoleAdmin)
	other, r, err := fleet.API.CreateKey(ctx, tok1, fleet.TenantID(1), 1, 1)
	if sc.Check(r, err, http.StatusOK, "", "tenant 1 minting while tenant 2 is limited") {
		t.Cleanup(func() { _, _ = fleet.API.RevokeKey(cleanupCtx(), tok1, fleet.TenantID(1), other.KeyID) })
	}
}
