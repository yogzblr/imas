//go:build uat

package uattests

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// fleet is the run's shared harness, built once in TestMain.
var fleet *harness.Fleet

// earlyToken is tenant 1's admin token minted when the run starts. By the
// time X1 runs it has usually expired, which gives X1 a genuinely expired
// Keycloak token without a special client.
var earlyToken string

func TestMain(m *testing.M) {
	env, err := harness.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "uat: %v\n", err)
		os.Exit(1)
	}
	fleet, err = harness.NewFleet(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uat: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	earlyToken, err = fleet.Tokens.Fresh(ctx, 1, harness.RoleAdmin)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "uat: tenant 1's admin can't get a Keycloak token, so nothing can run: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// ready returns the fleet with every sprout's ID resolved and asset ID
// linked (once per run), failing the test if that couldn't start at all.
func ready(t *testing.T, sc *harness.Scenario) *harness.Fleet {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := fleet.Prepare(ctx); err != nil {
		sc.Fatalf("preparing the sprouts (sprout IDs, asset links): %v", err)
	}
	return fleet
}

// ctxFor returns a context bounded by d, cancelled when the test ends.
func ctxFor(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// token returns a tenant's token for a role, failing the test if Keycloak
// won't give one.
func token(t *testing.T, sc *harness.Scenario, tenant int, role harness.Role) string {
	t.Helper()
	tok, err := fleet.Tokens.Tenant(ctxFor(t, time.Minute), tenant, role)
	sc.NoErr(err, "getting tenant %d's %s token", tenant, role)
	return tok
}

// scratchTenant creates a tenant for the test and a Keycloak user mapped
// to it, and returns the tenant ID and that user's token. It skips the
// test, with the reason, when keycloak.json has no admin identity: a
// tenant created during the run is unreachable without a token whose
// organization.id is its ID. waitActive also waits until provisioning
// has finished.
func scratchTenant(t *testing.T, sc *harness.Scenario, purpose string, waitActive bool) (string, string) {
	t.Helper()
	ctx := ctxFor(t, 15*time.Minute)
	if !fleet.Tokens.HasAdmin() {
		sc.Skipf("%v; this scenario needs a tenant of its own", harness.ErrNoKeycloakAdmin)
	}
	sc.Step("create a scratch tenant (%s)", purpose)
	st, r, err := fleet.API.CreateTenant(ctx, token(t, sc, 1, harness.RoleAdmin), "uat-"+purpose+"-"+harness.Nonce(6))
	sc.Expect(r, err, 202, "", "POST /v1/tenants")
	sc.Step("create a Keycloak user for tenant %s", st.TenantID)
	user, err := fleet.Tokens.ScratchUser(ctx, st.TenantID)
	sc.NoErr(err, "creating a scratch Keycloak user")
	t.Cleanup(func() {
		if err := user.Delete(context.Background()); err != nil {
			t.Logf("deleting the scratch Keycloak user: %v", err)
		}
	})
	tok, err := user.Token(ctx)
	sc.NoErr(err, "scratch user token")
	if waitActive {
		sc.Step("wait for tenant %s to be active", st.TenantID)
		got, err := fleet.API.WaitTenantStatus(ctx, tok, st.TenantID, harness.DefaultTenantTimeout, harness.TenantActive, harness.TenantFailed)
		sc.NoErr(err, "waiting for provisioning")
		if got.Status != harness.TenantActive {
			sc.Fatalf("provisioning failed: last_error %q", got.LastError)
		}
	}
	return st.TenantID, tok
}

// offboard deletes a scratch tenant and waits until it is offboarded,
// best effort (used in cleanups).
func offboard(t *testing.T, tenantID, tok string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := fleet.API.WaitTenantStatus(ctx, tok, tenantID, harness.DefaultTenantTimeout,
		harness.TenantActive, harness.TenantFailed, harness.TenantOffboarding, harness.TenantOffboarded); err != nil {
		t.Logf("scratch tenant %s: %v", tenantID, err)
		return
	}
	if _, err := fleet.API.DeleteTenant(ctx, tok, tenantID); err != nil {
		t.Logf("offboarding scratch tenant %s: %v", tenantID, err)
	}
}

// mintKey mints a key in tenant n and revokes it when the test ends.
func mintKey(t *testing.T, sc *harness.Scenario, n, hours, maxUses int) harness.EnrollmentKey {
	t.Helper()
	ctx := ctxFor(t, 2*time.Minute)
	tok := token(t, sc, n, harness.RoleAdmin)
	key, err := fleet.API.MintKey(ctx, tok, fleet.TenantID(n), hours, maxUses)
	sc.NoErr(err, "minting an enrolment key in tenant %d", n)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = fleet.API.RevokeKey(ctx, tok, fleet.TenantID(n), key.KeyID)
	})
	return key
}

// syntheticEnroll makes a synthetic sprout and enrolls it (step 1 only).
func syntheticEnroll(t *testing.T, sc *harness.Scenario, joinToken string) (*harness.SyntheticSprout, *harness.EnrollResult) {
	t.Helper()
	s, err := harness.NewSyntheticSprout("uat-synth-" + harness.Nonce(8))
	sc.NoErr(err, "making a synthetic sprout")
	res, err := fleet.Enroll.Enroll(ctxFor(t, 3*time.Minute), s, joinToken)
	sc.NoErr(err, "POST /v1/enroll through Envoy")
	return s, res
}

// linkSynthetic links a fresh asset ID to a synthetic sprout of tenant n
// and returns it.
func linkSynthetic(t *testing.T, sc *harness.Scenario, n int, sproutID string) string {
	t.Helper()
	asset := "uat-synth-" + harness.Nonce(10)
	r, err := fleet.API.LinkAsset(ctxFor(t, time.Minute), token(t, sc, n, harness.RoleAdmin), fleet.TenantID(n), sproutID, asset)
	sc.Expect(r, err, 201, "", "linking asset %s to synthetic sprout %s", asset, sproutID)
	return asset
}

// cleanupCtx is the context of a cleanup: the HTTP client's own timeout
// bounds each call.
func cleanupCtx() context.Context { return context.Background() }
