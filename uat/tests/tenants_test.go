//go:build uat

package uattests

import (
	"net/http"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// tenantIDRe is saasapi's tenant ID: "t_" and 16 lowercase base32
// characters (internal/saasapi/idgen.go).
var tenantIDRe = regexp.MustCompile(`^t_[a-z2-7]{16}$`)

func TestSmokeT1_CreateTenant(t *testing.T) {
	sc := harness.Begin(t, "T1")
	ctx := ctxFor(t, 15*time.Minute)
	sc.Step("POST /v1/tenants")
	st, r, err := fleet.API.CreateTenant(ctx, token(t, sc, 1, harness.RoleAdmin), "uat-t1-"+harness.Nonce(6))
	sc.Expect(r, err, http.StatusAccepted, "", "POST /v1/tenants")
	if !tenantIDRe.MatchString(st.TenantID) {
		sc.Errorf("tenant_id %q is not t_ and 16 base32 characters", st.TenantID)
	}
	if st.Status != harness.TenantPending {
		sc.Errorf("status %q, want pending", st.Status)
	}
	if !fleet.Tokens.HasAdmin() {
		sc.Skipf("tenant %s was created (202, pending), but polling its status needs a token whose organization.id is the new ID: %v", st.TenantID, harness.ErrNoKeycloakAdmin)
	}
	sc.Step("create a Keycloak user for %s", st.TenantID)
	user, err := fleet.Tokens.ScratchUser(ctx, st.TenantID)
	sc.NoErr(err, "creating a scratch Keycloak user")
	t.Cleanup(func() { _ = user.Delete(cleanupCtx()) })
	tok, err := user.Token(ctx)
	sc.NoErr(err, "scratch user token")
	t.Cleanup(func() { offboard(t, st.TenantID, tok) })

	sc.Step("poll GET /v1/tenants/%s/status until active", st.TenantID)
	got, err := fleet.API.WaitTenantStatus(ctx, tok, st.TenantID, harness.DefaultTenantTimeout, harness.TenantActive, harness.TenantFailed)
	sc.NoErr(err, "waiting for provisioning")
	if got.Status != harness.TenantActive {
		sc.Fatalf("provisioning ended %s: last_error %q", got.Status, got.LastError)
	}
	if got.TenantID != st.TenantID {
		sc.Errorf("status names tenant %q, want %q", got.TenantID, st.TenantID)
	}
}

func TestCoreT2_TenantValidation(t *testing.T) {
	sc := harness.Begin(t, "T2")
	ctx := ctxFor(t, 2*time.Minute)
	tok := token(t, sc, 1, harness.RoleAdmin)
	for _, c := range []struct{ name, body string }{
		{"no name", `{}`},
		{"empty name", `{"name": ""}`},
		{"blank name", `{"name": "   "}`},
		{"plan only", `{"plan_id": "uat"}`},
		{"not JSON", `{"name": `},
	} {
		sc.Step("POST /v1/tenants with %s", c.name)
		r, err := fleet.API.Do(ctx, harness.Request{
			Method: http.MethodPost, Path: "/v1/tenants", Token: tok,
			RawBody: []byte(c.body), ContentType: "application/json",
		})
		sc.Check(r, err, http.StatusBadRequest, "invalid_request", "POST /v1/tenants with %s", c.name)
	}
}

func TestCoreT3_StatusErrorFields(t *testing.T) {
	sc := harness.Begin(t, "T3")
	ctx := ctxFor(t, 2*time.Minute)
	allowed := []string{"tenant_id", "status", "last_error", "warning"}
	for _, n := range []int{1, 2} {
		tsc := sc.ForTenant(t, n)
		tsc.Step("GET status of tenant %d", n)
		r, err := fleet.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(fleet.TenantID(n), "status"), Token: token(t, tsc, n, harness.RoleAdmin)})
		tsc.Expect(r, err, http.StatusOK, "", "GET status")
		var body map[string]any
		tsc.NoErr(r.Decode(&body), "decoding the status")
		for k, v := range body {
			if !slices.Contains(allowed, k) {
				tsc.Errorf("status has an undocumented field %q", k)
			}
			if _, ok := v.(string); !ok {
				tsc.Errorf("status field %q is %T, want a string", k, v)
			}
		}
		if body["status"] != harness.TenantActive {
			tsc.Errorf("tenant %d is %v, want active", n, body["status"])
		}
		if le, ok := body["last_error"]; ok && body["status"] == harness.TenantActive {
			tsc.Logf("active tenant carries last_error %q (from an earlier job)", le)
		}
	}
	// What can't be asserted from outside: last_error appears only after
	// a provisioning job got no result SAASAPI_OUTBOX_MAX_ATTEMPTS times
	// (farmer down for the sweeper's whole backoff, about an hour with
	// the defaults), and warning only when farmer's result carries one.
	// Neither can be caused from the runner without stopping farmer for
	// that long. internal/saasapi/tenants_test.go covers both fields.
	sc.Skipf("the field shape was checked on both tenants, but a last_error or warning can't be caused from outside (it needs farmer unreachable through %s publishes, about an hour); covered by unit tests in internal/saasapi", "SAASAPI_OUTBOX_MAX_ATTEMPTS")
}

func TestCoreT4_DeleteTenant(t *testing.T) {
	sc := harness.Begin(t, "T4")
	if !fleet.Tokens.HasAdmin() {
		sc.Skipf("%v; T4 needs a tenant of its own to delete", harness.ErrNoKeycloakAdmin)
	}
	ctx := ctxFor(t, 20*time.Minute)
	sc.Step("create a scratch tenant")
	st, r, err := fleet.API.CreateTenant(ctx, token(t, sc, 1, harness.RoleAdmin), "uat-t4-"+harness.Nonce(6))
	sc.Expect(r, err, http.StatusAccepted, "", "POST /v1/tenants")
	user, err := fleet.Tokens.ScratchUser(ctx, st.TenantID)
	sc.NoErr(err, "creating a scratch Keycloak user")
	t.Cleanup(func() { _ = user.Delete(cleanupCtx()) })
	tok, err := user.Token(ctx)
	sc.NoErr(err, "scratch user token")

	deleted := false
	t.Run("while_provisioning", func(t *testing.T) {
		ssc := harness.Begin(t, "T4")
		ssc.Step("DELETE while the tenant is pending")
		r, err := fleet.API.DeleteTenant(ctx, tok, st.TenantID)
		ssc.NoErr(err, "DELETE")
		switch {
		case r.Is(http.StatusConflict, "provisioning_in_progress"):
		case r.Status == http.StatusAccepted:
			deleted = true
			ssc.Skipf("provisioning finished before the DELETE arrived (it answered 202), so the 409 provisioning_in_progress window couldn't be observed; internal/saasapi tests cover it")
		default:
			ssc.Fatalf("want 409 provisioning_in_progress (or 202 if provisioning already finished), got %s", r)
		}
	})

	t.Run("offboard", func(t *testing.T) {
		ssc := harness.Begin(t, "T4")
		if !deleted {
			ssc.Step("wait until active")
			got, err := fleet.API.WaitTenantStatus(ctx, tok, st.TenantID, harness.DefaultTenantTimeout, harness.TenantActive, harness.TenantFailed)
			ssc.NoErr(err, "waiting for provisioning")
			if got.Status != harness.TenantActive {
				ssc.Fatalf("provisioning ended %s: %q", got.Status, got.LastError)
			}
			ssc.Step("DELETE the active tenant")
			r, err := fleet.API.DeleteTenant(ctx, tok, st.TenantID)
			ssc.Expect(r, err, http.StatusAccepted, "", "DELETE")
			var body harness.TenantStatus
			ssc.NoErr(r.Decode(&body), "decoding the DELETE answer")
			if body.Status != harness.TenantOffboarding {
				ssc.Errorf("DELETE answered status %q, want offboarding", body.Status)
			}
		}
		ssc.Step("poll until offboarded")
		got, err := fleet.API.WaitTenantStatus(ctx, tok, st.TenantID, harness.DefaultTenantTimeout, harness.TenantOffboarded)
		ssc.NoErr(err, "waiting for offboarding")
		if got.Status != harness.TenantOffboarded {
			ssc.Fatalf("status %s", got.Status)
		}
		ssc.Step("DELETE again")
		r, err := fleet.API.DeleteTenant(ctx, tok, st.TenantID)
		ssc.Check(r, err, http.StatusConflict, "offboarding_in_progress", "a second DELETE")
	})
}

func TestCoreT5_OffboardedTenantCutOff(t *testing.T) {
	sc := harness.Begin(t, "T5")
	ctx := ctxFor(t, 25*time.Minute)
	tid, tok := scratchTenant(t, sc, "t5", true)

	sc.Step("mint a key in the scratch tenant")
	key, err := fleet.API.MintKey(ctx, tok, tid, 1, 3)
	sc.NoErr(err, "minting a key")
	sc.Step("enrol a synthetic sprout before offboarding")
	synth, res := syntheticEnroll(t, sc, key.RegistrationKey)
	if !res.OK() || res.TenantID != tid {
		sc.Fatalf("enrolment before offboarding: %s (want 200 in tenant %s)", res, tid)
	}
	asset := "uat-t5-" + harness.Nonce(8)
	r, err := fleet.API.LinkAsset(ctx, tok, tid, res.SproutID, asset)
	sc.Expect(r, err, http.StatusCreated, "", "linking an asset to the synthetic sprout")

	sc.Step("offboard the tenant")
	r, err = fleet.API.DeleteTenant(ctx, tok, tid)
	sc.Expect(r, err, http.StatusAccepted, "", "DELETE")
	got, err := fleet.API.WaitTenantStatus(ctx, tok, tid, harness.DefaultTenantTimeout, harness.TenantOffboarded)
	sc.NoErr(err, "waiting for offboarded")
	_ = got

	t.Run("keys", func(t *testing.T) {
		ssc := harness.Begin(t, "T5")
		ssc.Step("enrol a new synthetic sprout with the tenant's unspent key")
		_, res := syntheticEnroll(t, ssc, key.RegistrationKey)
		if res.OK() || res.Status != http.StatusUnauthorized || res.Error != "enrollment_failed" {
			ssc.Errorf("want 401 enrollment_failed, got %s", res)
		}
		ssc.Step("re-enrol the existing synthetic sprout")
		res2, err := fleet.Enroll.Enroll(ctx, synth, key.RegistrationKey)
		ssc.NoErr(err, "enrol")
		if res2.OK() {
			ssc.Errorf("the offboarded tenant's sprout got an identity back: %s", res2)
		}
	})
	t.Run("sprouts", func(t *testing.T) {
		ssc := harness.Begin(t, "T5")
		ssc.Step("post a cmd.run to the tenant's sprout")
		_, r, err := fleet.API.PostBatch(ctx, tok, tid, []string{asset}, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
		ssc.Check(r, err, http.StatusConflict, "tenant_not_active", "a batch in an offboarded tenant")
	})
	t.Run("bus_account", func(t *testing.T) {
		ssc := harness.Begin(t, "T5")
		// The bus account is farmer's NATS Account for the tenant, pushed
		// to the bus in the DMZ. The runner reaches only saasapi, Keycloak
		// and Envoy, and a synthetic sprout never opens a bus connection,
		// so whether the Account was revoked can't be observed from here.
		// internal/pki's deprovision tests (and PKI.1) cover the lockout.
		ssc.Skipf("the tenant's NATS Account lives on the bus, which the runner can't reach and a synthetic sprout never connects to; covered by internal/pki deprovision tests")
	})
}

func TestCoreT6_TenantsStaySeparate(t *testing.T) {
	sc := harness.Begin(t, "T6")
	f := ready(t, sc)
	ctx := ctxFor(t, 15*time.Minute)
	tok := map[int]string{1: token(t, sc, 1, harness.RoleAdmin), 2: token(t, sc, 2, harness.RoleAdmin)}
	other := map[int]int{1: 2, 2: 1}

	t.Run("tenants", func(t *testing.T) {
		ssc := harness.Begin(t, "T6")
		for n, o := range other {
			ssc.Step("tenant %d reads tenant %d", n, o)
			r, err := f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(f.TenantID(o)), Token: tok[n]})
			ssc.Check(r, err, http.StatusForbidden, "forbidden", "tenant %d's token on tenant %d", n, o)
		}
	})
	t.Run("keys", func(t *testing.T) {
		ssc := harness.Begin(t, "T6")
		keys := map[int]harness.EnrollmentKey{1: mintKey(t, ssc, 1, 1, 1), 2: mintKey(t, ssc, 2, 1, 1)}
		for n, o := range other {
			ssc.Step("tenant %d lists its keys", n)
			list, r, err := f.API.ListKeys(ctx, tok[n], f.TenantID(n))
			ssc.Expect(r, err, http.StatusOK, "", "listing keys")
			if _, ok := harness.FindKey(list, keys[n].KeyID); !ok {
				ssc.Errorf("tenant %d's list lacks its own key %s", n, keys[n].KeyID)
			}
			if _, ok := harness.FindKey(list, keys[o].KeyID); ok {
				ssc.Errorf("tenant %d's list shows tenant %d's key %s", n, o, keys[o].KeyID)
			}
			ssc.Step("tenant %d revokes tenant %d's key under its own path", n, o)
			r, err = f.API.RevokeKey(ctx, tok[n], f.TenantID(n), keys[o].KeyID)
			ssc.Check(r, err, http.StatusNotFound, "enrollment_key_not_found", "revoking another tenant's key under one's own tenant")
		}
	})
	t.Run("sprouts", func(t *testing.T) {
		ssc := harness.Begin(t, "T6")
		for n, o := range other {
			theirs := harness.Assets(f.Sprouts(harness.InTenant(o)))
			if len(theirs) == 0 {
				continue
			}
			ssc.Step("tenant %d looks up tenant %d's asset IDs", n, o)
			lk, r, err := f.API.LookupAssets(ctx, tok[n], f.TenantID(n), theirs)
			ssc.Expect(r, err, http.StatusOK, "", "lookup")
			if len(lk.Results) != 0 {
				ssc.Errorf("tenant %d resolved tenant %d's assets: %+v", n, o, lk.Results)
			}
			for _, a := range theirs {
				if !lk.IsUnresolved(a) {
					ssc.Errorf("asset %s isn't listed unresolved", a)
				}
			}
		}
	})
	t.Run("recipes", func(t *testing.T) {
		ssc := harness.Begin(t, "T6")
		name := "uat.t6." + harness.Nonce(8)
		ssc.Step("tenant 1 uploads %s", name)
		_, err := f.API.UploadRecipe(ctx, tok[1], f.TenantID(1), name, "steps: {}\n")
		ssc.NoErr(err, "uploading")
		t.Cleanup(func() { _, _ = f.API.DeleteRecipe(cleanupCtx(), tok[1], f.TenantID(1), name) })
		ssc.Step("tenant 2 reads %s", name)
		_, r, err := f.API.GetRecipe(ctx, tok[2], f.TenantID(2), name)
		ssc.Check(r, err, http.StatusNotFound, "recipe_not_found", "tenant 2 reading tenant 1's recipe")
		all, err := f.API.AllRecipes(ctx, tok[2], f.TenantID(2))
		ssc.NoErr(err, "listing tenant 2's recipes")
		for _, rec := range all {
			if rec.Name == name {
				ssc.Errorf("tenant 2's list shows tenant 1's recipe %s", name)
			}
		}
	})
	t.Run("batches", func(t *testing.T) {
		ssc := harness.Begin(t, "T6")
		ssc.Step("tenant 1 posts a batch")
		id, err := f.API.StartBatch(ctx, tok[1], f.TenantID(1), []string{"uat-t6-none-" + harness.Nonce(6)}, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
		ssc.NoErr(err, "posting")
		ssc.Step("tenant 2 reads batch %s under its own path", id)
		_, r, err := f.API.GetBatch(ctx, tok[2], f.TenantID(2), id)
		ssc.Check(r, err, http.StatusNotFound, "batch_not_found", "tenant 2 reading tenant 1's batch")
	})
	t.Run("job_logs", func(t *testing.T) {
		ssc := harness.Begin(t, "T6")
		// saasapi has no job log route; a batch reports only status, exit
		// code and error code per item. Farmer keeps job logs under
		// jobs/<tenant_id>/<sprout_id>/<jid>/ (FIX.2), read by the imas
		// CLI over the bus, which the runner can't reach.
		ssc.Skipf("saasapi exposes no job logs and the CLI's path to them (the bus) isn't reachable from the runner; FIX.2's unit tests cover the per-tenant job keys")
	})
}
