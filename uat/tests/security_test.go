//go:build uat

package uattests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func TestCoreX1_TokenRefusals(t *testing.T) {
	sc := harness.Begin(t, "X1")
	ctx := ctxFor(t, 15*time.Minute)
	tid := fleet.TenantID(1)
	good := token(t, sc, 1, harness.RoleAdmin)
	statusPath := harness.TenantPath(tid, "status")
	var bodies [][]byte

	// unauthorized expects saasapi's one 401 for every credential failure.
	unauthorized := func(sc *harness.Scenario, req harness.Request, what string) {
		sc.T.Helper()
		if req.Method == "" {
			req.Method = http.MethodGet
		}
		if req.Path == "" {
			req.Path = statusPath
		}
		r, err := fleet.API.Do(ctx, req)
		if sc.Check(r, err, http.StatusUnauthorized, "unauthorized", "%s", what) {
			bodies = append(bodies, bytes.TrimSpace(r.Body))
		}
	}

	sc.Step("control: both credentials")
	r, err := fleet.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: statusPath, Token: good})
	sc.Expect(r, err, http.StatusOK, "", "a good request")

	t.Run("no_internal_auth", func(t *testing.T) {
		unauthorized(harness.Begin(t, "X1"), harness.Request{Token: good, NoInternalAuth: true}, "no X-Internal-Auth")
	})
	t.Run("wrong_internal_auth", func(t *testing.T) {
		unauthorized(harness.Begin(t, "X1"), harness.Request{Token: good, InternalAuth: "uat-wrong-" + harness.Nonce(12)}, "a wrong X-Internal-Auth")
	})
	t.Run("no_token", func(t *testing.T) {
		ssc := harness.Begin(t, "X1")
		unauthorized(ssc, harness.Request{}, "no bearer token")
		unauthorized(ssc, harness.Request{Path: "/v1/versions"}, "no bearer token on /v1/versions")
		unauthorized(ssc, harness.Request{Method: http.MethodPost, Path: "/v1/tenants", Body: map[string]string{"name": "uat-x1"}}, "no bearer token on POST /v1/tenants")
	})
	t.Run("malformed_token", func(t *testing.T) {
		unauthorized(harness.Begin(t, "X1"), harness.Request{Token: "not-a-jwt"}, "a malformed token")
	})
	t.Run("bad_signature", func(t *testing.T) {
		unauthorized(harness.Begin(t, "X1"), harness.Request{Token: harness.TamperSignature(good)}, "a token with an altered signature")
	})
	t.Run("forged_token", func(t *testing.T) {
		ssc := harness.Begin(t, "X1")
		claims, err := harness.DecodeClaims(good)
		ssc.NoErr(err, "reading a good token's claims")
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		forged, err := harness.ForgeEdDSA(claims)
		ssc.NoErr(err, "forging")
		unauthorized(ssc, harness.Request{Token: forged}, "a token with the right claims signed by an unknown key")
	})
	t.Run("expired", func(t *testing.T) {
		ssc := harness.Begin(t, "X1")
		exp, err := harness.ExpiresAt(earlyToken)
		ssc.NoErr(err, "reading the early token's exp")
		if wait := time.Until(exp) + 5*time.Second; wait > 0 {
			if wait > 7*time.Minute {
				ssc.Skipf("the realm's access tokens live until %s; waiting %s for one to expire is too long for this run (shorten the access token lifespan of the UAT realm)", exp.Format(time.RFC3339), wait.Round(time.Second))
			}
			ssc.Step("wait %s for the token minted at the start of the run to expire", wait.Round(time.Second))
			time.Sleep(wait)
		}
		unauthorized(ssc, harness.Request{Token: earlyToken}, "an expired token")
	})
	t.Run("wrong_audience", func(t *testing.T) {
		ssc := harness.Begin(t, "X1")
		other, ok, err := fleet.Tokens.OtherAudience(ctx, 1)
		if !ok {
			ssc.Skipf("keycloak.json has no other_audience_client, so no token without saasapi's audience can be had")
		}
		ssc.NoErr(err, "token from the other client")
		if c, err := harness.DecodeClaims(other); err == nil {
			ssc.Logf("other client's token aud: %v", c["aud"])
		}
		unauthorized(ssc, harness.Request{Token: other}, "a token for another audience")
	})
	t.Run("readonly_write", func(t *testing.T) {
		ssc := harness.Begin(t, "X1")
		if !fleet.Tokens.HasUser(1, harness.RoleReadOnly) {
			ssc.Skipf("keycloak.json has no read only user for tenant 1")
		}
		ro := token(t, ssc, 1, harness.RoleReadOnly)
		name := "uat.x1." + harness.Nonce(8)
		_, r, err := fleet.API.PutRecipe(ctx, ro, tid, name, "steps: {}\n", harness.Create)
		ssc.Check(r, err, http.StatusForbidden, "forbidden", "PUT recipe with a read only token")
		r, err = fleet.API.DeleteRecipe(ctx, ro, tid, name)
		ssc.Check(r, err, http.StatusForbidden, "forbidden", "DELETE recipe with a read only token")
	})
	t.Run("same_answer", func(t *testing.T) {
		ssc := harness.Begin(t, "X1")
		ssc.Step("every 401 is the same, saying nothing of why")
		for i := 1; i < len(bodies); i++ {
			if !bytes.Equal(bodies[i], bodies[0]) {
				ssc.Errorf("401 bodies differ: %q vs %q", bodies[0], bodies[i])
			}
		}
	})
}

// envoyGet sends a request to Envoy as an unenrolled host would.
func envoyGet(t *testing.T, sc *harness.Scenario, method, path string, hdr http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxFor(t, time.Minute), method, strings.TrimRight(fleet.Env.EnvoyURL, "/")+path, nil)
	sc.NoErr(err, "building the request")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := fleet.HTTP11.Do(req)
	sc.NoErr(err, "%s %s through Envoy", method, path)
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// fromFarmer reports whether a body is a farmer JSON error, which means
// Envoy let the request through.
func fromFarmer(body string) bool {
	var m map[string]any
	return json.Unmarshal([]byte(body), &m) == nil && m["error"] != nil
}

func TestCoreX2_EnvoyRequiresGatewayJWT(t *testing.T) {
	sc := harness.Begin(t, "X2")
	forged, err := harness.ForgeEdDSA(map[string]any{
		"iss": "imas-gateway", "sub": "UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"tenant_id": fleet.TenantID(1), "sprout_id": "uat-x2", "exp": time.Now().Add(time.Hour).Unix(),
	})
	sc.NoErr(err, "forging a gateway JWT")
	ws := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}}
	withAuth := func(h http.Header, v string) http.Header {
		c := h.Clone()
		if c == nil {
			c = http.Header{}
		}
		c.Set("Authorization", v)
		return c
	}
	for _, c := range []struct {
		name, method, path string
		hdr                http.Header
	}{
		{"files_no_jwt", http.MethodGet, "/files/sprouts/" + fleet.TenantID(1) + "/uat-x2/recipe.json", nil},
		{"manifest_no_jwt", http.MethodGet, "/v1/sprout/update-manifest", nil},
		{"websocket_no_jwt", http.MethodGet, "/", ws},
		{"websocket_garbage_jwt", http.MethodGet, "/", withAuth(ws, "Bearer not-a-jwt")},
		{"websocket_forged_jwt", http.MethodGet, "/", withAuth(ws, "Bearer "+forged)},
		{"files_forged_jwt", http.MethodGet, "/files/sprouts/" + fleet.TenantID(1) + "/uat-x2/recipe.json", http.Header{"Authorization": {"Bearer " + forged}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ssc := harness.Begin(t, "X2")
			ssc.Step("%s %s", c.method, c.path)
			status, body := envoyGet(t, ssc, c.method, c.path, c.hdr)
			if status != http.StatusUnauthorized {
				ssc.Errorf("want 401 from Envoy's jwt_authn, got %d %q", status, body)
			}
			if fromFarmer(body) {
				ssc.Errorf("the refusal came from farmer (%q), so Envoy let it through", body)
			}
		})
	}
	t.Run("enroll_control", func(t *testing.T) {
		ssc := harness.Begin(t, "X2")
		// The control: /v1/enroll is the route Envoy does not gate, so a
		// junk request reaches farmer and gets farmer's own JSON refusal.
		// Without it, a dead Envoy answering 401 to everything would pass.
		synth, err := harness.NewSyntheticSprout("uat-x2-" + harness.Nonce(6))
		ssc.NoErr(err, "synthetic sprout")
		res, err := fleet.Enroll.Enroll(ctxFor(t, 3*time.Minute), synth, "ek_uatx2nonexistent.secret")
		ssc.NoErr(err, "POST /v1/enroll")
		if res.Status != http.StatusUnauthorized || res.Error != "enrollment_failed" {
			ssc.Errorf("want farmer's 401 enrollment_failed through Envoy, got %s", res)
		}
	})
}

func TestCoreX3_SproutCannotReachCore(t *testing.T) {
	sc := harness.Begin(t, "X3")
	f := ready(t, sc)
	envHost, envPort, err := f.Env.SproutEnvoyHostPort()
	sc.NoErr(err, "Envoy's address")
	port, err := strconv.Atoi(envPort)
	sc.NoErr(err, "Envoy's port")
	control := harness.Target{Host: envHost, Port: port}
	var targets []harness.Target
	for _, ip := range []string{f.Env.UAT.Core.PrivateIP, f.Env.UAT.Core.PublicIP} {
		if ip == "" {
			continue
		}
		for _, p := range f.Env.CoreProbePorts() {
			targets = append(targets, harness.Target{Host: ip, Port: p})
		}
	}
	if len(targets) == 0 {
		sc.Fatalf("uat.json gives core no private_ip or public_ip to probe")
	}
	f.EachSprout(t, sc, f.Sprouts(), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 10*time.Minute)
		all := append([]harness.Target{control}, targets...)
		sc.Step("probe Envoy (control) and %d core addresses from the host", len(targets))
		res, err := f.OnHost(ctx, sp, harness.TCPProbe(all))
		sc.NoErr(err, "vmctl.sh run")
		open, err := harness.ParseTCPProbe(res, len(all))
		sc.NoErr(err, "reading the probe")
		if !open[0] {
			sc.Fatalf("the control failed: the host can't open Envoy at %s, so the closed core ports prove nothing", control)
		}
		for i, tg := range targets {
			if open[i+1] {
				sc.Errorf("the sprout's host opened a connection to core at %s", tg)
			}
		}
	})
}

// route is one tenant-scoped call for the cross-tenant check.
type route struct {
	name, method, path string
	body               any
	raw                []byte
	hdr                http.Header
	// flagged routes are off by default: their plain 404 also counts as
	// refused (nothing ran).
	flagged bool
}

// tenantRoutes lists every tenant-scoped route of docs/api/saasapi.md
// for victim tenant v, with IDs that exist in v where it matters.
func tenantRoutes(v, sproutID, asset, batchID string) []route {
	p := func(e ...string) string { return harness.TenantPath(v, e...) }
	recipe := p("recipes") + "/uat.x4.victim"
	return []route{
		{name: "get_tenant", method: http.MethodGet, path: p()},
		{name: "patch_tenant", method: http.MethodPatch, path: p(), body: map[string]string{"name": "uat-x4-must-not-apply"}},
		{name: "get_status", method: http.MethodGet, path: p("status")},
		{name: "mint_key", method: http.MethodPost, path: p("enrollment-keys"), body: map[string]int{"expires_in_hours": 1, "max_uses": 1}},
		{name: "list_keys", method: http.MethodGet, path: p("enrollment-keys")},
		{name: "revoke_key", method: http.MethodDelete, path: p("enrollment-keys", "ek_uatx4nonexistent")},
		{name: "link_asset", method: http.MethodPost, path: p("sprouts", sproutID, "asset-link"), body: map[string]string{"asset_id": "uat-x4-" + harness.Nonce(6)}},
		{name: "unlink_asset", method: http.MethodDelete, path: p("sprouts", "uat-x4-nonexistent", "asset-link")},
		{name: "lookup", method: http.MethodGet, path: p("sprouts") + "?asset_ids=" + asset},
		{name: "post_batch", method: http.MethodPost, path: p("sprouts", "actions"), body: map[string]any{
			"asset_ids": []string{asset}, "action": map[string]any{"type": "cmd.run", "params": map[string]any{"cmd": "id -u"}}}},
		{name: "get_batch", method: http.MethodGet, path: p("sprouts", "actions", batchID)},
		{name: "get_policy", method: http.MethodGet, path: p("update-policy")},
		{name: "patch_policy", method: http.MethodPatch, path: p("update-policy"), body: map[string]any{"auto_update": false}},
		{name: "list_recipes", method: http.MethodGet, path: p("recipes")},
		{name: "get_recipe", method: http.MethodGet, path: recipe},
		{name: "put_recipe", method: http.MethodPut, path: recipe, raw: []byte("steps: {}\n"), hdr: http.Header{"If-None-Match": {"*"}}},
		{name: "delete_recipe", method: http.MethodDelete, path: recipe},
		{name: "post_update", method: http.MethodPost, path: p("sprouts", "updates"), body: map[string]any{"asset_ids": []string{asset}, "target_version": "v0.0.1"}, flagged: true},
		{name: "get_update", method: http.MethodGet, path: p("sprouts", "updates", batchID), flagged: true},
	}
}

func TestCoreX4_CrossTenantDenied(t *testing.T) {
	sc := harness.Begin(t, "X4")
	f := ready(t, sc)
	ctx := ctxFor(t, 15*time.Minute)
	other := map[int]int{1: 2, 2: 1}
	for _, n := range []int{1, 2} {
		attacker, victim := n, other[n]
		t.Run("t"+strconv.Itoa(attacker)+"_on_other", func(t *testing.T) {
			tsc := sc.ForTenant(t, attacker)
			vs := f.Sprouts(harness.InTenant(victim))
			sproutID, asset := "uat-x4-none", "uat-x4-none"
			if len(vs) > 0 && vs[0].SproutID != "" {
				sproutID, asset = vs[0].SproutID, vs[0].AssetID
			}
			tsc.Step("tenant %d makes a batch for the victim routes", victim)
			batchID, err := f.API.StartBatch(ctx, token(t, tsc, victim, harness.RoleAdmin), f.TenantID(victim), []string{"uat-x4-none-" + harness.Nonce(6)}, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
			tsc.NoErr(err, "the victim's batch")
			roles := []harness.Role{harness.RoleAdmin}
			if f.Tokens.HasUser(attacker, harness.RoleReadOnly) {
				roles = append(roles, harness.RoleReadOnly)
			}
			for _, role := range roles {
				tok := token(t, tsc, attacker, role)
				for _, rt := range tenantRoutes(f.TenantID(victim), sproutID, asset, batchID) {
					var r *harness.Response
					var err error
					for i := 0; i < 5; i++ { // a 429 would hide the answer; a 403 isn't rate limited
						r, err = f.API.Do(ctx, harness.Request{Method: rt.method, Path: rt.path, Token: tok, Body: rt.body, RawBody: rt.raw, Header: rt.hdr, ContentType: contentTypeFor(rt)})
						if err != nil || r.Status != http.StatusTooManyRequests {
							break
						}
						time.Sleep(2 * time.Second)
					}
					tsc.Step("%s token of tenant %d: %s %s", role, attacker, rt.method, rt.name)
					switch {
					case err != nil:
						tsc.Errorf("%s: %v", rt.name, err)
					case rt.flagged && harness.NotFoundOrForbidden(r):
					case r.Is(http.StatusForbidden, "forbidden"):
					default:
						tsc.Errorf("%s %s on tenant %d with tenant %d's %s token: want 403 forbidden, got %s", rt.method, rt.path, victim, attacker, role, r)
					}
				}
			}
		})
	}
	t.Run("delete_tenant", func(t *testing.T) {
		ssc := harness.Begin(t, "X4")
		// Deleting tenant 2 would end the run if the check were broken, so
		// the victim of DELETE is a tenant made for it.
		ssc.Step("create a victim tenant")
		st, r, err := f.API.CreateTenant(ctx, token(t, ssc, 1, harness.RoleAdmin), "uat-x4-victim-"+harness.Nonce(6))
		ssc.Expect(r, err, http.StatusAccepted, "", "POST /v1/tenants")
		for _, n := range []int{1, 2} {
			ssc.Step("tenant %d deletes the victim", n)
			r, err := f.API.DeleteTenant(ctx, token(t, ssc, n, harness.RoleAdmin), st.TenantID)
			ssc.Check(r, err, http.StatusForbidden, "forbidden", "DELETE another tenant with tenant %d's token", n)
		}
		if fleet.CanMakeScratchUsers() {
			if user, err := fleet.ScratchUser(ctx, st.TenantID); err == nil {
				if tok, err := user.Token(ctx); err == nil {
					offboard(t, st.TenantID, tok)
				}
				_ = user.Delete(cleanupCtx())
			}
		}
	})
}

func contentTypeFor(rt route) string {
	if rt.raw != nil {
		return "application/yaml"
	}
	return ""
}

func TestCoreX5_SproutRefusesPlaintext(t *testing.T) {
	sc := harness.Begin(t, "X5")
	// A plaintext cmd.run or cook can only be put in front of a sprout by
	// publishing on its subjects (imas.sprouts.<id>.cmd.run, .cook) on the
	// bus, with a NATS credential allowed to publish there: farmer's for
	// that tenant's Account. The runner reaches only saasapi, Keycloak and
	// Envoy; the bus is reachable from core alone, and no UAT credential
	// may publish on a sprout's subjects. Through the API every request is
	// sealed by farmer, so there is no outside way to send the sprout a
	// plaintext one. The refusal itself (encryption-required, no-keys) is
	// covered by internal/ingredients/cmd/sealed_test.go and
	// internal/cook/sealed tests (FIX.1); S5 covers farmer's side.
	sc.Skipf("a plaintext cmd.run or cook can only reach a sprout through the bus with farmer's NATS credential, which the runner neither reaches nor holds; covered by the sealed unit tests (FIX.1) and, for farmer's side, by S5")
}
