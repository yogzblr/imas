// Package harness is the reusable half of the UAT gate's acceptance suite
// (docs/claude-code-parallel-build-plan.md, section 4h, UAT.5). The
// scenario tests in uat/tests and the ingredient conformance runner in
// uat/tests/ingredients (UAT.7) both build on it. It has no build tag, so
// its own unit tests run in go test ./... against fake servers; nothing in
// it talks to a real deployment unless a test under the uat tag asks it to.
//
// # The interface, in one place
//
//	env, err := harness.Load()          // reads $IMAS_UAT_DIR (see below)
//	f, err  := harness.NewFleet(env)    // API client, tokens, vmctl, enroller
//	f.Prepare(ctx)                      // resolves sprout IDs, links asset IDs
//
//	tok, _ := f.Tokens.Tenant(ctx, 1, harness.RoleAdmin)
//	b, _   := f.Do(ctx, 1, sprouts, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
//	b, _   := f.Do(ctx, 1, sprouts, harness.CookAction("uat.r4.x", false))
//	item   := b.For(sprout)             // one item per asset ID
//	res, _ := f.OnHost(ctx, sprout, harness.FileState(sprout, path))  // out of band
//	f.VM.Restart(ctx, sprout.VM)        // uat/access/vmctl.sh, never Azure directly
//
//	sc := harness.Begin(t, "C1")        // every failure names id, OS, tenant, step
//	f.EachTenant(t, sc, func(t *testing.T, sc *harness.Scenario, tenant int) { ... })
//	f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) { ... })
//
// The pieces, each usable on its own:
//
//   - Env (config.go): the uat JSON from tofu and the material directory.
//   - Client (api.go): the saasapi routes of docs/api/saasapi.md, typed,
//     with both credentials (X-Internal-Auth and the Keycloak bearer).
//   - Tokens (tokens.go): Keycloak tokens by tenant and role, and scratch
//     users for tenants a test creates itself (Keycloak admin API).
//   - VMCtl (vmctl.go): uat/access/vmctl.sh, the Access interface. Run
//     wraps a script so its exit code and values survive whatever vmctl
//     prints around them; HostScript (hostscript.go) has the Linux and
//     Windows versions of the checks the scenarios need.
//   - Enroller (enroll.go): synthetic sprouts that do step 1 of
//     POST /v1/enroll through Envoy, so key and keyless-sprout scenarios
//     need no real host.
//   - Fleet (fleet.go): the sprouts of the run, asset links, batches with
//     rate-limit retries, cooks, waiting for connections.
//   - Scenario (scenario.go): failure messages of the form
//     "[C1 os=ubuntu tenant=1 vm=t1-ubuntu step=wait for the batch] ...",
//     and subtest names (t1, t1-ubuntu) that uat/tests/uatreport turns into
//     one summary line per scenario id, OS and tenant.
//
// # The material directory ($IMAS_UAT_DIR)
//
// uat/tests/README.md is the full description, with examples. In short:
// uat.json (tofu output uat, required), keycloak.json (issuer, client,
// tenant users, optional Keycloak admin, required), internal-auth-secret
// (saasapi's X-Internal-Auth secret, required), uat-ca.pem (the run's CA,
// optional), harness.json (endpoint and command overrides, optional),
// tenants.json and sprouts.json (tenant and sprout IDs when keycloak.json
// and the hosts don't give them, optional). $IMAS_UAT_VMCTL names the
// vmctl.sh to use; $IMAS_UAT_RELEASE_TAG, when set, is the release the
// sprouts must be running.
//
// Secrets (passwords, the internal secret, tokens, join tokens) are never
// printed: error messages name the request and the status, not the body
// of a credential exchange.
package harness
