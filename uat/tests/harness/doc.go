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
//     users for tenants a test creates itself (Keycloak admin API). One
//     request per user at a time; a password that worked earlier in the
//     run and is then refused is retried for a while, as a Keycloak
//     temporary lockout.
//   - VMCtl (vmctl.go): uat/access/vmctl.sh, the Access interface. Run
//     wraps a script so its exit code and values survive whatever vmctl
//     prints around them; HostScript (hostscript.go) has the Linux and
//     Windows versions of the checks the scenarios need.
//   - Enroller (enroll.go): synthetic sprouts that do step 1 of
//     POST /v1/enroll through Envoy, so key and keyless-sprout scenarios
//     need no real host.
//   - Fleet (fleet.go): the sprouts of the run, asset links, batches with
//     rate-limit retries, cooks, waiting for connections.
//   - The ha tier (P24, brief H5): Kube (kube.go) runs kubectl on a hub's
//     cluster; HA (ha.go, Fleet.HA) has both clusters, the hubs' fixed
//     names, the node a node stop picks, the stateful services' checks,
//     the loaders' /status, the HA5 NetworkPolicy block, helm upgrade and
//     the core check; StartLoops and Window (loops.go) run the traffic
//     loops and check the owner's error windows; Fleet.TrafficPlan
//     (traffic.go) builds the loops over the run's sprouts; FullEnroller
//     and Enrolment (enrolment.go) enrol complete sprouts and check
//     mint-or-reuse; BusConnect (busconn.go) connects one to a bus node;
//     VMCtl.StopVM and StartVM stop and start a hub node.
//   - Inside the core hub (the W1 cases): Fleet.CoreProbe (acceptance.go)
//     runs uat/hub/core/acceptance.sh, with typed wrappers for the operator
//     purge, the tenant inventory (TenantDataSpec and TombstoneSpec, from
//     internal/tenantpurge; each table counted by its InventoryKeyColumns
//     column), backdating rows, restarts, sweeps, objects,
//     Valkey keys, props and job status; Enrolment.ConnectThroughEnvoy
//     and its sealed, forged and plaintext facts and step events
//     (sproutbus.go) are a sprout on the bus; NKeyNonce, PutNKey and
//     NKeySubmission (putnkey.go) are a standalone farmer's legacy NKey
//     registration; RB1PartRecipe and RB1MainRecipe (renderbudget.go)
//     are RB1's recipes, rendered by internal/cook in a unit test.
//   - Scenario (scenario.go): failure messages of the form
//     "[C1 os=ubuntu tenant=1 vm=t1-ubuntu step=wait for the batch] ...",
//     and subtest names (t1, t1-ubuntu) that uat/tests/uatreport turns into
//     one summary line per scenario id, OS and tenant.
//
// # The material directory ($IMAS_UAT_DIR)
//
// uat/tests/README.md is the full description, with examples. In short:
// uat.json (tofu output uat, required); uat/hub/core's core.json,
// credentials.json and keycloak.json (UAT.3b, owner decisions of
// 2026-10-06), in the directory or under core/out and core/sensitive,
// giving saasapi's URL and secret, the CA, the Keycloak clients and the
// tenant users; optional internal-auth-secret, uat-ca.pem, harness.json
// (endpoint, command and bind_tenant overrides), tenants.json and
// sprouts.json. UAT.4 binds tenants 1 and 2; Fleet.CheckTenantClaims checks
// their tokens carry their IDs, and Fleet.ScratchUser makes users for
// tenants a test creates with bind-tenant.sh --scratch-user (see bind.go). $IMAS_UAT_VMCTL names the vmctl.sh
// to use; $IMAS_UAT_RELEASE_TAG, when set, is the release the sprouts must
// be running.
//
// Secrets (passwords, the internal secret, tokens, join tokens) are never
// printed: error messages name the request and the status, not the body
// of a credential exchange.
package harness
