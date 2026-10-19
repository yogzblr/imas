//go:build uat

package uattests

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"

	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/uat/tests/harness"
)

// The acceptance cases of the S, T and U fixes on a deployed stack (brief
// docs/briefs/W-uat-acceptance.md, unit W1): B1 (S3), E1 (S6), D1 (U4),
// U1 (U3), N1 (T6, L12) and RB1 (S4). Each looks at the stack through
// saasapi, Envoy and the sprout hosts like the other cases, and inside the
// core hub through uat/hub/core/acceptance.sh (harness.Fleet.CoreProbe).
// The short retention settings they rely on are the UAT core hub's
// (uat/hub/core/values/farmer-uat.yaml); the chart's defaults stay as
// shipped.

// needCore skips, with the reason, when the run has no way into the core
// hub (no core kubeconfig and endpoints file: harness.ErrNoCoreAccess).
func needCore(sc *harness.Scenario) {
	sc.T.Helper()
	if !fleet.CanReachCore() {
		sc.Skipf("%v", harness.ErrNoCoreAccess)
	}
}

// uatValues reads the UAT core hub's values file, the settings the hub was
// installed with (uat/hub/core/values/farmer-uat.yaml).
func uatValues(t *testing.T, sc *harness.Scenario) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "hub", "core", "values", "farmer-uat.yaml"))
	sc.NoErr(err, "reading uat/hub/core/values/farmer-uat.yaml")
	var v map[string]any
	sc.NoErr(yaml.Unmarshal(b, &v), "parsing uat/hub/core/values/farmer-uat.yaml")
	return v
}

// valueAt is the value at a dotted path of a values map, or nil.
func valueAt(v map[string]any, path string) any {
	var cur any = v
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

// eventually polls cond every 3 s until it holds or d has passed, and
// returns the last error it gave.
func eventually(ctx context.Context, d time.Duration, cond func() error) error {
	deadline := time.Now().Add(d)
	for {
		err := cond()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// unknownAssets is n asset IDs no sprout has: a batch over them is
// accepted and its items end unresolved at once, never pending.
func unknownAssets(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%03d", prefix, i)
	}
	return out
}

// TestCoreB1_BacklogFull covers S3 (P3 walkthrough 3.4 item 5): a tenant
// whose pending actions (queued or dispatching items) fill
// SAASAPI_ACTION_MAX_PENDING_PER_TENANT (20 on the UAT core hub) is refused
// at submit time with 429 backlog_full, its details and Retry-After: 60;
// once they drain, the same request is accepted.
func TestCoreB1_BacklogFull(t *testing.T) {
	sc := harness.Begin(t, "B1")
	f := ready(t, sc)
	ctx := ctxFor(t, 15*time.Minute)
	tok := token(t, sc, 1, harness.RoleAdmin)
	tid := f.TenantID(1)
	sprouts := f.Sprouts(harness.InTenant(1))
	if len(sprouts) == 0 {
		sc.Fatalf("tenant 1 has no sprouts, so nothing can be kept pending")
	}

	// Each sprout runs a 40 s sleep: its item is dispatching (pending)
	// until the sprout answers. One batch per OS, as the command differs.
	sc.Step("keep tenant 1's %d sprouts busy with a 40 s cmd.run each", len(sprouts))
	var busy []string
	for _, family := range []bool{false, true} {
		var group []harness.Sprout
		for _, sp := range sprouts {
			if sp.IsWindows() == family {
				group = append(group, sp)
			}
		}
		if len(group) == 0 {
			continue
		}
		cmd := harness.SleepCmd(group[0], 40)
		cmd.TimeoutSeconds = 120
		id, r, err := f.API.PostBatchPastRateLimit(ctx, tok, tid, harness.Assets(group), harness.CmdRunAction(cmd))
		sc.Expect(r, err, http.StatusAccepted, "", "posting the sleeps")
		busy = append(busy, id)
	}

	nonce := harness.Nonce(6)
	sc.Step("post 100 unknown asset IDs while the sleeps are pending")
	_, r, err := f.API.PostBatchPastRateLimit(ctx, tok, tid, unknownAssets("uat-b1-"+nonce+"-probe", 100), harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
	sc.Expect(r, err, http.StatusTooManyRequests, "backlog_full",
		"100 more items with the cap of uat/hub/core/values/farmer-uat.yaml (saasapi.actionDispatch.maxPendingPerTenant 20)")
	detail := func(r *harness.Response, k string) int {
		v, ok := r.Error.Details[k].(float64)
		if !ok {
			sc.Fatalf("backlog_full details lack %q: %s", k, r.Body)
		}
		return int(v)
	}
	checkRefusal := func(r *harness.Response, requested int) (pending, limit int) {
		if got := r.Header.Get("Retry-After"); got != "60" {
			sc.Errorf("Retry-After %q, want 60", got)
		}
		pending, limit = detail(r, "pending"), detail(r, "limit")
		if got := detail(r, "requested"); got != requested {
			sc.Errorf("details.requested %d, want %d", got, requested)
		}
		if got := detail(r, "available"); got != max(limit-pending, 0) {
			sc.Errorf("details.available %d, want limit - pending = %d", got, max(limit-pending, 0))
		}
		if pending+requested <= limit {
			sc.Errorf("refused although pending %d + requested %d fit the limit %d", pending, requested, limit)
		}
		return pending, limit
	}
	pending, limit := checkRefusal(r, 100)
	if pending < len(sprouts) {
		sc.Errorf("details.pending %d, but tenant 1's %d sleeping items are pending", pending, len(sprouts))
	}
	if pending > limit {
		sc.Fatalf("tenant 1 already had %d items pending, over the limit %d, before this case", pending, limit)
	}

	// The smallest request that doesn't fit now: it fits once the sleeps
	// drain (they take pending down by len(sprouts) >= 1).
	n := limit - pending + 1
	assets := unknownAssets("uat-b1-"+nonce, n)
	sc.Step("post %d unknown asset IDs: one more than the %d the backlog has room for", n, limit-pending)
	_, r, err = f.API.PostBatchPastRateLimit(ctx, tok, tid, assets, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
	sc.Expect(r, err, http.StatusTooManyRequests, "backlog_full", "a request one item over the room left")
	checkRefusal(r, n)

	sc.Step("wait for the sleeps to finish")
	for _, id := range busy {
		b, err := f.API.WaitBatch(ctx, tok, tid, id, harness.DefaultBatchTimeout)
		sc.NoErr(err, "waiting for batch %s", id)
		for _, it := range b.Items {
			if it.Status != harness.ItemSucceeded {
				sc.Errorf("a sleep ended %s", it)
			}
		}
	}
	sc.Step("post the same %d asset IDs again", n)
	id, r, err := f.API.PostBatchPastRateLimit(ctx, tok, tid, assets, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
	sc.Expect(r, err, http.StatusAccepted, "", "the same request after the backlog drained")
	b, err := f.API.WaitBatch(ctx, tok, tid, id, harness.DefaultBatchTimeout)
	sc.NoErr(err, "waiting for the accepted batch")
	if len(b.Items) != n {
		sc.Errorf("the accepted batch has %d items, want %d", len(b.Items), n)
	}
}

// TestCoreE1_TenantPurge covers S6 (P3 walkthrough 3.6 item 3): an
// offboarded tenant's data is erased by a purge, started on the operator
// plane (POST /v1/operator/tenants/{tenant_id}/purge) or by the outbox
// sweeper once the tenant has been offboarded for SAASAPI_TENANT_PURGE_AFTER
// (1h on the UAT core hub; the case moves offboarded_at back past it rather
// than wait). The tombstone answers (status purged, no name), PATCH is
// 409 tenant_purged, the routes that store anything answer 404
// tenant_not_found, everything internal/tenantpurge lists is gone (keys,
// sprouts, recipes and other objects, Valkey keys, the KV keypair and both
// Transit keys) and what it keeps stays; another tenant is untouched.
func TestCoreE1_TenantPurge(t *testing.T) {
	sc := harness.Begin(t, "E1")
	needCore(sc)
	f := ready(t, sc)
	ctx := ctxFor(t, 40*time.Minute)

	// A scratch tenant with something in every store: a key, an enrolled
	// sprout (its NKey, box key and User JWT), an asset link, a recipe
	// (and its audit records), a batch, and the sprout's sealed facts
	// (props, once farmer has the tenant's bus connection open: not
	// required before the purge, counted after it).
	populate := func(t *testing.T, sc *harness.Scenario, tid, tok string) {
		t.Helper()
		sc.Step("give tenant %s data in every store", tid)
		key, err := f.API.MintKey(ctx, tok, tid, 1, 2)
		sc.NoErr(err, "minting a key")
		e, err := harness.NewEnrolment("uat-e1-"+harness.Nonce(8), key.RegistrationKey)
		sc.NoErr(err, "sprout keys")
		sc.NoErr(harness.NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP).Enrol(ctx, e), "enrolling a sprout")
		r, err := f.API.LinkAsset(ctx, tok, tid, e.SproutID, "uat-e1-"+harness.Nonce(10))
		sc.Expect(r, err, http.StatusCreated, "", "linking an asset")
		_, err = f.API.UploadRecipe(ctx, tok, tid, "uat.e1.r"+strings.ToLower(harness.Nonce(6)), "steps: {}\n")
		sc.NoErr(err, "uploading a recipe")
		_, err = f.API.StartBatch(ctx, tok, tid, []string{"uat-e1-none-" + harness.Nonce(6)}, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
		sc.NoErr(err, "posting a batch")
		nc, err := e.ConnectThroughEnvoy(ctx, f.Env.EnvoyURL, f.Env.CAPool)
		sc.NoErr(err, "connecting the sprout to the bus through Envoy")
		m, err := e.SealedFacts(e.Facts("uat-e1"))
		sc.NoErr(err, "sealing facts")
		sc.NoErr(harness.Publish(nc, m), "publishing sealed facts")
		nc.Close()
		spec := harness.TenantDataSpec(tid)
		sc.NoErr(eventually(ctx, 2*time.Minute, func() error {
			got, err := f.Inventory(ctx, spec)
			if err != nil {
				return err
			}
			for _, k := range []string{"farmer.pki_nkeys", "farmer.pki_sprout_box_keys", "farmer.sprout_user_jwt",
				"saas.enrollment_keys", "saas.asset_links", "saas.asset_action_batches", "objects.recipes", "objects.sprout_jwts",
				"kv:" + spec.OpenBaoKV[0], "transit:" + spec.Transit[0], "transit:" + spec.Transit[1]} {
				if got[k] == 0 {
					return fmt.Errorf("before the purge, %s counts 0 for tenant %s: the check can't see the data it must see gone (%v)", k, tid, got)
				}
			}
			return nil
		}), "the tenant's data before the purge")
	}
	offboarded := func(t *testing.T, sc *harness.Scenario, tid, tok string) harness.TenantStatus {
		t.Helper()
		sc.Step("offboard tenant %s", tid)
		r, err := f.API.DeleteTenant(ctx, tok, tid)
		sc.Expect(r, err, http.StatusAccepted, "", "DELETE")
		st, err := f.API.WaitTenantStatus(ctx, tok, tid, harness.DefaultTenantTimeout, harness.TenantOffboarded)
		sc.NoErr(err, "waiting for offboarded")
		at, err := time.Parse(time.RFC3339, st.PurgeAfter)
		sc.NoErr(err, "the offboarded tenant's purge_after %q", st.PurgeAfter)
		// SAASAPI_TENANT_PURGE_AFTER is 1h on the UAT core hub.
		if d := time.Until(at); d <= 0 || d > time.Hour+5*time.Minute {
			sc.Errorf("purge_after is %s from now, want within the hub's 1h delay", d.Round(time.Second))
		}
		return st
	}
	purged := func(t *testing.T, sc *harness.Scenario, tid, tok, trigger string) {
		t.Helper()
		sc.Step("wait for tenant %s to be purged (%s)", tid, trigger)
		st, err := f.API.WaitTenantStatus(ctx, tok, tid, 10*time.Minute, harness.TenantPurged)
		sc.NoErr(err, "waiting for purged (last_error %q)", st.LastError)

		sc.Step("the tombstone of %s", tid)
		r, err := f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(tid), Token: tok})
		sc.Expect(r, err, http.StatusOK, "", "GET the tenant")
		var ten map[string]any
		sc.NoErr(r.Decode(&ten), "decoding the tenant")
		if ten["status"] != harness.TenantPurged || (ten["name"] != nil && ten["name"] != "") {
			sc.Errorf("the tombstone reads %v, want status purged and no name", ten)
		}
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodPatch, Path: harness.TenantPath(tid), Token: tok, Body: map[string]string{"name": "uat-e1-renamed"}})
		sc.Check(r, err, http.StatusConflict, "tenant_purged", "PATCH a purged tenant")
		r, err = f.API.DeleteTenant(ctx, tok, tid)
		sc.Check(r, err, http.StatusConflict, "offboarding_in_progress", "DELETE a purged tenant")
		for _, p := range [][]string{{"enrollment-keys"}, {"recipes"}, {"update-policy"}} {
			r, err := f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(tid, p...), Token: tok})
			sc.Check(r, err, http.StatusNotFound, "tenant_not_found", "GET %s of a purged tenant", p[0])
		}
		r, err = f.API.LinkAsset(ctx, tok, tid, "uat-e1-gone", "uat-e1-"+harness.Nonce(8))
		sc.Check(r, err, http.StatusNotFound, "tenant_not_found", "linking an asset in a purged tenant")

		sc.Step("everything internal/tenantpurge erases is gone")
		spec := harness.TenantDataSpec(tid)
		got, err := f.Inventory(ctx, spec)
		sc.NoErr(err, "counting the tenant's data")
		for _, k := range harness.InventoryKeys(spec) {
			if got[k] != 0 {
				sc.Errorf("after the purge %s still counts %d", k, got[k])
			}
		}
		keep := harness.TombstoneSpec(tid)
		got, err = f.Inventory(ctx, keep)
		sc.NoErr(err, "counting the tombstone")
		for _, k := range harness.InventoryKeys(keep) {
			if got[k] == 0 {
				sc.Errorf("the purge removed %s, which the tombstone keeps", k)
			}
		}
		jobs, err := f.ProvisioningJobs(ctx, tid)
		sc.NoErr(err, "reading the provisioning jobs")
		ok := false
		for _, j := range jobs {
			ok = ok || (j.Type == "purge" && j.Status == "succeeded")
		}
		if !ok {
			sc.Errorf("no succeeded purge job among %+v", jobs)
		}
	}

	t.Run("operator", func(t *testing.T) {
		ssc := harness.Begin(t, "E1")
		tid, tok := scratchTenant(t, ssc, "e1op", true)
		populate(t, ssc, tid, tok)
		offboarded(t, ssc, tid, tok)
		ssc.Step("POST /v1/operator/tenants/%s/purge", tid)
		ans, err := f.PurgeTenant(ctx, tid)
		ssc.NoErr(err, "the operator purge")
		if ans.Status != http.StatusAccepted || !strings.Contains(string(ans.Body), `"job_id":"pj_`) || !strings.Contains(string(ans.Body), `"status":"offboarded"`) {
			ssc.Fatalf("the operator plane answered %d %s, want 202 with the purge job and status offboarded", ans.Status, ans.Body)
		}
		again, err := f.PurgeTenant(ctx, tid)
		ssc.NoErr(err, "a second operator purge")
		if again.Status != http.StatusConflict || !(strings.Contains(string(again.Body), "purge_in_progress") || strings.Contains(string(again.Body), "not_offboarded")) {
			ssc.Errorf("a second purge answered %d %s, want 409 purge_in_progress (or not_offboarded once done)", again.Status, again.Body)
		}
		purged(t, ssc, tid, tok, "operator")
	})
	t.Run("retention", func(t *testing.T) {
		ssc := harness.Begin(t, "E1")
		tid, tok := scratchTenant(t, ssc, "e1ret", true)
		populate(t, ssc, tid, tok)
		offboarded(t, ssc, tid, tok)
		// The hub purges an hour after offboarding; the case moves the start
		// of that hour back by two, so the sweeper (every 30 s) is due now.
		ssc.Step("move tenant %s's offboarding two hours back", tid)
		n, err := f.Backdate(ctx, harness.BackdateSpec{TenantID: tid, Seconds: 2 * 3600, Offboarded: true})
		ssc.NoErr(err, "moving offboarded_at back")
		if n != 1 {
			ssc.Fatalf("moved %d rows, want the tenant's", n)
		}
		purged(t, ssc, tid, tok, "the retention sweeper")
	})
	t.Run("other_tenant", func(t *testing.T) {
		ssc := harness.Begin(t, "E1")
		ssc.Step("tenant 2 after the purges")
		tok := token(t, ssc, 2, harness.RoleAdmin)
		st, r, err := f.API.GetTenantStatus(ctx, tok, f.TenantID(2))
		ssc.Expect(r, err, http.StatusOK, "", "tenant 2's status")
		if st.Status != harness.TenantActive {
			ssc.Errorf("tenant 2 is %s", st.Status)
		}
		_, r, err = f.API.ListKeys(ctx, tok, f.TenantID(2))
		ssc.Check(r, err, http.StatusOK, "", "tenant 2's keys")
		if assets := harness.Assets(f.Sprouts(harness.InTenant(2))); len(assets) > 0 {
			lk, r, err := f.API.LookupAssets(ctx, tok, f.TenantID(2), assets)
			ssc.Expect(r, err, http.StatusOK, "", "tenant 2's lookup")
			if len(lk.Results) != len(assets) {
				ssc.Errorf("tenant 2 resolves %d of its %d assets", len(lk.Results), len(assets))
			}
		}
		spec := harness.TenantDataSpec(f.TenantID(2))
		got, err := f.Inventory(ctx, spec)
		ssc.NoErr(err, "counting tenant 2's data")
		for _, k := range []string{"kv:" + spec.OpenBaoKV[0], "transit:" + spec.Transit[0], "transit:" + spec.Transit[1]} {
			if got[k] != 1 {
				ssc.Errorf("tenant 2's %s is gone", k)
			}
		}
		if len(f.Sprouts(harness.InTenant(2))) > 0 && got["farmer.pki_nkeys"] == 0 {
			ssc.Errorf("tenant 2's sprouts are gone from farmer.pki_nkeys")
		}
	})
}

// TestCoreD1_Retention covers U4 (docs/retention.md) with the UAT core
// hub's short settings (uat/hub/core/values/farmer-uat.yaml): the recipe
// audit sweep deletes the audit days older than
// IMAS_RECIPE_AUDIT_RETENTION_DAYS and keeps the rest; the log retention
// CronJob, with Fluent Bit shipping, deletes the log days older than
// logShipping.retention.days and keeps the rest; saasapi's prune deletes
// finished action batches, finished provisioning jobs of a live tenant and
// expired enrollment keys older than SAASAPI_TERMINAL_ROW_RETENTION, and
// keeps a batch with a pending item and an offboarded tenant's jobs (its
// tombstone's record). The case moves its own rows' and objects' dates back
// past the limits instead of waiting days.
func TestCoreD1_Retention(t *testing.T) {
	sc := harness.Begin(t, "D1")
	needCore(sc)
	f := ready(t, sc)
	ctx := ctxFor(t, 40*time.Minute)
	v := uatValues(t, sc)

	sc.Step("the retention settings the hub runs with")
	info, err := f.Retention(ctx)
	sc.NoErr(err, "reading the workloads' settings")
	auditDays, _ := strconv.Atoi(info.Farmer["IMAS_RECIPE_AUDIT_RETENTION_DAYS"])
	if want := valueAt(v, "farmer.retention.recipeAuditDays"); fmt.Sprint(want) != strconv.Itoa(auditDays) || auditDays < 1 {
		sc.Fatalf("farmer runs with IMAS_RECIPE_AUDIT_RETENTION_DAYS %q, values/farmer-uat.yaml says %v", info.Farmer["IMAS_RECIPE_AUDIT_RETENTION_DAYS"], want)
	}
	rows, err := time.ParseDuration(info.SaaSAPI["SAASAPI_TERMINAL_ROW_RETENTION"])
	want, werr := time.ParseDuration(fmt.Sprint(valueAt(v, "saasapi.retention.terminalRows")))
	if err != nil || werr != nil || rows != want {
		sc.Fatalf("saasapi runs with SAASAPI_TERMINAL_ROW_RETENTION %q, values/farmer-uat.yaml says %v", info.SaaSAPI["SAASAPI_TERMINAL_ROW_RETENTION"], valueAt(v, "saasapi.retention.terminalRows"))
	}
	if !info.LogShipper.DaemonSet || !info.LogShipper.ConfigMap || !info.LogShipper.Ready {
		sc.Errorf("the log shipper: DaemonSet %v, its Fluent Bit ConfigMap %v, ready %v", info.LogShipper.DaemonSet, info.LogShipper.ConfigMap, info.LogShipper.Ready)
	}
	logDays := info.LogRetention.Days
	if want := valueAt(v, "logShipping.retention.days"); !info.LogRetention.CronJob || fmt.Sprint(want) != strconv.Itoa(logDays) {
		sc.Fatalf("the log retention CronJob: present %v, -days=%d; values/farmer-uat.yaml says %v", info.LogRetention.CronJob, logDays, want)
	}

	day := func(daysAgo int) time.Time { return time.Now().UTC().AddDate(0, 0, -daysAgo) }
	nonce := strings.ToLower(harness.Nonce(8))
	t.Run("recipe_audit", func(t *testing.T) {
		ssc := harness.Begin(t, "D1")
		tid := f.TenantID(1)
		name := "uat.d1." + nonce
		ssc.Step("upload %s (its audit records are today's)", name)
		upload(t, ssc, 1, name, "steps: {}\n")
		todayPrefix := fmt.Sprintf("tenants/%s/recipe-audit/%s/", tid, day(0).Format("2006-01-02"))
		today, err := f.Objects(ctx, "recipes", todayPrefix)
		ssc.NoErr(err, "listing today's audit records")
		if len(today) == 0 {
			ssc.Fatalf("no audit record under %s after an upload", todayPrefix)
		}
		// The sweep deletes the days before Cutoff(now, days): the start of
		// the day `days` back (internal/retention). That day is kept.
		old := fmt.Sprintf("tenants/%s/recipe-audit/%s/uat-d1-%s-old.json", tid, day(auditDays+2).Format("2006-01-02"), nonce)
		edge := fmt.Sprintf("tenants/%s/recipe-audit/%s/uat-d1-%s-edge.json", tid, day(auditDays).Format("2006-01-02"), nonce)
		for _, k := range []string{old, edge} {
			ssc.NoErr(f.PutObject(ctx, "recipes", k, []byte(`{"uat":"d1"}`)), "writing %s", k)
		}
		t.Cleanup(func() { _ = f.DeleteObject(cleanupCtx(), "recipes", edge) })
		ssc.Step("run farmer's recipe audit sweep")
		ssc.NoErr(f.Sweep(ctx, "recipe-audit"), "the recipe audit sweep")
		ssc.NoErr(eventually(ctx, 5*time.Minute, func() error {
			keys, err := f.Objects(ctx, "recipes", fmt.Sprintf("tenants/%s/recipe-audit/%s/", tid, day(auditDays+2).Format("2006-01-02")))
			if err != nil {
				return err
			}
			for _, k := range keys {
				if k == old {
					return fmt.Errorf("%s (%d days old, over the %d-day limit) is still there", old, auditDays+2, auditDays)
				}
			}
			return nil
		}), "the sweep deleting the old day")
		for _, prefix := range []string{todayPrefix, edge} {
			keys, err := f.Objects(ctx, "recipes", prefix)
			ssc.NoErr(err, "listing %s", prefix)
			if len(keys) == 0 {
				ssc.Errorf("the sweep deleted %s, inside the %d-day limit", prefix, auditDays)
			}
		}
	})
	t.Run("log_retention", func(t *testing.T) {
		ssc := harness.Begin(t, "D1")
		key := func(daysAgo int, what string) string {
			return fmt.Sprintf("logs/%s/uat-d1-%s-%s.gz", day(daysAgo).Format("2006/01/02"), nonce, what)
		}
		old, edge := key(logDays+2, "old"), key(logDays, "edge")
		for _, k := range []string{old, edge} {
			ssc.NoErr(f.PutObject(ctx, "logs", k, []byte("uat d1")), "writing %s", k)
		}
		t.Cleanup(func() { _ = f.DeleteObject(cleanupCtx(), "logs", edge) })
		ssc.Step("run the log retention CronJob once")
		ssc.NoErr(f.Sweep(ctx, "log-retention"), "the log retention Job")
		for k, want := range map[string]bool{old: false, edge: true} {
			keys, err := f.Objects(ctx, "logs", k)
			ssc.NoErr(err, "listing %s", k)
			if (len(keys) > 0) != want {
				ssc.Errorf("%s present %v after the CronJob, want %v (limit %d days)", k, len(keys) > 0, want, logDays)
			}
		}
	})
	t.Run("terminal_rows", func(t *testing.T) {
		ssc := harness.Begin(t, "D1")
		tok := token(t, ssc, 1, harness.RoleAdmin)
		tid := f.TenantID(1)
		sprouts := f.Sprouts(harness.InTenant(1))
		if len(sprouts) == 0 {
			ssc.Fatalf("tenant 1 has no sprouts, so no batch can be kept pending")
		}
		ssc.Step("a live tenant and an offboarded one, each with finished provisioning jobs")
		live, liveTok := scratchTenant(t, ssc, "d1live", true)
		t.Cleanup(func() { offboard(t, live, liveTok) })
		gone, goneTok := scratchTenant(t, ssc, "d1gone", true)
		r, err := f.API.DeleteTenant(ctx, goneTok, gone)
		ssc.Expect(r, err, http.StatusAccepted, "", "offboarding %s", gone)
		_, err = f.API.WaitTenantStatus(ctx, goneTok, gone, harness.DefaultTenantTimeout, harness.TenantOffboarded)
		ssc.NoErr(err, "waiting for %s to be offboarded", gone)

		ssc.Step("a finished batch, a batch kept pending, an enrollment key")
		done, err := f.API.StartBatch(ctx, tok, tid, []string{"uat-d1-none-" + nonce}, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}))
		ssc.NoErr(err, "posting a batch that finishes at once")
		_, err = f.API.WaitBatch(ctx, tok, tid, done, harness.DefaultBatchTimeout)
		ssc.NoErr(err, "waiting for it")
		cmd := harness.SleepCmd(sprouts[0], 150)
		cmd.TimeoutSeconds = 300
		pending, err := f.API.StartBatch(ctx, tok, tid, []string{sprouts[0].AssetID}, harness.CmdRunAction(cmd))
		ssc.NoErr(err, "posting a 150 s sleep")
		key := mintKey(t, ssc, 1, 1, 1)
		jobIDs := func(tenant string) []string {
			jobs, err := f.ProvisioningJobs(ctx, tenant)
			ssc.NoErr(err, "reading %s's provisioning jobs", tenant)
			var ids []string
			for _, j := range jobs {
				if j.Status == "succeeded" || j.Status == "failed" {
					ids = append(ids, j.ID)
				}
			}
			return ids
		}
		liveJobs, goneJobs := jobIDs(live), jobIDs(gone)
		if len(liveJobs) == 0 || len(goneJobs) < 2 {
			ssc.Fatalf("finished provisioning jobs: %d of the live tenant, %d of the offboarded one", len(liveJobs), len(goneJobs))
		}

		// Two hours past the limit: older than it however the clocks of
		// the runner and the database differ.
		secs := int64((rows + 2*time.Hour) / time.Second)
		ssc.Step("move them %s back, past SAASAPI_TERMINAL_ROW_RETENTION %s", time.Duration(secs)*time.Second, rows)
		for _, spec := range []harness.BackdateSpec{
			{TenantID: tid, Seconds: secs, Batches: []string{done, pending}, EnrollmentKeys: []string{key.KeyID}},
			{TenantID: live, Seconds: secs, ProvisioningJobs: liveJobs},
			{TenantID: gone, Seconds: secs, ProvisioningJobs: goneJobs},
		} {
			_, err := f.Backdate(ctx, spec)
			ssc.NoErr(err, "moving %s's rows back", spec.TenantID)
		}
		ssc.Step("restart saasapi: its prune runs at start")
		ssc.NoErr(f.RestartCoreWorkload(ctx, "saasapi"), "restarting saasapi")
		ssc.NoErr(eventually(ctx, 3*time.Minute, func() error {
			_, r, err := f.API.GetBatch(ctx, tok, tid, done)
			if err != nil {
				return err
			}
			if !r.Is(http.StatusNotFound, "batch_not_found") {
				return fmt.Errorf("the finished batch past the limit answers %s, want 404 batch_not_found", r)
			}
			return nil
		}), "the finished batch pruned")
		_, r, err = f.API.GetBatch(ctx, tok, tid, pending)
		ssc.Check(r, err, http.StatusOK, "", "the batch whose item was pending at the prune")
		list, r, err := f.API.ListKeys(ctx, tok, tid)
		ssc.Expect(r, err, http.StatusOK, "", "listing tenant 1's keys")
		if _, ok := harness.FindKey(list, key.KeyID); ok {
			ssc.Errorf("the key whose expiry is past the limit is still listed")
		}
		left := map[string]bool{}
		for _, id := range jobIDs(live) {
			left[id] = true
		}
		for _, id := range liveJobs {
			if left[id] {
				ssc.Errorf("the live tenant's finished job %s past the limit was kept", id)
			}
		}
		left = map[string]bool{}
		for _, id := range jobIDs(gone) {
			left[id] = true
		}
		for _, id := range goneJobs {
			if !left[id] {
				ssc.Errorf("the offboarded tenant's job %s was pruned: it is its tombstone's record", id)
			}
		}
	})
}

// TestCoreU1_SealedFactsAndSteps covers U3 (security review P6): sprouts
// seal their facts and cook step events, farmer stores the facts and
// records the steps; a facts report in plaintext or under another key,
// and a step event in plaintext, are refused, and a plaintext one marks
// the sprout as needing an upgrade until its next sealed facts report
// (internal/heartbeat upgrade.go). The run's sprouts show the sealed path;
// a sprout enrolled by the case and connected through Envoy sends the
// forged ones. Brief correction (W1): jobs.follow is the CLI's leg, whose
// users are farmer's organization, never a SaaS tenant's sprouts, so the
// steps are checked where farmer records them (farmer.job_status and the
// job's objects) instead.
func TestCoreU1_SealedFactsAndSteps(t *testing.T) {
	sc := harness.Begin(t, "U1")
	needCore(sc)
	f := ready(t, sc)

	f.EachSprout(t, sc, f.Sprouts(), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 10*time.Minute)
		tid := f.TenantID(sp.Tenant)
		sc.Step("the sprout's facts, sealed, are fresh in farmer.props")
		sc.NoErr(eventually(ctx, 4*time.Minute, func() error {
			props, err := f.Props(ctx, tid, sp.SproutID)
			if err != nil {
				return err
			}
			if p, ok := props["os"]; !ok || p.ExpiresIn <= 0 {
				return fmt.Errorf("no fresh os prop for %s (%+v): its facts don't arrive", sp.SproutID, props["os"])
			}
			return nil
		}), "the sprout's facts")
		if ok, kind, err := f.ValkeyGet(ctx, harness.UpgradeMarkerKey(tid, sp.SproutID)); err != nil || ok {
			sc.Errorf("the sprout is marked as needing an upgrade (%q, %v)", kind, err)
		}
		if sp.Tenant != 1 {
			return
		}
		sc.Step("cook on the sprout: farmer records its sealed step events")
		nonce := harness.Nonce(8)
		name := "uat.u1." + strings.ToLower(nonce)
		path := sp.TempPath("imas-uat-u1-" + nonce + ".txt")
		upload(t, sc, 1, name, markerRecipe("uat u1 marker", path, "u1 "+nonce))
		b, err := f.Cook(ctx, 1, []harness.Sprout{sp}, name, false)
		sc.NoErr(err, "the cook")
		it := sc.ExpectItem(b, sp, harness.ItemSucceeded, "")
		ok, status, err := f.JobStatus(ctx, tid, sp.SproutID, it.JID)
		sc.NoErr(err, "reading farmer.job_status")
		if !ok || status != "succeeded" {
			sc.Errorf("farmer.job_status for job %s: exists %v, status %q, want succeeded", it.JID, ok, status)
		}
		objs, err := f.Objects(ctx, "jobs", fmt.Sprintf("jobs/%s/%s/%s/", tid, sp.SproutID, it.JID))
		sc.NoErr(err, "listing the job's objects")
		if len(objs) == 0 {
			sc.Errorf("the job store holds nothing for job %s", it.JID)
		}
	})

	t.Run("forged", func(t *testing.T) {
		ssc := harness.Begin(t, "U1")
		ctx := ctxFor(t, 15*time.Minute)
		key := mintKey(t, ssc, 1, 1, 1)
		e, err := harness.NewEnrolment("uat-u1-"+harness.Nonce(8), key.RegistrationKey)
		ssc.NoErr(err, "sprout keys")
		ssc.Step("enrol a sprout and connect it to the bus through Envoy")
		ssc.NoErr(harness.NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP).Enrol(ctx, e), "enrolling")
		nc, err := e.ConnectThroughEnvoy(ctx, f.Env.EnvoyURL, f.Env.CAPool)
		ssc.NoErr(err, "connecting through Envoy")
		defer nc.Close()
		tid, marker := e.TenantID, harness.UpgradeMarkerKey(e.TenantID, e.SproutID)
		hostname := func() string {
			props, err := f.Props(ctx, tid, e.SproutID)
			ssc.NoErr(err, "reading the sprout's props")
			return props["hostname"].Value
		}
		markedAs := func() string {
			ok, kind, err := f.ValkeyGet(ctx, marker)
			ssc.NoErr(err, "reading the needs-upgrade marker")
			if !ok {
				return ""
			}
			return kind
		}
		sealed := func(name string) {
			ssc.Step("a sealed facts report naming %s", name)
			m, err := e.SealedFacts(e.Facts(name))
			ssc.NoErr(err, "sealing")
			ssc.NoErr(harness.Publish(nc, m), "publishing")
			ssc.NoErr(eventually(ctx, 2*time.Minute, func() error {
				if got := hostname(); got != name {
					return fmt.Errorf("farmer stored hostname %q, want %q from the sealed report", got, name)
				}
				if kind := markedAs(); kind != "" {
					return fmt.Errorf("still marked as needing an upgrade (%s) after a sealed report", kind)
				}
				return nil
			}), "farmer storing the sealed report")
		}
		refusedWith := func(what, kind string, m func() error) {
			ssc.Step("%s", what)
			before := hostname()
			ssc.NoErr(m(), "publishing")
			ssc.NoErr(eventually(ctx, 2*time.Minute, func() error {
				if got := markedAs(); got != kind {
					return fmt.Errorf("the needs-upgrade marker is %q, want %q", got, kind)
				}
				return nil
			}), "farmer refusing %s", what)
			if got := hostname(); got != before {
				ssc.Errorf("%s changed the stored hostname to %q", what, got)
			}
		}

		nonce := strings.ToLower(harness.Nonce(6))
		sealed("uat-u1-" + nonce + "-sealed")
		refusedWith("a plaintext facts report", "facts", func() error {
			m, err := e.PlaintextFacts(e.Facts("uat-u1-" + nonce + "-plain"))
			if err != nil {
				return err
			}
			return harness.Publish(nc, m)
		})
		sealed("uat-u1-" + nonce + "-sealed2")

		ssc.Step("a facts report sealed under another box key")
		before := hostname()
		m, err := e.ForgedSealedFacts(e.Facts("uat-u1-" + nonce + "-forged"))
		ssc.NoErr(err, "sealing under another key")
		ssc.NoErr(harness.Publish(nc, m), "publishing")
		time.Sleep(10 * time.Second)
		if got := hostname(); got != before {
			ssc.Errorf("a report sealed under another key was stored (hostname %q)", got)
		}

		jid := strings.ToLower(fmt.Sprintf("%08x-0000-4000-8000-%012x", time.Now().Unix(), time.Now().UnixNano()%(1<<48)))
		refusedWith("a plaintext cook step event", "cook step", func() error {
			return harness.Publish(nc, e.PlaintextStepEvent(jid, "uat-u1-step"))
		})
		ok, _, err := f.JobStatus(ctx, tid, e.SproutID, jid)
		ssc.NoErr(err, "reading farmer.job_status")
		if ok {
			ssc.Errorf("farmer recorded job %s from a plaintext step event", jid)
		}
		sealed("uat-u1-" + nonce + "-sealed3")
	})
}

// TestCoreN1_PutNKeyProof covers T6 (security review L12): a standalone
// farmer (enrolment off) files an NKey on PUT /pki/putnkey only with a
// proof of possession, the NKey's signature over a nonce from GET
// /pki/nkeynonce, spent once; without one it answers 403 before anything
// is stored, so nobody can file another sprout's public NKey (as rejected,
// which revoked it). The hosted stack (enrolment on) registers neither
// route and its Envoy routes no /pki/ path: there the case checks the
// route is refused and skips, with that reason.
func TestCoreN1_PutNKeyProof(t *testing.T) {
	sc := harness.Begin(t, "N1")
	ctx := ctxFor(t, 5*time.Minute)
	sc.Step("GET /pki/nkeynonce through Envoy")
	nonce, a, err := fleet.NKeyNonce(ctx)
	sc.NoErr(err, "GET /pki/nkeynonce")
	victim, err := nkeys.CreateUser()
	sc.NoErr(err, "an NKey")
	vpub, _ := victim.PublicKey()
	if nonce == "" {
		sc.Step("PUT /pki/putnkey with no proof, on the hosted stack")
		put, err := fleet.PutNKey(ctx, pki.KeySubmission{NKey: vpub, SproutID: "uat-n1-" + strings.ToLower(harness.Nonce(6))})
		sc.NoErr(err, "PUT /pki/putnkey")
		if put.Status/100 == 2 {
			sc.Fatalf("the hosted stack accepted PUT /pki/putnkey without a proof: %s", put)
		}
		sc.Skipf("the hosted stack serves neither GET /pki/nkeynonce (%s) nor PUT /pki/putnkey (%s): enrolment is on, so farmer registers neither route and Envoy routes no /pki/ path; the proof of possession (L12, T6) applies to standalone installs only",
			a, put)
	}

	attacker, err := nkeys.CreateUser()
	sc.NoErr(err, "an NKey")
	apub, _ := attacker.PublicKey()
	n := strings.ToLower(harness.Nonce(6))
	vid, aid := "uat-n1-v-"+n, "uat-n1-a-"+n
	fresh := func() string {
		nonce, a, err := fleet.NKeyNonce(ctx)
		sc.NoErr(err, "GET /pki/nkeynonce")
		if nonce == "" {
			sc.Fatalf("GET /pki/nkeynonce answered %s", a)
		}
		return nonce
	}
	put := func(what string, sub pki.KeySubmission, want int) {
		sc.Step("%s", what)
		got, err := fleet.PutNKey(ctx, sub)
		sc.NoErr(err, "PUT /pki/putnkey")
		if got.Status != want {
			sc.Errorf("%s: %s, want HTTP %d", what, got, want)
		}
	}
	sign := func(signer nkeys.KeyPair, nkey, id, nonce string) pki.KeySubmission {
		sub, err := harness.NKeySubmission(signer, nkey, id, nonce)
		sc.NoErr(err, "signing")
		return sub
	}

	put("an NKey with no signature", pki.KeySubmission{NKey: vpub, SproutID: vid, Nonce: nonce}, http.StatusForbidden)
	put("a signature over a nonce farmer never issued", sign(victim, vpub, vid, "bm90LWEtbm9uY2U"), http.StatusForbidden)
	valid := sign(victim, vpub, vid, fresh())
	put("the victim's NKey with its proof", valid, http.StatusOK)
	put("the same submission again (its nonce spent)", valid, http.StatusForbidden)
	put("the attacker's NKey with its proof", sign(attacker, apub, aid, fresh()), http.StatusOK)
	put("the victim's public NKey under the attacker's sprout, signed by the attacker", sign(attacker, vpub, aid, fresh()), http.StatusForbidden)
	put("the victim's NKey with a new proof: still the one on file", sign(victim, vpub, vid, fresh()), http.StatusOK)
}

// TestCoreRB1_CookRenderBudget covers S4 (security review B4) on the real
// stack: every render of one cook (the recipe and everything it includes,
// rendered once to find the includes and once to build the steps) shares
// farmer's per-cook budget (the chart's farmer.recipes.templateLimits,
// 100000 range iterations; 10000 per render). A recipe including seven
// recipes of 9000 iterations each passes every per-render limit and the
// upload checks, but its cook (126000) runs out of budget: farmer logs the
// budget error, sends the sprout nothing, and the item must fail. One
// including two of them (36000) applies.
func TestCoreRB1_CookRenderBudget(t *testing.T) {
	sc := harness.Begin(t, "RB1")
	needCore(sc)
	f := ready(t, sc)
	nonce := strings.ToLower(harness.Nonce(8))
	const spin = `{{ range split (printf "%09000d" 0) "" }}{{ end }}`
	var parts []string
	for i := range 7 {
		p := fmt.Sprintf("uat.rb1.%s.p%d", nonce, i)
		upload(t, sc, 1, p, spin+"steps: {}\n")
		parts = append(parts, p)
	}
	mainRecipe := func(includes []string, file, text string) string {
		return "include:\n  - " + strings.Join(includes, "\n  - ") + fmt.Sprintf(`
steps:
  uat rb1 marker:
    file.content:
{{- if eq (props "os") "windows" }}
      - name: 'C:\Windows\Temp\%[1]s'
{{- else }}
      - name: /var/tmp/%[1]s
{{- end }}
      - text: "%[2]s"
`, file, text)
	}
	overFile, inFile := "imas-uat-rb1-"+nonce+"-over.txt", "imas-uat-rb1-"+nonce+"-in.txt"
	over, in := "uat.rb1."+nonce+".over", "uat.rb1."+nonce+".in"
	upload(t, sc, 1, over, mainRecipe(parts, overFile, "rb1 over "+nonce))
	upload(t, sc, 1, in, mainRecipe(parts[:2], inFile, "rb1 in "+nonce))

	f.EachSprout(t, sc, f.Sprouts(harness.InTenant(1)), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 20*time.Minute)
		tok := token(t, sc, 1, harness.RoleAdmin)
		start := time.Now()
		sc.Step("cook %s (seven includes: over the per-cook budget)", over)
		id, err := f.API.StartBatch(ctx, tok, f.TenantID(1), []string{sp.AssetID}, harness.CookAction(over, false))
		sc.NoErr(err, "posting the cook")
		needle := "error cooking recipe for " + sp.SproutID + ": cook exceeded its render budget"
		sc.NoErr(eventually(ctx, 3*time.Minute, func() error {
			n, err := f.LogCount(ctx, "farmer", time.Since(start)+time.Minute, needle)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("farmer logged no %q", needle)
			}
			return nil
		}), "farmer's budget error")
		fi, err := f.File(ctx, sp, sp.TempPath(overFile))
		sc.NoErr(err, "reading the host")
		if fi.Exists {
			sc.Errorf("the cook over the budget changed the sprout: %s exists", sp.TempPath(overFile))
		}
		sc.Step("the over-budget cook's item")
		b, err := f.API.WaitBatch(ctx, tok, f.TenantID(1), id, harness.DefaultCookTimeout)
		if err != nil {
			sc.Errorf("the batch of a cook refused for its render budget never finished (%v): the item stays running, "+
				"since farmer only logs a cook that fails before it reaches the sprout (internal/natsapi cook.go) and "+
				"no job_status row is ever written for saasapi to read", err)
		} else if it, _ := b.For(sp); it.Status != harness.ItemFailed {
			sc.Errorf("the cook over the budget ended %s, want failed", it)
		}

		sc.Step("cook %s (two includes: inside the budget)", in)
		b, err = f.Cook(ctx, 1, []harness.Sprout{sp}, in, false)
		sc.NoErr(err, "the cook inside the budget")
		sc.ExpectItem(b, sp, harness.ItemSucceeded, "")
		fi, err = f.File(ctx, sp, sp.TempPath(inFile))
		sc.NoErr(err, "reading the host")
		if !fi.Exists || fi.Content != "rb1 in "+nonce+"\n" {
			sc.Errorf("%s: exists %v, content %q", sp.TempPath(inFile), fi.Exists, fi.Content)
		}
	})
}
