package jobs

// FIX.2 (security review 2026-10-b, I4): job objects are keyed on
// (tenant_id, sprout_id), and two tenants with the same sprout_id and jid
// never see each other's objects.

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
)

const (
	tenantA    = "t_a"
	tenantB    = "t_b"
	sharedSID  = "web-01"
	sharedJID  = "11111111-2222-3333-4444-555555555555"
	hostileTID = "t_a/../t_b"
)

// hostileSegments are IDs that must never become a key segment.
var hostileSegments = []string{
	"", ".", "..", "a/b", "../t_b", "t_b/..", "a..b", `a\b`, "a\x00b", "a\nb", "a\x7fb",
	"\xff\xfe", strings.Repeat("x", maxKeySegmentLen+1),
}

func TestJobKey_Layout(t *testing.T) {
	for _, c := range []struct {
		tenant, sprout, jid, object, want string
	}{
		{tenantA, "", "", "", "jobs/t_a/"},
		{tenantA, sharedSID, "", "", "jobs/t_a/web-01/"},
		{tenantA, sharedSID, "j1", "", "jobs/t_a/web-01/j1/"},
		{tenantA, sharedSID, "j1", createdObject, "jobs/t_a/web-01/j1/created.jsonl"},
		{tenantA, sharedSID, "j1", metaObject, "jobs/t_a/web-01/j1/meta.json"},
		{tenantA, sharedSID, "j1", expiredObject, "jobs/t_a/web-01/j1/expired.json"},
		{tenantA, sharedSID, "j1", "events/1-ab.jsonl", "jobs/t_a/web-01/j1/events/1-ab.jsonl"},
	} {
		got, err := jobKey(c.tenant, c.sprout, c.jid, c.object)
		if err != nil || got != c.want {
			t.Errorf("jobKey(%q, %q, %q, %q) = %q, %v; want %q", c.tenant, c.sprout, c.jid, c.object, got, err, c.want)
		}
	}
	at := time.Unix(0, 42)
	key := tenantEventKey(tenantA, sharedSID, "j1", at)
	if !strings.HasPrefix(key, "jobs/t_a/web-01/j1/events/00000000000000000042-") || !strings.HasSuffix(key, ".jsonl") {
		t.Errorf("event key = %q", key)
	}
	if ref, name, ok := parseJobKey(key); !ok || ref != (jobRef{tenantA, sharedSID, "j1"}) || !strings.HasPrefix(name, eventsDir) {
		t.Errorf("parseJobKey(%q) = %+v, %q, %v", key, ref, name, ok)
	}
}

// A hostile tenant, sprout or job ID (slash, dot-dot, backslash, control
// characters, invalid UTF-8, too long, empty) is refused before any key is
// built, and so are malformed combinations and unknown object names.
func TestJobKey_RefusesHostileSegments(t *testing.T) {
	for _, bad := range hostileSegments {
		for name, args := range map[string][4]string{
			"tenant": {bad, sharedSID, "j1", createdObject},
			"sprout": {tenantA, bad, "j1", createdObject},
			"jid":    {tenantA, sharedSID, bad, createdObject},
		} {
			if bad == "" && name != "tenant" {
				continue // an empty trailing part builds a prefix; see below
			}
			if key, err := jobKey(args[0], args[1], args[2], args[3]); !errors.Is(err, ErrInvalidJobKey) {
				t.Errorf("%s %q: jobKey = %q, %v; want ErrInvalidJobKey", name, bad, key, err)
			}
		}
		if _, err := newJobRef(tenantA, bad, "j1"); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("newJobRef(sprout %q): %v; want ErrInvalidJobKey", bad, err)
		}
	}
	for _, args := range [][4]string{
		{tenantA, "", "j1", ""},               // jid without sprout
		{tenantA, "", "", createdObject},      // object without sprout
		{tenantA, sharedSID, "", metaObject},  // object without jid
		{tenantA, sharedSID, "j1", "x.json"},  // not a job object
		{tenantA, sharedSID, "j1", "events/"}, // not an event name
		{tenantA, sharedSID, "j1", "events/a/b.jsonl"},
		{tenantA, sharedSID, "j1", "events/../x.jsonl"},
	} {
		if key, err := jobKey(args[0], args[1], args[2], args[3]); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("jobKey%q = %q, %v; want ErrInvalidJobKey", args, key, err)
		}
	}
}

// Every Store method refuses a hostile tenant or sprout ID with
// ErrInvalidJobKey and reads nothing.
func TestStore_RefusesHostileTenantAndSprout(t *testing.T) {
	store, obj := newTestStore(t)
	seedTenantJob(t, obj, tenantB, sharedSID, sharedJID, "b-step")
	for _, bad := range []string{"", "..", hostileTID, "t_b/", "../t_b", "t\x00b"} {
		calls := map[string]error{}
		_, calls["GetJob"] = store.GetJob(bad, sharedSID, sharedJID)
		_, calls["FindJob"] = store.FindJob(bad, sharedJID)
		_, calls["ListJobsForSprout"] = store.ListJobsForSprout(bad, sharedSID)
		_, calls["ListAllJobs"] = store.ListAllJobs(bad, 0)
		_, calls["ListSprouts"] = store.ListSprouts(bad)
		_, calls["CountJobsForSprout"] = store.CountJobsForSprout(bad, sharedSID)
		calls["DeleteJob"] = store.DeleteJob(bad, sharedSID, sharedJID)
		for name, err := range calls {
			if !errors.Is(err, ErrInvalidJobKey) {
				t.Errorf("tenant %q: %s = %v; want ErrInvalidJobKey", bad, name, err)
			}
		}
	}
	for _, bad := range []string{"..", "a/b", "../web-01", "web\x00"} {
		if _, err := store.GetJob(tenantB, bad, sharedJID); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("sprout %q: GetJob = %v", bad, err)
		}
		if _, err := store.ListJobsForSprout(tenantB, bad); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("sprout %q: ListJobsForSprout = %v", bad, err)
		}
		if err := store.DeleteJob(tenantB, bad, sharedJID); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("sprout %q: DeleteJob = %v", bad, err)
		}
	}
	if _, err := store.GetJob(tenantB, sharedSID, sharedJID); err != nil {
		t.Errorf("tenant b's job after the refusals: %v", err)
	}
}

// The listeners refuse to write under a hostile tenant ID (it would come
// from farmer's own tenant list, never a message, but is checked anyway).
func TestListeners_RefuseHostileTenant(t *testing.T) {
	obj := useTestObjStore(t)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)
	for _, bad := range []string{"", "..", hostileTID, "t_b/x"} {
		recordJobCreation(bad, sharedSID, cook.RecipeEnvelope{JobID: sharedJID, Steps: []cook.Step{{ID: "s1"}}})
		logJobs(bad, stepMsg(t, "imas.cook."+sharedSID+"."+sharedJID, step))
		markJobExpired(bad, sharedSID, sharedJID, time.Now())
	}
	if keys := listKeys(t, obj, ""); len(keys) != 0 {
		t.Errorf("expected nothing written for hostile tenants, got %v", keys)
	}
}

// seedTenantJob writes a one-event job for tenantID, as the listener
// writes an event arriving on that tenant's connection.
func seedTenantJob(t *testing.T, obj *objectstore.Store, tenantID, sproutID, jid, stepID string) {
	t.Helper()
	b, _ := json.Marshal(cook.StepCompletion{ID: cook.StepID(stepID), CompletionStatus: cook.StepCompleted, Started: time.Now()})
	putObject(t, obj, tenantEventKey(tenantID, sproutID, jid, time.Now()), append(b, '\n'))
}

func stepIDs(s *JobSummary) []string {
	var ids []string
	for _, st := range s.Steps {
		ids = append(ids, string(st.ID))
	}
	slices.Sort(ids)
	return ids
}

// Two tenants whose sprouts share a sprout_id run jobs with the same jid,
// through the real listener path (each tenant's events on its own
// connection, as farmer has one per tenant). Each tenant's reads, lists,
// counts and deletes see only its own objects.
func TestTwoTenants_SameSproutAndJID_WriteListReadDelete(t *testing.T) {
	obj := useTestObjStore(t)
	_, connA := startTestNATSServer(t)
	_, connB := startTestNATSServer(t)
	RegisterNatsConn(tenantA, connA)
	RegisterNatsConn(tenantB, connB)
	t.Cleanup(func() { cook.SetDispatchRecorder(nil) })

	recordJobCreation(tenantA, sharedSID, cook.RecipeEnvelope{JobID: sharedJID, InvokedBy: "UALICE", Steps: []cook.Step{{ID: "a-1"}}})
	recordJobCreation(tenantB, sharedSID, cook.RecipeEnvelope{JobID: sharedJID, InvokedBy: "UBOB", Steps: []cook.Step{{ID: "b-1"}, {ID: "b-2"}}})
	for conn, ids := range map[*nats.Conn][]string{connA: {"a-1"}, connB: {"b-1", "b-2"}} {
		for _, id := range ids {
			b, _ := json.Marshal(cook.StepCompletion{ID: cook.StepID(id), CompletionStatus: cook.StepCompleted, Started: time.Now()})
			if err := conn.Publish("imas.cook."+sharedSID+"."+sharedJID, b); err != nil {
				t.Fatal(err)
			}
		}
		conn.Flush()
	}

	store := NewStoreWithObjectStore(obj)
	want := map[string]struct {
		steps   []string
		invoker string
	}{
		tenantA: {[]string{"a-1", "a-1"}, "UALICE"},             // placeholder + event
		tenantB: {[]string{"b-1", "b-1", "b-2", "b-2"}, "UBOB"}, // placeholders + events
	}
	for tenant, w := range want {
		var got *JobSummary
		if !eventually(5*time.Second, func() bool {
			s, err := store.GetJob(tenant, sharedSID, sharedJID)
			got = s
			return err == nil && len(s.Steps) == len(w.steps)
		}) {
			t.Fatalf("%s: GetJob = %+v", tenant, got)
		}
		if got.TenantID != tenant || got.InvokedBy != w.invoker || !slices.Equal(stepIDs(got), w.steps) {
			t.Errorf("%s: GetJob = tenant %q, invoker %q, steps %v; want %s, %s, %v", tenant, got.TenantID, got.InvokedBy, stepIDs(got), tenant, w.invoker, w.steps)
		}
		found, err := store.FindJob(tenant, sharedJID)
		if err != nil || found.TenantID != tenant || !slices.Equal(stepIDs(found), w.steps) {
			t.Errorf("%s: FindJob = %+v, %v", tenant, found, err)
		}
		for name, list := range map[string]func() ([]JobSummary, error){
			"ListAllJobs":       func() ([]JobSummary, error) { return store.ListAllJobs(tenant, 0) },
			"ListJobsForSprout": func() ([]JobSummary, error) { return store.ListJobsForSprout(tenant, sharedSID) },
		} {
			all, err := list()
			if err != nil || len(all) != 1 || all[0].TenantID != tenant || !slices.Equal(stepIDs(&all[0]), w.steps) {
				t.Errorf("%s: %s = %+v, %v; want only its own job", tenant, name, all, err)
			}
		}
		if n, err := store.CountJobsForSprout(tenant, sharedSID); err != nil || n != 1 {
			t.Errorf("%s: CountJobsForSprout = %d, %v", tenant, n, err)
		}
		if sprouts, err := store.ListSprouts(tenant); err != nil || !slices.Equal(sprouts, []string{sharedSID}) {
			t.Errorf("%s: ListSprouts = %v, %v", tenant, sprouts, err)
		}
	}
	for _, key := range listKeys(t, obj, jobKeyPrefix) {
		if !strings.HasPrefix(key, "jobs/t_a/web-01/"+sharedJID+"/") && !strings.HasPrefix(key, "jobs/t_b/web-01/"+sharedJID+"/") {
			t.Errorf("unexpected key %q", key)
		}
	}

	// A third tenant with the same sprout_id sees nothing.
	if _, err := store.GetJob("t_c", sharedSID, sharedJID); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("t_c GetJob: %v, want ErrJobNotFound", err)
	}
	if all, err := store.ListAllJobs("t_c", 0); err != nil || len(all) != 0 {
		t.Errorf("t_c ListAllJobs = %v, %v", all, err)
	}
	if err := store.DeleteJob("t_c", sharedSID, sharedJID); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("t_c DeleteJob: %v, want ErrJobNotFound", err)
	}

	// Deleting tenant A's job leaves tenant B's whole.
	if err := store.DeleteJob(tenantA, sharedSID, sharedJID); err != nil {
		t.Fatal(err)
	}
	if keys := listKeys(t, obj, "jobs/t_a/"); len(keys) != 0 {
		t.Errorf("tenant a's objects left after its delete: %v", keys)
	}
	if got, err := store.GetJob(tenantB, sharedSID, sharedJID); err != nil || len(got.Steps) != 4 || got.InvokedBy != "UBOB" {
		t.Errorf("tenant b's job after a's delete = %+v, %v", got, err)
	}
}

// The reaper is a platform-wide scan: it parses each job's tenant from its
// keys and expires each job by its own keys. Tenant A's old job goes;
// tenant B's recent job with the same sprout_id and jid stays, and the
// other way round.
func TestTwoTenants_SameSproutAndJID_Expire(t *testing.T) {
	store, obj := newTestStore(t)
	old := time.Now().Add(-48 * time.Hour)
	step := makeStep("s1", cook.StepCompleted, old, time.Second)
	b, _ := json.Marshal(step)
	putObject(t, obj, tenantEventKey(tenantA, sharedSID, sharedJID, old), append(b, '\n'))
	putObject(t, obj, mustKey(tenantA, sharedSID, sharedJID, metaObject), []byte(`{"jid":"x","created_at":"2000-01-01T00:00:00Z"}`))
	putObject(t, obj, tenantEventKey(tenantB, sharedSID, sharedJID, time.Now()), append(b, '\n'))
	putObject(t, obj, mustKey(tenantB, sharedSID, sharedJID, metaObject), []byte(`{"jid":"x","created_at":"2000-01-01T00:00:00Z"}`))

	store.reap(24 * time.Hour)
	if keys := listKeys(t, obj, "jobs/t_a/"); len(keys) != 0 {
		t.Errorf("tenant a's expired job not reaped: %v", keys)
	}
	if keys := listKeys(t, obj, "jobs/t_b/"); len(keys) != 2 {
		t.Errorf("tenant b's live job reaped with a's: %v", keys)
	}

	// The other way round: B old, A recent.
	putObject(t, obj, tenantEventKey(tenantA, sharedSID, sharedJID, time.Now()), append(b, '\n'))
	for _, k := range listKeys(t, obj, "jobs/t_b/") {
		if err := obj.Delete(t.Context(), k); err != nil {
			t.Fatal(err)
		}
	}
	putObject(t, obj, tenantEventKey(tenantB, sharedSID, sharedJID, old), append(b, '\n'))
	store.reap(24 * time.Hour)
	if keys := listKeys(t, obj, "jobs/t_b/"); len(keys) != 0 {
		t.Errorf("tenant b's expired job not reaped: %v", keys)
	}
	if _, err := store.GetJob(tenantA, sharedSID, sharedJID); err != nil {
		t.Errorf("tenant a's live job: %v", err)
	}
}

// The reconcile window is per (tenant, sprout, jid) in the job store too:
// tenant A's late job is marked expired under jobs/t_a/ only, and tenant
// B's on-time job with the same sprout_id and jid is recorded in full,
// with no marker.
func TestTwoTenants_SameSproutAndJID_Reconcile(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	recordJobCreation(tenantA, sharedSID, cook.RecipeEnvelope{JobID: sharedJID, Steps: []cook.Step{{ID: "s1"}}, DispatchedAt: h.now.Add(-2 * time.Hour)})
	recordJobCreation(tenantB, sharedSID, cook.RecipeEnvelope{JobID: sharedJID, Steps: []cook.Step{{ID: "s1"}}, DispatchedAt: h.now})
	for _, tenant := range []string{tenantA, tenantB} {
		for _, id := range []string{"start-" + sharedJID, "s1", "completed-" + sharedJID} {
			b, _ := json.Marshal(cook.StepCompletion{ID: cook.StepID(id), CompletionStatus: cook.StepCompleted})
			logJobs(tenant, &nats.Msg{Subject: "imas.cook." + sharedSID + "." + sharedJID, Data: b})
		}
	}

	if !objectExists(t, objStore, mustKey(tenantA, sharedSID, sharedJID, expiredObject)) {
		t.Error("tenant a's late job has no expiry marker")
	}
	if objectExists(t, objStore, mustKey(tenantB, sharedSID, sharedJID, expiredObject)) {
		t.Error("tenant b's on-time job was marked expired")
	}
	store := NewStoreWithObjectStore(objStore)
	a, err := store.GetJob(tenantA, sharedSID, sharedJID)
	if err != nil || a.Status != JobExpired {
		t.Errorf("tenant a: %+v, %v; want expired", a, err)
	}
	b, err := store.GetJob(tenantB, sharedSID, sharedJID)
	if err != nil || b.Status == JobExpired || len(b.Steps) != 4 {
		t.Errorf("tenant b: %+v, %v; want recorded in full (4 steps), not expired", b, err)
	}
	if got := indexStatus(t, db, tenantB, sharedSID, sharedJID); got != JobIndexStatusSucceeded {
		t.Errorf("tenant b index status = %q", got)
	}
}

// indexJobs drops another tenant's keys even when a listing returns them
// (say, an object store that ignored the prefix).
func TestIndexJobs_DropsOtherTenantsKeys(t *testing.T) {
	keys := []string{
		mustKey(tenantA, sharedSID, sharedJID, createdObject),
		mustKey(tenantB, sharedSID, sharedJID, createdObject),
		mustKey(tenantB, sharedSID, sharedJID, metaObject),
	}
	idx := indexJobs(keys, tenantA)
	if len(idx) != 1 {
		t.Fatalf("indexJobs(%s) = %v", tenantA, idx)
	}
	for ref := range idx {
		if ref.tenantID != tenantA {
			t.Errorf("ref %+v of another tenant", ref)
		}
	}
	if all := indexJobs(keys, ""); len(all) != 2 {
		t.Errorf("platform-wide index = %v, want both tenants' jobs", all)
	}
}

// Objects in the pre-tenant layout (jobs/<sprout>/<jid>/...) are never
// read: not by any Store method, not even for a tenant whose ID equals the
// old sprout segment, and the reaper neither reads nor deletes them.
func TestOldLayoutNotRead(t *testing.T) {
	store, obj := newTestStore(t)
	step, _ := json.Marshal(makeStep("s1", cook.StepCompleted, time.Now().Add(-72*time.Hour), time.Second))
	old := []string{
		"jobs/web-01/" + sharedJID + "/created.jsonl",
		"jobs/web-01/" + sharedJID + "/meta.json",
		"jobs/web-01/" + sharedJID + "/expired.json",
		"jobs/web-01/" + sharedJID + "/events/00000000000000000001-abcd1234.jsonl",
	}
	for _, key := range old {
		putObject(t, obj, key, append(step, '\n'))
		if ref, name, ok := parseJobKey(key); ok {
			t.Errorf("parseJobKey(%q) = %+v, %q; want refused", key, ref, name)
		}
	}
	for _, tenant := range []string{"web-01", tenantA} {
		if all, err := store.ListAllJobs(tenant, 0); err != nil || len(all) != 0 {
			t.Errorf("ListAllJobs(%s) = %v, %v; want none", tenant, all, err)
		}
		if _, err := store.FindJob(tenant, sharedJID); !errors.Is(err, ErrJobNotFound) {
			t.Errorf("FindJob(%s) = %v", tenant, err)
		}
		if sprouts, err := store.ListSprouts(tenant); err != nil || len(sprouts) != 0 {
			t.Errorf("ListSprouts(%s) = %v, %v", tenant, sprouts, err)
		}
	}
	// The old event key read as jobs/<tenant>/<sprout>/<jid>/<name>.
	if _, err := store.GetJob("web-01", sharedJID, "events"); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("GetJob(web-01, jid, events) = %v", err)
	}
	if _, err := store.ListJobsForSprout("web-01", sharedJID); !errors.Is(err, ErrSproutNoJobs) {
		t.Errorf("ListJobsForSprout(web-01, jid) = %v", err)
	}
	store.reap(time.Hour)
	for _, key := range old {
		if !objectExists(t, obj, key) {
			t.Errorf("reaper deleted old-layout key %q", key)
		}
	}
}

// The CLI's local store is one directory per tenant: two tenants' jobs
// with the same sprout_id and jid are kept apart, and a sprout or job ID
// that could leave its directory is refused.
func TestCLIStore_PerTenantAndHostileIDs(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stores := map[string]*CLIStore{}
	for _, tenant := range []string{tenantA, tenantB} {
		setCLITenant(t, tenant)
		dir, err := DefaultCLIStorePath()
		if err != nil {
			t.Fatal(err)
		}
		if stores[tenant], err = NewCLIStore(dir); err != nil {
			t.Fatal(err)
		}
		if err := stores[tenant].AppendStep(sharedSID, sharedJID, makeStep(tenant+"-step", cook.StepCompleted, time.Now(), time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for tenant, store := range stores {
		got, _, err := store.GetJob(sharedJID)
		if err != nil || len(got.Steps) != 1 || string(got.Steps[0].ID) != tenant+"-step" {
			t.Errorf("%s: local GetJob = %+v, %v; want only its own step", tenant, got, err)
		}
		if all, err := store.ListJobs(0, "", ""); err != nil || len(all) != 1 {
			t.Errorf("%s: local ListJobs = %v, %v", tenant, all, err)
		}
	}

	store := stores[tenantA]
	for _, bad := range []string{"..", "../" + tenantB, "a/b", "a\x00b"} {
		if err := store.AppendStep(bad, sharedJID, makeStep("x", cook.StepCompleted, time.Now(), 0)); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("AppendStep(sprout %q) = %v", bad, err)
		}
		if err := store.AppendStep(sharedSID, bad, makeStep("x", cook.StepCompleted, time.Now(), 0)); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("AppendStep(jid %q) = %v", bad, err)
		}
		if err := store.RecordJobStart(CLIJobMeta{JID: sharedJID, SproutID: bad}); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("RecordJobStart(sprout %q) = %v", bad, err)
		}
		if _, _, err := store.GetJob(bad); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("GetJob(%q) = %v", bad, err)
		}
		if err := store.DeleteJob(bad); !errors.Is(err, ErrInvalidJobKey) {
			t.Errorf("DeleteJob(%q) = %v", bad, err)
		}
	}
	if got, _, err := stores[tenantB].GetJob(sharedJID); err != nil || len(got.Steps) != 1 {
		t.Errorf("tenant b's local job after a's refusals: %+v, %v", got, err)
	}
}
