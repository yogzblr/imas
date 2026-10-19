package cook

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/yogzblr/imas/internal/pki"
)

// Which failed cooks SendCookEventContext records as refused (P29): those
// that fail before any copy of the job could reach the sprout, and only
// those. A failure once the recipe is staged leaves a copy the sprout can
// still pull and cook (stagedsync.go), so recording it as refused could
// contradict a job that runs.

// recordedRefusal is one DispatchRefusalRecorder call.
type recordedRefusal struct {
	tenantID, sproutID, jid string
	err                     error
}

// recordRefusals installs a DispatchRefusalRecorder for the rest of t and
// returns what it saw.
func recordRefusals(t *testing.T) func() []recordedRefusal {
	t.Helper()
	var mu sync.Mutex
	var got []recordedRefusal
	SetDispatchRefusalRecorder(func(tenantID, sproutID, jid string, err error) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, recordedRefusal{tenantID, sproutID, jid, err})
	})
	t.Cleanup(func() { SetDispatchRefusalRecorder(nil) })
	return func() []recordedRefusal {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRefusal(nil), got...)
	}
}

// recordDispatches installs a DispatchRecorder for the rest of t and
// returns the JIDs it saw.
func recordDispatches(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	SetDispatchRecorder(func(_, _ string, env RecipeEnvelope) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, env.JobID)
	})
	t.Cleanup(func() { SetDispatchRecorder(nil) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// wantRefused checks that exactly one refusal was recorded, for jid on
// sproutID in the test tenant, with err.
func wantRefused(t *testing.T, refusals []recordedRefusal, sproutID, jid string, err error) {
	t.Helper()
	if len(refusals) != 1 {
		t.Fatalf("refusals recorded: %+v, want one for %s", refusals, jid)
	}
	r := refusals[0]
	if r.tenantID != testTenantID || r.sproutID != sproutID || r.jid != jid || r.err != err {
		t.Errorf("refusal %+v, want tenant %s sprout %s jid %s err %v", r, testTenantID, sproutID, jid, err)
	}
}

// Every refusal before anything is staged or pushed: a recipe that
// doesn't resolve, a target step that isn't in it, a stage that fails.
func TestSendCookEvent_RefusedBeforeStaging(t *testing.T) {
	for _, c := range []struct {
		name   string
		recipe RecipeName
		opts   []CookOption
		setup  func(t *testing.T)
	}{
		{name: "the recipe doesn't resolve", recipe: "missing"},
		{name: "the target step isn't in the recipe", recipe: "first", opts: []CookOption{WithTargetStep("no such step")}},
		{name: "staging fails", recipe: "first", setup: func(t *testing.T) {
			// As in TestStageRecipe_SealFailureRefusesDispatch: the
			// sprout has a box key, but nothing can seal to it.
			pki.InvalidateTenantBoxKeys(testTenantID)
			t.Setenv("IMAS_TENANTBOX_OPENBAO_ADDR", "")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			newStageTestStore(t)
			useStageKeys(t, testTenantID)
			nc, cleanup := startCookTestNATS(t)
			defer cleanup()
			sp := newStageSprout(t, testTenantID, "refused-sprout")
			pushed := ackCooks(t, nc, sp, true)
			refusals, dispatches := recordRefusals(t), recordDispatches(t)
			if c.setup != nil {
				c.setup(t)
			}

			jid := GenerateJobID()
			err := SendCookEvent(testTenantID, sp.id, c.recipe, jid, false, c.opts...)
			if err == nil {
				t.Fatal("SendCookEvent: got nil, want the refusal")
			}
			wantRefused(t, refusals(), sp.id, jid, err)
			if d := dispatches(); len(d) != 0 {
				t.Errorf("recorded as dispatched too: %v", d)
			}
			if ok, _ := store.Exists(context.Background(), mustStagedKey(t, testTenantID, sp.id)); ok {
				t.Error("a refused cook left a staged copy")
			}
			select {
			case env := <-pushed:
				t.Errorf("a refused cook was pushed: %+v", env)
			default:
			}
		})
	}
}

// The per-cook render budget is one of those refusals (RB1, S4): a cook
// whose recipes each fit a render but together exceed the cook's range
// iterations fails with ErrCookRenderBudget, returned unchanged, so the
// caller's log still names it.
func TestSendCookEvent_RenderBudgetIsARefusal(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	sp := newStageSprout(t, testTenantID, "budget-refused")
	setCookLimits(t, RenderLimits{CookMaxRangeIterations: 20})
	writeRecipe(t, "recipes/part-a.imas", rangeRecipe("part-a", 6))
	writeRecipe(t, "recipes/part-b.imas", rangeRecipe("part-b", 6))
	writeRecipe(t, "recipes/over.imas", "include:\n  - part-a\n  - part-b\n"+plainRecipe("over"))
	refusals := recordRefusals(t)

	jid := GenerateJobID()
	err := SendCookEvent(testTenantID, sp.id, "over", jid, false)
	cookBudgetError(t, err, CookBudgetIterations)
	wantRefused(t, refusals(), sp.id, jid, err)
}

// The stage guard's refusal: its staged copy is removed, so nothing of
// the job is left to pull.
func TestSendCookEvent_StageGuardRefusal(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	sp := newStageSprout(t, testTenantID, "guard-refused")
	refusals, dispatches := recordRefusals(t), recordDispatches(t)

	guardErr := errors.New("sprout replaced")
	jid := GenerateJobID()
	err := SendCookEvent(testTenantID, sp.id, "first", jid, false, WithStageGuard(func() error { return guardErr }))
	if !errors.Is(err, guardErr) {
		t.Fatalf("SendCookEvent: got %v, want the guard's error", err)
	}
	wantRefused(t, refusals(), sp.id, jid, err)
	if d := dispatches(); len(d) != 0 {
		t.Errorf("recorded as dispatched too: %v", d)
	}
}

// If the guard refuses but its staged copy can't be removed, the sprout
// could still pull and cook it: not recorded as refused.
func TestSendCookEvent_StageGuardWithCopyLeftIsNotARefusal(t *testing.T) {
	srv := newStageTestStore(t)
	useStageKeys(t, testTenantID)
	sp := newStageSprout(t, testTenantID, "guard-copy-left")
	refusals := recordRefusals(t)

	guardErr := errors.New("sprout replaced")
	err := SendCookEvent(testTenantID, sp.id, "first", GenerateJobID(), false, WithStageGuard(func() error {
		srv.FailNext(1, http.StatusForbidden, "AccessDenied") // UnstageRecipe's Delete
		return guardErr
	}))
	if !errors.Is(err, guardErr) {
		t.Fatalf("SendCookEvent: got %v, want the guard's error", err)
	}
	if ok, _ := store.Exists(context.Background(), mustStagedKey(t, testTenantID, sp.id)); !ok {
		t.Fatal("the staged copy is gone: the Delete was meant to fail")
	}
	if r := refusals(); len(r) != 0 {
		t.Errorf("recorded as refused with its copy still staged: %+v", r)
	}
}

// A push the sprout doesn't acknowledge comes after staging: the job was
// dispatched (recorded as such), its copy stays staged, and it is not a
// refusal. Nor is a cook that succeeds.
func TestSendCookEvent_FailuresAfterStagingAreNotRefusals(t *testing.T) {
	for _, ack := range []bool{false, true} {
		newStageTestStore(t)
		useStageKeys(t, testTenantID)
		nc, cleanup := startCookTestNATS(t)
		sp := newStageSprout(t, testTenantID, "staged-sprout")
		ackCooks(t, nc, sp, ack)
		refusals, dispatches := recordRefusals(t), recordDispatches(t)

		jid := GenerateJobID()
		err := SendCookEvent(testTenantID, sp.id, "first", jid, false)
		cleanup()
		if (err == nil) != ack {
			t.Fatalf("ack %v: SendCookEvent: %v", ack, err)
		}
		if r := refusals(); len(r) != 0 {
			t.Errorf("ack %v: recorded as refused: %+v", ack, r)
		}
		if d := dispatches(); len(d) != 1 || d[0] != jid {
			t.Errorf("ack %v: dispatches recorded %v, want [%s]", ack, d, jid)
		}
	}
}

// With no recorder installed a refusal is only returned, as before.
func TestSendCookEvent_RefusalWithoutRecorder(t *testing.T) {
	newStageTestStore(t)
	SetDispatchRefusalRecorder(nil)
	if err := SendCookEvent(testTenantID, "no-recorder", "missing", GenerateJobID(), false); err == nil {
		t.Fatal("SendCookEvent: got nil for a missing recipe")
	}
}
