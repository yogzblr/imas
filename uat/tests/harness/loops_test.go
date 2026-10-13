package harness

import (
	"context"
	"strings"
	"testing"
	"time"
)

// at is a moment u units after t0.
func at(t0 time.Time, u float64) time.Time { return t0.Add(time.Duration(u * float64(time.Second))) }

func TestWindowsOnRecords(t *testing.T) {
	t0 := time.Now()
	ok := func(k OpKind, from, to float64) Op {
		return Op{Kind: k, Start: at(t0, from), End: at(t0, to), Attempts: 1}
	}
	bad := func(k OpKind, from, to float64) Op {
		return Op{Kind: k, Start: at(t0, from), End: at(t0, to), Attempts: 4, Err: "HTTP 503"}
	}
	obs := func(vm string, u float64, up bool) Observation { return Observation{Sprout: vm, At: at(t0, u), Up: up} }

	clean := &Record{Started: t0, Stopped: at(t0, 100),
		Ops: []Op{ok(OpAPI, 1, 1.1), ok(OpEnrol, 2, 3), ok(OpCmd, 5, 6)},
		Obs: []Observation{obs("a", 1, true), obs("a", 10, false), obs("a", 30, true)}}
	if v := clean.Violations(PodKillWindow); len(v) != 0 {
		t.Errorf("a 20 s reconnect is inside the pod kill window: %v", v)
	}
	if v := clean.Violations(NodeStopWindow); len(v) != 0 {
		t.Errorf("clean record: %v", v)
	}

	// 45 s without the API: inside the node stop window, never inside the
	// pod kill window (a call failed after its retries).
	r45 := &Record{Started: t0, Stopped: at(t0, 200),
		Ops: []Op{ok(OpAPI, 1, 1.1), bad(OpAPI, 10, 17), bad(OpAPI, 25, 32), ok(OpAPI, 54, 55), ok(OpAPI, 56, 56.5)}}
	if v := r45.Violations(NodeStopWindow); len(v) != 0 {
		t.Errorf("45 s is inside the 60 s node stop window: %v", v)
	}
	if v := r45.Violations(PodKillWindow); len(v) != 2 || !strings.Contains(v[0], "failed after 4 attempts") {
		t.Errorf("the pod kill window must name both failed calls: %v", v)
	}
	if o := r45.OpOutages(); len(o) != 1 || o[0].Length() != 45*time.Second || !o[0].Ended {
		t.Errorf("outages %+v", o)
	}

	// 90 s: outside the node stop window.
	r90 := &Record{Started: t0, Stopped: at(t0, 200),
		Ops: []Op{bad(OpEnrol, 10, 17), ok(OpEnrol, 99, 100)},
		Obs: []Observation{obs("b", 5, false), obs("b", 95, true)}}
	v := r90.Violations(NodeStopWindow)
	if len(v) != 2 || !strings.Contains(v[0], "enrolment not served for 1m30s") || !strings.Contains(v[1], "sprout b down for 1m30s") {
		t.Errorf("90 s must break the node stop window for the enrolment and the sprout: %v", v)
	}

	// Never recovered.
	never := &Record{Started: t0, Stopped: at(t0, 50), Ops: []Op{bad(OpCmd, 10, 17)}, Obs: []Observation{obs("c", 12, false)}}
	if v := never.Violations(NodeStopWindow); len(v) != 2 || !strings.Contains(v[0], "not served again") || !strings.Contains(v[1], "not up again") {
		t.Errorf("unrecovered: %v", v)
	}
	// A success that started before the failure does not end it.
	overlap := &Record{Started: t0, Stopped: at(t0, 50), Ops: []Op{ok(OpAPI, 5, 20), bad(OpAPI, 10, 17)}}
	if o := overlap.OpOutages(); len(o) != 1 || o[0].Ended {
		t.Errorf("overlap: %+v", o)
	}
	if v := (&Record{Started: t0, Stopped: at(t0, 9), Ops: []Op{bad(OpAPI, 1, 2)}}).Violations(RollingWindow); len(v) != 1 {
		t.Errorf("rolling: %v", v)
	}
	if s := r90.Summary(); !strings.Contains(s, "enrolment: 2 calls, 1 retried, 1 failed, longest outage 1m30s") || !strings.Contains(s, "sprout b down at most 1m30s") {
		t.Errorf("summary: %s", s)
	}
	if w := NodeStopWindow.Scaled(0.1); w.ServedWithin != 6*time.Second || w.ReconnectWithin != 6*time.Second {
		t.Errorf("scaled %+v", w)
	}
}

// unit is the harness tests' second: the owner's windows run 10 times
// faster against the fake stack.
const unit = 100 * time.Millisecond

func scaledCadence() LoopPlan {
	return LoopPlan{
		APIEvery: unit, EnrolEvery: 10 * unit, CmdEvery: 5 * unit, RecipeEvery: 15 * unit,
		Retries: []time.Duration{unit, 2 * unit, 4 * unit}, OpTimeout: 30 * unit,
	}
}

// runAgainstFake runs the ha tier's loops against the fake stack with an
// outage of outageUnits of the API, then one of the sprouts, and returns the record and what the
// checks after it found.
func runAgainstFake(t *testing.T, outageUnits float64, configure func(*Fleet, *fakeStackKnobs)) (*Record, []string, []string, []string, []string) {
	t.Helper()
	f, s := fakeFleet(t)
	knobs := &fakeStackKnobs{}
	if configure != nil {
		configure(f, knobs)
	}
	s.ActionBurst = 100000
	s.RemintOnReplay = knobs.remint
	s.DuplicateRuns = knobs.dup
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := f.Prepare(c); err != nil {
		t.Fatal(err)
	}
	tok, err := f.Admin(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.API.MintKey(c, tok, f.TenantID(1), 2, 500)
	if err != nil {
		t.Fatal(err)
	}
	fe := NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP)
	marker := "imas-uat-ha-test-" + Nonce(6)
	plan, ledger := f.TrafficPlan(Traffic{
		Cadence: scaledCadence(), JoinToken: key.RegistrationKey, Enroller: fe,
		Marker: marker, Recipes: true, Poll: unit / 2,
	})
	run := StartLoops(c, plan)
	time.Sleep(10 * unit)
	// First the API is gone (every /v1 route answers 503), then, with the
	// API back, the sprouts are cut off: the API's outage and the sprouts'
	// are measured apart, since a sprout is only seen through the API.
	d := time.Duration(outageUnits * float64(unit))
	run.Mark("API outage")
	s.Outage(d)
	time.Sleep(d + 15*unit)
	run.Mark("sprouts cut off")
	s.CutSprouts(d)
	time.Sleep(d + 15*unit)
	rec := run.Stop()
	t.Log(rec.Summary())
	return rec, Duplicates(rec.Enrolments), fe.ReplayAll(c, rec.Enrolments), f.CheckMarkers(c, marker, ledger), f.CheckRecipes(c, rec.Recipes)
}

type fakeStackKnobs struct{ remint, dup bool }

func TestLoopsFake45sInsideNodeStopWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: runs the loops for seconds")
	}
	rec, dups, replays, markers, recipes := runAgainstFake(t, 45, nil)
	if v := rec.Violations(NodeStopWindow.Scaled(0.1)); len(v) != 0 {
		t.Errorf("a 45 s outage must hold the node stop window: %v", v)
	}
	if v := rec.Violations(PodKillWindow.Scaled(0.1)); len(v) == 0 {
		t.Error("a 45 s outage must break the pod kill window (calls fail after 3 retries)")
	}
	if len(rec.Enrolments) < 2 || len(rec.Recipes) < 2 {
		t.Errorf("%d enrolments and %d recipes: the loops did not run", len(rec.Enrolments), len(rec.Recipes))
	}
	for name, v := range map[string][]string{"duplicates": dups, "replays": replays, "markers": markers, "recipes": recipes} {
		if len(v) != 0 {
			t.Errorf("%s: %v", name, v)
		}
	}
}

func TestLoopsFake90sOutsideNodeStopWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: runs the loops for seconds")
	}
	rec, _, _, _, _ := runAgainstFake(t, 90, nil)
	v := rec.Violations(NodeStopWindow.Scaled(0.1))
	var api, sprout bool
	for _, s := range v {
		api = api || strings.Contains(s, "api not served for")
		sprout = sprout || strings.Contains(s, "sprout t1-ubuntu down for")
	}
	if !api || !sprout {
		t.Errorf("a 90 s outage must break the node stop window for the API and every sprout: %v", v)
	}
}

func TestLoopsFakeCatchDuplicates(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: runs the loops for seconds")
	}
	_, _, replays, markers, _ := runAgainstFake(t, 0, func(_ *Fleet, k *fakeStackKnobs) { k.remint, k.dup = true, true })
	if len(replays) == 0 || !strings.Contains(replays[0], "a second JWT was minted") {
		t.Errorf("a re-minted User JWT must be caught: %v", replays)
	}
	if len(markers) == 0 || !strings.Contains(markers[0], "ran 2 times") {
		t.Errorf("a cmd.run that ran twice must be caught: %v", markers)
	}
}
