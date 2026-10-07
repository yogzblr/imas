package ingredients

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// Job is one subtest of TestIngredients: a case on one sprout, or a
// documented skip.
type Job struct {
	Case *Case
	// Name is the subtest name: the sprout's (t1-ubuntu), or t1-<os> when
	// no sprout of it is in the run.
	Name   string
	Sprout harness.Sprout
	// Cross is tenant 1's sprout of the same OS, for a tenant 2 job.
	Cross *harness.Sprout
	// Skip, when set, is why the job doesn't run.
	Skip string
}

// Plan is every case in run order and the subtests each reports.
type Plan struct {
	Cases []*Case
	Jobs  map[string][]*Job
}

// osesOf lists the OSes a case reports on: those of its method in the
// registry (so a skipped OS still shows up with its reason), plus any the
// case itself names.
func osesOf(reg *Registry, c *Case) []string {
	set := map[string]bool{}
	if m, ok := reg.Get(c.ID); ok {
		for _, o := range m.OSes() {
			set[o] = true
		}
	}
	for _, m := range reg.Unreachable {
		if m.ID() == c.ID {
			for _, o := range m.OSes() {
				set[o] = true
			}
		}
	}
	if c.Backend != "" && len(set) == 0 && len(c.OS) == 0 && len(c.SkipOS) == 0 {
		for _, o := range KnownOSes {
			set[o] = true
		}
	}
	for _, o := range c.OS {
		set[o] = true
	}
	for o := range c.SkipOS {
		set[o] = true
	}
	var out []string
	for _, o := range KnownOSes {
		if set[o] {
			out = append(out, o)
		}
	}
	return out
}

// BuildPlan turns the cases into subtests: one per tenant 1 sprout of each
// OS the case applies to, plus one per tenant 2 sprout for a case marked
// tenant2. An OS with no sprout in the run, or a skipped one, still gets
// a subtest that skips with the reason, so every skip is in the report.
func BuildPlan(reg *Registry, cases []*Case, sprouts []harness.Sprout) *Plan {
	p := &Plan{Cases: cases, Jobs: map[string][]*Job{}}
	of := func(tenant int, os string) []harness.Sprout {
		var out []harness.Sprout
		for _, s := range sprouts {
			if s.Tenant == tenant && s.OS == os {
				out = append(out, s)
			}
		}
		return out
	}
	for _, c := range cases {
		var jobs []*Job
		for _, os := range osesOf(reg, c) {
			runs, reason := c.Runs(os)
			if !runs && reason == "" {
				reason = "the case doesn't run on " + os
			}
			t1 := of(1, os)
			if len(t1) == 0 {
				if runs {
					reason = "uat.json has no tenant 1 sprout running " + os
				}
				jobs = append(jobs, &Job{Case: c, Name: "t1-" + os, Sprout: harness.Sprout{OS: os, Tenant: 1}, Skip: reason})
				continue
			}
			for _, s := range t1 {
				jobs = append(jobs, &Job{Case: c, Name: s.Name(), Sprout: s, Skip: reason})
			}
			if !runs || !c.Tenant2 {
				continue
			}
			cross := t1[0]
			for _, s := range of(2, os) {
				jobs = append(jobs, &Job{Case: c, Name: s.Name(), Sprout: s, Cross: &cross})
			}
		}
		p.Jobs[c.ID] = jobs
	}
	return p
}

// Runner runs the plan's jobs: one worker per sprout VM takes that VM's
// jobs in plan order, so sprouts run in parallel and one sprout runs its
// cases in order, whatever the test framework's parallelism. Subtests
// collect the outcomes with Result.
type Runner struct {
	Driver Driver
	// Ready says why a sprout can't be used (Fleet.Ready); nil if it can.
	Ready func(harness.Sprout) error
	// Nonce returns a fresh nonce for a job.
	Nonce func() string
	// Selected reports whether go test will run the subtest of a case on
	// a sprout (see Matcher); unselected jobs aren't started.
	Selected func(caseID, name string) bool

	mu      sync.Mutex
	locks   map[string]*sync.Mutex
	results map[*Job]chan *Outcome
}

func (r *Runner) lock(vm string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locks == nil {
		r.locks = map[string]*sync.Mutex{}
	}
	l, ok := r.locks[vm]
	if !ok {
		l = &sync.Mutex{}
		r.locks[vm] = l
	}
	return l
}

// Start launches the workers.
func (r *Runner) Start(ctx context.Context, p *Plan) {
	r.mu.Lock()
	r.results = map[*Job]chan *Outcome{}
	byVM := map[string][]*Job{}
	var vms []string
	for _, c := range p.Cases {
		for _, j := range p.Jobs[c.ID] {
			if j.Skip != "" || j.Sprout.VM == "" {
				continue
			}
			if r.Selected != nil && !r.Selected(c.ID, j.Name) {
				continue
			}
			r.results[j] = make(chan *Outcome, 1)
			if _, ok := byVM[j.Sprout.VM]; !ok {
				vms = append(vms, j.Sprout.VM)
			}
			byVM[j.Sprout.VM] = append(byVM[j.Sprout.VM], j)
		}
	}
	r.mu.Unlock()
	for _, vm := range vms {
		jobs := byVM[vm]
		go func() {
			for _, j := range jobs {
				r.results[j] <- r.run(ctx, j)
			}
		}()
	}
}

// Result returns a job's outcome: the worker's, or, for a job no worker
// took (a selection the Matcher didn't foresee), one run now under the
// sprout's lock.
func (r *Runner) Result(ctx context.Context, j *Job) *Outcome {
	if j.Skip != "" {
		return SkipOutcome(j.Case.ID, j.Sprout, j.Skip)
	}
	r.mu.Lock()
	ch, ok := r.results[j]
	r.mu.Unlock()
	if !ok {
		return r.run(ctx, j)
	}
	select {
	case o := <-ch:
		return o
	case <-ctx.Done():
		return FailOutcome(j.Case.ID, j.Sprout, "the run ended before the case ran on this sprout: %v", ctx.Err())
	}
}

func (r *Runner) run(ctx context.Context, j *Job) *Outcome {
	l := r.lock(j.Sprout.VM)
	l.Lock()
	defer l.Unlock()
	if ctx.Err() != nil {
		return FailOutcome(j.Case.ID, j.Sprout, "the run ended before the case ran on this sprout: %v", ctx.Err())
	}
	if r.Ready != nil {
		if err := r.Ready(j.Sprout); err != nil {
			return FailOutcome(j.Case.ID, j.Sprout, "sprout not ready: %v", err)
		}
	}
	nonce := "uat00000"
	if r.Nonce != nil {
		nonce = r.Nonce()
	}
	// A cycle is four cooks and three host calls, plus the revert.
	budget := 5*j.Case.CookTimeout() + 45*time.Minute
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cy := &Cycle{Case: j.Case, Sprout: j.Sprout, Driver: r.Driver, Vars: NewVars(j.Case, j.Sprout, nonce), CrossCheck: j.Cross}
	return cy.Run(cctx)
}

// Replay reports an outcome in the subtest that owns it: log lines are
// logged, errors and fatal lines fail the test (a fatal line is the one
// that stopped the cycle; the revert's lines after it are still
// reported), a skip skips it.
func Replay(t testing.TB, o *Outcome) {
	t.Helper()
	defer func() {
		if o.Elapsed > 0 {
			t.Logf("case time on this sprout: %s", o.Elapsed.Round(time.Second))
		}
	}()
	for _, l := range o.Lines {
		switch l.Kind {
		case "log":
			t.Log(l.Text)
		case "error":
			t.Error(l.Text)
		case "fatal":
			t.Error(l.Text)
		case "skip":
			t.Skip(l.Text)
		default:
			t.Errorf("unknown outcome line %q: %s", l.Kind, l.Text)
		}
	}
}
