package harness

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// The ha tier's traffic (docs/briefs/H-azure-next-runs.md, H5): while a
// pod or a node is taken away, loops make an API call every second, enrol
// a new sprout every 10 seconds and run cmd.run on the enrolled sprouts
// every 5 seconds, and record what each one saw. The owner's error
// windows (same brief, Owner decisions) are then checked against the
// record:
//
//   - pod kill: no API call fails after 3 client retries (waits 1 s, 2 s,
//     4 s), and every sprout is connected again within 30 s;
//   - node stop: the API, a new enrolment and a cmd.run are served by other
//     pods within 60 s, and every sprout that was on the stopped node's bus
//     node is connected again within 60 s.

// OpKind names a loop.
type OpKind string

// The loops.
const (
	OpAPI    OpKind = "api"
	OpEnrol  OpKind = "enrolment"
	OpCmd    OpKind = "cmd.run"
	OpRecipe OpKind = "recipe"
)

// DefaultRetries are the client retries of the error windows: 3, after
// 1 s, 2 s and 4 s.
var DefaultRetries = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// Op is one loop operation, with its retries.
type Op struct {
	Kind     OpKind
	Start    time.Time
	End      time.Time
	Attempts int
	// Err is the last attempt's error; empty when the operation succeeded.
	Err string
}

// OK reports whether the operation succeeded, retries included.
func (o Op) OK() bool { return o.Err == "" }

// Observation is one look at a sprout: up when the API reported it
// connected or a cmd.run on it succeeded, down when the API reported it
// not connected or a cmd.run on it failed.
type Observation struct {
	Sprout string
	At     time.Time
	Up     bool
	Detail string
}

// Mark is a labelled moment of a run (a pod deleted, a VM stopped).
type Mark struct {
	Label string
	At    time.Time
}

// LoopPlan says what the loops do. A zero interval turns a loop off.
type LoopPlan struct {
	APIEvery    time.Duration
	EnrolEvery  time.Duration
	CmdEvery    time.Duration
	RecipeEvery time.Duration
	// Retries are the waits before each retry (DefaultRetries).
	Retries []time.Duration
	// OpTimeout bounds one attempt (default 2 minutes).
	OpTimeout time.Duration

	// API is one API call; it returns what it saw of the sprouts.
	API func(ctx context.Context) ([]Observation, error)
	// Enrol enrols one new sprout.
	Enrol func(ctx context.Context) (*Enrolment, error)
	// Cmd runs cmd.run on the enrolled sprouts; the error is set only when
	// the API call itself failed, a failed item is a down observation.
	Cmd func(ctx context.Context) ([]Observation, error)
	// Recipe uploads one recipe and returns its name.
	Recipe func(ctx context.Context) (string, error)
}

// DefaultLoopPlan is the brief's cadence: an API call every second, an
// enrolment every 10 seconds, cmd.run every 5 seconds.
func DefaultLoopPlan() LoopPlan {
	return LoopPlan{APIEvery: time.Second, EnrolEvery: 10 * time.Second, CmdEvery: 5 * time.Second, Retries: DefaultRetries}
}

// Record is what the loops saw.
type Record struct {
	mu         sync.Mutex
	Started    time.Time
	Stopped    time.Time
	Ops        []Op
	Obs        []Observation
	Marks      []Mark
	Enrolments []*Enrolment
	Recipes    []string
}

// Running is a set of loops in progress.
type Running struct {
	rec    *Record
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// StartLoops starts the loops of plan; Stop ends them.
func StartLoops(ctx context.Context, plan LoopPlan) *Running {
	if plan.Retries == nil {
		plan.Retries = DefaultRetries
	}
	if plan.OpTimeout <= 0 {
		plan.OpTimeout = 2 * time.Minute
	}
	lctx, cancel := context.WithCancel(ctx)
	r := &Running{rec: &Record{Started: time.Now()}, cancel: cancel}
	r.loop(lctx, plan, OpAPI, plan.APIEvery, plan.API != nil, func(c context.Context) error {
		obs, err := plan.API(c)
		r.rec.observe(obs)
		return err
	})
	r.loop(lctx, plan, OpEnrol, plan.EnrolEvery, plan.Enrol != nil, func(c context.Context) error {
		e, err := plan.Enrol(c)
		if err == nil && e != nil {
			r.rec.mu.Lock()
			r.rec.Enrolments = append(r.rec.Enrolments, e)
			r.rec.mu.Unlock()
		}
		return err
	})
	r.loop(lctx, plan, OpCmd, plan.CmdEvery, plan.Cmd != nil, func(c context.Context) error {
		obs, err := plan.Cmd(c)
		r.rec.observe(obs)
		return err
	})
	r.loop(lctx, plan, OpRecipe, plan.RecipeEvery, plan.Recipe != nil, func(c context.Context) error {
		name, err := plan.Recipe(c)
		if err == nil {
			r.rec.mu.Lock()
			r.rec.Recipes = append(r.rec.Recipes, name)
			r.rec.mu.Unlock()
		}
		return err
	})
	return r
}

// loop starts fn every interval, each run in its own goroutine so a slow
// one never delays the next tick.
func (r *Running) loop(ctx context.Context, plan LoopPlan, kind OpKind, every time.Duration, on bool, fn func(context.Context) error) {
	if every <= 0 || !on {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.rec.add(runOp(ctx, plan, kind, fn))
			}()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// runOp runs fn with the plan's retries.
func runOp(ctx context.Context, plan LoopPlan, kind OpKind, fn func(context.Context) error) Op {
	op := Op{Kind: kind, Start: time.Now()}
	for i := 0; ; i++ {
		op.Attempts++
		actx, cancel := context.WithTimeout(ctx, plan.OpTimeout)
		err := fn(actx)
		cancel()
		if err == nil {
			op.Err = ""
			break
		}
		op.Err = err.Error()
		if i >= len(plan.Retries) || ctx.Err() != nil {
			break
		}
		if sleep(ctx, plan.Retries[i]) != nil {
			break
		}
	}
	op.End = time.Now()
	return op
}

func (rec *Record) add(op Op) {
	// An operation cut short by Stop says nothing about the service.
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.Stopped.IsZero() && op.End.After(rec.Stopped) && !op.OK() {
		return
	}
	rec.Ops = append(rec.Ops, op)
}

func (rec *Record) observe(obs []Observation) {
	if len(obs) == 0 {
		return
	}
	rec.mu.Lock()
	rec.Obs = append(rec.Obs, obs...)
	rec.mu.Unlock()
}

// Mark records a labelled moment.
func (r *Running) Mark(label string) {
	r.rec.mu.Lock()
	r.rec.Marks = append(r.rec.Marks, Mark{Label: label, At: time.Now()})
	r.rec.mu.Unlock()
}

// Record returns the record so far (shared; read it after Stop).
func (r *Running) Record() *Record { return r.rec }

// Stop ends the loops, waits for the operations in flight and returns the
// record. Stopping again changes nothing.
func (r *Running) Stop() *Record {
	r.once.Do(func() {
		r.rec.mu.Lock()
		r.rec.Stopped = time.Now()
		r.rec.mu.Unlock()
		r.cancel()
		r.wg.Wait()
	})
	return r.rec
}

// Window is an error window of the owner's (H-azure-next-runs.md, Owner
// decisions).
type Window struct {
	Name string
	// NoFailure: no operation may fail after its retries.
	NoFailure bool
	// ServedWithin, when set: after an operation fails, one of the same
	// kind must succeed within this long.
	ServedWithin time.Duration
	// ReconnectWithin, when set: a sprout seen down must be seen up again
	// within this long.
	ReconnectWithin time.Duration
}

// The owner's windows.
var (
	// PodKillWindow: no API call fails after 3 client retries, and every
	// sprout is connected again within 30 s.
	PodKillWindow = Window{Name: "pod kill", NoFailure: true, ReconnectWithin: 30 * time.Second}
	// NodeStopWindow: the API, an enrolment and a cmd.run are served by
	// other pods within 60 s, and every sprout is connected again within
	// 60 s.
	NodeStopWindow = Window{Name: "node stop", ServedWithin: 60 * time.Second, ReconnectWithin: 60 * time.Second}
	// RollingWindow: a rolling restart (HA3): no call fails after 3
	// retries.
	RollingWindow = Window{Name: "rolling restart", NoFailure: true}
)

// Scaled is the window with every duration multiplied by f (for the
// harness's own tests, which run the windows in milliseconds).
func (w Window) Scaled(f float64) Window {
	w.ServedWithin = time.Duration(float64(w.ServedWithin) * f)
	w.ReconnectWithin = time.Duration(float64(w.ReconnectWithin) * f)
	return w
}

// Outage is a stretch where a loop or a sprout was not served.
type Outage struct {
	// What is the loop kind or the sprout.
	What  string
	From  time.Time
	To    time.Time
	Ended bool
	// Detail is the first failure's error.
	Detail string
}

// Length is how long the outage lasted (until the end of the record when
// it never ended).
func (o Outage) Length() time.Duration { return o.To.Sub(o.From) }

// OpOutages lists, per loop kind, the stretches from a failed operation's
// start to the end of the first operation of the same kind that started
// after it and succeeded.
func (rec *Record) OpOutages() []Outage {
	rec.mu.Lock()
	ops := append([]Op(nil), rec.Ops...)
	end := rec.Stopped
	rec.mu.Unlock()
	if end.IsZero() {
		end = time.Now()
	}
	byKind := map[OpKind][]Op{}
	for _, o := range ops {
		byKind[o.Kind] = append(byKind[o.Kind], o)
	}
	var out []Outage
	for _, kind := range []OpKind{OpAPI, OpEnrol, OpCmd, OpRecipe} {
		list := byKind[kind]
		sort.Slice(list, func(i, j int) bool { return list[i].Start.Before(list[j].Start) })
		var cur *Outage
		for _, o := range list {
			switch {
			case !o.OK() && cur == nil:
				cur = &Outage{What: string(kind), From: o.Start, Detail: o.Err}
			case o.OK() && cur != nil && !o.Start.Before(cur.From):
				cur.To, cur.Ended = o.End, true
				out = append(out, *cur)
				cur = nil
			}
		}
		if cur != nil {
			cur.To = end
			out = append(out, *cur)
		}
	}
	return out
}

// SproutOutages lists, per sprout, the stretches from a down observation
// to the first up observation after it.
func (rec *Record) SproutOutages() []Outage {
	rec.mu.Lock()
	obs := append([]Observation(nil), rec.Obs...)
	end := rec.Stopped
	rec.mu.Unlock()
	if end.IsZero() {
		end = time.Now()
	}
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].At.Before(obs[j].At) })
	open := map[string]*Outage{}
	var names []string
	var out []Outage
	for _, o := range obs {
		cur := open[o.Sprout]
		switch {
		case !o.Up && cur == nil:
			open[o.Sprout] = &Outage{What: o.Sprout, From: o.At, Detail: o.Detail}
			names = append(names, o.Sprout)
		case o.Up && cur != nil:
			cur.To, cur.Ended = o.At, true
			out = append(out, *cur)
			delete(open, o.Sprout)
		}
	}
	for _, n := range names {
		if cur, ok := open[n]; ok {
			cur.To = end
			out = append(out, *cur)
			delete(open, n)
		}
	}
	return out
}

// Violations checks the record against a window and describes each
// breach; none means the window held.
func (rec *Record) Violations(w Window) []string {
	var v []string
	rec.mu.Lock()
	ops := append([]Op(nil), rec.Ops...)
	start := rec.Started
	rec.mu.Unlock()
	if w.NoFailure {
		for _, o := range ops {
			if !o.OK() {
				v = append(v, fmt.Sprintf("%s: a %s call at +%s failed after %d attempts: %s",
					w.Name, o.Kind, o.Start.Sub(start).Round(100*time.Millisecond), o.Attempts, o.Err))
			}
		}
	}
	if w.ServedWithin > 0 {
		for _, o := range rec.OpOutages() {
			switch {
			case !o.Ended:
				v = append(v, fmt.Sprintf("%s: %s not served again after it failed at +%s (%s; the loops ran %s more): %s",
					w.Name, o.What, o.From.Sub(start).Round(100*time.Millisecond), "never", o.Length().Round(100*time.Millisecond), o.Detail))
			case o.Length() > w.ServedWithin:
				v = append(v, fmt.Sprintf("%s: %s not served for %s from +%s, more than %s: %s",
					w.Name, o.What, o.Length().Round(100*time.Millisecond), o.From.Sub(start).Round(100*time.Millisecond), w.ServedWithin, o.Detail))
			}
		}
	}
	if w.ReconnectWithin > 0 {
		for _, o := range rec.SproutOutages() {
			switch {
			case !o.Ended:
				v = append(v, fmt.Sprintf("%s: sprout %s down from +%s and not up again by the end of the loops (%s): %s",
					w.Name, o.What, o.From.Sub(start).Round(100*time.Millisecond), o.Length().Round(100*time.Millisecond), o.Detail))
			case o.Length() > w.ReconnectWithin:
				v = append(v, fmt.Sprintf("%s: sprout %s down for %s from +%s, more than %s: %s",
					w.Name, o.What, o.Length().Round(100*time.Millisecond), o.From.Sub(start).Round(100*time.Millisecond), w.ReconnectWithin, o.Detail))
			}
		}
	}
	return v
}

// Summary is the record's timings, for the test log: the marks, each
// loop's count, failures and longest outage, and each sprout's longest
// outage.
func (rec *Record) Summary() string {
	rec.mu.Lock()
	ops := append([]Op(nil), rec.Ops...)
	marks := append([]Mark(nil), rec.Marks...)
	start, stop := rec.Started, rec.Stopped
	enrols, recipes := len(rec.Enrolments), len(rec.Recipes)
	rec.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "loops ran %s", stop.Sub(start).Round(100*time.Millisecond))
	for _, m := range marks {
		fmt.Fprintf(&b, "; %s at +%s", m.Label, m.At.Sub(start).Round(100*time.Millisecond))
	}
	count := map[OpKind][2]int{}
	retried := map[OpKind]int{}
	for _, o := range ops {
		c := count[o.Kind]
		c[0]++
		if !o.OK() {
			c[1]++
		}
		count[o.Kind] = c
		if o.Attempts > 1 {
			retried[o.Kind]++
		}
	}
	longest := map[string]time.Duration{}
	for _, o := range rec.OpOutages() {
		longest[o.What] = max(longest[o.What], o.Length())
	}
	for _, k := range []OpKind{OpAPI, OpEnrol, OpCmd, OpRecipe} {
		c, ok := count[k]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "; %s: %d calls, %d retried, %d failed, longest outage %s", k, c[0], retried[k], c[1], longest[string(k)].Round(100*time.Millisecond))
	}
	fmt.Fprintf(&b, "; %d enrolments, %d recipes", enrols, recipes)
	sl := map[string]time.Duration{}
	var names []string
	for _, o := range rec.SproutOutages() {
		if _, ok := sl[o.What]; !ok {
			names = append(names, o.What)
		}
		sl[o.What] = max(sl[o.What], o.Length())
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "; sprout %s down at most %s", n, sl[n].Round(100*time.Millisecond))
	}
	return b.String()
}
