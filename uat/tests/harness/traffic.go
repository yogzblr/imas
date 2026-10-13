package harness

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Traffic configures Fleet.TrafficPlan: the ha tier's loops against the
// run's own sprouts and tenants.
type Traffic struct {
	// Cadence is the loop plan whose intervals and retries are used
	// (DefaultLoopPlan; the harness's tests scale it down).
	Cadence LoopPlan
	// JoinToken is the key new sprouts enrol with (tenant 1's, minted by
	// the scenario with enough uses).
	JoinToken string
	// Enroller enrols them (NewFullEnroller over the fleet's client).
	Enroller *FullEnroller
	// Marker names the file every cmd.run appends its run's word to, in
	// the sprout's temp directory (design T8: no batch runs twice).
	Marker string
	// Recipes turns the recipe loop on (every RecipeEvery of Cadence, or
	// 15 s): HA2 checks they survive a node stop.
	Recipes bool
	// Poll is how often a batch is polled (default 1 s).
	Poll time.Duration
	// Sprouts are the sprouts the API and cmd.run loops use (default all).
	Sprouts []Sprout
}

// Ledger records which word each cmd.run carried and whether its item
// succeeded, by sprout VM, for CheckMarkers.
type Ledger struct {
	mu    sync.Mutex
	words map[string]map[string]bool // vm -> word -> succeeded
}

func (l *Ledger) add(vm, word string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.words == nil {
		l.words = map[string]map[string]bool{}
	}
	if l.words[vm] == nil {
		l.words[vm] = map[string]bool{}
	}
	l.words[vm][word] = ok
}

// MarkerCmd is a cmd.run that appends word to path: through sh on Linux,
// cmd.exe on Windows (args given, so nothing else is a shell's).
func MarkerCmd(sp Sprout, path, word string) CmdRun {
	if sp.IsWindows() {
		// No quotes: Windows would escape them on the way to cmd.exe, and
		// the temp paths have no spaces.
		return CmdRun{Cmd: "cmd.exe", Args: []string{"/c", "echo " + word + ">>" + path}}
	}
	return CmdRun{Cmd: "sh", Args: []string{"-c", "echo " + word + " >> " + ShQuote(path)}}
}

// TrafficPlan builds the loops of the ha tier for the fleet:
//
//   - API: GET .../sprouts?asset_ids= for one tenant's sprouts, the
//     tenants in turn; each answer is an observation of every sprout's
//     connected flag;
//   - enrolment: a new sprout enrolled in full (FullEnroller) with
//     JoinToken;
//   - cmd.run: per tenant, one batch over its sprouts appending a fresh
//     word to the Marker file; each item is an observation, and the
//     ledger keeps the words for CheckMarkers. Only an API failure
//     (posting or reading the batch) fails the operation; a 429 is waited
//     out;
//   - recipe (with Recipes): a new recipe in tenant 1.
func (f *Fleet) TrafficPlan(t Traffic) (LoopPlan, *Ledger) {
	plan := t.Cadence
	if plan.APIEvery == 0 && plan.EnrolEvery == 0 && plan.CmdEvery == 0 {
		plan = DefaultLoopPlan()
	}
	if t.Recipes && plan.RecipeEvery == 0 {
		plan.RecipeEvery = 15 * time.Second
	}
	if !t.Recipes {
		plan.RecipeEvery = 0
	}
	poll := t.Poll
	if poll <= 0 {
		poll = time.Second
	}
	sprouts := t.Sprouts
	if sprouts == nil {
		sprouts = f.Sprouts()
	}
	byTenant := map[int][]Sprout{}
	var tenants []int
	for _, sp := range sprouts {
		if byTenant[sp.Tenant] == nil {
			tenants = append(tenants, sp.Tenant)
		}
		byTenant[sp.Tenant] = append(byTenant[sp.Tenant], sp)
	}
	sort.Ints(tenants)
	ledger := &Ledger{}
	var turn int
	var turnMu sync.Mutex

	plan.API = func(ctx context.Context) ([]Observation, error) {
		if len(tenants) == 0 {
			return nil, nil
		}
		turnMu.Lock()
		n := tenants[turn%len(tenants)]
		turn++
		turnMu.Unlock()
		tok, err := f.Admin(ctx, n)
		if err != nil {
			return nil, err
		}
		ss := byTenant[n]
		lk, r, err := f.API.LookupAssets(ctx, tok, f.TenantID(n), Assets(ss))
		if err != nil {
			return nil, err
		}
		if r.Status != http.StatusOK {
			return nil, fmt.Errorf("lookup in tenant %d: %s", n, r)
		}
		now := time.Now()
		var obs []Observation
		for _, sp := range ss {
			res, ok := lk.Find(sp.AssetID)
			up := ok && res.Connected
			detail := "lookup: connected"
			if !up {
				detail = "lookup: not connected"
			}
			obs = append(obs, Observation{Sprout: sp.VM, At: now, Up: up, Detail: detail})
		}
		return obs, nil
	}
	if t.JoinToken != "" && t.Enroller != nil {
		plan.Enrol = func(ctx context.Context) (*Enrolment, error) {
			e, err := NewEnrolment("uat-ha-"+Nonce(10), t.JoinToken)
			if err != nil {
				return nil, err
			}
			if err := t.Enroller.Enrol(ctx, e); err != nil {
				return nil, err
			}
			return e, nil
		}
	} else {
		plan.EnrolEvery = 0
	}
	plan.Cmd = func(ctx context.Context) ([]Observation, error) {
		var obs []Observation
		for _, n := range tenants {
			o, err := f.markerBatch(ctx, n, byTenant[n], t.Marker, poll, ledger)
			obs = append(obs, o...)
			if err != nil {
				return obs, err
			}
		}
		return obs, nil
	}
	if t.Marker == "" {
		plan.CmdEvery = 0
	}
	plan.Recipe = func(ctx context.Context) (string, error) {
		tok, err := f.Admin(ctx, 1)
		if err != nil {
			return "", err
		}
		name := "uat.ha." + Nonce(10)
		err = retryRateLimited(ctx, time.Minute, func() (*Response, error) {
			_, r, err := f.API.PutRecipe(ctx, tok, f.TenantID(1), name, RecipeContent(name), Create)
			return r, err
		}, http.StatusCreated)
		if err != nil {
			return "", fmt.Errorf("PUT recipe %s: %w", name, err)
		}
		return name, nil
	}
	return plan, ledger
}

// RecipeContent is the body of a recipe the ha tier creates: it names
// itself, so a read back proves the right object came back.
func RecipeContent(name string) string {
	return "# " + name + "\nsteps: {}\n"
}

// markerBatch posts and waits for one marker batch in tenant n, polling
// every poll. Each attempt carries a fresh word: a retried batch that had
// in fact run is never mistaken for a duplicate.
func (f *Fleet) markerBatch(ctx context.Context, n int, ss []Sprout, marker string, poll time.Duration, ledger *Ledger) ([]Observation, error) {
	tok, err := f.Admin(ctx, n)
	if err != nil {
		return nil, err
	}
	word := Nonce(10)
	// One batch carries one action, so one word for every sprout; the path
	// is per family.
	var obs []Observation
	var linux, windows []Sprout
	for _, sp := range ss {
		if sp.IsWindows() {
			windows = append(windows, sp)
		} else {
			linux = append(linux, sp)
		}
	}
	for _, group := range [][]Sprout{linux, windows} {
		if len(group) == 0 {
			continue
		}
		act := CmdRunAction(MarkerCmd(group[0], group[0].TempPath(marker), word))
		id, err := f.API.StartBatch(ctx, tok, f.TenantID(n), Assets(group), act)
		if err != nil {
			return obs, fmt.Errorf("posting the cmd.run batch in tenant %d: %w", n, err)
		}
		b, err := f.waitBatch(ctx, tok, f.TenantID(n), id, poll)
		if err != nil {
			return obs, err
		}
		now := time.Now()
		for _, sp := range group {
			it, ok := b.For(sp)
			up := ok && it.Status == ItemSucceeded
			detail := "cmd.run succeeded"
			if !up {
				detail = "cmd.run: " + it.String()
			}
			ledger.add(sp.VM, word, up)
			obs = append(obs, Observation{Sprout: sp.VM, At: now, Up: up, Detail: detail})
		}
	}
	return obs, nil
}

// waitBatch polls a batch every poll until it completes or ctx ends; a
// failed read is the API failing.
func (f *Fleet) waitBatch(ctx context.Context, tok, tid, id string, poll time.Duration) (*Batch, error) {
	for {
		b, r, err := f.API.GetBatch(ctx, tok, tid, id)
		if err != nil {
			return nil, fmt.Errorf("reading batch %s: %w", id, err)
		}
		if r.Status != http.StatusOK {
			return nil, fmt.Errorf("reading batch %s: %s", id, r)
		}
		if b.Status == BatchCompleted {
			return b, nil
		}
		if err := sleep(ctx, poll); err != nil {
			return nil, fmt.Errorf("batch %s still %s: %w", id, b.Status, err)
		}
	}
}

// CheckMarkers reads each sprout's marker file and checks no word appears
// twice (a batch ran twice) and every succeeded item's word appears once.
func (f *Fleet) CheckMarkers(ctx context.Context, marker string, ledger *Ledger) []string {
	ledger.mu.Lock()
	words := map[string]map[string]bool{}
	for vm, ws := range ledger.words {
		words[vm] = map[string]bool{}
		for w, ok := range ws {
			words[vm][w] = ok
		}
	}
	ledger.mu.Unlock()
	var out []string
	for _, sp := range f.Sprouts() {
		ws := words[sp.VM]
		if len(ws) == 0 {
			continue
		}
		fi, err := f.File(ctx, sp, sp.TempPath(marker))
		if err != nil {
			out = append(out, fmt.Sprintf("%s: reading %s: %v", sp.VM, marker, err))
			continue
		}
		count := map[string]int{}
		for _, l := range strings.Split(strings.ReplaceAll(fi.Content, "\r", ""), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				count[l]++
			}
		}
		var names []string
		for w := range ws {
			names = append(names, w)
		}
		sort.Strings(names)
		for _, w := range names {
			switch c := count[w]; {
			case c > 1:
				out = append(out, fmt.Sprintf("%s: the cmd.run carrying %s ran %d times", sp.VM, w, c))
			case ws[w] && c == 0:
				out = append(out, fmt.Sprintf("%s: the cmd.run carrying %s succeeded but never ran", sp.VM, w))
			}
		}
	}
	return out
}

// CheckRecipes reads back every recipe the loops created and returns the
// ones missing or wrong.
func (f *Fleet) CheckRecipes(ctx context.Context, names []string) []string {
	tok, err := f.Admin(ctx, 1)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	for _, n := range names {
		rec, r, err := f.API.GetRecipe(ctx, tok, f.TenantID(1), n)
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("recipe %s: %v", n, err))
		case r.Status != http.StatusOK:
			out = append(out, fmt.Sprintf("recipe %s: %s", n, r))
		case rec.Content == nil || *rec.Content != RecipeContent(n):
			out = append(out, fmt.Sprintf("recipe %s came back with other content", n))
		}
	}
	return out
}
