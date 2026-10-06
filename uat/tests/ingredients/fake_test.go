package ingredients

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// fakeSprout is a sprout host with one piece of state: whether the case's
// change is on it. Cooks and host scripts act on it the way the real
// ones would, with switches for the ways an ingredient can misbehave.
type fakeSprout struct {
	applied bool
	setups  int
	reverts int
}

// behaviour switches of fakeDriver.
type behaviour struct {
	testApplies   bool // test mode makes the change
	alwaysChanges bool // every real cook reports a change
	neverChanges  bool // no real cook reports a change
	testFails     bool // the test mode cook fails
	realFails     bool // the real cook fails
	noJobLog      bool // the sprout keeps no job log
	setupFails    bool // the setup script exits 1
	leakTo        string
	// leakTo: a real cook also changes this VM (broken tenant scoping)
}

type fakeDriver struct {
	b       behaviour
	delay   time.Duration
	mu      sync.Mutex
	hosts   map[string]*fakeSprout
	recipes map[string]string // tenant/name -> content
	deleted []string
	logs    map[string][]StepCompletion
	jids    int
	events  []string // vm:what, in order
	running map[string]bool
	maxPar  int
}

func newFakeDriver(b behaviour) *fakeDriver {
	return &fakeDriver{b: b, hosts: map[string]*fakeSprout{}, recipes: map[string]string{}, logs: map[string][]StepCompletion{}, running: map[string]bool{}}
}

func (d *fakeDriver) host(vm string) *fakeSprout {
	h, ok := d.hosts[vm]
	if !ok {
		h = &fakeSprout{}
		d.hosts[vm] = h
	}
	return h
}

func (d *fakeDriver) enter(vm, what string) func() {
	d.mu.Lock()
	d.events = append(d.events, vm+":"+what)
	d.running[vm] = true
	n := 0
	for _, r := range d.running {
		if r {
			n++
		}
	}
	if n > d.maxPar {
		d.maxPar = n
	}
	d.mu.Unlock()
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	return func() {
		d.mu.Lock()
		d.running[vm] = false
		d.mu.Unlock()
	}
}

func (d *fakeDriver) Upload(_ context.Context, tenant int, name, content string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.recipes[fmt.Sprintf("%d/%s", tenant, name)] = content
	return nil
}

func (d *fakeDriver) Delete(_ context.Context, tenant int, name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deleted = append(d.deleted, fmt.Sprintf("%d/%s", tenant, name))
}

func (d *fakeDriver) Cook(_ context.Context, sp harness.Sprout, recipe string, test bool, _ time.Duration) (harness.Item, error) {
	defer d.enter(sp.VM, fmt.Sprintf("cook %s test=%v", recipe, test))()
	d.mu.Lock()
	defer d.mu.Unlock()
	content, ok := d.recipes[fmt.Sprintf("%d/%s", sp.Tenant, recipe)]
	if !ok {
		return harness.Item{AssetID: sp.AssetID, Status: harness.ItemFailed, Error: "job_failed"}, nil
	}
	steps, err := RecipeSteps(content)
	if err != nil {
		return harness.Item{}, err
	}
	d.jids++
	jid := fmt.Sprintf("j%d", d.jids)
	h := d.host(sp.VM)
	var lines []StepCompletion
	status, item := StatusCompleted, harness.ItemSucceeded
	changed := false
	switch {
	case strings.HasSuffix(recipe, ".revert"):
		h.applied = false
	case test:
		if d.b.testFails {
			status, item = StatusFailed, harness.ItemFailed
		}
		if d.b.testApplies {
			h.applied = true
		}
	default:
		if d.b.realFails {
			status, item = StatusFailed, harness.ItemFailed
			break
		}
		changed = !h.applied
		if d.b.alwaysChanges {
			changed = true
		}
		if d.b.neverChanges {
			changed = false
		}
		h.applied = true
		if d.b.leakTo != "" {
			d.host(d.b.leakTo).applied = true
		}
	}
	lines = append(lines, StepCompletion{ID: "start-" + jid, CompletionStatus: StatusCompleted})
	for _, s := range steps {
		var e *string
		if status == StatusFailed {
			msg := "boom"
			e = &msg
		}
		lines = append(lines, StepCompletion{ID: s, CompletionStatus: status, ChangesMade: changed, Error: e})
	}
	if !d.b.noJobLog {
		d.logs[jid] = lines
	}
	it := harness.Item{AssetID: sp.AssetID, SproutID: sp.SproutID, Status: item, JID: jid}
	if item == harness.ItemFailed {
		it.Error = "job_failed"
	}
	return it, nil
}

var fakeJIDRe = regexp.MustCompile(`(j[0-9]+)\.jsonl`)

func (d *fakeDriver) Run(_ context.Context, sp harness.Sprout, script string) (*harness.RunResult, error) {
	defer d.enter(sp.VM, "run")()
	d.mu.Lock()
	defer d.mu.Unlock()
	h := d.host(sp.VM)
	var out []string
	val := func(k, v string) { out = append(out, harness.ValuePrefix+k+"="+v) }
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	switch {
	case strings.Contains(script, harness.ValuePrefix+"SETUP_RC"):
		h.setups++
		rc := "0"
		if d.b.setupFails {
			rc = "1"
		}
		val("SETUP_RC", rc)
		val("SETUP_OUT", b64("setup output"))
	case strings.Contains(script, harness.ValuePrefix+"REVERT_RC"):
		h.reverts++
		h.applied = false
		val("REVERT_RC", "0")
		val("REVERT_OUT", b64(""))
	}
	if strings.Contains(script, harness.ValuePrefix+"CHECK_RC") {
		rc := "1"
		if h.applied {
			rc = "0"
		}
		val("CHECK_RC", rc)
		val("CHECK_OUT", b64(fmt.Sprintf("applied=%v", h.applied)))
	}
	seen := map[string]bool{}
	i := 0
	for _, m := range fakeJIDRe.FindAllStringSubmatch(script, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		lines, ok := d.logs[m[1]]
		if !ok {
			val(fmt.Sprintf("JOBLOG_%d", i), "MISSING")
		} else {
			var buf strings.Builder
			for _, l := range lines {
				b, _ := json.Marshal(l)
				buf.Write(b)
				buf.WriteString("\n")
			}
			val(fmt.Sprintf("JOBLOG_%d", i), b64(buf.String()))
		}
		i++
	}
	val("RC", "0")
	return harness.ParseRunOutput([]byte(strings.Join(out, "\n") + "\n")), nil
}
