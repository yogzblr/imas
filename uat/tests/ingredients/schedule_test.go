package ingredients

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func jobNames(js []*Job) string {
	var out []string
	for _, j := range js {
		s := j.Name
		if j.Skip != "" {
			s += "(skip)"
		}
		if j.Cross != nil {
			s += "(x" + j.Cross.VM + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func TestBuildPlan(t *testing.T) {
	reg := NewRegistry([]Method{
		{Ingredient: "file", Method: "content", GOOS: []string{GOOSLinux, GOOSWindows}},
		{Ingredient: "win_x", Method: "on", GOOS: []string{GOOSWindows}},
	}, nil)
	content := mustCase(t, strings.Replace(cycleCase, "os: [", "tenant2: true\nos: [", 1))
	skipped := mustCase(t, "id: I.win_x.on\nskip: needs a feature\n")
	sprouts := []harness.Sprout{t1Ubuntu, t1Win, t2Ubuntu, {VM: "t2-windows", Tenant: 2, OS: "windows"}}
	p := BuildPlan(reg, []*Case{content, skipped}, sprouts)
	if got := jobNames(p.Jobs["I.file.content"]); got != "t1-ubuntu t2-ubuntu(xt1-ubuntu) t1-alma(skip) t1-windows t2-windows(xt1-windows)" {
		t.Errorf("file.content jobs: %s", got)
	}
	alma := p.Jobs["I.file.content"][2]
	if !strings.Contains(alma.Skip, "no tenant 1 sprout running alma") {
		t.Errorf("alma skip reason %q", alma.Skip)
	}
	if got := jobNames(p.Jobs["I.win_x.on"]); got != "t1-windows(skip)" {
		t.Errorf("win_x.on jobs: %s", got)
	}
	o := (&Runner{}).Result(context.Background(), p.Jobs["I.win_x.on"][0])
	if s, ok := o.Skipped(); !ok || !strings.Contains(s, "[I.win_x.on os=windows tenant=1 vm=t1-windows] SKIP: needs a feature") {
		t.Errorf("skip outcome %+v", o.Lines)
	}
}

// TestRunnerOrderAndParallelism runs three cases on two sprouts: each
// sprout must run them in order, the sprouts must overlap, and a job the
// selection left out must still run, inline, when its subtest asks.
func TestRunnerOrderAndParallelism(t *testing.T) {
	reg := NewRegistry([]Method{
		{Ingredient: "file", Method: "content", GOOS: []string{GOOSLinux}},
		{Ingredient: "file", Method: "touch", GOOS: []string{GOOSLinux}},
		{Ingredient: "file", Method: "absent", GOOS: []string{GOOSLinux}},
	}, nil)
	var cases []*Case
	for i, m := range []string{"touch", "absent", "content"} {
		text := strings.NewReplacer("I.file.content", "I.file."+m, "file.content:", "file."+m+":").Replace(cycleCase)
		text = strings.Replace(text, "os: [ubuntu, alma, windows]", fmt.Sprintf("os: [ubuntu, alma]\norder: %d", 10+i), 1)
		text = text[:strings.Index(text, "windows:\n")]
		cases = append(cases, mustCase(t, text))
	}
	SortCases(cases)
	d := newFakeDriver(behaviour{})
	d.delay = 2 * time.Millisecond
	p := BuildPlan(reg, cases, []harness.Sprout{t1Ubuntu, t1Alma})
	var mu sync.Mutex
	asked := map[string]bool{}
	r := &Runner{Driver: d, Nonce: func() string { return "n0nce123" }, Selected: func(id, name string) bool {
		mu.Lock()
		defer mu.Unlock()
		asked[id+"/"+name] = true
		return !(id == "I.file.absent" && name == "t1-alma")
	}}
	ctx := context.Background()
	r.Start(ctx, p)
	for _, c := range p.Cases {
		for _, j := range p.Jobs[c.ID] {
			if e := errorsOf(r.Result(ctx, j)); e != "" {
				t.Errorf("%s on %s:\n%s", c.ID, j.Name, e)
			}
		}
	}
	if len(asked) != 6 {
		t.Errorf("selection asked about %d jobs: %v", len(asked), asked)
	}
	order := map[string][]string{}
	for _, e := range d.events {
		vm, what, _ := strings.Cut(e, ":")
		if strings.HasPrefix(what, "cook uat.i.file.") && strings.HasSuffix(what, "test=true") && !strings.Contains(what, ".revert") {
			name := strings.TrimPrefix(what, "cook uat.i.file.")
			name = name[:strings.Index(name, ".")]
			if l := order[vm]; len(l) == 0 || l[len(l)-1] != name {
				order[vm] = append(order[vm], name)
			}
		}
	}
	if got := strings.Join(order["t1-ubuntu"], ","); got != "touch,absent,content" {
		t.Errorf("t1-ubuntu ran %s, want the case order touch,absent,content", got)
	}
	if got := strings.Join(order["t1-alma"], ","); got != "touch,content,absent" {
		// absent wasn't selected for t1-alma, so its worker skipped it and
		// the subtest ran it inline afterwards.
		t.Errorf("t1-alma ran %s", got)
	}
	if d.maxPar < 2 {
		t.Errorf("the sprouts never ran in parallel (max %d)", d.maxPar)
	}
}

func TestRunnerNotReadyAndCancelled(t *testing.T) {
	reg := NewRegistry([]Method{{Ingredient: "file", Method: "content", GOOS: []string{GOOSLinux}}}, nil)
	c := mustCase(t, strings.Replace(cycleCase[:strings.Index(cycleCase, "windows:\n")], "os: [ubuntu, alma, windows]", "os: [ubuntu]", 1))
	p := BuildPlan(reg, []*Case{c}, []harness.Sprout{t1Ubuntu})
	r := &Runner{Driver: newFakeDriver(behaviour{}), Ready: func(harness.Sprout) error { return fmt.Errorf("no sprout ID") }}
	o := r.Result(context.Background(), p.Jobs[c.ID][0])
	if e := errorsOf(o); !strings.Contains(e, "sprout not ready: no sprout ID") {
		t.Errorf("not ready: %q", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = &Runner{Driver: newFakeDriver(behaviour{})}
	if e := errorsOf(r.Result(ctx, p.Jobs[c.ID][0])); !strings.Contains(e, "the run ended before the case ran") {
		t.Errorf("cancelled: %q", e)
	}
}
