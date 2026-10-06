package ingredients

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/yogzblr/imas/uat/tests/harness"
)

const cycleCase = `id: I.file.content
os: [ubuntu, alma, windows]
linux:
  setup: echo prepare
  recipe: |
    steps:
      uat one:
        file.content:
          - name: /var/tmp/a-@NONCE@
      uat two:
        file.content:
          - name: /var/tmp/b-@NONCE@
  check: test -f /var/tmp/a-@NONCE@
  revert: rm -f /var/tmp/a-@NONCE@
windows:
  recipe: |
    steps:
      uat one:
        file.content:
          - name: '@TMP@\a-@NONCE@'
  check: exit 0
`

var (
	t1Ubuntu = harness.Sprout{VM: "t1-ubuntu", Tenant: 1, OS: "ubuntu", SproutID: "ubuntu-01", AssetID: "a-t1u"}
	t2Ubuntu = harness.Sprout{VM: "t2-ubuntu", Tenant: 2, OS: "ubuntu", SproutID: "ubuntu-01", AssetID: "a-t2u"}
	t1Alma   = harness.Sprout{VM: "t1-alma", Tenant: 1, OS: "alma", SproutID: "alma-01", AssetID: "a-t1a"}
	t1Win    = harness.Sprout{VM: "t1-windows", Tenant: 1, OS: "windows", SproutID: "win-01", AssetID: "a-t1w"}
)

func runCycle(t *testing.T, caseText string, b behaviour, sp harness.Sprout, prepare func(*fakeDriver)) (*Outcome, *fakeDriver) {
	t.Helper()
	c := mustCase(t, caseText)
	d := newFakeDriver(b)
	if prepare != nil {
		prepare(d)
	}
	cy := &Cycle{Case: c, Sprout: sp, Driver: d, Vars: NewVars(c, sp, "n0nce123")}
	if sp.Tenant == 2 {
		x := t1Ubuntu
		cy.CrossCheck = &x
	}
	return cy.Run(context.Background()), d
}

func errorsOf(o *Outcome) string {
	var out []string
	for _, l := range o.Lines {
		if l.Kind == "error" || l.Kind == "fatal" {
			out = append(out, l.Text)
		}
	}
	return strings.Join(out, "\n")
}

func TestCycleConformingIngredient(t *testing.T) {
	o, d := runCycle(t, cycleCase, behaviour{}, t1Ubuntu, nil)
	if e := errorsOf(o); e != "" {
		t.Fatalf("a conforming ingredient failed:\n%s", e)
	}
	h := d.hosts["t1-ubuntu"]
	if h.setups != 1 || h.reverts != 1 || h.applied {
		t.Errorf("setup %d, revert %d, applied after revert %v", h.setups, h.reverts, h.applied)
	}
	var cooks []string
	for _, e := range d.events {
		if strings.Contains(e, "cook") {
			cooks = append(cooks, e[strings.Index(e, "test="):])
		}
	}
	if strings.Join(cooks, ",") != "test=true,test=false,test=true,test=false" {
		t.Errorf("cook sequence %v", cooks)
	}
	if len(d.deleted) != 1 || d.deleted[0] != "1/"+RecipeName(mustCase(t, cycleCase), "n0nce123", "") {
		t.Errorf("recipes deleted: %v", d.deleted)
	}
	if !strings.Contains(o.Lines[0].Text, "[I.file.content os=ubuntu tenant=1 vm=t1-ubuntu step=setup]") {
		t.Errorf("first line %q", o.Lines[0].Text)
	}
}

func TestCycleFindings(t *testing.T) {
	for name, tc := range map[string]struct {
		b       behaviour
		caseTxt string
		sp      harness.Sprout
		want    []string
		fatal   bool
	}{
		"test mode changes the host": {b: behaviour{testApplies: true}, want: []string{"step=after test mode", "the check already passes before the real cook: test mode changed the host"}},
		"not idempotent":             {b: behaviour{alwaysChanges: true}, want: []string{"the second real cook (job j4): step \"uat one\" reported a change", "not idempotent"}},
		"no change reported":         {b: behaviour{neverChanges: true}, want: []string{"the first real cook (job j2): no step reported a change"}},
		"test mode fails":            {b: behaviour{testFails: true}, want: []string{"cook in test mode: want the item succeeded, got asset a-t1u sprout ubuntu-01: failed", "cook in test mode again"}},
		"real cook fails":            {b: behaviour{realFails: true}, want: []string{"step=cook for real] FAIL: cook for real: want the item succeeded"}, fatal: true},
		"no job log":                 {b: behaviour{noJobLog: true}, want: []string{"the sprout has no job log for it"}},
		"setup fails":                {b: behaviour{setupFails: true}, want: []string{"the setup script exited 1 (not the ingredient's fault"}, fatal: true},
		"tenant scoping broken": {b: behaviour{leakTo: "t1-ubuntu"}, sp: t2Ubuntu,
			want: []string{"tenant 2's cook shows on tenant 1's sprout t1-ubuntu, which has the same sproutid"}},
	} {
		t.Run(name, func(t *testing.T) {
			sp := tc.sp
			if sp.VM == "" {
				sp = t1Ubuntu
			}
			text := tc.caseTxt
			if text == "" {
				text = cycleCase
			}
			o, d := runCycle(t, text, tc.b, sp, nil)
			e := errorsOf(o)
			for _, w := range tc.want {
				if !strings.Contains(e, w) {
					t.Errorf("missing %q in:\n%s", w, e)
				}
			}
			hasFatal := false
			for _, l := range o.Lines {
				hasFatal = hasFatal || l.Kind == "fatal"
			}
			if hasFatal != tc.fatal {
				t.Errorf("fatal %v, want %v", hasFatal, tc.fatal)
			}
			if d.hosts[sp.VM].reverts != 1 {
				t.Errorf("the revert must run whatever happened: %d", d.hosts[sp.VM].reverts)
			}
		})
	}
}

func TestCycleCaseKnobs(t *testing.T) {
	// idempotent: false accepts a change on every run.
	o, _ := runCycle(t, strings.Replace(cycleCase, "os: [", "idempotent: false\nos: [", 1), behaviour{alwaysChanges: true}, t1Ubuntu, nil)
	if e := errorsOf(o); e != "" {
		t.Errorf("idempotent: false:\n%s", e)
	}
	// An assertion method: present before, no change, never reverted into absence.
	assert := strings.Replace(cycleCase, "os: [", "changes: false\npre_check: present\nos: [", 1)
	o, _ = runCycle(t, assert, behaviour{neverChanges: true}, t1Ubuntu, func(d *fakeDriver) { d.host("t1-ubuntu").applied = true })
	if e := errorsOf(o); e != "" {
		t.Errorf("assertion case:\n%s", e)
	}
	o, _ = runCycle(t, assert, behaviour{neverChanges: true}, t1Ubuntu, nil)
	if e := errorsOf(o); !strings.Contains(e, "the case expects the state to be in place already") {
		t.Errorf("present pre-check not enforced:\n%s", e)
	}
	// A skipped OS and a skipped case.
	o, _ = runCycle(t, strings.Replace(cycleCase, "os: [ubuntu, alma, windows]", "os: [ubuntu, windows]\nskip_os: {alma: no reason to run}", 1), behaviour{}, t1Alma, nil)
	if s, ok := o.Skipped(); !ok || !strings.Contains(s, "SKIP: no reason to run") {
		t.Errorf("skip_os: %+v", o.Lines)
	}
	// Windows uses the windows part.
	o, d := runCycle(t, cycleCase, behaviour{}, t1Win, nil)
	if e := errorsOf(o); e != "" {
		t.Errorf("windows:\n%s", e)
	}
	for k, v := range d.recipes {
		if !strings.Contains(v, `C:\Windows\Temp\a-n0nce123`) {
			t.Errorf("recipe %s not expanded for Windows: %s", k, v)
		}
	}
}

// TestScriptCallRunsInSh runs the Linux wrapper of a case script in a real
// sh, through harness.WrapScript, and reads it back as the runner does.
func TestScriptCallRunsInSh(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, need := range []string{"base64", "mktemp"} {
		if _, err := exec.LookPath(need); err != nil {
			t.Skip("no " + need)
		}
	}
	script := ScriptCall(t1Ubuntu, "echo 'quoted \"text\" $HOME'\nprintf 'line two\\n'\nexit 3", "CHECK") +
		"\n" + ScriptCall(t1Ubuntu, "true", "REVERT")
	out, err := exec.Command(sh, "-c", harness.WrapScript(harness.FamilyLinux, script)).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	res := harness.ParseRunOutput(out)
	rc, text := scriptResult(res, "CHECK")
	if rc != 3 || !strings.Contains(text, `quoted "text" `) || !strings.Contains(text, "line two") {
		t.Errorf("CHECK rc %d out %q", rc, text)
	}
	if rc, _ := scriptResult(res, "REVERT"); rc != 0 || res.ExitCode != 0 {
		t.Errorf("REVERT rc %d, wrapper %d", rc, res.ExitCode)
	}
	if strings.Contains(HostCall(t1Ubuntu, "", []string{"ok_1", "bad;rm -rf /"}), "bad;rm") {
		t.Error("a job id that isn't one must not reach the script")
	}
	if out, err := exec.Command(sh, "-n", "-c", HostCall(t1Ubuntu, "true", []string{"j1", "j2"})).CombinedOutput(); err != nil {
		t.Errorf("HostCall isn't valid sh: %v %s", err, out)
	}
}

func TestParseJobLog(t *testing.T) {
	res := harness.ParseRunOutput([]byte("__IMAS_UAT_JOBLOG_0=" +
		"eyJJRCI6InN0YXJ0LWoxIiwiQ29tcGxldGlvblN0YXR1cyI6Mn0KeyJJRCI6InMiLCJDb21wbGV0aW9uU3RhdHVzIjozLCJDaGFuZ2VzTWFkZSI6ZmFsc2UsIkVycm9yIjoibm9wZSJ9Cg==" +
		"\n__IMAS_UAT_JOBLOG_1=MISSING\n__IMAS_UAT_JOBLOGDIR=/x\n"))
	l, err := ParseJobLog(res, 0)
	if err != nil || len(l.Steps) != 1 || l.Steps[0].ID != "s" || l.Steps[0].CompletionStatus != StatusFailed || l.Steps[0].errText() != "nope" {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := ParseJobLog(res, 1); err == nil || !strings.Contains(err.Error(), "(/x)") {
		t.Errorf("missing log: %v", err)
	}
	if _, err := ParseJobLog(res, 2); err == nil {
		t.Error("an absent value is an error")
	}
}
