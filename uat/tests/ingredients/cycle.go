package ingredients

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// Driver is what a case cycle needs from the stack. The uat runner backs
// it with uat/tests/harness (saasapi batches and recipes, vmctl.sh); the
// unit tests back it with a fake sprout.
type Driver interface {
	// Upload creates or replaces a recipe in a tenant.
	Upload(ctx context.Context, tenant int, name, content string) error
	// Delete removes a recipe, best effort.
	Delete(ctx context.Context, tenant int, name string)
	// Cook cooks a recipe on one sprout through the API and waits for
	// the batch item.
	Cook(ctx context.Context, sp harness.Sprout, recipe string, test bool, timeout time.Duration) (harness.Item, error)
	// Run runs a host script on the sprout's VM outside the platform
	// (vmctl.sh run) and returns what it printed.
	Run(ctx context.Context, sp harness.Sprout, script string) (*harness.RunResult, error)
}

// Line is one message of an outcome, already formatted the way
// harness.Scenario formats them ("[<id> os=.. tenant=.. vm=.. step=..]
// FAIL: ..."), so uat/tests/uatreport reads it the same way.
type Line struct {
	Kind string // log, error, fatal, skip
	Text string
}

// Outcome is what one case did on one sprout, replayed later by the
// subtest that reports it.
type Outcome struct {
	Lines   []Line
	Elapsed time.Duration
}

// Failed reports whether any line is an error.
func (o *Outcome) Failed() bool {
	for _, l := range o.Lines {
		if l.Kind == "error" || l.Kind == "fatal" {
			return true
		}
	}
	return false
}

// Skipped returns the skip line, if the outcome is a skip.
func (o *Outcome) Skipped() (string, bool) {
	for _, l := range o.Lines {
		if l.Kind == "skip" {
			return l.Text, true
		}
	}
	return "", false
}

// recorder builds an Outcome with harness.Scenario's message format.
type recorder struct {
	id, os, vm string
	tenant     int
	step       string
	out        *Outcome
}

func newRecorder(id string, sp harness.Sprout) *recorder {
	return &recorder{id: id, os: sp.OS, vm: sp.VM, tenant: sp.Tenant, out: &Outcome{}}
}

func (r *recorder) where() string {
	var b strings.Builder
	b.WriteString("[" + r.id)
	if r.os != "" {
		b.WriteString(" os=" + r.os)
	}
	if r.tenant != 0 {
		fmt.Fprintf(&b, " tenant=%d", r.tenant)
	}
	if r.vm != "" {
		b.WriteString(" vm=" + r.vm)
	}
	if r.step != "" {
		b.WriteString(" step=" + r.step)
	}
	b.WriteString("]")
	return b.String()
}

func (r *recorder) Step(format string, args ...any) {
	r.step = fmt.Sprintf(format, args...)
	r.out.Lines = append(r.out.Lines, Line{"log", r.where()})
}

func (r *recorder) Logf(format string, args ...any) {
	r.out.Lines = append(r.out.Lines, Line{"log", r.where() + " " + fmt.Sprintf(format, args...)})
}

func (r *recorder) Errorf(format string, args ...any) {
	r.out.Lines = append(r.out.Lines, Line{"error", r.where() + " FAIL: " + fmt.Sprintf(format, args...)})
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.out.Lines = append(r.out.Lines, Line{"fatal", r.where() + " FAIL: " + fmt.Sprintf(format, args...)})
}

func (r *recorder) Skipf(format string, args ...any) {
	r.out.Lines = append(r.out.Lines, Line{"skip", r.where() + " SKIP: " + fmt.Sprintf(format, args...)})
}

// SkipOutcome is the outcome of a case that doesn't run on a sprout.
func SkipOutcome(id string, sp harness.Sprout, reason string) *Outcome {
	r := newRecorder(id, sp)
	r.Skipf("%s", oneLine(reason))
	return r.out
}

// FailOutcome is the outcome of a case that couldn't start on a sprout.
func FailOutcome(id string, sp harness.Sprout, format string, args ...any) *Outcome {
	r := newRecorder(id, sp)
	r.Fatalf(format, args...)
	return r.out
}

// Cycle runs one case on one sprout.
type Cycle struct {
	Case   *Case
	Sprout harness.Sprout
	Driver Driver
	// Vars are the placeholder values (see NewVars).
	Vars Vars
	// CrossCheck, for a tenant 2 run, is tenant 1's sprout of the same OS
	// (the same sproutid): after the real cook, tenant 2's check must
	// still fail there.
	CrossCheck *harness.Sprout
}

// NewVars returns the placeholder values for a case on a sprout.
func NewVars(c *Case, sp harness.Sprout, nonce string) Vars {
	src := "/var/tmp"
	if sp.IsWindows() {
		src = "/Windows/Temp"
	}
	return Vars{
		"@NONCE@":     nonce,
		"@TMP@":       sp.TempDir(),
		"@SRCTMP@":    src,
		"@TENANT@":    fmt.Sprint(sp.Tenant),
		"@SPROUT_ID@": sp.SproutID,
		"@CASE@":      strings.ReplaceAll(strings.ToLower(c.ID), ".", "-"),
	}
}

// RecipeName is the recipe name a case is uploaded under.
func RecipeName(c *Case, nonce, suffix string) string {
	n := "uat." + strings.ToLower(c.ID) + "." + nonce
	if suffix != "" {
		n += "." + suffix
	}
	return n
}

// Run runs the cycle of the catalogue: cook in test mode (it must succeed
// and change nothing on the host: the out of band check still fails),
// cook for real (a change is reported), cook in test mode again, cook for
// real again (no change is reported: idempotent), check out of band, and
// revert. A failure names the case, the sprout and what differed; the
// revert runs whatever happened.
//
// "Test mode shows a pending change" can't be asserted: the sprout drops
// a test mode step's Changed and notes (internal/cook/sproutcook.go), so
// neither its job log nor the API carries them. The cycle asserts by
// effect instead (test mode succeeds, every step completes, the host is
// untouched), as UAT.5's R5 does.
func (cy *Cycle) Run(ctx context.Context) *Outcome {
	start := time.Now()
	c, sp, d := cy.Case, cy.Sprout, cy.Driver
	r := newRecorder(c.ID, sp)
	defer func() { r.out.Elapsed = time.Since(start) }()
	if ok, reason := c.Runs(sp.OS); !ok {
		if reason == "" {
			reason = "the case doesn't list " + sp.OS
		}
		r.Skipf("%s", oneLine(reason))
		return r.out
	}
	part := c.For(sp.OS).Expand(cy.Vars)
	nonce := cy.Vars["@NONCE@"]
	recipe := RecipeName(c, nonce, "")
	revertRecipe := RecipeName(c, nonce, "revert")
	timeout := c.CookTimeout()
	steps, err := RecipeSteps(part.Recipe)
	if err != nil {
		r.Fatalf("the case's recipe doesn't parse: %v", err)
		return r.out
	}

	// The revert runs whatever happens below, after the recipes are
	// cleaned up from the tenant.
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout+5*time.Minute)
		defer cancel()
		if part.RevertRecipe != "" {
			r.Step("revert (recipe)")
			if err := d.Upload(cctx, sp.Tenant, revertRecipe, part.RevertRecipe); err != nil {
				r.Errorf("uploading the revert recipe: %v; the host may keep the change", err)
			} else {
				it, err := d.Cook(cctx, sp, revertRecipe, false, timeout)
				if err != nil || it.Status != harness.ItemSucceeded {
					r.Errorf("the revert cook: %s; the host may keep the change", itemOrErr(it, err))
				}
				d.Delete(cctx, sp.Tenant, revertRecipe)
			}
		}
		if part.Revert != "" {
			r.Step("revert (host script)")
			res, err := d.Run(cctx, sp, ScriptCall(sp, part.Revert, "REVERT"))
			if err != nil {
				r.Errorf("the revert script: %v; the host may keep the change", err)
			} else if rc, out := scriptResult(res, "REVERT"); rc != 0 {
				r.Errorf("the revert script exited %d: %s; the host may keep the change", rc, clip(out, 400))
			}
		}
		d.Delete(cctx, sp.Tenant, recipe)
	}()

	if part.Setup != "" {
		r.Step("setup")
		res, err := d.Run(ctx, sp, ScriptCall(sp, part.Setup, "SETUP"))
		if err != nil {
			r.Fatalf("running the setup script: %v", err)
			return r.out
		}
		if rc, out := scriptResult(res, "SETUP"); rc != 0 {
			r.Fatalf("the setup script exited %d (not the ingredient's fault; the case can't run): %s", rc, clip(out, 400))
			return r.out
		}
	}

	r.Step("upload the recipe")
	if err := d.Upload(ctx, sp.Tenant, recipe, part.Recipe); err != nil {
		r.Fatalf("uploading recipe %s: %v", recipe, err)
		return r.out
	}

	// A failed real cook stops the cycle (nothing after it can be
	// judged); a failed test mode cook is recorded and the cycle goes on,
	// so one finding doesn't hide the next.
	cook := func(what string, test bool) (string, bool) {
		r.Step("%s", what)
		it, err := d.Cook(ctx, sp, recipe, test, timeout)
		report := r.Errorf
		if !test {
			report = r.Fatalf
		}
		if err != nil {
			report("%s: %v", what, err)
			return "", false
		}
		if it.Status != harness.ItemSucceeded {
			report("%s: want the item succeeded, got %s", what, it)
			cy.explain(ctx, r, it.JID, steps)
			return it.JID, false
		}
		return it.JID, true
	}

	jidTest1, okTest1 := cook("cook in test mode", true)
	r.Step("after test mode: the host is unchanged and the job log is clean")
	var jids []string
	if okTest1 {
		jids = []string{jidTest1}
	}
	res, err := d.Run(ctx, sp, HostCall(sp, part.Check, jids))
	if err != nil {
		r.Fatalf("reading the host: %v", err)
		return r.out
	}
	if part.Check != "" {
		rc, out := scriptResult(res, "CHECK")
		switch c.Pre() {
		case PreAbsent:
			if rc == 0 {
				r.Errorf("the check already passes before the real cook: test mode changed the host, or the state was there before (check output: %s)", clip(out, 300))
			}
		case PrePresent:
			if rc != 0 {
				r.Errorf("the check fails before the real cook (exit %d): the case expects the state to be in place already: %s", rc, clip(out, 300))
			}
		}
	}
	if okTest1 {
		cy.checkLog(r, res, 0, jidTest1, steps, "the test mode cook", false, false)
	}

	jidReal1, ok := cook("cook for real", false)
	if !ok {
		return r.out
	}
	if cy.CrossCheck != nil && part.Check != "" && c.Pre() == PreAbsent {
		x := *cy.CrossCheck
		r.Step("tenant scoping: the change is not on %s (tenant %d, same sproutid)", x.VM, x.Tenant)
		xres, err := d.Run(ctx, x, ScriptCall(x, part.Check, "CHECK"))
		if err != nil {
			r.Errorf("running the check on %s: %v", x.VM, err)
		} else if rc, out := scriptResult(xres, "CHECK"); rc == 0 {
			r.Errorf("tenant %d's cook shows on tenant %d's sprout %s, which has the same sproutid: tenant scoping broken (check output: %s)", sp.Tenant, x.Tenant, x.VM, clip(out, 300))
		}
	}
	jidTest2, okTest2 := cook("cook in test mode again", true)
	jidReal2, ok := cook("cook for real again", false)
	if !ok {
		return r.out
	}

	r.Step("check out of band")
	logJIDs := []string{jidReal1, jidReal2}
	if okTest2 {
		logJIDs = append(logJIDs, jidTest2)
	}
	res, err = d.Run(ctx, sp, HostCall(sp, part.Check, logJIDs))
	if err != nil {
		r.Fatalf("reading the host: %v", err)
		return r.out
	}
	if part.Check != "" {
		rc, out := scriptResult(res, "CHECK")
		if rc != 0 {
			r.Errorf("the out of band check exits %d after the real cook: the change isn't on the host: %s", rc, clip(out, 400))
		} else if part.ExpectOutput != "" && !strings.Contains(out, part.ExpectOutput) {
			r.Errorf("the check's output lacks %q: %s", part.ExpectOutput, clip(out, 400))
		}
	}
	cy.checkLog(r, res, 0, jidReal1, steps, "the first real cook", c.WantChanges(), false)
	cy.checkLog(r, res, 1, jidReal2, steps, "the second real cook", false, c.WantIdempotent())
	if okTest2 {
		cy.checkLog(r, res, 2, jidTest2, steps, "the second test mode cook", false, false)
	}
	return r.out
}

// explain reads the job log of a failed cook and records its failed steps.
func (cy *Cycle) explain(ctx context.Context, r *recorder, jid string, steps []string) {
	if jid == "" {
		return
	}
	res, err := cy.Driver.Run(ctx, cy.Sprout, HostCall(cy.Sprout, "", []string{jid}))
	if err != nil {
		return
	}
	log, err := ParseJobLog(res, 0)
	if err != nil {
		r.Logf("job log %s: %v", jid, err)
		return
	}
	for _, s := range log.Steps {
		if s.CompletionStatus != StatusCompleted {
			r.Logf("job %s step %q: %s: %s", jid, s.ID, statusName(s.CompletionStatus), s.errText())
		}
	}
}

// checkLog asserts on one cook's job log: every step of the recipe is
// there and completed; with wantChange at least one reported a change;
// with wantNone none did.
func (cy *Cycle) checkLog(r *recorder, res *harness.RunResult, i int, jid string, steps []string, what string, wantChange, wantNone bool) {
	log, err := ParseJobLog(res, i)
	if err != nil {
		r.Errorf("%s (job %s): %v", what, jid, err)
		return
	}
	got := map[string]StepCompletion{}
	for _, s := range log.Steps {
		got[s.ID] = s
	}
	changed := false
	for _, id := range steps {
		s, ok := got[id]
		if !ok {
			r.Errorf("%s (job %s): step %q is not in the sprout's job log", what, jid, id)
			continue
		}
		if s.CompletionStatus != StatusCompleted {
			r.Errorf("%s (job %s): step %q is %s: %s", what, jid, id, statusName(s.CompletionStatus), s.errText())
		}
		if s.ChangesMade {
			changed = true
			if wantNone {
				r.Errorf("%s (job %s): step %q reported a change, but the first real cook already made it: not idempotent (changes: %s)", what, jid, id, clip(strings.Join(s.Changes, "; "), 300))
			}
		}
	}
	if wantChange && !changed {
		r.Errorf("%s (job %s): no step reported a change, though the out of band check failed before it", what, jid)
	}
}

// Step completion statuses (internal/cook's CompletionStatus).
const (
	StatusNotStarted = 0
	StatusInProgress = 1
	StatusCompleted  = 2
	StatusFailed     = 3
	StatusSkipped    = 4
)

func statusName(s int) string {
	switch s {
	case StatusNotStarted:
		return "not started"
	case StatusInProgress:
		return "in progress"
	case StatusCompleted:
		return "completed"
	case StatusFailed:
		return "failed"
	case StatusSkipped:
		return "skipped"
	}
	return fmt.Sprintf("status %d", s)
}

// StepCompletion is one line of a sprout's job log (internal/cook's
// StepCompletion as it marshals).
type StepCompletion struct {
	ID               string   `json:"ID"`
	CompletionStatus int      `json:"CompletionStatus"`
	ChangesMade      bool     `json:"ChangesMade"`
	Changes          []string `json:"Changes"`
	Error            *string  `json:"Error"`
}

// JobLog is a job's step completions, without the start/completed markers.
type JobLog struct {
	Steps []StepCompletion
}

// errNoJobLog says a job log the host didn't have.
const errNoJobLog = "the sprout has no job log for it under its joblogdir"

// ParseJobLog reads the i-th job log a HostCall printed.
func ParseJobLog(res *harness.RunResult, i int) (*JobLog, error) {
	v, ok := res.Value(fmt.Sprintf("JOBLOG_%d", i))
	if !ok {
		return nil, fmt.Errorf("the host script printed no JOBLOG_%d line: %s", i, clip(res.Output, 300))
	}
	if v == "MISSING" {
		dir, _ := res.Value("JOBLOGDIR")
		return nil, fmt.Errorf("%s (%s), so the change and idempotency results can't be read", errNoJobLog, dir)
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("job log is not base64: %w", err)
	}
	log := &JobLog{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s StepCompletion
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			return nil, fmt.Errorf("job log line is not a step completion: %w", err)
		}
		if strings.HasPrefix(s.ID, "start-") || strings.HasPrefix(s.ID, "completed-") || strings.HasPrefix(s.ID, "timeout-") {
			continue
		}
		log.Steps = append(log.Steps, s)
	}
	return log, sc.Err()
}

func (s StepCompletion) errText() string {
	if s.Error == nil {
		return ""
	}
	return *s.Error
}

var jidRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// ScriptCall wraps a case script so that it runs in a child shell (sh on
// Linux, powershell.exe -File on Windows), and prints its exit status and
// output as values named <key>_RC and <key>_OUT (base64). The script is
// passed base64-encoded, so no quoting of its text matters.
func ScriptCall(sp harness.Sprout, script, key string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	if sp.IsWindows() {
		return fmt.Sprintf(`$__f = Join-Path $env:TEMP ('imas-uat-' + [guid]::NewGuid().ToString('N') + '.ps1')
[IO.File]::WriteAllText($__f, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%[1]s')))
$__o = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $__f 2>&1 | Out-String
$__rc = $LASTEXITCODE
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $__f
Write-Output ('__IMAS_UAT_%[2]s_RC=' + $__rc)
Write-Output ('__IMAS_UAT_%[2]s_OUT=' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$__o)))
$global:LASTEXITCODE = 0`, b64, key)
	}
	return fmt.Sprintf(`__f=$(mktemp /tmp/imas-uat-XXXXXXXX)
printf '%%s' '%[1]s' | base64 -d > "$__f"
__o=$(sh "$__f" 2>&1)
__rc=$?
rm -f "$__f"
echo "__IMAS_UAT_%[2]s_RC=$__rc"
echo "__IMAS_UAT_%[2]s_OUT=$(printf '%%s' "$__o" | base64 | tr -d '\n')"
true`, b64, key)
}

// HostCall runs the check (if any) as CHECK and prints the sprout's job
// logs of the jids as JOBLOG_<i> (base64 of the .jsonl, or MISSING), in
// one vmctl.sh call: a call through the Azure control plane takes tens of
// seconds.
func HostCall(sp harness.Sprout, check string, jids []string) string {
	var b strings.Builder
	if check != "" {
		b.WriteString(ScriptCall(sp, check, "CHECK"))
		b.WriteString("\n")
	}
	if sp.IsWindows() {
		b.WriteString(`$__d = Join-Path $env:ProgramData 'imas\cache\sprout\jobs'
$__cfg = Join-Path $env:ProgramData 'imas\sprout'
$__m = Select-String -LiteralPath $__cfg -Pattern '^joblogdir:\s*(.+)$' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($__m) { $__d = $__m.Matches[0].Groups[1].Value.Trim().Trim('"', "'") }
Write-Output ('__IMAS_UAT_JOBLOGDIR=' + $__d)
`)
		for i, j := range jids {
			if !jidRe.MatchString(j) {
				fmt.Fprintf(&b, "Write-Output '__IMAS_UAT_JOBLOG_%d=MISSING'\n", i)
				continue
			}
			fmt.Fprintf(&b, `$__p = Join-Path $__d '%[2]s.jsonl'
if (Test-Path -LiteralPath $__p) { Write-Output ('__IMAS_UAT_JOBLOG_%[1]d=' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($__p))) } else { Write-Output '__IMAS_UAT_JOBLOG_%[1]d=MISSING' }
`, i, j)
		}
		b.WriteString("$global:LASTEXITCODE = 0\n")
		return b.String()
	}
	fmt.Fprintf(&b, `__d=$(sed -n 's/^joblogdir:[[:space:]]*//p' %s 2>/dev/null | tr -d "\"'" | head -n1)
[ -n "$__d" ] || __d=/var/cache/imas/sprout/jobs
echo "__IMAS_UAT_JOBLOGDIR=$__d"
`, harness.LinuxSproutConfig)
	for i, j := range jids {
		if !jidRe.MatchString(j) {
			fmt.Fprintf(&b, "echo '__IMAS_UAT_JOBLOG_%d=MISSING'\n", i)
			continue
		}
		fmt.Fprintf(&b, `if [ -r "$__d/%[2]s.jsonl" ]; then echo "__IMAS_UAT_JOBLOG_%[1]d=$(base64 < "$__d/%[2]s.jsonl" | tr -d '\n')"; else echo "__IMAS_UAT_JOBLOG_%[1]d=MISSING"; fi
`, i, j)
	}
	b.WriteString("true\n")
	return b.String()
}

// scriptResult reads <key>_RC and <key>_OUT; a missing RC is -1.
func scriptResult(res *harness.RunResult, key string) (int, string) {
	rc := -1
	if v, ok := res.Value(key + "_RC"); ok {
		fmt.Sscan(v, &rc)
	}
	out := ""
	if v, ok := res.Value(key + "_OUT"); ok {
		if b, err := base64.StdEncoding.DecodeString(v); err == nil {
			out = strings.TrimSpace(string(b))
		}
	}
	if rc == -1 && out == "" {
		out = "the script printed no result: " + clip(res.Output, 300)
	}
	return rc, out
}

func itemOrErr(it harness.Item, err error) string {
	if err != nil {
		return err.Error()
	}
	return it.String()
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	if s == "" {
		return "(no output)"
	}
	return s
}
