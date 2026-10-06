package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ev builds test2json events: action, test name, and output for "output".
func ev(pkg string, lines ...string) []Event {
	var out []Event
	for _, l := range lines {
		parts := strings.SplitN(l, " ", 3)
		e := Event{Action: parts[0], Package: pkg}
		if len(parts) > 1 && parts[1] != "-" {
			e.Test = parts[1]
		}
		if len(parts) > 2 {
			e.Output = parts[2] + "\n"
		}
		out = append(out, e)
	}
	return out
}

func summarize(t *testing.T, tier string, ids []string, events []Event) *Report {
	t.Helper()
	cat := loadCat(t)
	sel, err := cat.Select(tier, ids)
	if err != nil {
		t.Fatal(err)
	}
	return Summarize(cat, sel, events)
}

func lineFor(r *Report, id, osName, tenant string) (Line, bool) {
	for _, l := range r.Lines {
		if l.ID == id && l.OS == osName && l.Tenant == tenant {
			return l, true
		}
	}
	return Line{}, false
}

const pkg = "github.com/yogzblr/imas/uat/tests"

func smokeEvents() []Event {
	return ev(pkg,
		"run TestSmokeT1_CreateTenant",
		"output TestSmokeT1_CreateTenant     tenants_test.go:22: [T1 step=POST /v1/tenants]",
		"pass TestSmokeT1_CreateTenant",
		"run TestSmokeK1_MintKey",
		"pass TestSmokeK1_MintKey",
		"run TestSmokeS1_SproutEnrolledThroughEnvoy",
		"run TestSmokeS1_SproutEnrolledThroughEnvoy/t1-ubuntu",
		"run TestSmokeS1_SproutEnrolledThroughEnvoy/t2-windows.t2-win",
		"output TestSmokeS1_SproutEnrolledThroughEnvoy/t2-windows.t2-win     sprouts_test.go:30: [S1 os=windows tenant=2 vm=t2-win step=x]",
		"output TestSmokeS1_SproutEnrolledThroughEnvoy/t2-windows.t2-win     sprouts_test.go:31: [S1 os=windows tenant=2 vm=t2-win step=x] FAIL: imas-sprout is not installed",
		"output TestSmokeS1_SproutEnrolledThroughEnvoy/t2-windows.t2-win --- FAIL: TestSmokeS1_SproutEnrolledThroughEnvoy/t2-windows.t2-win (1.00s)",
		"pass TestSmokeS1_SproutEnrolledThroughEnvoy/t1-ubuntu",
		"fail TestSmokeS1_SproutEnrolledThroughEnvoy/t2-windows.t2-win",
		"fail TestSmokeS1_SproutEnrolledThroughEnvoy",
		"run TestSmokeC1_CmdRunEverySprout",
		"run TestSmokeC1_CmdRunEverySprout/t1",
		"run TestSmokeC1_CmdRunEverySprout/t1/t1-ubuntu",
		"output TestSmokeC1_CmdRunEverySprout/t1/t1-ubuntu     cmd_test.go:9: [C1 os=ubuntu tenant=1 vm=t1-ubuntu] SKIP: no reason to run",
		"skip TestSmokeC1_CmdRunEverySprout/t1/t1-ubuntu",
		"pass TestSmokeC1_CmdRunEverySprout/t1",
		"pass TestSmokeC1_CmdRunEverySprout",
		"fail -",
	)
}

func TestSummarizeLines(t *testing.T) {
	r := summarize(t, "smoke", nil, smokeEvents())
	if !r.Failed() {
		t.Error("a failed sprout must fail the run")
	}
	if l, ok := lineFor(r, "S1", "windows", "2"); !ok || l.Status != "FAIL" || !strings.Contains(l.Detail, "FAIL: imas-sprout is not installed") || !strings.Contains(l.Detail, "[S1 os=windows") {
		t.Errorf("S1 windows 2: %+v %v", l, ok)
	}
	if l, ok := lineFor(r, "S1", "ubuntu", "1"); !ok || l.Status != "PASS" {
		t.Errorf("S1 ubuntu 1: %+v", l)
	}
	if l, ok := lineFor(r, "C1", "ubuntu", "1"); !ok || l.Status != "SKIP" || l.Detail != "no reason to run" {
		t.Errorf("C1: %+v", l)
	}
	if l, ok := lineFor(r, "T1", "-", "-"); !ok || l.Status != "PASS" {
		t.Errorf("T1: %+v", l)
	}
	if len(r.Missing) != 0 || len(r.PackageErrors) != 0 || r.NoTests || r.TopLevelRun != 4 {
		t.Errorf("missing %v pkg %v notests %v top %d", r.Missing, r.PackageErrors, r.NoTests, r.TopLevelRun)
	}
	// The catalogue order: T1, K1, S1, C1.
	var order []string
	for _, l := range r.Lines {
		if len(order) == 0 || order[len(order)-1] != l.ID {
			order = append(order, l.ID)
		}
	}
	if strings.Join(order, " ") != "T1 K1 S1 C1" {
		t.Errorf("order %v", order)
	}
	var out bytes.Buffer
	r.Print(&out)
	for _, want := range []string{"RESULT: FAIL", "C1 os=ubuntu tenant=1: no reason to run", "FAIL   S1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the summary lacks %q:\n%s", want, out.String())
		}
	}
}

func TestNoSilentGreen(t *testing.T) {
	t.Run("nothing ran", func(t *testing.T) {
		r := summarize(t, "core", nil, ev(pkg, "output - uat: IMAS_UAT_DIR is not set", "fail -"))
		if !r.Failed() || !r.NoTests || len(r.Missing) != 35 || len(r.PackageErrors) != 1 || !strings.Contains(r.PackageErrors[0], "IMAS_UAT_DIR") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("a scenario missing", func(t *testing.T) {
		evs := smokeEvents()[:5] // T1 and K1 only, both passing
		r := summarize(t, "smoke", nil, evs)
		if !r.Failed() || len(r.Missing) != 2 || !strings.HasPrefix(r.Missing[0], "S1") {
			t.Errorf("missing %v", r.Missing)
		}
	})
	t.Run("a skip without a reason", func(t *testing.T) {
		r := summarize(t, "core", []string{"X5"}, ev(pkg,
			"run TestCoreX5_SproutRefusesPlaintext",
			"output TestCoreX5_SproutRefusesPlaintext --- SKIP: TestCoreX5_SproutRefusesPlaintext (0.00s)",
			"skip TestCoreX5_SproutRefusesPlaintext"))
		if !r.Failed() || len(r.Unreasoned) != 1 {
			t.Errorf("unreasoned %v", r.Unreasoned)
		}
	})
	t.Run("a skip with a reason passes", func(t *testing.T) {
		r := summarize(t, "core", []string{"X5"}, ev(pkg,
			"run TestCoreX5_SproutRefusesPlaintext",
			"output TestCoreX5_SproutRefusesPlaintext     security_test.go:1: [X5] SKIP: the bus is out of reach",
			"skip TestCoreX5_SproutRefusesPlaintext"))
		if r.Failed() {
			t.Errorf("%+v", r)
		}
		var out bytes.Buffer
		r.Print(&out)
		if !strings.Contains(out.String(), "X5 os=- tenant=-: the bus is out of reach") || !strings.Contains(out.String(), "RESULT: PASS") {
			t.Error(out.String())
		}
	})
	t.Run("a plain t.Skip reason counts", func(t *testing.T) {
		r := summarize(t, "core", []string{"X5"}, ev(pkg,
			"run TestCoreX5_SproutRefusesPlaintext",
			"output TestCoreX5_SproutRefusesPlaintext     security_test.go:1: no bus",
			"skip TestCoreX5_SproutRefusesPlaintext"))
		if r.Failed() || r.Lines[0].Detail != "no bus" {
			t.Errorf("%+v", r.Lines)
		}
	})
	t.Run("a test that never finished", func(t *testing.T) {
		r := summarize(t, "core", []string{"C3"}, ev(pkg,
			"run TestCoreC3_TimeoutHonoured",
			"output TestCoreC3_TimeoutHonoured panic: test timed out after 4h0m0s",
			"fail -"))
		if !r.Failed() || len(r.Unfinished) != 1 || r.Lines[0].Status != "FAIL" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("a parent failing on its own", func(t *testing.T) {
		r := summarize(t, "core", []string{"C7"}, ev(pkg,
			"run TestCoreC7_BatchPerItemResults",
			"run TestCoreC7_BatchPerItemResults/t1",
			"pass TestCoreC7_BatchPerItemResults/t1",
			"output TestCoreC7_BatchPerItemResults     cmd_test.go:1: [C7] FAIL: after the subtests",
			"fail TestCoreC7_BatchPerItemResults",
			"fail -"))
		if l, ok := lineFor(r, "C7", "-", "-"); !ok || l.Status != "FAIL" {
			t.Errorf("%+v", r.Lines)
		}
		if len(r.PackageErrors) != 0 {
			t.Errorf("a package fail with a failed test is not a package error: %v", r.PackageErrors)
		}
	})
	t.Run("output that isn't JSON", func(t *testing.T) {
		evs, err := ReadEvents(strings.NewReader("# github.com/x\n./a.go:1: undefined: y\n" + `{"Action":"run","Package":"p","Test":"TestCoreC2_X"}` + "\n"))
		if err != nil || len(evs) != 3 {
			t.Fatalf("%v %v", evs, err)
		}
		r := summarize(t, "core", []string{"C2"}, evs)
		if !r.Failed() || len(r.PackageErrors) != 1 || !strings.Contains(r.PackageErrors[0], "undefined: y") {
			t.Errorf("%+v", r.PackageErrors)
		}
	})
	t.Run("tests of another tier don't count", func(t *testing.T) {
		r := summarize(t, "resilience", nil, ev(pkg, "run TestCoreC2_X", "pass TestCoreC2_X"))
		if !r.NoTests || !r.Failed() {
			t.Errorf("%+v", r)
		}
	})
}

func TestIngredientLines(t *testing.T) {
	evs := ev(pkg+"/ingredients",
		"run TestIngredients",
		"run TestIngredients/I.file.managed",
		"run TestIngredients/I.file.managed/t1-ubuntu",
		"pass TestIngredients/I.file.managed/t1-ubuntu",
		"run TestIngredients/I.winappx.present",
		"run TestIngredients/I.winappx.present/t1-win",
		"output TestIngredients/I.winappx.present/t1-win     runner_test.go:5: Windows Server Core has no appx",
		"skip TestIngredients/I.winappx.present/t1-win",
		"pass TestIngredients/I.winappx.present",
		"pass TestIngredients/I.file.managed",
		"pass TestIngredients",
		"run TestIngredientsCoverage",
		"pass TestIngredientsCoverage",
	)
	r := summarize(t, "ingredients", nil, evs)
	if r.Failed() {
		t.Errorf("%+v", r)
	}
	if l, ok := lineFor(r, "I.file.managed", "ubuntu", "1"); !ok || l.Status != "PASS" {
		t.Errorf("%+v", r.Lines)
	}
	if l, ok := lineFor(r, "I.winappx.present", "windows", "1"); !ok || l.Status != "SKIP" {
		t.Errorf("%+v", r.Lines)
	}
	if _, ok := lineFor(r, "IngredientsCoverage", "-", "-"); !ok {
		t.Errorf("coverage line: %+v", r.Lines)
	}
	r = summarize(t, "ingredients", []string{"I.file.managed", "I.cmd.run"}, evs)
	if !r.Failed() || len(r.Missing) != 1 || !strings.HasPrefix(r.Missing[0], "I.cmd.run") {
		t.Errorf("missing %v", r.Missing)
	}
	r = summarize(t, "ingredients", nil, nil)
	if !r.Failed() || len(r.Missing) != 1 || !strings.Contains(r.Missing[0], "UAT.7") {
		t.Errorf("no ingredient tests: %v", r.Missing)
	}
}

func TestPlaceOf(t *testing.T) {
	for name, want := range map[string][2]string{
		"TestCoreC1_X":                         {"-", "-"},
		"TestCoreC1_X/t2":                      {"-", "2"},
		"TestCoreC1_X/t1/t1-ubuntu":            {"ubuntu", "1"},
		"TestCoreC1_X/t2-windows.t2-win":       {"windows", "2"},
		"TestCoreC4_X/t1_shell_syntax":         {"-", "1"},
		"TestCoreS2_X/alma":                    {"alma", "-"},
		"TestCoreX1_X/no_token":                {"-", "-"},
		"TestCoreX4_X/t2_on_other":             {"-", "2"},
		"TestIngredients/I.file.managed/x":     {"-", "-"},
		"TestIngredients/ubuntu_t2/I.pkg.a":    {"ubuntu", "2"},
		"TestT1Ubuntu/t1-ubuntu-but-renamed-x": {"ubuntu", "1"},
	} {
		o, tn := placeOf(name)
		if o != want[0] || tn != want[1] {
			t.Errorf("%s: %s %s, want %v", name, o, tn, want)
		}
	}
}

func TestJUnit(t *testing.T) {
	r := summarize(t, "smoke", nil, smokeEvents()[:5])
	var buf bytes.Buffer
	if err := r.WriteJUnit(&buf); err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	s := doc.Suites[0]
	if s.Tests != 4 || s.Failures != 2 || s.Name != "imas-uat-smoke" {
		t.Errorf("suite %+v", s)
	}
}

func TestRunCommand(t *testing.T) {
	catalogue := filepath.Join("..", "catalogue.tsv")
	var out, errOut bytes.Buffer
	if code := run([]string{"pattern", "-catalogue", catalogue, "-tier", "core", "C2"}, nil, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "^Test(?:CoreC2)_" {
		t.Errorf("pattern: %d %q %q", code, out.String(), errOut.String())
	}
	if code := run([]string{"pattern", "-catalogue", catalogue, "-tier", "core", "L1"}, nil, &out, &errOut); code != 2 {
		t.Errorf("an id of another tier: %d", code)
	}
	if code := run(nil, nil, &out, &errOut); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code := run([]string{"frobnicate", "-catalogue", catalogue, "-tier", "core"}, nil, &out, &errOut); code != 2 {
		t.Errorf("unknown command: %d", code)
	}

	var events bytes.Buffer
	enc := json.NewEncoder(&events)
	for _, e := range smokeEvents() {
		_ = enc.Encode(e)
	}
	junit := filepath.Join(t.TempDir(), "junit.xml")
	out.Reset()
	code := run([]string{"summarize", "-catalogue", catalogue, "-tier", "smoke", "-junit", junit}, bytes.NewReader(events.Bytes()), &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "RESULT: FAIL") {
		t.Errorf("summarize: %d\n%s", code, out.String())
	}
	if b, err := os.ReadFile(junit); err != nil || !bytes.Contains(b, []byte("<testsuites>")) {
		t.Errorf("junit %v", err)
	}
	out.Reset()
	if code := run([]string{"follow"}, strings.NewReader(`{"Action":"output","Output":"hello\n"}`+"\nnot json\n"), &out, &errOut); code != 0 || out.String() != "hello\nnot json\n" {
		t.Errorf("follow: %q", out.String())
	}
}

// TestRunShAgainstFakeStack runs uat/tests/run.sh for real (build, test
// binary, report) against the fake stack, for the smoke tier and one
// scenario of the resilience tier. It builds the uat-tagged test binary,
// so it takes a while; -short skips it.
func TestRunShAgainstFakeStack(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if runtime.GOOS == "windows" {
		t.Skip("run.sh is a bash script for the Linux runner")
	}
	for _, tool := range []string{"bash", "curl", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	bin := filepath.Join(t.TempDir(), "fakestack")
	build := exec.Command("go", "build", "-o", bin, "./uat/tests/fakestack")
	build.Dir = filepath.Join("..", "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the fake stack: %v\n%s", err, out)
	}
	// startFake serves a fake stack whose material is in the given layout
	// and returns its directory once every file is written.
	startFake := func(layout string, ready ...string) string {
		dir := t.TempDir()
		fake := exec.Command(bin, "-dir", dir, "-layout", layout)
		if err := fake.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fake.Process.Kill(); _ = fake.Wait() })
		deadline := time.Now().Add(3 * time.Minute)
		for _, f := range ready {
			for {
				if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the fake stack (%s) didn't start", layout)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		return dir
	}
	runSh := func(dir string, args ...string) (int, string) {
		cmd := exec.Command("bash", append([]string{filepath.Join("..", "run.sh")}, args...)...)
		cmd.Env = append(os.Environ(), "IMAS_UAT_DIR="+dir, "IMAS_UAT_REPORT_DIR="+filepath.Join(dir, "report-"+args[0]),
			"IMAS_UAT_VMCTL=", "IMAS_UAT_BIND_TENANT=", "IMAS_UAT_CORE_KUBECONFIG=", "IMAS_UAT_ENDPOINTS=")
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, string(out)
	}
	dir := startFake("flat", ".ready")
	if code, out := runSh(dir, "smoke"); code != 0 || !strings.Contains(out, "RESULT: PASS") || !strings.Contains(out, "PASS   C1                     windows  2") {
		t.Errorf("smoke against the fake: exit %d\n%s", code, out)
	}
	if code, out := runSh(dir, "resilience", "L2"); code != 0 || !strings.Contains(out, "PASS   L2") {
		t.Errorf("L2 against the fake: exit %d\n%s", code, out)
	}
	if code, out := runSh(dir, "lifecycle"); code != 1 || !strings.Contains(out, "NO TEST MATCHED") || !strings.Contains(out, "MISS   L4") {
		t.Errorf("lifecycle has no tests yet and must fail: exit %d\n%s", code, out)
	}
	if code, _ := runSh(dir, "core", "Q7"); code != 2 {
		t.Errorf("an unknown id must be a usage error: %d", code)
	}

	// uat/hub/core's layout (core.json, credentials.json and keycloak.json,
	// no Keycloak admin): smoke passes, T1 getting the user for the tenant
	// it creates from the fake bind-tenant.sh --scratch-user.
	core := startFake("core", ".ready")
	code, out := runSh(core, "smoke")
	if code != 0 || !strings.Contains(out, "RESULT: PASS") || !strings.Contains(out, "PASS   K1") ||
		!strings.Contains(out, "PASS   T1") || strings.Contains(out, "SKIP   T1") {
		t.Errorf("smoke against the fake in the core layout: exit %d\n%s", code, out)
	}
}
