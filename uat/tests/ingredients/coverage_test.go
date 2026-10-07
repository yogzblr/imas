package ingredients

import (
	"strings"
	"testing"
)

// fakeRegistry is a registry of three methods, one unreachable one and
// one backend.
func fakeRegistry() *Registry {
	r := NewRegistry([]Method{
		{Ingredient: "file", Method: "content", GOOS: []string{GOOSLinux}},
		{Ingredient: "file", Method: "content", GOOS: []string{GOOSWindows}},
		{Ingredient: "cron", Method: "present", GOOS: []string{GOOSLinux}},
		{Ingredient: "win_x", Method: "on", GOOS: []string{GOOSWindows}},
	}, []Backend{{Registry: "sdb", Name: "openbao", GOOS: []string{GOOSLinux}}})
	r.Unreachable = []Method{{Ingredient: "win_y", Method: "off", GOOS: []string{GOOSWindows}, Package: ModulePath + "/internal/ingredients/winy"}}
	return r
}

func mustCase(t *testing.T, text string) *Case {
	t.Helper()
	c, err := ParseCase([]byte(text), "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const recipeOf = "  recipe: 'steps: {s: {%s: [{name: x}]}}'\n  check: x\n"

func caseText(id, osLine, method string, family string) string {
	return "id: " + id + "\n" + osLine + family + ":\n" + strings.Replace(recipeOf, "%s", method, 1)
}

func TestCoverageComplete(t *testing.T) {
	reg := fakeRegistry()
	cases := []*Case{
		mustCase(t, "id: I.file.content\nos: [ubuntu, alma, windows]\nlinux:\n"+strings.Replace(recipeOf, "%s", "file.content", 1)+"windows:\n"+strings.Replace(recipeOf, "%s", "file.content", 1)),
		mustCase(t, caseText("I.cron.present", "os: [ubuntu]\nskip_os: {alma: no cron here}\n", "cron.present", "linux")),
		mustCase(t, "id: I.win_x.on\nskip: needs a feature\n"),
		mustCase(t, "id: I.win_y.off\nskip: not imported by the sprout\n"),
		mustCase(t, "id: I.sdb.openbao\nbackend: sdb:openbao\nskip: unreachable\n"),
	}
	rep := Coverage(reg, cases)
	if err := rep.Err(); err != nil {
		t.Fatalf("complete coverage reported: %v", err)
	}
	if rep.Methods != 3 || rep.Pairs != 6 || rep.Runnable != 4 || rep.Skipped != 2 {
		t.Errorf("counts %+v", rep)
	}
	var skips []string
	for _, s := range rep.Skips {
		skips = append(skips, s.ID+"/"+s.OS+"/"+s.Reason)
	}
	want := "I.cron.present/alma/no cron here I.sdb.openbao/all/unreachable I.win_x.on/all/needs a feature I.win_y.off/all/not imported by the sprout"
	if strings.Join(skips, " ") != want {
		t.Errorf("skips:\n got %v\nwant %s", skips, want)
	}
	if s := rep.String(); !strings.Contains(s, "SKIP    I.cron.present") || !strings.Contains(s, "0 missing") {
		t.Errorf("report text:\n%s", s)
	}
}

func TestCoverageGaps(t *testing.T) {
	reg := fakeRegistry()
	cases := []*Case{
		// file.content lists only ubuntu: alma and windows are gaps.
		mustCase(t, caseText("I.file.content", "os: [ubuntu]\n", "file.content", "linux")),
		// cron.present cooks the wrong method and lists windows.
		mustCase(t, "id: I.cron.present\nos: [ubuntu, alma, windows]\nlinux:\n"+strings.Replace(recipeOf, "%s", "file.content", 1)+"windows:\n"+strings.Replace(recipeOf, "%s", "cron.present", 1)),
		// win_x.on has no case at all; win_y.off is unreachable but not a skip.
		mustCase(t, caseText("I.win_y.off", "os: [windows]\n", "win_y.off", "windows")),
		// a case for nothing registered, and a backend that isn't.
		mustCase(t, "id: I.ghost.boo\nskip: x\n"),
		mustCase(t, "id: I.sdb.vault\nbackend: sdb:vault\nskip: x\n"),
	}
	rep := Coverage(reg, cases)
	err := rep.Err()
	if err == nil {
		t.Fatal("gaps not reported")
	}
	for _, want := range []string{
		"I.file.content on alma: the case neither lists alma",
		"I.file.content on windows: the case neither lists windows",
		"I.win_x.on on windows: no case file win_x/on.yaml",
		"I.cron.present: lists windows, but the method is registered only for ubuntu, alma",
		"I.cron.present on alma: the recipe doesn't use cron.present",
		"I.win_y.off: " + ModulePath + "/internal/ingredients/winy registers it but no sprout imports",
		"I.ghost.boo (): no such registered method",
		"I.sdb.vault: backend sdb:vault is not registered",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

// TestCoverage is the guard of plan section 4h: a registered ingredient
// method on an OS with neither a case nor a written skip fails go test
// ./..., so a new ingredient can't slip in untested. Add a case file under
// uat/cases (README.md there) to fix it.
func TestCoverage(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCases(CasesDir(root))
	if err != nil {
		t.Fatal(err)
	}
	rep := Coverage(reg, cases)
	t.Log("\n" + rep.String())
	if err := rep.Err(); err != nil {
		t.Fatalf("uat/cases doesn't cover the ingredient registry (add a case file or a written skip, see uat/cases/README.md):\n%v", err)
	}
}
