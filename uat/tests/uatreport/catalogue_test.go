package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func loadCat(t *testing.T) *Catalogue {
	t.Helper()
	c, err := LoadCatalogue(filepath.Join("..", "catalogue.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestCatalogueMatchesPlan keeps catalogue.tsv in step with the Scenario
// catalogue table of plan section 4h: same ids, same tiers, same text.
func TestCatalogueMatchesPlan(t *testing.T) {
	cat := loadCat(t)
	f, err := os.Open(filepath.Join("..", "..", "..", "docs", "claude-code-parallel-build-plan.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	row := regexp.MustCompile(`^\| ([A-Z][0-9]+|I\.name\.method) \| (.+) \| ([a-z, ]+) \|$`)
	in := false
	plan := map[string]Scenario{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "### Scenario catalogue") {
			in = true
			continue
		}
		if in && strings.HasPrefix(line, "### ") {
			break
		}
		m := row.FindStringSubmatch(line)
		if !in || m == nil {
			continue
		}
		id := m[1]
		if id == "I.name.method" {
			id = ingredientWildcard
		}
		var tiers []string
		for _, tr := range strings.Split(m[3], ",") {
			tiers = append(tiers, strings.TrimSpace(tr))
		}
		plan[id] = Scenario{ID: id, Tiers: tiers, Title: strings.TrimSpace(m[2])}
	}
	if len(plan) < 40 {
		t.Fatalf("read only %d rows from the plan's Scenario catalogue; has the table moved?", len(plan))
	}
	for id, p := range plan {
		c, ok := cat.Get(id)
		if !ok {
			t.Errorf("the plan has %s, catalogue.tsv doesn't", id)
			continue
		}
		if strings.Join(c.Tiers, ",") != strings.Join(p.Tiers, ",") {
			t.Errorf("%s: tiers %v, the plan says %v", id, c.Tiers, p.Tiers)
		}
		if id != ingredientWildcard && c.Title != p.Title {
			t.Errorf("%s: title %q, the plan says %q", id, c.Title, p.Title)
		}
	}
	for _, s := range cat.Scenarios {
		if _, ok := plan[s.ID]; !ok {
			t.Errorf("catalogue.tsv has %s, the plan doesn't", s.ID)
		}
	}
}

var testFunc = regexp.MustCompile(`(?m)^func (Test(Smoke|Core|Resilience|Ingredients|Lifecycle)([A-Z][0-9]+)?(_\w*)?)\(t \*testing\.T\)`)

// TestEveryScenarioHasATest checks, from the source, that each UAT.5
// scenario has exactly one test function, named with the prefix of its
// first tier and its id, and that no test function claims an id the
// catalogue doesn't have.
func TestEveryScenarioHasATest(t *testing.T) {
	cat := loadCat(t)
	files, err := filepath.Glob(filepath.Join("..", "*_test.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no test files under uat/tests: %v", err)
	}
	found := map[string][]string{}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range testFunc.FindAllStringSubmatch(string(b), -1) {
			name, prefix, id := m[1], m[2], m[3]
			if id == "" {
				t.Errorf("%s: %s has a tier prefix but no scenario id", file, name)
				continue
			}
			s, ok := cat.Get(id)
			if !ok {
				t.Errorf("%s: %s names %s, which isn't in the catalogue", file, name, id)
				continue
			}
			if s.Prefix() != prefix {
				t.Errorf("%s: %s should be Test%s%s_...", file, name, s.Prefix(), id)
			}
			found[id] = append(found[id], name)
		}
	}
	for _, s := range cat.Scenarios {
		if s.Owner != "UAT.5" {
			continue
		}
		switch len(found[s.ID]) {
		case 0:
			t.Errorf("%s (%s) has no test function", s.ID, s.Title)
		case 1:
		default:
			t.Errorf("%s has several test functions: %v", s.ID, found[s.ID])
		}
	}
}

func TestReadCatalogueErrors(t *testing.T) {
	for _, bad := range []string{
		"T1\tsmoke\tx",
		"T1\tsmoky\tx\tUAT.5",
		"t1\tsmoke\tx\tUAT.5",
		"T1\tsmoke\tx\tUAT.5\nT1\tcore\ty\tUAT.5",
	} {
		if _, err := ReadCatalogue(strings.NewReader(bad)); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// matches is go test -run's matching: the pattern split on slashes, one
// part per level of the test name; levels beyond the pattern match.
func matches(t *testing.T, pattern, name string) bool {
	t.Helper()
	pats := strings.Split(pattern, "/")
	parts := strings.Split(name, "/")
	for i, p := range pats {
		if i >= len(parts) {
			return true
		}
		if !regexp.MustCompile(p).MatchString(parts[i]) {
			return false
		}
	}
	return true
}

func TestRunPatterns(t *testing.T) {
	cat := loadCat(t)
	names := []string{
		"TestSmokeT1_CreateTenant", "TestCoreT2_TenantValidation", "TestCoreC2_NonZeroExit",
		"TestCoreC20_Imaginary", "TestResilienceL1_RebootSurvived", "TestLifecycleL4_Upgrade",
		"TestIngredients", "TestIngredients/I.file.managed/t1-ubuntu", "TestIngredients/I.file.managed_x",
		"TestIngredientsCoverage", "TestHarnessUnit",
	}
	for _, c := range []struct {
		tier string
		ids  []string
		want []string
	}{
		{"smoke", nil, []string{"TestSmokeT1_CreateTenant"}},
		{"core", nil, []string{"TestSmokeT1_CreateTenant", "TestCoreT2_TenantValidation", "TestCoreC2_NonZeroExit", "TestCoreC20_Imaginary"}},
		{"resilience", nil, []string{"TestResilienceL1_RebootSurvived"}},
		{"lifecycle", nil, []string{"TestLifecycleL4_Upgrade"}},
		{"ingredients", nil, []string{"TestIngredients", "TestIngredients/I.file.managed/t1-ubuntu", "TestIngredients/I.file.managed_x", "TestIngredientsCoverage"}},
		{"core", []string{"C2", "T1"}, []string{"TestSmokeT1_CreateTenant", "TestCoreC2_NonZeroExit"}},
		{"smoke", []string{"T1"}, []string{"TestSmokeT1_CreateTenant"}},
		{"all", []string{"L1"}, []string{"TestResilienceL1_RebootSurvived"}},
		{"ingredients", []string{"I.file.managed"}, []string{"TestIngredients", "TestIngredients/I.file.managed/t1-ubuntu"}},
	} {
		sel, err := cat.Select(c.tier, c.ids)
		if err != nil {
			t.Fatalf("%s %v: %v", c.tier, c.ids, err)
		}
		pat := cat.RunPattern(sel)
		var got []string
		for _, n := range names {
			if matches(t, pat, n) {
				got = append(got, n)
			}
		}
		sort.Strings(got)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s %v: pattern %q matches %v, want %v", c.tier, c.ids, pat, got, want)
		}
	}
	all, _ := cat.Select("all", nil)
	if p := cat.RunPattern(all); p != "^Test(?:Smoke|Core|Resilience|Ingredients|Lifecycle)" {
		t.Errorf("all: %q", p)
	}
}

func TestSelectErrors(t *testing.T) {
	cat := loadCat(t)
	for _, c := range []struct {
		tier string
		ids  []string
	}{
		{"nightly", nil},
		{"smoke", []string{"C2"}},
		{"core", []string{"L1"}},
		{"core", []string{"Z9"}},
		{"core", []string{"I.*"}},
		{"core", []string{"I.file.managed"}},
		{"all", []string{"C2", "I.file.managed"}},
	} {
		if _, err := cat.Select(c.tier, c.ids); err == nil {
			t.Errorf("%s %v should be refused", c.tier, c.ids)
		}
	}
	sel, err := cat.Select("core", []string{"C2", "C2"})
	if err != nil || len(sel.Static) != 1 {
		t.Errorf("a repeated id: %+v %v", sel, err)
	}
	if len(cat.Expected(sel)) != 1 || cat.ExpectsIngredients(sel) {
		t.Error("Expected for one id")
	}
	core, _ := cat.Select("core", nil)
	if n := len(cat.Expected(core)); n != 35 {
		t.Errorf("tier core expects %d scenarios, want 35", n)
	}
	ing, _ := cat.Select("ingredients", nil)
	if !cat.ExpectsIngredients(ing) || len(cat.Expected(ing)) != 0 {
		t.Error("tier ingredients")
	}
	every, _ := cat.Select("all", nil)
	if !cat.ExpectsIngredients(every) || len(cat.Expected(every)) != 40 {
		t.Errorf("tier all expects %d", len(cat.Expected(every)))
	}
}
