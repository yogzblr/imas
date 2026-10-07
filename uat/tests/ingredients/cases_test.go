package ingredients

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/uat/tests/harness"
)

const goodCase = `id: I.file.content
title: write a file
os: [ubuntu, windows]
skip_os:
  alma: not today
tenant2: true
linux:
  setup: echo setup
  recipe: |
    steps:
      s:
        file.content:
          - name: /var/tmp/x-@NONCE@
          - text: ['hi']
  check: test -f /var/tmp/x-@NONCE@
  revert: rm -f /var/tmp/x-@NONCE@
ubuntu:
  check: test -s /var/tmp/x-@NONCE@
windows:
  recipe: |
    steps:
      s:
        file.content:
          - name: '@TMP@\x-@NONCE@'
  check: exit 0
`

func TestParseCase(t *testing.T) {
	c, err := ParseCase([]byte(goodCase), "file/content.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Ingredient() != "file" || c.Method() != "content" || !c.Tenant2 || c.OrderKey() != DefaultOrder || c.Pre() != PreAbsent {
		t.Errorf("parsed %+v", c)
	}
	if !c.WantChanges() || !c.WantIdempotent() || c.CookTimeout() != DefaultCookTimeout {
		t.Errorf("defaults wrong")
	}
	if ok, _ := c.Runs("ubuntu"); !ok {
		t.Error("runs on ubuntu")
	}
	if ok, why := c.Runs("alma"); ok || why != "not today" {
		t.Errorf("alma: %v %q", ok, why)
	}
	if p := c.For("ubuntu"); p.Check != "test -s /var/tmp/x-@NONCE@" || p.Setup != "echo setup" {
		t.Errorf("ubuntu part should take its own check and the family's setup: %+v", p)
	}
	v := Vars{"@NONCE@": "abc", "@TMP@": `C:\Windows\Temp`}
	if got := c.For("windows").Expand(v).Recipe; !strings.Contains(got, `C:\Windows\Temp\x-abc`) {
		t.Errorf("expanded recipe %q", got)
	}
}

func TestParseCaseRejects(t *testing.T) {
	for name, tc := range map[string]struct{ text, file, want string }{
		"bad id":        {"id: I.File.x\nos: [ubuntu]\n", "", "not I.<ingredient>.<method>"},
		"unknown field": {"id: I.a.b\nos: [ubuntu]\nfoo: 1\n", "", "field foo not found"},
		"wrong file":    {"id: I.a.b\nskip: x\n", "a/c.yaml", "should be a/b.yaml"},
		"no os":         {"id: I.a.b\n", "", "neither os"},
		"bad os":        {"id: I.a.b\nos: [debian]\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}', check: x}\n", "", "not one of"},
		"os and skip":   {"id: I.a.b\nos: [ubuntu]\nskip_os: {ubuntu: x}\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}', check: x}\n", "", "both in os and in skip_os"},
		"empty reason":  {"id: I.a.b\nskip_os: {alma: ' '}\n", "", "has no reason"},
		"no recipe":     {"id: I.a.b\nos: [alma]\nlinux: {check: x}\n", "", "alma: no recipe"},
		"no check":      {"id: I.a.b\nos: [alma]\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}'}\n", "", "alma: no check"},
		"template":      {"id: I.a.b\nos: [alma]\nlinux: {recipe: 'steps: {s: {a.b: [{name: \"{{ x }}\"}]}}', check: x}\n", "", "template"},
		"placeholder":   {"id: I.a.b\nos: [alma]\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}', check: '@WHAT@'}\n", "", "unknown placeholder @WHAT@"},
		"bad recipe":    {"id: I.a.b\nos: [alma]\nlinux: {recipe: 'steps: {s: {a.b: c}}', check: x}\n", "", "list of properties"},
		"reboot early":  {"id: I.a.b\nos: [alma]\nneeds: [reboot]\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}', check: x}\n", "", "ordered last"},
		"pre_check":     {"id: I.a.b\nos: [alma]\npre_check: maybe\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}', check: x}\n", "", "pre_check"},
		"timeout":       {"id: I.a.b\nos: [alma]\ntimeout: soon\nlinux: {recipe: 'steps: {s: {a.b: [{name: x}]}}', check: x}\n", "", "timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCase([]byte(tc.text), tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRecipeSteps(t *testing.T) {
	ids, err := RecipeSteps("steps:\n  b: {x.y: [{name: n}]}\n  a: {x.z: []}\n")
	if err != nil || strings.Join(ids, ",") != "a,b" {
		t.Fatalf("%v %v", ids, err)
	}
	for _, bad := range []string{"nope: 1", "steps: [1]", "steps: {a: {x.y: [], x.z: []}}", "steps: {a: {xy: []}}"} {
		if _, err := RecipeSteps(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	ms, _ := StepMethods("steps:\n  b: {x.y: [{name: n}]}\n")
	if strings.Join(ms, ",") != "x.y" {
		t.Errorf("step methods %v", ms)
	}
}

func TestLoadCasesOrderAndDuplicates(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a/b.yaml":  "id: I.a.b\nskip: x\n",
		"a/c.yaml":  "id: I.a.c\nskip: x\norder: 50\n",
		"z/z.yaml":  "id: I.z.z\nskip: x\nneeds: [reboot]\norder: 950\n",
		"README.md": "not a case",
	})
	cases, err := LoadCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range cases {
		ids = append(ids, c.ID)
	}
	if strings.Join(ids, " ") != "I.a.c I.a.b I.z.z" {
		t.Errorf("order: %v", ids)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "d.yaml"), []byte("id: I.a.b\nskip: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The id decides the file name, so a second file with the same id is
	// always misnamed.
	if _, err := LoadCases(dir); err == nil || !strings.Contains(err.Error(), "a/d.yaml: the file should be a/b.yaml") {
		t.Errorf("a duplicate id in another file should be refused, got %v", err)
	}
}

// TestCasesOfThisRepository loads every case under uat/cases.
func TestCasesOfThisRepository(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCases(CasesDir(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 100 {
		t.Errorf("only %d cases", len(cases))
	}
	tenant2 := 0
	for _, c := range cases {
		if c.Tenant2 {
			tenant2++
			for _, os := range c.OS {
				p := c.For(os)
				if !strings.Contains(p.Check, "@NONCE@") {
					t.Errorf("%s is in the tenant 2 subset, but its %s check doesn't depend on the nonce, so the cross-tenant check can't tell the tenants apart", c.ID, os)
				}
			}
		}
		if c.Skip == "" {
			for _, os := range c.OS {
				// Every placeholder must expand; the recipes must stay valid.
				sp := harness.Sprout{OS: os, Tenant: 1, VM: "t1-" + os, SproutID: "x-01"}
				p := c.For(os).Expand(NewVars(c, sp, "abcd1234"))
				for _, s := range []string{p.Setup, p.Recipe, p.Check, p.Revert, p.RevertRecipe} {
					if m := placeholderRe.FindString(s); m != "" {
						t.Errorf("%s on %s: %s left unexpanded", c.ID, os, m)
					}
				}
				if _, err := RecipeSteps(p.Recipe); err != nil {
					t.Errorf("%s on %s: the expanded recipe: %v", c.ID, os, err)
				}
				if len(RecipeName(c, "abcd1234", "revert")) > 255 {
					t.Errorf("%s: recipe name too long", c.ID)
				}
			}
		}
	}
	if tenant2 == 0 || tenant2 > 10 {
		t.Errorf("%d cases in the tenant 2 subset; it should be small but not empty", tenant2)
	}
}
