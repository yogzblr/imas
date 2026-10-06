package ingredients

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EnvCasesDir overrides where the case files are read from (default
// <repo>/uat/cases).
const EnvCasesDir = "IMAS_UAT_CASES_DIR"

// Pre-check expectations: what the check reports after the first test
// mode cook, before any real cook.
const (
	PreAbsent  = "absent"  // the check fails: the change isn't there yet (the default)
	PrePresent = "present" // the check passes already (assertion methods such as file.exists)
	PreNone    = "none"    // not checked (the state can't be known beforehand)
)

// DefaultOrder is the order of a case that sets none. Cases run in
// (order, id) order on each sprout; anything needing a reboot must be
// ordered at RebootOrder or later.
const (
	DefaultOrder = 100
	RebootOrder  = 900
)

// DefaultCookTimeout bounds one cook of a case.
const DefaultCookTimeout = 6 * time.Minute

// Part is what a case does on one OS family or OS. Scripts are POSIX sh
// (run as root) on Linux and PowerShell (run as SYSTEM, in a child
// powershell.exe -File) on Windows; a script reports failure with a
// non-zero exit status (exit N; on Windows an uncaught error exits 1).
type Part struct {
	// Setup prepares the host before the first cook (a source file, a
	// throwaway service). It must exit 0.
	Setup string `yaml:"setup,omitempty"`
	// Recipe is the recipe uploaded to the tenant and cooked: the steps
	// under test and nothing else.
	Recipe string `yaml:"recipe,omitempty"`
	// Check is the out of band check: exit 0 when the state the recipe
	// asks for is in place.
	Check string `yaml:"check,omitempty"`
	// ExpectOutput, if set, must appear in the check's output when it
	// passes after the real cook.
	ExpectOutput string `yaml:"expect_output,omitempty"`
	// RevertRecipe is cooked (for real) at the end; Revert is a host
	// script run after it. Both run even when the cycle failed.
	RevertRecipe string `yaml:"revert_recipe,omitempty"`
	Revert       string `yaml:"revert,omitempty"`
}

// Case is one ingredient conformance case: uat/cases/<ingredient>/<method>.yaml.
type Case struct {
	// ID is I.<ingredient>.<method>.
	ID    string `yaml:"id"`
	Title string `yaml:"title,omitempty"`
	// OS lists the sprout OSes the case runs on: ubuntu, alma, windows.
	OS []string `yaml:"os,omitempty"`
	// Tenant2 repeats the case on tenant 2's sprouts, and checks the
	// change didn't reach tenant 1's sprout of the same OS (which has the
	// same sproutid).
	Tenant2 bool `yaml:"tenant2,omitempty"`
	// Order sorts cases on a sprout (default 100); RebootOrder and above
	// run last.
	Order int `yaml:"order,omitempty"`
	// Needs names what the case depends on beyond a plain sprout:
	// reboot, internet, openbao, windows-feature:<name>, ...
	Needs []string `yaml:"needs,omitempty"`
	// Skip, when set, is the written reason the whole case doesn't run.
	Skip string `yaml:"skip,omitempty"`
	// SkipOS gives the reason one OS of the method doesn't run the case.
	SkipOS map[string]string `yaml:"skip_os,omitempty"`
	// Changes (default true): the first real cook must report a change.
	Changes *bool `yaml:"changes,omitempty"`
	// Idempotent (default true): the second real cook must report none.
	Idempotent *bool `yaml:"idempotent,omitempty"`
	// PreCheck is absent (default), present or none.
	PreCheck string `yaml:"pre_check,omitempty"`
	// Timeout bounds each cook (a Go duration; default 6m).
	Timeout string `yaml:"timeout,omitempty"`
	// Backend, for a case that covers an entry of the sdb or file source
	// registry rather than a method: "sdb:openbao".
	Backend string `yaml:"backend,omitempty"`
	// Notes is free text: why the change is harmless, what a failure
	// would mean.
	Notes string `yaml:"notes,omitempty"`

	Linux   *Part `yaml:"linux,omitempty"`
	Windows *Part `yaml:"windows,omitempty"`
	Ubuntu  *Part `yaml:"ubuntu,omitempty"`
	Alma    *Part `yaml:"alma,omitempty"`

	// File is where the case was read from.
	File string `yaml:"-"`
}

// KnownOSes are the sprout OSes of the contract, in report order.
var KnownOSes = []string{"ubuntu", "alma", "windows"}

func knownOS(os string) bool {
	for _, k := range KnownOSes {
		if k == os {
			return true
		}
	}
	return false
}

var (
	caseIDRe      = regexp.MustCompile(`^I\.([a-z0-9_]+)\.([a-z0-9_]+)$`)
	needRe        = regexp.MustCompile(`^[a-z0-9-]+(:[A-Za-z0-9_.-]+)?$`)
	placeholderRe = regexp.MustCompile(`@[A-Z0-9_]+@`)
)

// Placeholders a case may use in its scripts and recipes; the runner
// fills them per sprout (see Vars).
var Placeholders = map[string]string{
	"@NONCE@":     "8 random lowercase letters and digits, fresh for every case on every sprout",
	"@TMP@":       "the sprout's temp directory: /var/tmp, or C:\\Windows\\Temp",
	"@SRCTMP@":    "the temp directory as a file source path: /var/tmp, or /Windows/Temp (a path the file ingredient reads as the file protocol on Windows)",
	"@TENANT@":    "the tenant number, 1 or 2",
	"@SPROUT_ID@": "the sprout's ID",
	"@CASE@":      "the case id with dots as dashes (i-file-content)",
}

// Ingredient and Method split the id.
func (c *Case) Ingredient() string { return caseIDRe.FindStringSubmatch(c.ID)[1] }

// Method is the method part of the id.
func (c *Case) Method() string { return caseIDRe.FindStringSubmatch(c.ID)[2] }

// OrderKey is the case's order, defaulted.
func (c *Case) OrderKey() int {
	if c.Order == 0 {
		return DefaultOrder
	}
	return c.Order
}

// WantChanges reports whether the first real cook must report a change.
func (c *Case) WantChanges() bool { return c.Changes == nil || *c.Changes }

// WantIdempotent reports whether the second real cook must report none.
func (c *Case) WantIdempotent() bool { return c.Idempotent == nil || *c.Idempotent }

// Pre is the pre-check expectation, defaulted.
func (c *Case) Pre() string {
	if c.PreCheck == "" {
		return PreAbsent
	}
	return c.PreCheck
}

// CookTimeout is the per-cook timeout, defaulted.
func (c *Case) CookTimeout() time.Duration {
	if d, err := time.ParseDuration(c.Timeout); err == nil && d > 0 {
		return d
	}
	return DefaultCookTimeout
}

// Runs reports whether the case runs on os, and if not, why.
func (c *Case) Runs(os string) (bool, string) {
	if c.Skip != "" {
		return false, c.Skip
	}
	if r, ok := c.SkipOS[os]; ok {
		return false, r
	}
	for _, o := range c.OS {
		if o == os {
			return true, ""
		}
	}
	return false, ""
}

// For returns the case's part for an OS: the OS's own part laid over its
// family's, field by field.
func (c *Case) For(os string) Part {
	var fam, own *Part
	switch os {
	case "windows":
		fam = c.Windows
	case "ubuntu":
		fam, own = c.Linux, c.Ubuntu
	case "alma":
		fam, own = c.Linux, c.Alma
	}
	var p Part
	if fam != nil {
		p = *fam
	}
	if own != nil {
		over := func(dst *string, v string) {
			if v != "" {
				*dst = v
			}
		}
		over(&p.Setup, own.Setup)
		over(&p.Recipe, own.Recipe)
		over(&p.Check, own.Check)
		over(&p.ExpectOutput, own.ExpectOutput)
		over(&p.RevertRecipe, own.RevertRecipe)
		over(&p.Revert, own.Revert)
	}
	return p
}

// Validate checks a case on its own (Coverage checks it against the
// registry).
func (c *Case) Validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if !caseIDRe.MatchString(c.ID) {
		bad("id %q is not I.<ingredient>.<method> (lowercase letters, digits, _)", c.ID)
		return errors.Join(errs...)
	}
	if c.File != "" {
		want := filepath.Join(c.Ingredient(), c.Method()+".yaml")
		if !strings.HasSuffix(filepath.ToSlash(c.File), filepath.ToSlash(want)) {
			bad("the file should be %s", want)
		}
	}
	if c.Skip == "" && len(c.OS) == 0 && len(c.SkipOS) == 0 {
		bad("neither os, skip_os nor skip is set")
	}
	seen := map[string]bool{}
	for _, o := range c.OS {
		if !knownOS(o) {
			bad("os %q is not one of %v", o, KnownOSes)
		}
		if seen[o] {
			bad("os %q listed twice", o)
		}
		seen[o] = true
	}
	for o, r := range c.SkipOS {
		if !knownOS(o) {
			bad("skip_os names %q, not one of %v", o, KnownOSes)
		}
		if strings.TrimSpace(r) == "" {
			bad("skip_os.%s has no reason", o)
		}
		if seen[o] {
			bad("%s is both in os and in skip_os", o)
		}
	}
	switch c.PreCheck {
	case "", PreAbsent, PrePresent, PreNone:
	default:
		bad("pre_check %q is not absent, present or none", c.PreCheck)
	}
	if c.Timeout != "" {
		if d, err := time.ParseDuration(c.Timeout); err != nil || d <= 0 {
			bad("timeout %q is not a positive Go duration", c.Timeout)
		}
	}
	for _, n := range c.Needs {
		if !needRe.MatchString(n) {
			bad("need %q is not a lowercase word with an optional :detail", n)
		}
		if n == "reboot" && c.OrderKey() < RebootOrder && c.Skip == "" {
			bad("a case that needs a reboot must be ordered last (order >= %d)", RebootOrder)
		}
	}
	if c.Backend != "" && !strings.Contains(c.Backend, ":") {
		bad("backend %q is not <registry>:<name>", c.Backend)
	}
	if c.Skip != "" {
		return errors.Join(errs...)
	}
	for _, o := range c.OS {
		p := c.For(o)
		if strings.TrimSpace(p.Recipe) == "" {
			bad("%s: no recipe", o)
		}
		if strings.TrimSpace(p.Check) == "" && c.Pre() != PreNone {
			bad("%s: no check", o)
		}
		if strings.TrimSpace(p.Check) == "" && c.Pre() == PreNone && p.ExpectOutput != "" {
			bad("%s: expect_output without a check", o)
		}
		if strings.Contains(p.Recipe, "{{") || strings.Contains(p.RevertRecipe, "{{") {
			bad("%s: recipes are cooked as written; farmer would render {{ }} as a template", o)
		}
		if p.Recipe != "" {
			if n, err := RecipeSteps(p.Recipe); err != nil {
				bad("%s: recipe: %v", o, err)
			} else if len(n) == 0 {
				bad("%s: the recipe has no steps", o)
			}
		}
		if p.RevertRecipe != "" {
			if _, err := RecipeSteps(p.RevertRecipe); err != nil {
				bad("%s: revert_recipe: %v", o, err)
			}
		}
		for _, s := range []string{p.Setup, p.Recipe, p.Check, p.ExpectOutput, p.RevertRecipe, p.Revert} {
			for _, ph := range placeholderRe.FindAllString(s, -1) {
				if _, ok := Placeholders[ph]; !ok {
					bad("%s: unknown placeholder %s", o, ph)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// RecipeSteps returns the step ids of a recipe, sorted, after checking it
// has the shape farmer reads: steps: {<id>: {<ingredient>.<method>: [ {k: v}, ... ]}}.
func RecipeSteps(recipe string) ([]string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(recipe), &doc); err != nil {
		return nil, err
	}
	raw, ok := doc["steps"]
	if !ok {
		return nil, errors.New("no steps key")
	}
	steps, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("steps is %T, not a map", raw)
	}
	var ids []string
	for id, st := range steps {
		m, ok := st.(map[string]any)
		if !ok || len(m) != 1 {
			return nil, fmt.Errorf("step %q must hold exactly one ingredient.method", id)
		}
		for k, v := range m {
			if strings.Count(k, ".") != 1 {
				return nil, fmt.Errorf("step %q: %q is not ingredient.method", id, k)
			}
			list, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("step %q: %s must hold a list of properties", id, k)
			}
			for _, it := range list {
				if pm, ok := it.(map[string]any); !ok || len(pm) == 0 {
					return nil, fmt.Errorf("step %q: each property of %s must be a one-key map", id, k)
				}
			}
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// StepMethods returns the ingredient.method keys a recipe's steps use.
func StepMethods(recipe string) ([]string, error) {
	var doc struct {
		Steps map[string]map[string]any `yaml:"steps"`
	}
	if err := yaml.Unmarshal([]byte(recipe), &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, st := range doc.Steps {
		for k := range st {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ParseCase decodes one case file strictly (unknown fields are errors).
func ParseCase(b []byte, file string) (*Case, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Case
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	c.File = file
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &c, nil
}

// LoadCases reads every <ingredient>/<method>.yaml under dir, sorted by
// (order, id). Duplicate ids are errors.
func LoadCases(dir string) ([]*Case, error) {
	var cases []*Case
	var errs []error
	ids := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		c, err := ParseCase(b, rel)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if prev, dup := ids[c.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: id %s is also in %s", rel, c.ID, prev))
			return nil
		}
		ids[c.ID] = rel
		cases = append(cases, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	SortCases(cases)
	return cases, nil
}

// SortCases sorts by (order, id).
func SortCases(cases []*Case) {
	sort.SliceStable(cases, func(i, j int) bool {
		if cases[i].OrderKey() != cases[j].OrderKey() {
			return cases[i].OrderKey() < cases[j].OrderKey()
		}
		return cases[i].ID < cases[j].ID
	})
}

// CasesDir is $IMAS_UAT_CASES_DIR, or <root>/uat/cases.
func CasesDir(root string) string {
	if d := os.Getenv(EnvCasesDir); d != "" {
		return d
	}
	return filepath.Join(root, "uat", "cases")
}

// Vars are the placeholder values for one case on one sprout.
type Vars map[string]string

// Expand fills the placeholders of s.
func (v Vars) Expand(s string) string {
	return placeholderRe.ReplaceAllStringFunc(s, func(ph string) string {
		if val, ok := v[ph]; ok {
			return val
		}
		return ph
	})
}

// Expand returns p with every field's placeholders filled.
func (p Part) Expand(v Vars) Part {
	return Part{
		Setup:        v.Expand(p.Setup),
		Recipe:       v.Expand(p.Recipe),
		Check:        v.Expand(p.Check),
		ExpectOutput: v.Expand(p.ExpectOutput),
		RevertRecipe: v.Expand(p.RevertRecipe),
		Revert:       v.Expand(p.Revert),
	}
}
