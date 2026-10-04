package cook

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/props"
)

// SEC.4 (security review H2 and M8): recipe templates are untrusted, and
// prop and fact values are data, never recipe structure.

func setTestProp(t *testing.T, tenantID, sproutID, name, value string) {
	t.Helper()
	if err := props.SetPropForTenant(tenantID, sproutID, name, value); err != nil {
		t.Fatalf("setting prop %s: %v", name, err)
	}
	t.Cleanup(func() { props.DeletePropForTenant(tenantID, sproutID, name) })
}

// stepsFor renders recipe text for sproutID through the real render and
// YAML path and returns the steps by ID.
func stepsFor(t *testing.T, sproutID, recipe string) map[string]Step {
	t.Helper()
	newRecipeTestStore(t)
	writeRecipe(t, "recipes/inject.imas", recipe)
	steps, err := resolveRecipeSteps(context.Background(), testPropsTenantID, sproutID, "inject")
	if err != nil {
		t.Fatalf("resolveRecipeSteps: %v", err)
	}
	out := map[string]Step{}
	for _, s := range steps {
		out[string(s.ID)] = s
	}
	return out
}

// TestPropValueWithNewlineStaysOneValue: a prop value carrying a newline
// and YAML for an extra cmd.run step, printed into every kind of YAML
// scalar a recipe might use, stays one string value and adds no step.
func TestPropValueWithNewlineStaysOneValue(t *testing.T) {
	const sproutID = "inject-sprout"
	evil := "x\n  evil:\n    cmd.run:\n      - name: touch /tmp/pwned\n"
	setTestProp(t, testPropsTenantID, sproutID, "motd", evil)
	quoteBreak := `a"` + "\n" + `  evil: {cmd.run: [{name: touch /tmp/pwned}]}` + "\n" + `  b: "`
	setTestProp(t, testPropsTenantID, sproutID, "quoted", quoteBreak)
	flowBreak := `a}], evil: {cmd.run: [{name: touch /tmp/pwned}]}, z: {file.absent: [{name: b`
	setTestProp(t, testPropsTenantID, sproutID, "flow", flowBreak)

	cases := map[string]struct {
		recipe string
		want   string
	}{
		"plain": {
			recipe: "steps:\n  banner:\n    file.content:\n      - name: /etc/motd\n      - text: {{ props \"motd\" }}\n",
			want:   evil,
		},
		"plain with surrounding text": {
			recipe: "steps:\n  banner:\n    file.content:\n      - name: /etc/motd\n      - text: hello {{ props \"motd\" }} bye\n",
			want:   "hello " + evil + " bye",
		},
		"double quoted": {
			recipe: "steps:\n  banner:\n    file.content:\n      - name: /etc/motd\n      - text: \"{{ props \"quoted\" }}\"\n",
			want:   quoteBreak,
		},
		"single quoted": {
			recipe: "steps:\n  banner:\n    file.content:\n      - name: /etc/motd\n      - text: '{{ props \"quoted\" }}'\n",
			want:   quoteBreak,
		},
		"flow mapping": {
			recipe: "steps: {banner: {file.content: [{name: /etc/motd}, {text: {{ props \"flow\" }}}]}}\n",
			want:   flowBreak,
		},
		"block literal": {
			recipe: "steps:\n  banner:\n    file.content:\n      - name: /etc/motd\n      - text: |\n          {{ props \"motd\" }}\n",
			want:   evil,
		},
		"through string helpers": {
			recipe: "steps:\n  banner:\n    file.content:\n      - name: /etc/motd\n      - text: {{ lower (printf \"%s\" (trimSpace (props \"motd\"))) }}\n",
			want:   strings.ToLower(strings.TrimSpace(evil)),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			steps := stepsFor(t, sproutID, tc.recipe)
			if len(steps) != 1 {
				t.Fatalf("got %d steps %v, want only banner", len(steps), steps)
			}
			got, _ := steps["banner"].Properties["text"].(string)
			if name == "block literal" {
				got = strings.TrimSuffix(got, "\n")
				if got != evil && got != strings.TrimSuffix(evil, "\n") {
					t.Fatalf("text = %q, want %q", got, evil)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("text = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHostnameFactWithNewlineStaysOneValue: the hostname a sprout reports
// (a fact) is data too, and hostname is the sprout's own, not farmer's.
func TestHostnameFactWithNewlineStaysOneValue(t *testing.T) {
	const sproutID = "inject-host-sprout"
	evil := "web\nevil:\n  cmd.run:\n    - name: id"
	setTestProp(t, testPropsTenantID, sproutID, "hostname", evil)
	steps := stepsFor(t, sproutID, "steps:\n  {{ hostname }} banner:\n    file.content:\n      - name: /etc/motd\n      - text: {{ hostname }}\n")
	if len(steps) != 1 {
		t.Fatalf("got %d steps, want 1: %v", len(steps), steps)
	}
	s, ok := steps[evil+" banner"]
	if !ok {
		t.Fatalf("step key not taken from the hostname as one string: %v", steps)
	}
	if s.Properties["text"] != evil {
		t.Fatalf("text = %q, want %q", s.Properties["text"], evil)
	}
}

func TestHostnameFallsBackToSproutID(t *testing.T) {
	out, err := renderRecipeTemplate(testPropsTenantID, "no-hostname-sprout", "h", []byte(`h: {{ hostname }}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "h: no-hostname-sprout" {
		t.Fatalf("got %q", out)
	}
}

// TestPlainPropKeepsScalarType: a bare prop that is a number or bool is
// still one, as it was when values were spliced into the text; quoting
// makes it a string; YAML syntax in the value stays a string.
func TestPlainPropKeepsScalarType(t *testing.T) {
	const sproutID = "type-sprout"
	setTestProp(t, testPropsTenantID, sproutID, "port", "8080")
	setTestProp(t, testPropsTenantID, sproutID, "on", "true")
	setTestProp(t, testPropsTenantID, sproutID, "list", "[a, b]")
	setTestProp(t, testPropsTenantID, sproutID, "map", "{a: b}")
	steps := stepsFor(t, sproutID, `steps:
  s:
    x.y:
      - port: {{ props "port" }}
      - qport: "{{ props "port" }}"
      - on: {{ props "on" }}
      - list: {{ props "list" }}
      - map: {{ props "map" }}
      - missing: {{ props "nope" }}
`)
	p := steps["s"].Properties
	if p["port"] != 8080 {
		t.Errorf("port = %#v, want int 8080", p["port"])
	}
	if p["qport"] != "8080" {
		t.Errorf("qport = %#v, want string", p["qport"])
	}
	if p["on"] != true {
		t.Errorf("on = %#v, want true", p["on"])
	}
	if p["list"] != "[a, b]" || p["map"] != "{a: b}" {
		t.Errorf("list/map = %#v / %#v, want strings", p["list"], p["map"])
	}
	if v, ok := p["missing"]; !ok || v != nil {
		t.Errorf("missing = %#v, want null as before", v)
	}
}

// TestPropValueLookingLikePlaceholderIsNotExpanded: substitution is one
// pass, so a value whose text is itself a placeholder is inserted as
// text.
func TestPropValueLookingLikePlaceholderIsNotExpanded(t *testing.T) {
	const sproutID = "placeholder-sprout"
	fake := encodeTemplatePlaceholder("x\nevil: {cmd.run: [{name: id}]}")
	setTestProp(t, testPropsTenantID, sproutID, "fake", fake)
	steps := stepsFor(t, sproutID, "steps:\n  s:\n    x.y:\n      - v: {{ props \"fake\" }}\n")
	if len(steps) != 1 || steps["s"].Properties["v"] != fake {
		t.Fatalf("got %v, want one step with the literal text", steps)
	}
}

// TestDuplicateKeysFromValuesRefused: two keys that differ only as
// placeholders but are equal as values are a YAML error, as they would
// be in the text.
func TestDuplicateKeysFromValuesRefused(t *testing.T) {
	const sproutID = "dupkey-sprout"
	setTestProp(t, testPropsTenantID, sproutID, "a", "same")
	setTestProp(t, testPropsTenantID, sproutID, "b", "same")
	newRecipeTestStore(t)
	writeRecipe(t, "recipes/dup.imas", "steps:\n  {{ props \"a\" }}:\n    x.y: []\n  {{ props \"b\" }}:\n    x.y: []\n")
	if _, err := resolveRecipeSteps(context.Background(), testPropsTenantID, sproutID, "dup"); err == nil {
		t.Fatal("duplicate step IDs from prop values were accepted")
	}
}

// TestRemovedTemplateFuncsFailToRender: env and every builtin removed from
// recipes fail, even in a branch that would never run.
func TestRemovedTemplateFuncsFailToRender(t *testing.T) {
	for _, tmpl := range []string{
		`v: {{ env "HOME" }}`,
		`v: {{ if false }}{{ env "IMAS_PXC_DSN" }}{{ end }}`,
		`v: {{ call sproutID }}`,
		`v: {{ html "<a>" }}`,
		`v: {{ js "a'b" }}`,
		`v: {{ "x" | html }}`,
		`v: {{ with $f := "x" }}{{ js $f }}{{ end }}`,
	} {
		t.Run(tmpl, func(t *testing.T) {
			_, err := renderRecipeTemplate(testPropsTenantID, "removed-sprout", "removed", []byte(tmpl))
			if !errors.Is(err, ErrTemplateFuncRemoved) {
				t.Fatalf("got %v, want ErrTemplateFuncRemoved", err)
			}
			if err := ValidateRecipeSource("removed", []byte(tmpl)); !errors.Is(err, ErrTemplateFuncRemoved) {
				t.Fatalf("ValidateRecipeSource: got %v, want ErrTemplateFuncRemoved", err)
			}
		})
	}
}

// TestTemplateRecursionRefused: template, define and block allow
// unbounded recursion; none is accepted.
func TestTemplateRecursionRefused(t *testing.T) {
	for _, tmpl := range []string{
		`{{ define "a" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		`{{ block "a" . }}x{{ end }}`,
		`{{ template "missing" }}`,
	} {
		if _, err := renderRecipeTemplate(testPropsTenantID, "rec-sprout", "rec", []byte(tmpl)); !errors.Is(err, ErrTemplateConstruct) {
			t.Errorf("%s: got %v, want ErrTemplateConstruct", tmpl, err)
		}
	}
}

// TestRangeLimits: range over an integer is refused, and the total
// iterations of every range in a render are capped.
func TestRangeLimits(t *testing.T) {
	if _, err := renderRecipeTemplate(testPropsTenantID, "range-sprout", "r", []byte(`{{ range 1000000000 }}{{ end }}`)); !errors.Is(err, ErrTemplateConstruct) {
		t.Errorf("range over int: got %v, want ErrTemplateConstruct", err)
	}
	nested := `{{ range split (printf "%0999d" 0) "" }}{{ range split (printf "%0999d" 0) "" }}{{ end }}{{ end }}`
	if _, err := renderRecipeTemplate(testPropsTenantID, "range-sprout", "r", []byte(nested)); !errors.Is(err, ErrTemplateRangeTooLong) {
		t.Errorf("nested ranges: got %v, want ErrTemplateRangeTooLong", err)
	}
	ok := `l:{{ range split "a,b,c" "," }} {{ . }}{{ end }}`
	out, err := renderRecipeTemplate(testPropsTenantID, "range-sprout", "r", []byte(ok))
	if err != nil || strings.TrimSpace(string(out)) != "l: a b c" {
		t.Errorf("small range: got %q, %v", out, err)
	}
}

// TestTemplateTimeLimit: a render that keeps working past
// RecipeRenderTimeout stops with ErrTemplateTimeout, promptly, whether its
// loops call functions or are empty.
func TestTemplateTimeLimit(t *testing.T) {
	origTimeout, origRange := RecipeRenderTimeout, maxRangeIterations
	RecipeRenderTimeout, maxRangeIterations = 100*time.Millisecond, 1<<40
	t.Cleanup(func() { RecipeRenderTimeout, maxRangeIterations = origTimeout, origRange })

	list := `(split (printf "%0999d" 0) "")`
	for name, tmpl := range map[string]string{
		"empty bodies":   `{{ range ` + list + ` }}{{ range ` + list + ` }}{{ range ` + list + ` }}{{ end }}{{ end }}{{ end }}`,
		"function calls": `{{ range ` + list + ` }}{{ range ` + list + ` }}{{ $x := replace (printf "%0999d" 0) "0" "1" }}{{ end }}{{ end }}{{ range ` + list + ` }}{{ range ` + list + ` }}{{ range ` + list + ` }}{{ upper "a" }}{{ end }}{{ end }}{{ end }}`,
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := renderRecipeTemplate(testPropsTenantID, "time-sprout", "t", []byte(tmpl))
			if !errors.Is(err, ErrTemplateTimeout) {
				t.Fatalf("got %v, want ErrTemplateTimeout", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("render stopped after %v, want about %v", elapsed, RecipeRenderTimeout)
			}
		})
	}
}

// TestTemplateSizeLimits: output, single values, printf widths and the
// source are all capped.
func TestTemplateSizeLimits(t *testing.T) {
	origOut := MaxRenderedRecipeBytes
	MaxRenderedRecipeBytes = 4096
	t.Cleanup(func() { MaxRenderedRecipeBytes = origOut })

	big := `{{ range split (printf "%0999d" 0) "" }}{{ printf "%0999d" 0 }}{{ end }}`
	if _, err := renderRecipeTemplate(testPropsTenantID, "size-sprout", "s", []byte(big)); !errors.Is(err, ErrTemplateOutputTooBig) {
		t.Errorf("output: got %v, want ErrTemplateOutputTooBig", err)
	}
	// Doubling a variable stops at maxTemplateValueBytes, before output.
	doubling := `{{ $s := printf "%0999d" 0 }}{{ range split (printf "%0999d" 0) "" }}{{ $s = printf "%s%s" $s $s }}{{ end }}`
	if _, err := renderRecipeTemplate(testPropsTenantID, "size-sprout", "s", []byte(doubling)); !errors.Is(err, ErrTemplateValueTooBig) {
		t.Errorf("doubling: got %v, want ErrTemplateValueTooBig", err)
	}
	blowup := `{{ replace (printf "%0999d" 0) "" (printf "%0999d" 0) }}`
	if _, err := renderRecipeTemplate(testPropsTenantID, "size-sprout", "s", []byte(blowup)); !errors.Is(err, ErrTemplateValueTooBig) {
		t.Errorf("replace: got %v, want ErrTemplateValueTooBig", err)
	}
	for _, f := range []string{`{{ printf "%01000000d" 0 }}`, `{{ printf "%*d" 1000000 0 }}`, `{{ printf "%.5000f" 1.0 }}`, `{{ printf "%[1]d" 1 }}`} {
		if _, err := renderRecipeTemplate(testPropsTenantID, "size-sprout", "s", []byte(f)); !errors.Is(err, ErrTemplateArgument) {
			t.Errorf("%s: got %v, want ErrTemplateArgument", f, err)
		}
	}
	source := []byte("a: " + strings.Repeat("x", MaxRecipeSourceBytes))
	if _, err := renderRecipeTemplate(testPropsTenantID, "size-sprout", "s", source); !errors.Is(err, ErrRecipeTooLarge) {
		t.Errorf("source: got %v, want ErrRecipeTooLarge", err)
	}
}

// TestOversizeRecipeObjectRefused: readRecipe never reads a recipe over
// MaxRecipeSourceBytes from the store.
func TestOversizeRecipeObjectRefused(t *testing.T) {
	newRecipeTestStore(t)
	writeRecipe(t, "recipes/huge.imas", "a: "+strings.Repeat("x", MaxRecipeSourceBytes))
	if _, err := resolveRecipeSteps(context.Background(), testPropsTenantID, "huge-sprout", "huge"); !errors.Is(err, ErrRecipeTooLarge) {
		t.Fatalf("got %v, want ErrRecipeTooLarge", err)
	}
}

func TestValidateRecipeSource(t *testing.T) {
	if err := ValidateRecipeSource("ok", []byte("steps:\n  s:\n    cmd.run:\n      - name: echo {{ props \"x\" }} {{ hostname }}\n")); err != nil {
		t.Errorf("valid recipe refused: %v", err)
	}
	if err := ValidateRecipeSource("bad", []byte("steps: [\n")); err == nil {
		t.Error("invalid YAML accepted")
	}
}

func TestCheckFormat(t *testing.T) {
	for _, ok := range []string{"%s", "%d-%s", "%%", "%05d", "%-10s", "%.2f", "%1000d", "abc"} {
		if err := checkFormat(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"%1001d", "%*d", "%.*f", "%[2]s", "%.99999f"} {
		if err := checkFormat(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSetRenderLimits(t *testing.T) {
	orig := CurrentRenderLimits()
	t.Cleanup(func() {
		if err := SetRenderLimits(orig); err != nil {
			t.Fatal(err)
		}
	})
	if orig != (RenderLimits{DefaultMaxRecipeSourceBytes, DefaultMaxRenderedRecipeBytes, DefaultMaxTemplateValueBytes, DefaultRecipeRenderTimeout, DefaultMaxRangeIterations}) {
		t.Fatalf("defaults = %+v", orig)
	}
	// Zero fields keep the current value.
	if err := SetRenderLimits(RenderLimits{}); err != nil || CurrentRenderLimits() != orig {
		t.Fatalf("empty limits: %v, %+v", err, CurrentRenderLimits())
	}
	want := RenderLimits{MaxSourceBytes: 1000, MaxRenderedBytes: 4000, MaxValueBytes: 2000, RenderTimeout: time.Second, MaxRangeIterations: 5}
	if err := SetRenderLimits(want); err != nil || CurrentRenderLimits() != want {
		t.Fatalf("set: %v, %+v", err, CurrentRenderLimits())
	}
	// The new limits are the ones a render uses.
	if _, err := renderRecipeTemplate(testPropsTenantID, "limits-sprout", "l", []byte(`{{ range split "a,b,c,d,e,f" "," }}{{ end }}`)); !errors.Is(err, ErrTemplateRangeTooLong) {
		t.Errorf("range over 6 with a budget of 5: got %v", err)
	}
	for name, bad := range map[string]RenderLimits{
		"negative source":     {MaxSourceBytes: -1},
		"huge output":         {MaxRenderedBytes: 1 << 30},
		"value above output":  {MaxRenderedBytes: 100, MaxValueBytes: 200},
		"negative timeout":    {RenderTimeout: -time.Second},
		"long timeout":        {RenderTimeout: time.Hour},
		"negative iterations": {MaxRangeIterations: -5},
		"too many iterations": {MaxRangeIterations: 1 << 30},
	} {
		if err := SetRenderLimits(bad); !errors.Is(err, ErrRenderLimits) {
			t.Errorf("%s: got %v, want ErrRenderLimits", name, err)
		}
		if CurrentRenderLimits() != want {
			t.Errorf("%s: limits changed on error: %+v", name, CurrentRenderLimits())
		}
	}
}
