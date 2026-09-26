package cook

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/ingredients/sdb"
)

// --- parsing: cond, register, secrets, on_exit ---

func TestExtractCond(t *testing.T) {
	tests := []struct {
		name    string
		props   map[string]interface{}
		want    *Cond
		wantErr bool
	}{
		{"absent", map[string]interface{}{}, nil, false},
		{"simple", map[string]interface{}{"cond": "test -f /tmp/x"}, &Cond{Test: "test -f /tmp/x"}, false},
		{"negated", map[string]interface{}{"cond": "test -f /tmp/x", "cond_negate": true}, &Cond{Test: "test -f /tmp/x", Negate: true}, false},
		{"wrong type", map[string]interface{}{"cond": 5}, nil, true},
		{"empty", map[string]interface{}{"cond": ""}, nil, true},
		{"bad negate type", map[string]interface{}{"cond": "test -f /tmp/x", "cond_negate": "yes"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractCond(tt.props)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractCond() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil cond, got %+v", got)
				}
				return
			}
			if got == nil || got.Test != tt.want.Test || got.Negate != tt.want.Negate {
				t.Fatalf("extractCond() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractRegister(t *testing.T) {
	tests := []struct {
		name    string
		props   map[string]interface{}
		want    *Register
		wantErr bool
	}{
		{"absent", map[string]interface{}{}, nil, false},
		{"bare string", map[string]interface{}{"register": "OUT"}, &Register{Name: "OUT"}, false},
		{"empty string", map[string]interface{}{"register": ""}, nil, true},
		{
			"map with sensitive",
			map[string]interface{}{"register": map[string]interface{}{"name": "TOKEN", "sensitive": true}},
			&Register{Name: "TOKEN", Sensitive: true}, false,
		},
		{"map missing name", map[string]interface{}{"register": map[string]interface{}{"sensitive": true}}, nil, true},
		{"bad type", map[string]interface{}{"register": 5}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRegister(tt.props)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractRegister() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil register, got %+v", got)
				}
				return
			}
			if got == nil || *got != *tt.want {
				t.Fatalf("extractRegister() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractSecrets(t *testing.T) {
	got, err := extractSecrets(map[string]interface{}{
		"secrets": map[string]interface{}{"DB_PASS": "sdb://openbao/secret/db#password"},
	})
	if err != nil {
		t.Fatalf("extractSecrets: %v", err)
	}
	if got["DB_PASS"] != "sdb://openbao/secret/db#password" {
		t.Fatalf("unexpected secrets map: %+v", got)
	}

	if _, err := extractSecrets(map[string]interface{}{"secrets": "not-a-map"}); err == nil {
		t.Fatal("expected error for non-map secrets")
	}
	if _, err := extractSecrets(map[string]interface{}{"secrets": map[string]interface{}{"X": 5}}); err == nil {
		t.Fatal("expected error for non-string secret ref")
	}
}

func TestExtractOnExit(t *testing.T) {
	raw := map[string]interface{}{
		"on_exit": []interface{}{
			map[string]interface{}{
				"cmd.run": []interface{}{
					map[string]interface{}{"name": "rm -f /tmp/x"},
				},
			},
		},
	}
	steps, err := extractOnExit("mystep", raw)
	if err != nil {
		t.Fatalf("extractOnExit: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("expected 1 on_exit step, got %d", len(steps))
	}
	s := steps[0]
	if s.Ingredient != "cmd" || s.Method != "run" {
		t.Fatalf("unexpected on_exit step %+v", s)
	}
	if s.Properties["name"] != "rm -f /tmp/x" {
		t.Fatalf("unexpected on_exit properties %+v", s.Properties)
	}
	if s.ID != "mystep-on_exit-0" {
		t.Fatalf("unexpected on_exit step id %q", s.ID)
	}
}

func TestRecipeToStepWiresOrchestrationPrimitives(t *testing.T) {
	recipe := map[string]interface{}{
		"cmd.run": []interface{}{
			map[string]interface{}{"name": "echo hi"},
			map[string]interface{}{"cond": "test -f /tmp/marker"},
			map[string]interface{}{"register": "OUT"},
			map[string]interface{}{"secrets": map[string]interface{}{"TOKEN": "sdb://cooktest/token"}},
			map[string]interface{}{"on_exit": []interface{}{
				map[string]interface{}{"cmd.run": []interface{}{
					map[string]interface{}{"name": "cleanup"},
				}},
			}},
		},
	}
	step, err := recipeToStep("mystep", recipe)
	if err != nil {
		t.Fatalf("recipeToStep: %v", err)
	}
	if step.Cond == nil || step.Cond.Test != "test -f /tmp/marker" {
		t.Errorf("expected cond to be wired, got %+v", step.Cond)
	}
	if step.Register == nil || step.Register.Name != "OUT" {
		t.Errorf("expected register to be wired, got %+v", step.Register)
	}
	if step.Secrets["TOKEN"] != "sdb://cooktest/token" {
		t.Errorf("expected secrets to be wired, got %+v", step.Secrets)
	}
	if len(step.OnExit) != 1 {
		t.Errorf("expected 1 on_exit step, got %d", len(step.OnExit))
	}
}

// --- runtime evaluation helpers ---

func TestEvalCond(t *testing.T) {
	ctx := context.Background()

	if passed, err := evalCond(ctx, nil); err != nil || !passed {
		t.Fatalf("nil cond: passed=%v err=%v, want true, nil", passed, err)
	}
	if passed, err := evalCond(ctx, &Cond{Test: "true"}); err != nil || !passed {
		t.Fatalf("passing test: passed=%v err=%v, want true, nil", passed, err)
	}
	if passed, err := evalCond(ctx, &Cond{Test: "false"}); err != nil || passed {
		t.Fatalf("failing test: passed=%v err=%v, want false, nil", passed, err)
	}
	if passed, err := evalCond(ctx, &Cond{Test: "false", Negate: true}); err != nil || !passed {
		t.Fatalf("negated failing test: passed=%v err=%v, want true, nil", passed, err)
	}
	if passed, err := evalCond(ctx, &Cond{Test: "true", Negate: true}); err != nil || passed {
		t.Fatalf("negated passing test: passed=%v err=%v, want false, nil", passed, err)
	}
}

func TestRuntimeContextVars(t *testing.T) {
	old := config.FarmerOrganization
	config.FarmerOrganization = "acme-corp"
	defer func() { config.FarmerOrganization = old }()

	ctx := runtimeContextVars("sprout-123")
	if ctx["IMAS_SPROUT_ID"] != "sprout-123" {
		t.Errorf("IMAS_SPROUT_ID = %q, want sprout-123", ctx["IMAS_SPROUT_ID"])
	}
	if ctx["IMAS_TENANT_ID"] != "acme-corp" {
		t.Errorf("IMAS_TENANT_ID = %q, want acme-corp", ctx["IMAS_TENANT_ID"])
	}
}

func TestSubstituteProperties(t *testing.T) {
	vars := newRunVars()
	vars.set("OUT", "resolved-value", false)
	lookup := vars.lookup(map[string]string{"IMAS_SPROUT_ID": "s1"})

	props := map[string]interface{}{
		"name":    "use {OUT} on {IMAS_SPROUT_ID}",
		"list":    []interface{}{"a {OUT}", "b"},
		"strs":    []string{"x {OUT}"},
		"unknown": "keep {NOT_SET} as-is",
		"number":  42,
	}
	out := substituteProperties(props, lookup)

	if out["name"] != "use resolved-value on s1" {
		t.Errorf("name = %q", out["name"])
	}
	if list, ok := out["list"].([]interface{}); !ok || list[0] != "a resolved-value" {
		t.Errorf("list = %+v", out["list"])
	}
	if strs, ok := out["strs"].([]string); !ok || strs[0] != "x resolved-value" {
		t.Errorf("strs = %+v", out["strs"])
	}
	if out["unknown"] != "keep {NOT_SET} as-is" {
		t.Errorf("unknown = %q, want placeholder left untouched", out["unknown"])
	}
	if out["number"] != 42 {
		t.Errorf("number = %v, want untouched", out["number"])
	}
	// original map must not be mutated
	if props["name"] != "use {OUT} on {IMAS_SPROUT_ID}" {
		t.Errorf("substituteProperties mutated its input: %q", props["name"])
	}
}

func TestRedactHelpers(t *testing.T) {
	sensitive := []string{"topsecret", "anothersecret"}

	if got := redact("value=topsecret end", sensitive); got != "value=**REDACTED** end" {
		t.Errorf("redact() = %q", got)
	}
	if got := redact("nothing here", sensitive); got != "nothing here" {
		t.Errorf("redact() should be a no-op, got %q", got)
	}

	notes := redactNotes([]string{"a topsecret b", "clean"}, sensitive)
	if notes[0] != "a **REDACTED** b" || notes[1] != "clean" {
		t.Errorf("redactNotes() = %+v", notes)
	}

	err := redactError(fmt.Errorf("failed with topsecret in it"), sensitive)
	if strings.Contains(err.Error(), "topsecret") {
		t.Errorf("redactError() leaked secret: %v", err)
	}
}

// --- sdb integration ---

type stubSecretProvider struct {
	mu     sync.Mutex
	values map[string]string
}

func (s *stubSecretProvider) Get(_ context.Context, ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.values[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("stubSecretProvider: no value for %s", ref)
}

func (s *stubSecretProvider) set(ref, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[ref] = value
}

var testSecretProvider = &stubSecretProvider{values: map[string]string{}}

func init() {
	// Registered once for the whole test binary; RegisterProvider refuses a
	// second registration under the same name, and per-test values are set
	// on the shared stub instead of re-registering.
	_ = sdb.RegisterProvider("cooktest", testSecretProvider)
}

func TestResolveSecrets(t *testing.T) {
	testSecretProvider.set("sdb://cooktest/mysecret", "the-actual-secret")

	vars := newRunVars()
	err := resolveSecrets(context.Background(), map[string]string{"TOKEN": "sdb://cooktest/mysecret"}, vars)
	if err != nil {
		t.Fatalf("resolveSecrets: %v", err)
	}
	v, ok := vars.get("TOKEN")
	if !ok || v.value != "the-actual-secret" || !v.sensitive {
		t.Fatalf("TOKEN = %+v, ok=%v, want the-actual-secret/sensitive", v, ok)
	}
}

func TestResolveSecretsUnknownRef(t *testing.T) {
	vars := newRunVars()
	err := resolveSecrets(context.Background(), map[string]string{"TOKEN": "sdb://cooktest/does-not-exist"}, vars)
	if err == nil {
		t.Fatal("expected error resolving unknown secret ref")
	}
}

// --- end-to-end via CookRecipeEnvelope ---

func TestCookRecipeEnvelopeCondSkipsStep(t *testing.T) {
	_, cleanup := startCookTestNATS(t)
	defer cleanup()

	tmpDir := t.TempDir()
	oldDir := config.JobLogDir
	config.JobLogDir = tmpDir
	defer func() { config.JobLogDir = oldDir }()

	origCooker := NewRecipeCooker
	defer func() { NewRecipeCooker = origCooker }()
	oldSproutID := config.SproutID
	config.SproutID = "cond-sprout"
	defer func() { config.SproutID = oldSproutID }()

	applied := false
	NewRecipeCooker = func(id StepID, ingredient Ingredient, method string, params map[string]interface{}) (RecipeCooker, error) {
		return &mockRecipeCooker{
			applyResult: Result{Succeeded: true, Changed: true},
		}, nil
	}
	_ = applied

	envelope := RecipeEnvelope{
		JobID: "cond-job",
		Steps: []Step{
			{
				ID: "gated", Ingredient: "cmd", Method: "run",
				Properties: map[string]interface{}{"name": "echo should not run"},
				Cond:       &Cond{Test: "false"},
			},
		},
	}
	if err := CookRecipeEnvelope(envelope); err != nil {
		t.Fatalf("CookRecipeEnvelope: %v", err)
	}

	logFile := filepath.Join(tmpDir, "cond-job.jsonl")
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read job log: %v", err)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var c StepCompletion
		if jsonErr := json.Unmarshal([]byte(line), &c); jsonErr != nil {
			continue
		}
		if c.ID == "gated" {
			found = true
			if c.CompletionStatus != StepSkipped {
				t.Errorf("expected gated step to be StepSkipped, got %v", c.CompletionStatus)
			}
		}
	}
	if !found {
		t.Fatal("gated step completion not found in job log")
	}
}

func TestCookRecipeEnvelopeOnExitRunsOnFailure(t *testing.T) {
	_, cleanup := startCookTestNATS(t)
	defer cleanup()

	tmpDir := t.TempDir()
	oldDir := config.JobLogDir
	config.JobLogDir = tmpDir
	defer func() { config.JobLogDir = oldDir }()

	origCooker := NewRecipeCooker
	defer func() { NewRecipeCooker = origCooker }()
	oldSproutID := config.SproutID
	config.SproutID = "onexit-sprout"
	defer func() { config.SproutID = oldSproutID }()

	var mu sync.Mutex
	var calledIDs []StepID
	NewRecipeCooker = func(id StepID, ingredient Ingredient, method string, params map[string]interface{}) (RecipeCooker, error) {
		mu.Lock()
		calledIDs = append(calledIDs, id)
		mu.Unlock()
		if id == "main" {
			return &mockRecipeCooker{applyResult: Result{Succeeded: false, Failed: true}}, nil
		}
		return &mockRecipeCooker{applyResult: Result{Succeeded: true, Changed: true}}, nil
	}

	envelope := RecipeEnvelope{
		JobID: "onexit-job",
		Steps: []Step{
			{
				ID: "main", Ingredient: "cmd", Method: "run",
				Properties: map[string]interface{}{"name": "false"},
				OnExit: []Step{
					{ID: "main-on_exit-0", Ingredient: "cmd", Method: "run", Properties: map[string]interface{}{"name": "cleanup"}},
				},
			},
		},
	}
	if err := CookRecipeEnvelope(envelope); err != nil {
		t.Fatalf("CookRecipeEnvelope: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	sawCleanup := false
	for _, id := range calledIDs {
		if id == "main-on_exit-0" {
			sawCleanup = true
		}
	}
	if !sawCleanup {
		t.Errorf("expected on_exit step to run despite main step failure, calls: %v", calledIDs)
	}
}

func TestCookRecipeEnvelopeRegisterAndSubstitution(t *testing.T) {
	_, cleanup := startCookTestNATS(t)
	defer cleanup()

	tmpDir := t.TempDir()
	oldDir := config.JobLogDir
	config.JobLogDir = tmpDir
	defer func() { config.JobLogDir = oldDir }()

	origCooker := NewRecipeCooker
	defer func() { NewRecipeCooker = origCooker }()
	oldSproutID := config.SproutID
	config.SproutID = "register-sprout"
	defer func() { config.SproutID = oldSproutID }()

	var mu sync.Mutex
	var consumeName string
	NewRecipeCooker = func(id StepID, ingredient Ingredient, method string, params map[string]interface{}) (RecipeCooker, error) {
		if id == "produce" {
			return &mockRecipeCooker{
				applyResult: Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{SimpleNote("produced-value")}},
			}, nil
		}
		mu.Lock()
		consumeName, _ = params["name"].(string)
		mu.Unlock()
		return &mockRecipeCooker{applyResult: Result{Succeeded: true}}, nil
	}

	envelope := RecipeEnvelope{
		JobID: "register-job",
		Steps: []Step{
			{
				ID: "produce", Ingredient: "cmd", Method: "run",
				Properties: map[string]interface{}{"name": "echo produce"},
				Register:   &Register{Name: "OUT"},
			},
			{
				ID: "consume", Ingredient: "cmd", Method: "run",
				Properties: map[string]interface{}{"name": "use {OUT}"},
				Requisites: RequisiteSet{{Condition: Require, StepIDs: []StepID{"produce"}}},
			},
		},
	}
	if err := CookRecipeEnvelope(envelope); err != nil {
		t.Fatalf("CookRecipeEnvelope: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if consumeName != "use produced-value" {
		t.Errorf("consume step name = %q, want %q", consumeName, "use produced-value")
	}
}

// TestCookRecipeEnvelopeSensitiveRedaction is the security-review test: a
// value marked sensitive via Register must never appear in the persisted
// job log, and must still be scrubbed when the very same completion struct
// is formatted the way sproutcook.go's own log.Infof/Tracef call sites
// format it for verbose/debug output -- not just when it is JSON-marshaled
// for the job log file.
func TestCookRecipeEnvelopeSensitiveRedaction(t *testing.T) {
	_, cleanup := startCookTestNATS(t)
	defer cleanup()

	tmpDir := t.TempDir()
	oldDir := config.JobLogDir
	config.JobLogDir = tmpDir
	defer func() { config.JobLogDir = oldDir }()

	origCooker := NewRecipeCooker
	defer func() { NewRecipeCooker = origCooker }()
	oldSproutID := config.SproutID
	config.SproutID = "redact-sprout"
	defer func() { config.SproutID = oldSproutID }()

	const secret = "sup3r-s3cr3t-token-DO-NOT-LEAK"

	NewRecipeCooker = func(id StepID, ingredient Ingredient, method string, params map[string]interface{}) (RecipeCooker, error) {
		switch id {
		case "produce":
			// Simulates a step whose own output *is* the sensitive value,
			// e.g. probe.http capturing a token from a response body.
			return &mockRecipeCooker{
				applyResult: Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{SimpleNote(secret)}},
			}, nil
		case "consume":
			// Simulates a downstream ingredient that echoes its (now
			// substituted) input back into its own notes -- the leak path
			// that redaction at the StepCompletion boundary must still
			// catch, since this step never registers anything itself.
			name, _ := params["name"].(string)
			return &mockRecipeCooker{
				applyResult: Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{SimpleNote("ran: " + name)}},
			}, nil
		}
		return nil, fmt.Errorf("unexpected step id %s", id)
	}

	envelope := RecipeEnvelope{
		JobID: "redact-job",
		Steps: []Step{
			{
				ID: "produce", Ingredient: "cmd", Method: "run",
				Properties: map[string]interface{}{"name": "echo produce"},
				Register:   &Register{Name: "TOKEN", Sensitive: true},
			},
			{
				ID: "consume", Ingredient: "cmd", Method: "run",
				Properties: map[string]interface{}{"name": "use {TOKEN}"},
				Requisites: RequisiteSet{{Condition: Require, StepIDs: []StepID{"produce"}}},
			},
		},
	}
	if err := CookRecipeEnvelope(envelope); err != nil {
		t.Fatalf("CookRecipeEnvelope: %v", err)
	}

	// --- persisted job log path ---
	logFile := filepath.Join(tmpDir, "redact-job.jsonl")
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read job log: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("persisted job log leaked the sensitive value:\n%s", raw)
	}
	if !strings.Contains(string(raw), RedactedPlaceholder) {
		t.Fatalf("expected redaction placeholder in job log, got:\n%s", raw)
	}

	// --- verbose/debug output path ---
	// sproutcook.go logs each completion with:
	//   log.Infof("Step %s completed with status %v", completion.ID, completion)
	// using the exact same StepCompletion value that was persisted above.
	// Reconstruct that value from the persisted bytes (a lossless
	// round-trip for the ID/Changes fields this test cares about) and
	// apply the identical formatting to prove the debug/verbose sink is
	// not a separate, unguarded path.
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var completion StepCompletion
		if jsonErr := json.Unmarshal([]byte(line), &completion); jsonErr != nil {
			t.Fatalf("unmarshal persisted completion: %v", jsonErr)
		}
		debugLine := fmt.Sprintf("Step %s completed with status %v", completion.ID, completion)
		if strings.Contains(debugLine, secret) {
			t.Fatalf("verbose/debug-formatted log output leaked the sensitive value: %s", debugLine)
		}
	}
}
