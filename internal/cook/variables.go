package cook

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/log"
)

// RedactedPlaceholder replaces every occurrence of a sensitive value
// wherever step output is persisted or logged.
const RedactedPlaceholder = "**REDACTED**"

var varPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// registeredValue is one entry in a runVars store.
type registeredValue struct {
	value     string
	sensitive bool
}

// runVars holds the per-recipe-run variable state: values registered by
// steps (Step.Register) and secrets resolved via sdb:// (Step.Secrets),
// available to later steps as {NAME} substitutions in their own properties.
// A runVars is scoped to a single CookRecipeEnvelope invocation and must not
// be reused across runs.
type runVars struct {
	mu   sync.Mutex
	vars map[string]registeredValue
}

func newRunVars() *runVars {
	return &runVars{vars: make(map[string]registeredValue)}
}

func (r *runVars) set(name, value string, sensitive bool) {
	if name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vars[name] = registeredValue{value: value, sensitive: sensitive}
}

func (r *runVars) get(name string) (registeredValue, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.vars[name]
	return v, ok
}

// sensitiveValues snapshots every value currently registered as sensitive,
// across every step that has run so far in this recipe -- not just the step
// that produced the output being checked. A value registered by step A must
// stay redacted if it resurfaces in step B's output later in the same run.
func (r *runVars) sensitiveValues() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.vars))
	for _, v := range r.vars {
		if v.sensitive && v.value != "" {
			out = append(out, v.value)
		}
	}
	return out
}

// lookup returns a variable resolver combining runtime context variables
// (which always win, since they are not user-overridable) with this run's
// registered/secret variables.
func (r *runVars) lookup(runtimeCtx map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if v, ok := runtimeCtx[name]; ok {
			return v, true
		}
		if v, ok := r.get(name); ok {
			return v.value, true
		}
		return "", false
	}
}

// runtimeContextVars returns the auto-populated variables available in
// every recipe step, regardless of any register/secrets usage.
func runtimeContextVars(sproutID string) map[string]string {
	return map[string]string{
		"IMAS_SPROUT_ID": sproutID,
		"IMAS_TENANT_ID": config.FarmerOrganization,
	}
}

// resolveSecrets resolves each of a step's sdb:// refs and registers the
// result as a sensitive variable under its given name. Secrets are always
// sensitive: there is no way to opt a resolved secret out of redaction.
func resolveSecrets(ctx context.Context, secrets map[string]string, vars *runVars) error {
	for name, ref := range secrets {
		val, err := sdb.Get(ctx, ref)
		if err != nil {
			return fmt.Errorf("resolve secret %s (%s): %w", name, ref, err)
		}
		vars.set(name, val, true)
	}
	return nil
}

// substituteString replaces every {VAR_NAME} occurrence in s using lookup.
// A name lookup does not find is left untouched, rather than erroring or
// substituting an empty string, since the placeholder text may be
// unrelated (e.g. a literal brace in a template written by hand).
func substituteString(s string, lookup func(string) (string, bool)) string {
	if !strings.Contains(s, "{") {
		return s
	}
	return varPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v, ok := lookup(name); ok {
			return v
		}
		return m
	})
}

// substituteValue applies substituteString to every string reachable inside
// v, recursing into []string and []interface{} (the two shapes step
// properties arrive in from parsed recipe YAML), leaving any other type
// unchanged.
func substituteValue(v interface{}, lookup func(string) (string, bool)) interface{} {
	switch t := v.(type) {
	case string:
		return substituteString(t, lookup)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = substituteString(s, lookup)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, item := range t {
			out[i] = substituteValue(item, lookup)
		}
		return out
	default:
		return v
	}
}

// substituteProperties returns a copy of props with every string value
// (recursively) run through substituteString. The original map is left
// untouched, since Step.Properties may be inspected again (e.g. by on_exit
// or a retry) after this step has substituted its own copy.
func substituteProperties(props map[string]interface{}, lookup func(string) (string, bool)) map[string]interface{} {
	if props == nil {
		return nil
	}
	out := make(map[string]interface{}, len(props))
	for k, v := range props {
		out[k] = substituteValue(v, lookup)
	}
	return out
}

// evalCond runs a Cond's shell test and reports whether the step it guards
// should run. A nil Cond always passes. Only a genuine failure to invoke the
// shell (not found, permissions, context cancellation) is returned as an
// error -- a nonzero exit from the test itself is a normal "does not pass"
// result, not a step failure.
func evalCond(ctx context.Context, cond *Cond) (bool, error) {
	if cond == nil {
		return true, nil
	}
	command := exec.CommandContext(ctx, "sh", "-c", cond.Test)
	runErr := command.Run()
	passed := runErr == nil
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return false, fmt.Errorf("evaluating cond %q: %w", cond.Test, runErr)
		}
	}
	if cond.Negate {
		passed = !passed
	}
	return passed, nil
}

// captureRegisterValue derives the value a Register captures from a step's
// Result: its notes, joined by newline. Notes are the only output every
// ingredient produces generically, regardless of what it does.
func captureRegisterValue(res Result) string {
	if len(res.Notes) == 0 {
		return ""
	}
	parts := make([]string, len(res.Notes))
	for i, n := range res.Notes {
		parts[i] = n.String()
	}
	return strings.Join(parts, "\n")
}

// redact replaces every occurrence of any sensitive value in s with
// RedactedPlaceholder.
func redact(s string, sensitive []string) string {
	if s == "" || len(sensitive) == 0 {
		return s
	}
	for _, v := range sensitive {
		if v == "" {
			continue
		}
		s = strings.ReplaceAll(s, v, RedactedPlaceholder)
	}
	return s
}

// redactNotes applies redact to a slice of already-stringified notes -- the
// form a StepCompletion carries, and so the form written to the persisted
// job log, published over NATS, and included in log.Infof/Tracef output.
func redactNotes(notes []string, sensitive []string) []string {
	if len(sensitive) == 0 || len(notes) == 0 {
		return notes
	}
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = redact(n, sensitive)
	}
	return out
}

// redactError returns an error whose message has sensitive values redacted.
// This deliberately discards error wrapping when redaction actually changes
// the message: preserving %w-chains is not worth the risk of a sensitive
// value surviving inside a wrapped error's unexported state, and this
// boundary (about to be logged and persisted) is not one anything downstream
// unwraps.
func redactError(err error, sensitive []string) error {
	if err == nil || len(sensitive) == 0 {
		return err
	}
	msg := err.Error()
	redacted := redact(msg, sensitive)
	if redacted == msg {
		return err
	}
	return errors.New(redacted)
}

// runOnExit runs a step's deferred on_exit actions after its Apply/Test,
// regardless of the parent step's own outcome. Failures are logged (with
// sensitive-value redaction applied first) rather than propagated: on_exit
// is cleanup, and a cleanup step's failure must not be mistaken for the
// parent step's own result.
func runOnExit(ctx context.Context, steps []Step, vars *runVars, runtimeCtx map[string]string, testMode bool) {
	for _, step := range steps {
		if err := resolveSecrets(ctx, step.Secrets, vars); err != nil {
			log.Errorf("on_exit step %s: resolving secrets: %v", step.ID, redactError(err, vars.sensitiveValues()))
			continue
		}
		props := substituteProperties(step.Properties, vars.lookup(runtimeCtx))
		ingredient, err := NewRecipeCooker(step.ID, step.Ingredient, step.Method, props)
		if err != nil {
			log.Errorf("on_exit step %s: %v", step.ID, redactError(err, vars.sensitiveValues()))
			continue
		}
		var res Result
		if testMode {
			res, err = ingredient.Test(ctx)
		} else {
			res, err = ingredient.Apply(ctx)
		}
		if step.Register != nil && !testMode {
			vars.set(step.Register.Name, captureRegisterValue(res), step.Register.Sensitive)
		}
		sensitive := vars.sensitiveValues()
		if err != nil {
			log.Errorf("on_exit step %s failed: %v", step.ID, redactError(err, sensitive))
			continue
		}
		if !testMode && !res.Succeeded {
			log.Errorf("on_exit step %s did not succeed", step.ID)
		}
	}
}
