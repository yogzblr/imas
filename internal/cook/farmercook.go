package cook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"text/template/parse"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/google/uuid"
	"github.com/yogzblr/imas/internal/log"
	"gopkg.in/yaml.v3"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/props"
)

// CookOption configures optional parameters for SendCookEvent.
type CookOption func(*cookOptions)

type cookOptions struct {
	invokedBy  string
	targetStep StepID
	stageGuard func() error
}

// WithInvoker sets the pubkey of the user who initiated the cook.
func WithInvoker(pubkey string) CookOption {
	return func(o *cookOptions) {
		o.invokedBy = pubkey
	}
}

// WithTargetStep restricts the cook to a single step (and the transitive
// closure of its requisite dependencies) instead of the whole recipe tree.
// An empty id runs the full recipe.
func WithTargetStep(id StepID) CookOption {
	return func(o *cookOptions) {
		o.targetStep = id
	}
}

// WithStageGuard sets a check SendCookEventContext runs after staging the
// recipe (see stage.go) and before pushing it. If check returns an error,
// the staged copy is removed and nothing is pushed. The caller uses it to
// confirm the sprout still has the identity the recipe was rendered for,
// so a dispatch already in flight when a sprout is deleted or replaced
// can't leave the old host's recipe readable by the new one.
func WithStageGuard(check func() error) CookOption {
	return func(o *cookOptions) {
		o.stageGuard = check
	}
}

// Recipe templates are untrusted input (owner decision, 2026-10-04:
// tenants write recipes and upload them through the SaaS API). Farmer
// renders them with text/template under the restrictions below before
// parsing the result as YAML. FLAG FOR SECURITY REVIEW (security review
// M8 and H2).
//
// # Function map
//
// populateFuncMap is the whole set a recipe can call, on top of
// text/template's comparison and logic builtins (and, or, not, eq, ne, lt,
// le, gt, ge, len, index, slice). Every function is pure: none reads a
// file, the environment, the network, a process or a secret. The audit:
//
//   - env (os.Getenv) is removed: it read farmer's own environment, which
//     holds IMAS_PXC_DSN and the S3 keys (M8).
//   - call, html and js (text/template builtins) are removed: call invokes
//     a function value (none is reachable, but there is no need for it),
//     and html and js escape for contexts a YAML recipe never has.
//   - print, printf, println and urlquery (builtins) are replaced by
//     versions that cap their output and keep track of template values
//     (below). printf refuses '*' and widths or precisions over
//     maxFormatWidth, which fmt would otherwise allocate up to 1e6 of.
//   - props and hostname read the sprout's own props, scoped to
//     (tenant_id, sprout_id), from one query per render rather than one
//     per call. hostname is the "hostname" fact the sprout reported (it
//     used to be farmer's own os.Hostname, which named the farmer pod, not
//     the sprout); it falls back to the sprout ID.
//   - sproutID, join, split, replace, contains, hasPrefix, hasSuffix,
//     trimSpace, upper, lower, title, base, dir, ext, cleanPath, default
//     and ternary are string functions. base, dir, ext and cleanPath are
//     path/filepath string operations and never touch the filesystem.
//     Every string they return is capped at maxTemplateValueBytes, checked
//     before allocating where the size can be known (replace, join).
//
// # Bounded work
//
// The limits below are defaults; farmer takes them from the Helm chart's
// farmer.recipes.templateLimits (SetRenderLimits).
//
// A recipe template is parsed only if it is at most MaxRecipeSourceBytes.
// After parsing, the tree is checked and rewritten (sandboxTemplateTree):
// template, define and block are refused (they allow recursion), removed
// functions are refused even in a branch that would not run, every range
// pipeline goes through a guard that accepts only lists and maps and
// charges their length to a per-render budget of maxRangeIterations, and
// every range body starts with a deadline check. Every function call and
// every write of output checks the deadline too, and output stops at
// MaxRenderedRecipeBytes. So nothing in a render runs for long without
// checking the clock, and RecipeRenderTimeout bounds the whole render,
// includes excepted (each included recipe is a render of its own).
//
// A cook renders many recipes: the one it names and up to maxRecipeIncludes
// distinct includes, each twice (once to find its includes, once to build
// its steps). So a cook also has a budget of its own (cookBudget, security
// review B4), created by resolveRecipeSteps and charged by every render of
// both phases: total time inside executeRecipeTemplate
// (cookRenderTimeout), total rendered bytes (cookMaxRenderedBytes) and
// total range iterations (cookMaxRangeIterations). Each render stays
// inside its own limits as well; whichever runs out first stops it. A cook
// that runs out of budget fails with ErrCookRenderBudget before anything
// is staged or dispatched.
//
// # Template values
//
// props, hostname and sproutID return a templateValue, not a string, and
// every function above returns one when any of its inputs was one. When a
// templateValue is printed into the recipe text, it prints as an opaque,
// alphanumeric placeholder, not as its content. The YAML is parsed with
// the placeholders in place, so its structure comes only from the
// recipe's own text, and only then is each placeholder replaced by its
// value, inside the scalar that holds it (substituteTemplateValues in
// helpers.go). A value that contains a newline, a quote or YAML syntax
// stays one value. Comparisons (eq, ne, ...), len and if see the real
// content, since a templateValue is a string underneath.

// Render limits. Their defaults are the Default* constants; farmer sets
// them at startup from the Helm chart's farmer.recipes.templateLimits
// (SetRenderLimits), and tests lower them directly.
var (
	// MaxRecipeSourceBytes caps a recipe's source, checked before
	// parsing (and when it is read from the store).
	MaxRecipeSourceBytes = DefaultMaxRecipeSourceBytes
	// MaxRenderedRecipeBytes caps a template's rendered output.
	MaxRenderedRecipeBytes = DefaultMaxRenderedRecipeBytes
	// RecipeRenderTimeout caps one recipe's template execution.
	RecipeRenderTimeout = DefaultRecipeRenderTimeout
	// maxTemplateValueBytes caps any one string a template function
	// returns.
	maxTemplateValueBytes = DefaultMaxTemplateValueBytes
	// maxRangeIterations caps the total iterations of every range in one
	// render.
	maxRangeIterations = DefaultMaxRangeIterations
	// cookRenderTimeout caps the time every render of one cook spends in
	// executeRecipeTemplate, together.
	cookRenderTimeout = DefaultCookRenderTimeout
	// cookMaxRenderedBytes caps the output of every render of one cook,
	// together.
	cookMaxRenderedBytes = DefaultCookMaxRenderedBytes
	// cookMaxRangeIterations caps the range iterations of every render of
	// one cook, together.
	cookMaxRangeIterations = DefaultCookMaxRangeIterations
	// maxRecipeIncludes caps the distinct recipes one cook may include
	// (the recipe it names is not counted); at most
	// maxSettableRecipeIncludes.
	maxRecipeIncludes = DefaultMaxRecipeIncludes
)

// Default render limits.
const (
	DefaultMaxRecipeSourceBytes   = 256 << 10
	DefaultMaxRenderedRecipeBytes = 1 << 20
	DefaultMaxTemplateValueBytes  = 256 << 10
	DefaultRecipeRenderTimeout    = 2 * time.Second
	DefaultMaxRangeIterations     = 10000
	DefaultCookRenderTimeout      = 10 * time.Second
	DefaultCookMaxRenderedBytes   = 8 << 20
	DefaultCookMaxRangeIterations = 100000
	DefaultMaxRecipeIncludes      = 64
)

// Upper bounds SetRenderLimits accepts. They are far above any recipe's
// needs and exist so a typo in a Helm value (a missing unit, an extra
// digit) cannot quietly remove a limit.
const (
	maxSettableBytes          = 64 << 20
	maxSettableTimeout        = time.Minute
	maxSettableIterations     = 10_000_000
	maxSettableCookBytes      = 256 << 20
	maxSettableCookTimeout    = 5 * time.Minute
	maxSettableCookIterations = 100_000_000
	maxSettableRecipeIncludes = 256
)

// RenderLimits are the settable render limits. A zero field keeps the
// current value. The first five bound one render; the Cook* fields bound
// every render of one cook together (cookBudget), and MaxIncludes the
// distinct recipes one cook may include.
type RenderLimits struct {
	MaxSourceBytes         int
	MaxRenderedBytes       int
	MaxValueBytes          int
	RenderTimeout          time.Duration
	MaxRangeIterations     int
	CookRenderTimeout      time.Duration
	CookMaxRenderedBytes   int
	CookMaxRangeIterations int
	MaxIncludes            int
}

// ErrRenderLimits is returned by SetRenderLimits for a limit out of range.
var ErrRenderLimits = errors.New("recipe template render limit out of range")

// CurrentRenderLimits returns the render limits in force.
func CurrentRenderLimits() RenderLimits {
	return RenderLimits{
		MaxSourceBytes:         MaxRecipeSourceBytes,
		MaxRenderedBytes:       MaxRenderedRecipeBytes,
		MaxValueBytes:          maxTemplateValueBytes,
		RenderTimeout:          RecipeRenderTimeout,
		MaxRangeIterations:     maxRangeIterations,
		CookRenderTimeout:      cookRenderTimeout,
		CookMaxRenderedBytes:   cookMaxRenderedBytes,
		CookMaxRangeIterations: cookMaxRangeIterations,
		MaxIncludes:            maxRecipeIncludes,
	}
}

// SetRenderLimits installs l's non-zero fields as the render limits, after
// checking every field: each must be positive and at most 64 MiB (sizes),
// one minute (time) or 10,000,000 (iterations), and a single value may not
// exceed the rendered output cap. A per-cook limit must be at least its
// per-render limit and at most 256 MiB (bytes), five minutes (time) or
// 100,000,000 (iterations); the include cap is 1 to 256. On error nothing
// is changed. Call once at startup, before any cook.
func SetRenderLimits(l RenderLimits) error {
	next := CurrentRenderLimits()
	if l.MaxSourceBytes != 0 {
		next.MaxSourceBytes = l.MaxSourceBytes
	}
	if l.MaxRenderedBytes != 0 {
		next.MaxRenderedBytes = l.MaxRenderedBytes
	}
	if l.MaxValueBytes != 0 {
		next.MaxValueBytes = l.MaxValueBytes
	}
	if l.RenderTimeout != 0 {
		next.RenderTimeout = l.RenderTimeout
	}
	if l.MaxRangeIterations != 0 {
		next.MaxRangeIterations = l.MaxRangeIterations
	}
	if l.CookRenderTimeout != 0 {
		next.CookRenderTimeout = l.CookRenderTimeout
	}
	if l.CookMaxRenderedBytes != 0 {
		next.CookMaxRenderedBytes = l.CookMaxRenderedBytes
	}
	if l.CookMaxRangeIterations != 0 {
		next.CookMaxRangeIterations = l.CookMaxRangeIterations
	}
	if l.MaxIncludes != 0 {
		next.MaxIncludes = l.MaxIncludes
	}
	for name, v := range map[string]int{
		"source size":          next.MaxSourceBytes,
		"rendered output size": next.MaxRenderedBytes,
		"value size":           next.MaxValueBytes,
	} {
		if v <= 0 || v > maxSettableBytes {
			return fmt.Errorf("%w: %s %d must be between 1 and %d bytes", ErrRenderLimits, name, v, maxSettableBytes)
		}
	}
	if next.MaxValueBytes > next.MaxRenderedBytes {
		return fmt.Errorf("%w: value size %d exceeds rendered output size %d", ErrRenderLimits, next.MaxValueBytes, next.MaxRenderedBytes)
	}
	if next.RenderTimeout <= 0 || next.RenderTimeout > maxSettableTimeout {
		return fmt.Errorf("%w: render timeout %s must be above 0 and at most %s", ErrRenderLimits, next.RenderTimeout, maxSettableTimeout)
	}
	if next.MaxRangeIterations <= 0 || next.MaxRangeIterations > maxSettableIterations {
		return fmt.Errorf("%w: range iterations %d must be between 1 and %d", ErrRenderLimits, next.MaxRangeIterations, maxSettableIterations)
	}
	if next.CookRenderTimeout < next.RenderTimeout || next.CookRenderTimeout > maxSettableCookTimeout {
		return fmt.Errorf("%w: cook render timeout %s must be at least the render timeout %s and at most %s", ErrRenderLimits, next.CookRenderTimeout, next.RenderTimeout, maxSettableCookTimeout)
	}
	if next.CookMaxRenderedBytes < next.MaxRenderedBytes || next.CookMaxRenderedBytes > maxSettableCookBytes {
		return fmt.Errorf("%w: cook rendered output size %d must be between the rendered output size %d and %d bytes", ErrRenderLimits, next.CookMaxRenderedBytes, next.MaxRenderedBytes, maxSettableCookBytes)
	}
	if next.CookMaxRangeIterations < next.MaxRangeIterations || next.CookMaxRangeIterations > maxSettableCookIterations {
		return fmt.Errorf("%w: cook range iterations %d must be between the range iterations %d and %d", ErrRenderLimits, next.CookMaxRangeIterations, next.MaxRangeIterations, maxSettableCookIterations)
	}
	if next.MaxIncludes <= 0 || next.MaxIncludes > maxSettableRecipeIncludes {
		return fmt.Errorf("%w: includes %d must be between 1 and %d", ErrRenderLimits, next.MaxIncludes, maxSettableRecipeIncludes)
	}
	MaxRecipeSourceBytes = next.MaxSourceBytes
	MaxRenderedRecipeBytes = next.MaxRenderedBytes
	maxTemplateValueBytes = next.MaxValueBytes
	RecipeRenderTimeout = next.RenderTimeout
	maxRangeIterations = next.MaxRangeIterations
	cookRenderTimeout = next.CookRenderTimeout
	cookMaxRenderedBytes = next.CookMaxRenderedBytes
	cookMaxRangeIterations = next.CookMaxRangeIterations
	maxRecipeIncludes = next.MaxIncludes
	return nil
}

// maxFormatWidth caps a printf width or precision.
const maxFormatWidth = 1000

// Errors from a recipe render.
var (
	ErrTemplateFuncRemoved   = errors.New("template function is not available in recipes")
	ErrTemplateConstruct     = errors.New("template construct is not allowed in recipes")
	ErrTemplateTimeout       = errors.New("recipe template exceeded its time limit")
	ErrTemplateOutputTooBig  = errors.New("recipe template output exceeds its size limit")
	ErrTemplateValueTooBig   = errors.New("recipe template value exceeds its size limit")
	ErrTemplateRangeTooLong  = errors.New("recipe template ranges exceed their iteration limit")
	ErrRecipeTooLarge        = errors.New("recipe source exceeds its size limit")
	ErrTemplateArgument      = errors.New("invalid template function argument")
	ErrTemplateValueEncoding = errors.New("recipe template value is not valid UTF-8")
	// ErrCookRenderBudget is a cook whose renders together ran out of
	// its budget (cookBudget). It is always returned as a
	// *CookBudgetError naming the counter.
	ErrCookRenderBudget = errors.New("cook exceeded its render budget")
	// ErrTooManyIncludes is a cook, or an uploaded recipe's own include
	// list, over the include cap (IMAS_RECIPE_MAX_INCLUDES). It comes
	// joined with ErrInvalidFormat.
	ErrTooManyIncludes = errors.New("recipe includes too many recipes")
)

// The counters of a cook's render budget, as CookBudgetError.Counter.
const (
	CookBudgetTime       = "time"
	CookBudgetBytes      = "bytes"
	CookBudgetIterations = "iterations"
)

// CookBudgetError is ErrCookRenderBudget for one counter: Counter is
// CookBudgetTime, CookBudgetBytes or CookBudgetIterations and Limit the
// limit it ran out of, as text ("10s", "8388608").
type CookBudgetError struct {
	Counter string
	Limit   string
}

func (e *CookBudgetError) Error() string {
	return fmt.Sprintf("%s: %s", ErrCookRenderBudget, e.Exceeded())
}

// Exceeded names the counter and its limit, as "total render time over
// 10s".
func (e *CookBudgetError) Exceeded() string {
	what := map[string]string{
		CookBudgetTime:       "total render time",
		CookBudgetBytes:      "total rendered bytes",
		CookBudgetIterations: "total range iterations",
	}[e.Counter]
	return what + " over " + e.Limit
}

func (e *CookBudgetError) Unwrap() error { return ErrCookRenderBudget }

// cookBudget is one cook's render budget (see "Bounded work"): its
// limits, taken from the limits in force when the cook starts, and what
// every render of the cook has used so far. A cook renders its recipes one
// after another, so a budget is never shared between goroutines; each cook
// makes its own (newCookBudget).
type cookBudget struct {
	timeLimit  time.Duration
	bytesLimit int
	rangeLimit int

	timeUsed  time.Duration
	bytesUsed int
	rangeUsed int
}

func newCookBudget() *cookBudget {
	return &cookBudget{
		timeLimit:  cookRenderTimeout,
		bytesLimit: cookMaxRenderedBytes,
		rangeLimit: cookMaxRangeIterations,
	}
}

// exhausted is the error for counter running out.
func (b *cookBudget) exhausted(counter string) error {
	limit := b.timeLimit.String()
	switch counter {
	case CookBudgetBytes:
		limit = strconv.Itoa(b.bytesLimit)
	case CookBudgetIterations:
		limit = strconv.Itoa(b.rangeLimit)
	}
	return &CookBudgetError{Counter: counter, Limit: limit}
}

// removedTemplateFuncs are refused wherever they appear in a recipe.
var removedTemplateFuncs = []string{"env", "call", "html", "js"}

// Names of the functions sandboxTemplateTree inserts. A recipe calling
// them directly gains nothing.
const (
	rangeGuardFunc = "imasRangeGuard"
	rangeTickFunc  = "imasRangeTick"
)

// templateValue is a string that came from outside the recipe's own text:
// a prop, a fact or the sprout ID, or anything computed from one. See
// "Template values" above.
type templateValue string

// String is what text/template (through fmt) prints for v: a placeholder,
// never v itself.
func (v templateValue) String() string { return encodeTemplatePlaceholder(string(v)) }

// renderState is one render's deadline, budgets and props, and the
// budget of the cook the render is part of.
type renderState struct {
	tenantID  string
	sproutID  string
	deadline  time.Time
	rangeLeft int

	// cook is the cook's budget; cookDeadline is when the cook's time
	// runs out if this render keeps going. start is when the render
	// began: its time is charged to cook from there, so a render stopped
	// at cookDeadline is charged the whole of what was left.
	cook         *cookBudget
	cookDeadline time.Time
	start        time.Time

	propsLoaded bool
	props       map[string]string
}

// newRenderState starts one render charged to cook, a cook's budget.
// Every render has one: there is no render outside a budget.
func newRenderState(cook *cookBudget, tenantID, sproutID string) *renderState {
	now := time.Now()
	return &renderState{
		tenantID:     tenantID,
		sproutID:     sproutID,
		deadline:     now.Add(RecipeRenderTimeout),
		rangeLeft:    maxRangeIterations,
		cook:         cook,
		cookDeadline: now.Add(cook.timeLimit - cook.timeUsed),
		start:        now,
	}
}

// check fails a render past its own deadline (ErrTemplateTimeout) or past
// its cook's (ErrCookRenderBudget), whichever is earlier; at the same
// moment, its own.
func (rs *renderState) check() error {
	now := time.Now()
	if rs.cookDeadline.Before(rs.deadline) && now.After(rs.cookDeadline) {
		return rs.cook.exhausted(CookBudgetTime)
	}
	if now.After(rs.deadline) {
		return ErrTemplateTimeout
	}
	return nil
}

// prop returns the sprout's prop name, loading all of the sprout's props
// with one query on first use. An exact name match wins; otherwise the
// first case-insensitive match, as the database's collation would.
func (rs *renderState) prop(name string) string {
	if !rs.propsLoaded {
		rs.propsLoaded = true
		rs.props = map[string]string{}
		for k, v := range props.GetPropsForTenant(rs.tenantID, rs.sproutID) {
			if s, ok := v.(string); ok {
				rs.props[k] = s
			}
		}
	}
	if v, ok := rs.props[name]; ok {
		return v
	}
	for k, v := range rs.props {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// templateString unwraps a template function argument: a string, or a
// templateValue (tainted is then true).
func templateString(v any) (s string, tainted bool, err error) {
	switch x := v.(type) {
	case string:
		return x, false, nil
	case templateValue:
		return string(x), true, nil
	default:
		return "", false, fmt.Errorf("%w: want a string, got %T", ErrTemplateArgument, v)
	}
}

// templateStrings unwraps a list argument: []string, []templateValue or
// []any of strings and templateValues.
func templateStrings(v any) ([]string, bool, error) {
	switch x := v.(type) {
	case []string:
		return x, false, nil
	case []templateValue:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = string(e)
		}
		return out, true, nil
	case []any:
		out := make([]string, len(x))
		tainted := false
		for i, e := range x {
			s, t, err := templateString(e)
			if err != nil {
				return nil, false, err
			}
			out[i], tainted = s, tainted || t
		}
		return out, tainted, nil
	default:
		return nil, false, fmt.Errorf("%w: want a list of strings, got %T", ErrTemplateArgument, v)
	}
}

// templateResult wraps s as a templateValue if tainted, after checking its
// size.
func templateResult(s string, tainted bool) (any, error) {
	if len(s) > maxTemplateValueBytes {
		return nil, ErrTemplateValueTooBig
	}
	if tainted {
		return templateValue(s), nil
	}
	return s, nil
}

// unwrapFormatArgs replaces every templateValue in args by its content, so
// fmt formats the content rather than the placeholder, and reports whether
// there was one.
func unwrapFormatArgs(args []any) ([]any, bool) {
	out := make([]any, len(args))
	tainted := false
	for i, a := range args {
		if v, ok := a.(templateValue); ok {
			out[i], tainted = string(v), true
			continue
		}
		out[i] = a
	}
	return out, tainted
}

// checkFormat refuses a printf format with a '*' or '[' (width, precision
// or argument index from the arguments) or a width or precision over
// maxFormatWidth.
func checkFormat(format string) error {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
	verb:
		for i++; i < len(format); i++ {
			c := format[i]
			switch {
			case c == '*' || c == '[':
				return fmt.Errorf("%w: printf width, precision and argument indexes must be literal", ErrTemplateArgument)
			case c >= '0' && c <= '9':
				j := i
				for j < len(format) && format[j] >= '0' && format[j] <= '9' {
					j++
				}
				if n, err := strconv.Atoi(format[i:j]); err != nil || n > maxFormatWidth {
					return fmt.Errorf("%w: printf width or precision over %d", ErrTemplateArgument, maxFormatWidth)
				}
				i = j - 1
			case c == '+' || c == '-' || c == '#' || c == ' ' || c == '.':
			default:
				break verb
			}
		}
	}
	return nil
}

// stringFunc1 adapts a string-to-string function to template values: the
// result is a templateValue if the argument was.
func (rs *renderState) stringFunc1(f func(string) string) func(any) (any, error) {
	return func(v any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		s, tainted, err := templateString(v)
		if err != nil {
			return nil, err
		}
		return templateResult(f(s), tainted)
	}
}

// stringPredicate adapts a two-string predicate to template values.
func (rs *renderState) stringPredicate(f func(string, string) bool) func(any, any) (bool, error) {
	return func(a, b any) (bool, error) {
		if err := rs.check(); err != nil {
			return false, err
		}
		sa, _, err := templateString(a)
		if err != nil {
			return false, err
		}
		sb, _, err := templateString(b)
		if err != nil {
			return false, err
		}
		return f(sa, sb), nil
	}
}

func removedTemplateFunc(name string) func(...any) (string, error) {
	return func(...any) (string, error) {
		return "", fmt.Errorf("%w: %s", ErrTemplateFuncRemoved, name)
	}
}

// populateFuncMap returns the functions a recipe template may call for
// one render (see "Function map" above). rs supplies the sprout, the
// deadline and the range budget.
func populateFuncMap(rs *renderState) template.FuncMap {
	v := template.FuncMap{}

	// Removed: refused at parse time by sandboxTemplateTree, and failing
	// here as well. Overriding call, html and js replaces the builtins.
	for _, name := range removedTemplateFuncs {
		v[name] = removedTemplateFunc(name)
	}

	// The sprout's own data, as template values.
	v["props"] = func(name string) (templateValue, error) {
		if err := rs.check(); err != nil {
			return "", err
		}
		return templateValue(rs.prop(name)), nil
	}
	v["hostname"] = func() (templateValue, error) {
		if err := rs.check(); err != nil {
			return "", err
		}
		if h := rs.prop(facts.PropHostname); h != "" {
			return templateValue(h), nil
		}
		return templateValue(rs.sproutID), nil
	}
	v["sproutID"] = func() templateValue { return templateValue(rs.sproutID) }

	// String helpers.
	v["join"] = func(list any, sep any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		elems, t1, err := templateStrings(list)
		if err != nil {
			return nil, err
		}
		sepS, t2, err := templateString(sep)
		if err != nil {
			return nil, err
		}
		size := len(sepS) * max(len(elems)-1, 0)
		for _, e := range elems {
			size += len(e)
		}
		if size > maxTemplateValueBytes {
			return nil, ErrTemplateValueTooBig
		}
		return templateResult(strings.Join(elems, sepS), t1 || t2)
	}
	v["split"] = func(s any, sep any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		str, t1, err := templateString(s)
		if err != nil {
			return nil, err
		}
		sepS, t2, err := templateString(sep)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(str, sepS)
		if !t1 && !t2 {
			return parts, nil
		}
		out := make([]templateValue, len(parts))
		for i, p := range parts {
			out[i] = templateValue(p)
		}
		return out, nil
	}
	v["replace"] = func(s, old, repl any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		str, t1, err := templateString(s)
		if err != nil {
			return nil, err
		}
		oldS, t2, err := templateString(old)
		if err != nil {
			return nil, err
		}
		newS, t3, err := templateString(repl)
		if err != nil {
			return nil, err
		}
		n := strings.Count(str, oldS)
		if len(str)+n*(len(newS)-len(oldS)) > maxTemplateValueBytes {
			return nil, ErrTemplateValueTooBig
		}
		return templateResult(strings.ReplaceAll(str, oldS, newS), t1 || t2 || t3)
	}
	v["contains"] = rs.stringPredicate(strings.Contains)
	v["hasPrefix"] = rs.stringPredicate(strings.HasPrefix)
	v["hasSuffix"] = rs.stringPredicate(strings.HasSuffix)
	v["trimSpace"] = rs.stringFunc1(strings.TrimSpace)
	v["upper"] = rs.stringFunc1(strings.ToUpper)
	v["lower"] = rs.stringFunc1(strings.ToLower)
	v["title"] = rs.stringFunc1(cases.Title(language.English, cases.Compact).String)

	// Path helpers: string operations only, never the filesystem.
	v["base"] = rs.stringFunc1(filepath.Base)
	v["dir"] = rs.stringFunc1(filepath.Dir)
	v["ext"] = rs.stringFunc1(filepath.Ext)
	v["cleanPath"] = rs.stringFunc1(filepath.Clean)

	// Default value: returns fallback if value is empty.
	v["default"] = func(fallback, value any) (any, error) {
		s, _, err := templateString(value)
		if err != nil {
			return nil, err
		}
		if _, _, err := templateString(fallback); err != nil {
			return nil, err
		}
		if s == "" {
			return fallback, nil
		}
		return value, nil
	}

	// Conditional: ternary-style helper for templates.
	v["ternary"] = func(trueVal, falseVal any, cond bool) any {
		if cond {
			return trueVal
		}
		return falseVal
	}

	// Formatting builtins, replaced by capped, template-value-aware
	// versions.
	v["printf"] = func(format string, args ...any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		if err := checkFormat(format); err != nil {
			return nil, err
		}
		plain, tainted := unwrapFormatArgs(args)
		return templateResult(fmt.Sprintf(format, plain...), tainted)
	}
	v["print"] = func(args ...any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		plain, tainted := unwrapFormatArgs(args)
		return templateResult(fmt.Sprint(plain...), tainted)
	}
	v["println"] = func(args ...any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		plain, tainted := unwrapFormatArgs(args)
		return templateResult(fmt.Sprintln(plain...), tainted)
	}
	v["urlquery"] = func(args ...any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		plain, tainted := unwrapFormatArgs(args)
		return templateResult(url.QueryEscape(fmt.Sprint(plain...)), tainted)
	}

	// Inserted by sandboxTemplateTree.
	v[rangeGuardFunc] = func(val any) (any, error) {
		if err := rs.check(); err != nil {
			return nil, err
		}
		rv := reflect.ValueOf(val)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map:
		default:
			return nil, fmt.Errorf("%w: range over %T", ErrTemplateConstruct, val)
		}
		if rv.Len() > rs.rangeLeft {
			return nil, ErrTemplateRangeTooLong
		}
		if rv.Len() > rs.cook.rangeLimit-rs.cook.rangeUsed {
			return nil, rs.cook.exhausted(CookBudgetIterations)
		}
		rs.rangeLeft -= rv.Len()
		rs.cook.rangeUsed += rv.Len()
		return val, nil
	}
	v[rangeTickFunc] = func() (string, error) { return "", rs.check() }

	return v
}

// renderLimitWriter is the template's output: it refuses to grow past
// MaxRenderedRecipeBytes or what is left of the cook's byte budget, or to
// write after the deadline. Written bytes are charged to the cook as they
// are written.
type renderLimitWriter struct {
	rs  *renderState
	buf bytes.Buffer
}

func (w *renderLimitWriter) Write(p []byte) (int, error) {
	if err := w.rs.check(); err != nil {
		return 0, err
	}
	if w.buf.Len()+len(p) > MaxRenderedRecipeBytes {
		return 0, ErrTemplateOutputTooBig
	}
	cook := w.rs.cook
	if len(p) > cook.bytesLimit-cook.bytesUsed {
		return 0, cook.exhausted(CookBudgetBytes)
	}
	cook.bytesUsed += len(p)
	return w.buf.Write(p)
}

// executeRecipeTemplate parses file as a recipe template under the
// restrictions above and executes it for rs's sprout. The output still
// holds template-value placeholders; substituteTemplateValues resolves
// them. The time from rs's start to the return is charged to rs's cook.
func executeRecipeTemplate(rs *renderState, recipeName string, file []byte) ([]byte, error) {
	defer func() { rs.cook.timeUsed += time.Since(rs.start) }()
	if rs.cook.timeUsed >= rs.cook.timeLimit {
		return nil, rs.cook.exhausted(CookBudgetTime)
	}
	if len(file) > MaxRecipeSourceBytes {
		return nil, ErrRecipeTooLarge
	}
	temp := template.New(recipeName)
	temp.Funcs(populateFuncMap(rs))
	rt, err := temp.Parse(string(file))
	if err != nil {
		return nil, err
	}
	if len(rt.Templates()) > 1 {
		return nil, fmt.Errorf("%w: define and block", ErrTemplateConstruct)
	}
	if rt.Tree == nil || rt.Tree.Root == nil {
		return []byte{}, nil
	}
	if err := sandboxTemplateTree(rt.Tree.Root); err != nil {
		return nil, err
	}
	rt.Option("missingkey=error")
	w := &renderLimitWriter{rs: rs}
	if err := rt.Execute(w, nil); err != nil {
		// Surface the limit errors as themselves; text/template wraps
		// errors from functions and writers.
		for _, limit := range []error{ErrTemplateTimeout, ErrTemplateOutputTooBig} {
			if errors.Is(err, limit) {
				return nil, limit
			}
		}
		if budgetErr, ok := errors.AsType[*CookBudgetError](err); ok {
			return nil, budgetErr
		}
		return nil, err
	}
	return w.buf.Bytes(), nil
}

// sandboxTemplateTree checks a parsed recipe template and rewrites it in
// place (see "Bounded work" above): it refuses {{template}} and the
// removed functions, sends every range pipeline through rangeGuardFunc and
// starts every range body with rangeTickFunc.
func sandboxTemplateTree(n parse.Node) error {
	switch n := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := sandboxTemplateTree(c); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		return sandboxTemplateTree(n.Pipe)
	case *parse.IfNode:
		return sandboxBranch(&n.BranchNode)
	case *parse.WithNode:
		return sandboxBranch(&n.BranchNode)
	case *parse.RangeNode:
		if err := sandboxBranch(&n.BranchNode); err != nil {
			return err
		}
		n.Pipe.Cmds = append(n.Pipe.Cmds, identCommand(rangeGuardFunc, n.Pipe.Position()))
		tick := &parse.ActionNode{
			NodeType: parse.NodeAction,
			Pos:      n.Position(),
			Line:     n.Line,
			Pipe: &parse.PipeNode{
				NodeType: parse.NodePipe,
				Pos:      n.Position(),
				Line:     n.Line,
				Cmds:     []*parse.CommandNode{identCommand(rangeTickFunc, n.Position())},
			},
		}
		if n.List == nil {
			n.List = &parse.ListNode{NodeType: parse.NodeList, Pos: n.Position()}
		}
		n.List.Nodes = append([]parse.Node{tick}, n.List.Nodes...)
	case *parse.TemplateNode:
		return fmt.Errorf("%w: template %q", ErrTemplateConstruct, n.Name)
	case *parse.PipeNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Cmds {
			if err := sandboxTemplateTree(c); err != nil {
				return err
			}
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			if err := sandboxTemplateTree(a); err != nil {
				return err
			}
		}
	case *parse.ChainNode:
		return sandboxTemplateTree(n.Node)
	case *parse.IdentifierNode:
		if slices.Contains(removedTemplateFuncs, n.Ident) {
			return fmt.Errorf("%w: %s", ErrTemplateFuncRemoved, n.Ident)
		}
	}
	return nil
}

func sandboxBranch(b *parse.BranchNode) error {
	if err := sandboxTemplateTree(b.Pipe); err != nil {
		return err
	}
	if err := sandboxTemplateTree(b.List); err != nil {
		return err
	}
	return sandboxTemplateTree(b.ElseList)
}

func identCommand(name string, pos parse.Pos) *parse.CommandNode {
	return &parse.CommandNode{
		NodeType: parse.NodeCommand,
		Pos:      pos,
		Args:     []parse.Node{parse.NewIdentifier(name).SetTree(nil).SetPos(pos)},
	}
}

// ValidateRecipeSource renders src as a recipe template the way a cook
// would, for a sprout with no props, under the same function map and
// limits (in a budget of its own, as a cook of this one recipe), and
// parses the result as YAML. It is for checking a recipe before it is
// stored (the SaaS API upload, REC.1); it reads no props. It refuses a
// recipe whose own rendered include list has more entries than the include
// cap (ErrTooManyIncludes), but resolves no includes: a recipe may include
// one uploaded later, so the cook-time budget and include cap
// (resolveRecipeSteps) are the enforcement.
func ValidateRecipeSource(name string, src []byte) error {
	rs := newRenderState(newCookBudget(), "", "validation-sprout")
	rs.propsLoaded = true
	rs.props = map[string]string{}
	out, err := executeRecipeTemplate(rs, name, src)
	if err != nil {
		return err
	}
	b, err := substituteTemplateValues(out)
	if err != nil {
		return err
	}
	recipe, err := unmarshalRecipe(b)
	if err != nil {
		return err
	}
	// A malformed include list is left to the cook, as before S4; only
	// its length is checked here.
	if includes, err := includesFromMap(recipe); err == nil && len(includes) > maxRecipeIncludes {
		return tooManyIncludes()
	}
	return nil
}

// tooManyIncludes is the error for a cook, or an uploaded recipe, over
// the include cap.
func tooManyIncludes() error {
	return fmt.Errorf("%w: %w: more than %d recipes included", ErrInvalidFormat, ErrTooManyIncludes, maxRecipeIncludes)
}

// SendCookEvent triggers a recipe cook on sproutID, over tenantID's
// NATS connection (see SetFarmerConnGetter) — the sprout's own
// tenant, not necessarily whichever tenant happens to be "current" for the
// process. It is SendCookEventContext with context.Background().
func SendCookEvent(tenantID, sproutID string, recipeID RecipeName, JID string, test bool, opts ...CookOption) error {
	return SendCookEventContext(context.Background(), tenantID, sproutID, recipeID, JID, test, opts...)
}

// SendCookEventContext is SendCookEvent with a caller-supplied context,
// which bounds the recipe reads from object storage that prepare the
// dispatch.
func SendCookEventContext(ctx context.Context, tenantID, sproutID string, recipeID RecipeName, JID string, test bool, opts ...CookOption) error {
	validSteps, err := resolveRecipeSteps(ctx, tenantID, sproutID, recipeID)
	if err != nil {
		return err
	}
	var co cookOptions
	for _, opt := range opts {
		opt(&co)
	}
	// If a target step was requested, prune the tree to that step plus the
	// transitive closure of its requisite dependencies.
	if co.targetStep != "" {
		pruned, pruneErr := PruneToTarget(validSteps, co.targetStep)
		if pruneErr != nil {
			return pruneErr
		}
		validSteps = pruned
	}
	env := RecipeEnvelope{
		JobID:        JID,
		Steps:        validSteps,
		Test:         test,
		InvokedBy:    co.invokedBy,
		DispatchedAt: time.Now().UTC(),
	}
	// Stage before the push so the pull-readable copy (see stage.go) is
	// never older than what the sprout was just sent.
	if err := stageRecipe(ctx, tenantID, sproutID, env); err != nil {
		return err
	}
	if co.stageGuard != nil {
		if guardErr := co.stageGuard(); guardErr != nil {
			if err := UnstageRecipe(ctx, tenantID, sproutID); err != nil {
				return errors.Join(guardErr, fmt.Errorf("cook: removing staged recipe for %s/%s: %w", tenantID, sproutID, err))
			}
			return guardErr
		}
	}
	return sendEnvelope(tenantID, sproutID, env)
}

// SendStepsEvent sends steps to sproutID as one cook job under JID, the
// same way SendCookEvent sends a rendered recipe, for a job farmer builds
// itself rather than reading from the recipe store: today only
// internal.sprout.action's self_update (internal/natsapi/sprout_action.go),
// whose single step is the sprout's selfupdate ingredient.
func SendStepsEvent(tenantID, sproutID, JID string, steps []Step) error {
	return sendEnvelope(tenantID, sproutID, RecipeEnvelope{JobID: JID, Steps: steps, DispatchedAt: time.Now().UTC()})
}

// DispatchRecorder records a job farmer is about to dispatch: tenantID's
// sproutID is sent env. internal/jobs installs one (SetDispatchRecorder)
// to write the job's creation record, which it used to read off the bus
// before cook dispatches were sealed (sealed.go).
type DispatchRecorder func(tenantID, sproutID string, env RecipeEnvelope)

var (
	dispatchRecorderMu sync.RWMutex
	dispatchRecorder   DispatchRecorder
)

// SetDispatchRecorder installs fn as the DispatchRecorder every dispatch
// calls; nil removes it.
func SetDispatchRecorder(fn DispatchRecorder) {
	dispatchRecorderMu.Lock()
	defer dispatchRecorderMu.Unlock()
	dispatchRecorder = fn
}

func recordDispatch(tenantID, sproutID string, env RecipeEnvelope) {
	dispatchRecorderMu.RLock()
	fn := dispatchRecorder
	dispatchRecorderMu.RUnlock()
	if fn != nil {
		fn(tenantID, sproutID, env)
	}
}

// sendEnvelope delivers rEnvelope to sproutID over tenantID's own
// connection, sealed to the sprout (sealed.go), and waits for the
// sprout's acknowledgement. The job is recorded (DispatchRecorder) once
// the request is ready to send, before it is sent, so its creation record
// is in place before the sprout's first step event.
func sendEnvelope(tenantID, sproutID string, rEnvelope RecipeEnvelope) error {
	JID := rEnvelope.JobID
	log.Noticef("cooking sprout %s: %s", sproutID, JID)
	farmerConn, err := farmerBus.Conn(tenantID)
	if err != nil {
		return fmt.Errorf("cook: %w", err)
	}
	req, reqID, err := cookBoundary.request(tenantID, sproutID, rEnvelope)
	if err != nil {
		return err
	}
	recordDispatch(tenantID, sproutID, rEnvelope)
	msg, err := farmerConn.RequestMsg(req, 30*time.Second)
	if err != nil {
		return err
	}
	ack, err := cookBoundary.ack(tenantID, sproutID, reqID, msg)
	if err != nil {
		return err
	}
	if !ack.Acknowledged {
		return errors.New("sprout did not acknowledge recipe")
	}
	if ack.JobID != JID {
		return errors.New("sprout acknowledged recipe but returned wrong JobID")
	}
	return nil
}

// resolveRecipeSteps reads recipeID and everything it (transitively)
// includes from the object store, renders each for sproutID, and returns
// the validated step list a cook dispatch is built from. Every byte comes
// from the shared bucket (see store.go), never replica-local disk, so any
// farmer replica resolves the same recipe to the same steps.
//
// Every render of both phases, finding the includes and building the
// steps, is charged to one budget made here (cookBudget, "Bounded work");
// when it runs out the cook fails with ErrCookRenderBudget, before
// anything is staged or dispatched.
func resolveRecipeSteps(ctx context.Context, tenantID, sproutID string, recipeID RecipeName) ([]Step, error) {
	basepath := getBasePath()
	budget := newCookBudget()
	includes, err := collectAllIncludes(ctx, budget, tenantID, sproutID, basepath, recipeID)
	if err != nil {
		return nil, err
	}
	recipesteps := make(map[string]interface{})
	for _, inc := range includes {
		// load all imported files into recipefile list
		fp, fpErr := ResolveRecipeFilePath(ctx, tenantID, basepath, inc)
		if fpErr != nil {
			log.Errorf("could not find include %s: %v", inc, fpErr)
			if errors.Is(fpErr, ErrRecipeStoreNotConfigured) {
				return nil, fpErr
			}
			return nil, errors.Join(ErrNoRecipe, fpErr)
		}
		f, fpErr := readRecipe(ctx, fp)
		if fpErr != nil {
			return nil, fpErr
		}
		b, renderErr := renderRecipeTemplate(budget, tenantID, sproutID, fp, f)
		if renderErr != nil {
			return nil, renderErr
		}
		var recipe map[string]interface{}
		marshallErr := yaml.Unmarshal(b, &recipe)
		if marshallErr != nil {
			return nil, marshallErr
		}
		m, loadErr := stepsFromMap(recipe)
		if loadErr != nil {
			return nil, loadErr
		}
		// range over all keys under each recipe ID for matching ingredients
		recipesteps, err = joinMaps(recipesteps, m)
		if err != nil {
			return nil, err
		}
	}
	for id, step := range recipesteps {
		switch s := step.(type) {
		case map[string]interface{}:
			if len(s) != 1 {
				return nil, errors.Join(ErrInvalidFormat, fmt.Errorf("recipe %s must have one directive, but has %d", id, len(s)))
			}

		default:
			return nil, errors.Join(ErrInvalidFormat, fmt.Errorf("recipe %s must me a map[string]interface{} but found %T", id, step))
		}
	}
	steps, err := makeRecipeSteps(recipesteps)
	if err != nil {
		return nil, err
	}
	tree, err := validateRecipeTree(steps)
	if err != nil {
		return nil, err
	}
	validSteps := []Step{}
	for _, step := range tree {
		validSteps = append(validSteps, *step)
	}
	return validSteps, nil
}

func GenerateJobID() string {
	return uuid.New().String()
}

// ResolveRecipeFilePath resolves a dot-notation RecipeName to an object
// key in the recipe store (see store.go) for a sprout of tenantID: under
// tenants/<tenant_id>/recipes/ first, then under basepath, the
// platform-wide prefix (config.RecipeDir / IMAS_RECIPE_DIR, see
// getBasePath), never under another tenant's prefix. Within each prefix
// "<name>/init.imas" is tried before "<name>.imas", and a name ending in
// ".imas" names that file only. See "Recipe key layout" in store.go.
//
// An invalid name is ErrNoRecipe (joined with ErrInvalidRecipeName). With
// no store configured it returns ErrRecipeStoreNotConfigured, not
// ErrNoRecipe — there is no local-disk fallback.
func ResolveRecipeFilePath(ctx context.Context, tenantID, basepath string, recipeID RecipeName) (string, error) {
	return resolveRecipeKey(ctx, tenantID, basepath, recipeID)
}
