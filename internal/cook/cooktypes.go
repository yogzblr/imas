package cook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	OnChanges ReqType = "onchanges"
	OnFail    ReqType = "onfail"
	Require   ReqType = "require"

	OnChangesAny ReqType = "onchanges_any"
	OnFailAny    ReqType = "onfail_any"
	RequireAny   ReqType = "require_any"
)

const (
	StepNotStarted CompletionStatus = iota
	StepInProgress
	StepCompleted
	StepFailed
	StepSkipped
)

type (
	CompletionStatus     int
	SproutStepCompletion struct {
		SproutID      string
		CompletedStep StepCompletion
	}
	StepCompletion struct {
		ID               StepID
		CompletionStatus CompletionStatus
		ChangesMade      bool
		Changes          []string
		Started          time.Time     `json:"started,omitempty"`
		Duration         time.Duration `json:"duration,omitempty"`
		// Error is carried on the wire and in job logs as its message
		// string (see MarshalJSON/UnmarshalJSON), so a decoded Error keeps
		// its text but not its identity: errors.Is against a sentinel such
		// as ErrCookTimeout does not hold after a round trip.
		Error error
	}
	RecipeCooker interface {
		Apply(context.Context) (Result, error)
		Test(context.Context) (Result, error)
		Properties() (map[string]interface{}, error)
		Parse(id, method string, properties map[string]interface{}) (RecipeCooker, error)
		Methods() (string, []string)
		PropertiesForMethod(method string) (map[string]string, error)
	}
	RecipeEnvelope struct {
		JobID     string
		Steps     []Step
		Test      bool
		InvokedBy string `json:"invoked_by,omitempty"`
	}
	Ack struct {
		Acknowledged bool
		JobID        string
	}
	RecipeName   string
	Function     string
	StepID       string
	Ingredient   string
	RequisiteSet []Requisite
	Step         struct {
		Ingredient  Ingredient `json:"ingredient" yaml:"ingredient"`
		Method      string     `json:"method" yaml:"method"`
		ID          StepID
		Requisites  RequisiteSet
		Properties  map[string]interface{}
		IsRequisite bool
		// Cond gates whether the step runs at all: a shell test evaluated
		// before Apply/Test, with optional negation. nil means unconditional.
		Cond *Cond
		// OnExit steps run once after the step's Apply/Test, regardless of its
		// outcome (success, failure, or skip via Cond) -- e.g. cleanup that
		// must always happen.
		OnExit []Step
		// Register captures this step's output into a named variable other
		// steps can reference as {NAME} in their own properties.
		Register *Register
		// Secrets maps a variable name to an sdb:// ref; each is resolved via
		// the sdb package immediately before the step runs and is always
		// treated as sensitive (redacted from logs/job history).
		Secrets map[string]string
	}
	// Cond is a shell-evaluated precondition for a step. The step is
	// skipped (StepSkipped) unless the test's exit status, after Negate is
	// applied, indicates success.
	Cond struct {
		Test   string
		Negate bool
	}
	// Register names a variable a step's output should be captured into for
	// use by later steps. Sensitive values are redacted from the persisted
	// job log and from verbose/debug log output.
	Register struct {
		Name      string
		Sensitive bool
	}
	Targets   []StepID
	Requisite struct {
		Condition ReqType
		StepIDs   []StepID
		Steps     []*Step
	}
	Result struct {
		Succeeded bool
		Failed    bool
		Changed   bool
		Notes     []fmt.Stringer
	}
	CookSummary struct {
		Succeeded int
		Failures  int
		Changed   int
		Notes     []fmt.Stringer
	}
	Summary struct {
		Succeeded  int
		InProgress bool
		Failures   int
		Changes    int
		Errors     []error
	}
	SimpleNote string
	ReqType    string
)

// CookerFactory is a function type for creating RecipeCooker instances.
// It is set by the ingredients package to break the import cycle.
var NewRecipeCooker func(id StepID, ingredient Ingredient, method string, params map[string]interface{}) (RecipeCooker, error)

func (r RequisiteSet) AllIDs() []StepID {
	collection := []StepID{}
	for _, reqs := range r {
		collection = append(collection, reqs.StepIDs...)
	}
	return collection
}

func (r RequisiteSet) AllSteps() []*Step {
	collection := []*Step{}
	for _, reqs := range r {
		collection = append(collection, reqs.Steps...)
	}
	return collection
}

func (r RequisiteSet) Equals(other RequisiteSet) bool {
	if len(r) != len(other) {
		return false
	}
	rmap := make(map[ReqType]Requisite)
	omap := make(map[ReqType]Requisite)
	for _, req := range r {
		rmap[req.Condition] = req
	}
	for _, req := range other {
		omap[req.Condition] = req
	}
	for k, req := range rmap {
		oreq, ok := omap[k]
		if !ok {
			return false
		}
		if !req.Equals(oreq) {
			return false
		}
	}
	return true
}

func (r Requisite) Equals(other Requisite) bool {
	if r.Condition != other.Condition {
		return false
	}
	if len(r.StepIDs) != len(other.StepIDs) {
		return false
	}
	rmap := make(map[StepID]StepID)
	omap := make(map[StepID]StepID)
	for _, step := range r.StepIDs {
		rmap[step] = step
	}
	for _, step := range other.StepIDs {
		omap[step] = step
	}
	for k, step := range rmap {
		if omap[k] != step {
			return false
		}
	}
	return true
}

// stepCompletionFields has StepCompletion's fields but none of its methods,
// so (Un)MarshalJSON can delegate to encoding/json without recursing.
type stepCompletionFields StepCompletion

// errLegacyStepError stands in for an Error that an older imas encoded as
// `{}`, which kept that the step errored but lost the message.
var errLegacyStepError = errors.New("step error (message not recorded by the sending imas version)")

// MarshalJSON encodes Error as its message string, or null when Error is
// nil. encoding/json would otherwise write a non-nil error as `{}`, which
// drops the message and cannot be decoded back into an error.
func (s StepCompletion) MarshalJSON() ([]byte, error) {
	var msg *string
	if s.Error != nil {
		m := s.Error.Error()
		msg = &m
	}
	return json.Marshal(struct {
		stepCompletionFields
		Error *string `json:"Error"`
	}{stepCompletionFields(s), msg})
}

// UnmarshalJSON is the inverse of MarshalJSON. It also accepts what older
// versions wrote: null (no error, as in existing job logs) and `{}` (an
// error whose message was lost), so events from not-yet-upgraded sprouts
// are still recorded rather than dropped.
func (s *StepCompletion) UnmarshalJSON(b []byte) error {
	aux := struct {
		stepCompletionFields
		Error json.RawMessage `json:"Error"`
	}{stepCompletionFields: stepCompletionFields(*s)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*s = StepCompletion(aux.stepCompletionFields)
	if aux.Error == nil {
		// Key absent: leave Error as it was, like encoding/json does.
		return nil
	}
	s.Error = decodeStepError(aux.Error)
	return nil
}

func decodeStepError(raw json.RawMessage) error {
	var msg *string
	if err := json.Unmarshal(raw, &msg); err != nil {
		// Not null or a string: the legacy `{}` encoding (or something
		// else we can't read). The step still errored, so keep that.
		return errLegacyStepError
	}
	if msg == nil {
		return nil
	}
	return errors.New(*msg)
}

func (s SimpleNote) String() string {
	return string(s)
}

func Snprintf(format string, a ...any) SimpleNote {
	return SimpleNote(fmt.Sprintf(string(format), a...))
}
