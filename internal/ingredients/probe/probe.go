// Package probe implements imas's probe.* ingredients: atomic, single-shot
// checks against an external system (an HTTP endpoint, a database query).
// Each method makes one call and validates the response -- there is no
// internal sequencing or retry-as-a-workflow here. Chaining several probes,
// gating later steps on one, or polling until a condition holds is the
// recipe/cook engine's job (see docs/design/imas-sprout-orchestration.md),
// not probe's.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var ErrProbeMethodUndefined = errors.New("probe method undefined")

const (
	httpMethod     = "http"
	databaseMethod = "database"
)

// Compile-time interface check.
var _ cook.RecipeCooker = Probe{}

type Probe struct {
	id     string
	method string
	params map[string]interface{}
}

func (p Probe) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Probe{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (p Probe) validate() error {
	set, err := p.PropertiesForMethod(p.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if v.IsReq {
			if _, ok := p.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func (p Probe) Test(ctx context.Context) (cook.Result, error) {
	switch p.method {
	case httpMethod:
		return p.probeHTTP(ctx)
	case databaseMethod:
		return p.probeDatabase(ctx)
	default:
		return cook.Result{Succeeded: false, Failed: true},
			errors.Join(ErrProbeMethodUndefined, fmt.Errorf("method %s undefined", p.method))
	}
}

// Apply runs the identical probe as Test. A probe is a read-only check: it
// has no state of its own to converge, so there is nothing distinct for
// Apply to do beyond running the check for real (rather than skipping
// side-effecting parts, as most other ingredients' Test does).
func (p Probe) Apply(ctx context.Context) (cook.Result, error) {
	return p.Test(ctx)
}

func (p Probe) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case httpMethod:
		return httpMethodProps.ToMap(), nil
	case databaseMethod:
		return databaseMethodProps.ToMap(), nil
	default:
		return nil, errors.Join(ErrProbeMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (p Probe) Methods() (string, []string) {
	return "probe", []string{httpMethod, databaseMethod}
}

func (p Probe) Properties() (map[string]interface{}, error) {
	m := map[string]interface{}{}
	b, err := json.Marshal(p.params)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func init() {
	ingredients.RegisterAllMethods(Probe{})
}
