package cook

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"github.com/yogzblr/imas/internal/config"
)

// conn is the single connection a sprout process registers via
// RegisterNatsConn — used by CookRecipeEnvelope (sproutcook.go) to publish
// step-completion events back to farmer. Sprout is inherently single-tenant
// (one process, one connection), so this stays a bare package var.
var conn *nats.Conn

func RegisterNatsConn(n *nats.Conn) {
	conn = n
}

// farmerConns holds farmer's own per-tenant NATS connections — the
// counterpart to conn above, but keyed by tenant since a single farmer
// process now holds one connection per tenant (see
// docs/design/imas-tenant-context-threading.md's Option A). Only
// SendCookEvent (farmer's outbound leg, farmercook.go) reads this; sprout
// never calls RegisterFarmerNatsConn.
var (
	farmerConnMu sync.RWMutex
	farmerConns  = map[string]*nats.Conn{}
)

// RegisterFarmerNatsConn installs tenantID's NATS connection for
// SendCookEvent to trigger cooks through. Called once per tenant
// connection by cmd/farmer/main.go.
func RegisterFarmerNatsConn(tenantID string, n *nats.Conn) {
	farmerConnMu.Lock()
	defer farmerConnMu.Unlock()
	farmerConns[tenantID] = n
}

// UnregisterFarmerNatsConn removes tenantID's connection — called when
// that tenant is deprovisioned and its connection closed.
func UnregisterFarmerNatsConn(tenantID string) {
	farmerConnMu.Lock()
	defer farmerConnMu.Unlock()
	delete(farmerConns, tenantID)
}

func farmerConnFor(tenantID string) *nats.Conn {
	farmerConnMu.RLock()
	defer farmerConnMu.RUnlock()
	return farmerConns[tenantID]
}

func makeRecipeSteps(recipes map[string]interface{}) ([]*Step, error) {
	steps := []*Step{}
	for recipeName, recipe := range recipes {
		if _, ok := recipe.(map[string]interface{}); ok {
			step, err := recipeToStep(recipeName, recipe.(map[string]interface{}))
			if err != nil {
				return []*Step{}, err
			}
			steps = append(steps, &step)
		} else {
			return []*Step{}, fmt.Errorf("error: recipe %s must be a map", recipeName)
		}
	}
	return steps, nil
}

func recipeToStep(id string, recipe map[string]interface{}) (Step, error) {
	var step Step
	if len(recipe) != 1 {
		return step, errors.New("error: recipe must have exactly one key")
	}
	for k, v := range recipe {
		rp := strings.Split(k, ".")
		if len(rp) != 2 {
			return step, errors.New("error: recipe key must be in the form ingredient.method")
		}
		mi, ok := v.([]interface{})
		if !ok {
			return Step{}, fmt.Errorf("error: %s must contain a list of properties ([]interface{}), but is a %T", k, v)
		}
		m := make(map[string]interface{})
		for _, interf := range mi {
			if msi, ok := interf.(map[string]interface{}); ok {
				for k, v := range msi {
					m[k] = v
				}
			} else {
				return Step{}, fmt.Errorf("error: %s must contain a list of properties ([]interface{}), but is a %T", k, v)
			}
		}
		reqs, err := extractRequisites(m)
		if err != nil {
			return Step{}, err
		}
		cond, err := extractCond(m)
		if err != nil {
			return Step{}, err
		}
		register, err := extractRegister(m)
		if err != nil {
			return Step{}, err
		}
		secrets, err := extractSecrets(m)
		if err != nil {
			return Step{}, err
		}
		onExit, err := extractOnExit(id, m)
		if err != nil {
			return Step{}, err
		}
		step = Step{
			ID:          StepID(id),
			Ingredient:  Ingredient(rp[0]),
			Method:      rp[1],
			Requisites:  reqs,
			Properties:  m,
			IsRequisite: false,
			Cond:        cond,
			OnExit:      onExit,
			Register:    register,
			Secrets:     secrets,
		}
		return step, nil
	}
	// should be unreachable but need something to satisfy compiler
	return Step{}, errors.New("error: recipe must have exactly one key")
}

// maxRecipeIncludes caps the distinct recipes one cook may include.
const maxRecipeIncludes = 256

func collectAllIncludes(ctx context.Context, tenantID, sproutID, basepath string, recipeID RecipeName) ([]RecipeName, error) {
	// pass in an ID to a Recipe
	recipeFilePath, err := ResolveRecipeFilePath(ctx, tenantID, basepath, recipeID)
	if err != nil {
		return []RecipeName{}, err
	}
	f, err := readRecipe(ctx, recipeFilePath)
	if err != nil {
		return []RecipeName{}, err
	}
	// parse file imports
	starterIncludes, err := extractIncludes(ctx, tenantID, sproutID, basepath, string(recipeID), f)
	if err != nil {
		return []RecipeName{}, err
	}
	starterIncludes = append(starterIncludes, recipeID)
	includeSet := make(map[RecipeName]bool)
	for _, si := range starterIncludes {
		includeSet[si] = false
	}
	includeSet, err = collectIncludesRecurse(ctx, tenantID, sproutID, basepath, includeSet)
	if err != nil {
		return []RecipeName{}, err
	}
	includes := []RecipeName{}
	for inc := range includeSet {
		includes = append(includes, inc)
	}
	return includes, nil
}

func deInterfaceRequisites(req ReqType, v interface{}) (RequisiteSet, error) {
	requisites := []Requisite{}
	switch v := v.(type) {
	case string:
		requisites = append(requisites, Requisite{StepIDs: []StepID{StepID(v)}, Condition: req})
	case []interface{}:
		ids := []StepID{}
		for i, id := range v {
			if id, ok := id.(string); ok {
				ids = append(ids, StepID(id))
			} else {
				return []Requisite{}, errors.Join(errors.New(string(req)+" must be a string or a list of strings, got "+fmt.Sprintf("%T", v[i])), ErrInvalidFormat)
			}
		}
		requisites = append(requisites, Requisite{StepIDs: ids, Condition: req})
	default:
		return []Requisite{}, errors.Join(errors.New(string(req)+" must be a string or a list of strings, got "+fmt.Sprintf("%T", v)), ErrInvalidFormat)
	}
	return requisites, nil
}

func extractRequisites(step map[string]interface{}) (RequisiteSet, error) {
	rt, ok := step["requisites"]
	// if there isn't a requirements key, there aren't any requirements for this step
	if !ok {
		return []Requisite{}, nil
	}
	requisites := []Requisite{}
	// if there is a requirements key, it must be map[string]interface{} , i.e. map[string]string or map[string][]string
	if rti, ok := rt.([]interface{}); !ok {
		return []Requisite{}, errors.Join(errors.New("error: requirements must be a list of maps"), ErrInvalidFormat)
	} else {
		for _, m := range rti {
			mm, ok := m.(map[string]interface{})
			if !ok {
				return []Requisite{}, errors.Join(errors.New("error: requirements must be a list of maps"), ErrInvalidFormat)
			}
			for k, v := range mm {
				switch ReqType(k) {
				case OnChanges, OnFail, Require:
					fallthrough
				case OnChangesAny, OnFailAny, RequireAny:
					reqs, err := deInterfaceRequisites(ReqType(k), v)
					if err != nil {
						return []Requisite{}, err
					}
					requisites = append(requisites, reqs...)
				default:
					return []Requisite{}, errors.New("error: unknown requisite type " + k)
				}
			}
		}
	}
	return requisites, nil
}

// extractCond pulls an optional "cond" (and "cond_negate") key off a step's
// raw property map. "cond" is a shell test (run via the same shell-detection
// rules as cmd.run); the step is skipped unless the test's success, after
// cond_negate is applied, is true.
func extractCond(step map[string]interface{}) (*Cond, error) {
	raw, ok := step["cond"]
	if !ok {
		return nil, nil
	}
	test, ok := raw.(string)
	if !ok || test == "" {
		return nil, errors.Join(ErrInvalidCond, errors.New("cond must be a non-empty string"))
	}
	negate := false
	if n, ok := step["cond_negate"]; ok {
		negate, ok = n.(bool)
		if !ok {
			return nil, errors.Join(ErrInvalidCond, errors.New("cond_negate must be a bool"))
		}
	}
	return &Cond{Test: test, Negate: negate}, nil
}

// extractRegister pulls an optional "register" key off a step's raw property
// map, either a bare variable name or a map with "name" and "sensitive".
func extractRegister(step map[string]interface{}) (*Register, error) {
	raw, ok := step["register"]
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, errors.Join(ErrInvalidRegister, errors.New("register name must not be empty"))
		}
		return &Register{Name: v}, nil
	case map[string]interface{}:
		name, ok := v["name"].(string)
		if !ok || name == "" {
			return nil, errors.Join(ErrInvalidRegister, errors.New("register.name must be a non-empty string"))
		}
		sensitive := false
		if s, ok := v["sensitive"]; ok {
			sensitive, ok = s.(bool)
			if !ok {
				return nil, errors.Join(ErrInvalidRegister, errors.New("register.sensitive must be a bool"))
			}
		}
		return &Register{Name: name, Sensitive: sensitive}, nil
	default:
		return nil, errors.Join(ErrInvalidRegister, fmt.Errorf("register must be a string or map, got %T", raw))
	}
}

// extractSecrets pulls an optional "secrets" key off a step's raw property
// map: a map of variable name to sdb:// ref. Every resolved secret is always
// sensitive, regardless of how it is later used.
func extractSecrets(step map[string]interface{}) (map[string]string, error) {
	raw, ok := step["secrets"]
	if !ok {
		return nil, nil
	}
	sm, ok := raw.(map[string]interface{})
	if !ok {
		return nil, errors.Join(ErrInvalidSecrets, fmt.Errorf("secrets must be a map of variable name to sdb:// ref, got %T", raw))
	}
	out := make(map[string]string, len(sm))
	for k, v := range sm {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, errors.Join(ErrInvalidSecrets, fmt.Errorf("secrets.%s must be a non-empty sdb:// ref string", k))
		}
		out[k] = s
	}
	return out, nil
}

// extractOnExit pulls an optional "on_exit" key off a step's raw property
// map: a list of single-key ingredient.method entries, in the same shape as
// a top-level recipe step, run after the parent step regardless of outcome.
func extractOnExit(parentID string, step map[string]interface{}) ([]Step, error) {
	raw, ok := step["on_exit"]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, errors.Join(ErrInvalidOnExit, fmt.Errorf("on_exit must be a list, got %T", raw))
	}
	steps := make([]Step, 0, len(list))
	for i, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok || len(entry) != 1 {
			return nil, errors.Join(ErrInvalidOnExit, fmt.Errorf("on_exit[%d] must be a single ingredient.method map", i))
		}
		for k, v := range entry {
			rp := strings.Split(k, ".")
			if len(rp) != 2 {
				return nil, errors.Join(ErrInvalidOnExit, fmt.Errorf("on_exit[%d] key %q must be in the form ingredient.method", i, k))
			}
			mi, ok := v.([]interface{})
			if !ok {
				return nil, errors.Join(ErrInvalidOnExit, fmt.Errorf("on_exit[%d] %s must contain a list of properties, got %T", i, k, v))
			}
			props := make(map[string]interface{})
			for _, pi := range mi {
				pm, ok := pi.(map[string]interface{})
				if !ok {
					return nil, errors.Join(ErrInvalidOnExit, fmt.Errorf("on_exit[%d] %s properties must be a list of maps, got %T", i, k, pi))
				}
				for pk, pv := range pm {
					props[pk] = pv
				}
			}
			steps = append(steps, Step{
				ID:         StepID(fmt.Sprintf("%s-on_exit-%d", parentID, i)),
				Ingredient: Ingredient(rp[0]),
				Method:     rp[1],
				Properties: props,
			})
		}
	}
	return steps, nil
}

func joinMaps(a, b map[string]interface{}) (map[string]interface{}, error) {
	c := make(map[string]interface{})
	for k, v := range a {
		c[k] = v
	}
	for k, v := range b {
		if _, ok := c[k]; ok {
			return make(map[string]interface{}), errors.Join(ErrDuplicateKey, fmt.Errorf("error: key %s found in both maps", k))
		}
		c[k] = v
	}
	return c, nil
}

// the basepath and strip the extension
func pathToRecipeName(path string) (RecipeName, error) {
	path = strings.TrimSuffix(path, "."+config.ImasExt)
	path = strings.TrimPrefix(path, getBasePath()+"/")
	return RecipeName(path), nil
}

// attaches a related path to the prefix of a recipe name
// makes no guarantees that the resultant path is valid

func relativeRecipeToAbsolute(ctx context.Context, basepath, relatedRecipePath string, recipeID RecipeName) (RecipeName, error) {
	path := string(recipeID)
	if !strings.HasPrefix(path, ".") {
		if err := ValidateRecipeName(path); err != nil {
			return "", err
		}
		return recipeID, nil
	}
	path = strings.TrimPrefix(path, ".")

	relationBasePath := filepath.Dir(relatedRecipePath)

	path = filepath.Join(relationBasePath, path)
	name, err := pathToRecipeName(path)
	if err != nil {
		return "", err
	}
	// The joined path is a name again, and is resolved under the cooking
	// sprout's tenant and the platform prefix like any other; refuse one
	// that climbed out with "..".
	if err := ValidateRecipeName(string(name)); err != nil {
		return "", err
	}
	return name, nil
}

// RecipeDirEnvVar names an optional environment variable that overrides the
// recipe base path at cook time. This lets an operator point a cook at a
// different recipe tree — e.g. a specific git branch or tag, or a
// per-environment tree, synced under its own prefix — without rewriting the
// farmer config. When unset or empty, config.RecipeDir is used.
const RecipeDirEnvVar = "IMAS_RECIPE_DIR"

// getBasePath returns the object-key prefix recipes resolve under in the
// recipe store (see store.go). Despite the historical "dir" naming it is
// not a local filesystem path: nothing in this package reads recipes from
// local disk.
func getBasePath() string {
	if dir := os.Getenv(RecipeDirEnvVar); dir != "" {
		return dir
	}
	return config.RecipeDir
}

func extractIncludes(ctx context.Context, tenantID, sproutID, basepath, recipePath string, file []byte) ([]RecipeName, error) {
	recipeBytes, err := renderRecipeTemplate(tenantID, sproutID, recipePath, file)
	if err != nil {
		return []RecipeName{}, err
	}
	recipeMap, err := unmarshalRecipe(recipeBytes)
	if err != nil {
		return []RecipeName{}, err
	}
	includeList, err := includesFromMap(recipeMap)
	if err != nil {
		return []RecipeName{}, err
	}
	for i, inc := range includeList {
		tinc := string(inc)
		if strings.HasPrefix(tinc, ".") {

			rel, err := relativeRecipeToAbsolute(ctx, basepath, recipePath, inc)
			if err != nil {
				return []RecipeName{}, err
			}
			includeList[i] = rel
		}
	}
	return includeList, nil
}

// renderRecipeTemplate renders file, a recipe template, for tenantID's
// sproutID and returns YAML in which every prop, fact and sprout ID the
// template printed is a value inside the scalar it was printed into, never
// recipe structure (security review H2). See "Template values" in
// farmercook.go: the template runs with placeholders standing in for those
// values, the YAML is parsed, and substituteTemplateValues replaces them
// in the parsed scalars and encodes the result again. A template that
// printed no such value is returned exactly as it rendered.
func renderRecipeTemplate(tenantID, sproutID, recipeName string, file []byte) ([]byte, error) {
	out, err := executeRecipeTemplate(newRenderState(tenantID, sproutID), recipeName, file)
	if err != nil {
		return []byte{}, err
	}
	return substituteTemplateValues(out)
}

// Template-value placeholders. A placeholder is
// "imasv" + nonce + "x" + hex(value) + "x": letters and digits only, so it
// is inert in every YAML context (plain, quoted, block scalars, keys, flow
// collections) and YAML parsing never splits or changes it. The nonce is
// random per process so a recipe's own text is not mistaken for one by
// accident. Its secrecy is not relied on: substitution makes one pass over
// the parsed scalars, so a value whose content looks like a placeholder is
// inserted as that text, not expanded again.
var (
	templatePlaceholderPrefix = "imasv" + randomPlaceholderNonce() + "x"
	templatePlaceholderRE     = regexp.MustCompile(regexp.QuoteMeta(templatePlaceholderPrefix) + `([0-9a-f]*)x`)
)

func randomPlaceholderNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("cook: no randomness for template placeholders: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func encodeTemplatePlaceholder(value string) string {
	return templatePlaceholderPrefix + hex.EncodeToString([]byte(value)) + "x"
}

// substituteTemplateValues resolves the placeholders in rendered, a
// template's output (see renderRecipeTemplate). If there are none it
// returns rendered unchanged. Otherwise it parses rendered as one YAML
// document, replaces each placeholder inside the scalar (value or key)
// holding it, and encodes the document again, so the encoder quotes or
// block-formats each value as its content needs.
//
// A scalar that is a value, unquoted, and exactly one placeholder takes
// the YAML type its content resolves to as a single plain scalar (so
// "port: {{ props "port" }}" is still a number); anything that would not
// be a scalar (a mapping, a list, an alias) stays a string. Every other
// scalar holding a placeholder, and every key, is a string. Comments are
// dropped.
func substituteTemplateValues(rendered []byte) ([]byte, error) {
	if !bytes.Contains(rendered, []byte(templatePlaceholderPrefix)) {
		return rendered, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(rendered, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 {
		return []byte{}, nil
	}
	if err := substituteNode(&doc, false); err != nil {
		return nil, err
	}
	return yaml.Marshal(&doc)
}

func substituteNode(n *yaml.Node, isKey bool) error {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			if err := substituteNode(c, false); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i, c := range n.Content {
			if err := substituteNode(c, i%2 == 0); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if !strings.Contains(n.Value, templatePlaceholderPrefix) {
			return nil
		}
		whole := templatePlaceholderRE.FindString(n.Value) == n.Value
		var decodeErr error
		value := templatePlaceholderRE.ReplaceAllStringFunc(n.Value, func(ph string) string {
			raw, err := hex.DecodeString(templatePlaceholderRE.FindStringSubmatch(ph)[1])
			if err != nil {
				decodeErr = err
				return ""
			}
			return string(raw)
		})
		if decodeErr != nil {
			return decodeErr
		}
		if !utf8.ValidString(value) {
			return ErrTemplateValueEncoding
		}
		n.Value = value
		n.Tag = "!!str"
		n.Style &^= yaml.TaggedStyle
		if !isKey && whole && n.Style == 0 && plainScalarKeepsType(value) {
			n.Tag = ""
		}
	}
	return nil
}

// plainScalarKeepsType reports whether value, read as a single plain YAML
// scalar, is a number, a bool or null: the types a value printed bare into
// a recipe used to take. It decodes a lone scalar node, so YAML syntax in
// value is never parsed as structure.
func plainScalarKeepsType(value string) bool {
	var out any
	if err := (&yaml.Node{Kind: yaml.ScalarNode, Value: value}).Decode(&out); err != nil {
		return false
	}
	switch out.(type) {
	case nil, bool, int, int64, uint64, float64:
		return true
	}
	return false
}

func unmarshalRecipe(recipe []byte) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	err := yaml.Unmarshal(recipe, &rmap)
	return rmap, err
}

func collectIncludesRecurse(ctx context.Context, tenantID, sproutID, basepath string, starter map[RecipeName]bool) (map[RecipeName]bool, error) {
	allIncluded := false
	for !allIncluded {
		allIncluded = true
		for inc, done := range starter {
			if !done {
				allIncluded = false
				starter[inc] = true
				if len(starter) > maxRecipeIncludes {
					return starter, fmt.Errorf("%w: more than %d recipes included", ErrInvalidFormat, maxRecipeIncludes)
				}
				recipeFilePath, err := ResolveRecipeFilePath(ctx, tenantID, basepath, inc)
				if err != nil {
					return starter, err
				}
				f, err := readRecipe(ctx, recipeFilePath)
				if err != nil {
					return starter, err
				}
				// parse file imports
				eIncludes, err := extractIncludes(ctx, tenantID, sproutID, basepath, string(inc), f)
				if err != nil {
					return starter, err
				}
				for _, inc := range eIncludes {
					if _, ok := starter[inc]; !ok {
						starter[inc] = false
					}
				}

				newIncludes, err := collectIncludesRecurse(ctx, tenantID, sproutID, basepath, starter)
				if err != nil {
					return newIncludes, err
				}
				for inc, done := range newIncludes {
					starter[inc] = done
				}
			}
		}
	}
	return starter, nil
}

func stepsFromMap(recipe map[string]interface{}) (map[string]interface{}, error) {
	if steps, ok := recipe["steps"]; ok {
		switch s := steps.(type) {
		case map[string]interface{}:
			return s, nil
		default:
			return make(map[string]interface{}), fmt.Errorf("steps must be a map[string]interface{}, but found type %T", s)
		}
	}
	return make(map[string]interface{}), nil
}

func includesFromMap(recipe map[string]interface{}) ([]RecipeName, error) {
	if includes, ok := recipe["include"]; ok {
		switch i := includes.(type) {
		case []interface{}:
			inc := []RecipeName{}
			for _, v := range i {
				if s, ok := v.(string); ok {
					inc = append(inc, RecipeName(s))
				} else {
					return []RecipeName{}, fmt.Errorf("include must be a slice of strings, but found type %T in the slice", v)
				}
			}
			return inc, nil
		default:
			return []RecipeName{}, fmt.Errorf("include must be a slice of strings, but found type %T", i)
		}
	}

	return []RecipeName{}, nil
}

func validateRecipeTree(recipes []*Step) ([]*Step, error) {
	_, err := ValidateTrees(recipes)
	return recipes, err
}

// PruneToTarget returns the subset of steps needed to run the single step
// identified by target: the target itself plus the transitive closure of its
// requisite dependencies (every step reachable through Requisites). This lets
// a caller run an individual state (and only what it depends on) instead of
// the whole recipe tree, starting from the root of a given dependency subtree.
//
// The returned steps preserve their original relative order. An error is
// returned if target is not present in steps, or if a requisite references a
// step ID that does not exist in steps.
func PruneToTarget(steps []Step, target StepID) ([]Step, error) {
	byID := make(map[StepID]Step, len(steps))
	for _, s := range steps {
		byID[s.ID] = s
	}
	if _, ok := byID[target]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrTargetStepNotFound, target)
	}

	keep := make(map[StepID]bool)
	var visit func(id StepID) error
	visit = func(id StepID) error {
		if keep[id] {
			return nil
		}
		step, ok := byID[id]
		if !ok {
			return fmt.Errorf("%w: %q", ErrDanglingRequisite, id)
		}
		keep[id] = true
		for _, reqID := range step.Requisites.AllIDs() {
			if err := visit(reqID); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(target); err != nil {
		return nil, err
	}

	pruned := make([]Step, 0, len(keep))
	for _, s := range steps {
		if keep[s.ID] {
			pruned = append(pruned, s)
		}
	}
	return pruned, nil
}
