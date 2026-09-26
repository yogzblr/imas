package lgpo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrLGPOMethodUndefined = errors.New("lgpo method undefined")
	ErrMissingADMX         = errors.New("lgpo: missing admx path")
	ErrMissingClass        = errors.New("lgpo: missing or invalid class (want machine or user)")
	ErrMissingState        = errors.New("lgpo: missing or invalid state (want enabled or disabled)")
)

// Compile-time interface check.
var _ cook.RecipeCooker = LGPO{}

// LGPO is a imas ingredient for managing Windows Local Group Policy
// Administrative Template settings. "name" is the policy's ADMX <policy
// name="..."> identifier (not its display name).
//
// Required properties for both methods: name, admx, class ("machine" or
// "user"). "present" additionally requires state ("enabled" or
// "disabled") and, for policies with required elements, an "elements" map
// keyed by element ID. "adml" and "pol_path" are optional on both.
type LGPO struct {
	id     string
	method string
	params map[string]interface{}
}

func (l LGPO) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := LGPO{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (l LGPO) validate() error {
	set, err := l.PropertiesForMethod(l.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if !v.IsReq {
			continue
		}
		switch v.Key {
		case "name":
			if name, _ := l.params[v.Key].(string); name == "" {
				return ingredients.ErrMissingName
			}
		case "admx":
			if admx, _ := l.params[v.Key].(string); admx == "" {
				return ErrMissingADMX
			}
		case "class":
			if _, err := parseClass(l.params[v.Key]); err != nil {
				return err
			}
		case "state":
			if _, err := parseState(l.params[v.Key]); err != nil {
				return err
			}
		default:
			if _, ok := l.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func parseClass(raw interface{}) (string, error) {
	s, _ := raw.(string)
	switch strings.ToLower(s) {
	case "machine":
		return "Machine", nil
	case "user":
		return "User", nil
	default:
		return "", ErrMissingClass
	}
}

func parseState(raw interface{}) (State, error) {
	s, _ := raw.(string)
	switch strings.ToLower(s) {
	case "enabled":
		return StateEnabled, nil
	case "disabled":
		return StateDisabled, nil
	default:
		return "", ErrMissingState
	}
}

// defaultPolPath returns the well-known location of the local GPO
// registry.pol file for class ("Machine" or "User"), rooted at
// %SystemRoot% (falling back to C:\Windows if unset — this is a pure
// string computation, safe to call on any OS; it only resolves to a real
// path when the sprout is actually running on Windows).
func defaultPolPath(class string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	sub := "Machine"
	if strings.EqualFold(class, "user") {
		sub = "User"
	}
	return filepath.Join(root, "System32", "GroupPolicy", sub, "registry.pol")
}

// loadPolicy resolves the "name"/"admx"/"adml" params into a Policy,
// checking it against the requested class.
func (l LGPO) loadPolicy() (Policy, string, error) {
	name, _ := l.params["name"].(string)
	admxPath, _ := l.params["admx"].(string)
	class, err := parseClass(l.params["class"])
	if err != nil {
		return Policy{}, "", err
	}

	policies, err := LoadADMX(admxPath)
	if err != nil {
		return Policy{}, "", fmt.Errorf("lgpo: loading %s: %w", admxPath, err)
	}
	var res *Resources
	if admlPath, _ := l.params["adml"].(string); admlPath != "" {
		res, err = LoadADML(admlPath)
		if err != nil {
			return Policy{}, "", fmt.Errorf("lgpo: loading %s: %w", admlPath, err)
		}
	}
	p, err := FindPolicy(policies, name, res)
	if err != nil {
		return Policy{}, "", err
	}
	if !strings.EqualFold(p.Class, class) && !strings.EqualFold(p.Class, "both") {
		return Policy{}, "", fmt.Errorf("lgpo: policy %q is class %q, not %q", name, p.Class, class)
	}

	polPath, _ := l.params["pol_path"].(string)
	if polPath == "" {
		polPath = defaultPolPath(class)
	}
	return p, polPath, nil
}

func (l LGPO) elementValues() map[string]interface{} {
	m, _ := l.params["elements"].(map[string]interface{})
	return m
}

// readPolFile loads polPath, treating a missing file as an empty (but
// valid) registry.pol document, since a freshly installed machine has no
// local GPO file until the first policy is ever set.
func readPolFile(polPath string) (*File, error) {
	data, err := os.ReadFile(polPath)
	if errors.Is(err, os.ErrNotExist) {
		return NewFile(), nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func writePolFile(polPath string, f *File) error {
	if err := os.MkdirAll(filepath.Dir(polPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(polPath, f.Bytes(), 0o644)
}

func (l LGPO) dispatch(ctx context.Context, test bool) (cook.Result, error) {
	switch l.method {
	case "present":
		return l.present(ctx, test)
	case "absent":
		return l.absent(ctx, test)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrLGPOMethodUndefined, fmt.Errorf("method %s undefined", l.method))
	}
}

func (l LGPO) Test(ctx context.Context) (cook.Result, error) {
	return l.dispatch(ctx, true)
}

func (l LGPO) Apply(ctx context.Context) (cook.Result, error) {
	return l.dispatch(ctx, false)
}

func (l LGPO) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case "present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "ADMX policy name attribute"},
			ingredients.MethodProps{Key: "admx", Type: "string", IsReq: true, Description: "path to the .admx file defining this policy"},
			ingredients.MethodProps{Key: "adml", Type: "string", IsReq: false, Description: "path to the matching .adml file, for display text"},
			ingredients.MethodProps{Key: "class", Type: "string", IsReq: true, Description: "machine or user"},
			ingredients.MethodProps{Key: "state", Type: "string", IsReq: true, Description: "enabled or disabled"},
			ingredients.MethodProps{Key: "pol_path", Type: "string", IsReq: false, Description: "override the target registry.pol path"},
		}.ToMap(), nil
	case "absent":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "ADMX policy name attribute"},
			ingredients.MethodProps{Key: "admx", Type: "string", IsReq: true, Description: "path to the .admx file defining this policy"},
			ingredients.MethodProps{Key: "adml", Type: "string", IsReq: false, Description: "path to the matching .adml file, for display text"},
			ingredients.MethodProps{Key: "class", Type: "string", IsReq: true, Description: "machine or user"},
			ingredients.MethodProps{Key: "pol_path", Type: "string", IsReq: false, Description: "override the target registry.pol path"},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrLGPOMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (l LGPO) Methods() (string, []string) {
	return "lgpo", []string{"absent", "present"}
}

func (l LGPO) Properties() (map[string]interface{}, error) {
	m := map[string]interface{}{}
	b, err := json.Marshal(l.params)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func init() {
	ingredients.RegisterAllMethods(LGPO{})
}
