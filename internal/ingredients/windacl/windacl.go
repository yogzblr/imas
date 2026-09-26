//go:build windows

// Package windacl implements imas's win_dacl ingredient: explicit ACE
// (allow/deny) management and inheritance control for files and
// registry keys.
//
// It uses github.com/hectane/go-acl's GetNamedSecurityInfo/
// SetNamedSecurityInfo/SetEntriesInAcl wrappers around the same three
// Win32 calls Salt's win32security-based win_dacl module uses. The
// library ships file-object (SE_FILE_OBJECT) support directly;
// registry-key support (SE_REGISTRY_KEY) reuses the library's own
// object-type constant rather than adding a second dependency, with one
// gap filled locally: the library doesn't wrap
// GetExplicitEntriesFromAclW (needed to read an object's *explicit*
// ACEs back out, separate from whatever it inherits), so win32.go adds
// that call the same way the library adds its own advapi32 wrappers.
// See G.4 in docs/design/imas-windows-parity-addendum.md.
//
// FLAG FOR SECURITY REVIEW: propagation (which ACEs apply to an object
// itself vs. its children) and inheritance (whether an object accepts
// ACEs from its parent) are the two places a small mistake turns into
// an over- or under-broad grant -- see propagation.go and
// inheritance.go for the specific reasoning. This package cross-
// compiles (GOOS=windows) cleanly but has not been exercised against a
// real Windows filesystem or registry; treat it as ready for review,
// not verified.
package windacl

import (
	"context"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

const ingredientName = "win_dacl"

const (
	methodAcePresent          = "ace_present"
	methodAceAbsent           = "ace_absent"
	methodInheritanceEnabled  = "inheritance_enabled"
	methodInheritanceDisabled = "inheritance_disabled"
)

var (
	ErrInvalidObjectType  = errors.New("invalid object_type")
	ErrInvalidAccessMode  = errors.New("invalid access_mode")
	ErrInvalidPropagation = errors.New("invalid propagation")
	ErrInvalidRights      = errors.New("invalid rights")
	ErrUnknownPrincipal   = errors.New("unknown principal")
	ErrInvalidRegistryKey = errors.New("invalid registry key name")
	ErrWouldClearDACL     = errors.New("operation would leave the object with no explicit ACEs")
	ErrMissingProperty    = errors.New("missing required property")
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodAcePresent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "file path, or hive-qualified registry key path"},
		ingredients.MethodProps{Key: "object_type", Type: "string", IsReq: true, Description: "file or registry"},
		ingredients.MethodProps{Key: "principal", Type: "string", IsReq: true, Description: "account name or SID string"},
		ingredients.MethodProps{Key: "access_mode", Type: "string", IsReq: true, Description: "allow or deny"},
		ingredients.MethodProps{Key: "rights", Type: "string", IsReq: true, Description: "read, write, execute, full_control, or a numeric access mask"},
		ingredients.MethodProps{Key: "propagation", Type: "string", IsReq: false, Description: "key, key_and_subkeys (default), or subkeys"},
	},
	methodAceAbsent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "file path, or hive-qualified registry key path"},
		ingredients.MethodProps{Key: "object_type", Type: "string", IsReq: true, Description: "file or registry"},
		ingredients.MethodProps{Key: "principal", Type: "string", IsReq: true, Description: "account name or SID string"},
		ingredients.MethodProps{Key: "access_mode", Type: "string", IsReq: true, Description: "allow or deny"},
	},
	methodInheritanceEnabled: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "file path, or hive-qualified registry key path"},
		ingredients.MethodProps{Key: "object_type", Type: "string", IsReq: true, Description: "file or registry"},
	},
	methodInheritanceDisabled: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "file path, or hive-qualified registry key path"},
		ingredients.MethodProps{Key: "object_type", Type: "string", IsReq: true, Description: "file or registry"},
		ingredients.MethodProps{Key: "copy_inherited", Type: "bool", IsReq: false, Description: "copy currently-inherited ACEs into the explicit list before blocking inheritance (default true); false drops them instead"},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Dacl{}

// Dacl manages a single explicit ACE, or the inheritance state, of a
// file or registry key identified by "name".
type Dacl struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

// aclRequest is the validated, method-specific form of a Dacl's
// parameters, resolved once so Test/Apply share identical logic.
type aclRequest struct {
	displayName   string
	name          string
	seObjType     int32
	principal     string
	accessMode    int32
	rights        uint32
	inheritance   uint32
	copyInherited bool
}

func (d Dacl) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, ok := methodProps[method]; !ok {
		return nil, ingredients.ErrInvalidMethod
	}
	name, _ := params["name"].(string)
	if name == "" {
		return nil, ingredients.ErrMissingName
	}
	parsed := Dacl{id: id, method: method, name: name, params: params}
	if _, err := parsed.request(); err != nil {
		return nil, err
	}
	return parsed, nil
}

// request validates d.params against d.method and returns the resolved
// request used by the method implementations in acepresent.go,
// aceabsent.go and inheritance.go.
func (d Dacl) request() (aclRequest, error) {
	objTypeStr, _ := d.params["object_type"].(string)
	seObjType, err := seObjectType(objTypeStr)
	if err != nil {
		return aclRequest{}, err
	}
	resolvedName, err := resolveObjectName(objTypeStr, d.name)
	if err != nil {
		return aclRequest{}, err
	}
	req := aclRequest{displayName: d.name, name: resolvedName, seObjType: seObjType}

	switch d.method {
	case methodAcePresent, methodAceAbsent:
		principal, _ := d.params["principal"].(string)
		if principal == "" {
			return aclRequest{}, fmt.Errorf("%w: principal", ErrMissingProperty)
		}
		req.principal = principal

		accessModeStr, _ := d.params["access_mode"].(string)
		mode, err := parseAccessMode(accessModeStr)
		if err != nil {
			return aclRequest{}, err
		}
		req.accessMode = mode

		if d.method == methodAcePresent {
			rightsStr, _ := d.params["rights"].(string)
			if rightsStr == "" {
				return aclRequest{}, fmt.Errorf("%w: rights", ErrMissingProperty)
			}
			rights, err := parseRights(rightsStr)
			if err != nil {
				return aclRequest{}, err
			}
			req.rights = rights

			propagationStr, _ := d.params["propagation"].(string)
			inheritance, err := parsePropagation(objTypeStr, propagationStr)
			if err != nil {
				return aclRequest{}, err
			}
			req.inheritance = inheritance
		}
	case methodInheritanceDisabled:
		req.copyInherited = true
		if v, ok := d.params["copy_inherited"].(bool); ok {
			req.copyInherited = v
		}
	case methodInheritanceEnabled:
		// no method-specific fields
	}
	return req, nil
}

func (d Dacl) Methods() (string, []string) {
	return ingredientName, []string{
		methodAcePresent, methodAceAbsent,
		methodInheritanceEnabled, methodInheritanceDisabled,
	}
}

func (d Dacl) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (d Dacl) Properties() (map[string]interface{}, error) {
	return d.params, nil
}

func (d Dacl) Test(ctx context.Context) (cook.Result, error) {
	return d.dispatch(ctx, true)
}

func (d Dacl) Apply(ctx context.Context) (cook.Result, error) {
	return d.dispatch(ctx, false)
}

func (d Dacl) dispatch(ctx context.Context, test bool) (cook.Result, error) {
	req, err := d.request()
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch d.method {
	case methodAcePresent:
		return acePresent(req, test)
	case methodAceAbsent:
		return aceAbsent(req, test)
	case methodInheritanceEnabled:
		return inheritanceEnabled(req, test)
	case methodInheritanceDisabled:
		return inheritanceDisabled(req, test)
	default:
		return cook.Result{Failed: true}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(Dacl{})
}
