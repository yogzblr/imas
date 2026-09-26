//go:build windows

// Package wincertutil wraps the store-management core of Salt's
// win_pki/certutil-backed workflow: adding/removing a certificate from a
// Windows certificate store via certutil.exe, the same CLI tool Salt's
// own tooling shells out to for this. See G.9 in
// docs/design/imas-windows-parity-addendum.md.
//
// This is deliberately narrower than internal/ingredients/winpki (which
// uses the PowerShell PKI module's Cert: drive): certutil.exe works
// without the PKI module being present and is the tool Salt's own
// win_pki module falls back to for some operations.
package wincertutil

import (
	"context"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_certutil"

const (
	methodCertPresent = "cert_present"
	methodCertAbsent  = "cert_absent"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodCertPresent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "path", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "thumbprint", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "store", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodCertAbsent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "thumbprint", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "store", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Cert{}

// Cert manages a single certificate, identified by thumbprint, in a
// local machine certificate store via certutil.exe.
type Cert struct {
	id         string
	method     string
	name       string
	thumbprint string
	params     map[string]interface{}
}

func (c Cert) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, ok := methodProps[method]; !ok {
		return nil, ingredients.ErrInvalidMethod
	}
	name, ok := winexec.StringParam(params, "name")
	if !ok || name == "" {
		return nil, ingredients.ErrMissingName
	}
	thumbprint, ok := winexec.StringParam(params, "thumbprint")
	if !ok || thumbprint == "" {
		return nil, fmt.Errorf("missing required property thumbprint")
	}
	if method == methodCertPresent {
		if path, ok := winexec.StringParam(params, "path"); !ok || path == "" {
			return nil, fmt.Errorf("missing required property path")
		}
	}
	return Cert{id: id, method: method, name: name, thumbprint: thumbprint, params: params}, nil
}

func (c Cert) Methods() (string, []string) {
	return ingredientName, []string{methodCertPresent, methodCertAbsent}
}

func (c Cert) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (c Cert) Properties() (map[string]interface{}, error) {
	return c.params, nil
}

func (c Cert) store() string {
	return winexec.StringParamOr(c.params, "store", "My")
}

// exists parses `certutil -store <store> <thumbprint>` output. certutil
// prints "CertUtil: -store command completed successfully." on a match
// and an error message (e.g. "Cannot find object or property.") when the
// thumbprint isn't in the store.
func (c Cert) exists(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(c.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	out, runErr := winexec.RunCLI(ctx, "certutil.exe", []string{
		"-store", c.store(), c.thumbprint,
	}, timeout)
	if runErr != nil {
		// certutil exits non-zero when the thumbprint isn't found; that's
		// "doesn't exist", not a failure to determine state.
		if strings.Contains(out, "Cannot find") || strings.Contains(strings.ToLower(out), "not found") {
			return false, nil
		}
		return false, runErr
	}
	return strings.Contains(out, "command completed successfully"), nil
}

func (c Cert) Test(ctx context.Context) (cook.Result, error) {
	present, err := c.exists(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch c.method {
	case methodCertPresent:
		if present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already present", c.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be added", c.name))}}, nil
	case methodCertAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already absent", c.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be removed", c.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (c Cert) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(c.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	present, err := c.exists(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch c.method {
	case methodCertPresent:
		if present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already present", c.name))}}, nil
		}
		path, _ := winexec.StringParam(c.params, "path")
		if _, err := winexec.RunCLI(ctx, "certutil.exe", []string{"-addstore", c.store(), path}, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been added", c.name))}}, nil
	case methodCertAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already absent", c.name))}}, nil
		}
		if _, err := winexec.RunCLI(ctx, "certutil.exe", []string{"-delstore", c.store(), c.thumbprint}, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been removed", c.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(Cert{})
}
