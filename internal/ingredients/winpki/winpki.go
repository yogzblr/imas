//go:build windows

// Package winpki wraps the core of Salt's win_pki module: importing and
// removing certificates from a Windows certificate store via the PKI
// PowerShell module (Import-Certificate / Cert: drive), the same
// PowerShell surface Salt itself shells out to. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
package winpki

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_pki"

const (
	methodCertPresent = "cert_present"
	methodCertAbsent  = "cert_absent"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodCertPresent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "path", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "thumbprint", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "store_location", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "store_name", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodCertAbsent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "thumbprint", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "store_location", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "store_name", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Cert{}

// Cert manages a single certificate, identified by thumbprint, in a
// Windows certificate store.
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

func (c Cert) certPath() string {
	loc := winexec.StringParamOr(c.params, "store_location", "LocalMachine")
	name := winexec.StringParamOr(c.params, "store_name", "My")
	return fmt.Sprintf(`Cert:\%s\%s`, loc, name)
}

func (c Cert) exists(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(c.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	script := fmt.Sprintf(
		"@(Get-ChildItem -Path %s | Where-Object { $_.Thumbprint -eq %s }).Count",
		winexec.PSQuote(c.certPath()), winexec.PSQuote(c.thumbprint),
	)
	out, err := winexec.RunPowerShell(ctx, script, timeout)
	if err != nil {
		return false, err
	}
	return out != "" && out != "0", nil
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
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be imported", c.name))}}, nil
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
		script := fmt.Sprintf("Import-Certificate -FilePath %s -CertStoreLocation %s", winexec.PSQuote(path), winexec.PSQuote(c.certPath()))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been imported", c.name))}}, nil
	case methodCertAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already absent", c.name))}}, nil
		}
		script := fmt.Sprintf("Remove-Item -Path (Join-Path %s %s) -Force", winexec.PSQuote(c.certPath()), winexec.PSQuote(c.thumbprint))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
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
