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
//
// Only init (wincertutil.go) is Windows-only: the rest runs certutil
// through runCLI so its decisions are unit-tested on every platform.
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

// runCLI runs certutil.exe; tests replace it.
var runCLI = winexec.RunCLI

// cryptENotFound is CRYPT_E_NOT_FOUND, the HRESULT certutil.exe exits
// with when -store finds no certificate with the thumbprint.
const cryptENotFound = 0x80092004

// nteNotFound is NTE_NOT_FOUND ("Object was not found."), what certutil
// -store exits with on Windows Server 2022 when the thumbprint isn't in
// the store (W11 CI on windows-2022: "CertUtil: -store command FAILED:
// 0x80090011 (-2146893807 NTE_NOT_FOUND)").
const nteNotFound = 0x80090011

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

// certID is the thumbprint as certutil matches it: hex digits only, no
// spaces (the form certmgr and Get-ChildItem Cert:\ show differ).
func (c Cert) certID() string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(c.thumbprint), " ", ""))
}

// notFoundText is certutil's English "no such certificate" line, a
// fallback for an exit code that is not CRYPT_E_NOT_FOUND.
const notFoundText = "Cannot find object or property"

// exists runs `certutil -store <store> <thumbprint>`. The store is the
// local machine's (certutil's default; -user would pick the calling
// user's): the sprout runs as SYSTEM, so a per-user store would be
// SYSTEM's, not the one an administrator or the UAT check
// (Cert:\LocalMachine\<store>) reads. certutil exits 0 on a match and with
// CRYPT_E_NOT_FOUND or NTE_NOT_FOUND when the thumbprint isn't in the store; its messages
// are localized, so the exit code, not the text, is the signal.
//
// Exit 0 is a match, whatever the output says: for a certificate without
// its private key (the UAT cases' throwaway certificate) certutil prints
// "Cannot find the certificate and private key for decryption." on a
// match, which the earlier text guard read as "absent" -- so cert_present
// added the certificate again on every cook and cert_absent never removed
// it (UAT I.win_certutil.cert_present / cert_absent, Run 2 on rc.21).
func (c Cert) exists(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(c.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	out, runErr := runCLI(ctx, "certutil.exe", []string{
		"-store", c.store(), c.certID(),
	}, timeout)
	if runErr == nil {
		return true, nil
	}
	// CRYPT_E_NOT_FOUND is "doesn't exist", not a failure to determine
	// state. The code is the locale-independent signal; certutil's exact
	// English line is kept as a fallback.
	if code, ok := winexec.ExitCode(runErr); ok && (uint32(code) == cryptENotFound || uint32(code) == nteNotFound) {
		return false, nil
	}
	if _, ok := winexec.ExitCode(runErr); ok && strings.Contains(out, notFoundText) {
		return false, nil
	}
	return false, fmt.Errorf("reading certificate %s from store %s: %w", c.certID(), c.store(), runErr)
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
		if _, err := runCLI(ctx, "certutil.exe", []string{"-addstore", c.store(), path}, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been added", c.name))}}, nil
	case methodCertAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already absent", c.name))}}, nil
		}
		if _, err := runCLI(ctx, "certutil.exe", []string{"-delstore", c.store(), c.certID()}, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been removed", c.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}
