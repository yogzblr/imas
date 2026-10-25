// Package winpsget wraps Salt's win_psget module: installing/removing
// PowerShell modules via PowerShellGet (Install-Module/Uninstall-Module),
// the same PowerShell surface Salt itself shells out to. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
//
// Only init (register.go) is Windows-only: the rest runs PowerShell
// through runPowerShell so the scripts it builds and its decisions are
// unit-tested on every platform.
package winpsget

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_psget"

const (
	methodInstalled = "installed"
	methodRemoved   = "removed"
)

// runPowerShell runs powershell.exe; tests replace it.
var runPowerShell = winexec.RunPowerShell

// installTimeout bounds an install or removal when the step sets no
// timeout: it downloads from a repository (the NuGet provider first, on a
// fresh host), which takes longer than winexec.DefaultTimeout.
const installTimeout = 10 * time.Minute

// The scopes Install-Module accepts.
var scopes = map[string]string{"allusers": "AllUsers", "currentuser": "CurrentUser"}

var methodProps = map[string]ingredients.MethodPropsSet{
	methodInstalled: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "version", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "scope", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "repository", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodRemoved: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = PSGet{}

// PSGet manages a single PowerShell module by name.
type PSGet struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (p PSGet) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	if scope := winexec.StringParamOr(params, "scope", ""); scope != "" {
		if _, ok := scopes[strings.ToLower(scope)]; !ok {
			return nil, fmt.Errorf("invalid scope %q (must be AllUsers or CurrentUser)", scope)
		}
	}
	return PSGet{id: id, method: method, name: name, params: params}, nil
}

func (p PSGet) Methods() (string, []string) {
	return ingredientName, []string{methodInstalled, methodRemoved}
}

func (p PSGet) PropertiesForMethod(method string) (map[string]string, error) {
	props, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return props.ToMap(), nil
}

func (p PSGet) Properties() (map[string]interface{}, error) {
	return p.params, nil
}

// timeouts returns the bound for the state check and for the install or
// removal: the step's timeout for both when it sets one, else
// winexec.DefaultTimeout and installTimeout.
func (p PSGet) timeouts() (check, change time.Duration, err error) {
	raw := winexec.StringParamOr(p.params, "timeout", "")
	check, err = winexec.ParseTimeout(raw)
	if err != nil {
		return 0, 0, err
	}
	if raw == "" {
		return check, installTimeout, nil
	}
	return check, check, nil
}

// checkScript counts the installed copies of the module, of the
// requested version when the step names one.
func (p PSGet) checkScript() string {
	script := "@(Get-Module -ListAvailable -Name " + winexec.PSQuote(p.name)
	if version := winexec.StringParamOr(p.params, "version", ""); version != "" {
		// Both sides as four components, a missing one 0: [version]'5.4'
		// is not -eq an installed 5.4.0, and a prerelease ("2.0.0-beta1")
		// is not a [version] at all (Get-Module reports its base version
		// and keeps the label in the manifest's PSData.Prerelease). The
		// label must match too, none for a stable request, so an installed
		// 2.0.0 is not taken for a requested 2.0.0-beta1 or the reverse.
		script += " | Where-Object { (($_.Version.Major, $_.Version.Minor, [Math]::Max(0, $_.Version.Build), [Math]::Max(0, $_.Version.Revision)) -join '.') -eq " +
			winexec.PSQuote(fourPartVersion(version)) +
			" -and [string]$_.PrivateData.PSData.Prerelease -eq " + winexec.PSQuote(prereleaseLabel(version)) + " }"
	}
	return script + ").Count"
}

// fourPartVersion is a module version as Major.Minor.Build.Revision, the
// missing parts 0, without a prerelease or build suffix.
func fourPartVersion(v string) string {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(strings.TrimSpace(v), ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:4], ".")
}

// prereleaseLabel is a module version's prerelease label ("beta1" of
// "2.0.0-beta1"), without a build suffix; "" for a stable version.
func prereleaseLabel(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[i+1:]
	}
	return ""
}

// installScript installs the module. PowerShellGet 1.0.0.1, the one
// Windows Server 2022 ships, needs the NuGet provider before its first
// install and asks for it interactively, which fails under the sprout;
// so the script makes sure the provider is there, over TLS 1.2 (the
// gallery and the provider feed refuse older protocols, and .NET
// Framework 4.x does not offer TLS 1.2 by default). -Force also answers
// the untrusted-repository prompt for PSGallery. A failure names the
// stage it failed in.
//
// -Scope is given once: the default AllUsers, or the step's scope. UAT
// Run 2 on rc.21 sent "-Scope AllUsers -Scope 'AllUsers'", which
// PowerShell refuses (ParameterAlreadyBound).
func (p PSGet) installScript() string {
	scope := "AllUsers"
	if s := winexec.StringParamOr(p.params, "scope", ""); s != "" {
		scope = scopes[strings.ToLower(s)]
	}
	install := "Install-Module -Name " + winexec.PSQuote(p.name) + " -Force -AllowClobber -Scope " + winexec.PSQuote(scope)
	if version := winexec.StringParamOr(p.params, "version", ""); version != "" {
		install += " -RequiredVersion " + winexec.PSQuote(version)
	}
	if repo := winexec.StringParamOr(p.params, "repository", ""); repo != "" {
		install += " -Repository " + winexec.PSQuote(repo)
	}
	return strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		"$ProgressPreference = 'SilentlyContinue'",
		"$stage = 'TLS 1.2'",
		"try {",
		"  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12",
		"  $stage = 'NuGet provider (Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201)'",
		"  if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {",
		"    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope " + winexec.PSQuote(scope) + " | Out-Null",
		"  }",
		"  $stage = 'Install-Module'",
		"  " + install,
		"} catch {",
		"  [Console]::Error.WriteLine(\"win_psget: $stage failed: $($_.Exception.Message)\")",
		"  exit 1",
		"}",
	}, "\n")
}

func (p PSGet) removeScript() string {
	return "Uninstall-Module -Name " + winexec.PSQuote(p.name) + " -AllVersions -Force -ErrorAction Stop"
}

func (p PSGet) isInstalled(ctx context.Context, timeout time.Duration) (bool, error) {
	out, err := runPowerShell(ctx, p.checkScript(), timeout)
	if err != nil {
		return false, err
	}
	return out != "" && out != "0", nil
}

func (p PSGet) Test(ctx context.Context) (cook.Result, error) {
	check, _, err := p.timeouts()
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	installed, err := p.isInstalled(ctx, check)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch p.method {
	case methodInstalled:
		if installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already installed", p.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be installed", p.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", p.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be removed", p.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (p PSGet) Apply(ctx context.Context) (cook.Result, error) {
	check, change, err := p.timeouts()
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	installed, err := p.isInstalled(ctx, check)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch p.method {
	case methodInstalled:
		if installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already installed", p.name))}}, nil
		}
		if _, err := runPowerShell(ctx, p.installScript(), change); err != nil {
			return cook.Result{Failed: true}, fmt.Errorf("installing module %s: %w", p.name, err)
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been installed", p.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", p.name))}}, nil
		}
		if _, err := runPowerShell(ctx, p.removeScript(), change); err != nil {
			return cook.Result{Failed: true}, fmt.Errorf("removing module %s: %w", p.name, err)
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been removed", p.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}
