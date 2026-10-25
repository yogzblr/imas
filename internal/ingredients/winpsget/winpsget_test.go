package winpsget

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients"
)

// exitError stands in for *exec.ExitError.
type exitError int

func (e exitError) ExitCode() int { return int(e) }
func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// fakePS replaces runPowerShell: the check answers count, Install-Module
// and Uninstall-Module answer installErr.
type fakePS struct {
	count      string
	installErr error
	scripts    []string
	timeouts   []time.Duration
}

func (f *fakePS) install(t *testing.T) {
	t.Helper()
	orig := runPowerShell
	runPowerShell = func(_ context.Context, script string, timeout time.Duration) (string, error) {
		f.scripts = append(f.scripts, script)
		f.timeouts = append(f.timeouts, timeout)
		if strings.HasPrefix(script, "@(Get-Module") {
			return f.count, nil
		}
		return "", f.installErr
	}
	t.Cleanup(func() { runPowerShell = orig })
}

func parse(t *testing.T, method string, params map[string]interface{}) PSGet {
	t.Helper()
	c, err := (PSGet{}).Parse("id1", method, params)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c.(PSGet)
}

// The UAT case's recipe (I.win_psget.installed): scope AllUsers given
// explicitly. Run 2 on rc.21 built "-Scope AllUsers -Scope 'AllUsers'".
func TestInstallScriptBindsScopeOnce(t *testing.T) {
	p := parse(t, methodInstalled, map[string]interface{}{
		"name": "Microsoft.PowerShell.SecretManagement", "repository": "PSGallery", "scope": "AllUsers",
	})
	script := p.installScript()
	if n := strings.Count(script, "Install-Module -Name"); n != 1 {
		t.Fatalf("expected one Install-Module, got %d:\n%s", n, script)
	}
	line := ""
	for _, l := range strings.Split(script, "\n") {
		if strings.Contains(l, "Install-Module -Name") {
			line = l
		}
	}
	if n := strings.Count(line, "-Scope"); n != 1 {
		t.Errorf("Install-Module binds -Scope %d times: %s", n, line)
	}
	for _, want := range []string{"-Scope 'AllUsers'", "-Repository 'PSGallery'", "-Force", "-AllowClobber"} {
		if !strings.Contains(line, want) {
			t.Errorf("Install-Module line lacks %q: %s", want, line)
		}
	}
}

func TestInstallScriptDefaultsAndCurrentUser(t *testing.T) {
	p := parse(t, methodInstalled, map[string]interface{}{"name": "Pester"})
	if !strings.Contains(p.installScript(), "-Force -AllowClobber -Scope 'AllUsers'") {
		t.Errorf("default scope must be AllUsers:\n%s", p.installScript())
	}
	p = parse(t, methodInstalled, map[string]interface{}{"name": "Pester", "scope": "currentuser", "version": "5.4.0"})
	s := p.installScript()
	if !strings.Contains(s, "-Scope 'CurrentUser'") || strings.Contains(s, "-Scope 'AllUsers'") || !strings.Contains(s, "-RequiredVersion '5.4.0'") {
		t.Errorf("script:\n%s", s)
	}
}

// The first install on a fresh Server 2022 (PowerShellGet 1.0.0.1) needs
// the NuGet provider and TLS 1.2, and a failure names its stage.
func TestInstallScriptBootstrapsNuGetOverTLS12(t *testing.T) {
	s := parse(t, methodInstalled, map[string]interface{}{"name": "Pester"}).installScript()
	tls := strings.Index(s, "[Net.SecurityProtocolType]::Tls12")
	nuget := strings.Index(s, "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force")
	install := strings.Index(s, "Install-Module -Name")
	if tls < 0 || nuget < 0 || install < 0 || tls >= nuget || nuget >= install {
		t.Errorf("want TLS 1.2, then the NuGet provider, then Install-Module:\n%s", s)
	}
	if !strings.Contains(s, "$ErrorActionPreference = 'Stop'") || !strings.Contains(s, "$stage failed") || !strings.Contains(s, "exit 1") {
		t.Errorf("a failure must stop and name its stage:\n%s", s)
	}
}

func TestParseRejectsBadScope(t *testing.T) {
	if _, err := (PSGet{}).Parse("id1", methodInstalled, map[string]interface{}{"name": "Pester", "scope": "Machine"}); err == nil {
		t.Error("expected an error for scope Machine")
	}
}

func TestCheckScriptHonoursVersion(t *testing.T) {
	p := parse(t, methodInstalled, map[string]interface{}{"name": "Pester", "version": "5.4.0"})
	if got := p.checkScript(); !strings.Contains(got, "-eq '5.4.0.0'") {
		t.Errorf("check script %q ignores the version", got)
	}
}

func TestApplyInstallsWhenMissing(t *testing.T) {
	f := &fakePS{count: "0"}
	f.install(t)
	res, err := parse(t, methodInstalled, map[string]interface{}{"name": "Pester"}).Apply(context.Background())
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.scripts) != 2 || !strings.Contains(f.scripts[1], "Install-Module") {
		t.Fatalf("scripts: %q", f.scripts)
	}
	if f.timeouts[1] != installTimeout {
		t.Errorf("install timeout = %v, want %v", f.timeouts[1], installTimeout)
	}
}

func TestApplyInstalledIsIdempotent(t *testing.T) {
	f := &fakePS{count: "1"}
	f.install(t)
	res, err := parse(t, methodInstalled, map[string]interface{}{"name": "Pester"}).Apply(context.Background())
	if err != nil || !res.Succeeded || res.Changed || len(f.scripts) != 1 {
		t.Fatalf("res=%+v err=%v scripts=%q", res, err, f.scripts)
	}
}

func TestApplyInstallFailureCarriesTheReason(t *testing.T) {
	f := &fakePS{count: "0", installErr: ingredients.CommandError("powershell.exe", exitError(1), nil,
		[]byte("win_psget: Install-Module failed: No match was found for the specified search criteria and module name 'Nope'."))}
	f.install(t)
	_, err := parse(t, methodInstalled, map[string]interface{}{"name": "Nope"}).Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Install-Module failed: No match was found") || !strings.Contains(err.Error(), "installing module Nope") {
		t.Fatalf("err = %v", err)
	}
	var ee interface{ ExitCode() int }
	if !errors.As(err, &ee) {
		t.Error("the exit status must stay in the chain")
	}
}

func TestStepTimeoutBoundsBothCalls(t *testing.T) {
	f := &fakePS{count: "0"}
	f.install(t)
	if _, err := parse(t, methodInstalled, map[string]interface{}{"name": "Pester", "timeout": "3m"}).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, d := range f.timeouts {
		if d != 3*time.Minute {
			t.Errorf("call %d timeout = %v, want 3m", i, d)
		}
	}
}

func TestRemovedRemovesWhenInstalled(t *testing.T) {
	f := &fakePS{count: "2"}
	f.install(t)
	res, err := parse(t, methodRemoved, map[string]interface{}{"name": "Pester"}).Apply(context.Background())
	if err != nil || !res.Changed || !strings.Contains(f.scripts[1], "Uninstall-Module -Name 'Pester' -AllVersions -Force") {
		t.Fatalf("res=%+v err=%v scripts=%q", res, err, f.scripts)
	}
}

// A requested "5.4" matches an installed 5.4.0, and a prerelease compares
// by its base version (review on #320).
func TestCheckScriptComparesVersionsByFourParts(t *testing.T) {
	for in, want := range map[string]string{"5.4": "5.4.0.0", "5.4.0": "5.4.0.0", "1.2.3.4": "1.2.3.4", "2.0.0-beta1": "2.0.0.0", "3": "3.0.0.0"} {
		if got := fourPartVersion(in); got != want {
			t.Errorf("fourPartVersion(%q) = %q, want %q", in, got, want)
		}
	}
	p := PSGet{name: "M", params: map[string]interface{}{"version": "5.4"}}
	if s := p.checkScript(); !strings.Contains(s, "-eq '5.4.0.0'") || strings.Contains(s, "[version]'5.4'") {
		t.Errorf("check script: %s", s)
	}
}

// A prerelease request matches only that prerelease, and a stable request
// only a stable copy; a manifest may store the label with its leading "-"
// (review on #319 and #320).
func TestCheckScriptComparesThePrereleaseLabel(t *testing.T) {
	for in, want := range map[string]string{"2.0.0-beta1": "beta1", "2.0.0": "", "2.0.0-rc.1+build5": "rc.1", "2.0.0+build5": ""} {
		if got := prereleaseLabel(in); got != want {
			t.Errorf("prereleaseLabel(%q) = %q, want %q", in, got, want)
		}
	}
	for version, label := range map[string]string{"2.0.0-beta1": "'beta1'", "2.0.0": "''"} {
		s := PSGet{name: "M", params: map[string]interface{}{"version": version}}.checkScript()
		if !strings.Contains(s, "-eq '2.0.0.0' -and ([string]$_.PrivateData.PSData.Prerelease).TrimStart('-') -eq "+label+" }") {
			t.Errorf("check script for %s: %s", version, s)
		}
	}
	if s := (PSGet{name: "M", params: map[string]interface{}{}}).checkScript(); strings.Contains(s, "Prerelease") {
		t.Errorf("an unversioned check compares a label: %s", s)
	}
}

// A prerelease version installs with -AllowPrerelease, and fails plainly
// where PowerShellGet has no such parameter; a stable one has neither
// (review on #319).
func TestInstallScriptAllowsAPrerelease(t *testing.T) {
	pre := PSGet{name: "M", params: map[string]interface{}{"version": "2.0.0-beta1"}}.installScript()
	if !strings.Contains(pre, "-RequiredVersion '2.0.0-beta1' -AllowPrerelease") || !strings.Contains(pre, "Parameters.ContainsKey('AllowPrerelease')) { throw") {
		t.Errorf("prerelease install script:\n%s", pre)
	}
	stable := PSGet{name: "M", params: map[string]interface{}{"version": "2.0.0"}}.installScript()
	if strings.Contains(stable, "AllowPrerelease") {
		t.Errorf("stable install script:\n%s", stable)
	}
}
