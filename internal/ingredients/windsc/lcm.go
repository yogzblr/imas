package windsc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// runPowerShell runs powershell.exe; tests replace it.
var runPowerShell = winexec.RunPowerShell

// withDcomSession wraps body, a script that passes -CimSession $imasCim
// to the DSC cmdlets, in a CIM session to localhost over DCOM (see the
// package doc), closed whatever body does. A failure to open the session
// says so, so it is not mistaken for a configuration error.
func withDcomSession(body string) string {
	return strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		"$ProgressPreference = 'SilentlyContinue'",
		"try {",
		"  $imasCim = New-CimSession -ComputerName localhost -SessionOption (New-CimSessionOption -Protocol Dcom)",
		"} catch {",
		"  [Console]::Error.WriteLine(\"win_dsc: opening a CIM session to localhost over DCOM failed: $($_.Exception.Message)\")",
		"  exit 1",
		"}",
		"try {",
		"  " + body,
		"} finally {",
		"  Remove-CimSession -CimSession $imasCim -ErrorAction SilentlyContinue",
		"}",
	}, "\n")
}

// The LCM's own CIM methods, called through the DCOM session (W11 CI on
// Windows Server 2022: Test-DscConfiguration -Path -CimSession over DCOM
// sent the LCM a configuration it could not parse, "Syntax Error. Number
// value is not valid: empty number string"). TestConfiguration takes the
// compiled MOF as ConfigurationData prefixed with the total length as a
// 4-byte little-endian integer; SendConfigurationApply takes the MOF's bytes
// alone (W11 CI: given the prefix it parsed it as MOF text, the same
// "Syntax Error", its buffer starting with the length bytes).
const lcmClass = "-Namespace root/Microsoft/Windows/DesiredStateConfiguration -ClassName MSFT_DSCLocalConfigurationManager"

// mofData is the script lines that read the configuration at path (a .mof
// file, or a directory holding localhost.mof or a single .mof; several
// without localhost.mof are refused, one of them may be another node's) into
// $imasBytes, and the same with its length prefix into $imasData.
func mofData(path string) string {
	return strings.Join([]string{
		"$imasPath = " + winexec.PSQuote(path),
		"  if (Test-Path -LiteralPath $imasPath -PathType Container) {",
		"    $imasMof = Join-Path $imasPath 'localhost.mof'",
		"    if (-not (Test-Path -LiteralPath $imasMof)) {",
		"      $imasMofs = @(Get-ChildItem -LiteralPath $imasPath -Filter *.mof)",
		"      if ($imasMofs.Count -gt 1) { throw \"win_dsc: $imasPath holds $($imasMofs.Count) .mof files and no localhost.mof; name the one for this node\" }",
		"      $imasMof = @($imasMofs | ForEach-Object { $_.FullName })[0]",
		"    }",
		"  } else { $imasMof = $imasPath }",
		"  if (-not $imasMof -or -not (Test-Path -LiteralPath $imasMof)) { throw \"win_dsc: no compiled configuration (.mof) at $imasPath\" }",
		"  $imasBytes = [IO.File]::ReadAllBytes($imasMof)",
		"  [byte[]]$imasData = [BitConverter]::GetBytes([int]($imasBytes.Length + 4)) + $imasBytes",
	}, "\n")
}

// returnValueCheck is the script line that fails when the LCM method's
// result in $imasR reports a nonzero ReturnValue (the methods can report a
// failure there rather than throw).
func returnValueCheck(method string) string {
	return "  if ($imasR.ReturnValue) { throw \"win_dsc: " + method + " returned $($imasR.ReturnValue)\" }\n"
}

// testScript asks the LCM whether the node is in the configuration at
// path, as JSON.
func testScript(path string) string {
	return withDcomSession(mofData(path) + "\n" +
		"  $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName TestConfiguration -Arguments @{ ConfigurationData = $imasData }\n" +
		returnValueCheck("TestConfiguration") +
		"  if ($null -eq $imasR.InDesiredState) { throw \"win_dsc: TestConfiguration returned no InDesiredState (ReturnValue: $($imasR.ReturnValue))\" }\n" +
		"  [pscustomobject]@{ InDesiredState = [bool]$imasR.InDesiredState } | ConvertTo-Json -Compress")
}

// applyScript applies the configuration at path; the method returns once
// the LCM has applied it.
func applyScript(path string) string {
	return withDcomSession(mofData(path) + "\n" +
		"  $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName SendConfigurationApply -Arguments @{ ConfigurationData = $imasBytes; Force = $true }\n" +
		returnValueCheck("SendConfigurationApply"))
}

// parseInDesiredState reads testScript's output. TestConfiguration
// answers one object per node; every one must be in the desired state.
func parseInDesiredState(out string) (bool, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return false, fmt.Errorf("TestConfiguration returned nothing")
	}
	var one struct {
		InDesiredState *bool `json:"InDesiredState"`
	}
	if strings.HasPrefix(out, "[") {
		var many []struct {
			InDesiredState *bool `json:"InDesiredState"`
		}
		if err := json.Unmarshal([]byte(out), &many); err != nil {
			return false, fmt.Errorf("parsing TestConfiguration output: %w (output: %s)", err, out)
		}
		if len(many) == 0 {
			return false, fmt.Errorf("TestConfiguration returned no node")
		}
		for _, n := range many {
			if n.InDesiredState == nil {
				return false, fmt.Errorf("unexpected TestConfiguration output: %s", out)
			}
			if !*n.InDesiredState {
				return false, nil
			}
		}
		return true, nil
	}
	if err := json.Unmarshal([]byte(out), &one); err != nil {
		return false, fmt.Errorf("parsing TestConfiguration output: %w (output: %s)", err, out)
	}
	if one.InDesiredState == nil {
		return false, fmt.Errorf("unexpected TestConfiguration output: %s", out)
	}
	return *one.InDesiredState, nil
}

// inDesiredState asks the LCM about the compiled configuration at d.path.
func (d Dsc) inDesiredState(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	out, err := runPowerShell(ctx, testScript(d.path), timeout)
	if err != nil {
		return false, fmt.Errorf("the LCM's TestConfiguration of %s: %w", d.path, err)
	}
	return parseInDesiredState(out)
}

func (d Dsc) Test(ctx context.Context) (cook.Result, error) {
	ok, err := d.inDesiredState(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if ok {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already in the desired state", d.name))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be applied", d.name))}}, nil
}

func (d Dsc) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	ok, err := d.inDesiredState(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if ok {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already in the desired state", d.name))}}, nil
	}
	if _, err := runPowerShell(ctx, applyScript(d.path), timeout); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("the LCM's SendConfigurationApply of %s: %w", d.path, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been applied", d.name))}}, nil
}
