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
// value is not valid: empty number string"). SendConfigurationApply takes
// the MOF's bytes alone as ConfigurationData (W11 CI: given them prefixed
// with the total length as a 4-byte little-endian integer, the form
// PSDesiredStateConfiguration's own SendConfiguration callers use, it parsed
// the prefix as MOF text, the same "Syntax Error"). TestConfiguration is
// sent the bytes alone too, and the prefixed form only if the LCM refuses
// them as a syntax error: given the prefixed form it answered "not in the
// desired state" straight after a successful apply (W11 CI).
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
// path, as JSON: InDesiredState, the resources that are not (ResourceId,
// from WMF 5's ResourcesNotInDesiredState instances or an older flat list),
// and Detail: which form of the MOF the LCM took and everything it
// answered, for the step's note when the node is not in the desired state.
func testScript(path string) string {
	return withDcomSession(mofData(path) + "\n" +
		"  $imasForm = 'bare'\n" +
		"  try {\n" +
		"    $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName TestConfiguration -Arguments @{ ConfigurationData = $imasBytes }\n" +
		"  } catch {\n" +
		"    if ($_.Exception.Message -notmatch 'Syntax Error') { throw }\n" +
		"    $imasForm = 'length-prefixed'\n" +
		"    $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName TestConfiguration -Arguments @{ ConfigurationData = $imasData }\n" +
		"  }\n" +
		returnValueCheck("TestConfiguration") +
		"  if ($null -eq $imasR.InDesiredState) { throw \"win_dsc: TestConfiguration returned no InDesiredState (ReturnValue: $($imasR.ReturnValue))\" }\n" +
		"  $imasDetail = 'MOF sent ' + $imasForm + ' (' + $imasBytes.Length + ' bytes, starting ' + ((@($imasBytes | Select-Object -First 4) | ForEach-Object { '{0:x2}' -f $_ }) -join '') + '); the LCM answered ' + ((@($imasR.PSObject.Properties | Where-Object { $_.Name -notlike 'Cim*' -and $_.Name -ne 'PSComputerName' }) | ForEach-Object { $_.Name + '=' + (@($_.Value | ForEach-Object { if ($_ -is [Microsoft.Management.Infrastructure.CimInstance]) { $_.ResourceId } else { $_ } }) -join ',') }) -join '; ')\n" +
		"  [pscustomobject]@{ InDesiredState = [bool]$imasR.InDesiredState; ResourceId = @(@($imasR.ResourcesNotInDesiredState | ForEach-Object { $_.ResourceId }) + @($imasR.ResourceId) | Where-Object { $_ }); Detail = $imasDetail } | ConvertTo-Json -Compress")
}

// applyScript applies the configuration at path; the method returns once
// the LCM has applied it.
func applyScript(path string) string {
	return withDcomSession(mofData(path) + "\n" +
		"  $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName SendConfigurationApply -Arguments @{ ConfigurationData = $imasBytes; Force = $true }\n" +
		returnValueCheck("SendConfigurationApply"))
}

// testAnswer is one node's answer in testScript's output.
type testAnswer struct {
	InDesiredState *bool    `json:"InDesiredState"`
	ResourceID     []string `json:"ResourceId"`
	Detail         string   `json:"Detail"`
}

// parseInDesiredState reads testScript's output. TestConfiguration
// answers one object per node; every one must be in the desired state.
// It also returns what to say about the nodes that are not: the resources
// reported out of it, else the LCM's whole answer (testAnswer.Detail).
func parseInDesiredState(out string) (bool, []string, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return false, nil, fmt.Errorf("TestConfiguration returned nothing")
	}
	var many []testAnswer
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &many); err != nil {
			return false, nil, fmt.Errorf("parsing TestConfiguration output: %w (output: %s)", err, out)
		}
		if len(many) == 0 {
			return false, nil, fmt.Errorf("TestConfiguration returned no node")
		}
	} else {
		var one testAnswer
		if err := json.Unmarshal([]byte(out), &one); err != nil {
			return false, nil, fmt.Errorf("parsing TestConfiguration output: %w (output: %s)", err, out)
		}
		many = []testAnswer{one}
	}
	ok := true
	var ids []string
	for _, n := range many {
		if n.InDesiredState == nil {
			return false, nil, fmt.Errorf("unexpected TestConfiguration output: %s", out)
		}
		if !*n.InDesiredState {
			ok = false
			if len(n.ResourceID) == 0 && n.Detail != "" {
				ids = append(ids, n.Detail)
				continue
			}
			ids = append(ids, n.ResourceID...)
		}
	}
	return ok, ids, nil
}

// pendingNote names the configuration and, when the LCM said, the
// resources not in the desired state, or else its whole answer.
func (d Dsc) pendingNote(verb string, ids []string) cook.SimpleNote {
	if len(ids) == 0 {
		return cook.SimpleNote(fmt.Sprintf("%s %s", d.name, verb))
	}
	return cook.SimpleNote(fmt.Sprintf("%s %s (not in the desired state: %s)", d.name, verb, strings.Join(ids, ", ")))
}

// inDesiredState asks the LCM about the compiled configuration at d.path.
func (d Dsc) inDesiredState(ctx context.Context) (bool, []string, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return false, nil, err
	}
	out, err := runPowerShell(ctx, testScript(d.path), timeout)
	if err != nil {
		return false, nil, fmt.Errorf("the LCM's TestConfiguration of %s: %w", d.path, err)
	}
	return parseInDesiredState(out)
}

func (d Dsc) Test(ctx context.Context) (cook.Result, error) {
	ok, ids, err := d.inDesiredState(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if ok {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already in the desired state", d.name))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{d.pendingNote("would be applied", ids)}}, nil
}

func (d Dsc) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	ok, ids, err := d.inDesiredState(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if ok {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already in the desired state", d.name))}}, nil
	}
	if _, err := runPowerShell(ctx, applyScript(d.path), timeout); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("the LCM's SendConfigurationApply of %s: %w", d.path, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{d.pendingNote("has been applied", ids)}}, nil
}
