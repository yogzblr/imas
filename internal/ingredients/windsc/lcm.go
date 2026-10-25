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
// the MOF's bytes alone as ConfigurationData (given them prefixed with the
// total length as a 4-byte little-endian integer, it parsed the prefix as
// MOF text, the same "Syntax Error").
//
// TestConfiguration given a configuration does not evaluate it there: with
// the compiled MOF bare or length-prefixed, as UTF-16 or UTF-8, it
// answered ReturnValue 0 and InDesiredState=False with no resource in or
// out of the desired state, straight after SendConfigurationApply had
// applied the same bytes (W11 CI). So the test asks about the LCM's
// current configuration instead (TestConfiguration with no arguments, what
// Test-DscConfiguration does), and takes the node to be in this
// configuration's desired state only when
//   - this ingredient last applied this very MOF: Apply records its SHA-256
//     under the sprout's state directory (lcmRecord), so a changed MOF is
//     applied again;
//   - the LCM's current configuration is this one: the resources it
//     evaluated carry this MOF's ResourceIDs and ConfigurationName, so a
//     configuration someone else applied since is not taken for it;
//   - and the LCM says it is in the desired state, having evaluated at
//     least one resource (with no current configuration, as after
//     Remove-DscConfigurationDocument, TestConfiguration fails, which
//     counts as not in it).
//
// Otherwise the note says which of these failed.
const lcmClass = "-Namespace root/Microsoft/Windows/DesiredStateConfiguration -ClassName MSFT_DSCLocalConfigurationManager"

// lcmRecord is where Apply records the SHA-256 of the MOF it last applied:
// the LCM holds one current configuration per node, so one record.
const lcmRecord = `$env:ProgramData\imas\state\sprout\win_dsc\current.sha256`

// mofData is the script lines that read the configuration at path (a .mof
// file, or a directory holding localhost.mof or a single .mof; several
// without localhost.mof are refused, one of them may be another node's) into
// $imasBytes, its SHA-256 into $imasHash, and its ResourceIDs and
// ConfigurationNames, sorted, into $imasWantIds and $imasWantNames.
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
		"  $imasHash = (Get-FileHash -LiteralPath $imasMof -Algorithm SHA256).Hash",
		"  $imasText = [IO.File]::ReadAllText($imasMof)",
		"  $imasWantIds = (@([regex]::Matches($imasText, 'ResourceID\\s*=\\s*\"([^\"]+)\"') | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique) -join '|'",
		"  $imasWantNames = (@([regex]::Matches($imasText, 'ConfigurationName\\s*=\\s*\"([^\"]+)\"') | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique) -join '|'",
		"  $imasRecord = \"" + lcmRecord + "\"",
	}, "\n")
}

// returnValueCheck is the script line that fails when the LCM method's
// result in $imasR reports a nonzero ReturnValue (the methods can report a
// failure there rather than throw).
func returnValueCheck(method string) string {
	return "  if ($imasR.ReturnValue) { throw \"win_dsc: " + method + " returned $($imasR.ReturnValue)\" }\n"
}

// testScript asks whether the node is in the configuration at path (see
// lcmClass), as JSON: InDesiredState, the resources that are not
// (ResourceId), and Detail: why not, for the step's note.
func testScript(path string) string {
	return withDcomSession(mofData(path) + "\n" + strings.Join([]string{
		"  $imasIn = $false; $imasNot = @(); $imasWhy = ''",
		"  $imasRecorded = ''",
		"  if (Test-Path -LiteralPath $imasRecord) { $imasRecorded = ([IO.File]::ReadAllText($imasRecord)).Trim() }",
		"  if ($imasRecorded -ne $imasHash) {",
		"    $imasWhy = 'this ingredient has not applied this configuration (SHA-256 ' + $imasHash + ') as the current one'",
		"  } else {",
		"    $imasR = $null",
		"    try { $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName TestConfiguration } catch { $imasWhy = 'the LCM could not test its current configuration: ' + $_.Exception.Message }",
		"  }",
		"  if ($imasR) {",
		"  " + returnValueCheck("TestConfiguration") +
			"    $imasAll = @(@($imasR.ResourcesInDesiredState) + @($imasR.ResourcesNotInDesiredState) | Where-Object { $_ })",
		"    $imasHaveIds = (@($imasAll | ForEach-Object { $_.ResourceId }) | Sort-Object -Unique) -join '|'",
		"    $imasHaveNames = (@($imasAll | ForEach-Object { $_.ConfigurationName } | Where-Object { $_ }) | Sort-Object -Unique) -join '|'",
		"    if ($imasAll.Count -eq 0) {",
		"      $imasWhy = 'the LCM evaluated no resource of its current configuration'",
		"    } elseif ($imasHaveIds -ne $imasWantIds -or ($imasHaveNames -and $imasHaveNames -ne $imasWantNames)) {",
		"      $imasWhy = 'the LCM''s current configuration is another one (' + $imasHaveNames + ': ' + $imasHaveIds + ')'",
		"    } else {",
		"      $imasIn = [bool]$imasR.InDesiredState",
		"      $imasNot = @($imasR.ResourcesNotInDesiredState | ForEach-Object { $_.ResourceId } | Where-Object { $_ })",
		"      if (-not $imasIn) { $imasWhy = 'the LCM reports it out of the desired state' }",
		"    }",
		"  }",
		"  [pscustomobject]@{ InDesiredState = $imasIn; ResourceId = $imasNot; Detail = $imasWhy } | ConvertTo-Json -Compress",
	}, "\n"))
}

// applyScript applies the configuration at path; the method returns once
// the LCM has applied it. It then records the MOF's SHA-256 (lcmRecord) for
// testScript.
func applyScript(path string) string {
	return withDcomSession(mofData(path) + "\n" +
		"  $imasR = Invoke-CimMethod -CimSession $imasCim " + lcmClass + " -MethodName SendConfigurationApply -Arguments @{ ConfigurationData = $imasBytes; Force = $true }\n" +
		returnValueCheck("SendConfigurationApply") +
		"  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $imasRecord) | Out-Null\n" +
		"  [IO.File]::WriteAllText($imasRecord, $imasHash)")
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
