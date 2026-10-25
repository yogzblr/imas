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

// testScript asks the LCM whether the node is in the configuration at
// path, as JSON. Some parameter sets answer a bare Boolean rather than a
// result object; both become {"InDesiredState": ...}.
func testScript(path string) string {
	return withDcomSession("Test-DscConfiguration -Path " + winexec.PSQuote(path) +
		" -CimSession $imasCim | ForEach-Object { if ($_ -is [bool]) { [pscustomobject]@{ InDesiredState = $_ } } else { $_ | Select-Object -Property InDesiredState } } | ConvertTo-Json -Compress")
}

// applyScript applies the configuration at path and waits for it.
func applyScript(path string) string {
	return withDcomSession("Start-DscConfiguration -Path " + winexec.PSQuote(path) +
		" -CimSession $imasCim -Wait -Force -ErrorAction Stop")
}

// parseInDesiredState reads testScript's output. Test-DscConfiguration
// answers one object per node; every one must be in the desired state.
func parseInDesiredState(out string) (bool, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return false, fmt.Errorf("Test-DscConfiguration returned nothing")
	}
	var one struct {
		InDesiredState *bool `json:"InDesiredState"`
	}
	if strings.HasPrefix(out, "[") {
		var many []struct {
			InDesiredState *bool `json:"InDesiredState"`
		}
		if err := json.Unmarshal([]byte(out), &many); err != nil {
			return false, fmt.Errorf("parsing Test-DscConfiguration output: %w (output: %s)", err, out)
		}
		if len(many) == 0 {
			return false, fmt.Errorf("Test-DscConfiguration returned no node")
		}
		for _, n := range many {
			if n.InDesiredState == nil {
				return false, fmt.Errorf("unexpected Test-DscConfiguration output: %s", out)
			}
			if !*n.InDesiredState {
				return false, nil
			}
		}
		return true, nil
	}
	if err := json.Unmarshal([]byte(out), &one); err != nil {
		return false, fmt.Errorf("parsing Test-DscConfiguration output: %w (output: %s)", err, out)
	}
	if one.InDesiredState == nil {
		return false, fmt.Errorf("unexpected Test-DscConfiguration output: %s", out)
	}
	return *one.InDesiredState, nil
}

// inDesiredState runs Test-DscConfiguration against the compiled
// configuration at d.path.
func (d Dsc) inDesiredState(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	out, err := runPowerShell(ctx, testScript(d.path), timeout)
	if err != nil {
		return false, fmt.Errorf("Test-DscConfiguration -Path %s: %w", d.path, err)
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
		return cook.Result{Failed: true}, fmt.Errorf("Start-DscConfiguration -Path %s: %w", d.path, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been applied", d.name))}}, nil
}
