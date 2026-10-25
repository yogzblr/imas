package windsc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients"
)

type exitError int

func (e exitError) ExitCode() int { return int(e) }
func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// wsmanErr is UAT I.win_dsc.applied's failure on Run 2 on rc.21, when the
// DSC cmdlets opened their own WS-Management session to localhost.
const wsmanErr = `Test-DscConfiguration : The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".
    + CategoryInfo          : ConnectionError: (root/Microsoft/...gurationManager:String) [Test-DscConfiguration], CimException
    + FullyQualifiedErrorId : HRESULT 0x80338012,Test-DscConfiguration`

// Every DSC cmdlet goes through a CIM session to localhost over DCOM,
// never the cmdlet's own WS-Management session.
func TestScriptsUseADcomCimSession(t *testing.T) {
	for name, s := range map[string]string{"test": testScript(`C:\Windows\Temp\x`), "apply": applyScript(`C:\Windows\Temp\x`)} {
		for _, want := range []string{
			"New-CimSession -ComputerName localhost -SessionOption (New-CimSessionOption -Protocol Dcom)",
			"-CimSession $imasCim",
			"Remove-CimSession -CimSession $imasCim",
			"over DCOM failed",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s script lacks %q:\n%s", name, want, s)
			}
		}
		if strings.Contains(s, "-Protocol Wsman") || strings.Contains(s, "-ComputerName localhost -Port") {
			t.Errorf("%s script uses WS-Management:\n%s", name, s)
		}
	}
	if !strings.Contains(testScript(`C:\it's`), `$imasPath = 'C:\it''s'`) {
		t.Error("the path must be quoted")
	}
}

func TestParseInDesiredState(t *testing.T) {
	tests := []struct {
		out     string
		want    bool
		ids     string
		wantErr bool
	}{
		{`{"InDesiredState":true,"ResourceId":[]}`, true, "", false},
		{`{"InDesiredState":false}`, false, "", false},
		{`{"InDesiredState":false,"ResourceId":["[File]Marker"]}`, false, "[File]Marker", false},
		{`[{"InDesiredState":true,"ResourceId":["[File]Ignored"]},{"InDesiredState":false,"ResourceId":["[File]B"]}]`, false, "[File]B", false},
		{`[{"InDesiredState":true}]`, true, "", false},
		{``, false, "", true},
		{`[]`, false, "", true},
		{`{"Other":1}`, false, "", true},
		{`not json`, false, "", true},
	}
	for _, tt := range tests {
		got, ids, err := parseInDesiredState(tt.out)
		if got != tt.want || strings.Join(ids, ",") != tt.ids || (err != nil) != tt.wantErr {
			t.Errorf("parseInDesiredState(%q) = %v, %q, %v", tt.out, got, ids, err)
		}
	}
}

func fake(t *testing.T, fn func(script string) (string, error)) *[]string {
	t.Helper()
	var scripts []string
	orig := runPowerShell
	runPowerShell = func(_ context.Context, script string, _ time.Duration) (string, error) {
		scripts = append(scripts, script)
		return fn(script)
	}
	t.Cleanup(func() { runPowerShell = orig })
	return &scripts
}

func parse(t *testing.T) Dsc {
	t.Helper()
	c, err := (Dsc{}).Parse("id1", methodApplied, map[string]interface{}{"name": "imas-uat", "path": `C:\Windows\Temp\imas-uat-dsc-x`})
	if err != nil {
		t.Fatal(err)
	}
	return c.(Dsc)
}

func TestApplyAppliesThenIsIdempotent(t *testing.T) {
	applied := false
	scripts := fake(t, func(s string) (string, error) {
		if strings.Contains(s, "SendConfigurationApply") {
			applied = true
			return "", nil
		}
		return fmt.Sprintf(`{"InDesiredState":%v}`, applied), nil
	})
	res, err := parse(t).Apply(context.Background())
	if err != nil || !res.Changed || len(*scripts) != 2 {
		t.Fatalf("first: res=%+v err=%v scripts=%d", res, err, len(*scripts))
	}
	res, err = parse(t).Apply(context.Background())
	if err != nil || res.Changed {
		t.Fatalf("second: res=%+v err=%v", res, err)
	}
}

func TestFailureCarriesTheCmdletError(t *testing.T) {
	fake(t, func(string) (string, error) {
		return "", ingredients.CommandError("powershell.exe", exitError(1), nil, []byte(wsmanErr))
	})
	_, err := parse(t).Test(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the LCM's TestConfiguration of") || !strings.Contains(err.Error(), "HRESULT 0x80338012") {
		t.Fatalf("err = %v", err)
	}
	var ee interface{ ExitCode() int }
	if !errors.As(err, &ee) {
		t.Error("exit status lost")
	}
}

// The resources the LCM reports out of the desired state are named in the
// step's note, so a run that keeps reapplying says which one (W11 CI).
func TestNoteNamesTheResourcesNotInTheDesiredState(t *testing.T) {
	fake(t, func(string) (string, error) {
		return `{"InDesiredState":false,"ResourceId":["[File]Marker"]}`, nil
	})
	res, err := parse(t).Test(context.Background())
	if err != nil || !res.Changed || len(res.Notes) != 1 || !strings.Contains(res.Notes[0].String(), "would be applied (not in the desired state: [File]Marker)") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// The LCM is asked through its own CIM methods (W11 CI: Test-DscConfiguration
// -Path over DCOM sent a configuration the LCM could not parse):
// TestConfiguration with the MOF's bytes, length-prefixed only if the LCM
// refuses them as a syntax error, its answer always the InDesiredState
// object parseInDesiredState reads, and no answer an error;
// SendConfigurationApply with the bytes alone.
func TestScriptsCallTheLCMMethods(t *testing.T) {
	test, apply := testScript(`C:\x`), applyScript(`C:\x`)
	for _, want := range []string{"-MethodName TestConfiguration", "[BitConverter]::GetBytes([int]($imasBytes.Length + 4)) + $imasBytes", "InDesiredState = [bool]$imasR.InDesiredState", "if ($null -eq $imasR.InDesiredState) { throw", "TestConfiguration -Arguments @{ ConfigurationData = $imasBytes }", "-notmatch 'Syntax Error') { throw }", "TestConfiguration -Arguments @{ ConfigurationData = $imasData }", "ResourceId = @($imasR.ResourceId", "localhost.mof"} {
		if !strings.Contains(test, want) {
			t.Errorf("test script lacks %q:\n%s", want, test)
		}
	}
	if !strings.Contains(apply, "-MethodName SendConfigurationApply") || !strings.Contains(apply, "ConfigurationData = $imasBytes; Force = $true") {
		t.Errorf("apply script:\n%s", apply)
	}
	// A nonzero ReturnValue fails both, and a directory with several MOFs
	// and no localhost.mof is refused rather than its first MOF applied
	// (review on #319).
	for name, s := range map[string]string{"test": test, "apply": apply} {
		for _, want := range []string{"if ($imasR.ReturnValue) { throw", "$imasMofs.Count -gt 1) { throw"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s script lacks %q:\n%s", name, want, s)
			}
		}
	}
	if strings.Contains(test+apply, "Test-DscConfiguration") || strings.Contains(test+apply, "Start-DscConfiguration") {
		t.Error("the scripts still use the cmdlets")
	}
}
