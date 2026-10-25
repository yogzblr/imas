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
	if !strings.Contains(testScript(`C:\it's`), `-Path 'C:\it''s'`) {
		t.Error("the path must be quoted")
	}
	if !strings.Contains(applyScript(`C:\x`), "Start-DscConfiguration -Path 'C:\\x' -CimSession $imasCim -Wait -Force") {
		t.Errorf("apply script:\n%s", applyScript(`C:\x`))
	}
}

func TestParseInDesiredState(t *testing.T) {
	tests := []struct {
		out     string
		want    bool
		wantErr bool
	}{
		{`{"InDesiredState":true}`, true, false},
		{`{"InDesiredState":false}`, false, false},
		{`[{"InDesiredState":true},{"InDesiredState":false}]`, false, false},
		{`[{"InDesiredState":true}]`, true, false},
		{``, false, true},
		{`{"Other":1}`, false, true},
		{`not json`, false, true},
	}
	for _, tt := range tests {
		got, err := parseInDesiredState(tt.out)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("parseInDesiredState(%q) = %v, %v", tt.out, got, err)
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
		if strings.Contains(s, "Start-DscConfiguration") {
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
	if err == nil || !strings.Contains(err.Error(), "Test-DscConfiguration -Path") || !strings.Contains(err.Error(), "HRESULT 0x80338012") {
		t.Fatalf("err = %v", err)
	}
	var ee interface{ ExitCode() int }
	if !errors.As(err, &ee) {
		t.Error("exit status lost")
	}
}
