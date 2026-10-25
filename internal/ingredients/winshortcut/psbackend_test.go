package winshortcut

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients"
)

type exitError uint32

func (e exitError) ExitCode() int { return int(e) }
func (e exitError) Error() string { return fmt.Sprintf("exit status %d", uint32(e)) }

type childCall struct {
	script  string
	env     []string
	timeout time.Duration
}

// fakeChild replaces runPowerShellEnv: it records each child and answers
// with out and err.
func fakeChild(t *testing.T, out string, err error) *[]childCall {
	t.Helper()
	var calls []childCall
	orig := runPowerShellEnv
	runPowerShellEnv = func(_ context.Context, script string, env []string, timeout time.Duration) (string, error) {
		calls = append(calls, childCall{script, env, timeout})
		return out, err
	}
	t.Cleanup(func() { runPowerShellEnv = orig })
	return &calls
}

func decodeRequest(t *testing.T, env []string) shortcutRequest {
	t.Helper()
	if len(env) != 1 || !strings.HasPrefix(env[0], inputEnv+"=") {
		t.Fatalf("env = %q", env)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(env[0], inputEnv+"="))
	if err != nil {
		t.Fatal(err)
	}
	var req shortcutRequest
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

// The shortcut work runs in a child powershell.exe, with the recipe's
// values in its environment, never in the script text.
func TestSaveRunsInAChildWithTheRequestInTheEnvironment(t *testing.T) {
	calls := fakeChild(t, "", nil)
	path := `C:\Users\Public\Desktop\it's $(evil).lnk`
	state := shortcutState{TargetPath: `C:\Windows\notepad.exe`, Arguments: `"; Remove-Item C:\ -Recurse #`, WindowStyle: 1}
	if err := (psShortcutBackend{}).Save(context.Background(), path, state); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("calls = %d", len(*calls))
	}
	c := (*calls)[0]
	if c.script != saveScript || strings.Contains(c.script, "evil") || strings.Contains(c.script, "Remove-Item") {
		t.Errorf("the script must be the fixed save script:\n%s", c.script)
	}
	if c.timeout != childTimeout {
		t.Errorf("timeout = %v, want %v", c.timeout, childTimeout)
	}
	req := decodeRequest(t, c.env)
	if req.Path != path || req.State == nil || *req.State != state {
		t.Errorf("request = %+v", req)
	}
	for _, want := range []string{"New-Object -ComObject WScript.Shell", "$shell.CreateShortcut($req.Path)", "$lnk.Save()", "$env:" + inputEnv} {
		if !strings.Contains(saveScript, want) {
			t.Errorf("save script lacks %q", want)
		}
	}
}

func TestLoadParsesTheChildsJSON(t *testing.T) {
	fakeChild(t, `{"TargetPath":"C:\\Windows\\notepad.exe","Arguments":"","Description":"d","WorkingDirectory":"","IconLocation":",0","WindowStyle":1,"Hotkey":""}`+"\r\n", nil)
	got, err := (psShortcutBackend{}).Load(context.Background(), `C:\x.lnk`)
	if err != nil {
		t.Fatal(err)
	}
	want := shortcutState{TargetPath: `C:\Windows\notepad.exe`, Description: "d", IconLocation: ",0", WindowStyle: 1}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// A shortcut saved with no icon reads back ",0": no change.
	desired := shortcutState{TargetPath: `C:\Windows\notepad.exe`, Description: "d", WindowStyle: 1}
	if !got.Equal(desired) {
		t.Error(`IconLocation ",0" must equal no icon`)
	}

	fakeChild(t, "garbage", nil)
	if _, err := (psShortcutBackend{}).Load(context.Background(), `C:\x.lnk`); err == nil || !strings.Contains(err.Error(), "garbage") {
		t.Errorf("err = %v", err)
	}
}

// UAT I.win_shortcut.present, Run 2 on rc.21: the real cook killed the
// sprout. A native fault now ends only the child, and the step fails with
// its NTSTATUS and the child's output.
func TestChildFaultFailsTheStepNotTheSprout(t *testing.T) {
	const accessViolation = 0xC0000005
	fakeChild(t, "", ingredients.CommandError("powershell.exe", exitError(accessViolation), nil, []byte("")))
	dir := t.TempDir()
	path := filepath.Join(dir, "uat.lnk")
	orig := backend
	backend = psShortcutBackend{}
	t.Cleanup(func() { backend = orig })

	res, err := newShortcut(methodPresent, map[string]interface{}{"name": path, "target": `C:\Windows\notepad.exe`}).Apply(context.Background())
	if err == nil || !res.Failed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	for _, want := range []string{"faulted (exit 0xC0000005)", "the sprout is unaffected", "Save("} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestChildTimeoutIsAnError(t *testing.T) {
	fakeChild(t, "", ingredients.CommandError("powershell.exe", fmt.Errorf("%w (signal: killed)", context.DeadlineExceeded), nil, nil))
	err := (psShortcutBackend{}).Save(context.Background(), `C:\x.lnk`, shortcutState{TargetPath: "x"})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "child powershell.exe") {
		t.Fatalf("err = %v", err)
	}
}

// Test mode never starts a child when the file is absent; with the file
// there it only reads.
func TestTestModeOnlyReads(t *testing.T) {
	calls := fakeChild(t, `{"TargetPath":"C:\\old.exe","WindowStyle":1}`, nil)
	orig := backend
	backend = psShortcutBackend{}
	t.Cleanup(func() { backend = orig })
	dir := t.TempDir()
	path := filepath.Join(dir, "uat.lnk")
	s := newShortcut(methodPresent, map[string]interface{}{"name": path, "target": `C:\Windows\notepad.exe`})
	if res, err := s.Test(context.Background()); err != nil || !res.Changed || len(*calls) != 0 {
		t.Fatalf("absent file: res=%+v err=%v calls=%d", res, err, len(*calls))
	}
	if err := os.WriteFile(path, []byte("lnk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := s.Test(context.Background()); err != nil || !res.Changed || len(*calls) != 1 || (*calls)[0].script != loadScript {
		t.Fatalf("present file: res=%+v err=%v calls=%+v", res, err, *calls)
	}
}
