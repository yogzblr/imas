package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/pki"
)

// runCmdRunAgainst runs `imas cmd run uptime -T <target>` in mode against
// the sealed stand-in farmer, which lists accepted and answers cmd.run
// with reply (encoded as farmer encodes it), and returns the output and
// the status the command exited with (0 if it didn't exit).
func runCmdRunAgainst(t *testing.T, mode, target string, accepted []string, reply any) (string, int) {
	t.Helper()
	conn, cleanup := setupTestNATS(t)
	defer cleanup()

	keys := pki.KeysByType{Accepted: pki.KeySet{Sprouts: make([]pki.KeyManager, len(accepted))}}
	for i, id := range accepted {
		keys.Accepted.Sprouts[i] = pki.KeyManager{SproutID: id}
	}
	if _, err := conn.Subscribe("imas.api.pki.list", func(msg *nats.Msg) { natsRespond(msg, keys) }); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Subscribe("imas.api.cmd.run", func(msg *nats.Msg) { natsRespond(msg, reply) }); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	oldMode, oldTarget, oldCohort, oldTimeout := outputMode, sproutTarget, cohortTarget, timeout
	defer func() { outputMode, sproutTarget, cohortTarget, timeout = oldMode, oldTarget, oldCohort, oldTimeout }()
	outputMode, sproutTarget, cohortTarget, timeout = mode, target, "", 2

	status, exits := 0, 0
	oldExit := cmdRunExit
	defer func() { cmdRunExit = oldExit }()
	cmdRunExit = func(code int) { status = code; exits++ }

	out := captureStdout(t, func() {
		cmdCmdRun.Run(cmdCmdRun, []string{"uptime"})
	})
	if exits > 1 {
		t.Errorf("cmd run exited %d times", exits)
	}
	return out, status
}

// farmer's refusal to send cmd.run to a sprout with no box key: the CLI
// shows its text, with the stable code and the re-enroll instruction,
// next to the other sprouts' output.
func TestCmdRunCommand_ShowsFarmersReenrollRefusal(t *testing.T) {
	refusal := &cook.ReenrollRequiredError{Op: "cmd.run", SproutID: "keyless-01"}
	reply := apitypes.TargetedResults{Results: map[string]interface{}{
		"keyless-01": apitypes.CmdRun{Error: refusal},
		"web-01":     apitypes.CmdRun{Stdout: "up 3 days\n"},
	}}
	out, status := runCmdRunAgainst(t, "", "keyless-01,web-01", []string{"keyless-01", "web-01"}, reply)
	if status != 1 {
		t.Errorf("exit status %d, want 1", status)
	}

	if strings.Contains(out, "invalid message") {
		t.Errorf("output reports an invalid message:\n%s", out)
	}
	for _, want := range []string{"keyless-01:", "error: " + refusal.Error(), "[" + cook.ReenrollRequiredCode + "]", "re-enroll", "web-01:", "up 3 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("output doesn't contain %q:\n%s", want, out)
		}
	}
}

// --output json keeps the error text in each sprout's result.
func TestCmdRunCommand_JSONKeepsTheError(t *testing.T) {
	refusal := &cook.ReenrollRequiredError{Op: "cmd.run", SproutID: "keyless-01"}
	reply := apitypes.TargetedResults{Results: map[string]interface{}{"keyless-01": apitypes.CmdRun{Error: refusal}}}
	out, status := runCmdRunAgainst(t, "json", "keyless-01", []string{"keyless-01"}, reply)
	if status != 1 {
		t.Errorf("exit status %d, want 1", status)
	}

	var parsed struct {
		Results map[string]struct {
			Error *string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	got := parsed.Results["keyless-01"].Error
	if got == nil || *got != refusal.Error() {
		t.Errorf("keyless-01's error in the JSON output = %v, want %q\n%s", got, refusal.Error(), out)
	}
}

// An older farmer's reply, with the error encoded as an object: the CLI
// shows that the sprout failed instead of "returned an invalid message!".
func TestCmdRunCommand_OlderFarmersErrorObject(t *testing.T) {
	reply := json.RawMessage(`{"results":{"keyless-01":{"stdout":"","stderr":"","errcode":0,"error":{"Op":"cmd.run","SproutID":"keyless-01"}}}}`)
	out, status := runCmdRunAgainst(t, "", "keyless-01", []string{"keyless-01"}, reply)
	if status != 1 {
		t.Errorf("exit status %d, want 1", status)
	}

	if strings.Contains(out, "invalid message") {
		t.Errorf("output reports an invalid message:\n%s", out)
	}
	if !strings.Contains(out, "keyless-01:") || !strings.Contains(out, "error: ") {
		t.Errorf("output doesn't show keyless-01's error:\n%s", out)
	}
}

// No error: no error line, and exit 0, in both output modes.
func TestCmdRunCommand_NoErrorNoErrorLine(t *testing.T) {
	reply := apitypes.TargetedResults{Results: map[string]interface{}{
		"web-01": apitypes.CmdRun{Stdout: "hi\n"},
		"web-02": apitypes.CmdRun{Stdout: "hi\n"},
	}}
	out, status := runCmdRunAgainst(t, "", "web-01,web-02", []string{"web-01", "web-02"}, reply)
	if strings.Contains(out, "error:") || !strings.Contains(out, "web-01:") || !strings.Contains(out, "hi") {
		t.Errorf("output:\n%s", out)
	}
	if status != 0 {
		t.Errorf("text: exit status %d, want 0", status)
	}
	if _, status := runCmdRunAgainst(t, "json", "web-01,web-02", []string{"web-01", "web-02"}, reply); status != 0 {
		t.Errorf("json: exit status %d, want 0", status)
	}
}

// The command ran but exited non-zero on one target: exit 1, after
// printing every target's output.
func TestCmdRunCommand_NonZeroExitCodeExitsOne(t *testing.T) {
	reply := apitypes.TargetedResults{Results: map[string]interface{}{
		"web-01": apitypes.CmdRun{Stdout: "fine\n"},
		"web-02": apitypes.CmdRun{Stderr: "disk full\n", ErrCode: 2},
	}}
	for _, mode := range []string{"", "json"} {
		out, status := runCmdRunAgainst(t, mode, "web-01,web-02", []string{"web-01", "web-02"}, reply)
		if status != 1 {
			t.Errorf("%q: exit status %d, want 1", mode, status)
		}
		if !strings.Contains(out, "fine") || !strings.Contains(out, "disk full") {
			t.Errorf("%q: output doesn't contain both targets' output:\n%s", mode, out)
		}
	}
}

// A result that can't be read counts as a failure.
func TestCmdRunFailed_UnreadableResult(t *testing.T) {
	results := apitypes.TargetedResults{Results: map[string]interface{}{
		"web-01": map[string]interface{}{"stdout": 3},
	}}
	if !cmdRunFailed(results) {
		t.Error("an unreadable result didn't count as a failure")
	}
	if cmdRunFailed(apitypes.TargetedResults{}) {
		t.Error("no results counted as a failure")
	}
}
