package cook

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/log"
)

// captureLog sends the log, as JSON at debug and up, to a buffer for the
// test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	b := &bytes.Buffer{}
	log.SetOutput(b)
	log.SetFormat(log.FormatJSON)
	log.SetLogLevel(log.LDebug)
	t.Cleanup(func() {
		log.SetOutput(nil)
		log.SetFormat(log.FormatText)
	})
	return b
}

func TestLogStepFailureLogsTheErrorAtError(t *testing.T) {
	b := captureLog(t)
	runErr := errors.New(`netsh.exe: exit status 2; stderr: (empty); stdout: token hunter2`)
	logStepFailure("job-1", StepCompletion{ID: "uat firewall rule_present", CompletionStatus: StepFailed, Error: runErr}, []string{"hunter2"})
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(b.Bytes()), &line); err != nil {
		t.Fatalf("want one JSON log line, got %q: %v", b.String(), err)
	}
	msg, _ := line["msg"].(string)
	if lvl, _ := line["level"].(string); lvl != "error" {
		t.Errorf("level = %q, want error (line %v)", lvl, line)
	}
	if !strings.Contains(msg, "Step uat firewall rule_present of job job-1 failed: netsh.exe: exit status 2") {
		t.Errorf("the line does not carry the step's error: %q", msg)
	}
	if strings.Contains(msg, "hunter2") || !strings.Contains(msg, RedactedPlaceholder) {
		t.Errorf("a sensitive value was not redacted: %q", msg)
	}
}

func TestLogStepFailureIsQuietOtherwise(t *testing.T) {
	b := captureLog(t)
	logStepFailure("job-1", StepCompletion{ID: "ok", CompletionStatus: StepCompleted}, nil)
	logStepFailure("job-1", StepCompletion{ID: "failed without an error", CompletionStatus: StepFailed}, nil)
	if b.Len() != 0 {
		t.Errorf("want no log line, got %q", b.String())
	}
}
