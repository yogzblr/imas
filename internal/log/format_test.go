package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"", FormatText, false},
		{"text", FormatText, false},
		{"json", FormatJSON, false},
		{" JSON ", FormatJSON, false},
		{"yaml", FormatText, true},
	} {
		got, err := ParseFormat(tt.in)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q, error %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

// TestSetFormatJSON: in JSON mode every terminal log entry is one JSON
// object per line, with the level and message as fields.
func TestSetFormatJSON(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetFormat(FormatJSON)
	t.Cleanup(func() {
		SetFormat(FormatText)
		SetOutput(nil)
	})

	Infof("enrolled %s", "web-1")
	Error("bus down")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), buf.String())
	}
	for i, want := range []struct{ level, msg string }{{"info", "enrolled web-1"}, {"error", "bus down"}} {
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &m); err != nil {
			t.Fatalf("line %q is not JSON: %v", lines[i], err)
		}
		if m["level"] != want.level || m["msg"] != want.msg {
			t.Errorf("line %d = %v, want level %q msg %q", i, m, want.level, want.msg)
		}
		if _, ok := m["time"]; !ok {
			t.Errorf("line %d has no time: %v", i, m)
		}
	}
}

func TestSetFormatText(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetFormat(FormatText)
	t.Cleanup(func() { SetOutput(nil) })

	Info("plain message")

	out := buf.String()
	if !strings.Contains(out, "plain message") || json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Errorf("text output = %q", out)
	}
}
