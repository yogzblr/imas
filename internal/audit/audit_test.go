package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// decodeLines parses every line of out as a JSON object.
func decodeLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var got []map[string]any
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line %q is not a JSON object: %v", l, err)
		}
		got = append(got, m)
	}
	return got
}

// TestAuditWritesJSONToStdout is test 10 of the slice 3 brief: a logger
// built with no writer writes one JSON line per event to stdout, with the
// required fields, and creates no file.
func TestAuditWritesJSONToStdout(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	logger := NewLogger(nil)
	os.Stdout = stdout

	for _, e := range []Entry{
		{Pubkey: "UADMIN", RoleName: "admin", Action: "cook", Targets: []string{"web-1"}, Success: true},
		{Username: "alice", Pubkey: "UALICE", RoleName: "dev", Action: "pki.accept", Success: false, Error: "denied"},
	} {
		if err := logger.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	lines := decodeLines(t, string(out))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), out)
	}
	for i, m := range lines {
		for _, k := range []string{"ts", "kind", "pubkey", "role", "action", "success"} {
			if _, ok := m[k]; !ok {
				t.Errorf("line %d has no %q: %v", i, k, m)
			}
		}
		if m["kind"] != Kind {
			t.Errorf("line %d kind = %v, want %q", i, m["kind"], Kind)
		}
		if _, err := time.Parse(time.RFC3339Nano, m["ts"].(string)); err != nil {
			t.Errorf("line %d ts %v: %v", i, m["ts"], err)
		}
	}
	if lines[0]["action"] != "cook" || lines[1]["error"] != "denied" {
		t.Errorf("lines out of order or wrong: %v", lines)
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("audit created files in the working directory: %v", files)
	}
}

func TestLogEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	entry := Entry{
		Timestamp: time.Date(2026, 3, 10, 5, 30, 0, 0, time.UTC),
		Pubkey:    "APUBKEY123",
		RoleName:  "admin",
		Action:    "cook",
		Targets:   []string{"web-1", "web-2"},
		Success:   true,
	}
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	want := `{"kind":"audit","ts":"2026-03-10T05:30:00Z","pubkey":"APUBKEY123","role":"admin","action":"cook","targets":["web-1","web-2"],"success":true}` + "\n"
	if buf.String() != want {
		t.Errorf("line = %s\nwant   %s", buf.String(), want)
	}

	var got Entry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.Timestamp.Equal(entry.Timestamp) || got.Action != "cook" || len(got.Targets) != 2 {
		t.Errorf("round trip = %+v", got)
	}
}

func TestLogWithErrorAndParams(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	err := logger.Log(Entry{
		Username:   "bob",
		Pubkey:     "UBOB",
		RoleName:   "viewer",
		Action:     "cook",
		Parameters: json.RawMessage(`{"recipe":"web"}`),
		Error:      "permission denied",
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Success || got.Error != "permission denied" || got.Username != "bob" {
		t.Errorf("entry = %+v", got)
	}
	if string(got.Parameters) != `{"recipe":"web"}` {
		t.Errorf("params = %s", got.Parameters)
	}
}

func TestLogDefaultTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	before := time.Now().UTC()
	if err := logger.Log(Entry{Action: "test"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	after := time.Now().UTC()

	var got Entry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Timestamp.Before(before) || got.Timestamp.After(after) {
		t.Errorf("timestamp %v not within [%v, %v]", got.Timestamp, before, after)
	}
}

// TestLogConcurrentLinesWhole: lines from concurrent callers never
// interleave, so every line the shipper reads is one whole record.
func TestLogConcurrentLinesWhole(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := logger.Log(Entry{Pubkey: "UPUB", Action: "props.set", Success: true}); err != nil {
				t.Errorf("Log: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := len(decodeLines(t, buf.String())); got != n {
		t.Errorf("got %d lines, want %d", got, n)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestLogWriteError(t *testing.T) {
	err := NewLogger(failWriter{}).Log(Entry{Action: "cook"})
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Errorf("Log error = %v, want the write error", err)
	}
}
