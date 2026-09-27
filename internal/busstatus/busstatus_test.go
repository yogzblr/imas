package busstatus

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testRecorder(t *testing.T) (*Recorder, string, *time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "sprout", "bus-status.json")
	now := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	r := NewRecorder(path)
	r.now = func() time.Time { return now }
	return r, path, &now
}

func mustRead(t *testing.T, path string) Status {
	t.Helper()
	st, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return st
}

func TestRecorderTransitions(t *testing.T) {
	r, path, now := testRecorder(t)
	pid := os.Getpid()

	r.Starting()
	if st := mustRead(t, path); st != (Status{State: Starting, Since: *now, PID: pid}) {
		t.Errorf("after Starting: %+v", st)
	}

	*now = now.Add(time.Minute)
	r.Disconnected(errors.New("dial tcp: connection refused"))
	want := Status{State: Disconnected, Since: *now, PID: pid, Error: "dial tcp: connection refused"}
	if st := mustRead(t, path); st != want {
		t.Errorf("after a failed connect: %+v, want %+v", st, want)
	}

	*now = now.Add(time.Minute)
	r.Connected("tls://bus.example.com:443")
	want = Status{State: Connected, Server: "tls://bus.example.com:443", Since: *now, PID: pid}
	if st := mustRead(t, path); st != want {
		t.Errorf("after Connected: %+v, want %+v", st, want)
	}

	// A lost connection keeps the server it was lost from.
	*now = now.Add(time.Minute)
	r.Disconnected(nil)
	want = Status{State: Disconnected, Server: "tls://bus.example.com:443", Since: *now, PID: pid}
	if st := mustRead(t, path); st != want {
		t.Errorf("after a lost connection: %+v, want %+v", st, want)
	}

	*now = now.Add(time.Minute)
	r.Connected("tls://bus2.example.com:443")
	if st := mustRead(t, path); st.State != Connected || st.Server != "tls://bus2.example.com:443" {
		t.Errorf("after a reconnect: %+v", st)
	}

	*now = now.Add(time.Minute)
	r.Stopped()
	stopped := Status{State: Stopped, Server: "tls://bus2.example.com:443", Since: *now, PID: pid}
	if st := mustRead(t, path); st != stopped {
		t.Errorf("after Stopped: %+v, want %+v", st, stopped)
	}

	// nats.go reports the disconnect Close causes after the sprout has
	// already recorded the shutdown; it must not overwrite it.
	*now = now.Add(time.Minute)
	r.Disconnected(errors.New("nats: connection closed"))
	r.Connected("tls://bus.example.com:443")
	r.Stopped()
	if st := mustRead(t, path); st != stopped {
		t.Errorf("after events past Stopped: %+v, want %+v", st, stopped)
	}
}

func TestStartingClearsServer(t *testing.T) {
	r, path, _ := testRecorder(t)
	r.Connected("tls://bus.example.com:443")
	r.Starting()
	if st := mustRead(t, path); st.Server != "" {
		t.Errorf("Starting kept server %q", st.Server)
	}
}

func TestWriteIsAtomicAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bus-status.json")
	for i := 0; i < 3; i++ {
		if err := Write(path, Status{State: Connected, PID: i}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "bus-status.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only bus-status.json", names)
	}
	if st := mustRead(t, path); st.PID != 2 {
		t.Errorf("PID = %d, want the last write's 2", st.PID)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("mode = %o, want 644", fi.Mode().Perm())
		}
	}
}

func TestWriteFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus-status.json")
	since := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	if err := Write(path, Status{State: Connected, Server: "tls://bus:443", Since: since, PID: 42}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The field names are an interface: the imas_verify Ansible role and
	// monitoring read them.
	want := `{"state":"connected","server":"tls://bus:443","since":"2026-09-27T10:00:00Z","pid":42}` + "\n"
	if string(data) != want {
		t.Errorf("file = %q, want %q", data, want)
	}
}

func TestWriteNoPath(t *testing.T) {
	if err := Write("", Status{State: Connected}); err == nil {
		t.Error("Write with no path succeeded")
	}
}

func TestReadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v, want fs.ErrNotExist", err)
	}
	for name, content := range map[string]string{
		"garbage":  "not json",
		"no state": `{"pid":1}`,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil {
			t.Errorf("%s: Read succeeded", name)
		}
	}
}

// An unwritable status file must not stop the recorder: it logs and
// carries on, and writes again once it can.
func TestRecorderSurvivesWriteErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "state")
	// A file where the status file's directory should be.
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "bus-status.json")
	r := NewRecorder(path)
	r.Starting()
	r.Connected("tls://bus:443")
	if r.lastErr == "" {
		t.Fatal("no write error recorded")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	r.Disconnected(nil)
	if st := mustRead(t, path); st.State != Disconnected || st.Server != "tls://bus:443" {
		t.Errorf("after recovering: %+v", st)
	}
	if r.lastErr != "" {
		t.Errorf("lastErr = %q after a successful write", r.lastErr)
	}
}
