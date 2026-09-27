//go:build windows

package winservice

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/log"
)

func TestCrashLogPath(t *testing.T) {
	for in, want := range map[string]string{
		`C:\ProgramData\imas\logs\sprout.log`: `C:\ProgramData\imas\logs\sprout-crash.log`,
		`C:\logs\sprout`:                      `C:\logs\sprout-crash`,
	} {
		if got := CrashLogPath(in); got != want {
			t.Errorf("CrashLogPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "sprout.log")
	crashPath := CrashLogPath(path)
	// An oversized crash log from earlier runs is rotated at startup.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crashPath, make([]byte, LogMaxSize), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := LogToFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Restore stderr and release both handles, or TempDir can't delete
	// the files on Windows.
	t.Cleanup(func() {
		log.SetOutput(nil)
		f.Close()
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
	})

	log.Warnf("service log line %d", 7)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "service log line 7") {
		t.Errorf("%s = %q, want the log line", path, b)
	}
	info, err := os.Stat(crashPath)
	if err != nil {
		t.Fatalf("crash log not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("crash log size = %d, want a fresh file after rotation", info.Size())
	}
	if info, err := os.Stat(crashPath + ".1"); err != nil || info.Size() != LogMaxSize {
		t.Errorf("rotated crash log: %v, %v", info, err)
	}
}
