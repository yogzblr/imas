package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckConfigRoot: farmer starts only with an existing config root
// directory and never creates one.
func TestCheckConfigRoot(t *testing.T) {
	dir := t.TempDir()
	if err := checkConfigRoot(dir); err != nil {
		t.Errorf("existing dir: %v", err)
	}

	missing := filepath.Join(dir, "imas")
	if err := checkConfigRoot(missing); err == nil {
		t.Error("missing dir: no error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("checkConfigRoot created %s", missing)
	}

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkConfigRoot(file); err == nil {
		t.Error("file: no error")
	}
}
