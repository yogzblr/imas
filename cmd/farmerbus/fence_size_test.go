package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeSize replaces dir's "replicas" the way kubelet updates a mounted
// ConfigMap directory: a new file renamed over the old one.
func writeSize(t *testing.T, dir, v string) {
	t.Helper()
	tmp := filepath.Join(dir, ".tmp")
	if err := os.WriteFile(tmp, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "replicas")); err != nil {
		t.Fatal(err)
	}
}

func TestFenceSizeFollowsFile(t *testing.T) {
	dir := t.TempDir()
	writeSize(t, dir, "5\n")
	c := newClusterSize(3, filepath.Join(dir, "replicas"), os.ReadFile)
	if got := c.get(); got != 5 {
		t.Fatalf("size = %d, want 5 from the file", got)
	}
	writeSize(t, dir, "7")
	if got := c.get(); got != 7 {
		t.Fatalf("after a scale-up size = %d, want 7", got)
	}
	writeSize(t, dir, "4")
	if got := c.get(); got != 4 {
		t.Fatalf("after a scale-down size = %d, want 4", got)
	}
}

func TestFenceSizeNeverBelowRoutes(t *testing.T) {
	dir := t.TempDir()
	writeSize(t, dir, "1")
	c := newClusterSize(3, filepath.Join(dir, "replicas"), os.ReadFile)
	if got := c.get(); got != 3 {
		t.Fatalf("size = %d, want the route count 3", got)
	}
	// No file configured: the route count alone.
	if got := newClusterSize(3, "", os.ReadFile).get(); got != 3 {
		t.Fatalf("no file: size = %d, want 3", got)
	}
}

func TestFenceSizeBadFileKeepsLast(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replicas")

	// Before any good value: the route count.
	c := newClusterSize(3, path, os.ReadFile)
	if got := c.get(); got != 3 {
		t.Fatalf("missing file before any good value: size = %d, want 3", got)
	}

	writeSize(t, dir, "5")
	if got := c.get(); got != 5 {
		t.Fatalf("size = %d, want 5", got)
	}
	for _, bad := range []string{"", "five", "0", "-2", "5.5", "99999999999999999999"} {
		writeSize(t, dir, bad)
		if got := c.get(); got != 5 {
			t.Errorf("file %q: size = %d, want the last good 5", bad, got)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := c.get(); got != 5 {
		t.Errorf("file removed: size = %d, want the last good 5", got)
	}
	// A read error of any kind is the same.
	c.read = func(string) ([]byte, error) { return nil, errors.New("eio") }
	if got := c.get(); got != 5 {
		t.Errorf("read error: size = %d, want 5", got)
	}
	// It recovers once the file is good again.
	c.read = os.ReadFile
	writeSize(t, dir, "6")
	if got := c.get(); got != 6 {
		t.Errorf("recovered: size = %d, want 6", got)
	}
}

func TestObservedServers(t *testing.T) {
	peers := map[string]bool{"B": true, "C": true}
	views := map[string]map[string]bool{
		"B": {"A": true, "C": true, "D": true},
		"C": {"A": true, "B": true},
	}
	if got := observedServers("A", peers, views); got != 4 {
		t.Fatalf("observed = %d, want 4 (A, B, C and D seen by B)", got)
	}
	if got := observedServers("A", nil, nil); got != 1 {
		t.Fatalf("alone: observed = %d, want 1", got)
	}
}
