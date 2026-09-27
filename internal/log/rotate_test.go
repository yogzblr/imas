package log

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func write(t *testing.T, r *RotatingFile, s string) {
	t.Helper()
	if n, err := r.Write([]byte(s)); err != nil || n != len(s) {
		t.Fatalf("Write(%q) = %d, %v", s, n, err)
	}
}

func TestRotatingFile_RotatesAndKeeps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sprout.log")
	r, err := OpenRotatingFile(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })

	write(t, r, "aaaaa\n")            // 6 bytes
	write(t, r, "bbb\n")              // 10: fits exactly
	write(t, r, "cccccc\n")           // 17 > 10: rotates, new file at 7
	write(t, r, "ddd\n")              // 11 > 10: rotates again
	write(t, r, "eeeeeeeeeeeeeeee\n") // rotates; oversized, but alone

	for p, want := range map[string]string{
		path:        "eeeeeeeeeeeeeeee\n",
		path + ".1": "ddd\n",
		path + ".2": "cccccc\n",
	} {
		if got := readFile(t, p); got != want {
			t.Errorf("%s = %q, want %q", filepath.Base(p), got, want)
		}
	}
	// keep=2: the oldest (aaaaa/bbb) was dropped.
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s.3 exists (err %v), want only 2 rotated files", path, err)
	}
}

func TestRotatingFile_OversizedWriteToEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sprout.log")
	r, err := OpenRotatingFile(path, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	write(t, r, "longer than four\n")
	if _, err := os.Stat(path + ".1"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an empty file was rotated for one oversized write")
	}
	if got := readFile(t, path); got != "longer than four\n" {
		t.Errorf("content = %q", got)
	}
}

func TestRotatingFile_AppendsAndCountsExistingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sprout.log")
	if err := os.WriteFile(path, []byte("12345678\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRotatingFile(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	write(t, r, "x\n") // 9+2 > 10: the existing content counts
	if got := readFile(t, path+".1"); got != "12345678\n" {
		t.Errorf("rotated = %q, want the previous content", got)
	}
	if got := readFile(t, path); got != "x\n" {
		t.Errorf("current = %q", got)
	}
}

// A rotation that can't rename keeps appending to the same file, and
// doesn't retry on every write.
func TestRotatingFile_RenameFailureKeepsLogging(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sprout.log")
	// path.1 as a non-empty directory: renaming the log over it fails
	// on every OS.
	if err := os.MkdirAll(filepath.Join(path+".1", "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRotatingFile(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	write(t, r, "0123456789")
	write(t, r, "after\n")
	write(t, r, "more\n")
	if got := readFile(t, path); got != "0123456789after\nmore\n" {
		t.Errorf("content = %q", got)
	}
}

func TestRotatingFile_Close(t *testing.T) {
	r, err := OpenRotatingFile(filepath.Join(t.TempDir(), "sprout.log"), 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close = %v, want os.ErrClosed", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
}

func TestOpenRotatingFile_InvalidArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sprout.log")
	for _, tc := range []struct {
		max  int64
		keep int
	}{{0, 1}, {-1, 1}, {10, 0}} {
		if _, err := OpenRotatingFile(path, tc.max, tc.keep); err == nil {
			t.Errorf("OpenRotatingFile(max %d, keep %d) succeeded", tc.max, tc.keep)
		}
	}
}

func TestRotateFile_MissingFilesSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sprout-crash.log")
	if err := RotateFile(path, 3); err != nil {
		t.Errorf("RotateFile with nothing to rotate = %v", err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RotateFile(path, 3); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path+".1"); got != "old" {
		t.Errorf("%s.1 = %q", path, got)
	}
}

func TestSetOutput(t *testing.T) {
	var b strings.Builder
	SetOutput(&b)
	t.Cleanup(func() { SetOutput(nil) })
	Warnf("to the file %d", 42)
	if !strings.Contains(b.String(), "to the file 42") {
		t.Errorf("output = %q", b.String())
	}
}
