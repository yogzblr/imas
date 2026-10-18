//go:build !windows

package fleetsign

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// trustTempACLs is a no-op on Unix-like systems, where a test's temp
// files are checked by their real owner and mode (trustpath_windows_test.go
// has the Windows version).
func trustTempACLs(*testing.T) {}

// otherOwner makes every path look owned by another uid for the rest of
// the test.
func otherOwner(t *testing.T) {
	t.Helper()
	orig := geteuid
	geteuid = func() int { return orig() + 1 }
	t.Cleanup(func() { geteuid = orig })
}

func TestCheckPrivateDir(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "stage")
	if err := os.Mkdir(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(priv); err != nil {
		t.Fatalf("a 0700 directory of ours: %v", err)
	}
	for _, mode := range []os.FileMode{0o750, 0o705, 0o755, 0o777, 0o720} {
		if err := os.Chmod(priv, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckPrivateDir(priv); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("mode %04o: %v, want ErrUnsafePath", mode, err)
		}
	}
	if err := os.Chmod(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(priv, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(link); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a symlink to a private directory: %v, want ErrUnsafePath", err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(file); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a file: %v, want ErrUnsafePath", err)
	}
	if err := CheckPrivateDir(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrUnsafePath) {
		t.Errorf("a missing directory: %v, want ErrNotExist", err)
	}
	otherOwner(t)
	if err := CheckPrivateDir(priv); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("another user's directory: %v, want ErrUnsafePath", err)
	}
}

func TestCheckNotWritableByOthers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for mode, ok := range map[os.FileMode]bool{0o755: true, 0o750: true, 0o700: true, 0o775: false, 0o757: false, 0o777: false} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		err := CheckNotWritableByOthers(dir)
		if ok && err != nil {
			t.Errorf("mode %04o: %v, want accepted", mode, err)
		}
		if !ok && !errors.Is(err, ErrUnsafePath) {
			t.Errorf("mode %04o: %v, want ErrUnsafePath", mode, err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := dir + "-link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckNotWritableByOthers(link); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a symlink: %v, want ErrUnsafePath", err)
	}
	otherOwner(t)
	if err := CheckNotWritableByOthers(dir); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("another user's directory: %v, want ErrUnsafePath", err)
	}
}

func TestCheckPrivateFile_Owner(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fleet-signing-keys.asc")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(file); err != nil {
		t.Fatalf("our 0600 file: %v", err)
	}
	otherOwner(t)
	if err := CheckPrivateFile(file); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("another user's file: %v, want ErrUnsafePath", err)
	}
	if _, err := LoadArmoredKeyring(file); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("LoadArmoredKeyring of another user's file: %v, want ErrUnsafePath", err)
	}
}
