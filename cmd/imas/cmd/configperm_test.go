package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRestrictConfigTightensFileAndDefaultDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), ".config", "imas")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // not narrowed by the umask
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "imas")
	if err := os.WriteFile(cfg, []byte("privkey: SAAxxxx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restrictConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o600 {
		t.Errorf("config file mode %v, want 0600", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("config directory mode %v, want 0700", st.Mode().Perm())
	}
	// A second call changes nothing and doesn't fail.
	if err := restrictConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

// A config file in some other directory is tightened, the directory (which
// may be anyone's) is left alone.
func TestRestrictConfigLeavesOtherDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "imas")
	if err := os.WriteFile(cfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restrictConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, want 0600", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
		t.Errorf("directory mode %v, want it left at 0755", st.Mode().Perm())
	}
}

func TestRestrictConfigMissingPath(t *testing.T) {
	if err := restrictConfig(""); err != nil {
		t.Errorf("empty path: %v", err)
	}
	if err := restrictConfig(filepath.Join(t.TempDir(), ".config", "imas", "imas")); err != nil {
		t.Errorf("a path that doesn't exist yet: %v", err)
	}
}
