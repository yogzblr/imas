//go:build !windows

package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/taigrr/jety"
)

// permissiveUmask sets the umask to 0 for the test, so that a mode the code
// passes (or forgets to pass) is the mode the file gets.
func permissiveUmask(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

// recordSteps sets configStep for the test and checks, at every step, that
// the path it names has the mode it must have: 0700 for the directory,
// 0600 for every file. It returns the steps seen.
func recordSteps(t *testing.T) *[]string {
	t.Helper()
	var steps []string
	configStep = func(step, path string) {
		steps = append(steps, step)
		st, err := os.Lstat(path)
		if err != nil {
			t.Errorf("step %s: %v", step, err)
			return
		}
		want := cliConfigFileMode
		if st.IsDir() {
			want = cliConfigDirMode
		}
		if st.Mode().Perm() != want {
			t.Errorf("step %s: %s has mode %v, want %v", step, path, st.Mode().Perm(), want)
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			t.Errorf("step %s: %s is not a regular file (%v)", step, path, st.Mode())
		}
	}
	t.Cleanup(func() { configStep = nil })
	return &steps
}

func noTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}
}

// The config file is 0600 in a 0700 directory from the first byte, even
// under umask 0 (issue #139), and the loader's truncation of the empty file
// keeps that mode.
func TestEnsureConfigFileIsPrivateFromTheStart(t *testing.T) {
	permissiveUmask(t)
	steps := recordSteps(t)
	home := t.TempDir()
	path := filepath.Join(home, ".config", "imas", "imas")
	if err := ensureConfigFile(path); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*steps, ","); got != "dir,temp,rename" {
		t.Errorf("steps %q, want dir,temp,rename", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != cliConfigFileMode || st.Size() != 0 {
		t.Errorf("config file mode %v size %d, want 0600 and empty", st.Mode().Perm(), st.Size())
	}
	if st, _ := os.Stat(filepath.Join(home, ".config")); st.Mode().Perm() != 0o755 {
		t.Errorf(".config mode %v, want 0755", st.Mode().Perm())
	}
	noTempFiles(t, filepath.Dir(path))

	// What config.LoadConfig does with an empty file: os.Create truncates
	// it and keeps its mode.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(path); st.Mode().Perm() != cliConfigFileMode {
		t.Errorf("after the loader's create, mode %v, want 0600", st.Mode().Perm())
	}
}

// A file another process creates between the check and the install (here
// from the step hook, once the temporary file exists) is kept: the install
// is a hard link, which never replaces it, and the temporary file goes.
func TestEnsureConfigFileKeepsAFileCreatedMeanwhile(t *testing.T) {
	permissiveUmask(t)
	dir := filepath.Join(t.TempDir(), ".config", "imas")
	path := filepath.Join(dir, "imas")
	configStep = func(step, _ string) {
		if step == "temp" {
			if err := os.WriteFile(path, []byte("privkey: SAAother\n"), 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { configStep = nil })
	if err := ensureConfigFile(path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "privkey: SAAother\n" {
		t.Errorf("the file created meanwhile was replaced: %q", b)
	}
	noTempFiles(t, dir)
}

// An existing default directory that is too wide is tightened before the
// file is made in it.
func TestEnsureConfigFileTightensExistingDefaultDir(t *testing.T) {
	permissiveUmask(t)
	recordSteps(t)
	dir := filepath.Join(t.TempDir(), ".config", "imas")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ensureConfigFile(filepath.Join(dir, "imas")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != cliConfigDirMode {
		t.Errorf("directory mode %v, want 0700", st.Mode().Perm())
	}
}

// An existing file is never replaced: it may hold the private key.
func TestEnsureConfigFileKeepsAnExistingFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".config", "imas")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "imas")
	if err := os.WriteFile(path, []byte("privkey: SAAxxxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := recordSteps(t)
	if err := ensureConfigFile(path); err != nil {
		t.Fatal(err)
	}
	if len(*steps) != 0 {
		t.Errorf("steps %v for an existing file, want none", *steps)
	}
	if b, _ := os.ReadFile(path); string(b) != "privkey: SAAxxxx\n" {
		t.Errorf("existing file changed to %q", b)
	}
}

// A rewrite goes through a 0600 temporary file renamed into place, under
// umask 0, and leaves no temporary file.
func TestWriteConfigFileIsPrivateAndAtomic(t *testing.T) {
	permissiveUmask(t)
	steps := recordSteps(t)
	old := jety.ConfigFileUsed()
	t.Cleanup(func() { jety.SetConfigFile(old) })
	if err := jety.SetConfigType("yaml"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), ".config", "imas")
	path := filepath.Join(dir, "imas")
	if err := ensureConfigFile(path); err != nil {
		t.Fatal(err)
	}
	*steps = nil
	jety.SetConfigFile(path)
	jety.Set("farmerinterface", "farmer.example.test")
	if err := writeConfigFile(path); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*steps, ","); got != "temp,written,rename" {
		t.Errorf("steps %q, want temp,written,rename", got)
	}
	if jety.ConfigFileUsed() != path {
		t.Errorf("ConfigFileUsed %q after the write, want %q", jety.ConfigFileUsed(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "farmer.example.test") {
		t.Errorf("config file %q lacks the value written", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != cliConfigFileMode {
		t.Errorf("config file mode %v, want 0600", st.Mode().Perm())
	}
	noTempFiles(t, dir)
}

// A temporary file name already taken (by another process, or a leftover)
// is skipped, never opened.
func TestCreatePrivateTempSkipsTakenName(t *testing.T) {
	permissiveUmask(t)
	dir := t.TempDir()
	first, err := createPrivateTemp(dir, "imas")
	if err != nil {
		t.Fatal(err)
	}
	second, err := createPrivateTemp(dir, "imas")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("both temporary files are %s", first)
	}
	for _, p := range []string{first, second} {
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != fs.FileMode(0o600) {
			t.Errorf("%s mode %v, want 0600", p, st.Mode().Perm())
		}
	}
}
