//go:build !windows

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// Security review L3: the keyring, the cache directory and the staging
// directories are checked by owner, mode and symlink (Lstat), and an
// update that fails a check is refused with the unsafe_path code before
// anything is downloaded or installed.

func assertUnsafe(t *testing.T, f *fixture, err error) {
	t.Helper()
	if !errors.Is(err, fleetsign.ErrUnsafePath) || !strings.Contains(err.Error(), "unsafe_path") {
		t.Fatalf("Apply error = %v, want fleetsign.ErrUnsafePath (unsafe_path)", err)
	}
	f.runDeferred()
	if f.packageRequests() != 0 {
		t.Error("the package was downloaded")
	}
	if _, _, installs := f.counts(); installs != 0 {
		t.Errorf("installed %d times", installs)
	}
}

func TestApply_UnsafeKeyring(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T){
		"mode 0644": func(t *testing.T) { os.Chmod(config.SproutFleetSigningKeyring, 0o644) },
		"mode 0660": func(t *testing.T) { os.Chmod(config.SproutFleetSigningKeyring, 0o660) },
		"a symlink to a good keyring": func(t *testing.T) {
			link := filepath.Join(t.TempDir(), "fleet-signing-keys.asc")
			if err := os.Symlink(config.SproutFleetSigningKeyring, link); err != nil {
				t.Fatal(err)
			}
			config.SproutFleetSigningKeyring = link
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(t)
			res, err := step(t, target(testTarget)).Apply(context.Background())
			if res.Succeeded {
				t.Fatal("succeeded")
			}
			assertUnsafe(t, f, err)
			if farmer, _, _ := f.counts(); farmer != 0 {
				t.Errorf("farmer asked %d times; the keyring is checked first", farmer)
			}
		})
	}
}

func TestApply_UnsafeCacheDir(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T){
		"group-writable": func(t *testing.T) {
			mkdir(t, config.CacheDir, 0o775)
		},
		"world-writable": func(t *testing.T) {
			mkdir(t, config.CacheDir, 0o777)
		},
		"a symlink to a private directory": func(t *testing.T) {
			real := filepath.Join(t.TempDir(), "real-cache")
			mkdir(t, real, 0o700)
			if err := os.Symlink(real, config.CacheDir); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(t)
			_, err := step(t, target(testTarget)).Apply(context.Background())
			assertUnsafe(t, f, err)
		})
	}
}

func mkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

// TestApply_StagingDirCreatedFresh: whatever is at the staging root when
// an update starts (a planted file in a loose directory, a symlink to
// someone else's directory) is removed, never reused; the update stages
// in a new 0700 directory and nothing is written through the symlink.
func TestApply_StagingDirCreatedFresh(t *testing.T) {
	t.Run("a loose directory with a planted file", func(t *testing.T) {
		f := newFixture(t)
		root := filepath.Join(config.CacheDir, stageDirName)
		mkdir(t, filepath.Join(root, "update-planted"), 0o777)
		os.Chmod(root, 0o777)
		planted := filepath.Join(root, "update-planted", testFileDeb)
		writeFile(t, planted, []byte("not the signed package"), 0o666)
		if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
			t.Fatalf("Apply = %+v, %v", res, err)
		}
		if _, err := os.Lstat(planted); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the planted file survived: %v", err)
		}
		fi, err := os.Lstat(root)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("staging root = %v, %v; want a fresh 0700 directory", fi, err)
		}
		if c := f.calls[0]; !strings.HasPrefix(c.args[len(c.args)-1], root+string(filepath.Separator)+"update-") {
			t.Errorf("installed %s, not from a fresh staging directory", c.args[len(c.args)-1])
		}
	})
	t.Run("a symlink to another directory", func(t *testing.T) {
		f := newFixture(t)
		elsewhere := filepath.Join(t.TempDir(), "elsewhere")
		mkdir(t, elsewhere, 0o777)
		mkdir(t, config.CacheDir, 0o700)
		if err := os.Symlink(elsewhere, filepath.Join(config.CacheDir, stageDirName)); err != nil {
			t.Fatal(err)
		}
		if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
			t.Fatalf("Apply = %+v, %v", res, err)
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Errorf("staged through the symlink: %v", entries)
		}
		if _, _, installs := f.counts(); installs != 1 {
			t.Errorf("installed %d times, want 1", installs)
		}
	})
}

// TestApply_StagingDirCheckedBeforeInstall: a staging directory that
// stops being private between the download and the installer (here,
// while the package's metadata is read) refuses the install.
func TestApply_StagingDirCheckedBeforeInstall(t *testing.T) {
	f := newFixture(t)
	query := queryCommand
	setSeam(t, &queryCommand, func(ctx context.Context, name string, args []string) ([]byte, error) {
		if filepath.Base(name) == "dpkg-deb" {
			os.Chmod(filepath.Dir(args[1]), 0o777)
		}
		return query(ctx, name, args)
	})
	_, err := step(t, target(testTarget)).Apply(context.Background())
	if !errors.Is(err, fleetsign.ErrUnsafePath) {
		t.Fatalf("Apply error = %v, want ErrUnsafePath", err)
	}
	f.runDeferred()
	if _, _, installs := f.counts(); installs != 0 {
		t.Errorf("installed %d times", installs)
	}
	assertNoStagedFiles(t)
}

// TestStageDir_Private: stageDir makes the cache directory, the staging
// root and the per-update directory, each 0700 and the sprout user's.
func TestStageDir_Private(t *testing.T) {
	saveConfig(t)
	config.CacheDir = filepath.Join(t.TempDir(), "cache")
	stage, err := stageDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{config.CacheDir, filepath.Dir(stage), stage} {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s = %v, %v; want a 0700 directory", dir, fi, err)
		}
	}
	if filepath.Dir(stage) != filepath.Join(config.CacheDir, stageDirName) {
		t.Errorf("stage %s is not under the staging root", stage)
	}
}
