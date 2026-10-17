package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/taigrr/jety"
)

const (
	// cliConfigFileMode is the mode of the imas CLI's config file: it holds
	// the NKey private key (privkey).
	cliConfigFileMode fs.FileMode = 0o600
	// cliConfigDirMode is the mode of the default config directory,
	// $HOME/.config/imas.
	cliConfigDirMode fs.FileMode = 0o700
)

// configStep, when set, is called after each step of ensureConfigFile and
// writeConfigFile with the step's name and the path it just made or
// changed. Tests use it to check the modes at every step.
var configStep func(step, path string)

func stepDone(step, path string) {
	if configStep != nil {
		configStep(step, path)
	}
}

// cliConfigPath is the CLI's config file, $HOME/.config/imas/imas, the path
// config.LoadConfig("imas") reads.
func cliConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "imas", "imas"), nil
}

// ensureConfigFile creates the CLI's config file, empty, when it does not
// exist, so that it is mode 0600 from the first byte (issue #139): the
// directory is created 0700 (its parent 0755), the file is opened under a
// temporary name in that directory with O_CREATE|O_EXCL and mode 0600, and
// renamed into place. The loader then finds an empty file and keeps it:
// truncating an existing file keeps its mode. An existing file is left
// alone (restrictConfig tightens it).
func ensureConfigFile(path string) error {
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, cliConfigDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if isDefaultConfigDir(dir) {
		// Mkdir's mode is narrowed by the umask, never widened, and an
		// existing default directory may be wider.
		if err := os.Chmod(dir, cliConfigDirMode); err != nil {
			return err
		}
	}
	stepDone("dir", dir)
	tmp, err := createPrivateTemp(dir, filepath.Base(path))
	if err != nil {
		return err
	}
	stepDone("temp", tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	stepDone("rename", path)
	return nil
}

// createPrivateTemp creates an empty file named .<base>.tmp-<n> in dir with
// O_CREATE|O_EXCL and mode 0600, set again with Chmod so that a umask
// cannot leave it narrower than the owner needs to write it, and returns
// its path.
func createPrivateTemp(dir, base string) (string, error) {
	for n := 0; ; n++ {
		tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d-%d", base, os.Getpid(), n))
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, cliConfigFileMode)
		if errors.Is(err, fs.ErrExist) && n < 100 {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := f.Chmod(cliConfigFileMode); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		return tmp, nil
	}
}

// writeConfigFile writes the loaded config to path atomically: jety
// encodes it into a 0600 file made by createPrivateTemp next to path, which
// is then renamed over path. A reader never sees a half-written file, and
// the file is never wider than 0600.
func writeConfigFile(path string) error {
	if path == "" {
		return errors.New("no config file")
	}
	tmp, err := createPrivateTemp(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return err
	}
	stepDone("temp", tmp)
	jety.SetConfigFile(tmp)
	werr := jety.WriteConfig()
	jety.SetConfigFile(path)
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	stepDone("written", tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	stepDone("rename", path)
	return nil
}

// restrictConfig tightens the CLI's config file to 0600, and its directory
// to 0700 when that is the default one ($HOME/.config/imas, never an
// arbitrary directory the file happens to be in). A path that doesn't exist
// yet is fine. ensureConfigFile creates the file 0600 and writeConfigFile
// rewrites it 0600; restrictConfig runs after the config is loaded and
// after it is written, so a file written by an earlier version (which
// created it 0644 in a 0755 directory) is fixed the next time the CLI
// starts, before a private key is put into it.
func restrictConfig(path string) error {
	if path == "" {
		return nil
	}
	var errs []error
	if dir := filepath.Dir(path); isDefaultConfigDir(dir) {
		if err := os.Chmod(dir, cliConfigDirMode); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("restricting %s to mode %o: %w", dir, cliConfigDirMode, err))
		}
	}
	if err := os.Chmod(path, cliConfigFileMode); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("restricting %s to mode %o: %w", path, cliConfigFileMode, err))
	}
	return errors.Join(errs...)
}

// isDefaultConfigDir reports whether dir is <something>/.config/imas.
func isDefaultConfigDir(dir string) bool {
	return filepath.Base(dir) == "imas" && filepath.Base(filepath.Dir(dir)) == ".config"
}
