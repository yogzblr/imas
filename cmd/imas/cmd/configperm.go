package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// cliConfigFileMode is the mode of the imas CLI's config file: it holds
	// the NKey private key (privkey).
	cliConfigFileMode fs.FileMode = 0o600
	// cliConfigDirMode is the mode of the default config directory,
	// $HOME/.config/imas.
	cliConfigDirMode fs.FileMode = 0o700
)

// restrictConfig tightens the CLI's config file to 0600, and its directory
// to 0700 when that is the default one ($HOME/.config/imas, never an
// arbitrary directory the file happens to be in). A path that doesn't exist
// yet is fine. It runs after the config is loaded and again after it is
// written, so a file created or rewritten with a wider mode (the loader
// creates it 0644 in a 0755 directory, and rewrites keep an existing
// file's mode) is tightened before the private key is put into it, and one
// written by an earlier version is fixed the next time the CLI starts.
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
