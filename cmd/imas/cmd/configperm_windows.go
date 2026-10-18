//go:build windows

package cmd

import (
	"fmt"
	"io/fs"
	"os"
)

// chmodNoFollow refuses a path that is not a directory (dir) or a regular
// file, then sets its mode. On Windows Chmod only sets or clears the
// read-only attribute, so a path swapped in after the check gains nothing.
func chmodNoFollow(path string, mode fs.FileMode, dir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if (dir && !st.IsDir()) || (!dir && !st.Mode().IsRegular()) {
		return notTypeError(path, dir)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("restricting %s to mode %o: %w", path, mode, err)
	}
	return nil
}
