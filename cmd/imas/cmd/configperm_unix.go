//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// chmodNoFollow sets path's mode through a handle opened without
// following a symlink (O_NOFOLLOW), after checking on that same handle that
// it is a directory (dir) or a regular file. Nothing resolves path again
// between the check and the change, so a symlink swapped in meanwhile is
// refused rather than followed.
func chmodNoFollow(path string, mode fs.FileMode, dir bool) error {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if dir {
		flags |= syscall.O_DIRECTORY
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || (dir && errors.Is(err, syscall.ENOTDIR)) {
			return notTypeError(path, dir)
		}
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if (dir && !st.IsDir()) || (!dir && !st.Mode().IsRegular()) {
		return notTypeError(path, dir)
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("restricting %s to mode %o: %w", path, mode, err)
	}
	return nil
}
