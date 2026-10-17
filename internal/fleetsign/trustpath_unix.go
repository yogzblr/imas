//go:build !windows

package fleetsign

import (
	"fmt"
	"os"
	"syscall"
)

// geteuid is os.Geteuid; a variable so tests can check the owner refusal
// without a second user.
var geteuid = os.Geteuid

// checkOwnerAndMode requires fi (the Lstat of path) to be owned by the
// effective uid and to have no permission bit outside maxPerm.
func checkOwnerAndMode(path string, fi os.FileInfo, maxPerm os.FileMode, _ bool) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: no owner information", ErrUnsafePath, path)
	}
	if euid := geteuid(); int(st.Uid) != euid {
		return fmt.Errorf("%w: %s is owned by uid %d, not the sprout's uid %d", ErrUnsafePath, path, st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&^maxPerm != 0 {
		return fmt.Errorf("%w: %s has mode %04o, looser than %04o", ErrUnsafePath, path, perm, maxPerm)
	}
	return nil
}
