//go:build !windows

package file

import (
	"os"
	"syscall"
)

// ownedBy reports whether name (not followed if a symlink) is owned by
// uid and gid; -1 matches any. A name that can't be read is not.
func ownedBy(name string, uid, gid int) bool {
	st, err := os.Lstat(name)
	if err != nil {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return (uid == -1 || int(sys.Uid) == uid) && (gid == -1 || int(sys.Gid) == gid)
}
