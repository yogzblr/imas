//go:build !windows

package selfupdate

import "syscall"

// detachedSysProcAttr starts the process in its own session. Only the
// Windows MSI install starts a detached process; this keeps the seam
// buildable elsewhere.
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
