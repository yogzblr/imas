//go:build windows

package selfupdate

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachedSysProcAttr starts msiexec in its own process group with no
// console, so it outlives the sprout's service process when the MSI stops
// that service.
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
}
