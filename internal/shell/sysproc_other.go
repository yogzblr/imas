//go:build !linux && !windows

package shell

import "syscall"

// shellSysProcAttr: no Pdeathsig outside Linux. pty.StartWithSize adds
// Setsid and Setctty, so end still kills the shell's whole process group,
// and Sprout.CloseAll ends every session when the sprout stops.
func shellSysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }
