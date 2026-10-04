//go:build linux

package shell

import "syscall"

// shellSysProcAttr makes the kernel kill the shell if the sprout dies
// (Pdeathsig). pty.StartWithSize adds Setsid and Setctty, so the shell
// leads its own session and process group, which end kills whole.
//
// Pdeathsig fires when the OS thread that started the shell exits, not
// the process. The Go runtime doesn't retire threads unless a goroutine
// locked to one exits, which nothing in the sprout does around a spawn.
func shellSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
