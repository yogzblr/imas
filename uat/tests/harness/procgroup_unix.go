//go:build unix

package harness

import (
	"os/exec"
	"syscall"
)

// killGroupOnCancel starts cmd in a process group of its own and makes a
// cancelled context kill the whole group, not only cmd: a timed out
// vmctl.sh must not leave its az, ssh or python child running (and, for
// run-command, keeping the VM's extension busy).
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
