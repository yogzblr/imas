//go:build !unix

package harness

import "os/exec"

// killGroupOnCancel leaves cmd as it is: the harness runs vmctl.sh on the
// Linux runner only.
func killGroupOnCancel(*exec.Cmd) {}
