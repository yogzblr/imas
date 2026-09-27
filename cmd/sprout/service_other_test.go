//go:build !windows

package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestProcessRunning(t *testing.T) {
	if !processRunning(os.Getpid()) {
		t.Error("processRunning(own pid) = false")
	}
	// A child that has exited and been reaped: its PID is free.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot run true: %v", err)
	}
	if processRunning(cmd.Process.Pid) {
		t.Errorf("processRunning(%d) = true for a reaped child", cmd.Process.Pid)
	}
	for _, pid := range []int{0, -1} {
		if processRunning(pid) {
			t.Errorf("processRunning(%d) = true", pid)
		}
	}
}
