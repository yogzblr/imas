//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/yogzblr/imas/internal/busstatus"
	"github.com/yogzblr/imas/internal/config"
)

// runAsService reports false: only Windows has a service manager that
// needs the process to check in. See service_windows.go.
func runAsService(func(context.Context)) bool { return false }

// startServiceLog is a no-op: a Unix service manager (systemd, OpenRC)
// collects stderr itself.
func startServiceLog() {}

const serviceCommandsHelp = `install, uninstall, start and stop manage the Windows service. On this
system, use the service manager: systemctl (or rc-service) start imas-sprout.
status shows whether the running sprout is connected to the bus. Exit code 0
if it is, 3 if it isn't, 4 if the sprout has recorded nothing yet.
`

// Exit codes of `imas-sprout status` on this system; the Windows ones
// (winservice.Status*) report the service's state instead.
const (
	busStatusConnected   = 0
	busStatusUnreadable  = 1
	busStatusNotRunning  = 3
	busStatusNotRecorded = 4
)

// runServiceCommand runs status and fails the rest: they manage the
// Windows service.
func runServiceCommand(cmd string) int {
	if cmd == "status" {
		return statusCommand()
	}
	return serviceCommandFailed(cmd, fmt.Errorf("%s manages the Windows service; on this system use the "+
		"service manager, e.g. systemctl %s imas-sprout", cmd, systemctlVerb(cmd)))
}

// statusCommand prints the bus state the sprout records
// (config.SproutBusStatusFile). The service manager reports the rest.
func statusCommand() int {
	path := config.SproutBusStatusFile()
	st, err := busstatus.Read(path)
	text, check := describeBusStatus(st, err, path, processRunning, time.Now())
	fmt.Printf("imas-sprout bus: %s\n  %-11s %s\n  %-11s %s\n", text,
		"recorded in:", path, "service:", "systemctl status imas-sprout (or rc-service imas-sprout status)")
	switch check {
	case busConnected:
		return busStatusConnected
	case busNotRecorded:
		return busStatusNotRecorded
	case busUnreadable:
		return busStatusUnreadable
	}
	return busStatusNotRunning
}

// processRunning reports whether a process pid exists. Without the service
// manager's main PID to compare against, a recycled PID can pass for the
// sprout; the imas_verify Ansible role compares against systemd's MainPID.
func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	// EPERM: it exists, owned by another user.
	return err == nil || errors.Is(err, syscall.EPERM)
}

func systemctlVerb(cmd string) string {
	switch cmd {
	case "install":
		return "enable"
	case "uninstall":
		return "disable"
	}
	return cmd
}
