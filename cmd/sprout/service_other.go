//go:build !windows

package main

import (
	"context"
	"fmt"
)

// runAsService reports false: only Windows has a service manager that
// needs the process to check in. See service_windows.go.
func runAsService(func(context.Context)) bool { return false }

// startServiceLog is a no-op: a Unix service manager (systemd, OpenRC)
// collects stderr itself.
func startServiceLog() {}

const serviceCommandsHelp = `install, uninstall, start, stop and status manage the Windows service. On
this system, use the service manager: systemctl (or rc-service) start imas-sprout.
`

// runServiceCommand fails: the service commands are Windows-only.
func runServiceCommand(cmd string) int {
	return serviceCommandFailed(cmd, fmt.Errorf("%s manages the Windows service; on this system use the "+
		"service manager, e.g. systemctl %s imas-sprout", cmd, systemctlVerb(cmd)))
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
