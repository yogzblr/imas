//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/cmd/sprout/internal/winservice"
	"github.com/yogzblr/imas/internal/busstatus"
	"github.com/yogzblr/imas/internal/config"
)

// serviceName is the SCM service the MSI installs
// (packaging/windows/imas-sprout.wxs), named like the systemd unit.
const serviceName = "imas-sprout"

// isService records, before init runs, whether the SCM started this
// process. A detection error is reported by runAsService.
var isService, isServiceErr = winservice.IsService()

// startServiceLog sends logs to %ProgramData%\imas\logs\sprout.log when
// the SCM started the process, since the SCM discards stderr. A console
// run keeps logging to stderr. If the file can't be opened there is
// nowhere to report it, so logs stay on stderr.
func startServiceLog() {
	if isServiceErr != nil || !isService {
		return
	}
	_, _ = winservice.LogToFile(serviceLogPath())
}

func serviceLogPath() string {
	return filepath.Join(config.SproutServiceLogDir(), "sprout.log")
}

// runAsService runs run under the SCM and reports true when the process
// was started as a Windows service, and reports false otherwise (started
// from a console), leaving run to the caller. It returns once the SCM has
// stopped the service; fatal errors inside run still exit the process
// without reporting SERVICE_STOPPED, so the SCM's failure actions (restart
// after 5s, set by the MSI) apply.
func runAsService(run func(context.Context)) bool {
	if isServiceErr != nil {
		log.Fatalf("cannot tell whether the sprout runs as a Windows service: %v", isServiceErr)
	}
	if !isService {
		return false
	}
	if err := winservice.Run(serviceName, run); err != nil {
		log.Fatalf("running as the %s service: %v", serviceName, err)
	}
	return true
}

const serviceCommandsHelp = `Service commands (all but status need an elevated prompt):
  install    register this binary as the imas-sprout service (automatic
             start, LocalSystem, restart 5s after a failure), as the MSI
             does; it is not started. Refused if a non-administrator can
             modify the binary or its directory.
  uninstall  stop the service and remove it. For an MSI install, uninstall
             the MSI instead.
  start      start the service and wait until it is running.
  stop       stop the service and wait until it has stopped.
  status     show the service's state and settings, and whether it is
             connected to the bus (needs an elevated prompt). Exit code 0
             if the service is running, 3 if it is not, 4 if it is not
             installed, whatever its bus connection.
`

// runServiceCommand runs one of serviceCommands and returns the exit code.
func runServiceCommand(cmd string) int {
	if cmd == "status" {
		return statusCommand()
	}
	if err := doServiceCommand(cmd); err != nil {
		return serviceCommandFailed(cmd, err)
	}
	return 0
}

func doServiceCommand(cmd string) error {
	if isService {
		return fmt.Errorf("not available while running as the service")
	}
	switch cmd {
	case "install":
		exe, err := winservice.ExePath()
		if err != nil {
			return err
		}
		if err := winservice.Install(winservice.Config{
			Name:        serviceName,
			DisplayName: "imas Sprout",
			Description: "imas remote control agent",
		}, exe); err != nil {
			return err
		}
		fmt.Printf("installed the %s service (%s). Set the farmer address and join token in the "+
			"sprout config, then run: imas-sprout start\n", serviceName, exe)
	case "uninstall":
		if err := winservice.Uninstall(serviceName); err != nil {
			return err
		}
		fmt.Printf("removed the %s service\n", serviceName)
	case "start":
		if err := winservice.Start(serviceName); err != nil {
			return err
		}
		fmt.Printf("%s is running\n", serviceName)
	case "stop":
		if err := winservice.Stop(serviceName); err != nil {
			return err
		}
		fmt.Printf("%s is stopped\n", serviceName)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// statusCommand prints the service's status and returns
// winservice.Status*: 0 running, 3 not running, 4 not installed; 1 if it
// can't be read.
func statusCommand() int {
	st, err := winservice.QueryStatus(serviceName)
	if errors.Is(err, winservice.ErrNotInstalled) {
		fmt.Printf("%s: not installed\n", serviceName)
		return winservice.StatusNotInstalled
	}
	if err != nil {
		return serviceCommandFailed("status", err)
	}
	fmt.Print(st.Format(serviceName, serviceLogPath()))
	// The exit code stays the service's: scripts already rely on it.
	path := config.SproutBusStatusFile()
	bus, err := busstatus.Read(path)
	isSprout := func(pid int) bool { return st.ExitCode() == winservice.StatusRunning && pid == int(st.PID) }
	text, _ := describeBusStatus(bus, err, path, isSprout, time.Now())
	fmt.Printf("  %-11s %s\n", "bus:", text)
	return st.ExitCode()
}
