//go:build windows

package winservice

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Status is a service's state and the settings `imas-sprout status` shows.
type Status struct {
	State                   svc.State
	PID                     uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	StartType               uint32
	BinaryPath              string
	Account                 string
	// Recovery and RecoveryReset are the failure actions; RecoveryErr is
	// set instead when they can't be read.
	Recovery      []mgr.RecoveryAction
	RecoveryReset time.Duration
	RecoveryErr   error
}

// Exit codes of `imas-sprout status`, as systemctl status uses them.
const (
	StatusRunning      = 0
	StatusNotRunning   = 3
	StatusNotInstalled = 4
)

// ExitCode is StatusRunning only when the service is Running, and
// StatusNotRunning in any other state (stopped, pending, paused).
func (s Status) ExitCode() int {
	if s.State == svc.Running {
		return StatusRunning
	}
	return StatusNotRunning
}

// QueryStatus reads the service's state and settings. It asks only for
// query access, so unlike the other commands it works without elevation.
// It returns ErrNotInstalled if the service doesn't exist.
func QueryStatus(name string) (Status, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Status{}, fmt.Errorf("connect to the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(m)
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Status{}, err
	}
	h, err := windows.OpenService(m, namep, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return Status{}, fmt.Errorf("%s: %w", name, ErrNotInstalled)
	}
	if err != nil {
		return Status{}, fmt.Errorf("open service %s: %w", name, err)
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return Status{}, fmt.Errorf("query %s: %w", name, err)
	}
	out := Status{
		State:                   st.State,
		PID:                     st.ProcessId,
		Win32ExitCode:           st.Win32ExitCode,
		ServiceSpecificExitCode: st.ServiceSpecificExitCode,
	}
	// QueryServiceConfig directly, not s.Config(): that also reads
	// QueryServiceConfig2 levels this command doesn't show, and fails
	// outright where they are missing (wine).
	if err := queryConfig(h, &out); err != nil {
		return Status{}, fmt.Errorf("read the config of %s: %w", name, err)
	}
	if out.Recovery, out.RecoveryErr = s.RecoveryActions(); out.RecoveryErr == nil {
		reset, err := s.ResetPeriod()
		out.RecoveryErr = err
		out.RecoveryReset = time.Duration(reset) * time.Second
	}
	return out, nil
}

func queryConfig(h windows.Handle, out *Status) error {
	n := uint32(1024)
	for {
		b := make([]byte, n)
		p := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
		err := windows.QueryServiceConfig(h, p, n, &n)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return err
		}
		out.StartType = p.StartType
		out.BinaryPath = windows.UTF16PtrToString(p.BinaryPathName)
		out.Account = windows.UTF16PtrToString(p.ServiceStartName)
		return nil
	}
}

// Format renders s for `imas-sprout status`; logPath is where the service
// logs (see LogToFile).
func (s Status) Format(name, logPath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", name, stateText(s.State))
	switch {
	case s.State != svc.Stopped && s.PID != 0:
		fmt.Fprintf(&b, " (pid %d)", s.PID)
	case s.State == svc.Stopped && s.Win32ExitCode == uint32(windows.ERROR_SERVICE_NEVER_STARTED):
		b.WriteString(" (not started since boot)")
	case s.State == svc.Stopped && s.Win32ExitCode != 0:
		fmt.Fprintf(&b, " (last exit: %s)", exitCodes(svc.Status{
			Win32ExitCode: s.Win32ExitCode, ServiceSpecificExitCode: s.ServiceSpecificExitCode,
		}))
	}
	b.WriteString("\n")
	row := func(k, v string) { fmt.Fprintf(&b, "  %-11s %s\n", k+":", v) }
	row("start type", startTypeName(s.StartType))
	row("binary", s.BinaryPath)
	row("account", accountName(s.Account))
	row("on failure", recoveryText(s.Recovery, s.RecoveryReset, s.RecoveryErr))
	row("log", logPath)
	return b.String()
}

func stateText(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "resuming"
	case svc.PausePending:
		return "pausing"
	case svc.Paused:
		return "paused"
	}
	return fmt.Sprintf("state %d", s)
}

func startTypeName(t uint32) string {
	switch t {
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	case mgr.StartAutomatic:
		return "automatic"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	}
	return fmt.Sprintf("start type %d", t)
}

func accountName(a string) string {
	if a == "" || strings.EqualFold(a, "LocalSystem") {
		return "LocalSystem"
	}
	return a
}

func recoveryText(actions []mgr.RecoveryAction, reset time.Duration, err error) string {
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	var parts []string
	for _, a := range actions {
		switch a.Type {
		case mgr.NoAction:
			parts = append(parts, "none")
		case mgr.ServiceRestart:
			parts = append(parts, "restart after "+a.Delay.String())
		case mgr.ComputerReboot:
			parts = append(parts, "reboot after "+a.Delay.String())
		case mgr.RunCommand:
			parts = append(parts, "run a command after "+a.Delay.String())
		default:
			parts = append(parts, fmt.Sprintf("action %d after %s", a.Type, a.Delay))
		}
	}
	if len(parts) == 0 {
		return "none (the service stays down)"
	}
	text := strings.Join(parts, ", ")
	if reset > 0 {
		text += fmt.Sprintf("; failure count resets after %s", reset)
	}
	return text
}
