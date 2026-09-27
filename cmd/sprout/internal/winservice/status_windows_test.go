//go:build windows

package winservice

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const logPath = `C:\ProgramData\imas\logs\sprout.log`

func TestStatusFormat_Running(t *testing.T) {
	s := Status{
		State:         svc.Running,
		PID:           4242,
		StartType:     mgr.StartAutomatic,
		BinaryPath:    `"C:\Program Files\imas\imas-sprout.exe"`,
		Account:       "LocalSystem",
		Recovery:      recoveryActions(),
		RecoveryReset: recoveryResetAfter,
	}
	want := `imas-sprout: running (pid 4242)
  start type: automatic
  binary:     "C:\Program Files\imas\imas-sprout.exe"
  account:    LocalSystem
  on failure: restart after 5s, restart after 5s, restart after 5s; failure count resets after 24h0m0s
  log:        C:\ProgramData\imas\logs\sprout.log
`
	if got := s.Format("imas-sprout", logPath); got != want {
		t.Errorf("Format =\n%s\nwant\n%s", got, want)
	}
	if s.ExitCode() != StatusRunning {
		t.Errorf("ExitCode = %d, want %d", s.ExitCode(), StatusRunning)
	}
}

func TestStatusFormat_FirstLine(t *testing.T) {
	cases := []struct {
		name string
		s    Status
		want string
		code int
	}{
		{"stopped cleanly", Status{State: svc.Stopped}, "imas-sprout: stopped\n", StatusNotRunning},
		{
			"crashed",
			Status{State: svc.Stopped, Win32ExitCode: 1067},
			"imas-sprout: stopped (last exit: exit code 1067: ",
			StatusNotRunning,
		},
		{
			"never started",
			Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_NEVER_STARTED)},
			"imas-sprout: stopped (not started since boot)\n",
			StatusNotRunning,
		},
		{
			"service-specific exit",
			Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: 3},
			"imas-sprout: stopped (last exit: service-specific exit code 3)\n",
			StatusNotRunning,
		},
		{"starting", Status{State: svc.StartPending, PID: 7}, "imas-sprout: starting (pid 7)\n", StatusNotRunning},
		{"stopping", Status{State: svc.StopPending, PID: 7}, "imas-sprout: stopping (pid 7)\n", StatusNotRunning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.s.Format("imas-sprout", logPath)
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("Format first line = %q, want prefix %q", strings.SplitAfter(got, "\n")[0], tc.want)
			}
			if tc.s.ExitCode() != tc.code {
				t.Errorf("ExitCode = %d, want %d", tc.s.ExitCode(), tc.code)
			}
		})
	}
}

func TestStatusFormat_Settings(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    Status
		want string
	}{
		{"manual start", Status{StartType: mgr.StartManual}, "start type: manual"},
		{"disabled", Status{StartType: mgr.StartDisabled}, "start type: disabled"},
		{"default account", Status{Account: ""}, "account:    LocalSystem"},
		{"other account", Status{Account: `NT AUTHORITY\LocalService`}, `account:    NT AUTHORITY\LocalService`},
		{"no recovery", Status{}, "on failure: none (the service stays down)"},
		{
			"recovery unreadable",
			Status{RecoveryErr: windows.ERROR_INVALID_LEVEL},
			"on failure: unknown (",
		},
		{
			"mixed actions, no reset",
			Status{Recovery: []mgr.RecoveryAction{
				{Type: mgr.ServiceRestart, Delay: time.Minute},
				{Type: mgr.NoAction},
			}},
			"on failure: restart after 1m0s, none\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.Format("imas-sprout", logPath); !strings.Contains(got, tc.want) {
				t.Errorf("Format =\n%s\nwant it to contain %q", got, tc.want)
			}
		})
	}
}

func TestQueryStatus_NotInstalled(t *testing.T) {
	_, err := QueryStatus("imas-winservice-does-not-exist")
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("QueryStatus = %v, want ErrNotInstalled", err)
	}
}
