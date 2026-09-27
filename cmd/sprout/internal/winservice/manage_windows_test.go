//go:build windows

package winservice

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// fakeService is a scripted SCM: each Query returns the next state in
// states (the last one repeats), and startErr/controlErrs are what Start
// and successive Control calls return.
type fakeService struct {
	states      []svc.Status
	startErr    error
	controlErrs []error
	starts      int
	controls    int
}

func (f *fakeService) Start(...string) error {
	f.starts++
	return f.startErr
}

func (f *fakeService) Control(c svc.Cmd) (svc.Status, error) {
	if c != svc.Stop {
		return svc.Status{}, errors.New("unexpected control")
	}
	f.controls++
	if len(f.controlErrs) > 0 {
		err := f.controlErrs[0]
		f.controlErrs = f.controlErrs[1:]
		return svc.Status{}, err
	}
	return svc.Status{}, nil
}

func (f *fakeService) Query() (svc.Status, error) {
	st := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return st, nil
}

func states(ss ...svc.State) []svc.Status {
	out := make([]svc.Status, len(ss))
	for i, s := range ss {
		out[i] = svc.Status{State: s}
	}
	return out
}

const (
	fastPoll    = time.Millisecond
	testWait    = time.Second
	shortExpiry = 20 * time.Millisecond
)

func TestStartAndWait(t *testing.T) {
	t.Run("starts", func(t *testing.T) {
		f := &fakeService{states: states(svc.StartPending, svc.StartPending, svc.Running)}
		if err := startAndWait(f, testWait, fastPoll); err != nil {
			t.Fatal(err)
		}
		if f.starts != 1 {
			t.Errorf("Start called %d times", f.starts)
		}
	})
	t.Run("already running", func(t *testing.T) {
		f := &fakeService{states: states(svc.Running), startErr: windows.ERROR_SERVICE_ALREADY_RUNNING}
		if err := startAndWait(f, testWait, fastPoll); err != nil {
			t.Fatalf("already running: %v, want success", err)
		}
	})
	t.Run("start refused", func(t *testing.T) {
		f := &fakeService{states: states(svc.Stopped), startErr: windows.ERROR_SERVICE_DISABLED}
		if err := startAndWait(f, testWait, fastPoll); !errors.Is(err, windows.ERROR_SERVICE_DISABLED) {
			t.Fatalf("err = %v, want ERROR_SERVICE_DISABLED", err)
		}
	})
	t.Run("dies while starting", func(t *testing.T) {
		f := &fakeService{states: []svc.Status{
			{State: svc.StartPending},
			{State: svc.Stopped, Win32ExitCode: 1067},
		}}
		err := startAndWait(f, testWait, fastPoll)
		if err == nil || !strings.Contains(err.Error(), "exit code 1067") {
			t.Fatalf("err = %v, want the exit code", err)
		}
	})
	t.Run("service-specific exit code", func(t *testing.T) {
		f := &fakeService{states: []svc.Status{{
			State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: 7,
		}}}
		err := startAndWait(f, testWait, fastPoll)
		if err == nil || !strings.Contains(err.Error(), "service-specific exit code 7") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := &fakeService{states: states(svc.StartPending)}
		err := startAndWait(f, shortExpiry, fastPoll)
		if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "StartPending") {
			t.Fatalf("err = %v, want a timeout naming the state", err)
		}
	})
}

func TestStopAndWait(t *testing.T) {
	t.Run("stops", func(t *testing.T) {
		f := &fakeService{states: states(svc.Running, svc.StopPending, svc.StopPending, svc.Stopped)}
		if err := stopAndWait(f, testWait, fastPoll); err != nil {
			t.Fatal(err)
		}
		if f.controls != 1 {
			t.Errorf("Stop sent %d times, want 1", f.controls)
		}
	})
	t.Run("already stopped", func(t *testing.T) {
		f := &fakeService{states: states(svc.Stopped)}
		if err := stopAndWait(f, testWait, fastPoll); err != nil {
			t.Fatal(err)
		}
		if f.controls != 0 {
			t.Errorf("Stop sent to a stopped service")
		}
	})
	t.Run("already stopping", func(t *testing.T) {
		f := &fakeService{states: states(svc.StopPending, svc.Stopped)}
		if err := stopAndWait(f, testWait, fastPoll); err != nil {
			t.Fatal(err)
		}
		if f.controls != 0 {
			t.Errorf("Stop sent to a stopping service")
		}
	})
	t.Run("start pending, then accepts stop", func(t *testing.T) {
		f := &fakeService{
			states: states(svc.StartPending, svc.StartPending, svc.Running, svc.Stopped),
			controlErrs: []error{
				windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
				windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
			},
		}
		if err := stopAndWait(f, testWait, fastPoll); err != nil {
			t.Fatal(err)
		}
		if f.controls != 3 {
			t.Errorf("Stop sent %d times, want 3", f.controls)
		}
	})
	t.Run("stopped in between", func(t *testing.T) {
		f := &fakeService{states: states(svc.Running, svc.Stopped), controlErrs: []error{windows.ERROR_SERVICE_NOT_ACTIVE}}
		if err := stopAndWait(f, testWait, fastPoll); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("control fails", func(t *testing.T) {
		f := &fakeService{states: states(svc.Running), controlErrs: []error{windows.ERROR_ACCESS_DENIED}}
		if err := stopAndWait(f, testWait, fastPoll); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("err = %v, want ERROR_ACCESS_DENIED", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := &fakeService{states: states(svc.Running, svc.StopPending)}
		err := stopAndWait(f, shortExpiry, fastPoll)
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v, want a timeout", err)
		}
	})
	t.Run("never accepts stop", func(t *testing.T) {
		f := &fakeService{states: states(svc.StartPending)}
		for i := 0; i < 1000; i++ {
			f.controlErrs = append(f.controlErrs, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
		}
		err := stopAndWait(f, shortExpiry, fastPoll)
		if !errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
			t.Fatalf("err = %v, want a timeout wrapping ERROR_SERVICE_CANNOT_ACCEPT_CTRL", err)
		}
	})
}

// The service Install creates must match the MSI's ServiceInstall row and
// MsiServiceConfigFailureActions table (packaging/windows/).
func TestServiceConfigMatchesMSI(t *testing.T) {
	c := serviceConfig(Config{Name: "imas-sprout", DisplayName: "imas Sprout", Description: "imas remote control agent"})
	if c.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || c.StartType != mgr.StartAutomatic ||
		c.ErrorControl != mgr.ErrorNormal || c.ServiceStartName != "" || c.DelayedAutoStart {
		t.Errorf("config = %+v, want own process, automatic start, normal errors, LocalSystem", c)
	}
	if c.DisplayName != "imas Sprout" || c.Description != "imas remote control agent" {
		t.Errorf("names = %q / %q", c.DisplayName, c.Description)
	}
	ra := recoveryActions()
	if len(ra) != 3 {
		t.Fatalf("%d recovery actions, want 3", len(ra))
	}
	for i, a := range ra {
		if a.Type != mgr.ServiceRestart || a.Delay != 5*time.Second {
			t.Errorf("action %d = %+v, want restart after 5s", i, a)
		}
	}
	if recoveryResetAfter != 86400*time.Second {
		t.Errorf("reset period = %s, want 86400s", recoveryResetAfter)
	}
}

// TestSCMCommandsE2E installs, starts, stops and uninstalls a real
// service. It changes the machine's service configuration, so it only runs
// when IMAS_WINSERVICE_E2E_EXE names a service binary (one that calls
// winservice.Run), from an elevated prompt.
func TestSCMCommandsE2E(t *testing.T) {
	exe := os.Getenv("IMAS_WINSERVICE_E2E_EXE")
	if exe == "" {
		t.Skip("set IMAS_WINSERVICE_E2E_EXE to a service binary to run")
	}
	const name = "imas-winservice-e2e"
	c := Config{Name: name, DisplayName: "imas winservice e2e", Description: "test"}
	if os.Getenv("IMAS_WINSERVICE_E2E_SKIP_ACL") != "" {
		// Wine synthesizes file DACLs from Unix modes; see the PR.
		saved := checkExe
		checkExe = func(string) error { return nil }
		t.Cleanup(func() { checkExe = saved })
	}
	t.Cleanup(func() { _ = Uninstall(name) })

	if err := Install(c, exe); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := Install(c, exe); !errors.Is(err, ErrExists) {
		t.Errorf("second install = %v, want ErrExists", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.OpenService(name)
	if err != nil {
		t.Fatal(err)
	}
	// Config and RecoveryActions read QueryServiceConfig2 levels that
	// wine's SCM doesn't implement (ERROR_INVALID_LEVEL); Windows does.
	switch cfg, err := s.Config(); {
	case errors.Is(err, windows.ERROR_INVALID_LEVEL):
		t.Log("this SCM can't report the service config; not checked")
	case err != nil:
		t.Fatal(err)
	case cfg.StartType != mgr.StartAutomatic || cfg.DisplayName != c.DisplayName:
		t.Errorf("installed config = %+v", cfg)
	}
	switch ra, err := s.RecoveryActions(); {
	case errors.Is(err, windows.ERROR_INVALID_LEVEL):
		t.Log("this SCM can't report recovery actions; not checked")
	case err != nil || len(ra) != 3:
		t.Errorf("recovery actions = %+v, %v", ra, err)
	}
	s.Close()
	m.Disconnect()

	// checkStatus asserts QueryStatus's state (and a PID while running).
	checkStatus := func(step string, want svc.State) {
		t.Helper()
		st, err := QueryStatus(name)
		if err != nil {
			t.Fatalf("status after %s: %v", step, err)
		}
		if st.State != want || (want == svc.Running) != (st.PID != 0) || st.StartType != mgr.StartAutomatic {
			t.Errorf("status after %s = %+v, want %s", step, st, stateName(want))
		}
	}
	checkStatus("install", svc.Stopped)
	for _, step := range []struct {
		name string
		f    func(string) error
		want svc.State
	}{
		{"stop (already stopped)", Stop, svc.Stopped},
		{"start", Start, svc.Running},
		{"start (already running)", Start, svc.Running},
		{"stop", Stop, svc.Stopped},
		{"start again", Start, svc.Running},
	} {
		if err := step.f(name); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		checkStatus(step.name, step.want)
	}
	if err := Uninstall(name); err != nil {
		t.Fatalf("uninstall (running): %v", err)
	}
	if _, err := QueryStatus(name); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("status after uninstall = %v, want ErrNotInstalled", err)
	}
	if err := Start(name); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("start after uninstall = %v, want ErrNotInstalled", err)
	}
	if err := Uninstall(name); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("second uninstall = %v, want ErrNotInstalled", err)
	}
}
