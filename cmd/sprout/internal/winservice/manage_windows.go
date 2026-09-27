//go:build windows

package winservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Config describes the service Install creates.
type Config struct {
	Name        string
	DisplayName string
	Description string
}

// Recovery settings, as the MSI sets them
// (packaging/windows/msi-postprocess.sh): restart 5s after each of the
// first three failures (the SCM repeats the last action after that), and
// reset the failure count after a day.
const (
	restartDelay       = 5 * time.Second
	recoveryResetAfter = 24 * time.Hour
)

// Timeouts for Start and Stop to reach the requested state. Stop allows
// for the handler's StopWaitHint.
const (
	StartTimeout = 30 * time.Second
	StopTimeout  = StopWaitHint + 15*time.Second
	pollInterval = 250 * time.Millisecond
)

// ErrExists and ErrNotInstalled are returned by Install and by the other
// commands when the service is, or isn't, already registered.
var (
	ErrExists       = errors.New("the service is already installed")
	ErrNotInstalled = errors.New("the service is not installed")
)

// serviceConfig is the mgr.Config the MSI's ServiceInstall row amounts to:
// an own-process service, started automatically, running as LocalSystem.
func serviceConfig(c Config) mgr.Config {
	return mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  c.DisplayName,
		Description:  c.Description,
		// ServiceStartName "" is LocalSystem.
	}
}

func recoveryActions() []mgr.RecoveryAction {
	a := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: restartDelay}
	return []mgr.RecoveryAction{a, a, a}
}

// checkExe is checkNotUserWritable, replaceable by tests.
var checkExe = checkNotUserWritable

// Install registers exe as the service c.Name with the MSI's settings. It
// doesn't start it: like the MSI, it leaves that to the admin once the
// config (farmer address, join token) is in place.
//
// It refuses an exe that a non-administrator could replace (see
// checkNotUserWritable): the service runs it as LocalSystem.
func Install(c Config, exe string) error {
	exe, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	if err := checkExe(exe); err != nil {
		return err
	}
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(c.Name); err == nil {
		s.Close()
		return fmt.Errorf("%s: %w", c.Name, ErrExists)
	}
	s, err := m.CreateService(c.Name, exe, serviceConfig(c))
	if err != nil {
		return fmt.Errorf("create service %s: %w", c.Name, err)
	}
	defer s.Close()
	if err := s.SetRecoveryActions(recoveryActions(), uint32(recoveryResetAfter/time.Second)); err != nil {
		// Without them a crashed sprout stays down; don't leave that
		// half-configured service behind.
		if delErr := s.Delete(); delErr != nil {
			return fmt.Errorf("set recovery actions: %w (and removing the service failed: %v)", err, delErr)
		}
		return fmt.Errorf("set recovery actions: %w", err)
	}
	return nil
}

// Uninstall stops the service if it's running, then deletes it. The SCM
// removes it once every open handle to it is closed.
func Uninstall(name string) error {
	return withService(name, func(s *mgr.Service) error {
		if err := stopAndWait(s, StopTimeout, pollInterval); err != nil {
			return err
		}
		if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("delete service %s: %w", name, err)
		}
		return nil
	})
}

// Start starts the service and waits until it reports Running. A service
// that is already running is left alone.
func Start(name string) error {
	return withService(name, func(s *mgr.Service) error {
		return startAndWait(s, StartTimeout, pollInterval)
	})
}

// Stop stops the service and waits until it reports Stopped. A service
// that is already stopped is left alone.
func Stop(name string) error {
	return withService(name, func(s *mgr.Service) error {
		return stopAndWait(s, StopTimeout, pollInterval)
	})
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, fmt.Errorf("connect to the service manager: %w (run from an elevated prompt)", err)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to the service manager: %w", err)
	}
	return m, nil
}

func withService(name string, f func(*mgr.Service) error) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("%s: %w", name, ErrNotInstalled)
	}
	if err != nil {
		return fmt.Errorf("open service %s: %w", name, err)
	}
	defer s.Close()
	return f(s)
}

// service is the part of *mgr.Service the start/stop logic uses, so tests
// can fake the SCM.
type service interface {
	Start(args ...string) error
	Control(svc.Cmd) (svc.Status, error)
	Query() (svc.Status, error)
}

func startAndWait(s service, timeout, poll time.Duration) error {
	err := s.Start()
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start: %w", err)
	}
	st, err := waitFor(s, svc.Running, timeout, poll)
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return fmt.Errorf("the service stopped while starting (%s); see the service log", exitCodes(st))
	}
	return nil
}

func stopAndWait(s service, timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query: %w", err)
		}
		switch st.State {
		case svc.Stopped:
			return nil
		case svc.StopPending:
			// Already stopping: just wait.
		default:
			_, err := s.Control(svc.Stop)
			switch {
			case err == nil, errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
			case errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL):
				// Still StartPending: retry until it accepts Stop.
				if time.Now().After(deadline) {
					return fmt.Errorf("stop: timed out after %s: %w", timeout, err)
				}
				time.Sleep(poll)
				continue
			default:
				return fmt.Errorf("stop: %w", err)
			}
		}
		_, err = waitFor(s, svc.Stopped, time.Until(deadline), poll)
		return err
	}
}

// waitFor polls until the service reports want, or Stopped (a start that
// failed), or timeout passes. It returns the last status.
func waitFor(s service, want svc.State, timeout, poll time.Duration) (svc.Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return st, fmt.Errorf("query: %w", err)
		}
		if st.State == want || st.State == svc.Stopped {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("timed out after %s waiting for the service to reach %s (it is %s)",
				timeout, stateName(want), stateName(st.State))
		}
		time.Sleep(poll)
	}
}

func exitCodes(st svc.Status) string {
	if st.Win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
		return fmt.Sprintf("service-specific exit code %d", st.ServiceSpecificExitCode)
	}
	return fmt.Sprintf("exit code %d: %v", st.Win32ExitCode, windows.Errno(st.Win32ExitCode))
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "StartPending"
	case svc.StopPending:
		return "StopPending"
	case svc.Running:
		return "Running"
	case svc.ContinuePending:
		return "ContinuePending"
	case svc.PausePending:
		return "PausePending"
	case svc.Paused:
		return "Paused"
	}
	return fmt.Sprintf("state %d", s)
}

// ExePath is the running binary's path, for Install.
func ExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
