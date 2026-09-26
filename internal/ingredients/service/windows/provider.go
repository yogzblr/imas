//go:build windows

// Package windows implements service.ServiceProvider against the Windows
// Service Control Manager via golang.org/x/sys/windows/svc/mgr.
//
// Windows has no native concept of "masking" a service the way systemd
// does. This provider maps the ServiceProvider surface onto the SCM's
// start-type config: Enable/Disable toggle Automatic vs. Manual start,
// and Mask/Unmask toggle Disabled vs. Manual start. Unmasking always
// restores Manual (not whatever start type was previously configured),
// since the SCM does not remember it for us.
package windows

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/service"
)

// ErrReloadNotSupported is returned for the "reloaded" method: Windows
// services have no generic reload signal equivalent to SIGHUP: restart
// instead.
var ErrReloadNotSupported = errors.New("windows services do not support reload; use restart instead")

// pollInterval is how often waitForState re-queries service status while
// waiting for a start/stop transition to complete. Overridable in tests.
var pollInterval = 200 * time.Millisecond

// scmService is the subset of *mgr.Service used by this provider, factored
// out so tests can substitute a fake.
type scmService interface {
	Start(args ...string) error
	Control(c svc.Cmd) (svc.Status, error)
	Query() (svc.Status, error)
	Config() (mgr.Config, error)
	UpdateConfig(c mgr.Config) error
	Close() error
}

// scmManager is the subset of *mgr.Mgr used by this provider.
type scmManager interface {
	OpenService(name string) (scmService, error)
	Disconnect() error
}

type realManager struct{ m *mgr.Mgr }

func (r realManager) OpenService(name string) (scmService, error) {
	s, err := r.m.OpenService(name)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r realManager) Disconnect() error { return r.m.Disconnect() }

// connectManager opens a connection to the SCM. Replaceable in tests.
var connectManager = func() (scmManager, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	return realManager{m}, nil
}

// WindowsService implements service.ServiceProvider against the Windows SCM.
type WindowsService struct {
	id     string
	name   string
	method string
	props  map[string]interface{}
}

// Compile-time interface check.
var _ service.ServiceProvider = WindowsService{}

func init() {
	service.RegisterProvider(WindowsService{})
}

func (s WindowsService) Properties() (map[string]interface{}, error) {
	return s.props, nil
}

func (s WindowsService) Parse(id, method string, properties map[string]interface{}) (service.ServiceProvider, error) {
	if properties == nil {
		properties = make(map[string]interface{})
	}
	nameI, ok := properties["name"]
	if !ok {
		return nil, ingredients.ErrMissingName
	}
	name, ok := nameI.(string)
	if !ok || name == "" {
		return nil, ingredients.ErrMissingName
	}
	return WindowsService{id: id, name: name, method: method, props: properties}, nil
}

func (s WindowsService) InitName() string {
	return "windows"
}

// IsInit always returns true: this provider only compiles on GOOS=windows,
// so if it is registered at all, it is the only usable provider.
func (s WindowsService) IsInit() bool {
	return true
}

func (s WindowsService) withService(fn func(scmService) error) error {
	m, err := connectManager()
	if err != nil {
		return fmt.Errorf("connecting to service control manager: %w", err)
	}
	defer m.Disconnect()
	sv, err := m.OpenService(s.name)
	if err != nil {
		return fmt.Errorf("opening service %q: %w", s.name, err)
	}
	defer sv.Close()
	return fn(sv)
}

func waitForState(ctx context.Context, sv scmService, want svc.State) error {
	for {
		status, err := sv.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func stateString(st svc.State) string {
	switch st {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start_pending"
	case svc.StopPending:
		return "stop_pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue_pending"
	case svc.PausePending:
		return "pause_pending"
	case svc.Paused:
		return "paused"
	default:
		return "unknown"
	}
}

func (s WindowsService) Start(ctx context.Context) error {
	return s.withService(func(sv scmService) error {
		status, err := sv.Query()
		if err != nil {
			return fmt.Errorf("querying service %q: %w", s.name, err)
		}
		if status.State == svc.Running {
			return nil
		}
		if err := sv.Start(); err != nil {
			return fmt.Errorf("starting service %q: %w", s.name, err)
		}
		return waitForState(ctx, sv, svc.Running)
	})
}

func (s WindowsService) Stop(ctx context.Context) error {
	return s.withService(func(sv scmService) error {
		status, err := sv.Query()
		if err != nil {
			return fmt.Errorf("querying service %q: %w", s.name, err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		if _, err := sv.Control(svc.Stop); err != nil {
			return fmt.Errorf("stopping service %q: %w", s.name, err)
		}
		return waitForState(ctx, sv, svc.Stopped)
	})
}

func (s WindowsService) Restart(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}
	return s.Start(ctx)
}

// Reload is not supported by the Windows SCM.
func (s WindowsService) Reload(_ context.Context) error {
	return ErrReloadNotSupported
}

func (s WindowsService) Status(ctx context.Context) (string, error) {
	var result string
	err := s.withService(func(sv scmService) error {
		status, err := sv.Query()
		if err != nil {
			return err
		}
		result = stateString(status.State)
		return nil
	})
	return result, err
}

func (s WindowsService) IsRunning(ctx context.Context) (bool, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return false, err
	}
	return status == "running", nil
}

func (s WindowsService) setStartType(t uint32) error {
	return s.withService(func(sv scmService) error {
		cfg, err := sv.Config()
		if err != nil {
			return fmt.Errorf("reading config for service %q: %w", s.name, err)
		}
		cfg.StartType = t
		if err := sv.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("updating config for service %q: %w", s.name, err)
		}
		return nil
	})
}

func (s WindowsService) Enable(_ context.Context) error {
	return s.setStartType(mgr.StartAutomatic)
}

func (s WindowsService) Disable(_ context.Context) error {
	return s.setStartType(mgr.StartManual)
}

func (s WindowsService) IsEnabled(_ context.Context) (bool, error) {
	var enabled bool
	err := s.withService(func(sv scmService) error {
		cfg, err := sv.Config()
		if err != nil {
			return err
		}
		enabled = cfg.StartType == mgr.StartAutomatic
		return nil
	})
	return enabled, err
}

// Mask sets the service's start type to Disabled, matching systemd's
// mask semantics (the service cannot be started at all, even manually).
func (s WindowsService) Mask(_ context.Context) error {
	return s.setStartType(mgr.StartDisabled)
}

// Unmask restores the service to Manual start. It does not attempt to
// remember whatever start type was configured before masking.
func (s WindowsService) Unmask(_ context.Context) error {
	return s.setStartType(mgr.StartManual)
}

func (s WindowsService) IsMasked(_ context.Context) (bool, error) {
	var masked bool
	err := s.withService(func(sv scmService) error {
		cfg, err := sv.Config()
		if err != nil {
			return err
		}
		masked = cfg.StartType == mgr.StartDisabled
		return nil
	})
	return masked, err
}
