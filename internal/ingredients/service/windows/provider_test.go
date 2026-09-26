//go:build windows

package windows

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/yogzblr/imas/internal/ingredients"
)

// fakeService is a stub scmService that records calls and returns queued
// Query statuses in order (repeating the last one once exhausted).
type fakeService struct {
	calls []string

	startErr   error
	controlErr error

	queryStatuses []svc.Status
	queryIdx      int
	queryErr      error

	cfg          mgr.Config
	cfgErr       error
	updateCfgErr error
	closed       bool
}

func (f *fakeService) Start(_ ...string) error {
	f.calls = append(f.calls, "start")
	return f.startErr
}

func (f *fakeService) Control(_ svc.Cmd) (svc.Status, error) {
	f.calls = append(f.calls, "control")
	return svc.Status{}, f.controlErr
}

func (f *fakeService) Query() (svc.Status, error) {
	f.calls = append(f.calls, "query")
	if f.queryErr != nil {
		return svc.Status{}, f.queryErr
	}
	if len(f.queryStatuses) == 0 {
		return svc.Status{}, nil
	}
	idx := f.queryIdx
	if idx >= len(f.queryStatuses) {
		idx = len(f.queryStatuses) - 1
	}
	f.queryIdx++
	return f.queryStatuses[idx], nil
}

func (f *fakeService) Config() (mgr.Config, error) {
	f.calls = append(f.calls, "config")
	return f.cfg, f.cfgErr
}

func (f *fakeService) UpdateConfig(c mgr.Config) error {
	f.calls = append(f.calls, "updateconfig")
	f.cfg = c
	return f.updateCfgErr
}

func (f *fakeService) Close() error {
	f.closed = true
	return nil
}

type fakeManager struct {
	svc          *fakeService
	openErr      error
	disconnected bool
}

func (m *fakeManager) OpenService(_ string) (scmService, error) {
	if m.openErr != nil {
		return nil, m.openErr
	}
	return m.svc, nil
}

func (m *fakeManager) Disconnect() error {
	m.disconnected = true
	return nil
}

// installFake replaces connectManager with one returning the given fake
// service, restoring the original and shrinking pollInterval for the test.
func installFake(t *testing.T, fs *fakeService) *fakeManager {
	t.Helper()
	fm := &fakeManager{svc: fs}
	origConnect := connectManager
	origPoll := pollInterval
	pollInterval = 0
	connectManager = func() (scmManager, error) {
		return fm, nil
	}
	t.Cleanup(func() {
		connectManager = origConnect
		pollInterval = origPoll
	})
	return fm
}

func newProvider(name string) WindowsService {
	return WindowsService{id: "test-id", name: name, method: "running", props: map[string]interface{}{"name": name}}
}

// --- Parse ---

func TestWindowsInitName(t *testing.T) {
	s := WindowsService{}
	if got := s.InitName(); got != "windows" {
		t.Errorf("InitName() = %q, want %q", got, "windows")
	}
}

func TestWindowsIsInit(t *testing.T) {
	s := WindowsService{}
	if !s.IsInit() {
		t.Error("IsInit() should always return true")
	}
}

func TestWindowsParseMissingName(t *testing.T) {
	s := WindowsService{}
	_, err := s.Parse("id", "running", map[string]interface{}{})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestWindowsParseNilProperties(t *testing.T) {
	s := WindowsService{}
	_, err := s.Parse("id", "running", nil)
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName for nil properties, got %v", err)
	}
}

func TestWindowsParseEmptyName(t *testing.T) {
	s := WindowsService{}
	_, err := s.Parse("id", "running", map[string]interface{}{"name": ""})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName for empty name, got %v", err)
	}
}

func TestWindowsParseNameNotString(t *testing.T) {
	s := WindowsService{}
	_, err := s.Parse("id", "running", map[string]interface{}{"name": 123})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName for non-string name, got %v", err)
	}
}

func TestWindowsParseValid(t *testing.T) {
	s := WindowsService{}
	p, err := s.Parse("svc-1", "running", map[string]interface{}{"name": "spooler"})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	ws, ok := p.(WindowsService)
	if !ok {
		t.Fatal("Parse() did not return WindowsService")
	}
	if ws.name != "spooler" {
		t.Errorf("name = %q, want %q", ws.name, "spooler")
	}
}

func TestWindowsProperties(t *testing.T) {
	props := map[string]interface{}{"name": "spooler"}
	s := WindowsService{props: props}
	got, err := s.Properties()
	if err != nil {
		t.Fatalf("Properties() error: %v", err)
	}
	if got["name"] != "spooler" {
		t.Errorf("Properties()[name] = %v, want %q", got["name"], "spooler")
	}
}

// --- Start/Stop/Restart ---

func TestStart(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Stopped}, {State: svc.Running}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if !fs.closed {
		t.Error("service handle was not closed")
	}
}

func TestStartAlreadyRunning(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Running}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	for _, c := range fs.calls {
		if c == "start" {
			t.Error("Start() should not have issued a start command when already running")
		}
	}
}

func TestStartError(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Stopped}}, startErr: errors.New("boom")}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Start(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStop(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Running}, {State: svc.Stopped}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

func TestStopAlreadyStopped(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Stopped}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	for _, c := range fs.calls {
		if c == "control" {
			t.Error("Stop() should not have issued a control command when already stopped")
		}
	}
}

func TestStopError(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Running}}, controlErr: errors.New("boom")}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Stop(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRestart(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{
		{State: svc.Running}, {State: svc.Stopped},
		{State: svc.Stopped}, {State: svc.Running},
	}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Restart(context.Background()); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}
}

func TestReloadNotSupported(t *testing.T) {
	svcP := newProvider("spooler")
	if err := svcP.Reload(context.Background()); !errors.Is(err, ErrReloadNotSupported) {
		t.Errorf("Reload() error = %v, want ErrReloadNotSupported", err)
	}
}

// --- Status/IsRunning ---

func TestStatus(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Running}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	got, err := svcP.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if got != "running" {
		t.Errorf("Status() = %q, want %q", got, "running")
	}
}

func TestStatusError(t *testing.T) {
	fs := &fakeService{queryErr: errors.New("boom")}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if _, err := svcP.Status(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestIsRunningTrue(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Running}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	running, err := svcP.IsRunning(context.Background())
	if err != nil {
		t.Fatalf("IsRunning() error: %v", err)
	}
	if !running {
		t.Error("IsRunning() = false, want true")
	}
}

func TestIsRunningFalse(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Stopped}}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	running, err := svcP.IsRunning(context.Background())
	if err != nil {
		t.Fatalf("IsRunning() error: %v", err)
	}
	if running {
		t.Error("IsRunning() = true, want false")
	}
}

// --- Enable/Disable/IsEnabled ---

func TestEnable(t *testing.T) {
	fs := &fakeService{}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Enable(context.Background()); err != nil {
		t.Fatalf("Enable() error: %v", err)
	}
	if fs.cfg.StartType != mgr.StartAutomatic {
		t.Errorf("StartType = %v, want StartAutomatic", fs.cfg.StartType)
	}
}

func TestDisable(t *testing.T) {
	fs := &fakeService{}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Disable(context.Background()); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if fs.cfg.StartType != mgr.StartManual {
		t.Errorf("StartType = %v, want StartManual", fs.cfg.StartType)
	}
}

func TestIsEnabledTrue(t *testing.T) {
	fs := &fakeService{cfg: mgr.Config{StartType: mgr.StartAutomatic}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	enabled, err := svcP.IsEnabled(context.Background())
	if err != nil {
		t.Fatalf("IsEnabled() error: %v", err)
	}
	if !enabled {
		t.Error("IsEnabled() = false, want true")
	}
}

func TestIsEnabledFalse(t *testing.T) {
	fs := &fakeService{cfg: mgr.Config{StartType: mgr.StartManual}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	enabled, err := svcP.IsEnabled(context.Background())
	if err != nil {
		t.Fatalf("IsEnabled() error: %v", err)
	}
	if enabled {
		t.Error("IsEnabled() = true, want false")
	}
}

func TestEnableConfigError(t *testing.T) {
	fs := &fakeService{cfgErr: errors.New("boom")}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Enable(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Mask/Unmask/IsMasked ---

func TestMask(t *testing.T) {
	fs := &fakeService{}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Mask(context.Background()); err != nil {
		t.Fatalf("Mask() error: %v", err)
	}
	if fs.cfg.StartType != mgr.StartDisabled {
		t.Errorf("StartType = %v, want StartDisabled", fs.cfg.StartType)
	}
}

func TestUnmask(t *testing.T) {
	fs := &fakeService{cfg: mgr.Config{StartType: mgr.StartDisabled}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	if err := svcP.Unmask(context.Background()); err != nil {
		t.Fatalf("Unmask() error: %v", err)
	}
	if fs.cfg.StartType != mgr.StartManual {
		t.Errorf("StartType = %v, want StartManual", fs.cfg.StartType)
	}
}

func TestIsMaskedTrue(t *testing.T) {
	fs := &fakeService{cfg: mgr.Config{StartType: mgr.StartDisabled}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	masked, err := svcP.IsMasked(context.Background())
	if err != nil {
		t.Fatalf("IsMasked() error: %v", err)
	}
	if !masked {
		t.Error("IsMasked() = false, want true")
	}
}

func TestIsMaskedFalse(t *testing.T) {
	fs := &fakeService{cfg: mgr.Config{StartType: mgr.StartManual}}
	installFake(t, fs)
	svcP := newProvider("spooler")
	masked, err := svcP.IsMasked(context.Background())
	if err != nil {
		t.Fatalf("IsMasked() error: %v", err)
	}
	if masked {
		t.Error("IsMasked() = true, want false")
	}
}

// --- withService wiring ---

func TestOpenServiceError(t *testing.T) {
	fm := installFake(t, &fakeService{})
	fm.openErr = errors.New("not found")
	svcP := newProvider("spooler")
	if err := svcP.Start(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDisconnectCalled(t *testing.T) {
	fs := &fakeService{queryStatuses: []svc.Status{{State: svc.Running}}}
	fm := installFake(t, fs)
	svcP := newProvider("spooler")
	if _, err := svcP.Status(context.Background()); err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if !fm.disconnected {
		t.Error("Disconnect() was not called")
	}
}
