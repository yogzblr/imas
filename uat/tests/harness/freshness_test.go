package harness

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// freshFixture is a session's files: the login stamp and two kube tunnels'
// opened/ stamps, each the given age.
func freshFixture(t *testing.T, now time.Time, login, core, dmz time.Duration) *Freshness {
	t.Helper()
	dir := t.TempDir()
	stamp := filepath.Join(dir, "az-relogin.stamp")
	if err := os.WriteFile(stamp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stamp, now.Add(-login), now.Add(-login)); err != nil {
		t.Fatal(err)
	}
	opened := filepath.Join(dir, "access", "opened")
	if err := os.MkdirAll(opened, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, age := range map[string]time.Duration{"uat-core-kube": core, "uat-dmz-kube": dmz, "t1-ubuntu-ssh": 30 * time.Minute} {
		at := strconv.FormatInt(now.Add(-age).Unix(), 10)
		if err := os.WriteFile(filepath.Join(opened, name), []byte(at+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Freshness{Hook: "session.sh", AccessDir: filepath.Join(dir, "access"), LoginStamp: stamp,
		After: 10 * time.Minute, Now: func() time.Time { return now }}
}

func TestFreshnessDue(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	if got := freshFixture(t, now, 2*time.Minute, 3*time.Minute, 9*time.Minute).Due(); got != "" {
		t.Errorf("young login and kube tunnels: Due = %q, want nothing (an old SSH tunnel is vmctl.sh's)", got)
	}
	got := freshFixture(t, now, 11*time.Minute, 3*time.Minute, 12*time.Minute).Due()
	if !strings.Contains(got, "azure login 11m0s old") || !strings.Contains(got, "uat-dmz kube tunnel 12m0s old") || strings.Contains(got, "uat-core") {
		t.Errorf("Due = %q, want the login and uat-dmz's kube tunnel only", got)
	}
	f := freshFixture(t, now, 10*time.Minute, 0, 0)
	if got := f.Due(); !strings.Contains(got, "azure login") {
		t.Errorf("a login of exactly REFRESH_AFTER is due: Due = %q", got)
	}
	f.LoginStamp = filepath.Join(t.TempDir(), "none")
	f.AccessDir = t.TempDir()
	if got := f.Due(); got != "" {
		t.Errorf("no session files: Due = %q, want nothing", got)
	}
}

func TestFreshnessEnsureRunsTheHookOnlyWhenDue(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	var calls []string
	run := func(_ context.Context, hook string, args ...string) error {
		calls = append(calls, hook+" "+strings.Join(args, " "))
		return nil
	}
	young := freshFixture(t, now, time.Minute, time.Minute, time.Minute)
	young.Run = run
	if err := young.Ensure(context.Background()); err != nil || len(calls) != 0 {
		t.Fatalf("young: err %v, calls %v; want no call", err, calls)
	}
	old := freshFixture(t, now, time.Minute, 15*time.Minute, time.Minute)
	old.Run = run
	if err := old.Ensure(context.Background()); err != nil || len(calls) != 1 || calls[0] != "session.sh ensure kube" {
		t.Fatalf("old kube tunnel: err %v, calls %v; want session.sh ensure kube", err, calls)
	}
	// Within Every of the last check, no second look.
	if err := old.Ensure(context.Background()); err != nil || len(calls) != 1 {
		t.Fatalf("second check within Every: calls %v", calls)
	}
	var nilF *Freshness
	if err := nilF.Ensure(context.Background()); err != nil {
		t.Errorf("a nil Freshness (the local rig) is a no-op: %v", err)
	}
}

func TestFreshnessFromEnv(t *testing.T) {
	t.Setenv(EnvSessionHook, "")
	t.Setenv(EnvSessionAccess, "/x")
	if FreshnessFromEnv() != nil {
		t.Error("no hook: want nil")
	}
	t.Setenv(EnvSessionHook, "/repo/uat/access/session.sh")
	t.Setenv(EnvReloginDir, "/state/session")
	t.Setenv(EnvRefreshAfter, "7")
	f := FreshnessFromEnv()
	if f == nil || f.After != 7*time.Minute || f.LoginStamp != "/state/session/az-relogin.stamp" || f.AccessDir != "/x" {
		t.Errorf("FreshnessFromEnv = %+v", f)
	}
}
