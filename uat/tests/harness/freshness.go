package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Freshness is the harness's half of REFRESH_AFTER (W10; uat/RUNBOOK.md,
// "The test channel"): before a kubectl call through a Bastion kube tunnel,
// it reads the Azure login's and the kube tunnels' ages from the session's
// files and, when one is past REFRESH_AFTER, has uat/access/session.sh
// renew them ("session.sh ensure kube") first. vmctl.sh makes the same
// check before each of its own commands, and session.sh's supervisor every
// minute; this covers a kubectl call that comes first. The check reads two
// file times and runs nothing when they are young.
type Freshness struct {
	// Hook is uat/access/session.sh (UAT_SESSION_HOOK).
	Hook string
	// AccessDir is tunnels.sh's state directory (UAT_SESSION_ACCESS): its
	// opened/<vm>-kube files are the kube tunnels' ages.
	AccessDir string
	// LoginStamp is az-relogin.sh's stamp, whose time is the login's.
	LoginStamp string
	// After is REFRESH_AFTER (UAT_REFRESH_AFTER_MIN, 10 minutes).
	After time.Duration
	// Every is the least time between two checks (default 10 s): many
	// kubectl calls in a row read the files once.
	Every time.Duration
	// Now and Run replace the clock and running the hook, for tests.
	Now func() time.Time
	Run func(ctx context.Context, hook string, args ...string) error

	mu   sync.Mutex
	last time.Time
}

// Env names Freshness reads.
const (
	EnvSessionHook   = "UAT_SESSION_HOOK"
	EnvSessionAccess = "UAT_SESSION_ACCESS"
	EnvReloginDir    = "AZ_RELOGIN_DIR"
	EnvRefreshAfter  = "UAT_REFRESH_AFTER_MIN"
)

// FreshnessFromEnv returns the run's Freshness, or nil when the run has no
// session hook or no tunnels (the local rig).
func FreshnessFromEnv() *Freshness {
	hook, access := os.Getenv(EnvSessionHook), os.Getenv(EnvSessionAccess)
	if hook == "" || access == "" {
		return nil
	}
	dir := os.Getenv(EnvReloginDir)
	if dir == "" {
		dir = os.Getenv("RUNNER_TEMP")
	}
	if dir == "" {
		dir = "/tmp"
	}
	after := 10 * time.Minute
	if n, err := strconv.Atoi(os.Getenv(EnvRefreshAfter)); err == nil && n > 0 {
		after = time.Duration(n) * time.Minute
	}
	return &Freshness{Hook: hook, AccessDir: access, LoginStamp: filepath.Join(dir, "az-relogin.stamp"), After: after}
}

func (f *Freshness) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// Due says what is past REFRESH_AFTER: "" when nothing is, else what and
// how old. A file that is missing is not due (nothing to renew).
func (f *Freshness) Due() string {
	now := f.now()
	var due []string
	if st, err := os.Stat(f.LoginStamp); err == nil {
		if age := now.Sub(st.ModTime()); age >= f.After {
			due = append(due, fmt.Sprintf("azure login %s old", age.Round(time.Second)))
		}
	}
	kubes, _ := filepath.Glob(filepath.Join(f.AccessDir, "opened", "*-kube"))
	for _, k := range kubes {
		b, err := os.ReadFile(k)
		if err != nil {
			continue
		}
		at, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			continue
		}
		if age := now.Sub(time.Unix(at, 0)); age >= f.After {
			due = append(due, fmt.Sprintf("%s tunnel %s old", strings.TrimSuffix(filepath.Base(k), "-kube")+" kube", age.Round(time.Second)))
		}
	}
	return strings.Join(due, ", ")
}

// Ensure renews what Due names, through the hook, at most once per Every.
// A failed renewal is returned, for the caller to log; the kubectl call
// goes ahead either way.
func (f *Freshness) Ensure(ctx context.Context) error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	every := f.Every
	if every <= 0 {
		every = 10 * time.Second
	}
	if now := f.now(); !f.last.IsZero() && now.Sub(f.last) < every {
		return nil
	}
	f.last = f.now()
	due := f.Due()
	if due == "" {
		return nil
	}
	run := f.Run
	if run == nil {
		run = runHook
	}
	if err := run(ctx, f.Hook, "ensure", "kube"); err != nil {
		return fmt.Errorf("renewing the session (%s): %w", due, err)
	}
	return nil
}

func runHook(ctx context.Context, hook string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, hook, args...)
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", hook, strings.Join(args, " "), err, tail(out, 600))
	}
	return nil
}

var (
	defaultFreshnessOnce sync.Once
	defaultFreshness     *Freshness
)

// sessionFreshness is the process's Freshness, from the environment.
func sessionFreshness() *Freshness {
	defaultFreshnessOnce.Do(func() { defaultFreshness = FreshnessFromEnv() })
	return defaultFreshness
}
