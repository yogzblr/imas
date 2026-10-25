package harness

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The kube tunnel lock (W11). UAT Run 2 on rc.21: session.sh's supervisor
// reopened uat-core's kube tunnel at 06:55:40Z, and D1's kubectl, started
// in the second between the supervisor's "no connection open" check and
// the reopen, got "connection refused" at 06:55:41Z. Now each kube tunnel
// has a reader/writer lock, <access dir>/locks/kube-<port>.lock (flock): a
// reopen takes it exclusively (uat/access/channel.sh ch_kube_lock), and
// every kubectl and acceptance.sh call of the harness takes it shared for
// its whole run, so a reopen waits for the calls in flight and a call
// waits for a reopen in progress. While a reopen runs, the channel also
// writes <access dir>/reopening/<vm>-kube; a single kubectl call that
// still gets "connection refused" on a tunnel being reopened is tried
// again for up to kubeReopenRetry.

const (
	// kubeLockWait bounds the wait for a reopen in progress (a reopen
	// takes up to about a minute: tunnels.sh's wait for the new tunnel).
	kubeLockWait = 3 * time.Minute
	// kubeReopenRetry bounds the retries of a refused connection while a
	// kube tunnel is being reopened.
	kubeReopenRetry = 30 * time.Second
)

var kubeServerRe = regexp.MustCompile(`(?m)^\s*server:\s*https://127\.0\.0\.1:([0-9]{1,5})\s*$`)

// kubeTunnelPort is the local port of the Bastion kube tunnel a kubeconfig
// points at, or "" when it points elsewhere (the local rig).
func kubeTunnelPort(kubeconfig string) string {
	b, err := os.ReadFile(kubeconfig)
	if err != nil {
		return ""
	}
	m := kubeServerRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// kubeLockPath is the lock file of the kube tunnel on port, or "" without
// a session (no UAT_SESSION_ACCESS: no tunnels).
func kubeLockPath(port string) string {
	dir := os.Getenv(EnvSessionAccess)
	if dir == "" || port == "" {
		return ""
	}
	return filepath.Join(dir, "locks", "kube-"+port+".lock")
}

// holdKubeTunnel takes the shared lock of the kube tunnel kubeconfig
// points at, waiting up to kubeLockWait for a reopen in progress, and
// returns its release. With no tunnel, or when the lock can't be taken,
// it holds nothing (the call goes ahead, as before W11).
func holdKubeTunnel(ctx context.Context, kubeconfig string) func() {
	path := kubeLockPath(kubeTunnelPort(kubeconfig))
	if path == "" {
		return func() {}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return func() {}
	}
	ctx, cancel := context.WithTimeout(ctx, kubeLockWait)
	defer cancel()
	release, err := lockShared(ctx, path)
	if err != nil {
		return func() {}
	}
	return release
}

// kubeReopening reports whether a kube tunnel is being reopened (a marker
// under <access dir>/reopening), and so a refused connection is worth
// another try.
func kubeReopening() bool {
	dir := os.Getenv(EnvSessionAccess)
	if dir == "" {
		return false
	}
	m, _ := filepath.Glob(filepath.Join(dir, "reopening", "*-kube"))
	return len(m) > 0
}

// refusedOnTunnel says a kubectl failure is a refused connection to a
// local tunnel port.
func refusedOnTunnel(stderr []byte) bool {
	s := string(stderr)
	return strings.Contains(s, "connection refused") && strings.Contains(s, "127.0.0.1:")
}
