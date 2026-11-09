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
// every kubectl call of the harness, and every script or helm call that
// runs kubectl (acceptance.sh, bind-tenant.sh, operator-release.sh, the
// core check, HA3's helm upgrade; onKubeTunnel), takes it shared for its
// whole run, so a reopen waits for the calls in flight and a call
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

// onKubeTunnel readies a script or helm call that runs kubectl on a hub's
// kube tunnel and is not retried: on an HA hub it first points kubeconfig
// at a node that answers (preSelect, W12), then holds that tunnel's shared
// lock (W11) until the returned release is called, so the supervisor
// cannot reopen the tunnel under the call. In that order: kube-select may
// reopen a tunnel itself, which needs the lock exclusively. UAT Run 3 on
// rc.23: HA6's bind-tenant.sh, which held no lock, got "connection
// refused" on uat-core-2's kube tunnel at 02:47:11Z, two seconds into the
// supervisor's reopen of it.
func onKubeTunnel(ctx context.Context, hub, kubeconfig string, ha bool) func() {
	if ha {
		preSelect(ctx, hub, kubeconfig)
	}
	return holdKubeTunnel(ctx, kubeconfig)
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

// --- an HA hub's API through its nodes' kube tunnels (W12) -----------------------

// An HA hub has no Bastion tunnel to its internal load balancer: Azure
// Bastion tunnels by IP to ports 22 and 3389 only (Azure UAT Run 3: "Custom
// ports are not allowed"). Its kubeconfig points at one node's kube tunnel
// and uat/access/session.sh kube-select moves it to another node of the hub
// whose tunnel answers (uat/access/channel.sh ch_kube_select). vmctl.sh
// stop-vm moves it before the ha tier stops a node; the harness asks again
// when a kubectl call cannot reach the API, and before a helm upgrade, the
// core check and acceptance.sh on an HA hub.

// kubeFailovers bounds the kube-selects one kubectl call may ask for.
const kubeFailovers = 2

// kubeSelectHook runs "session.sh kube-select <kubeconfig>". A variable,
// for tests.
var kubeSelectHook = func(ctx context.Context, hook, kubeconfig string) error {
	return runHook(ctx, hook, "kube-select", kubeconfig)
}

// kubeSelect points kubeconfig at a node whose kube tunnel answers, through
// the session hook, and says whether its server moved. Without a session
// ($UAT_SESSION_HOOK and $UAT_SESSION_ACCESS) or a kubeconfig on a tunnel it
// does nothing.
func kubeSelect(ctx context.Context, kubeconfig string) (moved bool, err error) {
	hook := os.Getenv(EnvSessionHook)
	if hook == "" || os.Getenv(EnvSessionAccess) == "" || kubeconfig == "" {
		return false, nil
	}
	before := kubeTunnelPort(kubeconfig)
	if before == "" {
		return false, nil
	}
	err = kubeSelectHook(ctx, hook, kubeconfig)
	return kubeTunnelPort(kubeconfig) != before, err
}

// unreachableAPI says a kubectl failure is one where the request never
// reached the API server: kubectl could not connect ("Unable to connect to
// the server", which covers a stopped node's Bastion tunnel closing the
// TLS handshake), or the local tunnel refused. A call that failed so can be
// run again on another node; one that failed after the server had it is
// never retried here.
func unreachableAPI(stderr []byte) bool {
	s := string(stderr)
	return strings.Contains(s, "Unable to connect to the server") || refusedOnTunnel(stderr)
}
