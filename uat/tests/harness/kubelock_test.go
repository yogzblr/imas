//go:build unix

package harness

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeKubeconfig(t *testing.T, server string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte("clusters:\n- cluster:\n    server: "+server+"\n  name: c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKubeTunnelPort(t *testing.T) {
	if p := kubeTunnelPort(writeKubeconfig(t, "https://127.0.0.1:20103")); p != "20103" {
		t.Errorf("port %q", p)
	}
	if p := kubeTunnelPort(writeKubeconfig(t, "https://10.0.0.4:6443")); p != "" {
		t.Errorf("a non-tunnel server gave %q", p)
	}
}

// A reopen holds the lock exclusively: a kubectl call waits for it, and
// takes it shared once it is free (W11).
func TestHoldKubeTunnelWaitsForAReopen(t *testing.T) {
	access := t.TempDir()
	t.Setenv(EnvSessionAccess, access)
	kc := writeKubeconfig(t, "https://127.0.0.1:20103")
	lock := filepath.Join(access, "locks", "kube-20103.lock")
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	held := make(chan func())
	go func() { held <- holdKubeTunnel(context.Background(), kc) }()
	select {
	case release := <-held:
		release()
		t.Fatal("took the lock while a reopen held it")
	case <-time.After(500 * time.Millisecond):
	}
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	var release func()
	select {
	case release = <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("still waiting after the reopen let the lock go")
	}
	// Held shared now: a reopen can't take it.
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Error("a reopen took the lock under a kubectl call")
	}
	release()
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Errorf("the lock is not free after the call: %v", err)
	}
}

// A kubectl call refused while a kube tunnel is being reopened is tried
// again; without a reopen in progress it is not.
func TestKubectlRetriesARefusalDuringAReopen(t *testing.T) {
	access := t.TempDir()
	t.Setenv(EnvSessionAccess, access)
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	bin := filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\nn=$(cat " + count + " 2>/dev/null || echo 0); n=$((n+1)); echo $n > " + count + "\n" +
		"if [ $n -lt 2 ]; then echo 'The connection to the server 127.0.0.1:20103 was refused - did you specify the right host or port? dial tcp 127.0.0.1:20103: connect: connection refused' >&2; exit 1; fi\necho ok\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	k := &Kube{Hub: "core", Kubeconfig: writeKubeconfig(t, "https://127.0.0.1:20103"), Kubectl: bin}
	if _, err := k.Run(context.Background(), nil, "get", "pods"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("with no reopen in progress the refusal must stand: %v", err)
	}
	_ = os.Remove(count)
	if err := os.MkdirAll(filepath.Join(access, "reopening"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(access, "reopening", "uat-core-kube"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := k.Run(context.Background(), nil, "get", "pods")
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("retry during a reopen: %q %v", out, err)
	}
}

// Every script and helm call that runs kubectl on a kube tunnel holds the
// tunnel's shared lock for its whole run (W11), so the supervisor can't
// reopen the tunnel under it. UAT Run 3 on rc.23: HA6's bind-tenant.sh held
// none and was refused on uat-core-2's kube tunnel two seconds into a
// reopen. Each stub tries to take the lock exclusively, as a reopen does,
// and fails when it can.
func TestScriptCallsHoldTheKubeTunnelLock(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("no flock(1)")
	}
	access := t.TempDir()
	t.Setenv(EnvSessionAccess, access)
	t.Setenv(EnvSessionHook, "")
	kc := writeKubeconfig(t, "https://127.0.0.1:20109")
	lock := filepath.Join(access, "locks", "kube-20109.lock")
	// The lock's directory exists, so a stub's flock can open the file
	// whether or not the call took the lock first.
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	state := t.TempDir()
	guard := "#!/bin/sh\nif flock -xn " + lock + " true; then echo 'the kube tunnel lock is free under the call' >&2; exit 1; fi\n"
	stub := func(name, rest string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(guard+rest), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bind := stub("bind-tenant.sh", "printf 'pw\\n' >"+state+"/pw\n"+
		`echo "{\"username\":\"$5\",\"tenant_id\":\"$7\",\"role\":\"$6\",\"password_file\":\"pw\"}"`+"\n")
	stub(AcceptanceScriptName, "echo '{\"updated\":1}'\n")
	stub(OperatorScriptName, "echo '{\"status\":201,\"body\":{}}'\n")
	check := stub("check.sh", "echo 'PASS  x'\n")
	stub("helm", "exit 0\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	f, _ := fakeFleet(t)
	f.Env.Bind = BindConfig{Script: bind, Kubeconfig: kc, Endpoints: "/e", StateDir: state}
	c := context.Background()
	if _, err := f.bindScratchUser(c, "scratch-x", "admin", "t_aaaaaaaaaaaaaaaa"); err != nil {
		t.Errorf("bind-tenant.sh: %v", err)
	}
	if _, err := f.CoreProbe(c, nil, "retention"); err != nil {
		t.Errorf("acceptance.sh: %v", err)
	}
	if a, err := f.PostAlteredRelease(c, "v1.2.3"); err != nil || a.Status != 201 {
		t.Errorf("operator-release.sh: %+v %v", a, err)
	}
	h := testHA(nil, nil)
	h.Fleet = f
	h.Cfg = HAConfig{CoreKubeconfig: kc, CoreChart: "/c/farmer.tgz", CoreCheck: check}
	if out, err := h.RunCoreCheck(c); err != nil {
		t.Errorf("check.sh: %v: %s", err, out)
	}
	if err := h.HelmUpgrade(c, "core", "a=b"); err != nil {
		t.Errorf("helm upgrade: %v", err)
	}
	// And each let the lock go.
	if out, err := exec.Command("flock", "-xn", lock, "true").CombinedOutput(); err != nil {
		t.Errorf("the lock is still held after the calls: %v %s", err, out)
	}
}
