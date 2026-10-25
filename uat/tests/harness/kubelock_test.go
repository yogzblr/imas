//go:build unix

package harness

import (
	"context"
	"os"
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
	unlocked := make(chan struct{})
	go func() {
		defer close(unlocked)
		time.Sleep(600 * time.Millisecond)
		_ = syscall.Flock(fd, syscall.LOCK_UN)
	}()
	defer func() { <-unlocked }()
	start := time.Now()
	release := holdKubeTunnel(context.Background(), kc)
	if waited := time.Since(start); waited < 500*time.Millisecond {
		t.Errorf("took the lock in %s while a reopen held it", waited)
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
