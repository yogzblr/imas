package sdb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genCert writes a minimal self-signed cert/key pair (PEM) for commonName
// to certPath/keyPath, for exercising CertWatcher without a real CA.
func genCert(t *testing.T, certPath, keyPath, commonName string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
}

func TestCertWatcher_LoadsInitialCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath, "initial")

	w, err := NewCertWatcher(certPath, keyPath, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer w.Close()

	cert, err := w.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil || cert.Certificate == nil {
		t.Fatal("expected a loaded certificate")
	}
}

func TestCertWatcher_ReloadsOnRotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath, "initial")

	w, err := NewCertWatcher(certPath, keyPath, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer w.Close()

	before, _ := w.GetClientCertificate(nil)

	// Simulate a customer dropping in a rotated cert: bump the mtime so
	// changed() notices even on filesystems with coarse mtime granularity.
	genCert(t, certPath, keyPath, "rotated")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}

	if !w.changed() {
		t.Fatal("expected changed() to detect the rotated files")
	}
	if err := w.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	after, _ := w.GetClientCertificate(nil)
	if string(after.Certificate[0]) == string(before.Certificate[0]) {
		t.Error("expected the reloaded certificate to differ from the original")
	}
}

func TestCertWatcher_BackgroundReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath, "initial")

	w, err := NewCertWatcher(certPath, keyPath, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer w.Close()

	before, _ := w.GetClientCertificate(nil)

	genCert(t, certPath, keyPath, "rotated")
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		after, _ := w.GetClientCertificate(nil)
		if string(after.Certificate[0]) != string(before.Certificate[0]) {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background watcher did not pick up the rotated cert in time")
}

func TestCertWatcher_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := NewCertWatcher(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), time.Hour)
	if err == nil {
		t.Fatal("expected an error for missing cert/key files")
	}
}

// TestCertWatcher_OnReload: a registered hook runs after a rotated
// certificate is loaded (and GetClientCertificate already returns the new
// one), not for the initial load and not for a rotation that fails to
// load.
func TestCertWatcher_OnReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath, "initial")

	w, err := NewCertWatcher(certPath, keyPath, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer w.Close()
	before, _ := w.GetClientCertificate(nil)

	fired := make(chan []byte, 4)
	w.OnReload(func() {
		c, _ := w.GetClientCertificate(nil)
		fired <- c.Certificate[0]
	})

	// A broken rotation: the watcher keeps the old certificate and runs
	// no hook.
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := time.Now().Add(time.Second)
	_ = os.Chtimes(certPath, broken, broken)
	select {
	case <-fired:
		t.Fatal("hook ran for a rotation that failed to load")
	case <-time.After(100 * time.Millisecond):
	}

	genCert(t, certPath, keyPath, "rotated")
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)
	select {
	case got := <-fired:
		if string(got) == string(before.Certificate[0]) {
			t.Fatal("hook ran before the rotated certificate was in place")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hook did not run after the rotation")
	}
}
