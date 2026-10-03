package openbao

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCA signs client certificates for tests that need a cert chaining to
// a CA (a real cert auth role trusts a CA, not a leaf).
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// writeClientCert writes a client cert/key pair for cn, signed by ca, to
// certPath/keyPath, replacing whatever was there the way a customer's
// rotation would: new content, then a later mtime so a CertWatcher
// polling at a coarse filesystem timestamp granularity still sees it.
func writeClientCert(t *testing.T, ca *testCA, certPath, keyPath, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	later := time.Now().Add(time.Duration(serial.Int64()%1000+1) * time.Second)
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, later, later); err != nil {
			t.Fatalf("touching %s: %v", p, err)
		}
	}
}

// mtlsVault is a TLS stand-in for OpenBao/Vault that requires a client
// certificate on every connection and only answers to one common name at
// a time, the way a customer server that has revoked or stopped trusting
// the previous certificate would.
type mtlsVault struct {
	mu        sync.Mutex
	allowedCN string
	seenCNs   []string
	protos    []int
	logins    int
}

func (m *mtlsVault) allow(cn string) {
	m.mu.Lock()
	m.allowedCN = cn
	m.mu.Unlock()
}

func (m *mtlsVault) handler(w http.ResponseWriter, r *http.Request) {
	cn := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	m.mu.Lock()
	m.seenCNs = append(m.seenCNs, cn)
	m.protos = append(m.protos, r.ProtoMajor)
	allowed := cn == m.allowedCN
	if allowed && strings.HasPrefix(r.URL.Path, "/v1/auth/") {
		m.logins++
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"certificate not trusted"}})
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/cert/login":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "tok-" + cn, "lease_duration": 3600},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/app/db":
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"missing client token"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]any{"password": "s3cret"}, "metadata": map[string]any{}},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
	}
}

func (m *mtlsVault) lastCN() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.seenCNs) == 0 {
		return ""
	}
	return m.seenCNs[len(m.seenCNs)-1]
}

// TestCertRotationWhileRunning rotates the client certificate files under
// a running provider and checks that the next requests present the new
// certificate, with no new Provider and no restart, over HTTP/1.1 and
// HTTP/2 (a customer's OpenBao or Vault negotiates HTTP/2 by default, and
// a reused HTTP/2 connection would keep presenting the old certificate).
func TestCertRotationWhileRunning(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			vault := &mtlsVault{allowedCN: "sprout-cert-1"}
			srv := httptest.NewUnstartedServer(http.HandlerFunc(vault.handler))
			srv.EnableHTTP2 = h2
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			srv.StartTLS()
			t.Cleanup(srv.Close)

			dir := t.TempDir()
			certPath := filepath.Join(dir, "client.crt")
			keyPath := filepath.Join(dir, "client.key")
			caPath := filepath.Join(dir, "server-ca.pem")
			serverCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
			if err := os.WriteFile(caPath, serverCA, 0o600); err != nil {
				t.Fatal(err)
			}
			clientCA := newTestCA(t, "customer client CA")
			writeClientCert(t, clientCA, certPath, keyPath, "sprout-cert-1")

			p, err := newWithCertWatch(srv.URL, certPath, keyPath, caPath, "", "", 20*time.Millisecond)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(p.Close)

			const ref = "sdb://openbao/secret/app/db#password"
			if got, err := p.Get(t.Context(), ref); err != nil || got != "s3cret" {
				t.Fatalf("Get before rotation = %q, %v", got, err)
			}
			if cn := vault.lastCN(); cn != "sprout-cert-1" {
				t.Fatalf("server saw %q before rotation", cn)
			}

			// The customer rotates the certificate and their server stops
			// accepting the old one.
			writeClientCert(t, clientCA, certPath, keyPath, "sprout-cert-2")
			vault.allow("sprout-cert-2")
			// The cached token stays valid (OpenBao doesn't bind a token
			// to the certificate that logged in); drop it so the rotated
			// certificate has to log in too.
			p.tokens.Invalidate()

			deadline := time.Now().Add(5 * time.Second)
			for {
				got, err := p.Get(t.Context(), ref)
				if err == nil {
					if got != "s3cret" {
						t.Fatalf("Get after rotation = %q", got)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("Get still failing 5s after rotation: %v", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if cn := vault.lastCN(); cn != "sprout-cert-2" {
				t.Fatalf("server saw %q after rotation, want the rotated certificate", cn)
			}
			vault.mu.Lock()
			logins, protos := vault.logins, vault.protos
			vault.mu.Unlock()
			wantProto := 1
			if h2 {
				wantProto = 2
			}
			for _, proto := range protos {
				if proto != wantProto {
					t.Fatalf("a request used HTTP/%d, want HTTP/%d", proto, wantProto)
				}
			}
			if logins != 2 {
				t.Errorf("logins = %d, want 2 (one per certificate)", logins)
			}
			// And every later request keeps presenting the new one.
			if _, err := p.Get(t.Context(), ref); err != nil {
				t.Fatalf("second Get after rotation: %v", err)
			}
			if cn := vault.lastCN(); cn != "sprout-cert-2" {
				t.Fatalf("server saw %q on a later request", cn)
			}
		})
	}
}
