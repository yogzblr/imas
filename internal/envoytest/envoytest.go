// Package envoytest runs a real Envoy binary on the shipped
// deploy/envoy/envoy.yaml, for tests that need a sprout's traffic to go
// through the actual DMZ gateway config rather than straight to farmer.
// It's a separate, exported package (like objectstoretest) because both
// internal/pki's enrollment/bus tests and internal/api's /files/ tests
// use it.
//
// The config is not a copy: Start renders envoy.yaml with only its
// deployment placeholders (listener port, DMZ cert paths, the
// farmer.internal upstreams, the admin port) substituted, and fails the
// test if any placeholder doesn't occur exactly as often as expected, so
// a change to the shipped file is tested as-is or breaks loudly here.
//
// Start skips the calling test unless IMAS_TEST_ENVOY_BIN names an Envoy
// binary with EdDSA support in jwt_authn (see
// deploy/envoy/testing/README.md).
package envoytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// EnvBin names the Envoy binary. EnvLogLevel optionally sets Envoy's log
// level (default "warning"); "debug" shows jwt_authn's decisions.
const (
	EnvBin      = "IMAS_TEST_ENVOY_BIN"
	EnvLogLevel = "IMAS_TEST_ENVOY_LOG_LEVEL"
)

// Upstreams are the host:port addresses Envoy's clusters point at. Both
// must speak TLS: envoy.yaml's clusters use an UpstreamTlsContext (with
// no validation context, so any certificate is accepted).
type Upstreams struct {
	// FarmerAPI stands in for farmer.internal:5405, which envoy.yaml uses
	// for three clusters: farmer_api (/v1/enroll, /v1/refresh, and the
	// jwt_authn JWKS fetch at /v1/.well-known/jwks.json) and
	// recipe_service (/files/).
	FarmerAPI string
	// NATSWebsocket stands in for farmer.internal:5407, nats-server's
	// websocket listener behind the default route.
	NATSWebsocket string
}

// Envoy is a running Envoy. Its listener serves a self-signed certificate
// for "localhost" and 127.0.0.1; TLSConfig trusts exactly that.
type Envoy struct {
	// URL is the https:// base URL of the DMZ listener.
	URL string
	// BusURL is the same listener as a wss:// NATS URL.
	BusURL  string
	RootCAs *x509.CertPool
	// CertPEM is the listener's certificate, for callers that pin a root
	// CA file (as a sprout pins config.SproutRootCA).
	CertPEM []byte
}

// TLSConfig returns a client TLS config that trusts only this Envoy.
func (e *Envoy) TLSConfig() *tls.Config {
	return &tls.Config{ServerName: "localhost", RootCAs: e.RootCAs, MinVersion: tls.VersionTLS12}
}

// HTTPClient returns a client that trusts only this Envoy.
func (e *Envoy) HTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: e.TLSConfig()}}
}

// Start renders envoy.yaml for u, starts Envoy, and waits until it is
// ready. Envoy is killed when t ends; its output is logged if t failed.
func Start(t testing.TB, u Upstreams) *Envoy {
	t.Helper()
	bin := os.Getenv(EnvBin)
	if bin == "" {
		t.Skipf("%s not set; skipping real-Envoy test", EnvBin)
	}
	dir := t.TempDir()
	certPath, keyPath, certPEM, leaf := writeCert(t, dir)
	port, adminPort := FreePort(t), FreePort(t)
	farmerHost, farmerPort := splitHostPort(t, u.FarmerAPI)
	wsHost, wsPort := splitHostPort(t, u.NATSWebsocket)

	cfg := Render(t, []Sub{
		{"address: 0.0.0.0, port_value: 8443", "address: 127.0.0.1, port_value: " + strconv.Itoa(port), 1},
		{"/etc/envoy/tls/dmz-cert.pem", certPath, 1},
		{"/etc/envoy/tls/dmz-key.pem", keyPath, 1},
		{"https://farmer.internal:5405/", "https://" + u.FarmerAPI + "/", 1},
		{"address: farmer.internal, port_value: 5405", "address: " + farmerHost + ", port_value: " + farmerPort, 2},
		{"address: farmer.internal, port_value: 5407", "address: " + wsHost + ", port_value: " + wsPort, 1},
		{"address: 127.0.0.1, port_value: 9901", "address: 127.0.0.1, port_value: " + strconv.Itoa(adminPort), 1},
	})
	cfgPath := filepath.Join(dir, "envoy.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, bin, cfgPath, adminPort)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &Envoy{
		URL:     fmt.Sprintf("https://localhost:%d", port),
		BusURL:  fmt.Sprintf("wss://localhost:%d", port),
		RootCAs: pool,
		CertPEM: certPEM,
	}
}

// Sub is one placeholder substitution: Old must occur exactly Count times.
type Sub struct {
	Old, New string
	Count    int
}

// Render returns deploy/envoy/envoy.yaml with subs applied, failing t if
// a substitution's count is off or a known placeholder remains.
func Render(t testing.TB, subs []Sub) string {
	t.Helper()
	_, self, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "deploy", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(raw)
	for _, s := range subs {
		if n := strings.Count(cfg, s.Old); n != s.Count {
			t.Fatalf("envoy.yaml: %q occurs %d times, envoytest expects %d; update envoytest alongside the config", s.Old, n, s.Count)
		}
		cfg = strings.ReplaceAll(cfg, s.Old, s.New)
	}
	if strings.Contains(cfg, "farmer.internal") || strings.Contains(cfg, "/etc/envoy/") {
		t.Fatal("envoy.yaml has a deployment placeholder envoytest doesn't substitute")
	}
	return cfg
}

func run(t testing.TB, bin, cfgPath string, adminPort int) {
	t.Helper()
	level := os.Getenv(EnvLogLevel)
	if level == "" {
		level = "warning"
	}
	var mu sync.Mutex
	var logs strings.Builder
	out := writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	})
	cmd := exec.Command(bin, "-c", cfgPath, "--disable-hot-restart", "--concurrency", "1", "-l", level)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting envoy: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	dump := func() string {
		mu.Lock()
		defer mu.Unlock()
		return logs.String()
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		if t.Failed() {
			t.Logf("envoy output:\n%s", dump())
		}
	})

	ready := fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		select {
		case err := <-exited:
			t.Fatalf("envoy exited before becoming ready (%v):\n%s", err, dump())
		default:
		}
		if resp, err := http.Get(ready); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
	t.Fatal("envoy did not become ready in 30s")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// FreePort returns a currently unused 127.0.0.1 TCP port.
func FreePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func splitHostPort(t testing.TB, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("envoytest: upstream %q: %v", addr, err)
	}
	return host, port
}

// writeCert writes a self-signed P-256 certificate for localhost and
// 127.0.0.1 to dir, for Envoy's downstream listener.
func writeCert(t testing.TB, dir string) (certPath, keyPath string, certPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "envoytest"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "dmz-cert.pem")
	keyPath = filepath.Join(dir, "dmz-key.pem")
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, certPEM, leaf
}
