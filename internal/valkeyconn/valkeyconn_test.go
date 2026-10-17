package valkeyconn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	valkey "github.com/valkey-io/valkey-go"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testCA is a CA and a server certificate it signed for the given DNS
// names and 127.0.0.1.
type testCA struct {
	pem    string
	server tls.Certificate
}

func newTestCA(t *testing.T, dnsNames ...string) testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "valkeyconn test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "valkey"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		pem:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		server: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
	}
}

func TestLoad(t *testing.T) {
	ca := newTestCA(t, "valkey.test")
	caFile := writeFile(t, "ca.crt", ca.pem)
	pwFile := writeFile(t, "password", "s3cret\n")

	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantPW  string
		wantTLS bool
		wantSNI string
		wantErr string
	}{
		{name: "nothing set"},
		{name: "password, newline trimmed", env: map[string]string{"IMAS_VALKEY_PASSWORD_FILE": pwFile}, wantPW: "s3cret"},
		{name: "CRLF trimmed", env: map[string]string{"SAASAPI_VALKEY_PASSWORD_FILE": writeFile(t, "pw", "abc\r\n")}, wantPW: "abc"},
		{name: "inner spaces kept", env: map[string]string{"IMAS_VALKEY_PASSWORD_FILE": writeFile(t, "pw", " a b\n")}, wantPW: " a b"},
		{name: "missing password file", env: map[string]string{"IMAS_VALKEY_PASSWORD_FILE": filepath.Join(t.TempDir(), "nope")}, wantErr: "IMAS_VALKEY_PASSWORD_FILE"},
		{name: "empty password file", env: map[string]string{"IMAS_VALKEY_PASSWORD_FILE": writeFile(t, "pw", "")}, wantErr: "empty"},
		{name: "newline-only password file", env: map[string]string{"IMAS_VALKEY_PASSWORD_FILE": writeFile(t, "pw", "\n")}, wantErr: "empty"},
		{name: "TLS false", env: map[string]string{"IMAS_VALKEY_TLS": "false"}},
		{name: "TLS bad bool", env: map[string]string{"IMAS_VALKEY_TLS": "yes please"}, wantErr: "IMAS_VALKEY_TLS"},
		{name: "TLS without CA", env: map[string]string{"IMAS_VALKEY_TLS": "true"}, wantErr: "IMAS_VALKEY_TLS_CA_FILE"},
		{name: "TLS unreadable CA", env: map[string]string{"IMAS_VALKEY_TLS": "true", "IMAS_VALKEY_TLS_CA_FILE": filepath.Join(t.TempDir(), "nope")}, wantErr: "IMAS_VALKEY_TLS_CA_FILE"},
		{name: "TLS bad PEM", env: map[string]string{"IMAS_VALKEY_TLS": "true", "IMAS_VALKEY_TLS_CA_FILE": writeFile(t, "ca", "not a pem")}, wantErr: "no PEM certificate"},
		{name: "CA without TLS", env: map[string]string{"IMAS_VALKEY_TLS_CA_FILE": caFile}, wantErr: "IMAS_VALKEY_TLS is not true"},
		{name: "server name without TLS", env: map[string]string{"SAASAPI_VALKEY_TLS_SERVER_NAME": "x"}, wantErr: "SAASAPI_VALKEY_TLS is not true"},
		{name: "TLS", env: map[string]string{"IMAS_VALKEY_TLS": "true", "IMAS_VALKEY_TLS_CA_FILE": caFile}, wantTLS: true},
		{name: "TLS server name", env: map[string]string{"SAASAPI_VALKEY_TLS": "true", "SAASAPI_VALKEY_TLS_CA_FILE": caFile, "SAASAPI_VALKEY_TLS_SERVER_NAME": "valkey.test"}, wantTLS: true, wantSNI: "valkey.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "IMAS"
			for k := range tc.env {
				prefix, _, _ = strings.Cut(k, "_")
			}
			o, err := Load(prefix, envOf(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.Password != tc.wantPW {
				t.Errorf("password %q, want %q", o.Password, tc.wantPW)
			}
			if (o.TLS != nil) != tc.wantTLS {
				t.Fatalf("TLS %v, want %v", o.TLS != nil, tc.wantTLS)
			}
			if o.TLS != nil {
				if o.TLS.MinVersion != tls.VersionTLS12 || o.TLS.InsecureSkipVerify || o.TLS.RootCAs == nil || o.TLS.ServerName != tc.wantSNI {
					t.Errorf("TLS config: min %x, insecure %v, roots %v, server name %q", o.TLS.MinVersion, o.TLS.InsecureSkipVerify, o.TLS.RootCAs != nil, o.TLS.ServerName)
				}
			}
		})
	}
}

// The password never shows in an error, String, %v or %#v.
func TestPasswordNeverPrinted(t *testing.T) {
	o := Options{Password: "hunter2-secret"}
	for _, s := range []string{o.String(), fmt.Sprintf("%v", o), fmt.Sprintf("%+v", o), fmt.Sprintf("%#v", o), fmt.Sprintf("%s", o)} {
		if strings.Contains(s, "hunter2") {
			t.Errorf("printed the password: %s", s)
		}
	}
	// A bad TLS setting next to a good password file: the error is
	// about TLS, without the password.
	_, err := Load("IMAS", envOf(map[string]string{
		"IMAS_VALKEY_PASSWORD_FILE": writeFile(t, "pw", "hunter2-secret"),
		"IMAS_VALKEY_TLS":           "true",
	}))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v", err)
	}
}

func connect(t *testing.T, o Options, addr string) (valkey.Client, error) {
	t.Helper()
	opt := o.ClientOption([]string{addr})
	opt.DisableCache = true
	opt.Dialer.Timeout = 2 * time.Second
	c, err := valkey.NewClient(opt)
	if err == nil {
		t.Cleanup(c.Close)
		err = c.Do(context.Background(), c.B().Ping().Build()).Error()
	}
	return c, err
}

func TestClientPassword(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireUserAuth(Username, "right")

	if _, err := connect(t, Options{Password: "right"}, mr.Addr()); err != nil {
		t.Fatalf("right password: %v", err)
	}
	if _, err := connect(t, Options{Password: "wrong"}, mr.Addr()); err == nil {
		t.Fatal("wrong password connected")
	}
	if _, err := connect(t, Options{}, mr.Addr()); err == nil {
		t.Fatal("no password connected to a server that needs one")
	}
}

func TestClientTLS(t *testing.T) {
	ca := newTestCA(t, "valkey.test")
	mr, err := miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{ca.server}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	mr.RequireUserAuth(Username, "pw")
	pwFile := writeFile(t, "pw", "pw\n")

	load := func(caPEM, serverName string) Options {
		t.Helper()
		env := map[string]string{
			"IMAS_VALKEY_PASSWORD_FILE": pwFile,
			"IMAS_VALKEY_TLS":           "true",
			"IMAS_VALKEY_TLS_CA_FILE":   writeFile(t, "ca.crt", caPEM),
		}
		if serverName != "" {
			env["IMAS_VALKEY_TLS_SERVER_NAME"] = serverName
		}
		o, err := Load("IMAS", envOf(env))
		if err != nil {
			t.Fatal(err)
		}
		return o
	}

	// The matching name passes; so does the dialled IP, which the
	// certificate carries.
	if _, err := connect(t, load(ca.pem, "valkey.test"), mr.Addr()); err != nil {
		t.Fatalf("matching server name: %v", err)
	}
	if _, err := connect(t, load(ca.pem, ""), mr.Addr()); err != nil {
		t.Fatalf("dialled address in the certificate: %v", err)
	}
	// A name the certificate doesn't carry is refused.
	if _, err := connect(t, load(ca.pem, "other.test"), mr.Addr()); err == nil {
		t.Fatal("a server name the certificate doesn't carry connected")
	}
	// A server certificate from another CA is refused.
	other := newTestCA(t, "valkey.test")
	if _, err := connect(t, load(other.pem, "valkey.test"), mr.Addr()); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("a certificate from another CA: err = %v, want unknown authority", err)
	}
	// Plaintext to a TLS server fails too.
	if _, err := connect(t, Options{Password: "pw"}, mr.Addr()); err == nil {
		t.Fatal("plaintext connected to the TLS server")
	}
}

func TestCheckEviction(t *testing.T) {
	info := func(maxmemory, policy string) string {
		return "# Memory\r\nused_memory:1000\r\nmaxmemory:" + maxmemory + "\r\nmaxmemory_human:x\r\nmaxmemory_policy:" + policy + "\r\n"
	}
	for _, tc := range []struct {
		name string
		info string
		err  error
		want string // "" means no warning
	}{
		{name: "allkeys-lru with a limit", info: info("1048576", "allkeys-lru"), want: "replay cache and the heartbeat keys are security state"},
		{name: "volatile-ttl with a limit", info: info("10", "volatile-ttl"), want: "maxmemory-policy volatile-ttl"},
		{name: "noeviction", info: info("1048576", "noeviction")},
		{name: "no limit", info: info("0", "allkeys-lru")},
		{name: "INFO fails", err: errors.New("NOPERM"), want: "could not read INFO memory"},
		{name: "INFO without the fields", info: "# Memory\r\nused_memory:1\r\n", want: "could not check the eviction policy"},
		{name: "INFO with a bad maxmemory", info: info("lots", "noeviction"), want: "not a number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			checkEviction(func() (string, error) { return tc.info, tc.err },
				func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("warned: %v", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Errorf("warnings %q, want one containing %q", got, tc.want)
			}
		})
	}
}

// CheckEviction against a server: miniredis has no INFO memory, so this
// is the "only logs when INFO fails" path through a real client.
func TestCheckEvictionClient(t *testing.T) {
	mr := miniredis.RunT(t)
	c, err := connect(t, Options{}, mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	CheckEviction(context.Background(), c, func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
	if len(got) != 1 || !strings.Contains(got[0], "eviction policy") {
		t.Errorf("warnings %q", got)
	}
}

// Against a real Valkey (CI's service container, SAASAPI_TEST_VALKEY_ADDR):
// its INFO memory parses, and its default (maxmemory 0) gives no warning.
// Read-only: the server is shared with other packages' tests.
func TestCheckEvictionRealServer(t *testing.T) {
	addr := os.Getenv("SAASAPI_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("SAASAPI_TEST_VALKEY_ADDR not set")
	}
	c, err := connect(t, Options{}, addr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Do(context.Background(), c.B().Info().Section("memory").Build()).ToString()
	if err != nil {
		t.Fatal(err)
	}
	maxmemory, policy, err := parseMemoryInfo(s)
	if err != nil || policy == "" {
		t.Fatalf("parse: %d %q %v\n%s", maxmemory, policy, err, s)
	}
	var got []string
	CheckEviction(context.Background(), c, func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
	if maxmemory == 0 && len(got) != 0 {
		t.Errorf("warned with maxmemory 0: %v", got)
	}
}
