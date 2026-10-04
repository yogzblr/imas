package client

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
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

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
)

// fakeBusTLS returns a server TLS config for 127.0.0.1 and writes its
// self-signed certificate to a file the CLI can load as its root CA.
func fakeBusTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-bus"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "rootca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, caPath
}

// captured is what the fake bus records from the CLI's CONNECT.
type captured struct {
	nkey string
	sig  []byte
	err  error
}

// runFakeBus accepts one connection, plays the NATS server handshake far
// enough to send nonce and read the CLI's CONNECT, then refuses it. It is
// a compromised bus: it chooses the nonce.
func runFakeBus(ln net.Listener, tlsCfg *tls.Config, nonce string, out chan<- captured) {
	conn, err := ln.Accept()
	if err != nil {
		out <- captured{err: err}
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	info, _ := json.Marshal(map[string]any{
		"server_id":     "FAKEBUS",
		"version":       "2.10.0",
		"proto":         1,
		"go":            "go1.26",
		"host":          "127.0.0.1",
		"max_payload":   1 << 20,
		"auth_required": true,
		"tls_required":  true,
		"nonce":         nonce,
	})
	if _, err := fmt.Fprintf(conn, "INFO %s\r\n", info); err != nil {
		out <- captured{err: err}
		return
	}
	tc := tls.Server(conn, tlsCfg)
	if err := tc.Handshake(); err != nil {
		out <- captured{err: fmt.Errorf("tls handshake: %w", err)}
		return
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		out <- captured{err: fmt.Errorf("reading CONNECT: %w", err)}
		return
	}
	body, ok := strings.CutPrefix(strings.TrimSpace(line), "CONNECT ")
	if !ok {
		out <- captured{err: fmt.Errorf("expected CONNECT, got %q", line)}
		return
	}
	var c struct {
		Nkey string `json:"nkey"`
		Sig  string `json:"sig"`
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		out <- captured{err: err}
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Sig)
	if err != nil {
		out <- captured{err: fmt.Errorf("decoding sig: %w", err)}
		return
	}
	fmt.Fprint(tc, "-ERR 'Authorization Violation'\r\n")
	out <- captured{nkey: c.Nkey, sig: sig}
}

// captureConnectSignature points the real CLI connect path
// (NewNatsClient) at a fake bus that sends nonce, and returns the
// signature the CLI made over it with its key.
func captureConnectSignature(t *testing.T, nonce string) (pubkey string, sig []byte) {
	t.Helper()
	setupTokenInjectionTest(t)
	tlsCfg, caPath := fakeBusTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	origURL, origCA, origName := config.FarmerBusURL, config.ImasRootCA, config.FarmerBusTLSServerName
	t.Cleanup(func() {
		config.FarmerBusURL, config.ImasRootCA, config.FarmerBusTLSServerName = origURL, origCA, origName
	})
	config.FarmerBusURL = "tls://" + ln.Addr().String()
	config.ImasRootCA = caPath
	config.FarmerBusTLSServerName = ""

	out := make(chan captured, 1)
	go runFakeBus(ln, tlsCfg, nonce, out)

	nc, err := NewNatsClient()
	if err == nil {
		nc.Close()
		t.Fatal("fake bus refused the connection, but NewNatsClient succeeded")
	}
	var got captured
	select {
	case got = <-out:
	case <-time.After(10 * time.Second):
		t.Fatal("fake bus captured nothing")
	}
	if got.err != nil {
		t.Fatalf("fake bus: %v", got.err)
	}

	want, err := auth.GetPubkey()
	if err != nil {
		t.Fatal(err)
	}
	if got.nkey != want {
		t.Fatalf("CONNECT nkey = %q, want the CLI's key %q", got.nkey, want)
	}
	// The capture is a genuine signature over the nonce, so any refusal
	// below comes from the expiry check, not from a bad signature.
	kp, err := nkeys.FromPublicKey(got.nkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Verify([]byte(nonce), got.sig); err != nil {
		t.Fatalf("captured signature doesn't verify over the nonce: %v", err)
	}
	return got.nkey, got.sig
}

// tokenFrom assembles the bearer token a compromised bus would build
// from a signature captured at connect.
func tokenFrom(t *testing.T, expires, pubkey string, sig []byte) (auth.UserAuth, string) {
	t.Helper()
	ua := auth.UserAuth{Expires: expires, Pubkey: pubkey, Sig: base64.StdEncoding.EncodeToString(sig)}
	b, err := json.Marshal(ua)
	if err != nil {
		t.Fatal(err)
	}
	return ua, base64.StdEncoding.EncodeToString(b)
}

// TestConnectNonceCannotMintLongLivedToken is the SEC.0 regression: a
// compromised bus sends an expiry timestamp as its nonce, captures the
// signature the CLI makes over it at connect, and presents that as a
// CLI token. Before the cap, IsValid accepted it until 2099.
func TestConnectNonceCannotMintLongLivedToken(t *testing.T) {
	const nonce = "2099-01-01T00:00:00Z"
	pubkey, sig := captureConnectSignature(t, nonce)
	ua, token := tokenFrom(t, nonce, pubkey, sig)

	if _, err := ua.IsValid(); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("IsValid on a token minted from a 2099 nonce = %v, want ErrInvalidToken", err)
	}
	if _, _, _, err := auth.WhoAmI(token); err == nil {
		t.Fatal("WhoAmI accepted a token minted from a 2099 nonce")
	}
}

// TestConnectNonceWithinCap documents what the stopgap still allows: a
// nonce inside MaxTokenExpiry() yields a token that IsValid accepts, so a
// compromised bus can still mint a short-lived token (closed only by
// Decision A in imas-payload-encryption-design.md).
func TestConnectNonceWithinCap(t *testing.T) {
	nonce := time.Now().Add(auth.TokenLifetime).UTC().Format(time.RFC3339)
	pubkey, sig := captureConnectSignature(t, nonce)
	ua, _ := tokenFrom(t, nonce, pubkey, sig)

	if got, err := ua.IsValid(); err != nil || got != pubkey {
		t.Fatalf("IsValid = %q, %v; want the CLI's key accepted", got, err)
	}
}
