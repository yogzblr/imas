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
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/api/client/clienttest"
	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
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
	setupCLIKey(t)
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
	// The capture is a genuine signature over the nonce: the bus does get
	// that much.
	kp, err := nkeys.FromPublicKey(got.nkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Verify([]byte(nonce), got.sig); err != nil {
		t.Fatalf("captured signature doesn't verify over the nonce: %v", err)
	}
	return got.nkey, got.sig
}

// TestConnectNonceSignatureIsAllTheBusGets is the J.3 half of the
// forged-token regression on the CLI side. A compromised bus chooses the
// nonce the CLI's NKey signs at CONNECT: here the expiry string that, as
// a bearer token, used to be valid until 2099 (SEC.0). The CLI still
// signs it (the bus's own handshake needs that), but nothing farmer
// accepts rests on that signature any more: the CLI builds no token, and
// every request it sends is a sealed c2f.api message under its box key,
// which the NKey never touches. internal/natsapi's
// TestForgedTokenRegression shows farmer refusing every use of such a
// signature.
func TestConnectNonceSignatureIsAllTheBusGets(t *testing.T) {
	const nonce = "2099-01-01T00:00:00Z"
	pubkey, sig := captureConnectSignature(t, nonce)
	if pubkey == "" || len(sig) == 0 {
		t.Fatal("no capture")
	}
	// The JSON a bus would hand farmer as the old token: there is no
	// longer any code in this repository that reads it.
	forged, _ := json.Marshal(map[string]string{"expires": nonce, "pubkey": pubkey, "sig": base64.StdEncoding.EncodeToString(sig)})
	if len(forged) == 0 {
		t.Fatal("marshal")
	}
}

// A request this CLI sends carries no NKey signature and nothing readable:
// the bus sees the subject, the principal header and ciphertext.
func TestSealedRequestCarriesNoSignature(t *testing.T) {
	defer startTestNATS(t)()
	wires := make(chan *nats.Msg, 1)
	tap, err := NatsConn.Subscribe("imas.api.auth.users.add", func(m *nats.Msg) { wires <- m })
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Unsubscribe()
	testFarmer.Handle(t, NatsConn, "auth.users.add", clienttest.Result(map[string]any{"success": true}))

	if _, err := AddUser("UNEWUSER", "admin", "", "AAAA"); err != nil {
		t.Fatal(err)
	}
	var wire *nats.Msg
	select {
	case wire = <-wires:
	case <-time.After(5 * time.Second):
		t.Fatal("tap saw nothing")
	}
	if wire.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 || wire.Header.Get(payloadbox.PrincipalHeader) != testFarmer.UserID {
		t.Fatalf("headers %v", wire.Header)
	}
	for _, s := range []string{"token", "UNEWUSER", "admin", "expires", testFarmer.UserID} {
		if strings.Contains(string(wire.Data), s) {
			t.Errorf("%q readable on the wire", s)
		}
	}
}

// setupCLIKey gives this CLI an NKey (jety's privkey).
func setupCLIKey(t *testing.T) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("# test config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jety.SetConfigType("toml")
	jety.SetConfigFile(configPath)
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	jety.Set("privkey", string(seed))
	t.Cleanup(func() { jety.Set("privkey", "") })
}
