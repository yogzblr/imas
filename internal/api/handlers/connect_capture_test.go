package handlers

// J.2 regression, the sprout's counterpart of SEC.0's
// internal/api/client TestConnectNonceCannotMintLongLivedToken. FLAG FOR
// SECURITY REVIEW.
//
// A compromised bus chooses the nonce in its INFO and the sprout signs it
// with its NKey seed when it connects (nats.UserJWTAndSeed, through the
// real pki.LoadSproutBus options). Before J.2 that seed also signed the
// /v1/refresh proof, and the replay path of /v1/enroll took an NKey
// signature alone, so a nonce shaped like either payload handed the bus a
// fresh gateway JWT for the sprout, and with it the sprout's staged
// rendered recipe from /files/. Here a fake bus captures exactly that
// signature from the real sprout connect path and presents it to the real
// handlers.

import (
	"bufio"
	"bytes"
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
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// fakeBusTLS returns a server TLS config for 127.0.0.1 and its
// self-signed certificate as PEM.
func fakeBusTLS(t *testing.T) (*tls.Config, []byte) {
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
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type capturedConnect struct {
	jwt string
	sig []byte
	err error
}

// runFakeBus accepts one connection, plays the NATS server handshake far
// enough to send nonce and read the client's CONNECT, then refuses it.
func runFakeBus(ln net.Listener, tlsCfg *tls.Config, nonce string, out chan<- capturedConnect) {
	conn, err := ln.Accept()
	if err != nil {
		out <- capturedConnect{err: err}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	info, _ := json.Marshal(map[string]any{
		"server_id": "FAKEBUS", "version": "2.10.0", "proto": 1, "go": "go1.26",
		"host": "127.0.0.1", "max_payload": 1 << 20,
		"auth_required": true, "tls_required": true, "nonce": nonce,
	})
	if _, err := fmt.Fprintf(conn, "INFO %s\r\n", info); err != nil {
		out <- capturedConnect{err: err}
		return
	}
	tc := tls.Server(conn, tlsCfg)
	if err := tc.Handshake(); err != nil {
		out <- capturedConnect{err: fmt.Errorf("tls handshake: %w", err)}
		return
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		out <- capturedConnect{err: fmt.Errorf("reading CONNECT: %w", err)}
		return
	}
	body, ok := strings.CutPrefix(strings.TrimSpace(line), "CONNECT ")
	if !ok {
		out <- capturedConnect{err: fmt.Errorf("expected CONNECT, got %q", line)}
		return
	}
	var c struct {
		JWT string `json:"jwt"`
		Sig string `json:"sig"`
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		out <- capturedConnect{err: err}
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Sig)
	if err != nil {
		out <- capturedConnect{err: fmt.Errorf("decoding sig: %w", err)}
		return
	}
	fmt.Fprint(tc, "-ERR 'Authorization Violation'\r\n")
	out <- capturedConnect{jwt: c.JWT, sig: sig}
}

// captureSproutConnectSignature points the enrolled sprout's real bus
// connection (pki.LoadSproutBus) at a fake bus that sends nonce, and
// returns the signature the sprout's NKey seed made over it.
func captureSproutConnectSignature(t *testing.T, s *handlerSprout, nonce string) []byte {
	t.Helper()
	tlsCfg, caPEM := fakeBusTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// The sprout's HTTPS client to farmer is already built; the bus
	// connection reads the root CA file afresh, so pin the fake bus there.
	if err := os.WriteFile(config.SproutRootCA, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	config.BusURLs = []string{"tls://" + ln.Addr().String()}

	out := make(chan capturedConnect, 1)
	go runFakeBus(ln, tlsCfg, nonce, out)
	bus, err := pki.LoadSproutBus()
	if err != nil {
		t.Fatal(err)
	}
	if nc, err := bus.Connect(nats.NoReconnect(), nats.Timeout(5*time.Second)); err == nil {
		nc.Close()
		t.Fatal("the fake bus refused the connection, but Connect succeeded")
	}
	var got capturedConnect
	select {
	case got = <-out:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake bus captured nothing")
	}
	if got.err != nil {
		t.Fatalf("fake bus: %v", got.err)
	}
	// A genuine signature by the sprout's NKey over the bus's nonce, so
	// every refusal below is about what the signature is allowed to prove.
	kp, err := nkeys.FromPublicKey(s.nkeyPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Verify([]byte(nonce), got.sig); err != nil {
		t.Fatalf("the captured signature doesn't verify over the nonce: %v", err)
	}
	return got.sig
}

func postJSON(h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return w
}

// A nonce shaped as the old refresh proof gets the sprout's signature over
// it, which no longer authorises a refresh in any form.
func TestConnectNonceCannotAuthoriseARefresh(t *testing.T) {
	s := enrollAgainstHandlers(t)
	ts := time.Now().Unix()
	nonce := string(pki.RefreshSigningPayload(ts, s.nkeyPub))
	sig := captureSproutConnectSignature(t, s, nonce)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// The pre-J.2 contract, exactly as the bus would have used it.
	assertEnrollFailed(t, postJSON(Refresh, "/v1/refresh", map[string]any{"nkey_pub": s.nkeyPub, "timestamp": ts, "nkey_sig": sigB64}))
	// The signature dressed as the sealed request, as a string and as an
	// envelope's box.
	assertEnrollFailed(t, postJSON(Refresh, "/v1/refresh", map[string]any{"nkey_pub": s.nkeyPub, "sealed": sigB64}))
	var nonceBytes [24]byte
	envelope := payloadbox.Envelope{V: payloadbox.Version, Copies: []payloadbox.Sealed{{Nonce: nonceBytes[:], Box: sig}}}
	assertEnrollFailed(t, postJSON(Refresh, "/v1/refresh", map[string]any{"nkey_pub": s.nkeyPub, "sealed": envelope}))

	// The sprout itself still refreshes.
	if _, err := pki.RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("the sprout's own sealed refresh: %v", err)
	}
}

// A nonce shaped as an enrollment payload gets the sprout's signature over
// it, with a join token of the bus's choosing. The replay path doesn't
// check the token, so this used to earn a fresh gateway JWT. Now it earns
// only what the bus already has (the identity and the User JWT it saw at
// CONNECT), and a box key proof the bus forges itself is refused.
func TestConnectNonceCannotEarnAGatewayJWTByEnrolling(t *testing.T) {
	s := enrollAgainstHandlers(t)
	ts := time.Now().Unix()
	const hostname, token = "web-01", "attacker.token"
	nonce := string(pki.EnrollSigningPayload(ts, s.nkeyPub, hostname, s.sproutPub, token))
	sig := captureSproutConnectSignature(t, s, nonce)
	req := enrollRequest{
		JoinToken: token, NKeyPub: s.nkeyPub, Hostname: hostname, SproutPub: s.sproutPub,
		Timestamp: ts, NKeySig: base64.RawURLEncoding.EncodeToString(sig),
	}
	w := postJSON(Enroll, "/v1/enroll", req)
	if strings.Contains(w.Body.String(), "gateway_jwt") {
		t.Fatalf("a CONNECT signature earned a gateway JWT: %s", w.Body)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected the identity replay (200, no gateway JWT), got %d: %s", w.Code, w.Body)
	}

	// With a proof the bus seals itself, under a box key of its own. A
	// fresh nonce, since each signed request is accepted once.
	tenantPub, err := pki.DecodeBoxPubKey(s.resp.TenantX25519Pub)
	if err != nil {
		t.Fatal(err)
	}
	_, busPriv, _ := box.GenerateKey(rand.Reader)
	msg, err := payloadbox.NewMessage(payloadbox.PurposeEnrollProof, pki.CurrentTenantID(), "web-01", "",
		map[string]string{"nkey_pub": s.nkeyPub, "sprout_pub": s.sproutPub})
	if err != nil {
		t.Fatal(err)
	}
	forged, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: busPriv}})
	if err != nil {
		t.Fatal(err)
	}
	ts2 := ts + 1
	sig2 := captureSproutConnectSignature(t, s, string(pki.EnrollSigningPayload(ts2, s.nkeyPub, hostname, s.sproutPub, token)))
	req.Timestamp, req.NKeySig, req.SproutPubProof = ts2, base64.RawURLEncoding.EncodeToString(sig2), forged
	assertEnrollFailed(t, postJSON(Enroll, "/v1/enroll", req))

	t.Run("keyless sprout", func(t *testing.T) { connectNonceAgainstAKeylessSprout(t, s) })
}

// The keyless case (security review 2026-10-b, B2): a sprout between
// enrollment step 1 and step 2 has an identity and a User JWT, so it
// connects to the bus, but no box key yet. The bus has it sign an
// enrollment payload naming a box key the bus holds, and sends that with a
// proof sealed under its own key, without a binding and with the sprout's
// real binding (which a DMZ terminating the enrollment TLS reads off step
// 1's response). Before SEC.7b farmer recorded the bus's key and returned
// a gateway JWT. Now every attempt is refused and the real sprout's own
// step 2 still succeeds.
func connectNonceAgainstAKeylessSprout(t *testing.T, enrolled *handlerSprout) {
	const hostname, joinToken = "web-02", "ek_keyless.secret"
	t.Cleanup(pki.UseInMemoryJoinToken(joinToken, pki.CurrentTenantID(), 1))
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	nkeyPub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	if err := os.WriteFile(config.NKeySproutPrivFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	realPub, realPriv, _ := box.GenerateKey(rand.Reader)
	realPubB64 := base64.StdEncoding.EncodeToString(realPub[:])

	// Step 1 only: the identity, its User JWT (which the sprout connects
	// to the bus with) and the binding.
	w := postJSON(Enroll, "/v1/enroll", signedEnrollRequest(t, kp, joinToken, hostname, realPubB64))
	if w.Code != http.StatusOK {
		t.Fatalf("step 1: %d %s", w.Code, w.Body)
	}
	var first enrollSuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || len(first.EnrollBinding) == 0 {
		t.Fatalf("step 1 response %s (%v): want an enroll_binding", w.Body, err)
	}
	if err := os.WriteFile(config.SproutUserJWTFile, []byte(first.JWT), 0o600); err != nil {
		t.Fatal(err)
	}
	keyless := &handlerSprout{kp: kp, nkeyPub: nkeyPub, sproutPub: realPubB64, farmer: enrolled.farmer}
	tenantPub, err := pki.DecodeBoxPubKey(first.TenantX25519Pub)
	if err != nil {
		t.Fatal(err)
	}
	proofUnder := func(sproutPubB64 string, priv *[32]byte) json.RawMessage {
		msg, err := payloadbox.NewMessage(payloadbox.PurposeEnrollProof, first.TenantID, first.SproutID, "",
			map[string]string{"nkey_pub": nkeyPub, "sprout_pub": sproutPubB64})
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: priv}})
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}

	busPub, busPriv, _ := box.GenerateKey(rand.Reader)
	busPubB64 := base64.StdEncoding.EncodeToString(busPub[:])
	ts := time.Now().Unix()
	for i, attempt := range []struct {
		name      string
		sproutPub string
		proof     json.RawMessage
		binding   json.RawMessage
	}{
		{name: "NKey signature alone", sproutPub: realPubB64},
		{name: "the bus's box key, no binding (the review's request)", sproutPub: busPubB64, proof: proofUnder(busPubB64, busPriv)},
		{name: "the bus's box key, the sprout's binding", sproutPub: busPubB64, proof: proofUnder(busPubB64, busPriv), binding: first.EnrollBinding},
	} {
		reqTS := ts + int64(i)
		sig := captureSproutConnectSignature(t, keyless, string(pki.EnrollSigningPayload(reqTS, nkeyPub, hostname, attempt.sproutPub, "attacker.token")))
		w := postJSON(Enroll, "/v1/enroll", enrollRequest{
			JoinToken: "attacker.token", NKeyPub: nkeyPub, Hostname: hostname, SproutPub: attempt.sproutPub,
			Timestamp: reqTS, NKeySig: base64.RawURLEncoding.EncodeToString(sig),
			SproutPubProof: attempt.proof, EnrollBinding: attempt.binding,
		})
		if strings.Contains(w.Body.String(), "gateway_jwt") {
			t.Fatalf("%s: a CONNECT signature earned a keyless sprout's gateway JWT: %s", attempt.name, w.Body)
		}
		assertEnrollFailed(t, w)
	}

	// The real sprout's step 2: its own proof and binding. It succeeds,
	// which also shows none of the above recorded a box key.
	step2 := signedEnrollRequest(t, kp, joinToken, hostname, realPubB64)
	step2.Timestamp = ts + 10
	sig, err := kp.Sign(pki.EnrollSigningPayload(step2.Timestamp, nkeyPub, hostname, realPubB64, joinToken))
	if err != nil {
		t.Fatal(err)
	}
	step2.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	step2.SproutPubProof, step2.EnrollBinding = proofUnder(realPubB64, realPriv), first.EnrollBinding
	w = postJSON(Enroll, "/v1/enroll", step2)
	var second enrollSuccessResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &second) != nil || second.GatewayJWT == "" {
		t.Fatalf("the real sprout's step 2: %d %s", w.Code, w.Body)
	}
}
