package handlers

// Runs the sprout's enrollment client (internal/pki/enrollclient.go)
// against this package's real Enroll handler over TLS, through the
// SproutRootCA-pinned client pki.LoadRootCA builds, so the client's copy
// of the wire types can't drift from the handler's. Only the replay path
// is reachable here: first-time enrollment needs saas.enrollment_keys,
// which the SQLite test DB can't serve (see internal/pki/enroll.go's
// enrollmentKeyStore); internal/pki/enrollclient_test.go covers it
// against pki.Enroll directly.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/pki"
)

// signingGatewayMinter mints real alg:EdDSA gateway JWTs, which the
// client parses (sub, iat, exp) before accepting a response.
type signingGatewayMinter struct{ key ed25519.PrivateKey }

func (m signingGatewayMinter) MintGatewayJWT(_ context.Context, c gatewayjwt.GatewayClaims) (string, error) {
	tok, err := jwt.NewBuilder().Subject(c.Subject).Issuer(gatewayjwt.GatewayIssuer).
		IssuedAt(time.Now()).Expiration(c.Expiry).Build()
	if err != nil {
		return "", err
	}
	b, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, m.key))
	return string(b), err
}

func TestEnrollClient_AgainstHandler(t *testing.T) {
	setupPKIDirs(t)
	withFakeTenantBoxOpenBao(t)
	withFakeFleetKeySource(t)
	_, gwKey, _ := ed25519.GenerateKey(rand.Reader)
	pki.SetGatewaySigner(signingGatewayMinter{key: gwKey})
	t.Cleanup(func() { pki.SetGatewaySigner(nil) })
	origTTL := config.GatewayJWTTTL
	config.GatewayJWTTTL = time.Hour
	t.Cleanup(func() { config.GatewayJWTTTL = origTTL })

	kp := acceptedTestNKey(t)
	nkeyPub, _ := kp.PublicKey()
	seed, _ := kp.Seed()

	dir := t.TempDir()
	paths := map[*string]string{
		&config.NKeySproutPrivFile:        "sprout.nkey",
		&config.SproutRootCA:              "tls-rootca.pem",
		&config.SproutUserJWTFile:         "sprout.jwt",
		&config.SproutGatewayJWTFile:      "gateway.jwt",
		&config.SproutTenantX25519PubFile: "tenant-x25519.pub",
		&config.SproutBoxPrivFile:         "sprout-x25519.key",
		&config.SproutBoxPubFile:          "sprout-x25519.pub",
		&config.SproutFleetSigningJWKS:    "fleet-signing-jwks.json",
	}
	for p, name := range paths {
		old := *p
		*p = filepath.Join(dir, name)
		t.Cleanup(func() { *p = old })
	}
	if err := os.WriteFile(config.NKeySproutPrivFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", Enroll)
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	oldURL := config.FarmerURL
	config.FarmerURL = ts.URL
	t.Cleanup(func() { config.FarmerURL = oldURL })
	// Pin the test server's certificate as the sprout's root CA, the file
	// FetchRootCA would otherwise have fetched.
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(config.SproutRootCA, rootPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pki.LoadRootCA("sprout"); err != nil {
		t.Fatalf("LoadRootCA: %v", err)
	}

	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pki.EnrollSprout(t.Context(), "irrelevant.token", "web-01", sproutPub)
	if err != nil {
		t.Fatalf("EnrollSprout against the real handler: %v", err)
	}
	if resp.SproutID != "web-01" || resp.NKeyIdentity != nkeyPub || len(resp.NatsURLs) == 0 {
		t.Errorf("unexpected response: %+v", resp)
	}
	if err := pki.PersistEnrollment(resp); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}
	if !pki.SproutEnrolled() {
		t.Fatal("expected the sprout to be enrolled")
	}
	if _, err := pki.LoadPinnedFleetSigningKeys(); err != nil {
		t.Errorf("fleet signing keys not pinned: %v", err)
	}

	id, err := pki.RefreshGatewayJWT(t.Context(), "web-01", sproutPub)
	if err != nil {
		t.Fatalf("RefreshGatewayJWT against the real handler: %v", err)
	}
	if id != "web-01" {
		t.Errorf("refresh replayed sprout_id %q, want web-01", id)
	}
}
