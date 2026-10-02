package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/saasapi"
)

const testChecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func testRelease() release {
	return release{
		Manifest: fleetsign.Manifest{
			Version:          "v2.4.1",
			OS:               "linux",
			Arch:             "amd64",
			FileName:         "imas-sprout_2.4.1_amd64.deb",
			ChecksumSHA256:   testChecksum,
			MinSproutVersion: "v2.0.0",
		},
		ArtifactURL: "https://artifacts.example.com/sprout-v2.4.1-linux-amd64",
	}
}

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	if err := db.AutoMigrate(&saasapi.FleetVersion{}); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	return db
}

// mockTransit implements Transit's sign/<key> and keys/<key> for one
// Ed25519 key, in the same request/response shapes as the real API (see
// internal/gatewayjwt's mockTransitServer). Only signToken may sign;
// readTokens may read keys. Any other token, or path, is a 403/404.
type mockTransit struct {
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	version    int
	signToken  string
	readTokens map[string]bool
	// tamper, when set, makes sign return a signature over different
	// bytes than it was given.
	tamper bool
	signs  int
	// older are earlier key versions Transit still holds but no longer
	// signs with (below version). minEncryption/minDecryption are the
	// key's floors as Transit reports them.
	older         map[int]ed25519.PublicKey
	minEncryption int
	minDecryption int
}

func newMockTransit(t *testing.T) *mockTransit {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &mockTransit{priv: priv, pub: pub, version: 1, signToken: "signer",
		readTokens: map[string]bool{"signer": true, "farmer-ro": true, "saasapi-ro": true}}
}

func (m *mockTransit) serve(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		deny := func() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"1 error occurred:\n\t* permission denied\n\n"}})
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/"+fleetsign.DefaultTransitKeyName:
			if tok != m.signToken {
				deny()
				return
			}
			var req struct{ Input string }
			json.NewDecoder(r.Body).Decode(&req)
			input, _ := base64.StdEncoding.DecodeString(req.Input)
			if m.tamper {
				input = append(input, 'x')
			}
			m.signs++
			sig := ed25519.Sign(m.priv, input)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"signature":   "vault:v" + strconv.Itoa(m.version) + ":" + base64.StdEncoding.EncodeToString(sig),
				"key_version": m.version,
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/"+fleetsign.DefaultTransitKeyName:
			if !m.readTokens[tok] {
				deny()
				return
			}
			keys := map[string]any{}
			add := func(v int, pub ed25519.PublicKey) {
				der, _ := x509.MarshalPKIXPublicKey(pub)
				keys[strconv.Itoa(v)] = map[string]any{
					"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
				}
			}
			add(m.version, m.pub)
			for v, pub := range m.older {
				add(v, pub)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type":                   "ed25519",
				"keys":                   keys,
				"min_encryption_version": m.minEncryption,
				"min_decryption_version": m.minDecryption,
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func setSignerEnv(t *testing.T, addr, token string) {
	t.Helper()
	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoTransitMount, "")
	t.Setenv(EnvOpenBaoAuthMethod, "")
	t.Setenv(EnvOpenBaoToken, token)
	t.Setenv(EnvTransitKeyName, "")
}

func newSigner(t *testing.T, m *mockTransit, token string) *obTransitClient {
	t.Helper()
	setSignerEnv(t, m.serve(t), token)
	c, err := newTransitClientFromEnv()
	if err != nil {
		t.Fatalf("newTransitClientFromEnv: %v", err)
	}
	return c
}

func TestPublish_InsertsSignedRow(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	out, err := publish(t.Context(), db, signer, testRelease(), "notes", at)
	if err != nil || out != outcomeInserted {
		t.Fatalf("publish = %q, %v", out, err)
	}
	var row saasapi.FleetVersion
	if err := db.Where("version = ?", "v2.4.1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.ID, "fv_") || row.Notes != "notes" || !row.ReleasedAt.Equal(at) {
		t.Errorf("row = %+v", row)
	}
	// The stored signature verifies with nothing but the public key — what
	// farmer, saasapi and the sprout each do.
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: m.pub}})
	if err := ks.Verify(testRelease().withSignature(row.Signature)); err != nil {
		t.Fatalf("stored signature does not verify: %v", err)
	}

	// Re-running for the same release is a no-op, not a second signature.
	out, err = publish(t.Context(), db, signer, testRelease(), "notes", at)
	if err != nil || out != outcomeUnchanged || m.signs != 1 {
		t.Fatalf("second publish = %q, %v (signs %d)", out, err, m.signs)
	}
}

// A row written before the signature column existed is signed in place,
// but only if its fields are exactly the ones this run was given.
func TestPublish_BackfillsUnmigratedRow(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)
	rel := testRelease()
	if err := db.Create(&saasapi.FleetVersion{ID: "fv_old", Version: rel.Version, ArtifactURL: rel.ArtifactURL,
		ChecksumSHA256: rel.ChecksumSHA256, ReleasedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	out, err := publish(t.Context(), db, signer, rel, "", time.Now())
	if err != nil || out != outcomeBackfilled {
		t.Fatalf("publish = %q, %v", out, err)
	}
	var row saasapi.FleetVersion
	db.First(&row, "id = ?", "fv_old")
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: m.pub}})
	if err := ks.Verify(rel.withSignature(row.Signature)); err != nil {
		t.Fatalf("backfilled signature does not verify: %v", err)
	}
}

func TestPublish_RefusesConflictingRow(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)
	rel := testRelease()
	// Someone with saas write access put an unsigned row in with a
	// different artifact URL. fleetreleaser must not sign it.
	db.Create(&saasapi.FleetVersion{ID: "fv_x", Version: rel.Version, ArtifactURL: "https://evil.example.com/sprout",
		ChecksumSHA256: rel.ChecksumSHA256, ReleasedAt: time.Now()})
	if _, err := publish(t.Context(), db, signer, rel, "", time.Now()); !errors.Is(err, errReleaseConflict) {
		t.Fatalf("publish = %v, want errReleaseConflict", err)
	}
	if m.signs != 0 {
		t.Fatalf("Transit was asked to sign %d time(s) for a conflicting row", m.signs)
	}
}

func TestPublish_RefusesExistingBadSignature(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)
	rel := testRelease()
	db.Create(&saasapi.FleetVersion{ID: "fv_x", Version: rel.Version, ArtifactURL: rel.ArtifactURL,
		ChecksumSHA256: rel.ChecksumSHA256, Signature: fleetsign.EncodeSignature(1, make([]byte, 64)), ReleasedAt: time.Now()})
	if _, err := publish(t.Context(), db, signer, rel, "", time.Now()); !errors.Is(err, errExistingSignatureInvalid) {
		t.Fatalf("publish = %v, want errExistingSignatureInvalid", err)
	}
}

// If what Transit hands back doesn't verify over the canonical message,
// nothing is written.
func TestPublish_SelfVerifiesBeforeWriting(t *testing.T) {
	m := newMockTransit(t)
	m.tamper = true
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)
	if _, err := publish(t.Context(), db, signer, testRelease(), "", time.Now()); err == nil {
		t.Fatal("publish accepted a signature that does not verify")
	}
	var n int64
	db.Model(&saasapi.FleetVersion{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d row(s) written after a failed self-verify", n)
	}
}

// A read-only token (what farmer and saasapi hold) gets a 403 from sign,
// and nothing is written. This is the mock's policy, not OpenBao's; see
// TestOpenBaoEnforcesReadOnlyFleetKey for the real one.
func TestPublish_ReadOnlyTokenCannotSign(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "saasapi-ro")
	db := newTestDB(t)
	_, err := publish(t.Context(), db, signer, testRelease(), "", time.Now())
	if !errors.Is(err, errSignFailed) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("publish with read-only token = %v, want errSignFailed/403", err)
	}
	var n int64
	db.Model(&saasapi.FleetVersion{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d row(s) written without a signature", n)
	}
}

func TestPublish_RejectsInvalidRelease(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "signer")
	rel := testRelease()
	rel.ArtifactURL = "http://artifacts.example.com/x"
	if _, err := publish(context.Background(), newTestDB(t), signer, rel, "", time.Now()); !errors.Is(err, errInvalidArtifactURL) {
		t.Fatalf("publish = %v, want errInvalidArtifactURL", err)
	}
	rel = testRelease()
	rel.FileName = "../imas-sprout.deb"
	if _, err := publish(context.Background(), newTestDB(t), signer, rel, "", time.Now()); !errors.Is(err, fleetsign.ErrInvalidManifest) {
		t.Fatalf("publish = %v, want ErrInvalidManifest", err)
	}
	if m.signs != 0 {
		t.Fatalf("Transit was asked to sign %d invalid release(s)", m.signs)
	}
}

// What fleetreleaser signs is the fleetsign.Manifest canonical message,
// byte for byte, with no URL in it.
func TestPublish_SignsManifestMessage(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)
	rel := testRelease()
	if _, err := publish(t.Context(), db, signer, rel, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	var row saasapi.FleetVersion
	db.First(&row, "version = ?", rel.Version)
	_, sig, err := fleetsign.DecodeSignature(row.Signature)
	if err != nil {
		t.Fatal(err)
	}
	want := "imas-fleet-manifest-v1|v2.4.1|linux|amd64|imas-sprout_2.4.1_amd64.deb|" + testChecksum + "|v2.0.0"
	if !ed25519.Verify(m.pub, []byte(want), sig) {
		t.Fatalf("stored signature is not over %q", want)
	}
}

func TestRun_UsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	valid := []string{"-version", "v1.0.0", "-os", "linux", "-arch", "amd64", "-file-name", "imas-sprout_1.0.0_amd64.deb",
		"-min-sprout-version", "v1.0.0", "-artifact-url", "https://a.example.com/x", "-checksum-sha256", testChecksum}
	with := func(extra ...string) []string { return append(append([]string(nil), valid...), extra...) }
	without := func(flag string) []string {
		var out []string
		for i := 0; i < len(valid); i += 2 {
			if valid[i] != flag {
				out = append(out, valid[i], valid[i+1])
			}
		}
		return out
	}
	cases := [][]string{
		{},
		{"-version", "v1.0.0", "-artifact-url", "https://a.example.com/x"},
		without("-os"),
		without("-arch"),
		without("-file-name"),
		without("-min-sprout-version"),
		without("-checksum-sha256"),
		without("-artifact-url"),
		with("-artifact-url", "http://a.example.com/x"),
		with("-version", "v1"),
		with("-min-sprout-version", "v9.0.0"),
		with("-file-name", "pool/imas.deb"),
		with("extra"),
		with("-released-at", "yesterday"),
	}
	t.Setenv(EnvOpenBaoAddr, "")
	for i, args := range cases {
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("case %d: exit %d, want 2 (stderr %s)", i, code, stderr.String())
		}
	}
	// Valid flags, missing DSN.
	setSignerEnv(t, "http://127.0.0.1:1", "x")
	t.Setenv(EnvDSN, "")
	if code := run(with("-checksum-sha256", strings.ToUpper(testChecksum)), &stdout, &stderr); code != 2 {
		t.Errorf("missing DSN: exit %d, want 2", code)
	}
}

// Rotation grace period: v2 is the only version new signatures use
// (min_encryption_version=2), but Transit still verifies v1
// (min_decryption_version=1). A release already published under v1 is
// valid for every verifier, so re-running fleetreleaser for it must say
// "unchanged" — not refuse it as an invalid signature — and must not
// re-sign it. Once v1 is retired (min_decryption_version=2), the same row
// is refused, matching the verifiers again.
func TestPublish_GracePeriodExistingRowSignedByOlderVersion(t *testing.T) {
	m := newMockTransit(t) // signs with m.version
	m.version = 2
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.older = map[int]ed25519.PublicKey{1: oldPub}
	m.minEncryption, m.minDecryption = 2, 1
	signer := newSigner(t, m, "signer")
	db := newTestDB(t)

	rel := testRelease()
	msg, _ := rel.Message()
	v1Sig := fleetsign.EncodeSignature(1, ed25519.Sign(oldPriv, msg))
	if err := db.Create(&saasapi.FleetVersion{ID: "fv_v1", Version: rel.Version, ArtifactURL: rel.ArtifactURL,
		ChecksumSHA256: rel.ChecksumSHA256, Signature: v1Sig, ReleasedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}

	out, err := publish(t.Context(), db, signer, rel, "", time.Now())
	if err != nil || out != outcomeUnchanged {
		t.Fatalf("publish during grace period = %q, %v; want unchanged", out, err)
	}
	if m.signs != 0 {
		t.Fatalf("Transit was asked to sign %d time(s) for an already-valid row", m.signs)
	}

	// A new release during the grace period is signed with v2, and the
	// post-sign self-verify still passes.
	next := rel
	next.Version = "v2.4.2"
	if out, err := publish(t.Context(), db, signer, next, "", time.Now()); err != nil || out != outcomeInserted {
		t.Fatalf("new release during grace period = %q, %v", out, err)
	}
	var row saasapi.FleetVersion
	db.First(&row, "version = ?", next.Version)
	if !strings.HasPrefix(row.Signature, "v2:") {
		t.Fatalf("new release signed as %q, want v2", row.Signature)
	}

	// v1 retired for verification: the old row is now refused, and left
	// as it was.
	m.minDecryption = 2
	if _, err := publish(t.Context(), db, signer, rel, "", time.Now()); !errors.Is(err, errExistingSignatureInvalid) {
		t.Fatalf("publish after retiring v1 = %v, want errExistingSignatureInvalid", err)
	}
	var old saasapi.FleetVersion
	if err := db.First(&old, "id = ?", "fv_v1").Error; err != nil {
		t.Fatal(err)
	}
	if old.Signature != v1Sig {
		t.Fatal("refused row was modified")
	}
}
