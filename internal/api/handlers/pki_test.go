package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/nats-io/nkeys"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/pkitest"
)

// setupPKIDirs wires up an in-memory PKI store (see internal/pki/store.go)
// and a miniredis-backed enrollment/refresh replay cache (see
// internal/pki/replaycache.go) for testing. It also creates a fake farmer
// NKey pub file so that pki.ReloadNKeys() (called by defer in AcceptNKey,
// DenyNKey, etc.) doesn't log.Fatal.
// pkiTestDBSeq numbers setupPKIDirs's databases.
var pkiTestDBSeq atomic.Int64

func setupPKIDirs(t *testing.T) string {
	t.Helper()

	// A shared-cache in-memory database lives as long as a connection to
	// it does, so a name reused by the same test under -count would find
	// the previous run's rows: give each call its own, and close it.
	dsn := "file:" + t.Name() + "-pki-" + strconv.FormatInt(pkiTestDBSeq.Add(1), 10) + "?mode=memory&cache=shared"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening pki test db: %v", err)
	}
	if sqlDB, err := gdb.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	if err := gdb.AutoMigrate(append(pki.Models(), pki.SproutJWTModels()...)...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })
	// Sprout User JWTs live in a bucket (pki.MintOrReuseUserJWT).
	sproutJWTs, err := objectstore.Open(objectstoretest.NewServer(t).Config())
	if err != nil {
		t.Fatalf("opening the fake sprout JWT bucket: %v", err)
	}
	pki.SetSproutJWTStore(sproutJWTs)
	t.Cleanup(func() { pki.SetSproutJWTStore(nil) })

	mr := miniredis.RunT(t)
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("connecting to miniredis: %v", err)
	}
	t.Cleanup(vc.Close)
	pki.SetReplayCacheClient(vc)
	t.Cleanup(func() { pki.SetReplayCacheClient(nil) })

	dir := t.TempDir()
	pkitest.Farmer(t) // the NATS trust chain in a fake Transit

	// Create a fake farmer NKey pub file so ReloadNKeys doesn't crash.
	farmerKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create farmer nkey: %v", err)
	}
	farmerPub, err := farmerKP.PublicKey()
	if err != nil {
		t.Fatalf("get farmer pub: %v", err)
	}
	farmerPubFile := filepath.Join(dir, "farmer.pub")
	if err := os.WriteFile(farmerPubFile, []byte(farmerPub), 0o644); err != nil {
		t.Fatalf("write farmer pub: %v", err)
	}
	config.NKeyFarmerPubFile = farmerPubFile

	// Set minimal config values so ConfigureNats() doesn't panic.
	config.FarmerBusPort = "0"
	config.FarmerInterface = "127.0.0.1"

	// Create self-signed TLS certs for ReloadNKeys -> ConfigureNats.
	createTestTLSCerts(t, dir)
	config.RootCA = filepath.Join(dir, "rootCA.pem")
	config.CertFile = filepath.Join(dir, "cert.pem")
	config.KeyFile = filepath.Join(dir, "key.pem")

	return dir
}

// writeSproutKey registers id at the given lifecycle state via the pki
// package's own lifecycle functions. dir is unused (kept so existing call
// sites don't need to change) now that PKI state lives in PXC, not on
// disk.
func writeSproutKey(t *testing.T, _, state, id, nkey string) {
	t.Helper()
	switch state {
	case "unaccepted":
		if err := pki.UnacceptNKey(pki.CurrentTenantID(), id, nkey); err != nil {
			t.Fatalf("UnacceptNKey(%q): %v", id, err)
		}
	case "accepted":
		if err := pki.UnacceptNKey(pki.CurrentTenantID(), id, nkey); err != nil {
			t.Fatalf("UnacceptNKey(%q): %v", id, err)
		}
		if err := pki.AcceptNKey(pki.CurrentTenantID(), id); err != nil {
			t.Fatalf("AcceptNKey(%q): %v", id, err)
		}
	case "denied":
		if err := pki.UnacceptNKey(pki.CurrentTenantID(), id, nkey); err != nil {
			t.Fatalf("UnacceptNKey(%q): %v", id, err)
		}
		if err := pki.DenyNKey(pki.CurrentTenantID(), id); err != nil {
			t.Fatalf("DenyNKey(%q): %v", id, err)
		}
	case "rejected":
		if err := pki.RejectNKey(pki.CurrentTenantID(), id, nkey); err != nil {
			t.Fatalf("RejectNKey(%q): %v", id, err)
		}
	default:
		t.Fatalf("writeSproutKey: unknown state %q", state)
	}
}

// --- PutNKey tests ---

func TestPutNKey_InvalidJSON(t *testing.T) {
	setupPKIDirs(t)

	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader([]byte("bad json")))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestPutNKey_InvalidSproutID(t *testing.T) {
	setupPKIDirs(t)

	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "INVALID-CAPS",
		NKey:     "UABC123",
	})
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid sprout ID, got %d", w.Code)
	}
}

func TestPutNKey_SproutIDWithUnderscore(t *testing.T) {
	setupPKIDirs(t)

	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "bad_id",
		NKey:     "UABC123",
	})
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for underscore in ID, got %d", w.Code)
	}
}

func TestPutNKey_InvalidNKey(t *testing.T) {
	setupPKIDirs(t)

	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "good-sprout",
		NKey:     "not-a-real-nkey",
	})
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid NKey, got %d", w.Code)
	}
}

func TestPutNKey_NewSprout(t *testing.T) {
	setupPKIDirs(t)

	// Generate a real NKey user key pair for testing
	nkey := generateTestUserNKey(t)

	body := signedSubmission(t, "new-sprout", nkey)
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for new sprout, got %d: %s", w.Code, w.Body.String())
	}

	var resp apitypes.Inline
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Success {
		t.Error("expected success=true")
	}

	// Verify the key was saved as unaccepted.
	got, err := pki.GetNKey(pki.CurrentTenantID(), "new-sprout")
	if err != nil {
		t.Fatalf("expected key to be saved: %v", err)
	}
	if got != nkey {
		t.Errorf("expected saved key %q, got %q", nkey, got)
	}
	found := false
	for _, s := range pki.GetNKeysByType(pki.CurrentTenantID(), "unaccepted").Sprouts {
		if s.SproutID == "new-sprout" {
			found = true
		}
	}
	if !found {
		t.Error("expected key to be saved in unaccepted state")
	}
}

func TestPutNKey_AlreadyKnownExact(t *testing.T) {
	dir := setupPKIDirs(t)

	nkey := generateTestUserNKey(t)
	writeSproutKey(t, dir, "accepted", "known-sprout", nkey)

	body := signedSubmission(t, "known-sprout", nkey)
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for re-submitting same key, got %d", w.Code)
	}

	var resp apitypes.Inline
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Success {
		t.Error("expected success=true for already known key")
	}
}

func TestPutNKey_SameIDDifferentKey(t *testing.T) {
	setupPKIDirs(t)

	existingKey := generateTestUserNKey(t)
	newKey := generateTestUserNKey(t)
	writeSproutKey(t, "", "accepted", "conflict-sprout", existingKey)

	body := signedSubmission(t, "conflict-sprout", newKey)
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (saved as conflict), got %d: %s", w.Code, w.Body.String())
	}

	// Should have been saved as conflict-sprout_1 in rejected.
	found := false
	for _, s := range pki.GetNKeysByType(pki.CurrentTenantID(), "rejected").Sprouts {
		if s.SproutID == "conflict-sprout_1" {
			found = true
		}
	}
	if !found {
		t.Error("expected conflicting key to be saved as conflict-sprout_1 in rejected")
	}
}

func TestPutNKey_SameIDDifferentKey_MatchInLoop(t *testing.T) {
	dir := setupPKIDirs(t)

	// Existing sprout with ID "loop-sprout" has key A
	existingKey := generateTestUserNKey(t)
	writeSproutKey(t, dir, "accepted", "loop-sprout", existingKey)

	// A _1 suffix already exists with key B (the one we'll re-submit)
	sameKey := generateTestUserNKey(t)
	writeSproutKey(t, dir, "rejected", "loop-sprout_1", sameKey)

	// Re-submitting key B should match at _1 and return 200 success
	body := signedSubmission(t, "loop-sprout", sameKey)
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp apitypes.Inline
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Success {
		t.Error("expected success=true for re-submitted known key in loop")
	}
}

func TestPutNKey_Over100Keys_ServiceUnavailable(t *testing.T) {
	dir := setupPKIDirs(t)

	// Create 100 different keys for the same sprout ID (base + _1.._99)
	baseKey := generateTestUserNKey(t)
	writeSproutKey(t, dir, "accepted", "flood-sprout", baseKey)

	for i := 1; i < 100; i++ {
		suffixedKey := generateTestUserNKey(t)
		name := "flood-sprout_" + strconv.Itoa(i)
		writeSproutKey(t, dir, "rejected", name, suffixedKey)
	}

	// Submit a brand new key — should hit the 100-key overflow
	newKey := generateTestUserNKey(t)
	body := signedSubmission(t, "flood-sprout", newKey)
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for 100+ keys, got %d: %s", w.Code, w.Body.String())
	}

	var resp apitypes.Inline
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("expected success=false for overflow")
	}
}

func TestPutNKey_EmptyBody(t *testing.T) {
	setupPKIDirs(t)

	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader([]byte("")))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
}

func TestPutNKey_EmptySproutID(t *testing.T) {
	setupPKIDirs(t)

	nkey := generateTestUserNKey(t)
	body := signedSubmission(t, "", nkey)
	req := httptest.NewRequest(http.MethodPut, "/nkey", bytes.NewReader(body))
	w := httptest.NewRecorder()
	PutNKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty sprout ID, got %d", w.Code)
	}
}

// --- GetCertificate tests ---

func TestGetCertificate(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "rootCA.pem")
	certContent := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(tmpFile, certContent, 0o644); err != nil {
		t.Fatal(err)
	}
	config.RootCA = tmpFile

	req := httptest.NewRequest(http.MethodGet, "/certificate", nil)
	w := httptest.NewRecorder()
	GetCertificate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Error("expected certificate content in response")
	}
}

func TestGetCertificate_MissingFile(t *testing.T) {
	config.RootCA = "/nonexistent/rootCA.pem"

	req := httptest.NewRequest(http.MethodGet, "/certificate", nil)
	w := httptest.NewRecorder()
	GetCertificate(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for missing cert file")
	}
}

// --- Test helpers ---

// createTestTLSCerts generates a self-signed CA and server cert/key in dir.
func createTestTLSCerts(t *testing.T, dir string) {
	t.Helper()

	// Generate CA key and cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(filepath.Join(dir, "rootCA.pem"), caCertPEM, 0o644); err != nil {
		t.Fatalf("write rootCA: %v", err)
	}

	// Generate server key and cert signed by CA
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caTemplate, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), srvCertPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), srvKeyPEM, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// generateTestUserNKey creates a valid NATS user public key for testing.
func generateTestUserNKey(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create test user nkey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}
	testNKeys.Store(pub, kp)
	return pub
}

// testNKeys holds the seed of every generateTestUserNKey key, so a
// submission can be signed (signedSubmission).
var testNKeys sync.Map

// signedSubmission is a PUT /pki/putnkey body for id and nkey (a
// generateTestUserNKey key) with a fresh nonce and the NKey's signature,
// as pki.PutNKey sends it.
func signedSubmission(t *testing.T, id, nkey string) []byte {
	t.Helper()
	v, ok := testNKeys.Load(nkey)
	if !ok {
		t.Fatalf("no seed for %s", nkey)
	}
	nonce, err := pki.IssueNKeyNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := v.(nkeys.KeyPair).Sign(pki.NKeySubmissionPayload(nonce, id, nkey))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(pki.KeySubmission{SproutID: id, NKey: nkey, Nonce: nonce, Sig: base64.RawURLEncoding.EncodeToString(sig)})
	return body
}

// --- PutNKey proof of possession (security review 2026-10, L12) ---

// A submission that does not prove possession of its NKey is refused with
// 403 and stores nothing: no nonce, a forged or someone else's signature,
// a signature over another ID, a spent or an expired nonce.
func TestPutNKey_RefusesWithoutProofOfPossession(t *testing.T) {
	setupPKIDirs(t)
	victim := generateTestUserNKey(t)
	attacker := generateTestUserNKey(t)
	writeSproutKey(t, "", "accepted", "victim", victim)

	sign := func(kpPub, nonce, id, nkey string) string {
		v, _ := testNKeys.Load(kpPub)
		sig, err := v.(nkeys.KeyPair).Sign(pki.NKeySubmissionPayload(nonce, id, nkey))
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}
	nonce := func() string {
		n, err := pki.IssueNKeyNonce()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	spent := signedSubmission(t, "other-id", victim)
	put := func(body []byte) int {
		w := httptest.NewRecorder()
		PutNKey(w, httptest.NewRequest(http.MethodPut, "/pki/putnkey", bytes.NewReader(body)))
		return w.Code
	}
	if code := put(spent); code != http.StatusOK {
		t.Fatalf("a valid submission: %d", code)
	}
	n1, n2, n3 := nonce(), nonce(), nonce()
	for name, sub := range map[string]pki.KeySubmission{
		"no nonce":               {SproutID: "victim-x", NKey: victim},
		"unknown nonce":          {SproutID: "victim-x", NKey: victim, Nonce: "bm90LWEtbm9uY2U", Sig: sign(victim, "bm90LWEtbm9uY2U", "victim-x", victim)},
		"signed by another key":  {SproutID: "victim-x", NKey: victim, Nonce: n1, Sig: sign(attacker, n1, "victim-x", victim)},
		"signature for other id": {SproutID: "victim-x", NKey: victim, Nonce: n2, Sig: sign(victim, n2, "victim-y", victim)},
		"signature not base64":   {SproutID: "victim-x", NKey: victim, Nonce: n3, Sig: "!!"},
	} {
		body, _ := json.Marshal(sub)
		if code := put(body); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}
	if code := put(spent); code != http.StatusForbidden {
		t.Errorf("replayed submission (spent nonce): %d, want 403", code)
	}
	for _, s := range pki.GetNKeysByType(pki.CurrentTenantID(), "unaccepted").Sprouts {
		if s.SproutID == "victim-x" {
			t.Fatal("an unproven submission was stored")
		}
	}
	for _, s := range pki.GetNKeysByType(pki.CurrentTenantID(), "rejected").Sprouts {
		if s.SproutID == "victim-x" || s.SproutID == "victim_1" {
			t.Fatal("an unproven submission was stored as rejected")
		}
	}
}

func TestGetNKeyNonce(t *testing.T) {
	a, b := httptest.NewRecorder(), httptest.NewRecorder()
	GetNKeyNonce(a, httptest.NewRequest(http.MethodGet, "/pki/nkeynonce", nil))
	GetNKeyNonce(b, httptest.NewRequest(http.MethodGet, "/pki/nkeynonce", nil))
	var na, nb pki.NKeyNonce
	if a.Code != http.StatusOK || json.Unmarshal(a.Body.Bytes(), &na) != nil || len(na.Nonce) < 40 {
		t.Fatalf("nonce answer %d %q", a.Code, a.Body.String())
	}
	if json.Unmarshal(b.Body.Bytes(), &nb) != nil || na.Nonce == nb.Nonce {
		t.Fatal("two requests got the same nonce")
	}
	if a.Header().Get("Cache-Control") != "no-store" {
		t.Error("nonce answer may be cached")
	}
}
