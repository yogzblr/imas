package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
	"github.com/yogzblr/imas/internal/pki"
)

// setupPKIDirs wires up an in-memory PKI store (see internal/pki/store.go)
// and a miniredis-backed enrollment/refresh replay cache (see
// internal/pki/replaycache.go) for testing and sets config.FarmerPKI. It
// also creates a fake farmer
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
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })

	mr := miniredis.RunT(t)
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("connecting to miniredis: %v", err)
	}
	t.Cleanup(vc.Close)
	pki.SetReplayCacheClient(vc)
	t.Cleanup(func() { pki.SetReplayCacheClient(nil) })

	dir := t.TempDir()
	config.FarmerPKI = dir + "/"

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

	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "new-sprout",
		NKey:     nkey,
	})
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

	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "known-sprout",
		NKey:     nkey,
	})
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

	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "conflict-sprout",
		NKey:     newKey,
	})
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
	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "loop-sprout",
		NKey:     sameKey,
	})
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
	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "flood-sprout",
		NKey:     newKey,
	})
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
	body, _ := json.Marshal(pki.KeySubmission{
		SproutID: "",
		NKey:     nkey,
	})
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
	return pub
}
