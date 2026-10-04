package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
)

// newTestDB opens a fresh in-memory, pure-Go (no CGO) sqlite database,
// migrates this package's table, and installs it as the package-level db
// used by every store function.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	if err := gdb.AutoMigrate(Models()...); err != nil {
		t.Fatalf("migrating test db: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() { SetDB(nil) })
	return gdb
}

// setupTestPKI wires up an in-memory PKI store plus the TLS/NKey
// scaffolding ReloadNKeys (called by Accept/Deny/Reject/Unaccept/Delete via
// defer) needs so it doesn't fatal during tests.
func setupTestPKI(t *testing.T) {
	t.Helper()
	newTestDB(t)

	tmpDir := t.TempDir()
	config.FarmerPKI = filepath.Join(tmpDir, "pki") + "/"

	farmerPubFile := filepath.Join(tmpDir, "farmer.pub")
	if err := os.WriteFile(farmerPubFile, []byte("UFAKE_FARMER_KEY_FOR_TESTING"), 0o600); err != nil {
		t.Fatalf("failed to write dummy farmer pub key: %v", err)
	}
	config.NKeyFarmerPubFile = farmerPubFile

	// NatsServer must be nil so ReloadNKeys skips the server reload.
	NatsServer = nil

	// ReloadNKeys calls ConfigureNats which needs valid TLS files.
	config.FarmerInterface = "127.0.0.1"
	config.FarmerBusPort = "14222"
	config.FarmerOrganization = "imas-test"
	config.CertificateValidTime = 24 * 365 * time.Hour
	config.RootCA = filepath.Join(tmpDir, "rootca.pem")
	config.RootCAPriv = filepath.Join(tmpDir, "rootca-key.pem")
	config.CertFile = filepath.Join(tmpDir, "cert.pem")
	config.KeyFile = filepath.Join(tmpDir, "key.pem")
	config.CertHosts = []string{"127.0.0.1"}

	generateTestCerts(t, tmpDir)
}

// generateTestCerts creates a self-signed CA and leaf certificate for
// ConfigureNats to load during ReloadNKeys.
func generateTestCerts(t *testing.T, tmpDir string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"imas-test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	// Write CA cert.
	writePEM(t, filepath.Join(tmpDir, "rootca.pem"), "CERTIFICATE", caDER)

	// Write CA private key.
	caPrivBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	writePEM(t, filepath.Join(tmpDir, "rootca-key.pem"), "PRIVATE KEY", caPrivBytes)

	// Leaf cert.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"imas-test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	writePEM(t, filepath.Join(tmpDir, "cert.pem"), "CERTIFICATE", leafDER)

	leafPrivBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	writePEM(t, filepath.Join(tmpDir, "key.pem"), "PRIVATE KEY", leafPrivBytes)
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		t.Fatalf("encode PEM to %s: %v", path, err)
	}
}

// writeKey inserts an NKey row directly into the test store at the given
// state, bypassing the lifecycle functions under test.
func writeKey(t *testing.T, state, sproutID, nkey string) {
	t.Helper()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID(), SproutID: sproutID, NKey: nkey, State: state}); err != nil {
		t.Fatalf("failed to write key row %s/%s: %v", state, sproutID, err)
	}
}

// keyState returns the current state of sproutID's row, or "" if it
// doesn't exist.
func keyState(t *testing.T, sproutID string) string {
	t.Helper()
	row, err := findNKeyRowInTenant(tenantID(), sproutID)
	if err != nil {
		return ""
	}
	return row.State
}

func TestIsValidSproutID(t *testing.T) {
	testCases := []struct {
		id            string
		shouldSucceed bool
		testID        string
	}{
		{id: "test", shouldSucceed: true, testID: "simple"},
		{id: "-test", shouldSucceed: false, testID: "leading hyphen"},
		{id: "te_st", shouldSucceed: true, testID: "embedded underscore"},
		{id: "imasNode", shouldSucceed: false, testID: "capital letter"},
		{id: "t.est", shouldSucceed: false, testID: "embedded dot"},
		{id: strings.Repeat("a", 300), shouldSucceed: false, testID: "300 long string"},
		{id: strings.Repeat("a", 253), shouldSucceed: true, testID: "253 long string"},
		{id: "0132-465798qwertyuiopasdfghjklzxcv_bnm", shouldSucceed: true, testID: "keyboard smash"},
		{id: "0132-465798qwertyuiopasdfghjklzxcv.bnm", shouldSucceed: false, testID: "keyboard smash with a dot"},
		{id: "te\nst", shouldSucceed: false, testID: "multiline"},
		{id: "", shouldSucceed: false, testID: "empty string"},
		{id: "_test", shouldSucceed: false, testID: "leading underscore"},
		{id: "test.", shouldSucceed: false, testID: "trailing dot"},
		{id: "a", shouldSucceed: true, testID: "single char"},
		// Security review 2026-10, M4: a dot would let sprout "web-01"'s
		// grants (imas.sprouts.web-01.>) cover "web-01.example.com"'s.
		{id: "web-01.example.com", shouldSucceed: false, testID: "fqdn-like"},
		{id: "192.168.1.1", shouldSucceed: false, testID: "ip-like"},
		{id: "web-01-example-com", shouldSucceed: true, testID: "fqdn mapped to dashes"},
		{id: ".web", shouldSucceed: false, testID: "leading dot"},
		// A NATS wildcard or token separator can never be part of an ID.
		{id: "web*", shouldSucceed: false, testID: "star"},
		{id: "web>", shouldSucceed: false, testID: "gt"},
		{id: "web 01", shouldSucceed: false, testID: "space"},
		// Reserved: imas.sprouts.announce.<id> is every sprout's
		// announcement, so a sprout named "announce" would receive them all.
		{id: "announce", shouldSucceed: false, testID: "reserved announce"},
		{id: "announce_1", shouldSucceed: true, testID: "suffixed reserved word is its own token"},
		{id: "announce-01", shouldSucceed: true, testID: "reserved word as a prefix"},
	}
	for _, tc := range testCases {
		t.Run(tc.testID, func(t *testing.T) {
			if IsValidSproutID(tc.id) != tc.shouldSucceed {
				t.Errorf("`%s`: expected %v but got %v", tc.id, tc.shouldSucceed, !tc.shouldSucceed)
			}
		})
	}
}

func TestSetupPKIFarmer(t *testing.T) {
	tmpDir := t.TempDir()
	config.FarmerPKI = filepath.Join(tmpDir, "pki") + "/"

	SetupPKIFarmer()

	info, err := os.Stat(config.FarmerPKI)
	if err != nil {
		t.Fatalf("expected PKI directory %s to exist: %v", config.FarmerPKI, err)
	}
	if !info.IsDir() {
		t.Errorf("expected %s to be a directory", config.FarmerPKI)
	}

	// Calling again should not fail (idempotent).
	SetupPKIFarmer()
}

func TestUnacceptNKey_NewSprout(t *testing.T) {
	setupTestPKI(t)

	err := UnacceptNKey(currentTenantID(), "webserver01", "NKEY_ABC123")
	if err != nil {
		t.Fatalf("UnacceptNKey failed: %v", err)
	}

	key, err := GetNKey(currentTenantID(), "webserver01")
	if err != nil {
		t.Fatalf("expected key: %v", err)
	}
	if key != "NKEY_ABC123" {
		t.Errorf("expected key content %q, got %q", "NKEY_ABC123", key)
	}
	if got := keyState(t, "webserver01"); got != stateUnaccepted {
		t.Errorf("expected state %q, got %q", stateUnaccepted, got)
	}
}

func TestUnacceptNKey_InvalidID(t *testing.T) {
	setupTestPKI(t)

	err := UnacceptNKey(currentTenantID(), "-invalid", "NKEY_ABC123")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestAcceptNKey(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "unaccepted", "db01", "NKEY_DB01")

	err := AcceptNKey(currentTenantID(), "db01")
	if err != nil {
		t.Fatalf("AcceptNKey failed: %v", err)
	}

	key, err := GetNKey(currentTenantID(), "db01")
	if err != nil {
		t.Fatalf("expected key: %v", err)
	}
	if key != "NKEY_DB01" {
		t.Errorf("key content mismatch: %q", key)
	}
	if got := keyState(t, "db01"); got != stateAccepted {
		t.Errorf("expected state %q, got %q", stateAccepted, got)
	}
}

func TestAcceptNKey_AlreadyAccepted(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "db01", "NKEY_DB01")

	err := AcceptNKey(currentTenantID(), "db01")
	if !errors.Is(err, ErrAlreadyAccepted) {
		t.Errorf("expected ErrAlreadyAccepted, got: %v", err)
	}
}

func TestAcceptNKey_InvalidID(t *testing.T) {
	setupTestPKI(t)

	err := AcceptNKey(currentTenantID(), "-nope")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestAcceptNKey_NotFound(t *testing.T) {
	setupTestPKI(t)

	err := AcceptNKey(currentTenantID(), "nonexistent")
	if !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
	}
}

func TestDenyNKey(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "unaccepted", "app01", "NKEY_APP01")

	err := DenyNKey(currentTenantID(), "app01")
	if err != nil {
		t.Fatalf("DenyNKey failed: %v", err)
	}

	if got := keyState(t, "app01"); got != stateDenied {
		t.Errorf("expected state %q, got %q", stateDenied, got)
	}
}

func TestDenyNKey_AlreadyDenied(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "denied", "app01", "NKEY_APP01")

	err := DenyNKey(currentTenantID(), "app01")
	if !errors.Is(err, ErrAlreadyDenied) {
		t.Errorf("expected ErrAlreadyDenied, got: %v", err)
	}
}

func TestRejectNKey_ExistingKey(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "unaccepted", "rogue01", "NKEY_ROGUE")

	err := RejectNKey(currentTenantID(), "rogue01", "")
	if err != nil {
		t.Fatalf("RejectNKey failed: %v", err)
	}

	key, err := GetNKey(currentTenantID(), "rogue01")
	if err != nil {
		t.Fatalf("expected key: %v", err)
	}
	if key != "NKEY_ROGUE" {
		t.Errorf("key content mismatch: %q", key)
	}
	if got := keyState(t, "rogue01"); got != stateRejected {
		t.Errorf("expected state %q, got %q", stateRejected, got)
	}
}

func TestRejectNKey_NewKeyDirect(t *testing.T) {
	setupTestPKI(t)

	// Reject a sprout that doesn't exist yet — creates directly as rejected.
	err := RejectNKey(currentTenantID(), "badactor", "NKEY_BAD")
	if err != nil {
		t.Fatalf("RejectNKey failed: %v", err)
	}

	key, err := GetNKey(currentTenantID(), "badactor")
	if err != nil {
		t.Fatalf("expected key: %v", err)
	}
	if key != "NKEY_BAD" {
		t.Errorf("expected %q, got %q", "NKEY_BAD", key)
	}
}

func TestRejectNKey_AlreadyRejected(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "rejected", "rogue01", "NKEY_ROGUE")

	err := RejectNKey(currentTenantID(), "rogue01", "")
	if !errors.Is(err, ErrAlreadyRejected) {
		t.Errorf("expected ErrAlreadyRejected, got: %v", err)
	}
}

func TestDeleteNKey(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "old01", "NKEY_OLD")

	err := DeleteNKey(currentTenantID(), "old01")
	if err != nil {
		t.Fatalf("DeleteNKey failed: %v", err)
	}

	if _, err := GetNKey(currentTenantID(), "old01"); !errors.Is(err, ErrSproutIDNotFound) {
		t.Error("expected key to be deleted")
	}
}

func TestDeleteNKey_NotFound(t *testing.T) {
	setupTestPKI(t)

	err := DeleteNKey(currentTenantID(), "ghost")
	if !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
	}
}

func TestDeleteNKey_InvalidID(t *testing.T) {
	setupTestPKI(t)

	err := DeleteNKey(currentTenantID(), "-bad")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestGetNKey(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "cache01", "NKEY_CACHE01")

	key, err := GetNKey(currentTenantID(), "cache01")
	if err != nil {
		t.Fatalf("GetNKey failed: %v", err)
	}
	if key != "NKEY_CACHE01" {
		t.Errorf("expected %q, got %q", "NKEY_CACHE01", key)
	}
}

func TestGetNKey_NotFound(t *testing.T) {
	setupTestPKI(t)

	_, err := GetNKey(currentTenantID(), "missing")
	if !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
	}
}

func TestGetNKey_InvalidID(t *testing.T) {
	setupTestPKI(t)

	_, err := GetNKey(currentTenantID(), "-invalid")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestGetNKey_FromEachState(t *testing.T) {
	setupTestPKI(t)

	states := []string{"unaccepted", "accepted", "denied", "rejected"}
	for _, state := range states {
		sproutID := state + "-sprout"
		expectedKey := "NKEY_" + strings.ToUpper(state)
		writeKey(t, state, sproutID, expectedKey)

		t.Run(state, func(t *testing.T) {
			key, err := GetNKey(currentTenantID(), sproutID)
			if err != nil {
				t.Fatalf("GetNKey(%q) failed: %v", sproutID, err)
			}
			if key != expectedKey {
				t.Errorf("expected %q, got %q", expectedKey, key)
			}
		})
	}
}

func TestNKeyExists(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "exist01", "NKEY_EXIST")

	t.Run("exists and matches", func(t *testing.T) {
		registered, matches := NKeyExists(currentTenantID(), "exist01", "NKEY_EXIST")
		if !registered {
			t.Error("expected registered=true")
		}
		if !matches {
			t.Error("expected matches=true")
		}
	})

	t.Run("exists but mismatches", func(t *testing.T) {
		registered, matches := NKeyExists(currentTenantID(), "exist01", "WRONG_KEY")
		if !registered {
			t.Error("expected registered=true")
		}
		if matches {
			t.Error("expected matches=false")
		}
	})

	t.Run("not registered", func(t *testing.T) {
		registered, matches := NKeyExists(currentTenantID(), "nope", "ANY")
		if registered {
			t.Error("expected registered=false")
		}
		if matches {
			t.Error("expected matches=false")
		}
	})
}

func TestGetNKeysByType(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "a1", "KEY_A1")
	writeKey(t, "accepted", "a2", "KEY_A2")
	writeKey(t, "denied", "d1", "KEY_D1")

	t.Run("accepted", func(t *testing.T) {
		ks := GetNKeysByType(currentTenantID(), "accepted")
		if len(ks.Sprouts) != 2 {
			t.Errorf("expected 2 accepted sprouts, got %d", len(ks.Sprouts))
		}
	})

	t.Run("denied", func(t *testing.T) {
		ks := GetNKeysByType(currentTenantID(), "denied")
		if len(ks.Sprouts) != 1 {
			t.Errorf("expected 1 denied sprout, got %d", len(ks.Sprouts))
		}
	})

	t.Run("empty state", func(t *testing.T) {
		ks := GetNKeysByType(currentTenantID(), "rejected")
		if len(ks.Sprouts) != 0 {
			t.Errorf("expected 0 rejected sprouts, got %d", len(ks.Sprouts))
		}
	})

	t.Run("invalid state", func(t *testing.T) {
		ks := GetNKeysByType(currentTenantID(), "bogus")
		if len(ks.Sprouts) != 0 {
			t.Errorf("expected 0 sprouts for invalid state, got %d", len(ks.Sprouts))
		}
	})
}

func TestListNKeysByType(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "a1", "KEY_A1")
	writeKey(t, "unaccepted", "u1", "KEY_U1")
	writeKey(t, "denied", "d1", "KEY_D1")
	writeKey(t, "rejected", "r1", "KEY_R1")

	all := ListNKeysByType(currentTenantID())
	if len(all.Accepted.Sprouts) != 1 {
		t.Errorf("expected 1 accepted, got %d", len(all.Accepted.Sprouts))
	}
	if len(all.Unaccepted.Sprouts) != 1 {
		t.Errorf("expected 1 unaccepted, got %d", len(all.Unaccepted.Sprouts))
	}
	if len(all.Denied.Sprouts) != 1 {
		t.Errorf("expected 1 denied, got %d", len(all.Denied.Sprouts))
	}
	if len(all.Rejected.Sprouts) != 1 {
		t.Errorf("expected 1 rejected, got %d", len(all.Rejected.Sprouts))
	}
}

func TestAcceptThenDeny(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "unaccepted", "flip01", "NKEY_FLIP")

	// Accept it.
	if err := AcceptNKey(currentTenantID(), "flip01"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	// Verify it's accepted.
	ks := GetNKeysByType(currentTenantID(), "accepted")
	found := false
	for _, s := range ks.Sprouts {
		if s.SproutID == "flip01" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("flip01 not found in accepted after AcceptNKey")
	}

	// Deny it.
	if err := DenyNKey(currentTenantID(), "flip01"); err != nil {
		t.Fatalf("DenyNKey: %v", err)
	}

	// Should be in denied, not accepted.
	ksAccepted := GetNKeysByType(currentTenantID(), "accepted")
	for _, s := range ksAccepted.Sprouts {
		if s.SproutID == "flip01" {
			t.Error("flip01 still in accepted after DenyNKey")
		}
	}
	ksDenied := GetNKeysByType(currentTenantID(), "denied")
	found = false
	for _, s := range ksDenied.Sprouts {
		if s.SproutID == "flip01" {
			found = true
			break
		}
	}
	if !found {
		t.Error("flip01 not found in denied after DenyNKey")
	}
}

func TestSetupPKISprout(t *testing.T) {
	tmpDir := t.TempDir()
	config.SproutPKI = filepath.Join(tmpDir, "sprout-pki/")

	SetupPKISprout()

	info, err := os.Stat(config.SproutPKI)
	if err != nil {
		t.Fatalf("expected sprout PKI directory to exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected sprout PKI path to be a directory")
	}

	// Idempotent.
	SetupPKISprout()
}

func TestRootCACached(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("imas cached", func(t *testing.T) {
		caFile := filepath.Join(tmpDir, "imas-rootca.pem")
		if err := os.WriteFile(caFile, []byte("cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		config.ImasRootCA = caFile
		if !RootCACached("imas") {
			t.Error("expected RootCACached to return true for imas")
		}
	})

	t.Run("sprout cached", func(t *testing.T) {
		caFile := filepath.Join(tmpDir, "sprout-rootca.pem")
		if err := os.WriteFile(caFile, []byte("cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		config.SproutRootCA = caFile
		if !RootCACached("sprout") {
			t.Error("expected RootCACached to return true for sprout")
		}
	})

	t.Run("imas not cached", func(t *testing.T) {
		config.ImasRootCA = filepath.Join(tmpDir, "nonexistent.pem")
		if RootCACached("imas") {
			t.Error("expected RootCACached to return false")
		}
	})
}

func TestCreateSproutID(t *testing.T) {
	id := createSproutID()
	if id == "" {
		t.Error("expected non-empty sprout ID")
	}
	// The ID should have no uppercase and no leading hyphen.
	if strings.ContainsAny(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("sprout ID should be lowercase, got %q", id)
	}
	if strings.HasPrefix(id, "-") {
		t.Errorf("sprout ID should not start with hyphen, got %q", id)
	}
}

func TestUnacceptNKey_MoveFromAccepted(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "revoke01", "NKEY_REVOKE")

	err := UnacceptNKey(currentTenantID(), "revoke01", "")
	if err != nil {
		t.Fatalf("UnacceptNKey failed: %v", err)
	}

	if got := keyState(t, "revoke01"); got != stateUnaccepted {
		t.Errorf("expected state %q, got %q", stateUnaccepted, got)
	}
}

func TestUnacceptNKey_AlreadyUnaccepted(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "unaccepted", "already01", "NKEY_ALREADY")

	err := UnacceptNKey(currentTenantID(), "already01", "")
	if !errors.Is(err, ErrAlreadyUnaccepted) {
		t.Errorf("expected ErrAlreadyUnaccepted, got: %v", err)
	}
}

func TestSetNATSServer(t *testing.T) {
	// SetNATSServer just assigns the package-level var.
	original := NatsServer
	defer func() { NatsServer = original }()

	SetNATSServer(nil)
	if NatsServer != nil {
		t.Error("expected NatsServer to be nil")
	}
}

func TestGetPubNKey_SproutKey(t *testing.T) {
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "sprout.pub")
	if err := os.WriteFile(pubFile, []byte("USPROUT_PUB_KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeySproutPubFile = pubFile

	key, err := GetPubNKey(SproutPubNKey)
	if err != nil {
		t.Fatalf("GetPubNKey(SproutPubNKey) failed: %v", err)
	}
	if key != "USPROUT_PUB_KEY" {
		t.Errorf("expected %q, got %q", "USPROUT_PUB_KEY", key)
	}
}

func TestGetPubNKey_FarmerKey(t *testing.T) {
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "farmer.pub")
	if err := os.WriteFile(pubFile, []byte("UFARMER_PUB_KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeyFarmerPubFile = pubFile

	key, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		t.Fatalf("GetPubNKey(FarmerPubNKey) failed: %v", err)
	}
	if key != "UFARMER_PUB_KEY" {
		t.Errorf("expected %q, got %q", "UFARMER_PUB_KEY", key)
	}
}

func TestGetPubNKey_MissingFile(t *testing.T) {
	config.NKeySproutPubFile = "/nonexistent/path/sprout.pub"

	_, err := GetPubNKey(SproutPubNKey)
	if err == nil {
		t.Error("expected error for missing pub key file")
	}
}

func TestGetPubNKey_CliKeyType(t *testing.T) {
	// CliPubNKey is not yet implemented — pubFile will be empty string,
	// which should fail with a file read error.
	_, err := GetPubNKey(CliPubNKey)
	if err == nil {
		t.Error("expected error for unimplemented CliPubNKey type")
	}
}

func TestGetSproutID_FromConfig(t *testing.T) {
	// When config.SproutID is set, GetSproutID should return it directly.
	config.SproutID = "preconfigured-sprout"
	defer func() { config.SproutID = "" }()

	id := GetSproutID()
	if id != "preconfigured-sprout" {
		t.Errorf("expected %q, got %q", "preconfigured-sprout", id)
	}
}

func TestGetSproutID_FallbackToHostname(t *testing.T) {
	// When config.SproutID is empty, it should fall back to hostname
	// and persist via SetSproutID (writes to jety, not config var).
	config.SproutID = ""

	id := GetSproutID()
	if id == "" {
		t.Error("expected non-empty sprout ID from hostname fallback")
	}
	// The returned ID should be a valid hostname-based string.
	if strings.HasPrefix(id, "-") {
		t.Errorf("sprout ID should not start with hyphen, got %q", id)
	}
}

func TestFetchRootCA_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "rootca.pem")
	if err := os.WriteFile(caFile, []byte("existing-cert"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should return nil (no error) because the file already exists.
	err := FetchRootCA(caFile)
	if err != nil {
		t.Errorf("expected nil error when CA already exists, got: %v", err)
	}

	// File should be unchanged.
	data, _ := os.ReadFile(caFile)
	if string(data) != "existing-cert" {
		t.Errorf("file should be unchanged, got %q", string(data))
	}
}

func TestFetchRootCA_FromServer(t *testing.T) {
	// Create a test HTTPS server that serves a fake cert.
	certPEM := generateSelfSignedCertPEM(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/cert/" {
			http.NotFound(w, r)
			return
		}
		w.Write(certPEM)
	}))
	defer ts.Close()

	// Parse test server address to get host:port.
	addr := ts.Listener.Addr().String()
	host, port, _ := strings.Cut(addr, ":")

	config.FarmerInterface = host
	config.FarmerAPIPort = port

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "fetched-rootca.pem")

	err := FetchRootCA(caFile)
	if err != nil {
		t.Fatalf("FetchRootCA failed: %v", err)
	}

	data, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("failed to read fetched CA: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty CA file")
	}
}

func TestFetchRootCA_ServerUnreachable(t *testing.T) {
	config.FarmerInterface = "127.0.0.1"
	config.FarmerAPIPort = "1" // port 1 should be unreachable

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "unreachable-rootca.pem")

	err := FetchRootCA(caFile)
	if err == nil {
		t.Error("expected error when server is unreachable")
	}

	// File should have been cleaned up.
	if _, statErr := os.Stat(caFile); !os.IsNotExist(statErr) {
		t.Error("expected CA file to be cleaned up on error")
	}
}

func TestLoadRootCA_ImasBinary(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a valid CA cert PEM.
	certPEM := generateSelfSignedCertPEM(t)
	caFile := filepath.Join(tmpDir, "imas-rootca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	config.ImasRootCA = caFile

	err := LoadRootCA("imas")
	if err != nil {
		t.Fatalf("LoadRootCA(imas) failed: %v", err)
	}

	// nkeyClient should be configured.
	if nkeyClient == nil {
		t.Error("expected nkeyClient to be non-nil after LoadRootCA")
	}
}

func TestLoadRootCA_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-rootca.pem")
	if err := os.WriteFile(caFile, []byte("not-a-valid-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.ImasRootCA = caFile

	err := LoadRootCA("imas")
	if !errors.Is(err, ErrCannotParseRootCA) {
		t.Errorf("expected ErrCannotParseRootCA, got: %v", err)
	}
}

func TestLoadRootCA_MissingFile(t *testing.T) {
	config.ImasRootCA = "/nonexistent/rootca.pem"

	err := LoadRootCA("imas")
	if err == nil {
		t.Error("expected error for missing root CA file")
	}
}

func TestPutNKey_Success(t *testing.T) {
	// Set up a sprout pub key file.
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "sprout.pub")
	if err := os.WriteFile(pubFile, []byte("UTEST_SPROUT_KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeySproutPubFile = pubFile

	// Set up a test HTTP server to receive the PUT request.
	var receivedSubmission KeySubmission
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/pki/putnkey" {
			t.Errorf("expected /pki/putnkey, got %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedSubmission); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	config.FarmerURL = ts.URL
	nkeyClient = ts.Client()

	err := PutNKey("test-sprout")
	if err != nil {
		t.Fatalf("PutNKey failed: %v", err)
	}

	if receivedSubmission.NKey != "UTEST_SPROUT_KEY" {
		t.Errorf("expected NKey %q, got %q", "UTEST_SPROUT_KEY", receivedSubmission.NKey)
	}
	if receivedSubmission.SproutID != "test-sprout" {
		t.Errorf("expected SproutID %q, got %q", "test-sprout", receivedSubmission.SproutID)
	}
}

func TestPutNKey_MissingPubKey(t *testing.T) {
	config.NKeySproutPubFile = "/nonexistent/sprout.pub"
	nkeyClient = &http.Client{}

	err := PutNKey("test-sprout")
	if err == nil {
		t.Error("expected error when sprout pub key file is missing")
	}
}

func TestPutNKey_ServerError(t *testing.T) {
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "sprout.pub")
	if err := os.WriteFile(pubFile, []byte("UTEST_KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeySproutPubFile = pubFile

	// Use a URL that won't connect.
	config.FarmerURL = "http://127.0.0.1:1"
	nkeyClient = &http.Client{Timeout: time.Millisecond * 100}

	err := PutNKey("test-sprout")
	if err == nil {
		t.Error("expected error when server is unreachable")
	}
}

func TestDenyNKey_InvalidID(t *testing.T) {
	setupTestPKI(t)

	err := DenyNKey(currentTenantID(), "-invalid")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestDenyNKey_NotFound(t *testing.T) {
	setupTestPKI(t)

	err := DenyNKey(currentTenantID(), "ghost")
	if !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
	}
}

func TestRejectNKey_InvalidID(t *testing.T) {
	setupTestPKI(t)

	err := RejectNKey(currentTenantID(), "-invalid", "")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestRejectNKey_NotFound(t *testing.T) {
	setupTestPKI(t)

	err := RejectNKey(currentTenantID(), "ghost", "")
	if !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
	}
}

func TestRootCACached_UnknownBinary(t *testing.T) {
	// Passing an unrecognized binary name should result in checking
	// an empty path, which should not exist.
	if RootCACached("unknown") {
		t.Error("expected false for unknown binary type")
	}
}

func TestAcceptNKey_WithSuffix(t *testing.T) {
	// When an ID contains "_<suffix>", AcceptNKey should strip the suffix
	// and also call DeleteNKey on the base ID.
	setupTestPKI(t)

	// Create the suffixed key.
	writeKey(t, "unaccepted", "web01_2", "NKEY_WEB01_2")

	err := AcceptNKey(currentTenantID(), "web01_2")
	if err != nil {
		t.Fatalf("AcceptNKey with suffix failed: %v", err)
	}

	// Should be accepted as "web01" (base name).
	key, err := GetNKey(currentTenantID(), "web01")
	if err != nil {
		t.Fatalf("expected key at base id: %v", err)
	}
	if key != "NKEY_WEB01_2" {
		t.Errorf("unexpected key content: %q", key)
	}
}

func TestNKeyExists_Mismatch(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "unreadable01", "SECRET")

	registered, matches := NKeyExists(currentTenantID(), "unreadable01", "WRONG")
	if !registered {
		t.Error("expected registered=true")
	}
	if matches {
		t.Error("expected matches=false for mismatched key")
	}
}

// generateSelfSignedCertPEM creates a self-signed certificate and returns
// its PEM encoding. Useful for tests that need valid certificate data.
func generateSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestFindNKeyRow_InvalidID(t *testing.T) {
	setupTestPKI(t)

	_, err := findNKeyRowInTenant(tenantID(), "-bad")
	if !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("expected ErrSproutIDInvalid, got: %v", err)
	}
}

func TestConfigureNats_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid certs.
	certPEM := generateSelfSignedCertPEM(t)
	caFile := filepath.Join(tmpDir, "rootca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Generate a leaf cert+key for CertFile/KeyFile.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// Self-sign the leaf for simplicity.
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &leafTemplate, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCertFile := filepath.Join(tmpDir, "cert.pem")
	leafKeyFile := filepath.Join(tmpDir, "key.pem")
	writePEM(t, leafCertFile, "CERTIFICATE", leafDER)
	leafPrivBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, leafKeyFile, "PRIVATE KEY", leafPrivBytes)

	config.FarmerInterface = "127.0.0.1"
	config.FarmerBusPort = "24222"
	config.RootCA = caFile
	config.CertFile = leafCertFile
	config.KeyFile = leafKeyFile

	opts := ConfigureNats()
	if opts.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", opts.Host)
	}
	if opts.Port != 24222 {
		t.Errorf("expected port 24222, got %d", opts.Port)
	}
	if opts.TLSConfig == nil {
		t.Error("expected TLSConfig to be set")
	}
	if !opts.TLS {
		t.Error("expected TLS to be true")
	}
}

func TestLoadRootCA_SproutBinary(t *testing.T) {
	tmpDir := t.TempDir()

	// For sprout binary, LoadRootCA calls FetchRootCA first.
	// We need a valid CA cert file at SproutRootCA.
	certPEM := generateSelfSignedCertPEM(t)
	caFile := filepath.Join(tmpDir, "sprout-rootca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	config.SproutRootCA = caFile

	err := LoadRootCA("sprout")
	if err != nil {
		t.Fatalf("LoadRootCA(sprout) failed: %v", err)
	}
	if nkeyClient == nil {
		t.Error("expected nkeyClient to be non-nil")
	}
}

func TestReloadNKeys_WithAcceptedSprouts(t *testing.T) {
	setupTestPKI(t)

	// Add some accepted sprouts with valid-looking NKeys.
	writeKey(t, "accepted", "web01", "UABC123")
	writeKey(t, "accepted", "db01", "UDEF456")

	// ReloadNKeys should not error when NatsServer is nil (skips reload).
	err := ReloadNKeys()
	// err may be nil (no server to reload) — that's fine.
	_ = err
	// The important thing is it doesn't panic or fatal.
}

// Verify that the full key lifecycle works: unaccept → accept → reject → unaccept.
func TestKeyLifecycle_FullCycle(t *testing.T) {
	setupTestPKI(t)

	// 1. Register as unaccepted.
	err := UnacceptNKey(currentTenantID(), "lifecycle01", "NKEY_LIFE")
	if err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}

	// 2. Accept.
	err = AcceptNKey(currentTenantID(), "lifecycle01")
	if err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}
	if got := keyState(t, "lifecycle01"); got != stateAccepted {
		t.Fatalf("expected state %q, got %q", stateAccepted, got)
	}

	// 3. Reject.
	err = RejectNKey(currentTenantID(), "lifecycle01", "")
	if err != nil {
		t.Fatalf("RejectNKey: %v", err)
	}
	if got := keyState(t, "lifecycle01"); got != stateRejected {
		t.Fatalf("expected state %q, got %q", stateRejected, got)
	}

	// 4. Unaccept again.
	err = UnacceptNKey(currentTenantID(), "lifecycle01", "")
	if err != nil {
		t.Fatalf("UnacceptNKey (from rejected): %v", err)
	}
	if got := keyState(t, "lifecycle01"); got != stateUnaccepted {
		t.Fatalf("expected state %q, got %q", stateUnaccepted, got)
	}

	// 5. Delete.
	err = DeleteNKey(currentTenantID(), "lifecycle01")
	if err != nil {
		t.Fatalf("DeleteNKey: %v", err)
	}
	if _, err := GetNKey(currentTenantID(), "lifecycle01"); !errors.Is(err, ErrSproutIDNotFound) {
		t.Error("expected key removed after delete")
	}
}

func TestSproutIDForNKey(t *testing.T) {
	setupTestPKI(t)

	writeKey(t, "accepted", "web01", "UABC123")
	writeKey(t, "unaccepted", "web02", "UDEF456")

	t.Run("accepted sprout resolves", func(t *testing.T) {
		id, err := SproutIDForNKey(currentTenantID(), "UABC123")
		if err != nil {
			t.Fatalf("SproutIDForNKey failed: %v", err)
		}
		if id != "web01" {
			t.Errorf("expected 'web01', got %q", id)
		}
	})

	t.Run("unaccepted sprout does not resolve", func(t *testing.T) {
		_, err := SproutIDForNKey(currentTenantID(), "UDEF456")
		if !errors.Is(err, ErrSproutIDNotFound) {
			t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
		}
	})

	t.Run("unknown key does not resolve", func(t *testing.T) {
		_, err := SproutIDForNKey(currentTenantID(), "UNKNOWN")
		if !errors.Is(err, ErrSproutIDNotFound) {
			t.Errorf("expected ErrSproutIDNotFound, got: %v", err)
		}
	})
}

// Suppress unused import warnings.
var _ = fmt.Sprintf

func TestNormalizeSproutID(t *testing.T) {
	for in, want := range map[string]string{
		"web01":                    "web01",
		"Web01.Example.COM":        "web01-example-com",
		"web01.example.com.":       "web01-example-com",
		"ip-10-0-0-5.ec2.internal": "ip-10-0-0-5-ec2-internal",
		"_web_01":                  "web-01",
		"--web":                    "web",
		"192.168.1.1":              "192-168-1-1",
		"announce":                 "announce", // still refused by IsValidSproutID
	} {
		if got := NormalizeSproutID(in); got != want {
			t.Errorf("NormalizeSproutID(%q) = %q, want %q", in, got, want)
		}
	}
	// Whatever a hostname looks like, the result never contains a dot.
	if got := NormalizeSproutID("a.b.c"); !IsValidSproutID(got) {
		t.Errorf("NormalizeSproutID(a.b.c) = %q is not a valid ID", got)
	}
}
