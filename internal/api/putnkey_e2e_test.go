package api

import (
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

// TestPutNKeyClientProvesPossession: the sprout's pki.PutNKey, against
// the router with enrolment off, fetches a nonce, signs it with its NKey
// seed and is stored as unaccepted (security review 2026-10, L12).
func TestPutNKeyClientProvesPossession(t *testing.T) {
	useRealGatewaySubjectCheck(t) // a pki database
	config.EnrollmentDisabled = true
	t.Cleanup(func() { config.EnrollmentDisabled = false })
	srv := httptest.NewTLSServer(NewRouter(""))
	defer srv.Close()

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	// Storing the key reloads the legacy tenant's Account, which needs
	// farmer's public NKey.
	farmerKP, _ := nkeys.CreateUser()
	farmerPub, _ := farmerKP.PublicKey()
	farmerPubFile := filepath.Join(dir, "farmer.pub")
	if err := os.WriteFile(farmerPubFile, []byte(farmerPub), 0o644); err != nil {
		t.Fatal(err)
	}
	kp, _ := nkeys.CreateUser()
	seed, _ := kp.Seed()
	pub, _ := kp.PublicKey()
	seedFile := filepath.Join(dir, "sprout.nk")
	if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		p   *string
		val string
	}{{&config.SproutRootCA, ca}, {&config.FarmerURL, srv.URL}, {&config.NKeySproutPrivFile, seedFile}, {&config.NKeyFarmerPubFile, farmerPubFile}, {&config.NKeyFarmerPrivFile, ""}} {
		old := *v.p
		*v.p = v.val
		t.Cleanup(func() { *v.p = old })
	}
	oldTOFU := config.SproutRootCATOFU
	config.SproutRootCATOFU = false
	t.Cleanup(func() { config.SproutRootCATOFU = oldTOFU })
	if err := pki.LoadRootCA("sprout"); err != nil {
		t.Fatal(err)
	}

	if err := pki.PutNKey("web-01"); err != nil {
		t.Fatalf("PutNKey: %v", err)
	}
	got, err := pki.GetNKey(pki.CurrentTenantID(), "web-01")
	if err != nil || got != pub {
		t.Fatalf("stored NKey %q (%v), want %s", got, err, pub)
	}
}
