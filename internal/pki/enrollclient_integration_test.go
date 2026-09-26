package pki

// Live-bus proof that what the enrollment client persists is what a
// sprout can connect with: the persisted NATS User JWT plus the NKey seed
// file (nats.UserJWTAndSeed, as cmd/sprout's ConnectSprout now uses)
// authenticates against a real operator-mode nats-server, and the seed
// alone (nats.NkeyOptionFromSeed, what ConnectSprout used before) does
// not.

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
)

func TestEnrollClient_PersistedCredentialsConnectToBus(t *testing.T) {
	store, _ := setupEnrollTest(t)
	useRealFarmerKey(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	defer startTestBus(t)()
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 1,
	}
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := EnrollSprout(t.Context(), "ek_1.supersecret", "web-01", sproutPub)
	if err != nil {
		t.Fatalf("EnrollSprout: %v", err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}

	userJWT, err := LoadSproutUserJWT()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := dialAsSprout(t, userJWT, []byte(strings.TrimSpace(string(seed))))
	if err != nil {
		t.Fatalf("persisted User JWT + seed should connect: %v", err)
	}
	nc.Close()

	// The previous ConnectSprout auth: NKey seed only, no User JWT.
	rootPEM, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	seedOnly, err := nats.NkeyOptionFromSeed(config.NKeySproutPrivFile)
	if err != nil {
		t.Fatal(err)
	}
	if nc, err := nats.Connect(config.FarmerBusURL,
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		seedOnly, nats.Timeout(5*time.Second), nats.NoReconnect(),
	); err == nil {
		nc.Close()
		t.Fatal("NKey seed alone should be refused by the operator-mode bus")
	}
}
