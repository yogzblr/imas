package pki

// End-to-end coverage for docs/design/imas-tenant-context-threading.md's
// Option A: this is the "actual gap" test the design doc calls for —
// provisioning two distinct tenants, establishing farmer's own dedicated
// connection into each one's Account (exactly the shape
// cmd/farmer/main.go's dialTenantBus/ConnectFarmer produces: one farmer
// NKey identity, a distinct per-tenant User JWT for each connection), and
// proving a message published under tenant B's sprout is received ONLY by
// farmer's tenant-B connection and never reaches farmer's tenant-A
// connection — real transport-level isolation, not just parameterized
// functions proven correct in isolation (that part is covered by
// tenant_integration_test.go and this package's other unit tests already).
//
// TestFarmerQueueGroupLoadBalancing_IsolatedPerTenant below is the second
// half of the design doc's testing requirement (point 6): verifying that
// workstream D's QueueSubscribe fix (natsCoreQueueGroup = "imas-core" in
// internal/natsapi/router.go and internal/facts/listener.go) still
// correctly load-balances across N farmer replicas per tenant connection,
// with no cross-tenant interference, now that there is more than one
// tenant connection for it to run on at all.

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// setupRealFarmerIdentity is useRealFarmerKey, but keeps the private seed
// around too (useRealFarmerKey only ever needed the public half, since
// minting a User JWT for a pubkey doesn't require its private key — see
// syncNatsAuth/syncTenantSprouts). Actually connecting as farmer, which
// this test does for two different tenant Accounts at once, needs the
// seed.
func setupRealFarmerIdentity(t *testing.T) []byte {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create farmer NKey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("failed to get farmer public key: %v", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatalf("failed to get farmer seed: %v", err)
	}
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(pub), 0o600); err != nil {
		t.Fatalf("failed to write farmer public key: %v", err)
	}
	return seed
}

// TestFarmerPerTenantConnections_TransportIsolation is the test
// docs/design/imas-tenant-context-threading.md's own testing requirement
// asks for: it provisions two tenants (t_a, t_b), opens one farmer
// connection into each — using pki.FarmerUserJWTForTenant, the exact JWT
// cmd/farmer/main.go's dialTenantBus reads to authenticate each per-tenant
// connection — subscribes each to the same sprout-facing subject pattern
// (imas.sprouts.*.facts, what internal/facts.RegisterFarmerListener
// actually subscribes every tenant connection to), then dials as a sprout
// enrolled under tenant B's Account and publishes. Only farmer's tenant-B
// connection may ever see that message; farmer's tenant-A connection must
// not, no matter how long it waits — that absence is the entire point of
// Option A's Account-per-tenant design.
func TestFarmerPerTenantConnections_TransportIsolation(t *testing.T) {
	setupTestPKI(t)
	farmerSeed := setupRealFarmerIdentity(t)
	defer startTestBus(t)()

	const tenantA = "t_a"
	const tenantB = "t_b"

	if err := ProvisionTenant(tenantA, "Tenant A"); err != nil {
		t.Fatalf("ProvisionTenant(%s): %v", tenantA, err)
	}
	if err := ProvisionTenant(tenantB, "Tenant B"); err != nil {
		t.Fatalf("ProvisionTenant(%s): %v", tenantB, err)
	}

	// Open farmer's own dedicated connection into each tenant's Account —
	// same NKey identity (farmerSeed), a distinct User JWT per tenant. This
	// mirrors cmd/farmer/main.go's dialTenantBus exactly (down to reusing
	// dialAsSprout, which is generic over which JWT/seed pair it dials
	// with, despite its name).
	farmerJWTA, err := FarmerUserJWTForTenant(tenantA)
	if err != nil {
		t.Fatalf("FarmerUserJWTForTenant(%s): %v", tenantA, err)
	}
	farmerJWTB, err := FarmerUserJWTForTenant(tenantB)
	if err != nil {
		t.Fatalf("FarmerUserJWTForTenant(%s): %v", tenantB, err)
	}
	if farmerJWTA == farmerJWTB {
		t.Fatal("expected distinct farmer User JWTs for tenant A and tenant B")
	}

	ncFarmerA, err := dialAsSprout(t, farmerJWTA, farmerSeed)
	if err != nil {
		t.Fatalf("farmer connecting under tenant A's Account: %v", err)
	}
	defer ncFarmerA.Close()
	ncFarmerB, err := dialAsSprout(t, farmerJWTB, farmerSeed)
	if err != nil {
		t.Fatalf("farmer connecting under tenant B's Account: %v", err)
	}
	defer ncFarmerB.Close()

	// Every tenant connection subscribes to the same sprout-facing subject
	// pattern — internal/facts.RegisterFarmerListener's own subject,
	// registered once per tenant connection per
	// docs/design/imas-tenant-context-threading.md's Option A.
	receivedA := make(chan *nats.Msg, 4)
	receivedB := make(chan *nats.Msg, 4)
	if _, err := ncFarmerA.Subscribe("imas.sprouts.*.facts", func(m *nats.Msg) { receivedA <- m }); err != nil {
		t.Fatalf("subscribing on tenant A's connection: %v", err)
	}
	if _, err := ncFarmerB.Subscribe("imas.sprouts.*.facts", func(m *nats.Msg) { receivedB <- m }); err != nil {
		t.Fatalf("subscribing on tenant B's connection: %v", err)
	}
	ncFarmerA.Flush()
	ncFarmerB.Flush()

	// Enroll a sprout under tenant B only, then dial as it and publish a
	// facts event — the literal scenario docs/design/
	// imas-tenant-context-threading.md's Phase 1 finding says was
	// structurally unreachable before this PR: "a sprout enrolled under
	// tenant B's dynamically provisioned Account can authenticate to the
	// bus, but every message it publishes ... lands in an Account
	// namespace that farmer's single connection ... structurally cannot
	// see."
	sproutKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("creating sprout NKey: %v", err)
	}
	sproutPub, err := sproutKP.PublicKey()
	if err != nil {
		t.Fatalf("sprout public key: %v", err)
	}
	sproutSeed, err := sproutKP.Seed()
	if err != nil {
		t.Fatalf("sprout seed: %v", err)
	}
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantB, SproutID: "web-01", NKey: sproutPub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant(tenantB); err != nil {
		t.Fatalf("ReloadNKeysForTenant(%s): %v", tenantB, err)
	}
	sproutJWT, err := GetSproutUserJWTForTenant(tenantB, "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}
	ncSprout, err := dialAsSprout(t, sproutJWT, sproutSeed)
	if err != nil {
		t.Fatalf("tenant B's sprout failed to connect: %v", err)
	}
	defer ncSprout.Close()

	payload, _ := json.Marshal(map[string]string{"os": "linux", "sprout": "web-01"})
	if err := ncSprout.Publish("imas.sprouts.web-01.facts", payload); err != nil {
		t.Fatalf("publishing facts from tenant B's sprout: %v", err)
	}
	ncSprout.Flush()

	// Tenant B's connection must receive it.
	select {
	case msg := <-receivedB:
		if string(msg.Data) != string(payload) {
			t.Errorf("tenant B received wrong payload: got %q, want %q", msg.Data, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tenant B's farmer connection never received the sprout's facts event")
	}

	// Tenant A's connection must never receive it — this is the assertion
	// that actually proves Account-level isolation, not just that tenant
	// B's own path works. A fixed wait is unavoidable to prove a negative;
	// it only needs to be long enough that a leaking message would have
	// arrived.
	select {
	case msg := <-receivedA:
		t.Fatalf("tenant A's farmer connection received a message published under tenant B's Account: %q", msg.Data)
	case <-time.After(500 * time.Millisecond):
		// Expected: nothing crossed the Account boundary.
	}
}

// natsCoreQueueGroupForTest mirrors internal/natsapi/router.go's and
// internal/facts/listener.go's own natsCoreQueueGroup constant — this
// package can't import natsapi (natsapi already imports pki), so the value
// is duplicated here the same way internal/facts's own copy is (see that
// file's doc comment on the same duplication).
const natsCoreQueueGroupForTest = "imas-core"

// TestFarmerQueueGroupLoadBalancing_IsolatedPerTenant provisions two
// tenants, opens two farmer "replica" connections per tenant (four
// connections total) all queue-subscribed under the shared "imas-core"
// group on the same subject pattern — exactly the shape N farmer replicas
// produce in production, once per tenant connection. It publishes several
// messages from each tenant's own sprout and asserts two properties at
// once: within a tenant, its two replica connections split the load (queue
// semantics still work); and across tenants, a connection never receives
// so much as one message published under the other tenant's Account (NATS
// Accounts are fully separate subject namespaces, so a queue group name
// being shared across two Accounts is just two unrelated queue groups that
// happen to share a string — this proves that isn't an assumption worth
// leaving untested, per the design doc's own "should work given the
// design is exactly the kind of assumption this whole effort exists to
// verify rather than trust").
func TestFarmerQueueGroupLoadBalancing_IsolatedPerTenant(t *testing.T) {
	setupTestPKI(t)
	farmerSeed := setupRealFarmerIdentity(t)
	defer startTestBus(t)()

	const tenantA = "t_qa"
	const tenantB = "t_qb"
	if err := ProvisionTenant(tenantA, "Tenant QA"); err != nil {
		t.Fatalf("ProvisionTenant(%s): %v", tenantA, err)
	}
	if err := ProvisionTenant(tenantB, "Tenant QB"); err != nil {
		t.Fatalf("ProvisionTenant(%s): %v", tenantB, err)
	}

	// connectReplicas opens n farmer connections under tenantID's Account,
	// each queue-subscribed to subject under the shared "imas-core" group,
	// delivering every received message onto a per-connection channel.
	connectReplicas := func(tenantID string, n int) ([]*nats.Conn, []chan *nats.Msg) {
		jwt, err := FarmerUserJWTForTenant(tenantID)
		if err != nil {
			t.Fatalf("FarmerUserJWTForTenant(%s): %v", tenantID, err)
		}
		conns := make([]*nats.Conn, n)
		chans := make([]chan *nats.Msg, n)
		for i := 0; i < n; i++ {
			nc, err := dialAsSprout(t, jwt, farmerSeed)
			if err != nil {
				t.Fatalf("connecting replica %d for tenant %s: %v", i, tenantID, err)
			}
			t.Cleanup(func() { nc.Close() })
			ch := make(chan *nats.Msg, 32)
			if _, err := nc.QueueSubscribe("imas.sprouts.*.facts", natsCoreQueueGroupForTest, func(m *nats.Msg) {
				ch <- m
			}); err != nil {
				t.Fatalf("queue-subscribing replica %d for tenant %s: %v", i, tenantID, err)
			}
			nc.Flush()
			conns[i] = nc
			chans[i] = ch
		}
		return conns, chans
	}

	_, replicasA := connectReplicas(tenantA, 2)
	_, replicasB := connectReplicas(tenantB, 2)

	// dialTenantSprout enrolls sproutID under tenantID and dials as it.
	dialTenantSprout := func(tenantID, sproutID string) *nats.Conn {
		sproutKP, err := nkeys.CreateUser()
		if err != nil {
			t.Fatalf("creating sprout NKey: %v", err)
		}
		sproutPub, err := sproutKP.PublicKey()
		if err != nil {
			t.Fatalf("sprout public key: %v", err)
		}
		sproutSeed, err := sproutKP.Seed()
		if err != nil {
			t.Fatalf("sprout seed: %v", err)
		}
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: sproutPub, State: stateAccepted}); err != nil {
			t.Fatalf("upsertNKeyRow: %v", err)
		}
		if err := ReloadNKeysForTenant(tenantID); err != nil {
			t.Fatalf("ReloadNKeysForTenant(%s): %v", tenantID, err)
		}
		sproutJWT, err := GetSproutUserJWTForTenant(tenantID, sproutID)
		if err != nil {
			t.Fatalf("GetSproutUserJWTForTenant: %v", err)
		}
		nc, err := dialAsSprout(t, sproutJWT, sproutSeed)
		if err != nil {
			t.Fatalf("sprout %s (tenant %s) failed to connect: %v", sproutID, tenantID, err)
		}
		t.Cleanup(func() { nc.Close() })
		return nc
	}

	sproutA := dialTenantSprout(tenantA, "sprout-qa")
	sproutB := dialTenantSprout(tenantB, "sprout-qb")

	const messagesPerTenant = 20
	for i := 0; i < messagesPerTenant; i++ {
		if err := sproutA.Publish("imas.sprouts.sprout-qa.facts", []byte("a")); err != nil {
			t.Fatalf("publishing from tenant A's sprout: %v", err)
		}
		if err := sproutB.Publish("imas.sprouts.sprout-qb.facts", []byte("b")); err != nil {
			t.Fatalf("publishing from tenant B's sprout: %v", err)
		}
	}
	sproutA.Flush()
	sproutB.Flush()

	drain := func(ch chan *nats.Msg) (count int, payloads map[string]int) {
		payloads = map[string]int{}
		for {
			select {
			case m := <-ch:
				count++
				payloads[string(m.Data)]++
			case <-time.After(500 * time.Millisecond):
				return
			}
		}
	}

	countA0, payloadsA0 := drain(replicasA[0])
	countA1, payloadsA1 := drain(replicasA[1])
	countB0, payloadsB0 := drain(replicasB[0])
	countB1, payloadsB1 := drain(replicasB[1])

	// Cross-tenant interference: neither of tenant A's replicas may ever
	// see tenant B's payload, and vice versa.
	for _, payloads := range []map[string]int{payloadsA0, payloadsA1} {
		if payloads["b"] != 0 {
			t.Errorf("tenant A replica received %d of tenant B's messages", payloads["b"])
		}
	}
	for _, payloads := range []map[string]int{payloadsB0, payloadsB1} {
		if payloads["a"] != 0 {
			t.Errorf("tenant B replica received %d of tenant A's messages", payloads["a"])
		}
	}

	// Queue semantics preserved: tenant A's two replicas together receive
	// every message exactly once, and (with 20 messages across 2 replicas)
	// neither replica should receive all of them.
	if totalA := countA0 + countA1; totalA != messagesPerTenant {
		t.Errorf("tenant A replicas received %d messages total, want %d", totalA, messagesPerTenant)
	}
	if countA0 == messagesPerTenant || countA1 == messagesPerTenant {
		t.Error("tenant A's messages were not load-balanced across its two replicas (one received all of them)")
	}
	if totalB := countB0 + countB1; totalB != messagesPerTenant {
		t.Errorf("tenant B replicas received %d messages total, want %d", totalB, messagesPerTenant)
	}
	if countB0 == messagesPerTenant || countB1 == messagesPerTenant {
		t.Error("tenant B's messages were not load-balanced across its two replicas (one received all of them)")
	}
}
