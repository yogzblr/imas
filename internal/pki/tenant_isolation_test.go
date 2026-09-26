package pki

// Concurrent two-tenant coverage for the PKI accept/deny call sites
// workstream E's follow-up threads real tenant identity through (see
// docs/design/imas-tenant-context-threading.md). PR #28 fixed this same
// bug class once already for a different call site; asserting against a
// single tenant twice would make a regression back to the process-global
// tenantID() seam invisible to tests the same way it was before that fix.
// These tests instead run two distinct tenants' Accept/Deny calls
// genuinely concurrently, against sprouts sharing the same sprout ID and
// NKey pubkey (a real scenario — two tenants' own sprouts are named and
// keyed independently of each other), and assert each tenant only ever
// sees its own state.

import (
	"sync"
	"testing"
)

// TestAcceptNKey_TwoTenantsConcurrently_DoNotCrossContaminate runs
// AcceptNKey for two different tenants, both accepting a sprout with the
// same ID and NKey, concurrently, and proves each tenant's accepted state
// is scoped to itself.
func TestAcceptNKey_TwoTenantsConcurrently_DoNotCrossContaminate(t *testing.T) {
	setupTestPKI(t)

	const sproutID = "web-01"
	const nkey = "UPUBSHARED"
	if err := UnacceptNKey("t_a", sproutID, nkey); err != nil {
		t.Fatalf("UnacceptNKey(t_a): %v", err)
	}
	if err := UnacceptNKey("t_b", sproutID, nkey); err != nil {
		t.Fatalf("UnacceptNKey(t_b): %v", err)
	}

	var wg sync.WaitGroup
	errsA := make(chan error, 1)
	errsB := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errsA <- AcceptNKey("t_a", sproutID)
	}()
	go func() {
		defer wg.Done()
		errsB <- AcceptNKey("t_b", sproutID)
	}()
	wg.Wait()
	close(errsA)
	close(errsB)
	if err := <-errsA; err != nil {
		t.Fatalf("AcceptNKey(t_a): %v", err)
	}
	if err := <-errsB; err != nil {
		t.Fatalf("AcceptNKey(t_b): %v", err)
	}

	rowA, err := findNKeyRowInTenant("t_a", sproutID)
	if err != nil {
		t.Fatalf("findNKeyRowInTenant(t_a): %v", err)
	}
	if rowA.State != stateAccepted {
		t.Errorf("t_a sprout state = %q, want %q", rowA.State, stateAccepted)
	}
	rowB, err := findNKeyRowInTenant("t_b", sproutID)
	if err != nil {
		t.Fatalf("findNKeyRowInTenant(t_b): %v", err)
	}
	if rowB.State != stateAccepted {
		t.Errorf("t_b sprout state = %q, want %q", rowB.State, stateAccepted)
	}

	// Deny t_a's sprout only; t_b's own identically-ID'd/keyed sprout must
	// stay accepted — this is the actual isolation property at risk.
	if err := DenyNKey("t_a", sproutID); err != nil {
		t.Fatalf("DenyNKey(t_a): %v", err)
	}
	rowA2, err := findNKeyRowInTenant("t_a", sproutID)
	if err != nil {
		t.Fatalf("findNKeyRowInTenant(t_a) after deny: %v", err)
	}
	if rowA2.State != stateDenied {
		t.Errorf("t_a sprout state after deny = %q, want %q", rowA2.State, stateDenied)
	}
	rowB2, err := findNKeyRowInTenant("t_b", sproutID)
	if err != nil {
		t.Fatalf("findNKeyRowInTenant(t_b) after t_a's deny: %v", err)
	}
	if rowB2.State != stateAccepted {
		t.Errorf("t_b sprout state after t_a's deny = %q, want unaffected %q", rowB2.State, stateAccepted)
	}
}

// TestDenyRejectUnaccept_TwoTenantsConcurrently exercises Deny/Reject
// concurrently across two tenants sharing a sprout ID, proving the
// resulting lifecycle states never leak across tenants.
func TestDenyRejectUnaccept_TwoTenantsConcurrently(t *testing.T) {
	setupTestPKI(t)

	const sproutID = "app-01"
	if err := UnacceptNKey("t_c", sproutID, "UPUBC"); err != nil {
		t.Fatalf("UnacceptNKey(t_c): %v", err)
	}
	if err := UnacceptNKey("t_d", sproutID, "UPUBD"); err != nil {
		t.Fatalf("UnacceptNKey(t_d): %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := DenyNKey("t_c", sproutID); err != nil {
			t.Errorf("DenyNKey(t_c): %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := RejectNKey("t_d", sproutID, ""); err != nil {
			t.Errorf("RejectNKey(t_d): %v", err)
		}
	}()
	wg.Wait()

	rowC, err := findNKeyRowInTenant("t_c", sproutID)
	if err != nil {
		t.Fatalf("findNKeyRowInTenant(t_c): %v", err)
	}
	if rowC.State != stateDenied {
		t.Errorf("t_c sprout state = %q, want %q", rowC.State, stateDenied)
	}
	if rowC.NKey != "UPUBC" {
		t.Errorf("t_c sprout NKey = %q, want %q (not t_d's)", rowC.NKey, "UPUBC")
	}

	rowD, err := findNKeyRowInTenant("t_d", sproutID)
	if err != nil {
		t.Fatalf("findNKeyRowInTenant(t_d): %v", err)
	}
	if rowD.State != stateRejected {
		t.Errorf("t_d sprout state = %q, want %q", rowD.State, stateRejected)
	}
	if rowD.NKey != "UPUBD" {
		t.Errorf("t_d sprout NKey = %q, want %q (not t_c's)", rowD.NKey, "UPUBD")
	}
}
