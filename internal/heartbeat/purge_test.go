package heartbeat

import (
	"context"
	"testing"
)

// PurgeTenant deletes one tenant's presence keys and acceptance markers
// and nothing of another tenant's, even for the same sprout ID.
func TestPurgeTenant(t *testing.T) {
	mr := newTestValkey(t)
	for _, tenant := range []string{"t_a", "t_b", "t_ab"} {
		mr.Set(keyFor(tenant, "web-01"), "1")
		mr.Set(acceptedKeyFor(tenant, "web-01"), "1")
	}
	mr.Set(keyFor("t_a", "db-01"), "1")
	counts, err := PurgeTenant(context.Background(), "t_a", 1)
	if err != nil || counts["valkey.heartbeat"] != 2 || counts["valkey.accepted"] != 1 {
		t.Fatalf("PurgeTenant = %v, %v", counts, err)
	}
	for _, tenant := range []string{"t_b", "t_ab"} {
		if !mr.Exists(keyFor(tenant, "web-01")) || !mr.Exists(acceptedKeyFor(tenant, "web-01")) {
			t.Errorf("%s's keys were deleted", tenant)
		}
	}
	if mr.Exists(keyFor("t_a", "web-01")) || mr.Exists(acceptedKeyFor("t_a", "web-01")) || mr.Exists(keyFor("t_a", "db-01")) {
		t.Error("t_a's keys are still there")
	}
	if counts, err := PurgeTenant(context.Background(), "t_a", 1); err != nil || counts["valkey.heartbeat"]+counts["valkey.accepted"] != 0 {
		t.Errorf("second PurgeTenant = %v, %v", counts, err)
	}
	if _, err := PurgeTenant(context.Background(), "t_a:*", 1); err == nil {
		t.Error("an invalid tenant ID was accepted")
	}
	SetClient(nil)
	if _, err := PurgeTenant(context.Background(), "t_a", 1); err == nil {
		t.Error("no client: want an error")
	}
}
