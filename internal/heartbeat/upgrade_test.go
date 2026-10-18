package heartbeat

import (
	"context"
	"testing"
)

// The marker is set, read and cleared per (tenant, sprout), expires, and
// is purged with its tenant.
func TestUpgradeMarker(t *testing.T) {
	mr := newTestValkey(t)
	ctx := context.Background()
	if got := upgradeKeyFor("t_a", "web-01"); got != "imas:upgrade:{t_a:web-01}" {
		t.Fatalf("key %q", got)
	}
	MarkUpgradeRequired("t_a", "web-01", UpgradeKindFacts)
	if got := UpgradeRequired(ctx, "t_a", "web-01"); got != UpgradeKindFacts {
		t.Fatalf("UpgradeRequired = %q", got)
	}
	if got := UpgradeRequired(ctx, "t_b", "web-01"); got != "" {
		t.Fatalf("another tenant's sprout of the same ID is marked: %q", got)
	}
	if got := mr.TTL(upgradeKeyFor("t_a", "web-01")); got != UpgradeMarkerTTL {
		t.Fatalf("TTL %s", got)
	}
	MarkUpgradeRequired("t_a", "web-01", UpgradeKindCookStep)
	if got := UpgradeRequired(ctx, "t_a", "web-01"); got != UpgradeKindCookStep {
		t.Fatalf("UpgradeRequired = %q", got)
	}
	ClearUpgradeRequired("t_a", "web-01")
	if got := UpgradeRequired(ctx, "t_a", "web-01"); got != "" {
		t.Fatalf("cleared marker reads %q", got)
	}
	MarkUpgradeRequired("t_a", "web-02", UpgradeKindFacts)
	mr.FastForward(UpgradeMarkerTTL)
	if got := UpgradeRequired(ctx, "t_a", "web-02"); got != "" {
		t.Fatalf("expired marker reads %q", got)
	}
	MarkUpgradeRequired("t_a", "web-03", UpgradeKindFacts)
	MarkUpgradeRequired("t_b", "web-03", UpgradeKindFacts)
	counts, err := PurgeTenant(ctx, "t_a", 10)
	if err != nil || counts["valkey.upgrade"] != 1 {
		t.Fatalf("PurgeTenant = %v, %v", counts, err)
	}
	if UpgradeRequired(ctx, "t_b", "web-03") == "" {
		t.Fatal("purging t_a removed t_b's marker")
	}
}

// Without Valkey the marker is a no-op, never an error.
func TestUpgradeMarkerNoClient(t *testing.T) {
	SetClient(nil)
	MarkUpgradeRequired("t_a", "web-01", UpgradeKindFacts)
	ClearUpgradeRequired("t_a", "web-01")
	if got := UpgradeRequired(context.Background(), "t_a", "web-01"); got != "" {
		t.Fatalf("got %q", got)
	}
}
