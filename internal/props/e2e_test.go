package props

import (
	"testing"
	"time"
)

// TestGetPropsExported verifies the exported GetProps wrapper calls through
// to the internal getProps correctly.
func TestGetPropsExported(t *testing.T) {
	newTestDB(t)

	// No sprout → nil.
	if got := GetProps("nonexistent"); got != nil {
		t.Errorf("expected nil for nonexistent sprout, got %v", got)
	}

	// Set props and verify.
	SetProp("exported-test", "k1", "v1")
	SetProp("exported-test", "k2", "v2")

	got := GetProps("exported-test")
	if len(got) != 2 {
		t.Fatalf("expected 2 props, got %d", len(got))
	}
	if got["k1"] != "v1" {
		t.Errorf("expected k1=v1, got %v", got["k1"])
	}
	if got["k2"] != "v2" {
		t.Errorf("expected k2=v2, got %v", got["k2"])
	}
}

// TestGetPropsExportedWithExpiredEntries confirms expired props are
// excluded from the exported GetProps.
func TestGetPropsExportedWithExpiredEntries(t *testing.T) {
	newTestDB(t)

	// Short TTL prop.
	setPropWithTTL(tenantID(), "exp-sprout", "temp", "gone", 1*time.Millisecond)
	// Long TTL prop.
	SetProp("exp-sprout", "stable", "here")

	time.Sleep(5 * time.Millisecond)

	got := GetProps("exp-sprout")
	if len(got) != 1 {
		t.Fatalf("expected 1 prop after expiry, got %d: %v", len(got), got)
	}
	if got["stable"] != "here" {
		t.Errorf("expected stable=here, got %v", got["stable"])
	}
}
