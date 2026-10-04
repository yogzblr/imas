package props

import (
	"testing"
	"time"
)

func TestSetPropForTenantWithTTL(t *testing.T) {
	gdb := newTestDB(t)
	before := time.Now()
	if err := SetPropForTenantWithTTL("t_ttl", "web-01", "hostname", "web", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	var row propRow
	if err := gdb.Where("tenant_id = ? AND sprout_id = ? AND name = ?", "t_ttl", "web-01", "hostname").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if exp := row.Expiry.Sub(before); exp < 10*time.Minute-time.Second || exp > 10*time.Minute+5*time.Second {
		t.Errorf("expiry is %v after the write, want 10m", exp)
	}
	if GetStringPropForTenant("t_ttl", "web-01", "hostname") != "web" {
		t.Error("prop not readable")
	}
	if err := SetPropForTenantWithTTL("t_ttl", "web-01", "gone", "x", -time.Second); err != nil {
		t.Fatal(err)
	}
	if GetStringPropForTenant("t_ttl", "web-01", "gone") != "" {
		t.Error("expired prop readable")
	}
	if err := SetPropForTenantWithTTL("t_ttl", "", "x", "x", time.Minute); err != ErrInvalidPropKey {
		t.Errorf("empty sprout ID: got %v", err)
	}
}
