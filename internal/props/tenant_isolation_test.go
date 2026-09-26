package props

// Concurrent two-tenant coverage for the ForTenant call sites workstream
// E's follow-up threads real tenant identity through (see
// docs/design/imas-tenant-context-threading.md). Runs two distinct
// tenants' Get/Set calls genuinely concurrently, against the same
// sprout ID and property name (a real scenario — two tenants' sprouts are
// named independently of each other), and asserts each tenant only ever
// sees its own value — not one tenant's value asserted twice, which would
// make a regression back to the process-global tenantID() seam invisible.

import (
	"sync"
	"testing"
)

func TestSetGetPropForTenant_TwoTenantsConcurrently_DoNotCrossContaminate(t *testing.T) {
	newTestDB(t)

	const sproutID = "web-01"
	const name = "role"

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := SetPropForTenant("t_a", sproutID, name, "primary"); err != nil {
			t.Errorf("SetPropForTenant(t_a): %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := SetPropForTenant("t_b", sproutID, name, "replica"); err != nil {
			t.Errorf("SetPropForTenant(t_b): %v", err)
		}
	}()
	wg.Wait()

	if got := GetStringPropForTenant("t_a", sproutID, name); got != "primary" {
		t.Errorf("t_a prop = %q, want %q", got, "primary")
	}
	if got := GetStringPropForTenant("t_b", sproutID, name); got != "replica" {
		t.Errorf("t_b prop = %q, want %q", got, "replica")
	}

	// Deleting t_a's prop must not affect t_b's identically-named one.
	if err := DeletePropForTenant("t_a", sproutID, name); err != nil {
		t.Fatalf("DeletePropForTenant(t_a): %v", err)
	}
	if got := GetStringPropForTenant("t_a", sproutID, name); got != "" {
		t.Errorf("t_a prop after delete = %q, want empty", got)
	}
	if got := GetStringPropForTenant("t_b", sproutID, name); got != "replica" {
		t.Errorf("t_b prop after t_a's delete = %q, want unaffected %q", got, "replica")
	}
}

func TestGetPropsForTenant_TwoTenantsConcurrently(t *testing.T) {
	newTestDB(t)

	const sproutID = "web-02"

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		SetPropForTenant("t_x", sproutID, "os", "linux")
		SetPropForTenant("t_x", sproutID, "arch", "amd64")
	}()
	go func() {
		defer wg.Done()
		SetPropForTenant("t_y", sproutID, "os", "windows")
		SetPropForTenant("t_y", sproutID, "arch", "arm64")
	}()
	wg.Wait()

	gotX := GetPropsForTenant("t_x", sproutID)
	if gotX["os"] != "linux" || gotX["arch"] != "amd64" {
		t.Errorf("t_x props = %v, want os=linux arch=amd64", gotX)
	}
	gotY := GetPropsForTenant("t_y", sproutID)
	if gotY["os"] != "windows" || gotY["arch"] != "arm64" {
		t.Errorf("t_y props = %v, want os=windows arch=arm64", gotY)
	}
}
