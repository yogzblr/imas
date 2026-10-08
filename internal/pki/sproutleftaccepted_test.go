package pki

import (
	"sync"
	"testing"
)

// OnSproutLeftAccepted fires, with the right tenant and sprout, for every
// way a sprout leaves the accepted state, and not for accepting one.
func TestOnSproutLeftAccepted(t *testing.T) {
	setupTestPKI(t)
	var mu sync.Mutex
	var got [][2]string
	OnSproutLeftAccepted(func(tenantID, sproutID string) {
		mu.Lock()
		got = append(got, [2]string{tenantID, sproutID})
		mu.Unlock()
	})
	t.Cleanup(func() { OnSproutLeftAccepted(nil) })
	take := func() [][2]string {
		mu.Lock()
		defer mu.Unlock()
		g := got
		got = nil
		return g
	}
	tenant := currentTenantID()

	for i, op := range []struct {
		name string
		do   func(id string) error
	}{
		{"deny", func(id string) error { return DenyNKey(tenant, id) }},
		{"unaccept", func(id string) error { return UnacceptNKey(tenant, id, "") }},
		{"reject", func(id string) error { return RejectNKey(tenant, id, "") }},
		{"delete", func(id string) error { return DeleteNKey(tenant, id) }},
	} {
		id := "left" + string(rune('a'+i))
		writeKey(t, "unaccepted", id, "UKEY"+id)
		if err := AcceptNKey(tenant, id); err != nil {
			t.Fatalf("%s: AcceptNKey: %v", op.name, err)
		}
		if g := take(); len(g) != 0 {
			t.Fatalf("%s: hook fired for accepting: %v", op.name, g)
		}
		if err := op.do(id); err != nil {
			t.Fatalf("%s: %v", op.name, err)
		}
		g := take()
		if len(g) != 1 || g[0] != [2]string{tenant, id} {
			t.Fatalf("%s: hook calls = %v, want exactly (%s, %s)", op.name, g, tenant, id)
		}
	}

	// A failed change does not fire it.
	if err := DenyNKey(tenant, "nobody"); err == nil {
		t.Fatal("denying an unknown sprout succeeded")
	}
	if g := take(); len(g) != 0 {
		t.Fatalf("hook fired for a failed change: %v", g)
	}
}
