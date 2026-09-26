package natsapi

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// stubNudge replaces cook.NudgeSprout, failing for the sprout IDs in fail,
// and records who was nudged in which tenant.
func stubNudge(t *testing.T, fail map[string]bool) *[]string {
	t.Helper()
	var mu sync.Mutex
	nudged := []string{}
	old := nudgeSprout
	nudgeSprout = func(tenantID, sproutID string) error {
		mu.Lock()
		defer mu.Unlock()
		nudged = append(nudged, tenantID+"/"+sproutID)
		if fail[sproutID] {
			return errors.New("no responders")
		}
		return nil
	}
	t.Cleanup(func() { nudgeSprout = old })
	return &nudged
}

func resyncParams(t *testing.T, ids ...string) json.RawMessage {
	t.Helper()
	ta := apitypes.TargetedAction{}
	for _, id := range ids {
		ta.Target = append(ta.Target, pki.KeyManager{SproutID: id})
	}
	b, err := json.Marshal(ta)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHandleCookResync_NudgesEachTarget(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "web-01", "UKEY_RESYNC_1")
	writeNKey(t, pkiDir, "accepted", "web-02", "UKEY_RESYNC_2")
	nudged := stubNudge(t, map[string]bool{"web-02": true})
	tenant := pki.CurrentTenantID()

	res, err := handleCookResync(tenant, resyncParams(t, "web-01", "web-02"))
	if err != nil {
		t.Fatalf("handleCookResync: %v", err)
	}
	results := res.(apitypes.TargetedResults).Results
	if got := results["web-01"].(apitypes.ResyncResult); !got.Nudged || got.Error != "" {
		t.Errorf("web-01 = %+v, want nudged", got)
	}
	if got := results["web-02"].(apitypes.ResyncResult); got.Nudged || got.Error == "" {
		t.Errorf("web-02 = %+v, want an error", got)
	}
	if len(*nudged) != 2 {
		t.Errorf("nudged %v, want both targets", *nudged)
	}
	for _, n := range *nudged {
		if n != tenant+"/web-01" && n != tenant+"/web-02" {
			t.Errorf("nudged %q outside the request's tenant", n)
		}
	}
}

func TestHandleCookResync_RejectsBadTargets(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "web-01", "UKEY_RESYNC_1")
	nudged := stubNudge(t, nil)

	for name, params := range map[string]json.RawMessage{
		"invalid JSON":      json.RawMessage(`{invalid`),
		"no targets":        resyncParams(t),
		"unknown sprout":    resyncParams(t, "web-01", "nope"),
		"underscore suffix": resyncParams(t, "web-01_2"),
	} {
		if _, err := handleCookResync(pki.CurrentTenantID(), params); err == nil {
			t.Errorf("%s: handleCookResync succeeded", name)
		}
	}
	if len(*nudged) != 0 {
		t.Errorf("nudged %v despite invalid requests", *nudged)
	}
}

// Resync can make sprouts cook, so it needs the "cook" action.
func TestCookResyncRequiresCookAction(t *testing.T) {
	if got := NATSMethodAction(MethodCookResync); got != rbac.ActionCook {
		t.Errorf("cook.resync requires %q, want %q", got, rbac.ActionCook)
	}
	if _, ok := routes[MethodCookResync]; !ok {
		t.Error("cook.resync is not routed")
	}
}
