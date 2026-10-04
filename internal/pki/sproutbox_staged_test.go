package pki

import (
	"errors"
	"testing"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// SproutOpenStagedFromFarmer (security review 2026-10-b, B1): a staged
// copy opens under the same keys and bindings as a sealed request, but
// without the replay guard, since it is read long after it was sealed and
// may be read more than once; internal/cook bounds replay by job ID and
// dispatch time instead.
func TestSproutOpenStagedFromFarmer(t *testing.T) {
	enrollForTest(t)
	data, id, err := SealToSprout("t_1", "web-01", payloadbox.PurposeStagedRecipe, "", map[string]string{"JobID": "j"})
	if err != nil {
		t.Fatalf("SealToSprout: %v", err)
	}
	for range 2 {
		msg, err := SproutOpenStagedFromFarmer("web-01", payloadbox.PurposeStagedRecipe, data)
		if err != nil || msg.ID != id || msg.TenantID != "t_1" || msg.SproutID != "web-01" {
			t.Fatalf("SproutOpenStagedFromFarmer: %+v, %v", msg, err)
		}
	}
	// Bound to its purpose both ways: a staged copy never opens as a
	// request, nor a sealed request as a staged copy.
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCookRequest, data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("staged copy opened as a cook request: %v", err)
	}
	dispatch, _, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCookRequest, "", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SproutOpenStagedFromFarmer("web-01", payloadbox.PurposeStagedRecipe, dispatch); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("sealed cook dispatch opened as a staged copy: %v", err)
	}
	// Bound to the sprout: one for another sprout ID doesn't open.
	if _, err := SproutOpenStagedFromFarmer("web-02", payloadbox.PurposeStagedRecipe, data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("staged copy opened for another sprout ID: %v", err)
	}
	// Plain JSON never opens.
	if _, err := SproutOpenStagedFromFarmer("web-01", payloadbox.PurposeStagedRecipe, []byte(`{"JobID":"forged"}`)); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("plain JSON opened as a staged copy: %v", err)
	}
}

// A staged copy sealed under the tenant key that names another tenant
// (two tenants sharing a keypair, H3) is refused by the tenant pin.
func TestSproutOpenStagedFromFarmer_RefusesAnotherTenant(t *testing.T) {
	enrollForTest(t)
	keys, err := TenantBoxKeys("t_1")
	if err != nil {
		t.Fatal(err)
	}
	active, _, err := ValidSproutBoxKeys("t_1", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	sproutPub, err := DecodeBoxPubKey(active)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeStagedRecipe, "t_2", "web-01", "", "x")
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sproutPub, Priv: keys[0].Priv}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SproutOpenStagedFromFarmer("web-01", payloadbox.PurposeStagedRecipe, data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("staged copy naming another tenant opened: %v", err)
	}
}

// Without keys the sprout can verify nothing, and opens nothing.
func TestSproutOpenStagedFromFarmer_NotReady(t *testing.T) {
	setupSproutFiles(t)
	if _, err := SproutOpenStagedFromFarmer("web-01", payloadbox.PurposeStagedRecipe, []byte(`{}`)); !errors.Is(err, ErrSproutBoxNotReady) {
		t.Errorf("SproutOpenStagedFromFarmer without keys = %v, want ErrSproutBoxNotReady", err)
	}
}
