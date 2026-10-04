package pki

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// H3 (security review 2026-10): a message farmer sealed for tenant B
// must not run on tenant A's same-named sprout, even when the keys let
// it open there (two tenants sharing a keypair, or a box key registered
// in both). Here the sprout is in t_1 and the message is sealed under
// t_1's own tenant key, the strongest form of a shared key, but names
// t_2: the sprout refuses it.
func TestSproutOpenFromFarmer_RefusesAnotherTenantUnderASharedKey(t *testing.T) {
	enrollForTest(t)
	if got, err := SproutTenantID(); err != nil || got != "t_1" {
		t.Fatalf("pinned tenant = %q, %v; want t_1", got, err)
	}
	set, err := loadTenantKeySet("t_1")
	if err != nil {
		t.Fatal(err)
	}
	sp, err := DecodeBoxPubKey(sproutCurrentPub(t))
	if err != nil {
		t.Fatal(err)
	}
	seal := func(tenantID string) []byte {
		t.Helper()
		msg, err := payloadbox.NewMessage(payloadbox.PurposeCmdRunRequest, tenantID, "web-01", "", "reboot")
		if err != nil {
			t.Fatal(err)
		}
		data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sp, Priv: set.current.priv}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, seal("t_2")); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("tenant t_1's sprout opened a message for t_2: %v", err)
	}
	// Control: the same construction for its own tenant opens.
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, seal("t_1")); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Farmer checks the tenant on everything it opens: a sprout reply that
// names another tenant is refused even though it opens under the keys.
func TestOpenFromSprout_RefusesAnotherTenant(t *testing.T) {
	enrollForTest(t)
	keys, err := loadSproutBoxKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.wipe()
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCmdRunResponse, "t_2", "web-01", "", "ok")
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: keys.current}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeCmdRunResponse, data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("farmer opened a reply naming another tenant: %v", err)
	}
	// Control: what the sprout itself seals names its pinned tenant.
	good, err := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, "", "ok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeCmdRunResponse, good); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// A sprout whose tenant pin is missing fails closed: it can't open or
// seal anything.
func TestSproutBox_MissingTenantPinFailsClosed(t *testing.T) {
	enrollForTest(t)
	data, _, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, "", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(SproutTenantIDFile()); err != nil {
		t.Fatal(err)
	}
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data); err == nil {
		t.Fatal("opened a message with no tenant pinned")
	}
	if _, err := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, "", "x"); err == nil {
		t.Fatal("sealed a message with no tenant pinned")
	}
	if !SproutBoxReady() {
		t.Fatal("SproutBoxReady must stay true, or the sprout would fall back to accepting plaintext")
	}
}

// M2 (security review 2026-10): the replay guard survives a restart.
func TestSproutOpenFromFarmer_ReplayAfterRestartRefused(t *testing.T) {
	enrollForTest(t)
	t.Cleanup(ForgetSproutReplayGuard)
	ForgetSproutReplayGuard()
	data, _, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, "", "shutdown -r now")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(sproutReplayGuardFile())
		if err != nil {
			t.Fatalf("replay guard not persisted: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("replay guard file mode = %o, want 600", perm)
		}
	}
	ForgetSproutReplayGuard() // the process restarts
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Fatalf("replay after a restart = %v, want ErrReplayed", err)
	}
}

// A replay guard file that can't be parsed fails closed for one window:
// nothing issued before the process started (plus the skew allowance) is
// accepted.
func TestSproutGuard_CorruptFileFailsClosed(t *testing.T) {
	enrollForTest(t)
	t.Cleanup(ForgetSproutReplayGuard)
	ForgetSproutReplayGuard()
	data, _, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, "", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sproutReplayGuardFile(), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := sproutProcessStart
	sproutProcessStart = time.Now()
	t.Cleanup(func() { sproutProcessStart = orig })
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data); !errors.Is(err, payloadbox.ErrStale) {
		t.Fatalf("open with a corrupt guard file = %v, want ErrStale", err)
	}
}
