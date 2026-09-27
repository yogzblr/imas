package payloadbox

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type keys struct{ pub, priv *[32]byte }

func genKeys(t *testing.T) keys {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{pub, priv}
}

// farmerPair/sproutPair are the two ends' views of one (tenant, sprout)
// key pairing.
func farmerPair(tenant, sprout keys) KeyPair { return KeyPair{PeerPub: sprout.pub, Priv: tenant.priv} }
func sproutPair(tenant, sprout keys) KeyPair { return KeyPair{PeerPub: tenant.pub, Priv: sprout.priv} }

func mustMessage(t *testing.T, purpose, sproutID, replyTo string, body any) Message {
	t.Helper()
	m, err := NewMessage(purpose, sproutID, replyTo, body)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSealOpenRoundTrip(t *testing.T) {
	tenant, sprout := genKeys(t), genKeys(t)
	msg := mustMessage(t, PurposeCmdRunRequest, "web-01", "", map[string]string{"command": "uptime"})
	data, err := Seal(msg, []KeyPair{farmerPair(tenant, sprout)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(data, []KeyPair{sproutPair(tenant, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.ID != msg.ID || got.IssuedAt != msg.IssuedAt || string(got.Body) != `{"command":"uptime"}` {
		t.Errorf("opened %+v, want %+v", got, msg)
	}
}

// The ciphertext must not carry the plaintext, and every seal must use a
// fresh nonce even for identical input.
func TestSealHidesPlaintextAndUsesFreshNonces(t *testing.T) {
	tenant, sprout := genKeys(t), genKeys(t)
	msg := mustMessage(t, PurposeCmdRunRequest, "web-01", "", "top-secret-command-line")
	a, _ := Seal(msg, []KeyPair{farmerPair(tenant, sprout)})
	b, _ := Seal(msg, []KeyPair{farmerPair(tenant, sprout)})
	for _, d := range [][]byte{a, b} {
		if bytes.Contains(d, []byte("top-secret")) || bytes.Contains(d, []byte("web-01")) || bytes.Contains(d, []byte(PurposeCmdRunRequest)) {
			t.Fatalf("envelope leaks plaintext: %s", d)
		}
	}
	var ea, eb Envelope
	json.Unmarshal(a, &ea)
	json.Unmarshal(b, &eb)
	if string(ea.Copies[0].Nonce) == string(eb.Copies[0].Nonce) {
		t.Error("two seals reused a nonce")
	}
}

// box's shared key is the same in both directions, so without purpose
// binding a request reflected back at its sender would open. It must not.
func TestOpenRejectsReflection(t *testing.T) {
	tenant, sprout := genKeys(t), genKeys(t)
	req := mustMessage(t, PurposeCmdRunRequest, "web-01", "", "x")
	data, _ := Seal(req, []KeyPair{farmerPair(tenant, sprout)})
	// Farmer, expecting a reply, is handed its own request.
	if _, err := Open(data, []KeyPair{farmerPair(tenant, sprout)}, Expect{Purpose: PurposeCmdRunResponse, SproutID: "web-01"}); !errors.Is(err, ErrOpen) {
		t.Fatalf("reflected request opened as a response: %v", err)
	}
	// And the same bytes do open for the purpose they were sealed for,
	// under the farmer's own view of the key pair: the check above is
	// what stops them, not the keys.
	if _, err := Open(data, []KeyPair{farmerPair(tenant, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestOpenRejectsWrongSproutAndWrongKeys(t *testing.T) {
	tenant, sprout, other := genKeys(t), genKeys(t), genKeys(t)
	data, _ := Seal(mustMessage(t, PurposeCmdRunRequest, "web-01", "", "x"), []KeyPair{farmerPair(tenant, sprout)})
	if _, err := Open(data, []KeyPair{sproutPair(tenant, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-02"}); !errors.Is(err, ErrOpen) {
		t.Errorf("opened for the wrong sprout: %v", err)
	}
	if _, err := Open(data, []KeyPair{sproutPair(tenant, other)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"}); !errors.Is(err, ErrOpen) {
		t.Errorf("opened under another sprout's key: %v", err)
	}
	otherTenant := genKeys(t)
	if _, err := Open(data, []KeyPair{sproutPair(otherTenant, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"}); !errors.Is(err, ErrOpen) {
		t.Errorf("opened under another tenant's key: %v", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	tenant, sprout := genKeys(t), genKeys(t)
	data, _ := Seal(mustMessage(t, PurposeCmdRunRequest, "web-01", "", "x"), []KeyPair{farmerPair(tenant, sprout)})
	var env Envelope
	json.Unmarshal(data, &env)
	env.Copies[0].Box[len(env.Copies[0].Box)-1] ^= 1
	tampered, _ := json.Marshal(env)
	if _, err := Open(tampered, []KeyPair{sproutPair(tenant, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"}); !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered envelope opened: %v", err)
	}
	for _, bad := range []string{``, `{}`, `not json`, `{"v":2,"s":[]}`, `{"v":1,"s":[{"n":"AA==","c":"AA=="}]}`} {
		if _, err := Open([]byte(bad), []KeyPair{sproutPair(tenant, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"}); !errors.Is(err, ErrOpen) {
			t.Errorf("Open(%q) = %v, want ErrOpen", bad, err)
		}
	}
}

// During a tenant key rotation's grace window farmer seals one copy per
// tenant key; a sprout pinned to either opens its own.
func TestOpenPicksTheCopyForThePinnedKey(t *testing.T) {
	oldTenant, newTenant, sprout := genKeys(t), genKeys(t), genKeys(t)
	data, err := Seal(mustMessage(t, PurposeCmdRunRequest, "web-01", "", "x"),
		[]KeyPair{farmerPair(newTenant, sprout), farmerPair(oldTenant, sprout)})
	if err != nil {
		t.Fatal(err)
	}
	for name, pinned := range map[string]keys{"old": oldTenant, "new": newTenant} {
		if _, err := Open(data, []KeyPair{sproutPair(pinned, sprout)}, Expect{Purpose: PurposeCmdRunRequest, SproutID: "web-01"}); err != nil {
			t.Errorf("sprout pinned to the %s tenant key: %v", name, err)
		}
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	tenant, sprout := genKeys(t), genKeys(t)
	good := mustMessage(t, PurposeCmdRunRequest, "web-01", "", "x")
	if _, err := Seal(good, nil); err == nil {
		t.Error("sealed under no key pairs")
	}
	noPurpose := good
	noPurpose.Purpose = ""
	if _, err := Seal(noPurpose, []KeyPair{farmerPair(tenant, sprout)}); err == nil {
		t.Error("sealed a message with no purpose")
	}
	many := make([]KeyPair, MaxCopies+1)
	for i := range many {
		many[i] = farmerPair(tenant, sprout)
	}
	if _, err := Seal(good, many); err == nil {
		t.Error("sealed more copies than MaxCopies")
	}
}

func TestReplayGuard(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	defer func(orig func() time.Time) { now = orig }(now)
	clock := base
	now = func() time.Time { return clock }

	g := NewReplayGuard()
	m := mustMessage(t, PurposeCmdRunRequest, "web-01", "", "x")
	if err := g.Accept(&m); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if err := g.Accept(&m); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: %v", err)
	}
	stale := m
	stale.ID = "other"
	stale.IssuedAt = base.Add(-DefaultMaxSkew - time.Second).Unix()
	if err := g.Accept(&stale); !errors.Is(err, ErrStale) {
		t.Errorf("stale: %v", err)
	}
	future := m
	future.ID = "future"
	future.IssuedAt = base.Add(DefaultMaxSkew + time.Second).Unix()
	if err := g.Accept(&future); !errors.Is(err, ErrStale) {
		t.Errorf("future: %v", err)
	}
	// Past the window the original is stale, not merely replayed.
	clock = base.Add(DefaultMaxSkew + time.Second)
	if err := g.Accept(&m); !errors.Is(err, ErrStale) {
		t.Errorf("after the window: %v", err)
	}
}

func TestReplayGuardCapacity(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	defer func(orig func() time.Time) { now = orig }(now)
	clock := base
	now = func() time.Time { return clock }

	g := &ReplayGuard{MaxSkew: time.Minute, MaxEntries: 2}
	for i := 0; i < 2; i++ {
		m := mustMessage(t, PurposeCmdRunRequest, "web-01", "", i)
		if err := g.Accept(&m); err != nil {
			t.Fatal(err)
		}
	}
	m := mustMessage(t, PurposeCmdRunRequest, "web-01", "", 3)
	if err := g.Accept(&m); !errors.Is(err, ErrReplayGuardFull) {
		t.Fatalf("over capacity: %v", err)
	}
	// Once the earlier entries expire they're swept to make room.
	clock = base.Add(time.Minute + time.Second)
	m = mustMessage(t, PurposeCmdRunRequest, "web-01", "", 4)
	if err := g.Accept(&m); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// Every boundary has its own purpose pair (the purpose is what stops a
// message sealed for one boundary being accepted on another), and each
// purpose names its direction.
func TestPurposesAreDistinctAndDirected(t *testing.T) {
	purposes := []string{
		PurposeCmdRunRequest, PurposeCmdRunResponse,
		PurposeCookRequest, PurposeCookResponse,
		PurposeCookNudgeRequest, PurposeCookNudgeResponse,
		PurposeFleetSigningResponse, PurposeBoxKeySubmit, PurposeTenantKeyContinuity,
	}
	seen := map[string]bool{}
	for _, p := range purposes {
		if seen[p] {
			t.Errorf("purpose %q is used twice", p)
		}
		seen[p] = true
		if !strings.HasPrefix(p, "f2s.") && !strings.HasPrefix(p, "s2f.") {
			t.Errorf("purpose %q doesn't name its direction", p)
		}
	}
}
