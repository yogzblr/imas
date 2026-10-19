package harness

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

// A sealed facts report opens under the sprout's box key and the tenant's
// key, as farmer opens it (internal/facts), for the sprout and tenant it
// names; one sealed under another key, or in plaintext, doesn't.
func TestSealedFacts(t *testing.T) {
	e, err := NewEnrolment("web-01", "")
	if err != nil {
		t.Fatal(err)
	}
	var tenantPriv [32]byte
	if _, err := rand.Read(tenantPriv[:]); err != nil {
		t.Fatal(err)
	}
	tenantPub, _ := curve25519.X25519(tenantPriv[:], curve25519.Basepoint)
	e.SproutID, e.TenantID, e.tenantPub = "web-01", "t_aaaaaaaaaaaaaaaa", base64.StdEncoding.EncodeToString(tenantPub)
	sproutPub, _ := base64.StdEncoding.DecodeString(e.BoxPub)
	var peer [32]byte
	copy(peer[:], sproutPub)
	open := func(data []byte) error {
		_, err := payloadbox.Open(data, []payloadbox.KeyPair{{PeerPub: &peer, Priv: &tenantPriv}},
			payloadbox.Expect{Purpose: payloadbox.PurposeFacts, TenantID: e.TenantID, SproutID: e.SproutID})
		return err
	}

	m, err := e.SealedFacts(e.Facts("marker"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "imas.sprouts.web-01.facts" || m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Errorf("sealed: subject %s, header %q", m.Subject, m.Header.Get(payloadbox.Header))
	}
	if err := open(m.Data); err != nil {
		t.Errorf("the sealed report doesn't open as farmer opens it: %v", err)
	}
	forged, err := e.ForgedSealedFacts(e.Facts("marker"))
	if err != nil {
		t.Fatal(err)
	}
	if open(forged.Data) == nil {
		t.Error("a report sealed under another key opens")
	}
	plain, err := e.PlaintextFacts(e.Facts("marker"))
	if err != nil || plain.Header.Get(payloadbox.Header) != "" {
		t.Errorf("plaintext: header %q, %v", plain.Header.Get(payloadbox.Header), err)
	}
	if s := e.PlaintextStepEvent("j1", "s1"); s.Subject != "imas.cook.web-01.j1" || len(s.Header) != 0 {
		t.Errorf("a plaintext step event: %s %v", s.Subject, s.Header)
	}
	e.tenantPub = ""
	if _, err := e.SealedFacts(e.Facts("marker")); err == nil {
		t.Error("sealed without a tenant key")
	}
}

// End to end against the fake stack: enrol a sprout in full, connect it
// through the fake Envoy with its gateway JWT, publish sealed and
// plaintext facts; without a gateway JWT the websocket is refused.
func TestConnectThroughEnvoy(t *testing.T) {
	f, s := fakeFleet(t)
	f.AcceptanceExec = fakeAcceptanceExec(t, s)
	c := ctx(t)
	tok, err := f.Tokens.Tenant(c, 1, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.API.MintKey(c, tok, fakestack.TenantID(1), 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnrolment("uat-bus-01", key.RegistrationKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ConnectThroughEnvoy(c, f.Env.EnvoyURL, f.Env.CAPool); err == nil {
		t.Fatal("connected before enrolling")
	}
	if err := NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP).Enrol(c, e); err != nil {
		t.Fatal(err)
	}
	nc, err := e.ConnectThroughEnvoy(c, f.Env.EnvoyURL, f.Env.CAPool)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	marker := UpgradeMarkerKey(e.TenantID, e.SproutID)
	plain, _ := e.PlaintextFacts(e.Facts("plain"))
	if err := Publish(nc, plain); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { ok, kind, _ := f.ValkeyGet(c, marker); return ok && kind == "facts" })
	sealed, _ := e.SealedFacts(e.Facts("sealed"))
	if err := Publish(nc, sealed); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		props, _ := f.Props(c, e.TenantID, e.SproutID)
		ok, _, _ := f.ValkeyGet(c, marker)
		return props["hostname"].Value == "sealed" && !ok
	})

	e.gatewayJWT = "not-a-jwt"
	if _, err := e.ConnectThroughEnvoy(c, f.Env.EnvoyURL, f.Env.CAPool); err == nil {
		t.Error("connected through the fake Envoy with a junk gateway JWT")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("the condition never held")
}
