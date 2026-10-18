package natsapi

// internal.tenant.boxkey (L24, U2): the SaaS API learns a tenant's current
// box public key, for the fingerprint it puts in a join token, only from a
// sealed farmer reply bound to its own request.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// stubTenantBoxKey makes the handler answer from keys (tenant -> key or
// error) and counts its lookups.
func stubTenantBoxKey(t *testing.T, keys map[string]any) *int {
	t.Helper()
	var n int
	orig := tenantBoxKeyForToken
	tenantBoxKeyForToken = func(tenantID string) (string, error) {
		n++
		switch v := keys[tenantID].(type) {
		case string:
			return v, nil
		case error:
			return "", v
		}
		return "", fmt.Errorf("no key for %s", tenantID)
	}
	t.Cleanup(func() { tenantBoxKeyForToken = orig })
	return &n
}

func (c *saasClient) openTenantBoxKeyReply(id string, msg *nats.Msg) (controlplane.TenantBoxKeyReply, error) {
	var out controlplane.TenantBoxKeyReply
	if code := msg.Header.Get(payloadbox.ErrorHeader); code != "" {
		return out, errRefused{code}
	}
	body, err := c.box.OpenTenantBoxKeyReply(id, msg.Data)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(body.Result, &out)
	return out, err
}

func TestTenantBoxKey_SealedReply(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	lookups := stubTenantBoxKey(t, map[string]any{
		"t_1":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"t_gone": fmt.Errorf("pki: tenant %q: %w", "t_gone", pki.ErrTenantDeprovisioned),
		"bad":    pki.ErrTenantIDInvalid,
	})
	if err := registerTenantBoxKey(nc, newSealedAPI()); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	saas := dialSaaSAPI(t, nc)

	m1, id1 := saas.sealedMsg(t, controlplane.SubjectTenantBoxKey, controlplane.TenantBoxKeyRequest{TenantID: "t_1"})
	reply := sendRaw(t, saas, m1)
	if reply.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 || strings.Contains(string(reply.Data), "t_1") {
		t.Fatalf("reply is not sealed: %v %q", reply.Header, reply.Data)
	}
	got, err := saas.openTenantBoxKeyReply(id1, reply)
	if err != nil || got.TenantID != "t_1" || got.TenantX25519Pub != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" || got.ErrorCode != "" {
		t.Fatalf("reply %+v, %v", got, err)
	}
	// Bound to its request: it doesn't open as the answer to another, nor
	// as an internal.sprout.action reply.
	_, id2 := saas.sealedMsg(t, controlplane.SubjectTenantBoxKey, controlplane.TenantBoxKeyRequest{TenantID: "t_1"})
	if _, err := saas.openTenantBoxKeyReply(id2, reply); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("answer to another request: %v, want ErrOpen", err)
	}
	if _, err := saas.box.OpenSproutActionReply(id1, reply.Data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("opened as a sprout action reply: %v", err)
	}

	for tenant, code := range map[string]controlplane.ErrorCode{
		"t_gone": controlplane.ErrorTenantNotFound,
		"bad":    controlplane.ErrorInvalidTenantID,
		"t_err":  controlplane.ErrorInternal,
	} {
		m, id := saas.sealedMsg(t, controlplane.SubjectTenantBoxKey, controlplane.TenantBoxKeyRequest{TenantID: tenant})
		got, err := saas.openTenantBoxKeyReply(id, sendRaw(t, saas, m))
		if err != nil || got.ErrorCode != code || got.TenantX25519Pub != "" {
			t.Errorf("%s: %+v, %v; want %s and no key", tenant, got, err, code)
		}
	}
	if *lookups != 4 {
		t.Fatalf("%d lookups, want 4", *lookups)
	}

	// Refused before any lookup: plaintext, an impostor's seal, a request
	// moved from another subject, and a replay.
	plain := nats.NewMsg(controlplane.SubjectTenantBoxKey)
	plain.Data = []byte(`{"tenant_id":"t_1"}`)
	wantSaaSRefusal(t, "plaintext", sendRaw(t, saas, plain), payloadbox.ErrorCodeEncryptionRequired)
	forged, _, err := sealedSaaSAPIMsg(impostorSaaSAPI(t, saas), controlplane.SubjectTenantBoxKey, controlplane.TenantBoxKeyRequest{TenantID: "t_1"})
	if err != nil {
		t.Fatal(err)
	}
	wantSaaSRefusal(t, "impostor", sendRaw(t, saas, forged), payloadbox.ErrorCodeOpenFailed)
	moved, _ := saas.sealedMsg(t, controlplane.SubjectSproutAction, controlplane.TenantBoxKeyRequest{TenantID: "t_1"})
	moved.Subject = controlplane.SubjectTenantBoxKey
	wantSaaSRefusal(t, "moved", sendRaw(t, saas, moved), payloadbox.ErrorCodeOpenFailed)
	replay := nats.NewMsg(m1.Subject)
	replay.Header, replay.Data = m1.Header, m1.Data
	wantSaaSRefusal(t, "replay", sendRaw(t, saas, replay), payloadbox.ErrorCodeOpenFailed)
	if *lookups != 4 {
		t.Fatalf("a refused request was looked up (%d lookups)", *lookups)
	}

	// A reply subject outside the SaaS API's inboxes gets no answer.
	other, err := nats.Connect(nc.ConnectedUrl())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	m, _ := saas.sealedMsg(t, controlplane.SubjectTenantBoxKey, controlplane.TenantBoxKeyRequest{TenantID: "t_1"})
	if _, err := other.RequestMsg(m, 300*time.Millisecond); err == nil {
		t.Error("answered on an inbox outside _INBOX.saasapi")
	}
	if *lookups != 4 {
		t.Fatalf("a request with a foreign inbox was looked up (%d lookups)", *lookups)
	}
}
