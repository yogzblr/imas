package saasapi

// internal.tenant.boxkey (L24, U2): a join token carries the fingerprint
// of the tenant key farmer names over the sealed control plane, and no
// token is minted from anything else.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/jointoken"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

const testTenantPub = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

// useRealTenantKeyFingerprint makes CreateEnrollmentKey ask farmer, as in
// production, for this test.
func useRealTenantKeyFingerprint(t *testing.T) {
	t.Helper()
	orig := tenantKeyFingerprintFor
	tenantKeyFingerprintFor = func(ctx context.Context, tenantID string) (string, error) {
		return tenantKeyFingerprint(ctx, bus, tenantID)
	}
	t.Cleanup(func() { tenantKeyFingerprintFor = orig })
}

// startFakeBoxKeyFarmer answers internal.tenant.boxkey with respond's
// reply, sealed as farmer seals it, or with respond's raw bytes.
func startFakeBoxKeyFarmer(t *testing.T, ns *server.Server, respond func(req controlplane.TenantBoxKeyRequest, id string) any) {
	t.Helper()
	fnc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fnc.Close)
	if _, err := fnc.Subscribe(controlplane.SubjectTenantBoxKey, func(msg *nats.Msg) {
		var req controlplane.TenantBoxKeyRequest
		sealed, err := farmerOpenRequest(msg, &req)
		if err != nil {
			t.Errorf("fake farmer: request didn't open: %v", err)
			return
		}
		switch out := respond(req, sealed.ID).(type) {
		case []byte:
			_ = msg.Respond(out)
		case *nats.Msg:
			out.Subject = msg.Reply
			_ = msg.RespondMsg(out)
		default:
			resp := nats.NewMsg(msg.Reply)
			resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			resp.Data = testKeys.sealFarmerReplyWire(pki.TenantBoxKeyReplyWire(), sealed.ID, out, "")
			_ = msg.RespondMsg(resp)
		}
	}); err != nil {
		t.Fatal(err)
	}
	_ = fnc.Flush()
}

func postEnrollmentKey(t *testing.T, tenantID string) (int, createEnrollmentKeyResponse, string) {
	t.Helper()
	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, createEnrollmentKeyRequest{ExpiresInHours: 1, MaxUses: 1})
	var resp createEnrollmentKeyResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, w.Body.String()
}

func TestCreateEnrollmentKey_FingerprintFromFarmer(t *testing.T) {
	gdb := newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	useRealTenantKeyFingerprint(t)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	var asked []string
	startFakeBoxKeyFarmer(t, ns, func(req controlplane.TenantBoxKeyRequest, _ string) any {
		asked = append(asked, req.TenantID)
		return controlplane.TenantBoxKeyReply{TenantID: req.TenantID, TenantX25519Pub: testTenantPub}
	})

	code, resp, body := postEnrollmentKey(t, tenantID)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	raw, _ := base64.StdEncoding.DecodeString(testTenantPub)
	want := jointoken.Fingerprint((*[32]byte)(raw))
	tok, err := jointoken.Parse(resp.RegistrationKey)
	if err != nil || tok.Fingerprint != want || resp.TenantKeyFingerprint != want || tok.KeyID != resp.KeyID {
		t.Fatalf("token %+v (%v), tenant_key_fingerprint %q; want fingerprint %s", tok, err, resp.TenantKeyFingerprint, want)
	}
	var stored EnrollmentKey
	if err := gdb.First(&stored, "key_id = ?", resp.KeyID).Error; err != nil || stored.KeyHash != hashSecret(tok.Secret) {
		t.Fatalf("stored %+v, %v: key_hash must be the hash of the secret alone", stored, err)
	}
	if len(asked) != 1 || asked[0] != tenantID {
		t.Fatalf("farmer was asked for %v", asked)
	}
}

// No usable answer from farmer, no key: nothing is stored, and the
// caller can try again (503), except for a deprovisioned tenant (409).
func TestCreateEnrollmentKey_NoTokenWithoutFarmersKey(t *testing.T) {
	gdb := newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	useRealTenantKeyFingerprint(t)
	orig := tenantBoxKeyTimeout
	tenantBoxKeyTimeout = 500 * time.Millisecond
	t.Cleanup(func() { tenantBoxKeyTimeout = orig })

	noKeys := func(t *testing.T, name string, wantCode int, wantErr string) {
		t.Helper()
		code, _, body := postEnrollmentKey(t, tenantID)
		if code != wantCode || !strings.Contains(body, `"`+wantErr+`"`) {
			t.Errorf("%s: %d %s, want %d %s", name, code, body, wantCode, wantErr)
		}
		var n int64
		gdb.Model(&EnrollmentKey{}).Where("tenant_id = ?", tenantID).Count(&n)
		if n != 0 {
			t.Fatalf("%s: %d keys stored", name, n)
		}
	}
	noKeys(t, "no bus", 503, "farmer_unavailable")

	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	noKeys(t, "no farmer", 503, "farmer_unavailable")

	impostor := newControlKeys()
	var answer func(req controlplane.TenantBoxKeyRequest, id string) any
	startFakeBoxKeyFarmer(t, ns, func(req controlplane.TenantBoxKeyRequest, id string) any { return answer(req, id) })
	for name, a := range map[string]func(controlplane.TenantBoxKeyRequest, string) any{
		"plaintext reply": func(req controlplane.TenantBoxKeyRequest, _ string) any {
			b, _ := json.Marshal(controlplane.TenantBoxKeyReply{TenantID: req.TenantID, TenantX25519Pub: testTenantPub})
			return b
		},
		"refusal code": func(controlplane.TenantBoxKeyRequest, string) any {
			m := nats.NewMsg("")
			m.Header.Set(payloadbox.ErrorHeader, payloadbox.ErrorCodeOpenFailed)
			return m
		},
		"sealed by an impostor": func(req controlplane.TenantBoxKeyRequest, id string) any {
			m := nats.NewMsg("")
			m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			m.Data = impostor.sealFarmerReplyWire(pki.TenantBoxKeyReplyWire(), id, controlplane.TenantBoxKeyReply{TenantID: req.TenantID, TenantX25519Pub: testTenantPub}, "")
			return m
		},
		"a reply to another request": func(req controlplane.TenantBoxKeyRequest, _ string) any {
			m := nats.NewMsg("")
			m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			m.Data = testKeys.sealFarmerReplyWire(pki.TenantBoxKeyReplyWire(), "another-request", controlplane.TenantBoxKeyReply{TenantID: req.TenantID, TenantX25519Pub: testTenantPub}, "")
			return m
		},
		"a sprout action reply": func(req controlplane.TenantBoxKeyRequest, id string) any {
			m := nats.NewMsg("")
			m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			m.Data = testKeys.sealFarmerReply(id, controlplane.TenantBoxKeyReply{TenantID: req.TenantID, TenantX25519Pub: testTenantPub}, "")
			return m
		},
		"another tenant's key": func(controlplane.TenantBoxKeyRequest, string) any {
			return controlplane.TenantBoxKeyReply{TenantID: "t_other", TenantX25519Pub: testTenantPub}
		},
		"no key": func(req controlplane.TenantBoxKeyRequest, _ string) any {
			return controlplane.TenantBoxKeyReply{TenantID: req.TenantID}
		},
		"not a key": func(req controlplane.TenantBoxKeyRequest, _ string) any {
			return controlplane.TenantBoxKeyReply{TenantID: req.TenantID, TenantX25519Pub: "AAAA"}
		},
		"farmer error": func(req controlplane.TenantBoxKeyRequest, _ string) any {
			return controlplane.TenantBoxKeyReply{TenantID: req.TenantID, ErrorCode: controlplane.ErrorInternal}
		},
		"sealed refusal": func(req controlplane.TenantBoxKeyRequest, id string) any {
			m := nats.NewMsg("")
			m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			m.Data = testKeys.sealFarmerReplyWire(pki.TenantBoxKeyReplyWire(), id, nil, "sealed store unavailable")
			return m
		},
	} {
		answer = a
		noKeys(t, name, 503, "farmer_unavailable")
	}

	answer = func(req controlplane.TenantBoxKeyRequest, _ string) any {
		return controlplane.TenantBoxKeyReply{TenantID: req.TenantID, ErrorCode: controlplane.ErrorTenantNotFound}
	}
	noKeys(t, "deprovisioned", 409, "tenant_deprovisioned")
}
