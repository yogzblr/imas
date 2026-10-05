package natsapi

// FIX.1 (FLAG FOR SECURITY REVIEW): farmer sends nothing to a sprout with
// no payload-encryption (box) key on record, and internal.sprout.action
// answers such a request with sprout_reenroll_required instead of
// internal_error or a dispatch that never arrives. Also the sealed stub
// sprout the real-dispatch tests use: since FIX.1 there is no plaintext
// stub, because farmer never sends one.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// sealedStubSprout is an enrolled sprout of tenant: its box key is on
// record, so farmer seals to it, and it opens what it receives and seals
// its replies with its own key and pinned tenant key, as a real sprout
// does. Create it after the test's mock OpenBao is up (dialSaaSAPI starts
// one), so the tenant key it pins is the one farmer seals with.
type sealedStubSprout struct {
	tenant, id string
	key        sproutKeypair
	tenantPub  *[32]byte
}

func newSealedStubSprout(t *testing.T, tenantID, sproutID string) sealedStubSprout {
	t.Helper()
	pki.InvalidateTenantBoxKeys(tenantID)
	key := newSproutKeypair(t)
	enrollSprout(t, tenantID, sproutID, key)
	return sealedStubSprout{tenant: tenantID, id: sproutID, key: key, tenantPub: pinnedTenantPub(t, tenantID)}
}

// answer subscribes nc to subject as s. Each request must open under
// reqPurpose; respond gets its body and returns the reply's body, which
// is sealed under respPurpose and bound to the request.
func (s sealedStubSprout) answer(t *testing.T, nc *nats.Conn, subject, reqPurpose, respPurpose string, respond func(body []byte) any) {
	t.Helper()
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Errorf("%s: farmer sent a plaintext request", subject)
			return
		}
		req, err := openAsSprout(s.key, s.tenant, s.tenantPub, s.id, reqPurpose, m.Data)
		if err != nil {
			t.Errorf("%s: opening farmer's request: %v", subject, err)
			return
		}
		msg, err := payloadbox.NewMessage(respPurpose, s.tenant, s.id, req.ID, respond(req.Body))
		if err != nil {
			t.Error(err)
			return
		}
		r := nats.NewMsg("")
		r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		if r.Data, err = payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: s.tenantPub, Priv: s.key.priv}}); err != nil {
			t.Error(err)
			return
		}
		_ = m.RespondMsg(r)
	})
	if err != nil {
		t.Fatalf("stub sprout subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

// failOnRequest fails t if anything reaches subject.
func failOnRequest(t *testing.T, nc *nats.Conn, subject string) {
	t.Helper()
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		t.Errorf("farmer sent %s to a sprout with no box key (sealed: %t)", subject, m.Header.Get(payloadbox.Header) != "")
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

func TestSendErrorCode(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want controlplane.ErrorCode
	}{
		"no box key":    {&cook.ReenrollRequiredError{Op: "cmd.run", SproutID: "web-01"}, ErrorSproutReenrollRequired},
		"wrapped":       {errors.Join(errors.New("sending"), &cook.ReenrollRequiredError{Op: "cook", SproutID: "web-01"}), ErrorSproutReenrollRequired},
		"timeout":       {nats.ErrTimeout, controlplane.ErrorSproutUnreachable},
		"no responders": {nats.ErrNoResponders, controlplane.ErrorSproutUnreachable},
		// The sprout's own no-keys refusal is not farmer's: farmer has a
		// box key on record for it, so it isn't classified as needing a
		// re-enrollment here.
		"sprout refused": {cmd.ErrSproutRefusedPayload, controlplane.ErrorInternal},
		"anything else":  {errors.New("boom"), controlplane.ErrorInternal},
	} {
		if got := sendErrorCode(c.err); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

// Through the real handlers, internal.sprout.action to an accepted sprout
// with no box key on record: cmd.run, cook and self_update are all
// refused with sprout_reenroll_required, synchronously (cook included,
// though its dispatch is asynchronous), and nothing reaches the sprout.
func TestSproutAction_SproutWithNoBoxKeyIsRefusedWithTheCode(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "keyless-01", "UKEY_KEYLESS")
	cmd.RegisterFarmerNatsConn(tenant, nc)
	defer cmd.UnregisterFarmerNatsConn(tenant)
	cook.RegisterFarmerNatsConn(tenant, nc)
	defer cook.UnregisterFarmerNatsConn(tenant)
	SetNatsConn(tenant, nc)
	defer ClearNatsConn(tenant)
	_, _, approve := newSUCatalog(t) // turns self_update on
	approve(tenant, ptr(suVersion))

	for _, suffix := range []string{"cmd.run", "cook", "recipe.nudge"} {
		failOnRequest(t, nc, "imas.sprouts.keyless-01."+suffix)
	}
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, nc)

	for _, action := range []controlplane.SproutAction{
		{Type: controlplane.ActionCmdRun, Params: json.RawMessage(`{"command":"uptime"}`)},
		{Type: controlplane.ActionCook, Params: json.RawMessage(`{"recipe":"nginx.harden"}`)},
		{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, controlplane.SelfUpdateParams{Version: suVersion})},
	} {
		reply := requestSproutAction(t, saas, controlplane.SproutActionRequest{TenantID: tenant, SproutID: "keyless-01", Action: action})
		if reply.Status != controlplane.StatusFailed || reply.ErrorCode != ErrorSproutReenrollRequired || reply.JID != "" || reply.Result != nil {
			t.Errorf("%s: reply %+v, want failed with %s", action.Type, reply, ErrorSproutReenrollRequired)
		}
	}
	nc.Flush()
	time.Sleep(100 * time.Millisecond) // a dispatch that slipped through would have landed
}

// The tenant-facing imas.api.cmd.run batch path: a keyless target's
// result carries farmer's refusal, naming the sprout and the code, and
// the other targets still run.
func TestHandleCmdRun_KeylessTargetFailsWithTheCode(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	writeNKey(t, "", "accepted", "keyless-01", "UKEY_KEYLESS")
	cmd.RegisterFarmerNatsConn(tenant, nc)
	defer cmd.UnregisterFarmerNatsConn(tenant)
	setupSealedEnv(t) // the mock OpenBao the stub sprout pins its tenant key from

	stub := newSealedStubSprout(t, tenant, "web-01")
	stub.answer(t, nc, "imas.sprouts.web-01.cmd.run", payloadbox.PurposeCmdRunRequest, payloadbox.PurposeCmdRunResponse,
		func([]byte) any { return apitypes.CmdRun{Stdout: "ok"} })
	failOnRequest(t, nc, "imas.sprouts.keyless-01.cmd.run")
	nc.Flush()

	res, err := handleCmdRun(tenant, mustJSON(t, apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "web-01"}, {SproutID: "keyless-01"}},
		Action: apitypes.CmdRun{Command: "uptime", Timeout: time.Second},
	}))
	if err != nil {
		t.Fatal(err)
	}
	results := res.(apitypes.TargetedResults).Results
	if ok := results["web-01"].(apitypes.CmdRun); ok.Error != nil || ok.Stdout != "ok" {
		t.Errorf("web-01: %+v", ok)
	}
	keyless := results["keyless-01"].(apitypes.CmdRun)
	if !errors.Is(keyless.Error, cook.ErrSproutReenrollRequired) {
		t.Fatalf("keyless-01: error %v, want cook.ErrSproutReenrollRequired", keyless.Error)
	}
	for _, want := range []string{"keyless-01", "re-enroll", cook.ReenrollRequiredCode} {
		if !strings.Contains(keyless.Error.Error(), want) {
			t.Errorf("keyless-01: error %q doesn't mention %q", keyless.Error, want)
		}
	}
}

// The resync batch: a keyless target's result is farmer's refusal text,
// with the code; nothing is sent to it.
func TestHandleCookResync_KeylessTargetFailsWithTheCode(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "keyless-01", "UKEY_KEYLESS")
	cook.RegisterFarmerNatsConn(tenant, nc)
	defer cook.UnregisterFarmerNatsConn(tenant)
	setupSealedEnv(t)
	failOnRequest(t, nc, cook.NudgeSubject("keyless-01"))
	nc.Flush()

	res, err := handleCookResync(tenant, mustJSON(t, apitypes.TargetedAction{Target: []pki.KeyManager{{SproutID: "keyless-01"}}}))
	if err != nil {
		t.Fatal(err)
	}
	got := res.(apitypes.TargetedResults).Results["keyless-01"].(apitypes.ResyncResult)
	if got.Nudged || !strings.Contains(got.Error, cook.ReenrollRequiredCode) || !strings.Contains(got.Error, "keyless-01") {
		t.Errorf("resync of a keyless sprout: %+v", got)
	}
}
