package natsapi

// Coverage for sprout_action.go (FLAG FOR SECURITY REVIEW): the scoped
// reply-inbox gate, the point-of-effect tenant check, and dispatch through
// the real handleCmdRun/handleCook. The credential side — that the SaaS
// API's SYS User can use this subject and nothing wider — is proven on a
// live, JWT-authenticated bus in internal/pki/saasapi_user_integration_test.go.

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

type dispatchCall struct {
	tenantID string
	params   json.RawMessage
}

// dispatchRecorder stubs dispatchCmdRun/dispatchCook, recording every call.
type dispatchRecorder struct {
	mu    sync.Mutex
	calls []dispatchCall
}

func (d *dispatchRecorder) record(tenantID string, params json.RawMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, dispatchCall{tenantID, params})
}

func (d *dispatchRecorder) all() []dispatchCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dispatchCall(nil), d.calls...)
}

// stubSproutActionDispatch replaces the dispatch functions with recorders
// that succeed. verify is installed as-is when non-nil.
func stubSproutActionDispatch(t *testing.T, verify func(string, string) error) *dispatchRecorder {
	t.Helper()
	origV, origR, origC, origT := verifySproutInTenant, dispatchCmdRun, dispatchCook, triggerCook
	origS, origK, origB := dispatchSelfUpdate, fleetKeys, requireSproutBoxKey
	t.Cleanup(func() {
		verifySproutInTenant, dispatchCmdRun, dispatchCook, triggerCook = origV, origR, origC, origT
		dispatchSelfUpdate, fleetKeys, requireSproutBoxKey = origS, origK, origB
	})
	requireSproutBoxKey = func(string, string, string) error { return nil }

	rec := &dispatchRecorder{}
	if verify != nil {
		verifySproutInTenant = verify
	}
	dispatchCmdRun = func(tenantID string, params json.RawMessage) (any, error) {
		rec.record(tenantID, params)
		var ta apitypes.TargetedAction
		_ = json.Unmarshal(params, &ta)
		out := apitypes.TargetedResults{Results: map[string]any{}}
		for _, tgt := range ta.Target {
			out.Results[tgt.SproutID] = apitypes.CmdRun{Stdout: "ok"}
		}
		return out, nil
	}
	dispatchCook = func(tenantID string, params json.RawMessage) (any, error) {
		rec.record(tenantID, params)
		return apitypes.CmdCook{JID: "jid-1"}, nil
	}
	triggerCook = func(string, string) error { return nil }
	dispatchSelfUpdate = func(tenantID, _, version string) (string, error) {
		rec.record(tenantID, mustJSON(t, controlplane.SelfUpdateParams{Version: version}))
		return "jid-su", nil
	}
	return rec
}

func cmdRunRequest(tenantID, sproutID string) controlplane.SproutActionRequest {
	return controlplane.SproutActionRequest{
		TenantID: tenantID,
		SproutID: sproutID,
		Action:   controlplane.SproutAction{Type: controlplane.ActionCmdRun, Params: json.RawMessage(`{"command":"uptime"}`)},
	}
}

func TestSproutAction_RegisteredWithTenantProvisioning(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	stubTenantProvisioning(t, func(string, string) error { return nil }, func(string) error { return nil })
	stubSproutActionDispatch(t, func(string, string) error { return nil })

	// initSystemAccountListeners only calls RegisterTenantProvisioning, so
	// that call alone must bring internal.sprout.action up.
	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	reply := requestSproutAction(t, dialSaaSAPI(t, nc), cmdRunRequest("t_1", "web-01"))
	if reply.Status != controlplane.StatusCompleted {
		t.Fatalf("unexpected reply %+v", reply)
	}
}

// TestSproutAction_RefusesUnscopedReplySubjects: farmer's SYS user has no
// permission restrictions and NATS doesn't check the reply subject a
// publisher sets, so a request whose reply subject isn't a SaaS API inbox
// must be neither executed nor answered. The requests are genuinely sealed
// by the SaaS API: the reply subject check comes first all the same.
func TestSproutAction_RefusesUnscopedReplySubjects(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	var verified atomic.Int32
	rec := stubSproutActionDispatch(t, func(string, string) error { verified.Add(1); return nil })
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatalf("RegisterSproutAction: %v", err)
	}
	saas := dialSaaSAPI(t, nc)

	watch, _ := nc.SubscribeSync(">")
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// No reply subject at all (fire-and-forget).
	m, _ := saas.sealedMsg(t, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"))
	if err := nc.PublishMsg(m); err != nil {
		t.Fatalf("publish: %v", err)
	}
	for _, reply := range []string{
		"_INBOX.farmer.abc",                     // another SYS user's inbox
		"_INBOX.saasapix.abc",                   // not a token boundary
		"_INBOX.saasapi",                        // the prefix alone
		"internal.tenant.provisioned.pj_forged", // a forged provisioning result
		"$SYS.REQ.SERVER.PING",
		"imas.sprouts.web-01.cmd.run",
	} {
		m, _ := saas.sealedMsg(t, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"))
		m.Reply = reply
		if err := nc.PublishMsg(m); err != nil {
			t.Fatalf("publish with reply %q: %v", reply, err)
		}
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Everything the watcher sees must be one of our own requests: farmer
	// published nothing, anywhere.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		msg, err := watch.NextMsg(50 * time.Millisecond)
		if err != nil {
			continue
		}
		if msg.Subject != controlplane.SubjectSproutAction {
			t.Fatalf("farmer published to %q in response to a request it should have dropped", msg.Subject)
		}
	}
	if verified.Load() != 0 || len(rec.all()) != 0 {
		t.Fatalf("a request with an unscoped reply subject was processed: verify=%d dispatch=%d", verified.Load(), len(rec.all()))
	}
}

// TestSproutAction_PointOfEffectCheckAgainstRealStore runs the real
// pki.VerifySproutInTenant: a sprout registered under one tenant can't be
// reached by asserting another, and nothing is dispatched when the check
// fails.
func TestSproutAction_PointOfEffectCheckAgainstRealStore(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	legacy := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	writeNKey(t, "", "unaccepted", "pending-01", "UKEY_PENDING")

	rec := stubSproutActionDispatch(t, nil) // real verifySproutInTenant
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatalf("RegisterSproutAction: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	saas := dialSaaSAPI(t, nc)

	for _, tc := range []struct {
		name, tenant, sprout string
	}{
		{"another tenant asserted", "t_other", "web-01"},
		{"tenant ID differing only in case", strings.ToUpper(legacy), "web-01"},
		{"unknown sprout", legacy, "web-99"},
		{"sprout not accepted", legacy, "pending-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := requestSproutAction(t, saas, cmdRunRequest(tc.tenant, tc.sprout))
			if reply.Status != controlplane.StatusFailed || reply.ErrorCode != controlplane.ErrorSproutNotFound {
				t.Fatalf("unexpected reply %+v", reply)
			}
		})
	}
	if calls := rec.all(); len(calls) != 0 {
		t.Fatalf("dispatched despite a failed tenant check: %+v", calls)
	}

	reply := requestSproutAction(t, saas, cmdRunRequest(legacy, "web-01"))
	if reply.Status != controlplane.StatusCompleted || reply.TenantID != legacy || reply.SproutID != "web-01" {
		t.Fatalf("unexpected reply for the sprout's own tenant: %+v", reply)
	}
	calls := rec.all()
	if len(calls) != 1 || calls[0].tenantID != legacy {
		t.Fatalf("expected one dispatch bound to %q, got %+v", legacy, calls)
	}
}

// TestSproutAction_DispatchIsBoundToTheVerifiedTenant: sprout IDs are only
// unique per tenant, so with "web-01" in both t_a and t_b, a request for
// t_b must dispatch under t_b (its connection, its Account) and target
// exactly that one sprout — nothing else from the request reaches the
// handler.
func TestSproutAction_DispatchIsBoundToTheVerifiedTenant(t *testing.T) {
	stored := map[[2]string]bool{{"t_a", "web-01"}: true, {"t_b", "web-01"}: true}
	rec := stubSproutActionDispatch(t, func(tenant, sprout string) error {
		if !stored[[2]string{tenant, sprout}] {
			return pki.ErrSproutIDNotFound
		}
		return nil
	})

	req := cmdRunRequest("t_b", "web-01")
	req.Action.Params = json.RawMessage(`{"command":"uptime","args":["-p"],"token":"stolen","target":[{"id":"db-01"}],"stdout":"forged"}`)
	reply := handleSproutAction(mustJSON(t, req))
	if reply.Status != controlplane.StatusCompleted {
		t.Fatalf("unexpected reply %+v", reply)
	}
	calls := rec.all()
	if len(calls) != 1 || calls[0].tenantID != "t_b" {
		t.Fatalf("expected one dispatch under t_b, got %+v", calls)
	}
	var ta struct {
		Target []pki.KeyManager `json:"target"`
		Action map[string]any   `json:"action"`
		Token  string           `json:"token"`
	}
	if err := json.Unmarshal(calls[0].params, &ta); err != nil {
		t.Fatalf("decoding dispatched params: %v", err)
	}
	if len(ta.Target) != 1 || ta.Target[0].SproutID != "web-01" {
		t.Fatalf("dispatched targets = %+v, want exactly web-01", ta.Target)
	}
	if ta.Token != "" || ta.Action["stdout"] != "" || ta.Action["stream_topic"] != nil {
		t.Fatalf("request fields beyond the sanitized action reached the handler: %s", calls[0].params)
	}

	if reply := handleSproutAction(mustJSON(t, cmdRunRequest("t_c", "web-01"))); reply.ErrorCode != controlplane.ErrorSproutNotFound {
		t.Fatalf("t_c has no web-01; got %+v", reply)
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("expected no further dispatch, got %d calls", n)
	}
}

func TestSproutAction_RejectsBeforeDispatch(t *testing.T) {
	enableSelfUpdate(t) // so self_update's params are what's checked
	rec := stubSproutActionDispatch(t, func(tenant, sprout string) error {
		switch {
		case !pki.IsValidTenantID(tenant):
			return pki.ErrTenantIDInvalid
		case !pki.IsValidSproutID(sprout):
			return pki.ErrSproutIDInvalid
		}
		return nil
	})
	action := func(typ, params string) controlplane.SproutAction {
		return controlplane.SproutAction{Type: typ, Params: json.RawMessage(params)}
	}
	for _, tc := range []struct {
		name string
		data []byte
		want controlplane.ErrorCode
	}{
		{"malformed JSON", []byte(`{not json`), controlplane.ErrorInvalidRequest},
		{"self_update without artifact_url or checksum", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("self_update", `{"version":"v2"}`)}), controlplane.ErrorInvalidRequest},
		{"self_update params not an object", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("self_update", `[]`)}), controlplane.ErrorInvalidRequest},
		{"unknown type", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("shell.start", `{}`)}), controlplane.ErrorUnsupportedAction},
		{"missing type", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01"}), controlplane.ErrorUnsupportedAction},
		{"bad tenant ID", mustJSON(t, controlplane.SproutActionRequest{TenantID: "../t_1", SproutID: "web-01", Action: action("cmd.run", `{"command":"uptime"}`)}), controlplane.ErrorInvalidRequest},
		{"bad sprout ID", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "../web", Action: action("cmd.run", `{"command":"uptime"}`)}), controlplane.ErrorInvalidRequest},
		{"sprout ID with underscore", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web_01", Action: action("cmd.run", `{"command":"uptime"}`)}), controlplane.ErrorInvalidRequest},
		{"cmd.run params not an object", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cmd.run", `"uptime"`)}), controlplane.ErrorInvalidRequest},
		{"cmd.run without command", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cmd.run", `{}`)}), controlplane.ErrorInvalidRequest},
		{"cmd.run with stream_topic", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cmd.run", `{"command":"uptime","stream_topic":"imas.sprouts.db-01.cmd.run"}`)}), controlplane.ErrorInvalidRequest},
		{"cmd.run timeout too long", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cmd.run", `{"command":"uptime","timeout":36000000000000}`)}), controlplane.ErrorInvalidRequest},
		{"cmd.run negative timeout", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cmd.run", `{"command":"uptime","timeout":-1}`)}), controlplane.ErrorInvalidRequest},
		{"cook without recipe", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cook", `{}`)}), controlplane.ErrorInvalidRequest},
		{"cook params not an object", mustJSON(t, controlplane.SproutActionRequest{TenantID: "t_1", SproutID: "web-01", Action: action("cook", `[]`)}), controlplane.ErrorInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := handleSproutAction(tc.data)
			if reply.Status != controlplane.StatusFailed || reply.ErrorCode != tc.want {
				t.Fatalf("got %+v, want failed/%s", reply, tc.want)
			}
		})
	}
	if calls := rec.all(); len(calls) != 0 {
		t.Fatalf("an invalid request was dispatched: %+v", calls)
	}
}

// TestSproutAction_ErrorsNeverCarryText mirrors the tenant-provisioning
// rule: a pki or dispatch error's text (paths, SQL) stays in farmer's log.
func TestSproutAction_ErrorsNeverCarryText(t *testing.T) {
	leaky := errors.New(`pki: looking up sprout "web-01" in tenant "t_1": dial tcp 10.0.0.7:3306: /var/lib/imas/pki broke`)
	stubSproutActionDispatch(t, func(string, string) error { return leaky })
	data := handleSproutActionJSON(t, cmdRunRequest("t_1", "web-01"))
	if strings.Contains(data, "10.0.0.7") || strings.Contains(data, "/var/lib") {
		t.Fatalf("raw error text leaked into the reply: %s", data)
	}
	var reply controlplane.SproutActionReply
	_ = json.Unmarshal([]byte(data), &reply)
	if reply.ErrorCode != controlplane.ErrorInternal {
		t.Fatalf("a database error must be internal_error, not a clean not-found; got %+v", reply)
	}

	stubSproutActionDispatch(t, func(string, string) error { return nil })
	dispatchCmdRun = func(string, json.RawMessage) (any, error) { return nil, leaky }
	data = handleSproutActionJSON(t, cmdRunRequest("t_1", "web-01"))
	if strings.Contains(data, "10.0.0.7") || !strings.Contains(data, string(controlplane.ErrorInternal)) {
		t.Fatalf("unexpected reply for a dispatch error: %s", data)
	}
}

// TestSproutAction_CmdRunThroughRealHandler dispatches through the real
// handleCmdRun and cmd.FRun to a fake sprout on the tenant's connection.
func TestSproutAction_CmdRunThroughRealHandler(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	legacy := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	writeNKey(t, "", "accepted", "offline-01", "UKEY_OFFLINE")
	cmd.RegisterFarmerNatsConn(legacy, nc)
	defer cmd.UnregisterFarmerNatsConn(legacy)
	saas := dialSaaSAPI(t, nc)

	// Both sprouts have a box key on record: cmd.run is sealed only, and
	// one without would be refused before anything is sent (FIX.1,
	// sprout_action_fix1_test.go).
	newSealedStubSprout(t, legacy, "offline-01")
	var got apitypes.CmdRun
	var gotMu sync.Mutex
	newSealedStubSprout(t, legacy, "web-01").answer(t, nc, "imas.sprouts.web-01.cmd.run",
		payloadbox.PurposeCmdRunRequest, payloadbox.PurposeCmdRunResponse, func(body []byte) any {
			gotMu.Lock()
			_ = json.Unmarshal(body, &got)
			gotMu.Unlock()
			return apitypes.CmdRun{Stdout: "up 3 days", Stderr: "warn", ErrCode: 3, Duration: time.Second}
		})
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatalf("RegisterSproutAction: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	req := cmdRunRequest(legacy, "web-01")
	req.Action.Params = json.RawMessage(`{"command":"uptime","args":["-p"]}`)
	reply := requestSproutAction(t, saas, req)
	if reply.Status != controlplane.StatusCompleted || reply.ErrorCode != "" || reply.Result == nil {
		t.Fatalf("unexpected reply %+v", reply)
	}
	if *reply.Result != (controlplane.CmdRunResult{Stdout: "up 3 days", Stderr: "warn", ExitCode: 3, Duration: time.Second}) {
		t.Fatalf("result = %+v", *reply.Result)
	}
	gotMu.Lock()
	if got.Command != "uptime" || len(got.Args) != 1 || got.Args[0] != "-p" {
		t.Fatalf("sprout received %+v", got)
	}
	gotMu.Unlock()

	// A registered sprout that doesn't answer.
	reply = requestSproutAction(t, saas, cmdRunRequest(legacy, "offline-01"))
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != controlplane.ErrorSproutUnreachable {
		t.Fatalf("unexpected reply for an offline sprout %+v", reply)
	}
}

// TestSproutAction_CookThroughRealHandler dispatches through the real
// handleCook and its trigger handshake: a dispatched reply means the
// trigger handleCook waits for was sent and answered.
func TestSproutAction_CookThroughRealHandler(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	legacy := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	SetNatsConn(legacy, nc)
	defer ClearNatsConn(legacy)

	if err := RegisterSproutAction(nc); err != nil {
		t.Fatalf("RegisterSproutAction: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	saas := dialSaaSAPI(t, nc)
	// A box key on record: a sprout without one is refused before the
	// cook is prepared (FIX.1, sprout_action_fix1_test.go).
	newSealedStubSprout(t, legacy, "web-01")
	reply := requestSproutAction(t, saas, controlplane.SproutActionRequest{
		TenantID: legacy,
		SproutID: "web-01",
		Action:   controlplane.SproutAction{Type: controlplane.ActionCook, Params: json.RawMessage(`{"recipe":"nginx.harden"}`)},
	})
	if reply.Status != controlplane.StatusDispatched || reply.JID == "" || reply.ErrorCode != "" {
		t.Fatalf("unexpected reply %+v", reply)
	}

	// No tenant connection: handleCook can't dispatch.
	ClearNatsConn(legacy)
	reply = handleSproutAction(mustJSON(t, controlplane.SproutActionRequest{
		TenantID: legacy,
		SproutID: "web-01",
		Action:   controlplane.SproutAction{Type: controlplane.ActionCook, Params: json.RawMessage(`{"recipe":"nginx.harden"}`)},
	}))
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != controlplane.ErrorInternal {
		t.Fatalf("unexpected reply with no tenant connection %+v", reply)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func handleSproutActionJSON(t *testing.T, req controlplane.SproutActionRequest) string {
	t.Helper()
	return string(mustJSON(t, handleSproutAction(mustJSON(t, req))))
}

func TestSproutActionConcurrency_FromEnv(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want int
	}{
		{"", defaultSproutActionConcurrency},
		{"8", 8},
		{" 16 ", 16},
		{"1", 1},
		{"1024", maxSproutActionConcurrency},
		{"5000", maxSproutActionConcurrency},
		{"0", defaultSproutActionConcurrency},
		{"-3", defaultSproutActionConcurrency},
		{"lots", defaultSproutActionConcurrency},
		{"8.5", defaultSproutActionConcurrency},
	} {
		t.Setenv(EnvSproutActionConcurrency, tc.env)
		if got := sproutActionConcurrency(); got != tc.want {
			t.Errorf("%s=%q: got %d, want %d", EnvSproutActionConcurrency, tc.env, got, tc.want)
		}
	}
}
