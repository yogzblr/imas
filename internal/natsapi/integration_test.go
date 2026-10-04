package natsapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/api/client"
	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// startEmbeddedNATS starts an embedded NATS server for integration tests.
// Returns the nats.Conn and a cleanup function.
func startEmbeddedNATS(t *testing.T) (*nats.Conn, func()) {
	t.Helper()

	opts := &server.Options{
		Host: "127.0.0.1",
		Port: -1,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		t.Fatalf("connect to test NATS: %v", err)
	}

	return nc, func() {
		nc.Close()
		ns.Shutdown()
	}
}

// --- Subscribe integration tests ---

func TestSubscribeRegistersAllRoutes(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Verify we can send a request to a registered route and get a response.
	// Use the version endpoint since it has no external dependencies.
	SetBuildVersion(config.Version{Tag: "v1.0.0-test"})
	defer SetBuildVersion(config.Version{})

	msg, err := nc.Request("imas.api.version", nil, 2*time.Second)
	if err != nil {
		t.Fatalf("request to imas.api.version: %v", err)
	}

	var resp response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}

	b, _ := json.Marshal(resp.Result)
	var ver config.Version
	json.Unmarshal(b, &ver)
	if ver.Tag != "v1.0.0-test" {
		t.Errorf("Tag = %q, want %q", ver.Tag, "v1.0.0-test")
	}
}

// sealedCaller registers a CLI user in tenantID and returns the CLI's
// sealed request function on nc, for tests that go through Subscribe.
// Call it after setupNatsAPIPKI, which swaps the database the user's key
// is stored in.
func sealedCaller(t *testing.T, nc *nats.Conn, tenantID string) func(method string, params any) (json.RawMessage, error) {
	t.Helper()
	setupSealedEnv(t)
	newSealedCLIUserIn(t, tenantID)
	return func(method string, params any) (json.RawMessage, error) {
		return client.SealedRequest(nc, payloadbox.PurposeCLIRequest, method, params, 5*time.Second)
	}
}

func TestSubscribeTestPingRoute(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	setupNatsAPIPKI(t)
	call := sealedCaller(t, nc, tenantID)
	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// test.ping with empty targets is refused by the scope check, even
	// with dangerously_allow_root set: the flag bypasses nothing on the
	// NATS path (owner decision, PR #95).
	params := apitypes.TargetedAction{
		Target: []pki.KeyManager{},
		Action: apitypes.PingPong{Ping: true},
	}
	if _, err := call("test.ping", params); err == nil || !strings.Contains(err.Error(), "no targets specified") {
		t.Fatalf("test.ping with no targets: %v, want refused", err)
	}
}

func TestSubscribeJobsListRoute(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	_, jobCleanup := setupJobStore(t)
	defer jobCleanup()
	call := sealedCaller(t, nc, tenantID)

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if _, err := call("jobs.list", nil); err != nil {
		t.Fatalf("jobs.list: %v", err)
	}
}

func TestSubscribePropsSetGetRoute(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)
	call := sealedCaller(t, nc, tenantID)

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Set a prop via NATS.
	if _, err := call("props.set", PropsParams{SproutID: "integration-sprout", Name: "env", Value: "testing"}); err != nil {
		t.Fatalf("props.set: %v", err)
	}

	// Get it back.
	res, err := call("props.get", PropsParams{SproutID: "integration-sprout", Name: "env"})
	if err != nil {
		t.Fatalf("props.get: %v", err)
	}
	var m map[string]string
	json.Unmarshal(res, &m)
	if m["value"] != "testing" {
		t.Errorf("value = %q, want %q", m["value"], "testing")
	}
}

func TestSubscribeHandlerError(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	_, jobCleanup := setupJobStore(t)
	defer jobCleanup()
	call := sealedCaller(t, nc, tenantID)

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Request a nonexistent job: the handler's error comes back inside the
	// sealed reply.
	if _, err := call("jobs.get", JobsGetParams{JID: "nonexistent-jid"}); err == nil {
		t.Fatal("expected error in response for nonexistent job")
	}
}

func TestSubscribeWithAuditLogging(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	dir := t.TempDir()
	logger, err := audit.NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()
	audit.SetGlobal(logger)
	defer audit.SetGlobal(nil)

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Version request should be logged.
	SetBuildVersion(config.Version{Tag: "audit-test"})
	defer SetBuildVersion(config.Version{})

	msg, err := nc.Request("imas.api.version", nil, 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	var resp response
	json.Unmarshal(msg.Data, &resp)
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
}

// --- probeSprout integration test ---
//
// probeSprout used to be a synchronous NATS request/reply ping to the
// sprout itself; it now reads a Valkey heartbeat key maintained by
// internal/heartbeat's $SYS.ACCOUNT.*.CONNECT/DISCONNECT listener (see
// docs/design/imas-master-plan.md Phase 1), so a live NATS connection to a
// mock sprout no longer drives it either way. internal/heartbeat's own
// test suite covers the event-to-sprout-ID mapping logic; a genuine
// online/offline round trip needs a live Valkey backend, which this
// package's test suite doesn't have (see internal/heartbeat's tests for
// why a fake isn't feasible without one).

func TestProbeSproutNoHeartbeatClient(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	// No Valkey client configured anywhere in this test binary — every
	// sprout must read as offline regardless of NATS connectivity.
	if probeSprout("acme", "test-sprout") {
		t.Error("expected probeSprout to return false with no heartbeat client configured")
	}
}

// --- handleCook integration test ---

func TestHandleCookSuccessWithNATS(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-cook-int", "UKEY_COOK_INT")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	params, _ := json.Marshal(map[string]interface{}{
		"target": []map[string]string{{"id": "sprout-cook-int"}},
		"action": map[string]string{"recipe": "test.recipe"},
	})

	result, err := handleCook(apiCaller{TenantID: tenantID}, params)
	if err != nil {
		t.Fatalf("handleCook: %v", err)
	}

	// Should return a CmdCook with a generated JID.
	cmd, ok := result.(apitypes.CmdCook)
	if !ok {
		t.Fatalf("result type = %T, want apitypes.CmdCook", result)
	}
	if cmd.JID == "" {
		t.Error("expected non-empty JID")
	}
	if cmd.Recipe != "test.recipe" {
		t.Errorf("Recipe = %q, want %q", cmd.Recipe, "test.recipe")
	}
}

// The job's invoker is the verified caller; a "token" or invoker in the
// params is ignored.
func TestHandleCookInvokerIsTheCaller(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-cook-tk", "UKEY_COOK_TK")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	params, _ := json.Marshal(map[string]interface{}{
		"token":   "USOMEONEELSE",
		"invoker": "USOMEONEELSE",
		"target":  []map[string]string{{"id": "sprout-cook-tk"}},
		"action":  map[string]string{"recipe": "deploy.recipe"},
	})

	result, err := handleCook(apiCaller{TenantID: tenantID, UserID: "UOPERATOR"}, params)
	if err != nil {
		t.Fatalf("handleCook: %v", err)
	}

	cmd := result.(apitypes.CmdCook)
	if cmd.JID == "" {
		t.Error("expected non-empty JID")
	}
}

func TestHandleCookMultipleTargets(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-multi-1", "UKEY_M1")
	writeNKey(t, pkiDir, "accepted", "sprout-multi-2", "UKEY_M2")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	params, _ := json.Marshal(map[string]interface{}{
		"target": []map[string]string{
			{"id": "sprout-multi-1"},
			{"id": "sprout-multi-2"},
		},
		"action": map[string]string{"recipe": "multi.recipe"},
	})

	result, err := handleCook(apiCaller{TenantID: tenantID}, params)
	if err != nil {
		t.Fatalf("handleCook: %v", err)
	}

	cmd := result.(apitypes.CmdCook)
	if cmd.JID == "" {
		t.Error("expected non-empty JID")
	}
}

func TestHandleCookTestMode(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-test-mode", "UKEY_TM")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	params, _ := json.Marshal(map[string]interface{}{
		"target": []map[string]string{{"id": "sprout-test-mode"}},
		"action": map[string]interface{}{"recipe": "dry-run.recipe", "test": true},
	})

	result, err := handleCook(apiCaller{TenantID: tenantID}, params)
	if err != nil {
		t.Fatalf("handleCook: %v", err)
	}

	cmd := result.(apitypes.CmdCook)
	if cmd.JID == "" {
		t.Error("expected non-empty JID")
	}
}

func TestHandleCookUnregisteredSprout(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	setupNatsAPIPKI(t)

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	params, _ := json.Marshal(map[string]interface{}{
		"target": []map[string]string{{"id": "unregistered-sprout"}},
		"action": map[string]string{"recipe": "test.recipe"},
	})

	_, err := handleCook(apiCaller{TenantID: tenantID}, params)
	if err == nil {
		t.Fatal("expected error for unregistered sprout")
	}
}

func TestHandleCookInvalidJSONWithNATS(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	_, err := handleCook(apiCaller{TenantID: tenantID}, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- handleSproutsList with NATS (probeSprout path) ---

// TestHandleSproutsListWithConnectedSprout used to mock a sprout
// responding to a ping and assert Connected=true; Connected now reflects
// a Valkey heartbeat key (see internal/heartbeat) instead of a live NATS
// round trip, so with no Valkey client configured in this test binary
// every accepted sprout reads as offline regardless of NATS connectivity
// — see the comment above TestProbeSproutNoHeartbeatClient.
func TestHandleSproutsListWithConnectedSprout(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-connected", "UKEY_CONN")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	result, err := handleSproutsList(adminCaller(t, tenantID), nil)
	if err != nil {
		t.Fatalf("handleSproutsList: %v", err)
	}

	m := result.(map[string][]SproutInfo)
	found := false
	for _, s := range m["sprouts"] {
		if s.ID == "sprout-connected" {
			found = true
			if s.Connected {
				t.Error("expected Connected=false with no heartbeat client configured")
			}
			break
		}
	}
	if !found {
		t.Error("sprout-connected not in list")
	}
}

func TestHandleSproutsGetWithNATS(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-get-int", "UKEY_GET_INT")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	params, _ := json.Marshal(pki.KeyManager{SproutID: "sprout-get-int"})
	result, err := handleSproutsGet(tenantID, params)
	if err != nil {
		t.Fatalf("handleSproutsGet: %v", err)
	}

	info := result.(SproutInfo)
	if info.ID != "sprout-get-int" {
		t.Errorf("ID = %q, want %q", info.ID, "sprout-get-int")
	}
	if info.Connected {
		t.Error("expected Connected=false with no heartbeat client configured")
	}
	if info.KeyState != "accepted" {
		t.Errorf("KeyState = %q, want %q", info.KeyState, "accepted")
	}
}

// --- handleJobsCancel with NATS ---

func TestHandleJobsCancelWithNATS(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	obj, jobCleanup := setupJobStore(t)
	defer jobCleanup()

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	// Create a running job (no completed steps = running status).
	steps := []cook.StepCompletion{
		{ID: "s1", Started: time.Now()},
	}
	writeTestJob(t, obj, "sprout-cancel-int", "jid-cancel-int", steps)

	// Subscribe to capture the cancel message.
	cancelReceived := make(chan bool, 1)
	nc.Subscribe("imas.sprouts.sprout-cancel-int.cancel", func(msg *nats.Msg) {
		cancelReceived <- true
	})
	nc.Flush()

	params, _ := json.Marshal(JobsGetParams{JID: "jid-cancel-int"})
	result, err := handleJobsCancel(adminCaller(t, tenantID), params)
	if err != nil {
		t.Fatalf("handleJobsCancel: %v", err)
	}

	m, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("result type = %T, want map[string]string", result)
	}
	if m["jid"] != "jid-cancel-int" {
		t.Errorf("jid = %q, want %q", m["jid"], "jid-cancel-int")
	}

	// Verify cancel was published.
	select {
	case <-cancelReceived:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("cancel message not received within timeout")
	}
}

// --- Unique tests from PR branch ---

func TestHandleCookTriggerAndSendEvents(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-cook-trigger", "UKEY_COOK_TRIGGER")

	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	defer ClearNatsConn(tenantID)

	setupSealedEnv(t)
	creator := newSealedCLIUserIn(t, tenantID)

	params := json.RawMessage(`{"target":[{"id":"sprout-cook-trigger"}],"action":{"recipe":"deploy.app"}}`)
	result, err := handleCook(apiCaller{TenantID: tenantID, UserID: creator.id}, params)
	if err != nil {
		t.Fatalf("handleCook: %v", err)
	}

	b, _ := json.Marshal(result)
	var cmd struct {
		JID string `json:"jid"`
	}
	json.Unmarshal(b, &cmd)

	// A plaintext trigger, as the CLI sent before J.3, is refused.
	plain, err := nc.Request(Subject(CookTriggerMethod(cmd.JID)), []byte(`{"jid":"`+cmd.JID+`"}`), 5*time.Second)
	if err != nil {
		t.Fatalf("plaintext trigger: %v", err)
	}
	if plain.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeEncryptionRequired {
		t.Fatalf("plaintext trigger answered %v %q", plain.Header, plain.Data)
	}

	// Another registered user may not fire someone else's job.
	newSealedCLIUserIn(t, tenantID)
	if _, err := client.TriggerCook(nc, cmd.JID); err == nil || !strings.Contains(err.Error(), rbac.ErrAccessDenied.Error()) {
		t.Fatalf("another user's trigger: %v, want access denied", err)
	}

	// The creator's sealed trigger answers with the sprout IDs.
	creator.use(t)
	sproutIDs, err := client.TriggerCook(nc, cmd.JID)
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if len(sproutIDs) != 1 || sproutIDs[0] != "sprout-cook-trigger" {
		t.Errorf("trigger response = %v, want [sprout-cook-trigger]", sproutIDs)
	}
}
