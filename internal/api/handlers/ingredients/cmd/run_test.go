package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	icmd "github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/pki"
)

// setupCmdTestPKI wires up an in-memory PKI store (see
// internal/pki/store.go) plus a dummy farmer pub key, so pki lifecycle
// calls (via addCmdTestSprout) don't hit ReloadNKeys' log.Fatalf path.
func setupCmdTestPKI(t *testing.T) string {
	t.Helper()

	dsn := "file:" + t.Name() + "-pki?mode=memory&cache=shared"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening pki test db: %v", err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })

	dir := t.TempDir()
	config.FarmerPKI = dir + "/"
	farmerPubFile := filepath.Join(dir, "farmer.pub")
	if err := os.WriteFile(farmerPubFile, []byte("UFAKE_FARMER_KEY_FOR_TESTING"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeyFarmerPubFile = farmerPubFile
	pki.NatsServer = nil
	return dir
}

// addCmdTestSprout registers id as an accepted sprout with the given nkey,
// via the same lifecycle pki.UnacceptNKey/AcceptNKey handlers use in
// production. dir is unused (kept so existing call sites don't need to
// change) now that PKI state lives in PXC, not on disk.
func addCmdTestSprout(t *testing.T, _, state, id, nkey string) {
	t.Helper()
	if state != "accepted" {
		t.Fatalf("addCmdTestSprout: unsupported state %q", state)
	}
	if err := pki.UnacceptNKey(pki.CurrentTenantID(), id, nkey); err != nil {
		t.Fatalf("UnacceptNKey(%q): %v", id, err)
	}
	if err := pki.AcceptNKey(pki.CurrentTenantID(), id); err != nil {
		t.Fatalf("AcceptNKey(%q): %v", id, err)
	}
}

// startCmdTestNATS starts an embedded NATS server, registers the connection
// with the ingredients/cmd package, and returns the nats.Conn plus a cleanup func.
func startCmdTestNATS(t *testing.T) (*nats.Conn, func()) {
	t.Helper()
	opts := &natsserver.Options{
		Host: "127.0.0.1",
		Port: -1,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	conn, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		t.Fatalf("connect to test NATS: %v", err)
	}
	// HCmdRun dispatches through cmd.FRun using pki.CurrentTenantID() (the
	// HTTP admin API's documented ceiling — see
	// docs/design/imas-tenant-context-threading.md), so tests register the
	// farmer-side connection under that same tenant.
	tenantID := pki.CurrentTenantID()
	icmd.RegisterFarmerNatsConn(tenantID, conn)
	return conn, func() {
		icmd.UnregisterFarmerNatsConn(tenantID)
		conn.Close()
		ns.Shutdown()
	}
}

func TestHCmdRun_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader([]byte("bad json")))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHCmdRun_InvalidAction(t *testing.T) {
	// Valid TargetedAction but action is a string, not a CmdRun object
	body := []byte(`{"target":[{"id":"sprout1"}],"action":"not-a-cmd-object"}`)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHCmdRun_InvalidSproutID(t *testing.T) {
	setupCmdTestPKI(t)

	body := []byte(`{"target":[{"id":"INVALID-CAPS"}],"action":{"command":"echo","args":["hello"]}}`)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHCmdRun_SproutIDWithUnderscore(t *testing.T) {
	setupCmdTestPKI(t)

	body := []byte(`{"target":[{"id":"bad_underscore"}],"action":{"command":"echo","args":["hello"]}}`)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHCmdRun_UnknownSprout(t *testing.T) {
	setupCmdTestPKI(t)

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "unknown-sprout"}},
		Action: map[string]interface{}{"command": "echo", "args": []string{"hello"}},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHCmdRun_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader([]byte("")))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
}

func TestHCmdRun_MultipleTargetsOneInvalid(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "good-sprout", "UKEY1")

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{
			{SproutID: "good-sprout"},
			{SproutID: "BAD-ID"},
		},
		Action: map[string]interface{}{"command": "echo"},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- Success-path tests using embedded NATS ---

func TestHCmdRun_SingleSproutSuccess(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "sprout1", "UKEY1")

	conn, cleanup := startCmdTestNATS(t)
	defer cleanup()

	// Mock the sprout responding to cmd.run
	mockResp := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"hello"},
		Stdout:  "hello\n",
		ErrCode: 0,
	}
	respBytes, _ := json.Marshal(mockResp)
	sub, err := conn.Subscribe("imas.sprouts.sprout1.cmd.run", func(msg *nats.Msg) {
		_ = msg.Respond(respBytes)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	conn.Flush()

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "sprout1"}},
		Action: map[string]interface{}{"command": "echo", "args": []string{"hello"}},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var results apitypes.TargetedResults
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if results.Results == nil {
		t.Fatal("expected non-nil results map")
	}
	if _, ok := results.Results["sprout1"]; !ok {
		t.Fatal("expected result for sprout1")
	}
}

func TestHCmdRun_MultipleSproutsSuccess(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "sprout1", "UKEY1")
	addCmdTestSprout(t, dir, "accepted", "sprout2", "UKEY2")

	conn, cleanup := startCmdTestNATS(t)
	defer cleanup()

	// Mock both sprouts
	mockResp := apitypes.CmdRun{
		Command: "hostname",
		Stdout:  "test-host\n",
		ErrCode: 0,
	}
	respBytes, _ := json.Marshal(mockResp)
	for _, topic := range []string{
		"imas.sprouts.sprout1.cmd.run",
		"imas.sprouts.sprout2.cmd.run",
	} {
		sub, err := conn.Subscribe(topic, func(msg *nats.Msg) {
			_ = msg.Respond(respBytes)
		})
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		defer sub.Unsubscribe()
	}
	conn.Flush()

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{
			{SproutID: "sprout1"},
			{SproutID: "sprout2"},
		},
		Action: map[string]interface{}{"command": "hostname"},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var results apitypes.TargetedResults
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(results.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results.Results))
	}
	for _, id := range []string{"sprout1", "sprout2"} {
		if _, ok := results.Results[id]; !ok {
			t.Fatalf("missing result for %s", id)
		}
	}
}

func TestHCmdRun_NATSTimeout(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "slow-sprout", "UKEY1")

	conn, cleanup := startCmdTestNATS(t)
	defer cleanup()

	// Subscribe but never respond — causes NATS request timeout
	sub, err := conn.Subscribe("imas.sprouts.slow-sprout.cmd.run", func(msg *nats.Msg) {
		// intentionally do nothing
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	conn.Flush()

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "slow-sprout"}},
		Action: map[string]interface{}{"command": "sleep", "args": []string{"100"}},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	// Handler still returns 200 with error in results
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (error in results), got %d", w.Code)
	}

	var results apitypes.TargetedResults
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if _, ok := results.Results["slow-sprout"]; !ok {
		t.Fatal("expected result entry for slow-sprout even on timeout")
	}
}

func TestHCmdRun_InvalidJSONResponse(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "garbled-sprout", "UKEY1")

	conn, cleanup := startCmdTestNATS(t)
	defer cleanup()

	// Respond with garbage data
	sub, err := conn.Subscribe("imas.sprouts.garbled-sprout.cmd.run", func(msg *nats.Msg) {
		_ = msg.Respond([]byte("not-json"))
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	conn.Flush()

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "garbled-sprout"}},
		Action: map[string]interface{}{"command": "echo"},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	// FRun returns an unmarshal error, but handler still returns 200
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHCmdRun_EmptyTargets(t *testing.T) {
	setupCmdTestPKI(t)

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{},
		Action: map[string]interface{}{"command": "echo"},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	// No targets means the validation loop is skipped and we go straight to
	// the empty results path → 200 with empty results map
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var results apitypes.TargetedResults
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(results.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results.Results))
	}
}

func TestHCmdRun_NilAction(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "sprout1", "UKEY1")

	conn, cleanup := startCmdTestNATS(t)
	defer cleanup()

	// null action decodes to zero-value CmdRun (empty command), which
	// still goes through the success path. The sprout mock just echoes back.
	mockResp := apitypes.CmdRun{ErrCode: 0}
	respBytes, _ := json.Marshal(mockResp)
	sub, err := conn.Subscribe("imas.sprouts.sprout1.cmd.run", func(msg *nats.Msg) {
		_ = msg.Respond(respBytes)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	conn.Flush()

	body := []byte(`{"target":[{"id":"sprout1"}],"action":null}`)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	// null action decodes to zero CmdRun → proceeds to NATS → 200
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHCmdRun_MultipleTargetsOneUnregistered(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "real-sprout", "UKEY1")

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{
			{SproutID: "real-sprout"},
			{SproutID: "ghost-sprout"},
		},
		Action: map[string]interface{}{"command": "echo"},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	// First target is valid, second is unregistered → early 404
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHCmdRun_SproutWithErrorResponse(t *testing.T) {
	dir := setupCmdTestPKI(t)
	addCmdTestSprout(t, dir, "accepted", "err-sprout", "UKEY1")

	conn, cleanup := startCmdTestNATS(t)
	defer cleanup()

	// Sprout responds with a non-zero exit code
	mockResp := apitypes.CmdRun{
		Command: "false",
		Stdout:  "",
		Stderr:  "command failed",
		ErrCode: 1,
	}
	respBytes, _ := json.Marshal(mockResp)
	sub, err := conn.Subscribe("imas.sprouts.err-sprout.cmd.run", func(msg *nats.Msg) {
		_ = msg.Respond(respBytes)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	conn.Flush()

	ta := apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "err-sprout"}},
		Action: map[string]interface{}{"command": "false"},
	}
	body, _ := json.Marshal(ta)
	req := httptest.NewRequest(http.MethodPost, "/cmd/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	HCmdRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var results apitypes.TargetedResults
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	raw, ok := results.Results["err-sprout"]
	if !ok {
		t.Fatal("expected result for err-sprout")
	}
	// Verify the error code propagated
	resultMap, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", raw)
	}
	if errCode, ok := resultMap["errcode"].(float64); !ok || int(errCode) != 1 {
		t.Fatalf("expected errcode=1, got %v", resultMap["errcode"])
	}
}
