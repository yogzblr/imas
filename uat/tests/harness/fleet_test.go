package harness

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

// fakeFleet starts the fake stack with the contract's six sprouts and
// returns a Fleet wired to it, vmctl.sh included.
func fakeFleet(t *testing.T) (*Fleet, *fakestack.Stack) {
	t.Helper()
	s := fakestack.New()
	t.Cleanup(s.Close)
	s.AddContractHosts()
	dir := t.TempDir()
	if err := s.WriteMaterial(dir, ""); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvVMCtl, "")
	t.Setenv(EnvVMCtlDefault, "")
	env, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFleet(env)
	if err != nil {
		t.Fatal(err)
	}
	f.VM.Exec = func(_ context.Context, args []string) ([]byte, int, error) {
		script := ""
		if len(args) > 2 {
			script = args[2]
		}
		code, out := s.Vmctl(args[0], args[1], script)
		return []byte(out), code, nil
	}
	return f, s
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func TestFleetPrepareAndRun(t *testing.T) {
	f, s := fakeFleet(t)
	if err := f.Prepare(ctx(t)); err != nil {
		t.Fatal(err)
	}
	all := f.Sprouts()
	if len(all) != 6 {
		t.Fatalf("%d sprouts", len(all))
	}
	for _, sp := range all {
		if err := f.Ready(sp); err != nil {
			t.Errorf("%s: %v", sp.VM, err)
		}
		h, _ := s.Host(sp.VM)
		if sp.SproutID != h.SproutID {
			t.Errorf("%s resolved to %q, want %q", sp.VM, sp.SproutID, h.SproutID)
		}
	}
	if got := f.Sprouts(InTenant(2), WithOS(OSAlma)); len(got) != 1 || got[0].VM != "t2-alma" {
		t.Errorf("filter: %+v", got)
	}
	if got := f.Sprouts(Linux()); len(got) != 4 {
		t.Errorf("linux filter: %d", len(got))
	}

	// Prepared twice is a no-op; the links resolve.
	if err := f.Prepare(ctx(t)); err != nil {
		t.Fatal(err)
	}
	tok, err := f.Admin(ctx(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	lk, r, err := f.API.LookupAssets(ctx(t), tok, f.TenantID(1), Assets(f.Sprouts(InTenant(1))))
	if err != nil || r.Status != 200 || len(lk.Results) != 3 {
		t.Fatalf("lookup %+v %v %v", lk, r, err)
	}

	sprouts := f.Sprouts(InTenant(1), Linux())
	b, err := f.Do(ctx(t), 1, sprouts, CmdRunAction(ExitCmd(sprouts[0], 7)))
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range sprouts {
		it, ok := b.For(sp)
		if !ok || it.Status != ItemFailed || it.Error != "command_failed" || it.ExitCode == nil || *it.ExitCode != 7 {
			t.Errorf("%s: %+v", sp.VM, it)
		}
	}
	if err := f.WaitConnected(ctx(t), all, 10*time.Second); err != nil {
		t.Error(err)
	}
	if err := f.WaitRuns(ctx(t), all, 10*time.Second); err != nil {
		t.Error(err)
	}

	// A stopped sprout: not connected, unreachable, and WaitConnected says
	// which.
	sp := sprouts[0]
	if err := f.VM.StopSprout(ctx(t), sp.VM); err != nil {
		t.Fatal(err)
	}
	b, err = f.Do(ctx(t), 1, []Sprout{sp}, CmdRunAction(TrueCmd(sp)))
	if it, _ := b.For(sp); err != nil || it.Error != "sprout_unreachable" {
		t.Errorf("stopped: %+v %v", it, err)
	}
	if err := f.WaitConnected(ctx(t), []Sprout{sp}, time.Second); err == nil || !strings.Contains(err.Error(), sp.VM) {
		t.Errorf("WaitConnected on a stopped sprout: %v", err)
	}
	if err := f.VM.StartSprout(ctx(t), sp.VM); err != nil {
		t.Fatal(err)
	}

	// Out of band: a file a cmd.run made, through vmctl.
	path := sp.TempPath("imas-uat-unit")
	if _, err := f.Do(ctx(t), 1, []Sprout{sp}, CmdRunAction(TouchCmd(sp, path))); err != nil {
		t.Fatal(err)
	}
	fi, err := f.File(ctx(t), sp, path)
	if err != nil || !fi.Exists {
		t.Errorf("file %+v %v", fi, err)
	}
	claims, err := f.HostClaims(ctx(t), sp)
	if err != nil || ClaimString(claims, "tenant_id") != f.TenantID(1) {
		t.Errorf("claims %v %v", claims, err)
	}
}

func TestFleetPrepareRecordsBrokenSprouts(t *testing.T) {
	f, _ := fakeFleet(t)
	// A VM vmctl doesn't know: its sprout can't be resolved, the rest can.
	f.mu.Lock()
	f.sprouts = append(f.sprouts, Sprout{VM: "t1-ghost", Tenant: 1, OS: OSUbuntu, AssetID: "uat-ghost"})
	f.mu.Unlock()
	if err := f.Prepare(ctx(t)); err != nil {
		t.Fatal(err)
	}
	for _, sp := range f.Sprouts() {
		err := f.Ready(sp)
		if sp.VM == "t1-ghost" && err == nil {
			t.Error("the ghost VM should not be ready")
		}
		if sp.VM != "t1-ghost" && err != nil {
			t.Errorf("%s: %v", sp.VM, err)
		}
	}
}

func TestAPIClientAgainstFake(t *testing.T) {
	f, _ := fakeFleet(t)
	c := ctx(t)
	tok, err := f.Admin(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	tid := f.TenantID(1)

	st, r, err := f.API.CreateTenant(c, tok, "unit")
	if err != nil || r.Status != http.StatusAccepted || st.Status != TenantPending {
		t.Fatalf("create %+v %v %v", st, r, err)
	}
	if _, r, _ := f.API.CreateTenant(c, tok, " "); !r.Is(400, "invalid_request") {
		t.Errorf("blank name: %s", r)
	}

	key, err := f.API.MintKey(c, tok, tid, 1, 2)
	if err != nil || !strings.HasPrefix(key.RegistrationKey, key.KeyID+".") {
		t.Fatalf("mint %+v %v", key, err)
	}
	keys, _, err := f.API.ListKeys(c, tok, tid)
	if k, ok := FindKey(keys, key.KeyID); err != nil || !ok || k.State != "active" {
		t.Errorf("list %+v %v", keys, err)
	}
	if r, err := f.API.RevokeKey(c, tok, tid, key.KeyID); err != nil || r.Status != 200 {
		t.Errorf("revoke %v %v", r, err)
	}

	rec, err := f.API.UploadRecipe(c, tok, tid, "uat.unit.one", "steps: {}\n")
	if err != nil || rec.SHA256 == "" {
		t.Fatalf("upload %+v %v", rec, err)
	}
	if _, err := f.API.UploadRecipe(c, tok, tid, "uat.unit.one", "steps: {a: {}}\n"); err != nil {
		t.Errorf("replacing through UploadRecipe: %v", err)
	}
	got, r, err := f.API.GetRecipe(c, tok, tid, "uat.unit.one")
	if err != nil || r.Status != 200 || got.Content == nil || *got.Content != "steps: {a: {}}\n" {
		t.Errorf("get %+v %v %v", got, r, err)
	}
	all, err := f.API.AllRecipes(c, tok, tid)
	if err != nil || len(all) != 1 {
		t.Errorf("all %+v %v", all, err)
	}
	if r, err := f.API.DeleteRecipe(c, tok, tid, "uat.unit.one"); err != nil || r.Status != 204 {
		t.Errorf("delete %v %v", r, err)
	}

	// Another tenant's path: 403 from the organization check.
	r, err = f.API.Do(c, Request{Method: http.MethodGet, Path: TenantPath(f.TenantID(2), "status"), Token: tok})
	if err != nil || !r.Is(403, "forbidden") || NotFoundOrForbidden(r) == false {
		t.Errorf("cross tenant %v %v", r, err)
	}
	// No internal secret: 401.
	r, _ = f.API.Do(c, Request{Method: http.MethodGet, Path: TenantPath(tid, "status"), Token: tok, NoInternalAuth: true})
	if !r.Is(401, "unauthorized") {
		t.Errorf("no secret: %s", r)
	}
}

func TestRetryRateLimited(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":"rate_limited","message":"slow down"}`)
			return
		}
		w.WriteHeader(202)
		fmt.Fprint(w, `{"batch_id":"b_1"}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "s", srv.Client())
	id, err := c.StartBatch(ctx(t), "tok", "t_x", []string{"a"}, CmdRunAction(CmdRun{Cmd: "id"}))
	if err != nil || id != "b_1" || calls.Load() != 3 {
		t.Errorf("id %q err %v calls %d", id, err, calls.Load())
	}

	calls.Store(-100) // always 429 from now on
	err = retryRateLimited(ctx(t), 1500*time.Millisecond, func() (*Response, error) {
		return &Response{Status: 429, Error: APIError{Code: "rate_limited"}}, nil
	}, 200)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("a budget that runs out should fail with the last answer: %v", err)
	}
	err = retryRateLimited(ctx(t), time.Minute, func() (*Response, error) {
		return &Response{Status: 500, Body: []byte("boom")}, nil
	}, 200)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("a 500 is not retried: %v", err)
	}
}

func TestResponseHelpers(t *testing.T) {
	r := &Response{Status: 409, Error: APIError{Code: "asset_link_conflict", Message: "taken"}}
	if r.String() != "HTTP 409 asset_link_conflict: taken" || !r.Is(409, "") || r.Is(409, "x") {
		t.Errorf("%s", r)
	}
	long := &Response{Status: 502, Body: []byte(strings.Repeat("x", 500))}
	if len(long.String()) > 220 {
		t.Errorf("a long body isn't cut: %d", len(long.String()))
	}
	var nilResp *Response
	if nilResp.String() != "no response" || nilResp.Is(200, "") {
		t.Error("nil response")
	}
	if TenantPath("t_a", "sprouts", "a/b", "asset-link") != "/v1/tenants/t_a/sprouts/a%2Fb/asset-link" {
		t.Errorf("TenantPath %s", TenantPath("t_a", "sprouts", "a/b", "asset-link"))
	}
	plain404 := &Response{Status: 404, Body: []byte("404 page not found")}
	if !NotFoundOrForbidden(plain404) || NotFoundOrForbidden(&Response{Status: 404, Error: APIError{Code: "tenant_not_found"}}) {
		t.Error("NotFoundOrForbidden")
	}
	var b *Batch
	if _, ok := b.Item("x"); ok {
		t.Error("a nil batch has no items")
	}
}

func TestRestartCommands(t *testing.T) {
	f, _ := fakeFleet(t)
	c, err := f.RestartCommand("farmer")
	if err != nil || c.VM != "uat-core" || !strings.Contains(c.Command, "app.kubernetes.io/component=farmer") {
		t.Errorf("farmer %+v %v", c, err)
	}
	if c, _ := f.RestartCommand("farmerbus"); c.VM != "uat-dmz" || !strings.Contains(c.Command, "statefulset") {
		t.Errorf("farmerbus %+v", c)
	}
	f.Env.Settings.Restart = map[string]RestartCommand{"envoy": {Command: "docker restart envoy"}}
	if c, _ := f.RestartCommand("envoy"); c.VM != "uat-dmz" || c.Command != "docker restart envoy" {
		t.Errorf("override %+v", c)
	}
	if _, err := f.RestartCommand("nope"); err == nil {
		t.Error("an unknown workload should fail")
	}
	if err := f.RestartWorkload(ctx(t), "farmer"); err != nil {
		t.Errorf("restart through the fake: %v", err)
	}
}
