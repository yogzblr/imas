package natsapi

// Security review 2026-10 fixes on internal.sprout.action (SEC.5; FLAG FOR
// SECURITY REVIEW): farmer's own self_update switch (L1), the tenant's
// rollout window enforced by farmer (L1), and per-tenant caps with a
// reserved self_update pool and a non-blocking refusal (M5).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetcatalog/fleetcatalogtest"
)

// The codes saasapi keeps verbatim (internal/saasapi, farmerErrorCode).
func TestSproutActionErrorCodeValues(t *testing.T) {
	for code, want := range map[controlplane.ErrorCode]string{
		ErrorSelfUpdateDisabled:  "self_update_disabled",
		ErrorRolloutWindowClosed: "rollout_window_closed",
		ErrorFarmerBusy:          "farmer_busy",
	} {
		if string(code) != want {
			t.Errorf("%s, want %s", code, want)
		}
	}
}

func TestSelfUpdateEnabledFromEnv(t *testing.T) {
	for env, want := range map[string]bool{
		"": false, "false": false, "0": false, "yes": false, "on": false, "treu": false,
		"true": true, "1": true, " TRUE ": true,
	} {
		t.Setenv(EnvSelfUpdateEnabled, env)
		if got := selfUpdateEnabledFromEnv(); got != want {
			t.Errorf("%s=%q: %v, want %v", EnvSelfUpdateEnabled, env, got, want)
		}
	}
}

// TestSelfUpdate_DisabledByDefault: with IMAS_SELF_UPDATE_ENABLED unset, a
// self_update for an approved, signed version is refused before the
// tenant, the sprout or the catalog is looked at; cmd.run is unaffected.
func TestSelfUpdate_DisabledByDefault(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	var verified atomic.Int32
	rec := stubSproutActionDispatch(t, func(string, string) error { verified.Add(1); return nil })
	newSUCatalog(t)                    // turns the switch on...
	t.Setenv(EnvSelfUpdateEnabled, "") // ...and the environment turns it off again
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, nc)

	reply := requestSproutAction(t, saas, controlplane.SproutActionRequest{TenantID: suTenant, SproutID: "web-01",
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, controlplane.SelfUpdateParams{Version: suVersion})}})
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != ErrorSelfUpdateDisabled || reply.JID != "" {
		t.Fatalf("reply = %+v, want failed/self_update_disabled", reply)
	}
	if verified.Load() != 0 || len(rec.all()) != 0 {
		t.Fatalf("a disabled self_update was looked up (%d) or dispatched (%+v)", verified.Load(), rec.all())
	}
	if reply := requestSproutAction(t, saas, cmdRunRequest(suTenant, "web-01")); reply.Status != controlplane.StatusCompleted {
		t.Fatalf("cmd.run with self_update off: %+v", reply)
	}
}

// fixSelfUpdateNow pins farmer's rollout window clock to now for the test.
func fixSelfUpdateNow(t *testing.T, now time.Time) {
	t.Helper()
	prev := selfUpdateNow
	selfUpdateNow = func() time.Time { return now }
	t.Cleanup(func() { selfUpdateNow = prev })
}

// TestSelfUpdate_RolloutWindowEnforcedByFarmer: farmer refuses a
// self_update outside the tenant's window, as saasapi does, and fails
// closed when it can't read the window or the row is corrupt. End to end
// with the switch on: handleSproutAction -> checkSelfUpdateRelease ->
// fleetcatalog.SQL's RolloutWindow over the saas schema -> dispatch.
func TestSelfUpdate_RolloutWindowEnforcedByFarmer(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	fixSelfUpdateNow(t, now)

	type windowCase struct {
		name  string
		setup func(c *suCatalog)
		want  controlplane.ErrorCode // "" means dispatched
	}
	// The table saasapi's policyRefusal is tested against too, its two
	// one-NULL (corrupt) rows included: internal_error, not "no window".
	var cases []windowCase
	for _, wc := range fleetcatalogtest.WindowCases(now) {
		want := controlplane.ErrorCode("")
		switch {
		case wc.Corrupt:
			want = controlplane.ErrorInternal
		case wc.Closed:
			want = ErrorRolloutWindowClosed
		}
		cases = append(cases, windowCase{wc.Name, func(c *suCatalog) {
			fleetcatalogtest.SetWindow(c.t, c.db, suTenant, wc.Start, wc.End)
		}, want})
	}
	cases = append(cases,
		// Two tenants with different windows: only the sprout's own
		// tenant's is read, both ways round.
		windowCase{"own window open, another tenant's closed", func(c *suCatalog) {
			c.setWindow(suTenant, now.Add(-time.Hour), now.Add(time.Hour))
			c.setWindow("t_other", now.Add(-2*time.Hour), now.Add(-time.Hour))
		}, ""},
		windowCase{"own window closed, another tenant's open", func(c *suCatalog) {
			c.setWindow(suTenant, now.Add(-2*time.Hour), now.Add(-time.Hour))
			c.setWindow("t_other", now.Add(-time.Hour), now.Add(time.Hour))
		}, ErrorRolloutWindowClosed},
		windowCase{"window read fails", func(c *suCatalog) {
			fleetcatalog.Install(fixedWindowCatalog{SQL: fleetcatalog.New(c.db), err: errCatalogDown})
		}, controlplane.ErrorInternal},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
			c, _, approve := newSUCatalog(t)
			approve("t_other", ptr(suVersion))
			tc.setup(c)
			reply := handleSproutAction(suRequest(t, suTenant, "web-01", controlplane.SelfUpdateParams{Version: suVersion}))
			if tc.want != "" {
				assertRefused(t, reply, rec, tc.want)
				return
			}
			if reply.Status != controlplane.StatusDispatched || len(rec.all()) != 1 {
				t.Fatalf("reply = %+v, dispatched %+v", reply, rec.all())
			}
		})
	}
}

// TestCheckSelfUpdateRelease_RolloutWindow: checkSelfUpdateRelease over
// the real catalog passes inside the window and refuses outside it.
func TestCheckSelfUpdateRelease_RolloutWindow(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	fixSelfUpdateNow(t, now)
	c, _, _ := newSUCatalog(t)

	c.setWindow(suTenant, now.Add(-time.Hour), now.Add(time.Hour))
	if code, err := checkSelfUpdateRelease(t.Context(), suTenant, suVersion); err != nil || code != "" {
		t.Fatalf("inside the window: %q, %v", code, err)
	}
	c.setWindow(suTenant, now.Add(time.Hour), now.Add(2*time.Hour))
	if code, err := checkSelfUpdateRelease(t.Context(), suTenant, suVersion); err == nil || code != ErrorRolloutWindowClosed {
		t.Fatalf("outside the window: %q, %v", code, err)
	}
}

// TestCheckRolloutWindow covers what the end-to-end path can't reach.
func TestCheckRolloutWindow(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	c, _, _ := newSUCatalog(t)
	sqlCat := fleetcatalog.New(c.db)
	for _, tc := range []struct {
		name string
		cat  fleetcatalog.Catalog
		want controlplane.ErrorCode
	}{
		// The policy row went away after the approved version was read.
		{"no policy row", sqlCat, controlplane.ErrorInternal},
		{"inside", fixedWindowCatalog{SQL: sqlCat, start: &start, end: &end, ok: true}, ""},
		// A Catalog other than fleetcatalog.SQL that hands back one end.
		{"start only from another catalog", fixedWindowCatalog{SQL: sqlCat, start: &start, ok: true}, controlplane.ErrorInternal},
		{"end only from another catalog", fixedWindowCatalog{SQL: sqlCat, end: &end, ok: true}, controlplane.ErrorInternal},
		{"read fails", fixedWindowCatalog{SQL: sqlCat, err: errCatalogDown}, controlplane.ErrorInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, err := checkRolloutWindow(t.Context(), tc.cat, "t_nopolicy", now)
			if code != tc.want || (err != nil) != (tc.want != "") {
				t.Fatalf("%q, %v; want %q", code, err, tc.want)
			}
		})
	}
}

// fixedWindowCatalog is the SQL catalog with a fixed RolloutWindow answer.
type fixedWindowCatalog struct {
	fleetcatalog.SQL
	start, end *time.Time
	ok         bool
	err        error
}

func (c fixedWindowCatalog) RolloutWindow(context.Context, string) (*time.Time, *time.Time, bool, error) {
	return c.start, c.end, c.ok, c.err
}

func TestSproutActionLimiter(t *testing.T) {
	l := newSproutActionLimiter(3, 2, 2)
	var held []func()
	take := func(tenant, typ string) bool {
		rel, why := l.tryAcquire(tenant, typ)
		if why != "" {
			return false
		}
		held = append(held, rel)
		return true
	}
	cmd, su := controlplane.ActionCmdRun, controlplane.ActionSelfUpdate
	if !take("t_a", cmd) || !take("t_a", controlplane.ActionCook) {
		t.Fatal("t_a's first two refused")
	}
	if take("t_a", cmd) {
		t.Fatal("t_a got a third slot past its cap of 2")
	}
	if !take("t_b", cmd) {
		t.Fatal("t_b refused while the pool had room")
	}
	if take("t_c", cmd) {
		t.Fatal("t_c got a slot in a full pool")
	}
	// The self_update pool is separate, with its own per-tenant count.
	if !take("t_a", su) || !take("t_c", su) {
		t.Fatal("self_update refused while its pool had room")
	}
	if take("t_d", su) {
		t.Fatal("self_update pool overfilled")
	}
	// Release is idempotent and frees exactly one slot.
	held[0]()
	held[0]()
	if !take("t_c", cmd) || take("t_d", cmd) {
		t.Fatal("releasing one slot freed the wrong number")
	}
	for _, rel := range held {
		rel()
	}
	for _, p := range l.pools {
		if p.used != 0 || len(p.byTenant) != 0 {
			t.Fatalf("pool left with %d used, tenants %v", p.used, p.byTenant)
		}
	}
}

// TestSproutAction_HostileTenantFillsItsCap is security review M5's
// scenario on a real bus: a tenant floods long cmd.runs. It gets its cap,
// the rest of its requests are refused at once with farmer_busy (the
// subscription never blocks behind them), and meanwhile another tenant's
// cmd.run and a rollout wave's self_updates, the hostile tenant's own
// included, still go through.
func TestSproutAction_HostileTenantFillsItsCap(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	stubSproutActionDispatch(t, func(string, string) error { return nil })
	_, _, approve := newSUCatalog(t)
	approve("t_hostile", ptr(suVersion))
	t.Setenv(EnvSproutActionConcurrency, "4")
	t.Setenv(EnvSproutActionTenantConcurrency, "2")
	t.Setenv(EnvSelfUpdateConcurrency, "2")

	release := make(chan struct{})
	var hostileRunning atomic.Int32
	dispatchCmdRun = func(tenant string, params json.RawMessage) (any, error) {
		if tenant == "t_hostile" {
			hostileRunning.Add(1)
			<-release
		}
		var ta apitypes.TargetedAction
		_ = json.Unmarshal(params, &ta)
		return apitypes.TargetedResults{Results: map[string]any{ta.Target[0].SproutID: apitypes.CmdRun{}}}, nil
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, nc)

	const flood = 6
	replies := make(chan controlplane.SproutActionReply, flood)
	for i := range flood {
		data := mustJSON(t, cmdRunRequest("t_hostile", fmt.Sprintf("web-%02d", i)))
		go func() {
			msg, err := saas.Request(controlplane.SubjectSproutAction, data, 10*time.Second)
			var r controlplane.SproutActionReply
			if err == nil {
				_ = json.Unmarshal(msg.Data, &r)
			}
			replies <- r
		}()
	}
	// flood minus the cap are refused at once, unrun.
	deadline := time.After(3 * time.Second)
	for i := 0; i < flood-2; i++ {
		select {
		case r := <-replies:
			if r.Status != controlplane.StatusFailed || r.ErrorCode != ErrorFarmerBusy || r.TenantID != "t_hostile" {
				t.Fatalf("over-cap reply = %+v, want failed/farmer_busy", r)
			}
		case <-deadline:
			t.Fatalf("only %d of %d over-cap requests were refused promptly", i, flood-2)
		}
	}
	for hostileRunning.Load() != 2 {
		select {
		case <-deadline:
			t.Fatalf("hostile tenant has %d running, want its cap of 2", hostileRunning.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Another tenant, while the hostile one holds its cap.
	if r := requestSproutAction(t, saas, cmdRunRequest(suTenant, "web-01")); r.Status != controlplane.StatusCompleted {
		t.Fatalf("other tenant's cmd.run: %+v", r)
	}
	// A rollout wave: the reserved pool, for the other tenant and for the
	// hostile tenant's own rollout.
	for _, tenant := range []string{suTenant, "t_hostile"} {
		r := requestSproutAction(t, saas, controlplane.SproutActionRequest{TenantID: tenant, SproutID: "web-01",
			Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, controlplane.SelfUpdateParams{Version: suVersion})}})
		if r.Status != controlplane.StatusDispatched {
			t.Fatalf("%s self_update while cmd.run is saturated: %+v", tenant, r)
		}
	}

	close(release)
	for i := 0; i < 2; i++ {
		select {
		case r := <-replies:
			if r.Status != controlplane.StatusCompleted {
				t.Fatalf("held cmd.run: %+v", r)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the hostile tenant's admitted requests never finished")
		}
	}
	// Its slots are free again.
	if r := requestSproutAction(t, saas, cmdRunRequest("t_hostile", "web-01")); r.Status != controlplane.StatusCompleted {
		t.Fatalf("after release: %+v", r)
	}
}

// TestSproutAction_FullPoolStillAdmitsSelfUpdate: several tenants, each
// within its cap, fill the cmd.run/cook pool. A further tenant is refused
// (farmer_busy, pool full), and self_update still has its reserved pool.
func TestSproutAction_FullPoolStillAdmitsSelfUpdate(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	stubSproutActionDispatch(t, func(string, string) error { return nil })
	_, _, approve := newSUCatalog(t)
	approve("t_c", ptr(suVersion))
	t.Setenv(EnvSproutActionConcurrency, "2")
	t.Setenv(EnvSproutActionTenantConcurrency, "1")
	t.Setenv(EnvSelfUpdateConcurrency, "1")

	release := make(chan struct{})
	var running atomic.Int32
	dispatchCmdRun = func(_ string, params json.RawMessage) (any, error) {
		running.Add(1)
		<-release
		var ta apitypes.TargetedAction
		_ = json.Unmarshal(params, &ta)
		return apitypes.TargetedResults{Results: map[string]any{ta.Target[0].SproutID: apitypes.CmdRun{}}}, nil
	}
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, nc)
	done := make(chan *nats.Msg, 2)
	for _, tenant := range []string{"t_a", "t_b"} {
		data := mustJSON(t, cmdRunRequest(tenant, "web-01"))
		go func() {
			msg, _ := saas.Request(controlplane.SubjectSproutAction, data, 10*time.Second)
			done <- msg
		}()
	}
	for deadline := time.Now().Add(3 * time.Second); running.Load() != 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("%d running, want 2", running.Load())
		}
	}
	if r := requestSproutAction(t, saas, cmdRunRequest("t_c", "web-01")); r.Status != controlplane.StatusFailed || r.ErrorCode != ErrorFarmerBusy {
		close(release)
		t.Fatalf("t_c with the pool full: %+v, want farmer_busy", r)
	}
	r := requestSproutAction(t, saas, controlplane.SproutActionRequest{TenantID: "t_c", SproutID: "web-01",
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, controlplane.SelfUpdateParams{Version: suVersion})}})
	close(release)
	if r.Status != controlplane.StatusDispatched {
		t.Fatalf("self_update with the cmd.run pool full: %+v", r)
	}
	for range 2 {
		if msg := <-done; msg == nil {
			t.Fatal("an admitted cmd.run got no reply")
		}
	}
}

// TestSproutAction_BusyReplyCarriesNoText: like every other refusal, the
// reply holds only tenant_id, sprout_id, status and the fixed code.
func TestSproutAction_BusyReplyCarriesNoText(t *testing.T) {
	r := refuseBusy(cmdRunRequest("t_1", "web-01"), nil, "tenant \"t_1\" already has 8 in flight")
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if r.ErrorCode != ErrorFarmerBusy || r.Status != controlplane.StatusFailed || len(m) != 4 {
		t.Fatalf("busy reply = %s", b)
	}
}
