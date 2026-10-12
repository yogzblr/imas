package natsapi

// E2 (P27.1): every package gets tenant connections from the registry.
// These tests install a real tenantconn.Registry, whose dialer connects
// to an embedded NATS server, as the getter natsapi, cook and the cmd
// ingredient use, then close the tenant's connection the way the idle
// sweeper does (Registry.Sweep) and check that the next cook dispatch,
// sprout action and its audit record succeed by redialing.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/tenantconn"
	"github.com/yogzblr/imas/internal/tenantconn/tenantconntest"
)

// redialBus is a tenant registry whose dialer connects to url, counting
// dials. fail, when set, makes every dial fail with it; gate, when set,
// holds every dial until it is closed.
type redialBus struct {
	url string
	now time.Time

	mu    sync.Mutex
	dials int
	fail  error
	gate  chan struct{}

	reg *tenantconn.Registry
}

const redialIdle = time.Minute

func newRedialBus(t *testing.T, url string) *redialBus {
	t.Helper()
	b := &redialBus{url: url, now: time.Unix(1_700_000_000, 0)}
	b.reg = tenantconn.New(tenantconn.Config{
		Dial:            b.dial,
		IdleTTL:         redialIdle,
		HeartbeatWindow: redialIdle,
		Now:             b.clock,
	})
	t.Cleanup(func() {
		for _, nc := range b.reg.All() {
			nc.Close()
		}
	})
	// The registry is the getter of every package that sends to a
	// tenant's bus, as cmd/farmer's installConnGetter makes it.
	tenantconntest.Use(t, SetConnGetter, b.reg)
	tenantconntest.Use(t, cook.SetFarmerConnGetter, b.reg)
	tenantconntest.Use(t, cmd.SetFarmerConnGetter, b.reg)
	return b
}

func (b *redialBus) clock() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.now
}

func (b *redialBus) dial(ctx context.Context, _ string, onClosed func(*nats.Conn)) (*nats.Conn, error) {
	b.mu.Lock()
	b.dials++
	fail, gate := b.fail, b.gate
	b.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fail != nil {
		return nil, fail
	}
	return nats.Connect(b.url, nats.ClosedHandler(onClosed))
}

func (b *redialBus) dialCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dials
}

// idleClose closes tenantID's connection as the idle sweeper does: the
// clock passes the idle TTL and Sweep runs. It returns the closed
// connection.
func (b *redialBus) idleClose(t *testing.T, tenantID string) *nats.Conn {
	t.Helper()
	nc, err := b.reg.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get(%s): %v", tenantID, err)
	}
	b.mu.Lock()
	b.now = b.now.Add(2 * redialIdle)
	b.mu.Unlock()
	if swept := b.reg.Sweep(); len(swept) != 1 || swept[0] != tenantID {
		t.Fatalf("Sweep closed %v, want [%s]", swept, tenantID)
	}
	if !nc.IsClosed() {
		t.Fatal("the swept connection is still open")
	}
	return nc
}

// auditEntries returns the audit entries written to buf for action.
func auditEntries(t *testing.T, buf *auditBuffer, action string) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// A tenant whose connection the idle sweeper closed is dialled again by
// the next sprout action (cmd.run and cook, each audited) and by a cook
// dispatch, instead of failing as "not connected".
func TestIdleClosedTenantRedialsOnUse(t *testing.T) {
	sys, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	_, s := useStageStore(t)
	origDir := config.RecipeDir
	config.RecipeDir = "recipes"
	t.Cleanup(func() { config.RecipeDir = origDir })
	t.Setenv(cook.RecipeDirEnvVar, "")
	objectstoretest.Seed(t, s, map[string]string{
		"recipes/webserver.imas": "steps:\n  install nginx:\n    cmd.run:\n      - name: echo hi\n",
	})
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")

	auditBuf := &auditBuffer{}
	audit.SetGlobal(audit.NewLogger(auditBuf))
	t.Cleanup(func() { audit.SetGlobal(nil) })
	audit.SetLevel(audit.LevelAll)
	t.Cleanup(func() { audit.SetLevel(audit.LevelWrite) })

	bus := newRedialBus(t, sys.ConnectedUrl())
	// The SaaS API reaches farmer on the SYS connection, not the tenant's.
	if err := RegisterSproutAction(sys); err != nil {
		t.Fatal(err)
	}
	if err := sys.Flush(); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, sys)

	// The sprout, on a connection of its own.
	sproutNC, err := nats.Connect(sys.ConnectedUrl())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sproutNC.Close)
	stub := newSealedStubSprout(t, tenant, "web-01")
	stub.answer(t, sproutNC, "imas.sprouts.web-01.cmd.run", payloadbox.PurposeCmdRunRequest, payloadbox.PurposeCmdRunResponse,
		func([]byte) any { return apitypes.CmdRun{Stdout: "up"} })
	cooked := make(chan string, 4)
	stub.answer(t, sproutNC, "imas.sprouts.web-01.cook", payloadbox.PurposeCookRequest, payloadbox.PurposeCookResponse,
		func(body []byte) any {
			var env cook.RecipeEnvelope
			_ = json.Unmarshal(body, &env)
			cooked <- env.JobID
			return cook.Ack{Acknowledged: true, JobID: env.JobID}
		})
	if err := sproutNC.Flush(); err != nil {
		t.Fatal(err)
	}

	// Sprout action cmd.run after an idle close.
	bus.idleClose(t, tenant)
	before := bus.dialCount()
	reply := requestSproutAction(t, saas, cmdRunRequest(tenant, "web-01"))
	if reply.Status != controlplane.StatusCompleted || reply.Result == nil || reply.Result.Stdout != "up" {
		t.Fatalf("cmd.run after idle close: reply %+v", reply)
	}
	if got := bus.dialCount(); got != before+1 {
		t.Errorf("cmd.run after idle close: %d dials, want %d", got, before+1)
	}

	// Sprout action cook after an idle close: prepared and dispatched.
	bus.idleClose(t, tenant)
	before = bus.dialCount()
	reply = requestSproutAction(t, saas, controlplane.SproutActionRequest{
		TenantID: tenant, SproutID: "web-01",
		Action: controlplane.SproutAction{Type: controlplane.ActionCook, Params: json.RawMessage(`{"recipe":"webserver"}`)},
	})
	if reply.Status != controlplane.StatusDispatched || reply.JID == "" {
		t.Fatalf("cook after idle close: reply %+v", reply)
	}
	select {
	case jid := <-cooked:
		if jid != reply.JID {
			t.Fatalf("sprout cooked %s, want %s", jid, reply.JID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the cook dispatched after an idle close never reached the sprout")
	}
	if got := bus.dialCount(); got != before+1 {
		t.Errorf("cook after idle close: %d dials, want %d (prepare and dispatch share one)", got, before+1)
	}

	// A cook dispatch straight through internal/cook after an idle close.
	bus.idleClose(t, tenant)
	before = bus.dialCount()
	jid := cook.GenerateJobID()
	if err := cook.SendCookEvent(tenant, "web-01", "webserver", jid, false); err != nil {
		t.Fatalf("SendCookEvent after idle close: %v", err)
	}
	if got := <-cooked; got != jid {
		t.Fatalf("sprout cooked %s, want %s", got, jid)
	}
	if got := bus.dialCount(); got != before+1 {
		t.Errorf("SendCookEvent after idle close: %d dials, want %d", got, before+1)
	}

	// Each sprout action's audit record says it succeeded.
	entries := auditEntries(t, auditBuf, auditActionSproutAction)
	if len(entries) != 2 {
		t.Fatalf("%d audit entries for %s, want 2: %s", len(entries), auditActionSproutAction, auditBuf.String())
	}
	for _, e := range entries {
		if !e.Success || e.Error != "" {
			t.Errorf("audit entry %+v, want a success", e)
		}
	}
}

// A dial that fails is returned as the dial's error, wrapped as "not
// connected", from every package; nothing reports a tenant as not
// connected for any other reason.
func TestTenantDialFailureReturnsTheDialError(t *testing.T) {
	sys, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	bus := newRedialBus(t, sys.ConnectedUrl())
	boom := errors.New("bus refused the connection")
	bus.fail = boom

	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, boom) {
			t.Errorf("%s: err = %v, want the dial error", what, err)
			return
		}
		if !strings.Contains(err.Error(), "not connected") {
			t.Errorf("%s: err = %q, want it to say not connected", what, err)
		}
	}
	_, err := tenantConn(tenant)
	check("natsapi", err)
	_, err = cmd.FRun(tenant, pki.KeyManager{SproutID: "web-01"}, apitypes.CmdRun{Command: "uptime"})
	check("cmd.FRun", err)
	check("cook.NudgeSprout", cook.NudgeSprout(tenant, "web-01"))
	check("PublishEncryptedTo", PublishEncryptedTo(tenant, "web-01", "imas.sprouts.web-01.x", payloadbox.PurposeCookRequest, nil))

	reply := handleSproutAction(mustJSON(t, cmdRunRequest(tenant, "web-01")))
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != controlplane.ErrorInternal {
		t.Errorf("sprout action with a failing dial: reply %+v, want failed internal_error", reply)
	}

	// The next use, once the bus is back, dials again.
	bus.mu.Lock()
	bus.fail = nil
	bus.mu.Unlock()
	if _, err := tenantConn(tenant); err != nil {
		t.Fatalf("tenantConn once the bus is back: %v", err)
	}
}

// Two callers that need an unconnected tenant at the same time share one
// dial and get the same connection.
func TestConcurrentTenantUsesShareOneDial(t *testing.T) {
	sys, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	tenant := "t_concurrent"
	bus := newRedialBus(t, sys.ConnectedUrl())
	bus.gate = make(chan struct{})

	type result struct {
		nc  *nats.Conn
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			nc, err := tenantConn(tenant)
			results <- result{nc, err}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for bus.dialCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no dial started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let the second caller reach the in-flight dial before releasing it.
	time.Sleep(50 * time.Millisecond)
	close(bus.gate)
	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatalf("errors: %v, %v", a.err, b.err)
	}
	if a.nc != b.nc {
		t.Error("the two callers got different connections")
	}
	if got := bus.dialCount(); got != 1 {
		t.Errorf("%d dials, want 1", got)
	}
}
