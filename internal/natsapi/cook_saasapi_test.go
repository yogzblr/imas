package natsapi

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	apitypes "github.com/yogzblr/imas/internal/api/types"
)

// stubSaaSAPICookPlan replaces prepareSaaSAPICookPlan with prepare,
// restoring it on cleanup.
func stubSaaSAPICookPlan(t *testing.T, prepare func(tenantID, invoker string, params json.RawMessage) (*cookPlan, error)) {
	t.Helper()
	orig := prepareSaaSAPICookPlan
	prepareSaaSAPICookPlan = prepare
	t.Cleanup(func() { prepareSaaSAPICookPlan = orig })
}

// TestRunSproutCookSingleCall: the SaaS API cook is prepared and
// dispatched in one call, with the JID it returns, exactly once and only
// after the prepare; nothing is held for a later trigger.
func TestRunSproutCookSingleCall(t *testing.T) {
	var mu sync.Mutex
	var steps []string
	dispatched := make(chan string, 2)
	stubSaaSAPICookPlan(t, func(tenantID, invoker string, params json.RawMessage) (*cookPlan, error) {
		if tenantID != "t_1" || invoker != "" {
			t.Errorf("prepare(%q, %q), want (t_1, \"\")", tenantID, invoker)
		}
		mu.Lock()
		steps = append(steps, "prepare")
		mu.Unlock()
		return &cookPlan{
			command:   apitypes.CmdCook{Recipe: "base"},
			sproutIDs: []string{"web-01"},
			dispatch: func(jid string) {
				mu.Lock()
				steps = append(steps, "dispatch")
				mu.Unlock()
				dispatched <- jid
			},
		}, nil
	})

	res, err := runSaaSAPICook("t_1", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("runSaaSAPICook: %v", err)
	}
	cmd, ok := res.(apitypes.CmdCook)
	if !ok || cmd.JID == "" || cmd.Recipe != "base" {
		t.Fatalf("result = %#v, want a CmdCook with a JID", res)
	}
	select {
	case jid := <-dispatched:
		if jid != cmd.JID {
			t.Fatalf("dispatched JID %q, returned %q", jid, cmd.JID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cook was not dispatched")
	}
	select {
	case jid := <-dispatched:
		t.Fatalf("dispatched a second time (%s)", jid)
	case <-time.After(50 * time.Millisecond):
	}
	mu.Lock()
	defer mu.Unlock()
	if len(steps) != 2 || steps[0] != "prepare" || steps[1] != "dispatch" {
		t.Fatalf("steps = %v, want [prepare dispatch]", steps)
	}
}

// TestRunSaaSAPICookPrepareFailsDispatchesNothing: a cook that fails
// validation is refused and never dispatched.
func TestRunSaaSAPICookPrepareFailsDispatchesNothing(t *testing.T) {
	bad := errors.New("invalid cook command")
	stubSaaSAPICookPlan(t, func(string, string, json.RawMessage) (*cookPlan, error) { return nil, bad })
	if res, err := runSaaSAPICook("t_1", json.RawMessage(`{}`)); !errors.Is(err, bad) || res != nil {
		t.Fatalf("runSaaSAPICook = %v, %v; want nil, %v", res, err, bad)
	}
}
