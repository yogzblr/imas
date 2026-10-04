package natsapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	nats "github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// cookTriggerWindow is how long a cook waits for its trigger.
var cookTriggerWindow = 15 * time.Second

// ErrCookAlreadyTriggered: a second trigger for a job that already ran.
var ErrCookAlreadyTriggered = errors.New("cook: this job was already triggered")

// CookTriggerMethod is the sealed method that starts job jid's dispatch:
// imas.api.cook.trigger.<jid>. The CLI sends it once it is subscribed to
// the job's step events, so it sees them from the first.
//
// The JID is in the subject (and so, sealed, in the request's bound
// method and subject), not only in the params: the replica that created
// the job is the only one holding it, and it alone subscribes to this
// subject, outside the queue group, for cookTriggerWindow. A queue-grouped
// imas.api.cook.trigger would land on any replica.
func CookTriggerMethod(jid string) string { return MethodCookTriggerPrefix + jid }

// cookPlan is a validated cook, ready to dispatch once triggered.
type cookPlan struct {
	command   apitypes.CmdCook
	sproutIDs []string
	dispatch  func(jid string)
}

// prepareCook validates a cook of params in tenantID for invoker (the
// verified user; empty for the SaaS API) and returns its plan.
func prepareCook(tenantID, invoker string, params json.RawMessage) (*cookPlan, error) {
	var ta apitypes.TargetedAction
	if err := json.Unmarshal(params, &ta); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	var command apitypes.CmdCook
	actionBytes, _ := json.Marshal(ta.Action)
	if err := json.Unmarshal(actionBytes, &command); err != nil {
		return nil, fmt.Errorf("invalid cook command: %w", err)
	}

	// Each target's NKey as of now, so each dispatch can check the sprout
	// still has this identity once its recipe is staged (see
	// sproutIdentityGuard).
	nkeys := make(map[string]string, len(ta.Target))
	for _, target := range ta.Target {
		if !pki.IsValidSproutID(target.SproutID) || strings.Contains(target.SproutID, "_") {
			return nil, fmt.Errorf("invalid sprout ID: %s", target.SproutID)
		}
		nkey, err := pki.GetNKey(tenantID, target.SproutID)
		if err != nil {
			return nil, fmt.Errorf("unknown sprout: %s", target.SproutID)
		}
		nkeys[target.SproutID] = nkey
	}

	if natsConnFor(tenantID) == nil {
		return nil, fmt.Errorf("NATS connection not available")
	}

	sproutIDs := make([]string, len(ta.Target))
	for i, t := range ta.Target {
		sproutIDs[i] = t.SproutID
	}
	dispatch := func(jid string) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		errs := make(map[string]error)
		wg.Add(len(ta.Target))

		for _, target := range ta.Target {
			go func(t pki.KeyManager) {
				defer wg.Done()
				cookOpts := []cook.CookOption{
					cook.WithInvoker(invoker),
					cook.WithStageGuard(sproutIdentityGuard(tenantID, t.SproutID, nkeys[t.SproutID])),
				}
				if command.State != "" {
					cookOpts = append(cookOpts, cook.WithTargetStep(cook.StepID(command.State)))
				}
				err := cook.SendCookEvent(tenantID, t.SproutID, command.Recipe, jid, command.Test, cookOpts...)
				if err != nil {
					mu.Lock()
					errs[t.SproutID] = err
					mu.Unlock()
				}
			}(target)
		}
		wg.Wait()
		for sproutID, err := range errs {
			log.Errorf("error cooking recipe for %s: %v", sproutID, err)
		}
	}
	return &cookPlan{command: command, sproutIDs: sproutIDs, dispatch: dispatch}, nil
}

// handleCook is a CLI user's cook: validated now, dispatched when the same
// user sends the job's sealed trigger (awaitCookTrigger). The job is
// attributed to the verified user.
func handleCook(c apiCaller, params json.RawMessage) (any, error) {
	plan, err := prepareCook(c.TenantID, c.UserID, params)
	if err != nil {
		return nil, err
	}
	jid := cook.GenerateJobID()
	if err := awaitCookTrigger(natsConnFor(c.TenantID), c.TenantID, c.UserID, jid, plan.sproutIDs, plan.dispatch); err != nil {
		return nil, err
	}
	plan.command.JID = jid
	return plan.command, nil
}

// localCooks are SaaS API cooks prepareSaaSAPICook made, waiting for
// triggerLocalCook on this replica, keyed on (tenant_id, jid).
var localCooks sync.Map

func localCookKey(tenantID, jid string) string { return tenantID + "\x00" + jid }

// prepareSaaSAPICook is internal.sprout.action's cook (dispatchCook): the
// same validation as a CLI cook, held on this replica until
// triggerLocalCook. The SaaS API tracks the job through farmer.jobs, not
// the event stream, so nothing needs to subscribe before dispatch, and the
// trigger never goes over the bus.
func prepareSaaSAPICook(tenantID string, params json.RawMessage) (any, error) {
	plan, err := prepareCook(tenantID, "", params)
	if err != nil {
		return nil, err
	}
	jid := cook.GenerateJobID()
	key := localCookKey(tenantID, jid)
	localCooks.Store(key, plan.dispatch)
	time.AfterFunc(cookTriggerWindow, func() {
		if _, ok := localCooks.LoadAndDelete(key); ok {
			log.Errorf("timeout waiting for cook trigger on JID %s", jid)
		}
	})
	plan.command.JID = jid
	return plan.command, nil
}

// triggerLocalCook starts the dispatch prepareSaaSAPICook held for jid in
// tenantID (triggerCook), once.
func triggerLocalCook(tenantID, jid string) error {
	v, ok := localCooks.LoadAndDelete(localCookKey(tenantID, jid))
	if !ok {
		return fmt.Errorf("no cook %s waiting in tenant %s", jid, tenantID)
	}
	go v.(func(string))(jid)
	return nil
}

// awaitCookTrigger subscribes, on this replica only, to job jid's sealed
// trigger (CookTriggerMethod) for cookTriggerWindow. The trigger runs
// through the same sealed path as every API request (open under the
// user's registered key, method and subject bound, replay guard, Valkey
// claim), and is accepted only from creator, the user who created the
// job, and only once; it answers with the targeted sprout IDs and starts
// dispatch. A refused trigger (another user, a replay) doesn't use the
// job up.
func awaitCookTrigger(nc *nats.Conn, tenantID, creator, jid string, sproutIDs []string, dispatch func(jid string)) error {
	method := CookTriggerMethod(jid)
	fired := make(chan struct{})
	var once sync.Once
	trigger := func(c apiCaller, _ json.RawMessage) (any, error) {
		if c.UserID != creator {
			return nil, rbac.ErrAccessDenied
		}
		first := false
		once.Do(func() { first = true; close(fired) })
		if !first {
			return nil, ErrCookAlreadyTriggered
		}
		go dispatch(jid)
		return sproutIDs, nil
	}
	sub, err := nc.Subscribe(Subject(method), func(m *nats.Msg) {
		replicaSealedAPI.serve(tenantID, method, trigger, m)
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe for cook trigger: %w", err)
	}
	go func() {
		select {
		case <-fired:
		case <-time.After(cookTriggerWindow):
			log.Errorf("timeout waiting for cook trigger on JID %s", jid)
		}
		_ = sub.Unsubscribe()
	}()
	return nil
}

// sproutIdentityGuard returns a cook.WithStageGuard check that fails once
// sproutID in tenantID no longer holds nkey: deleted, or replaced by a new
// host under the same sprout ID (see handlePKIAccept). The PKI handlers
// remove the staged recipe after such a change; this check catches a
// dispatch that staged its recipe after that removal ran.
func sproutIdentityGuard(tenantID, sproutID, nkey string) func() error {
	return func() error {
		if _, matches := pki.NKeyExists(tenantID, sproutID, nkey); !matches {
			return fmt.Errorf("sprout %s in tenant %s was deleted or replaced during dispatch", sproutID, tenantID)
		}
		return nil
	}
}
