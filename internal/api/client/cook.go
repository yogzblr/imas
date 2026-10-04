package client

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

func Cook(target string, cmdCook apitypes.CmdCook) (apitypes.CmdCook, error) {
	targets, err := ResolveTargets(target)
	if err != nil {
		return cmdCook, err
	}

	var ta apitypes.TargetedAction
	ta.Action = cmdCook
	ta.Target = make([]pki.KeyManager, len(targets))
	for i, sprout := range targets {
		ta.Target[i] = pki.KeyManager{SproutID: sprout}
	}

	resp, err := NatsRequest("cook", ta)
	if err != nil {
		return cmdCook, err
	}
	if err := json.Unmarshal(resp, &cmdCook); err != nil {
		return cmdCook, fmt.Errorf("cook: %w", err)
	}
	return cmdCook, nil
}

// CookTriggerTimeout is how long TriggerCook waits; farmer holds a cook
// for its trigger for 15 seconds.
var CookTriggerTimeout = 15 * time.Second

// TriggerCook starts job jid's dispatch with its sealed trigger,
// imas.api.cook.trigger.<jid>, sent on nc: the connection the caller
// subscribed to the job's step events on, so that subscription is ahead
// of the trigger on the wire. Farmer accepts it only from the user who
// created the job. It returns the targeted sprout IDs.
func TriggerCook(nc *nats.Conn, jid string) ([]string, error) {
	resp, err := SealedRequest(nc, payloadbox.PurposeCLIRequest, "cook.trigger."+jid, map[string]string{"jid": jid}, CookTriggerTimeout)
	if err != nil {
		return nil, err
	}
	var sprouts []string
	if err := json.Unmarshal(resp, &sprouts); err != nil {
		return nil, fmt.Errorf("cook trigger: %w", err)
	}
	return sprouts, nil
}

// Resync nudges the target's sprouts to pull their staged recipe and cook
// it if they missed its push (farmer's cook.resync). Each sprout's entry
// in the results is an apitypes.ResyncResult.
func Resync(target string) (apitypes.TargetedResults, error) {
	var tr apitypes.TargetedResults
	targets, err := ResolveTargets(target)
	if err != nil {
		return tr, err
	}
	var ta apitypes.TargetedAction
	ta.Target = make([]pki.KeyManager, len(targets))
	for i, sprout := range targets {
		ta.Target[i] = pki.KeyManager{SproutID: sprout}
	}
	resp, err := NatsRequest("cook.resync", ta)
	if err != nil {
		return tr, err
	}
	if err := json.Unmarshal(resp, &tr); err != nil {
		return tr, fmt.Errorf("cook.resync: %w", err)
	}
	return tr, nil
}
