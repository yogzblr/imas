package client

import (
	"encoding/json"
	"fmt"

	apitypes "github.com/yogzblr/imas/internal/api/types"
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
