package cook

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// nudgeTimeout bounds how long NudgeSprout waits for the sprout's Ack.
const nudgeTimeout = 10 * time.Second

// NudgeSprout asks sproutID, over tenantID's own connection, to pull its
// staged recipe now (the sprout side is SyncStagedRecipe) and waits for
// its Ack. The Ack only says the sprout will pull: whether it then cooks
// the recipe depends on whether it already handled that job and how old
// the job is. An operator uses this to resync sprouts, e.g. after a
// dispatch they missed while disconnected, without re-dispatching.
func NudgeSprout(tenantID, sproutID string) error {
	conn := farmerConnFor(tenantID)
	if conn == nil {
		return fmt.Errorf("cook: no NATS connection registered for tenant %s", tenantID)
	}
	msg, err := conn.Request(NudgeSubject(sproutID), nil, nudgeTimeout)
	if err != nil {
		return fmt.Errorf("cook: nudging sprout %s: %w", sproutID, err)
	}
	var ack Ack
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return fmt.Errorf("cook: decoding sprout %s's nudge ack: %w", sproutID, err)
	}
	if !ack.Acknowledged {
		return errors.New("cook: sprout did not acknowledge the nudge")
	}
	return nil
}
