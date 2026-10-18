package jobs

import (
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/log"
)

// CLIListener records job results into a CLIStore. It is used by the
// imas CLI to maintain a local copy of job execution data. It reads no
// bus subject itself: the CLI holds no tenant key, so it gets step events
// from farmer over the sealed farmer-to-CLI leg (internal/api/client's
// FollowJobs) and hands each one to Record.
type CLIListener struct {
	store   *CLIStore
	userKey string
}

// NewCLIListener creates a listener that will record job results into the
// given CLIStore. userKey is the public key of the current CLI user.
func NewCLIListener(store *CLIStore, userKey string) *CLIListener {
	return &CLIListener{
		store:   store,
		userKey: userKey,
	}
}

// RecordJobInit records the initial metadata for a job that the current
// user just initiated (via cook command).
func (l *CLIListener) RecordJobInit(jid, recipe string, sproutIDs []string) {
	for _, sproutID := range sproutIDs {
		meta := CLIJobMeta{
			JID:       jid,
			SproutID:  sproutID,
			Recipe:    recipe,
			UserKey:   l.userKey,
			CreatedAt: time.Now(),
		}
		if err := l.store.RecordJobStart(meta); err != nil {
			log.Errorf("CLI job store: failed to record job start for %s/%s: %v", sproutID, jid, err)
		}
	}
}

// Record appends one step event of job jid on sproutID, as farmer
// forwarded it.
func (l *CLIListener) Record(sproutID, jid string, step cook.StepCompletion) {
	if err := l.store.AppendStep(sproutID, jid, step); err != nil {
		log.Errorf("CLI job store: failed to append step for %s/%s: %v", sproutID, jid, err)
	}
}
