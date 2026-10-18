package cook

// Cook step events, sealed by the sprout (security review P6;
// docs/design/imas-payload-encryption-design.md, Decision 6). FLAG FOR
// SECURITY REVIEW.
//
// While it cooks, the sprout publishes one event per step, plus the
// start-<jid> and completed-<jid> (or timeout-<jid>) bookends, on
// imas.cook.<sprout_id>.<jid>. Each is a payloadbox envelope, purpose
// payloadbox.PurposeCookStep, sealed from the sprout's box key to its
// pinned tenant key, whose body (StepEvent) names the job. So a
// compromised bus can't read a step's change notes or errors, and can't
// forge a result: an event farmer can't open under the sprout's box key
// is refused, plaintext included, with no fallback.
//
// OpenStepEvent is the one check every farmer-side reader runs: the job
// store's listener (internal/jobs, which also refuses a replay, on this
// replica and cluster-wide) and the follow that forwards events to a CLI
// user (internal/natsapi's jobs.follow, f2c.cook.step). The imas CLI and
// imas serve hold no tenant key and never read imas.cook.* themselves.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// StepEventSubjectPattern is the wildcard farmer subscribes to for every
// sprout's step events.
const StepEventSubjectPattern = "imas.cook.*.*"

// StepEventSubject is where sproutID publishes job jid's step events.
func StepEventSubject(sproutID, jid string) string { return "imas.cook." + sproutID + "." + jid }

// StepEvent is the sealed body of a step event.
type StepEvent struct {
	// JobID is the job the event is for: the subject's last token, bound
	// inside the box, so a bus can't move an event to another job.
	JobID string         `json:"jid"`
	Step  StepCompletion `json:"step"`
}

// ErrPlaintextStepEvent: a step event arrived without the payloadbox
// marker. Refused from every sprout. The sprout runs a build older than
// sealed step events and needs an upgrade.
var ErrPlaintextStepEvent = errors.New("cook: plaintext step event refused; the sprout runs a build that can't seal its step events and needs an upgrade")

// stepPublisher is the part of *nats.Conn publishStepEvent uses.
type stepPublisher interface {
	PublishMsg(m *nats.Msg) error
}

// sproutStepPublisher is the sprout's bus connection (RegisterNatsConn),
// or nil before it has one.
func sproutStepPublisher() stepPublisher {
	if conn == nil {
		return nil
	}
	return conn
}

// publishStepEvent seals completion, a step event of job jid, from
// sproutID to farmer and publishes it on p. Nothing is published in
// plaintext: a failure to seal (no box keys) is logged and the event
// dropped. Only the step's ID goes in the log, never its notes or error.
func publishStepEvent(p stepPublisher, sproutID, jid string, completion StepCompletion) {
	if p == nil {
		return
	}
	data, err := pki.SproutSealForFarmer(sproutID, payloadbox.PurposeCookStep, "", StepEvent{JobID: jid, Step: completion})
	if err != nil {
		log.Errorf("cook: not publishing the event of step %s of job %s: sealing it: %v", completion.ID, jid, err)
		return
	}
	m := nats.NewMsg(StepEventSubject(sproutID, jid))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	if err := p.PublishMsg(m); err != nil {
		log.Errorf("cook: publishing the event of step %s of job %s: %v", completion.ID, jid, err)
	}
}

// OpenedStepEvent is a step event that passed OpenStepEvent.
type OpenedStepEvent struct {
	SproutID string
	JobID    string
	// EventID is the sprout's message ID: unique per event, so a reader
	// can drop a duplicate.
	EventID string
	Step    StepCompletion
	// msg is the opened message, for a replay guard.
	msg *payloadbox.Message
}

// Message is the opened payloadbox message, for the caller's replay guard
// and cluster-wide claim.
func (e *OpenedStepEvent) Message() *payloadbox.Message { return e.msg }

// StepEventSubjectIDs returns the sprout and job IDs in subject, which
// must be exactly imas.cook.<sprout_id>.<jid> with a valid sprout ID and a
// non-empty job ID.
func StepEventSubjectIDs(subject string) (sproutID, jid string, ok bool) {
	parts := strings.Split(subject, ".")
	if len(parts) != 4 || parts[0] != "imas" || parts[1] != "cook" || parts[3] == "" {
		return "", "", false
	}
	if !pki.IsValidSproutID(parts[2]) {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// OpenStepEvent checks m, a message on imas.cook.<sprout_id>.<jid> on
// tenantID's connection, and returns the event. It must be:
//
//   - on a well-formed subject (StepEventSubjectIDs);
//   - marked sealed (else ErrPlaintextStepEvent);
//   - a payloadbox envelope that opens under one of the subject's
//     sprout's box keys on record, active or in grace, against tenantID's
//     keys (pki.OpenFromSprout): purpose s2f.cook.step, tenant tenantID,
//     sprout ID the subject's, no ReplyTo;
//   - for the subject's job (StepEvent.JobID);
//   - fresh: IssuedAt within payloadbox.DefaultMaxSkew.
//
// Replay is the caller's: a reader that records the event runs it
// through its replay guard and a cluster-wide claim (internal/jobs).
func OpenStepEvent(tenantID string, m *nats.Msg) (*OpenedStepEvent, error) {
	if tenantID == "" {
		return nil, errors.New("cook: step event on a connection with no tenant")
	}
	sproutID, jid, ok := StepEventSubjectIDs(m.Subject)
	if !ok {
		return nil, fmt.Errorf("cook: step event on unexpected subject %q", m.Subject)
	}
	if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, ErrPlaintextStepEvent
	}
	msg, err := pki.OpenFromSprout(tenantID, sproutID, payloadbox.PurposeCookStep, m.Data)
	if err != nil {
		return nil, err
	}
	if msg.ReplyTo != "" {
		return nil, payloadbox.ErrOpen
	}
	if err := payloadbox.CheckFresh(msg); err != nil {
		return nil, err
	}
	var ev StepEvent
	if err := json.Unmarshal(msg.Body, &ev); err != nil {
		return nil, fmt.Errorf("cook: decoding a sealed step event: %w", err)
	}
	if ev.JobID != jid {
		return nil, fmt.Errorf("cook: sealed step event names job %q, not the subject's", ev.JobID)
	}
	return &OpenedStepEvent{SproutID: sproutID, JobID: jid, EventID: msg.ID, Step: ev.Step, msg: msg}, nil
}

// The farmer-to-CLI leg (U3). The imas CLI and imas serve hold no tenant
// key, so they never read imas.cook.* themselves. A user asks farmer to
// follow a job (or every job they may view) with the sealed jobs.follow
// request, naming a stream ID of their choosing; farmer opens each event
// (OpenStepEvent), checks the user may view its sprout, and forwards it on
// FollowSubject(stream) as an f2c.cook.step message sealed to the user's
// CLI box key, naming the jobs.follow request's ID (ReplyTo) and carrying
// a FollowedStepEvent. The CLI opens only what is sealed to its key and
// answers its own request.

// FollowSubjectPrefix is the prefix of every follow stream's subject.
const FollowSubjectPrefix = "imas.stream.cli."

// FollowSubject is the subject farmer forwards stream's events on.
func FollowSubject(stream string) string { return FollowSubjectPrefix + stream }

// ValidStreamID reports whether s is a follow stream ID: 32 lowercase hex
// digits (128 random bits, payloadbox.NewID's form), so it is one subject
// token with no wildcard.
func ValidStreamID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// ValidFollowJobID reports whether jid can name the job a follow is for:
// one subject token, no wildcard. Empty means every job.
func ValidFollowJobID(jid string) bool {
	return len(jid) <= 128 && !strings.ContainsAny(jid, ".*> \t\r\n")
}

// FollowedStepEvent is the sealed body of an f2c.cook.step message.
type FollowedStepEvent struct {
	// Stream is the follow stream's subject the event was sealed for, so
	// a bus can't move it to another stream of the same user.
	Stream   string         `json:"stream"`
	SproutID string         `json:"sid"`
	JobID    string         `json:"jid"`
	EventID  string         `json:"eid"`
	Step     StepCompletion `json:"step"`
}
