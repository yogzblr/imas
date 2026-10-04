package cook

// cook over the bus, sealed end to end
// (docs/design/imas-payload-encryption-design.md, workstream J), the same
// way internal/ingredients/cmd's sealed.go seals cmd.run: both ends in
// this file so they can't drift apart.
//
// FLAG FOR SECURITY REVIEW. Two farmer -> sprout requests carry cook:
//
//   - the dispatch on imas.sprouts.<id>.cook: a RecipeEnvelope (the
//     rendered steps the sprout will run, and whatever secrets the recipe
//     templated into them), answered by the sprout's Ack. Sealed under
//     payloadbox.PurposeCookRequest / PurposeCookResponse.
//   - the resync nudge on imas.sprouts.<id>.recipe.nudge (NudgeSubject),
//     which makes the sprout pull its staged recipe over HTTPS
//     (SyncStagedRecipe), answered by an Ack. It carries no recipe, but a
//     bus that could inject one could make a sprout cook a staged recipe
//     it chose to skip. Sealed under PurposeCookNudgeRequest /
//     PurposeCookNudgeResponse, its own pair, so a sealed nudge can never
//     be accepted as a dispatch or the reverse.
//
// Each request and its reply are payloadbox envelopes marked with the
// payloadbox.Header header; the reply names the request's message ID
// (ReplyTo). So a compromised bus can neither read a recipe, forge or
// replay a dispatch, nor answer one dispatch with another's Ack.
//
// Rules each end enforces, as for cmd.run:
//
//   - Farmer seals whenever the sprout has a box key on record. Only a
//     sprout enrolled before workstream J has none; it gets plaintext, as
//     before, with a warning. Any other failure to seal fails the
//     dispatch: never a silent fallback to plaintext.
//   - Farmer only accepts a sealed Ack that opens under its keys and
//     answers this request. A plaintext Ack to a sealed request is an
//     error, never an acknowledgement.
//   - A sprout with payload-encryption keys (pki.SproutBoxReady) refuses
//     a plaintext dispatch or nudge without acting on it, so a bus can't
//     inject one.
//
// Not sealed here: the step events the sprout publishes while it cooks
// (imas.cook.<id>.<jid>, sproutcook.go). They are fire-and-forget
// publishes read in plaintext by farmer's job store, the web UI's log
// stream and the imas CLI, which holds no tenant key; see
// docs/BUILD-STATUS.md.

import (
	"encoding/json"
	"errors"
	"fmt"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// ErrSproutRefusedPayload means the sprout answered a sealed cook
// dispatch or nudge with a payloadbox.ErrorHeader code instead of an Ack.
var ErrSproutRefusedPayload = errors.New("cook: sprout refused the sealed request")

// ErrReplyNotSealed means the sprout answered a sealed cook dispatch or
// nudge in plaintext.
var ErrReplyNotSealed = errors.New("cook: sprout answered a sealed request in plaintext; it may run a build older than sealed cook and needs upgrading")

// CookSubject is the subject farmer dispatches a recipe to sproutID on.
func CookSubject(sproutID string) string { return "imas.sprouts." + sproutID + ".cook" }

// boundary is one sealed farmer -> sprout request/Ack exchange.
type boundary struct {
	name        string
	subject     func(sproutID string) string
	reqPurpose  string
	respPurpose string
}

var (
	cookBoundary  = boundary{"cook", CookSubject, payloadbox.PurposeCookRequest, payloadbox.PurposeCookResponse}
	nudgeBoundary = boundary{"recipe nudge", NudgeSubject, payloadbox.PurposeCookNudgeRequest, payloadbox.PurposeCookNudgeResponse}
)

// request builds farmer's request carrying body to sproutID: sealed, or
// plaintext (body JSON-encoded, nothing for a nil body) for a sprout with
// no box key on record, in which case reqID is empty.
func (b boundary) request(tenantID, sproutID string, body any) (req *nats.Msg, reqID string, err error) {
	req = nats.NewMsg(b.subject(sproutID))
	data, reqID, err := pki.SealToSprout(tenantID, sproutID, b.reqPurpose, "", body)
	if errors.Is(err, pki.ErrNoActiveBoxKey) {
		log.Warnf("cook: sending %s to sprout %s in plaintext: it has no payload-encryption key on record (enrolled before workstream J); re-enroll it", b.name, sproutID)
		if body != nil {
			if req.Data, err = json.Marshal(body); err != nil {
				return nil, "", fmt.Errorf("cook: encoding %s for %s: %w", b.name, sproutID, err)
			}
		}
		return req, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("cook: sealing %s for %s: %w", b.name, sproutID, err)
	}
	req.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	req.Data = data
	return req, reqID, nil
}

// ack reads the sprout's Ack from reply, the answer to the request
// request returned with reqID (empty: it was plaintext).
func (b boundary) ack(tenantID, sproutID, reqID string, reply *nats.Msg) (Ack, error) {
	var ack Ack
	if reqID == "" {
		err := json.Unmarshal(reply.Data, &ack)
		return ack, err
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != "" {
		return ack, fmt.Errorf("%w: %s", ErrSproutRefusedPayload, code)
	}
	if reply.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return ack, ErrReplyNotSealed
	}
	m, err := pki.OpenFromSprout(tenantID, sproutID, b.respPurpose, reply.Data)
	if err != nil {
		return ack, fmt.Errorf("cook: opening %s reply from %s: %w", b.name, sproutID, err)
	}
	if m.ReplyTo != reqID {
		return ack, fmt.Errorf("cook: opening %s reply from %s: %w", b.name, sproutID, payloadbox.ErrOpen)
	}
	err = json.Unmarshal(m.Body, &ack)
	return ack, err
}

// open is the sprout's side: it returns the opened request's message if
// m is acceptable on this boundary, or the refusal to send back. A nil
// message and nil refusal mean m is a plaintext request to a sprout with
// no keys (enrolled before workstream J), to be handled as before.
func (b boundary) open(sproutID string, m *nats.Msg) (msg *payloadbox.Message, refused *nats.Msg) {
	sealed := m.Header.Get(payloadbox.Header) == payloadbox.HeaderBox1
	ready := pki.SproutBoxReady()
	switch {
	case !sealed && ready:
		log.Warnf("cook: refusing a plaintext %s: this sprout only accepts sealed ones", b.name)
		return nil, refusal(payloadbox.ErrorCodeEncryptionRequired)
	case !sealed:
		return nil, nil
	case !ready:
		log.Warnf("cook: refusing a sealed %s: this sprout has no payload-encryption keys; re-enroll it", b.name)
		return nil, refusal(payloadbox.ErrorCodeNoKeys)
	}
	msg, err := pki.SproutOpenFromFarmer(sproutID, b.reqPurpose, m.Data)
	if err != nil {
		// The reason stays in the local log; farmer and the bus get one
		// code for every way a request can fail to open.
		log.Warnf("cook: refusing a sealed %s: %v", b.name, err)
		return nil, refusal(payloadbox.ErrorCodeOpenFailed)
	}
	return msg, nil
}

// reply is the sprout's sealed Ack to msg, or a refusal if it can't be
// sealed.
func (b boundary) reply(sproutID string, msg *payloadbox.Message, ack Ack) *nats.Msg {
	data, err := pki.SproutSealForFarmer(sproutID, b.respPurpose, msg.ID, ack)
	if err != nil {
		log.Errorf("cook: sealing %s reply: %v", b.name, err)
		return refusal(payloadbox.ErrorCodeInternal)
	}
	r := nats.NewMsg("")
	r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	r.Data = data
	return r
}

func refusal(code string) *nats.Msg {
	r := nats.NewMsg("")
	r.Header.Set(payloadbox.ErrorHeader, code)
	return r
}

func plainAck(ack Ack) *nats.Msg {
	b, _ := json.Marshal(ack)
	return &nats.Msg{Data: b}
}

// RespondCook is the sprout's handler for a message on its own
// imas.sprouts.<id>.cook: it returns the reply to send and, if the
// dispatch was accepted, the envelope to cook (nil if refused). An
// accepted envelope has already been recorded as handled
// (claimPushedEnvelope), so the caller only has to cook it. sproutID is
// the sprout's enrolled ID.
//
// A dispatch of a job the sprout already handled (one listed in the
// handled jobs file, which survives restarts) is not cooked again: it is
// answered with an Ack that isn't Acknowledged, which farmer reports as a
// failed dispatch. With the persisted replay guard (sproutbox.go) this is
// the second of two independent stops on a replayed dispatch (security
// review 2026-10, M2).
//
// Nothing from the opened envelope is logged but its job ID and step
// count: the sprout's log is shipped over the bus in plaintext (H4).
func RespondCook(sproutID string, m *nats.Msg) (*nats.Msg, *RecipeEnvelope) {
	msg, refused := cookBoundary.open(sproutID, m)
	if refused != nil {
		return refused, nil
	}
	var env RecipeEnvelope
	if msg == nil {
		// Enrolled before workstream J: no keys, so plaintext as before.
		_ = json.Unmarshal(m.Data, &env)
		if ok, reply := claimDispatch(env); !ok {
			return plainAck(reply), nil
		}
		return plainAck(Ack{Acknowledged: true, JobID: env.JobID}), &env
	}
	if err := json.Unmarshal(msg.Body, &env); err != nil {
		log.Warnf("cook: refusing a sealed cook: its body does not decode as a recipe envelope")
		return refusal(payloadbox.ErrorCodeOpenFailed), nil
	}
	// Before cooking, so a pull of this job's staged copy (on reconnect
	// or a nudge) never cooks it a second time.
	if ok, reply := claimDispatch(env); !ok {
		return cookBoundary.reply(sproutID, msg, reply), nil
	}
	return cookBoundary.reply(sproutID, msg, Ack{Acknowledged: true, JobID: env.JobID}), &env
}

// claimDispatch records env's job as handled (claimPushedEnvelope) and
// reports whether it may be cooked; if not, ack is the refusal to send.
func claimDispatch(env RecipeEnvelope) (ok bool, ack Ack) {
	fresh, err := claimPushedEnvelope(env.JobID)
	if err != nil {
		log.Errorf("cook: refusing dispatch of job %s: recording it as handled failed: %v", env.JobID, err)
		return false, Ack{Acknowledged: false, JobID: env.JobID}
	}
	if !fresh {
		log.Warnf("cook: refusing dispatch of job %s: this sprout already handled it", env.JobID)
		return false, Ack{Acknowledged: false, JobID: env.JobID}
	}
	log.Infof("cook: accepted job %s (%d steps)", env.JobID, len(env.Steps))
	return true, Ack{}
}

// RespondNudge is the sprout's handler for a message on its own
// NudgeSubject: it returns the reply to send and whether the nudge was
// accepted, in which case the caller pulls its staged recipe
// (SyncStagedRecipe).
func RespondNudge(sproutID string, m *nats.Msg) (*nats.Msg, bool) {
	msg, refused := nudgeBoundary.open(sproutID, m)
	if refused != nil {
		return refused, false
	}
	if msg == nil {
		return plainAck(Ack{Acknowledged: true}), true
	}
	return nudgeBoundary.reply(sproutID, msg, Ack{Acknowledged: true}), true
}
