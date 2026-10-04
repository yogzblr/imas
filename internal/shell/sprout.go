package shell

// The sprout's end of sealed shell (leg 2). FLAG FOR SECURITY REVIEW.
//
// A start is acted on only if it is a sealed f2s.shell.start that opens
// under this sprout's keys, for its pinned tenant and its own sprout ID,
// fresh and never seen before (pki.SproutOpenFromFarmer, which runs the
// persisted replay guard). Anything else spawns nothing:
//
//   - a plaintext start is refused (encryption-required), whether or not
//     this sprout has box keys: there is no plaintext shell at all (owner
//     decision 2026-10-04). On Windows, a sprout without keys still gets
//     the old "not supported" answer, which leaks nothing either way;
//   - a sealed start on a sprout without keys gets no-keys;
//   - one that doesn't open, or whose body doesn't decode, gets
//     open-failed (the reason stays in the local log).
//
// A start that opened is answered sealed (s2f.shell.start, bound to the
// start's ID), either with the sprout's ephemeral key or with a fixed
// refusal code from local policy (shell-disabled, shell-not-allowed,
// too-many-sessions, unsupported, spawn-failed), so the bus learns
// nothing from it. The sprout logs a session's ID, who opened it and why
// it ended, never what was typed or printed: its log is shipped over the
// bus in plaintext.

import (
	"encoding/json"
	"sync"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// Sprout serves shell starts for one enrolled sprout.
type Sprout struct {
	id string
	nc *nats.Conn
	// Stream tunes each session's stream (tests shorten its timers).
	Stream payloadbox.StreamOptions

	mu       sync.Mutex
	sessions map[string]*sproutSession
}

// NewSprout returns the shell server for sproutID (its enrolled ID) on
// nc. Subscribe its HandleStart on StartSubject(sproutID).
func NewSprout(nc *nats.Conn, sproutID string) *Sprout {
	return &Sprout{id: sproutID, nc: nc, sessions: map[string]*sproutSession{}}
}

// Active is how many sessions are running.
func (sp *Sprout) Active() int {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return len(sp.sessions)
}

// HandleStart is the handler for imas.sprouts.<id>.shell.start.
func (sp *Sprout) HandleStart(m *nats.Msg) {
	reply, run := sp.respond(m)
	if err := m.RespondMsg(reply); err != nil {
		log.Errorf("shell: answering a start: %v", err)
		if run != nil {
			run.abort()
		}
		return
	}
	if run != nil {
		go run.run()
	}
}

// respond decides the reply to a start and, if a session was spawned,
// returns it to run once the reply is on its way.
func (sp *Sprout) respond(m *nats.Msg) (*nats.Msg, *sproutSession) {
	sealed := m.Header.Get(payloadbox.Header) == payloadbox.HeaderBox1
	ready := pki.SproutBoxReady()
	switch {
	case !sealed:
		log.Warnf("shell: refusing a plaintext start: shell sessions are sealed only")
		return plaintextRefusal(ready), nil
	case !ready:
		log.Warnf("shell: refusing a sealed start: this sprout has no payload-encryption keys; re-enroll it")
		return refusal(payloadbox.ErrorCodeNoKeys), nil
	}
	msg, err := pki.SproutOpenFromFarmer(sp.id, payloadbox.PurposeShellStart, m.Data)
	if err != nil {
		log.Warnf("shell: refusing a sealed start: %v", err)
		return refusal(payloadbox.ErrorCodeOpenFailed), nil
	}
	var body StartBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		log.Warnf("shell: refusing a sealed start: its body does not decode")
		return refusal(payloadbox.ErrorCodeOpenFailed), nil
	}
	answer, sess := sp.spawn(msg, &body)
	if answer.Error != "" {
		log.Warnf("shell: refusing session %s for %s: %s", safeID(body.SessionID), userLabel(body.User), answer.Error)
	}
	data, err := pki.SproutSealForFarmer(sp.id, payloadbox.PurposeShellStartReply, msg.ID, answer)
	if err != nil {
		log.Errorf("shell: sealing the start reply: %v", err)
		if sess != nil {
			sess.abort()
		}
		return refusal(payloadbox.ErrorCodeInternal), nil
	}
	reply := nats.NewMsg("")
	reply.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	reply.Data = data
	return reply, sess
}

func refusal(code string) *nats.Msg {
	reply := nats.NewMsg("")
	reply.Header.Set(payloadbox.ErrorHeader, code)
	return reply
}

// safeID is id if it is a well-formed session ID, for logging.
func safeID(id string) string {
	if ValidSessionID(id) {
		return id
	}
	return "(invalid)"
}

func userLabel(u StartUser) string {
	if u.Name != "" {
		return u.Name + " (" + u.Pubkey + ")"
	}
	return u.Pubkey
}

// validStart checks what a sealed start must carry, whatever the
// platform.
func validStart(msg *payloadbox.Message, body *StartBody) bool {
	if !ValidSessionID(body.SessionID) || body.User.Pubkey == "" || msg.TenantID == "" {
		return false
	}
	if len(body.FarmerEphPub) != 32 {
		return false
	}
	var k [32]byte
	copy(k[:], body.FarmerEphPub)
	if payloadbox.CheckPublicKey(&k) != nil {
		return false
	}
	_, err := payloadbox.EncodeTerminalSize(body.Cols, body.Rows)
	return err == nil && ValidShellPath(body.Shell)
}
