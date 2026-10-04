package cmd

// cmd.run over the bus, sealed end to end
// (docs/design/imas-payload-encryption-design.md, workstream J): the
// first farmer<->sprout boundary moved to ciphertext, both ends in this
// file so they can't drift apart.
//
// FLAG FOR SECURITY REVIEW. A command line (and its env, which can carry
// secrets) goes farmer -> sprout on imas.sprouts.<id>.cmd.run, and its
// stdout/stderr come back on the request's reply inbox. Both legs are
// internal/payloadbox envelopes marked with the payloadbox.Header header:
// the request under purpose f2s.cmd.run, the reply under s2f.cmd.run
// naming the request's message ID, so a compromised bus can neither read
// them, forge or replay a command, nor pass one command's output off as
// another's.
//
// Rules each end enforces:
//
//   - Farmer seals whenever the sprout has a box key on record. Only a
//     sprout enrolled before workstream J has none; it gets plaintext, as
//     before, with a warning (it can't open anything, and re-enrolling
//     fixes it). Any other failure to seal fails the command: never a
//     silent fallback to plaintext.
//   - Farmer only accepts a sealed reply that opens under its keys and
//     answers this request. A plaintext reply to a sealed request is an
//     error, never a result: that is what a sprout built before this
//     change sends back (it can't read the request), and what a bus
//     attempting a downgrade would send.
//   - A sprout with payload-encryption keys (pki.SproutBoxReady) refuses
//     a plaintext cmd.run without running it, so a bus can't inject one.
//   - Live output streaming (CmdRun.StreamTopic) is dropped from sealed
//     requests: it publishes output as it's produced, in plaintext, to a
//     subject the imas CLI reads directly (it holds no tenant key), which
//     is exactly the leak this boundary closes. The complete output still
//     comes back in the sealed reply.

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	nats "github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// ErrSproutRefusedPayload means the sprout answered a sealed cmd.run
// with a payloadbox.ErrorHeader code instead of a result.
var ErrSproutRefusedPayload = errors.New("cmd: sprout refused the sealed request")

// ErrReplyNotSealed means the sprout answered a sealed cmd.run in
// plaintext.
var ErrReplyNotSealed = errors.New("cmd: sprout answered a sealed request in plaintext; it may run a build older than payload encryption and needs upgrading")

func cmdRunSubject(sproutID string) string { return "imas.sprouts." + sproutID + ".cmd.run" }

// frun sends cmdRun to target's sprout over conn and returns its result.
func frun(conn *nats.Conn, tenantID string, target pki.KeyManager, cmdRun apitypes.CmdRun) (apitypes.CmdRun, error) {
	var results apitypes.CmdRun
	timeout := time.Second*15 + cmdRun.Timeout
	topic := cmdRunSubject(target.SproutID)

	if cmdRun.StreamTopic != "" {
		log.Debugf("cmd: not streaming output for %s: live streaming is plaintext, and cmd.run is sealed", target.SproutID)
	}
	sealedReq := cmdRun
	sealedReq.StreamTopic = ""
	data, reqID, err := pki.SealToSprout(tenantID, target.SproutID, payloadbox.PurposeCmdRunRequest, "", sealedReq)
	if errors.Is(err, pki.ErrNoActiveBoxKey) {
		log.Warnf("cmd: sending cmd.run to sprout %s in plaintext: it has no payload-encryption key on record (enrolled before workstream J); re-enroll it", target.SproutID)
		b, _ := json.Marshal(cmdRun)
		msg, err := conn.Request(topic, b, timeout)
		if err != nil {
			return results, err
		}
		err = json.Unmarshal(msg.Data, &results)
		return results, err
	}
	if err != nil {
		return results, fmt.Errorf("cmd: sealing cmd.run for %s: %w", target.SproutID, err)
	}

	req := nats.NewMsg(topic)
	req.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	req.Data = data
	reply, err := conn.RequestMsg(req, timeout)
	if err != nil {
		return results, err
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != "" {
		return results, fmt.Errorf("%w: %s", ErrSproutRefusedPayload, code)
	}
	if reply.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return results, ErrReplyNotSealed
	}
	m, err := pki.OpenFromSprout(tenantID, target.SproutID, payloadbox.PurposeCmdRunResponse, reply.Data)
	if err != nil {
		return results, fmt.Errorf("cmd: opening cmd.run reply from %s: %w", target.SproutID, err)
	}
	if m.ReplyTo != reqID {
		return results, fmt.Errorf("cmd: opening cmd.run reply from %s: %w", target.SproutID, payloadbox.ErrOpen)
	}
	err = json.Unmarshal(m.Body, &results)
	return results, err
}

// RespondCmdRun is the sprout's handler for a message on its own
// imas.sprouts.<id>.cmd.run: it runs the command (SRun) if the request
// is acceptable and returns the reply to send. sproutID is the sprout's
// enrolled ID.
func RespondCmdRun(sproutID string, m *nats.Msg) *nats.Msg {
	sealed := m.Header.Get(payloadbox.Header) == payloadbox.HeaderBox1
	ready := pki.SproutBoxReady()
	switch {
	case !sealed && ready:
		log.Warnf("cmd: refusing a plaintext cmd.run: this sprout only accepts sealed commands")
		return refusal(payloadbox.ErrorCodeEncryptionRequired)
	case !sealed:
		// Enrolled before workstream J: no keys, so plaintext as before.
		var cmdRun apitypes.CmdRun
		_ = json.Unmarshal(m.Data, &cmdRun)
		results, err := SRun(cmdRun)
		if err != nil {
			log.Error(err)
		}
		b, _ := json.Marshal(results)
		return &nats.Msg{Data: b}
	case !ready:
		log.Warnf("cmd: refusing a sealed cmd.run: this sprout has no payload-encryption keys; re-enroll it")
		return refusal(payloadbox.ErrorCodeNoKeys)
	}

	msg, err := pki.SproutOpenFromFarmer(sproutID, payloadbox.PurposeCmdRunRequest, m.Data)
	if err != nil {
		// The reason stays in the local log; farmer and the bus get one
		// code for every way a request can fail to open.
		log.Warnf("cmd: refusing a sealed cmd.run: %v", err)
		return refusal(payloadbox.ErrorCodeOpenFailed)
	}
	var cmdRun apitypes.CmdRun
	if err := json.Unmarshal(msg.Body, &cmdRun); err != nil {
		log.Warnf("cmd: refusing a sealed cmd.run: its body does not decode as a command")
		return refusal(payloadbox.ErrorCodeOpenFailed)
	}
	cmdRun.StreamTopic = ""
	results, err := SRun(cmdRun)
	if err != nil {
		// Not the error itself: the sprout's log is shipped over the
		// bus in plaintext, and exec errors name the command.
		log.Errorf("cmd: sealed cmd.run finished with an error (exit code %d)", results.ErrCode)
	}
	data, err := pki.SproutSealForFarmer(sproutID, payloadbox.PurposeCmdRunResponse, msg.ID, results)
	if err != nil {
		log.Errorf("cmd: sealing cmd.run reply: %v", err)
		return refusal(payloadbox.ErrorCodeInternal)
	}
	reply := nats.NewMsg("")
	reply.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	reply.Data = data
	return reply
}

func refusal(code string) *nats.Msg {
	reply := nats.NewMsg("")
	reply.Header.Set(payloadbox.ErrorHeader, code)
	return reply
}
