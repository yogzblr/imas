// Package fleetkeys serves imas-fleet-signing's current valid public key
// versions to sprouts over their own NATS connection, on
// imas.sprouts.<id>.fleetsigningkeys (design doc §2.5, "Key rotation").
//
// Why live, not only pinned: the release signing key rotates in OpenBao
// Transit, and a sprout that only ever trusted the key set it pinned at
// enrollment would refuse every release signed by a later version. The
// root of trust for a sprout is already its connection to farmer — TLS
// pinned to SproutRootCA, authenticated with its tenant-Account NATS User
// JWT — so the signing key is fetched through that connection, the same
// way Envoy re-reads internal/gatewayjwt's JWKS on rotation.
//
// FLAG FOR SECURITY REVIEW. Who can answer a sprout's request on this
// subject: whoever may subscribe to imas.sprouts.<id>.fleetsigningkeys in
// that tenant's Account — farmer, and any other User with the
// imas.> allow-all template (the imas CLI in the legacy tenant). Other
// sprouts can't: their Sub grant is their own imas.sprouts.<their id>.>
// only. Since cmd.run is sealed end to end
// (internal/ingredients/cmd/sealed.go), being able to publish to a sprout
// no longer means being able to command it, so a bus-level answer here
// must not be trusted either: whoever hands a sprout its key set decides
// which releases it will install (internal/ingredients/selfupdate).
//
// So the reply is sealed the same way cmd.run's is. The sprout's request
// carries a fresh message ID (Request.ID); farmer seals its Response to
// the sprout (pki.SealToSprout, purpose
// payloadbox.PurposeFleetSigningResponse, ReplyTo = that ID) and marks it
// with the payloadbox.Header header, and the sprout opens it with its own
// box key and pinned tenant key (pki.SproutOpenFromFarmer: purpose,
// sprout, freshness, replay) and requires ReplyTo to be the ID it just
// sent. Answering therefore takes the tenant's box private key, which
// only farmer holds (OpenBao), not just a bus permission. Release signing
// still protects against everyone outside that channel — saasapi and
// anyone else who can write saas.fleet_versions, and the artifact host.
//
// Rules each end enforces, and the plaintext carve-outs:
//
//   - Farmer seals whenever the request carries an ID and the sprout has a
//     box key on record. Two cases get today's plaintext reply instead:
//     a sprout with no box key on record (enrolled before workstream J; it
//     can't open anything, and re-enrolling fixes it), with a warning; and
//     a request with no ID (a sprout binary older than this change, which
//     couldn't read a sealed reply and would otherwise be unable to
//     self-update to one that can), also with a warning. Any other failure
//     to seal is answered errorUnavailable: never a silent fallback to
//     plaintext keys.
//   - A sprout with payload-encryption keys (pki.SproutBoxReady) only
//     accepts a sealed reply, so a bus can't downgrade it by answering in
//     plaintext (or by sending farmer a request without an ID, which gets
//     a plaintext answer this sprout then refuses). Only a sprout without
//     those keys — one enrolled before workstream J, which has no way to
//     authenticate farmer beyond the NATS layer — still accepts a
//     plaintext reply, and then only one with no payloadbox.Header header
//     at all. Those sprouts are exactly as exposed to a rogue imas.>
//     Subscriber as before this change until they are re-enrolled.
package fleetkeys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// SubjectToken is the last token of the request subject. The full
// subject is imas.sprouts.<sprout id>.fleetsigningkeys; the sprout's NATS
// User JWT grants Publish on its own copy only (internal/pki/jwtusers.go,
// sproutPermissions).
//
// The reply does NOT come back on an _INBOX.> subject: a sprout's JWT
// grants Publish on _INBOX.> (to answer farmer's requests) but Subscribe
// only on its own imas.sprouts.<id>.>, and granting it Subscribe on
// _INBOX.> would let every sprout read every reply in the tenant Account.
// So the sprout names a reply subject under its own tree,
// imas.sprouts.<id>.fleetsigningkeys.reply.<random> (ReplyPrefix), which
// its existing Subscribe grant already covers, and farmer refuses any
// other reply subject.
const SubjectToken = "fleetsigningkeys"

// replyToken separates the request subject from its reply subjects.
const replyToken = "reply"

// farmerSubject is what farmer queue-subscribes to on each tenant
// connection, as internal/facts does for imas.sprouts.*.facts.
const farmerSubject = "imas.sprouts.*." + SubjectToken

// natsCoreQueueGroup matches internal/facts' and internal/jobs' queue
// group, so exactly one farmer replica answers each request.
const natsCoreQueueGroup = "imas-core"

// SproutSubject is the subject sproutID sends its request on.
func SproutSubject(sproutID string) string {
	return "imas.sprouts." + sproutID + "." + SubjectToken
}

// ReplyPrefix is the prefix of every reply subject sproutID may ask farmer
// to answer on: imas.sprouts.<id>.fleetsigningkeys.reply. A reply subject
// is this plus exactly one more token.
func ReplyPrefix(sproutID string) string {
	return SproutSubject(sproutID) + "." + replyToken
}

// validReplySubject reports whether reply is one literal token under
// sproutID's own ReplyPrefix. Farmer answers from a User with Publish on
// all of imas.>, and NATS doesn't check a requester's reply subject
// against its own permissions — so without this a sprout could name
// another sprout's imas.sprouts.<other>.cmd.run as its "reply" and have
// farmer publish there for it (the same confused-deputy shape
// controlplane.ValidSaaSAPIReplySubject closes for internal.sprout.action).
func validReplySubject(sproutID, reply string) bool {
	tok, ok := strings.CutPrefix(reply, ReplyPrefix(sproutID)+".")
	return ok && tok != "" && !strings.ContainsAny(tok, ".*> \t\r\n") && len(reply) <= 255
}

// Request is the sprout's request body. ID is a fresh payloadbox message
// ID (payloadbox.NewID: 32 lowercase hex characters); farmer's sealed
// Response names it in ReplyTo, so a reply sealed for one request can't
// be passed off as the answer to another. It needn't be secret: only
// farmer can seal a reply that names it. An empty body, or no ID, is a
// sprout built before replies were sealed.
type Request struct {
	ID string `json:"id,omitempty"`
}

// validRequestID reports whether id has payloadbox.NewID's shape.
func validRequestID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// KeyVersion is one imas-fleet-signing key version, in the same shape as
// internal/gatewayjwt's TransitKeyVersion (what PublicKeys returns):
// the Transit version number and the raw 32-byte Ed25519 public key
// (standard base64 in JSON).
type KeyVersion struct {
	Version   int    `json:"version"`
	PublicKey []byte `json:"public_key"`
}

// Response is farmer's reply. Keys is every version at or above the key's
// min_decryption_version — every version Transit's own /verify still
// accepts — sorted ascending (fleetsign's readKeySet). On failure Keys is
// empty and Error is a fixed code, never error text.
type Response struct {
	Keys  []KeyVersion `json:"keys,omitempty"`
	Error string       `json:"error,omitempty"`
}

// errorUnavailable is Response.Error when farmer couldn't read the key
// set (no key source configured, or Transit unreachable/refusing).
const errorUnavailable = "unavailable"

// keySource is farmer's read-only Transit view of imas-fleet-signing, set
// once at startup (cmd/farmer's initFleetKeySource). Nil means every
// request is answered with errorUnavailable.
var keySource fleetsign.KeySetSource

// SetKeySource installs the read-only key source requests are answered
// from.
func SetKeySource(src fleetsign.KeySetSource) { keySource = src }

// farmerReadTimeout bounds one Transit key read (normally cached by the
// source for 60s).
const farmerReadTimeout = 10 * time.Second

// RegisterFarmerListener queue-subscribes nc — farmer's connection for
// tenantID — to imas.sprouts.*.fleetsigningkeys. The tenant is the
// connection's; the sprout is the subject's wildcard token, never the
// payload. The only thing read from the payload is Request.ID, which the
// sealed reply echoes.
func RegisterFarmerListener(tenantID string, nc *nats.Conn) error {
	if _, err := nc.QueueSubscribe(farmerSubject, natsCoreQueueGroup, func(msg *nats.Msg) {
		handle(tenantID, msg)
	}); err != nil {
		return fmt.Errorf("fleetkeys: subscribing to %s for tenant %s: %w", farmerSubject, tenantID, err)
	}
	return nil
}

func handle(tenantID string, msg *nats.Msg) {
	if msg.Reply == "" {
		return
	}
	tokens := strings.Split(msg.Subject, ".")
	if len(tokens) != 4 || tokens[2] == "" {
		log.Errorf("fleetkeys: unexpected subject %q (tenant %s)", msg.Subject, tenantID)
		return
	}
	sproutID := tokens[2]
	if !validReplySubject(sproutID, msg.Reply) {
		log.Errorf("fleetkeys: dropping request from sprout %s (tenant %s) with reply subject %q outside %s.*",
			sproutID, tenantID, msg.Reply, ReplyPrefix(sproutID))
		return
	}

	var req Request
	if len(msg.Data) > 0 {
		if err := json.Unmarshal(msg.Data, &req); err != nil || (req.ID != "" && !validRequestID(req.ID)) {
			log.Errorf("fleetkeys: dropping malformed request from sprout %s (tenant %s)", sproutID, tenantID)
			return
		}
	}

	resp := Response{Error: errorUnavailable}
	if src := keySource; src != nil {
		ctx, cancel := context.WithTimeout(context.Background(), farmerReadTimeout)
		ks, err := src.KeySet(ctx)
		cancel()
		if err != nil {
			log.Errorf("fleetkeys: reading fleet signing keys for sprout %s (tenant %s): %v", sproutID, tenantID, err)
		} else {
			resp = Response{Keys: make([]KeyVersion, 0, len(ks))}
			for _, k := range ks {
				resp.Keys = append(resp.Keys, KeyVersion{Version: k.Version, PublicKey: k.Key})
			}
		}
	} else {
		log.Errorf("fleetkeys: sprout %s (tenant %s) asked for fleet signing keys, but no key source is configured", sproutID, tenantID)
	}
	if err := msg.RespondMsg(reply(tenantID, sproutID, req.ID, resp)); err != nil {
		log.Errorf("fleetkeys: responding to sprout %s (tenant %s): %v", sproutID, tenantID, err)
	}
}

// reply builds farmer's answer to the request whose ID is reqID: resp
// sealed to the sprout, or plaintext in the two carve-outs the package
// comment describes. A failure to seal is never answered with resp in
// plaintext.
func reply(tenantID, sproutID, reqID string, resp Response) *nats.Msg {
	if reqID == "" {
		log.Warnf("fleetkeys: answering sprout %s (tenant %s) in plaintext: its request carries no message id, so it runs a build older than sealed fleet signing key replies; upgrade it",
			sproutID, tenantID)
		return plainReply(resp)
	}
	data, _, err := pki.SealToSprout(tenantID, sproutID, payloadbox.PurposeFleetSigningResponse, reqID, resp)
	if errors.Is(err, pki.ErrNoActiveBoxKey) {
		log.Warnf("fleetkeys: answering sprout %s (tenant %s) in plaintext: it has no payload-encryption key on record (enrolled before workstream J); re-enroll it",
			sproutID, tenantID)
		return plainReply(resp)
	}
	if err != nil {
		log.Errorf("fleetkeys: sealing fleet signing keys for sprout %s (tenant %s): %v", sproutID, tenantID, err)
		return plainReply(Response{Error: errorUnavailable})
	}
	m := nats.NewMsg("")
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m
}

func plainReply(resp Response) *nats.Msg {
	data, _ := json.Marshal(resp)
	return &nats.Msg{Data: data}
}

// ErrUnavailable: farmer answered, but couldn't provide the key set.
var ErrUnavailable = errors.New("fleetkeys: farmer could not provide the fleet signing keys")

// ErrReplyNotSealed: this sprout has payload-encryption keys, so it only
// accepts a sealed reply, and the one it got was plaintext. Either farmer
// has no box key on record for it (or couldn't seal, and is reporting
// that in the clear), or something other than farmer answered.
var ErrReplyNotSealed = errors.New("fleetkeys: reply is not sealed, and this sprout only accepts sealed fleet signing keys")

// Fetch is the sprout side: it asks farmer, over nc, for the current key
// set for sproutID, authenticates the answer (open, below) and validates
// it (fleetsign.NewKeySet: at least one key, positive unique versions,
// 32-byte keys).
func Fetch(ctx context.Context, nc *nats.Conn, sproutID string) (fleetsign.KeySet, error) {
	if nc == nil {
		return nil, errors.New("fleetkeys: no NATS connection")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("fleetkeys: generating reply subject: %w", err)
	}
	reqID, err := payloadbox.NewID()
	if err != nil {
		return nil, fmt.Errorf("fleetkeys: generating request id: %w", err)
	}
	body, _ := json.Marshal(Request{ID: reqID})
	reply := ReplyPrefix(sproutID) + "." + hex.EncodeToString(nonce[:])
	sub, err := nc.SubscribeSync(reply)
	if err != nil {
		return nil, fmt.Errorf("fleetkeys: subscribing to reply subject: %w", err)
	}
	defer sub.Unsubscribe()
	if err := nc.PublishRequest(SproutSubject(sproutID), reply, body); err != nil {
		return nil, fmt.Errorf("fleetkeys: requesting fleet signing keys: %w", err)
	}
	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("fleetkeys: requesting fleet signing keys: %w", err)
	}
	resp, err := open(sproutID, reqID, msg)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%w (%s)", ErrUnavailable, resp.Error)
	}
	keys := make([]fleetsign.PublicKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, fleetsign.PublicKey{Version: k.Version, Key: k.PublicKey})
	}
	return fleetsign.NewKeySet(keys)
}

// open authenticates and decodes msg, farmer's reply to sproutID's
// request reqID. A reply marked sealed must open under this sprout's keys
// for PurposeFleetSigningResponse and answer reqID (the same freshness
// check internal/ingredients/cmd's frun applies to a cmd.run reply). A
// reply with no payloadbox.Header header at all is decoded as plaintext
// only if this sprout has no payload-encryption keys to demand otherwise.
func open(sproutID, reqID string, msg *nats.Msg) (Response, error) {
	var resp Response
	switch format := msg.Header.Get(payloadbox.Header); {
	case format == payloadbox.HeaderBox1:
		m, err := pki.SproutOpenFromFarmer(sproutID, payloadbox.PurposeFleetSigningResponse, msg.Data)
		if err != nil {
			return resp, fmt.Errorf("fleetkeys: opening reply: %w", err)
		}
		if m.ReplyTo != reqID {
			return resp, fmt.Errorf("fleetkeys: opening reply: %w", payloadbox.ErrOpen)
		}
		if err := json.Unmarshal(m.Body, &resp); err != nil {
			return resp, fmt.Errorf("fleetkeys: decoding reply: %w", err)
		}
		return resp, nil
	case format != "":
		return resp, fmt.Errorf("fleetkeys: reply is in an unsupported payload format: %w", payloadbox.ErrOpen)
	case len(msg.Header.Values(payloadbox.Header)) > 0:
		// Present but empty: still not "no sealed header at all".
		return resp, fmt.Errorf("fleetkeys: reply has an empty payload format header: %w", payloadbox.ErrOpen)
	case pki.SproutBoxReady():
		return resp, ErrReplyNotSealed
	}
	// Enrolled before workstream J: nothing to authenticate farmer with
	// beyond the NATS layer, so plaintext as before.
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return resp, fmt.Errorf("fleetkeys: decoding reply: %w", err)
	}
	return resp, nil
}
