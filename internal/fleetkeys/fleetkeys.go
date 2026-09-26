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
// imas.> allow-all template (the imas CLI in the legacy tenant). Each of
// those can already publish imas.sprouts.<id>.cmd.run to the sprout, i.e.
// run arbitrary commands on it, so being able to hand it a key set gives
// them nothing new. Other sprouts can't answer: their Sub grant is their
// own imas.sprouts.<their id>.> only. What release signing still protects
// against is everyone outside that channel — saasapi and anyone else who
// can write saas.fleet_versions, and the artifact host — none of whom can
// reach this subject. See internal/ingredients/selfupdate for how the
// sprout uses the answer.
//
// That equivalence is CONDITIONAL on today's sprout: cmd/sprout executes a
// plaintext imas.sprouts.<id>.cmd.run from anyone allowed to publish it.
// If command payloads are ever authenticated beyond the NATS layer (e.g.
// workstream J's NaCl box, docs/design/imas-payload-encryption-design.md),
// the set of Users who can answer here becomes larger than the set who
// can command the sprout, and this reply must be authenticated the same
// way before that ships — otherwise this subject becomes the weakest way
// onto the sprout.
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
// connection's; the sprout is the subject's wildcard token. Nothing in the
// request payload is read.
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
	data, _ := json.Marshal(resp)
	if err := msg.Respond(data); err != nil {
		log.Errorf("fleetkeys: responding to sprout %s (tenant %s): %v", sproutID, tenantID, err)
	}
}

// ErrUnavailable: farmer answered, but couldn't provide the key set.
var ErrUnavailable = errors.New("fleetkeys: farmer could not provide the fleet signing keys")

// Fetch is the sprout side: it asks farmer, over nc, for the current key
// set for sproutID and validates the answer (fleetsign.NewKeySet: at least
// one key, positive unique versions, 32-byte keys).
func Fetch(ctx context.Context, nc *nats.Conn, sproutID string) (fleetsign.KeySet, error) {
	if nc == nil {
		return nil, errors.New("fleetkeys: no NATS connection")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("fleetkeys: generating reply subject: %w", err)
	}
	reply := ReplyPrefix(sproutID) + "." + hex.EncodeToString(nonce[:])
	sub, err := nc.SubscribeSync(reply)
	if err != nil {
		return nil, fmt.Errorf("fleetkeys: subscribing to reply subject: %w", err)
	}
	defer sub.Unsubscribe()
	if err := nc.PublishRequest(SproutSubject(sproutID), reply, nil); err != nil {
		return nil, fmt.Errorf("fleetkeys: requesting fleet signing keys: %w", err)
	}
	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("fleetkeys: requesting fleet signing keys: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, fmt.Errorf("fleetkeys: decoding reply: %w", err)
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
