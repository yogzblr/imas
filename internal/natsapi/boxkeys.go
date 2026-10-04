package natsapi

// Sprout-initiated payload-encryption key rotation
// (docs/design/imas-payload-encryption-design.md's "Key rotation"):
// farmer may *trigger* a rotation (handlePKIRotateBoxKey, below) but the
// instruction carries no key material; the sprout generates a new
// keypair locally and reports back only the new public key
// (handleBoxKeySubmit), which internal/pki.RotateSproutBoxKey records,
// grace-period-overlapping the previous key rather than revoking it
// immediately.
//
// FLAG FOR SECURITY REVIEW per the task brief: this is the NATS-facing
// half of the rotation lifecycle whose storage/state-machine half lives
// in internal/pki/boxkeys.go.
import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// handlePKIRotateBoxKey publishes a rotate instruction to a sprout. It
// never generates or transmits key material of its own — see this file's
// header comment and the design doc's explicit rejection of an earlier,
// unsafe framing that would have had farmer generate/hold a sprout's
// private key.
func handlePKIRotateBoxKey(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	if km.SproutID == "" {
		return nil, fmt.Errorf("id is required")
	}
	registered, _ := pki.NKeyExists(tenantID, km.SproutID, "")
	if !registered {
		return nil, fmt.Errorf("unknown sprout: %s", km.SproutID)
	}
	nc := natsConnFor(tenantID)
	if nc == nil {
		return nil, fmt.Errorf("NATS connection not available")
	}
	if err := nc.Publish(SproutSubject(km.SproutID, SproutBoxKeyRotateCmd), nil); err != nil {
		return nil, fmt.Errorf("failed to publish rotate instruction: %w", err)
	}
	return map[string]bool{"success": true}, nil
}

// rotateTenantBoxKeyRequest is MethodPKIRotateTenantBoxKey's params.
type rotateTenantBoxKeyRequest struct {
	// Sever cuts the old keys off at once, for suspected exposure: no
	// grace window and no continuity proofs, so the tenant's sprouts
	// must be re-enrolled. See pki.RotateTenantX25519Keypair.
	Sever bool `json:"sever"`
}

// handlePKIRotateTenantBoxKey rotates tenantID's own X25519 keypair —
// tenantID being the tenant whose connection the request arrived on, so
// one tenant can never rotate another's.
func handlePKIRotateTenantBoxKey(tenantID string, params json.RawMessage) (any, error) {
	var req rotateTenantBoxKeyRequest
	if len(params) > 0 && string(params) != "null" {
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, fmt.Errorf("invalid request: %w", err)
		}
	}
	rot, err := pki.RotateTenantX25519Keypair(tenantID, req.Sever)
	if err != nil {
		return nil, err
	}
	// A severed key may be in someone else's hands: end this replica's
	// shell sessions whose leg 2 used it now (key-severed). Other replicas
	// notice within shellRecheckInterval. A normal rotation keeps the
	// previous key in the set, so it ends nothing.
	go shellSessions.recheckTenantKeys(tenantID)
	return rot, nil
}

// boxKeySubmitRequest is what a sprout publishes on
// imas.sprouts.<id>.boxkey.pub, whether at first enrollment's follow-up
// traffic or after a rotation (self-initiated or farmer-triggered).
type boxKeySubmitRequest struct {
	Pub string `json:"pub"`
}

// handleBoxKeySubmit records a sprout's new payload-encryption public
// key. The sprout ID comes from the subject, not the message body — the
// same trust model internal/facts's listener uses. The subject must be
// exactly imas.sprouts.<id>.boxkey.pub with a valid sprout ID in the one
// token position: sprout IDs never contain a dot (pki.IsValidSproutID,
// security review 2026-10, M4), so <id> is always parts[2].
//
// That trust model is not enough here, though: this subject decides
// which key farmer seals every later payload to, and the threat this
// workstream exists for is a compromised bus, which can publish anything
// on any subject. A plaintext submission would let it swap in its own key
// and read everything farmer sends that sprout from then on. So a
// submission must be sealed (purpose s2f.boxkey.pub) under a key the
// sprout already holds: only the holder of that private key could have
// sealed it. It must also be fresh (payloadbox.DefaultMaxSkew).
//
// FLAG FOR SECURITY REVIEW (security review 2026-10, M3): only the
// sprout's *active* key may change which key is active
// (pki.RecordSproutBoxKeySubmission). A submission sealed under a key in
// its grace window may only re-assert the key that is already active (a
// sprout retrying a submission farmer already recorded); naming any other
// key is refused. Otherwise an old key leaked from, say, a VM snapshot
// could take over the sprout's sealed channel for the grace window after
// the rotation meant to retire it. pki.RotateSproutBoxKey never
// re-activates a superseded key either, so a replayed submission can't
// roll a sprout back.
func handleBoxKeySubmit(tenantID string, msg *nats.Msg) {
	parts := strings.Split(msg.Subject, ".")
	if len(parts) != 5 || parts[0] != "imas" || parts[1] != "sprouts" || parts[3] != "boxkey" || parts[4] != "pub" {
		log.Errorf("boxkeys: unexpected subject format: %s", msg.Subject)
		return
	}
	sproutID := parts[2]
	if !pki.IsValidSproutID(sproutID) {
		log.Warnf("boxkeys: refusing a box key submission for an invalid sprout ID on %s", msg.Subject)
		return
	}

	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		log.Warnf("boxkeys: refusing an unsealed box key submission for %s", sproutID)
		return
	}
	opened, sealedUnder, err := pki.OpenBoxKeySubmission(tenantID, sproutID, msg.Data)
	if err != nil {
		log.Warnf("boxkeys: refusing a box key submission for %s that doesn't open under its current keys: %v", sproutID, err)
		return
	}
	var req boxKeySubmitRequest
	if err := json.Unmarshal(opened.Body, &req); err != nil {
		log.Warnf("boxkeys: refusing a box key submission for %s with an undecodable body: %v", sproutID, err)
		return
	}
	issued := time.Unix(opened.IssuedAt, 0)
	if d := time.Since(issued); d > payloadbox.DefaultMaxSkew || d < -payloadbox.DefaultMaxSkew {
		log.Warnf("boxkeys: refusing a stale box key submission for %s (issued %s)", sproutID, issued.UTC().Format(time.RFC3339))
		return
	}
	if req.Pub == "" {
		log.Errorf("boxkeys: empty pub in submission from %s", sproutID)
		return
	}
	if err := pki.RecordSproutBoxKeySubmission(tenantID, sproutID, sealedUnder, req.Pub, config.BoxKeyGraceDuration); err != nil {
		log.Warnf("boxkeys: refusing a box key submission for %s: %v", sproutID, err)
		return
	}
	log.Noticef("boxkeys: sprout %s's payload-encryption key is recorded", sproutID)
}

// registerBoxKeySubmitListener subscribes to sprout key-rotation
// submissions on nc, scoped to tenantID (nc's own tenant — see
// docs/design/imas-tenant-context-threading.md). handleBoxKeySubmit is a
// plain nats.MsgHandler, not a `handler`-shaped route, so tenantID is
// captured directly in the subscription closure below rather than threaded
// through the routes map/authMiddleware machinery. QueueSubscribe under the
// shared natsCoreQueueGroup (see router.go's Subscribe): every replica
// reads the same PXC-backed pki_sprout_box_keys table
// (internal/pki/boxkeys.go), so exactly one replica should process a given
// submission — the same reasoning internal/facts's listener applies to
// sprout facts events.
func registerBoxKeySubmitListener(nc *nats.Conn, tenantID string) error {
	_, err := nc.QueueSubscribe(SproutBoxKeySubmitPattern, natsCoreQueueGroup, func(msg *nats.Msg) {
		handleBoxKeySubmit(tenantID, msg)
	})
	if err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", SproutBoxKeySubmitPattern, err)
	}
	return nil
}
