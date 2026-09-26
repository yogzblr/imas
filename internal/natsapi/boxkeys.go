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

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
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

// boxKeySubmitRequest is what a sprout publishes on
// imas.sprouts.<id>.boxkey.pub, whether at first enrollment's follow-up
// traffic or after a rotation (self-initiated or farmer-triggered).
type boxKeySubmitRequest struct {
	Pub string `json:"pub"`
}

// handleBoxKeySubmit records a sprout's new payload-encryption public
// key. The sprout ID comes from the subject, not the message body — the
// same trust model internal/facts's listener uses (the connection's own
// authenticated identity, enforced by NATS permissions on which subjects
// a given sprout connection may publish to, not by anything checked
// here).
func handleBoxKeySubmit(tenantID string, msg *nats.Msg) {
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		log.Errorf("boxkeys: unexpected subject format: %s", msg.Subject)
		return
	}
	sproutID := parts[2]

	var req boxKeySubmitRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Errorf("boxkeys: failed to unmarshal submission from %s: %v", sproutID, err)
		return
	}
	if req.Pub == "" {
		log.Errorf("boxkeys: empty pub in submission from %s", sproutID)
		return
	}
	if err := pki.RotateSproutBoxKey(tenantID, sproutID, req.Pub, config.BoxKeyGraceDuration); err != nil {
		log.Errorf("boxkeys: failed to record new box key for %s: %v", sproutID, err)
		return
	}
	log.Noticef("boxkeys: sprout %s rotated its payload-encryption key", sproutID)
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
