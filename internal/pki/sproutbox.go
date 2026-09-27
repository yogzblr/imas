package pki

// The sprout's end of sealed farmer<->sprout payloads
// (docs/design/imas-payload-encryption-design.md, workstream J), and its
// half of authenticated tenant key rotation.
//
// FLAG FOR SECURITY REVIEW. Keys: the sprout's own X25519 private key
// (config.SproutBoxPrivFile, generated here by EnsureSproutBoxKey and
// never sent anywhere) and the tenant public key it pinned at enrollment
// (config.SproutTenantX25519PubFile). Both are read from disk on every
// use, not cached, so a re-pin (reconcileTenantKeyPin) takes effect on
// the very next message and the private key isn't held in memory between
// messages.
//
// The pin only ever moves through reconcileTenantKeyPin: farmer's
// refresh (or enrollment) response names a different tenant key AND
// carries a continuity proof that opens under the currently pinned key,
// i.e. was sealed with the private key the sprout already trusts, and
// names exactly that new key. A different key without such a proof is
// still ErrTenantKeyMismatch, fatal as before.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// ErrSproutBoxNotReady means the sprout can't seal or open payloads: it
// has no box private key or no pinned tenant key, i.e. it enrolled
// before workstream J.
var ErrSproutBoxNotReady = errors.New("pki: sprout has no payload-encryption keys (box key or pinned tenant key)")

// sproutReplayGuard remembers the farmer->sprout messages this process
// has accepted (payloadbox.ReplayGuard).
var sproutReplayGuard = payloadbox.NewReplayGuard()

// SproutBoxReady reports whether this sprout has both keys it needs to
// seal and open payloads. A sprout that does refuses plaintext on sealed
// boundaries.
func SproutBoxReady() bool {
	for _, p := range []string{config.SproutBoxPrivFile, config.SproutTenantX25519PubFile} {
		if p == "" {
			return false
		}
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// loadSproutBoxKeyPair returns (pinned tenant pub, sprout priv). The
// caller wipes Priv when done.
func loadSproutBoxKeyPair() (payloadbox.KeyPair, error) {
	if !SproutBoxReady() {
		return payloadbox.KeyPair{}, ErrSproutBoxNotReady
	}
	pinned, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if err != nil {
		return payloadbox.KeyPair{}, fmt.Errorf("pki: reading pinned tenant X25519 public key: %w", err)
	}
	tenantPub, err := DecodeBoxPubKey(strings.TrimSpace(string(pinned)))
	if err != nil {
		return payloadbox.KeyPair{}, fmt.Errorf("pki: pinned tenant X25519 public key: %w", err)
	}
	raw, err := readBoxPrivKey(config.SproutBoxPrivFile)
	if err != nil {
		return payloadbox.KeyPair{}, err
	}
	var priv [32]byte
	copy(priv[:], raw)
	wipe(raw)
	return payloadbox.KeyPair{PeerPub: tenantPub, Priv: &priv}, nil
}

func wipeKeyPair(k payloadbox.KeyPair) {
	if k.Priv != nil {
		wipe(k.Priv[:])
	}
}

// SproutOpenFromFarmer opens data, a payload farmer sealed for sproutID
// under purpose, and checks it is fresh and not a replay
// (payloadbox.ErrOpen, ErrStale, ErrReplayed; distinguishable in the
// sprout's own log only: a reply to farmer carries one generic code).
func SproutOpenFromFarmer(sproutID, purpose string, data []byte) (*payloadbox.Message, error) {
	kp, err := loadSproutBoxKeyPair()
	if err != nil {
		return nil, err
	}
	defer wipeKeyPair(kp)
	msg, err := payloadbox.Open(data, []payloadbox.KeyPair{kp}, payloadbox.Expect{Purpose: purpose, SproutID: sproutID})
	if err != nil {
		return nil, err
	}
	if err := sproutReplayGuard.Accept(msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// SproutSealForFarmer seals body from sproutID to farmer under purpose,
// answering the request whose message ID is replyTo (empty for a message
// that isn't a reply). Sealed under the pinned tenant key: farmer opens
// under its current key or, inside a rotation's grace window, the
// previous one, so a sprout that hasn't re-pinned yet still gets through.
func SproutSealForFarmer(sproutID, purpose, replyTo string, body any) ([]byte, error) {
	kp, err := loadSproutBoxKeyPair()
	if err != nil {
		return nil, err
	}
	defer wipeKeyPair(kp)
	msg, err := payloadbox.NewMessage(purpose, sproutID, replyTo, body)
	if err != nil {
		return nil, err
	}
	return payloadbox.Seal(msg, []payloadbox.KeyPair{kp})
}

// reconcileTenantKeyPin checks pub, the tenant key in farmer's response
// to sproutID, against the pinned one. No pin yet, or the same key: nil.
// A different key: re-pins to pub if continuity (the response's
// tenant_x25519_continuity) proves the move, else ErrTenantKeyMismatch.
func reconcileTenantKeyPin(sproutID, pub string, continuity json.RawMessage) error {
	err := checkPinnedTenantKey(pub)
	if !errors.Is(err, ErrTenantKeyMismatch) {
		return err
	}
	if len(continuity) == 0 {
		return ErrTenantKeyMismatch
	}
	if err := verifyTenantKeyContinuity(sproutID, pub, continuity); err != nil {
		log.Errorf("pki: farmer's new tenant X25519 key came with a continuity proof that doesn't verify: %v", err)
		return ErrTenantKeyMismatch
	}
	if err := writeFileAtomic(config.SproutTenantX25519PubFile, []byte(pub), 0o644); err != nil {
		return fmt.Errorf("pki: re-pinning tenant X25519 public key: %w", err)
	}
	log.Noticef("pki: re-pinned the tenant X25519 public key after an authenticated tenant key rotation")
	return nil
}

// verifyTenantKeyContinuity opens proof under the pinned tenant key and
// this sprout's box key and checks it names pub.
func verifyTenantKeyContinuity(sproutID, pub string, proof json.RawMessage) error {
	kp, err := loadSproutBoxKeyPair()
	if err != nil {
		return err
	}
	defer wipeKeyPair(kp)
	msg, err := payloadbox.Open(proof, []payloadbox.KeyPair{kp},
		payloadbox.Expect{Purpose: payloadbox.PurposeTenantKeyContinuity, SproutID: sproutID})
	if err != nil {
		return err
	}
	var body tenantKeyContinuityBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return payloadbox.ErrOpen
	}
	if body.To != pub {
		return errors.New("proof names a different tenant key")
	}
	return nil
}
