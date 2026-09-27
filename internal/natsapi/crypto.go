package natsapi

// Shared NaCl box (X25519) encrypt/decrypt helpers for
// docs/design/imas-payload-encryption-design.md (workstream J), for
// natsapi handlers that exchange sealed payloads with sprouts.
//
// FLAG FOR SECURITY REVIEW per the task brief — this is cryptographic
// code defending against a compromised DMZ bus (see the design doc's
// "Why this exists").
//
// The wire format, purpose binding and replay rules are
// internal/payloadbox's; the key lookups (the tenant's keypair(s) from
// OpenBao, the sprout's box public key(s) from PXC, always by
// (tenant_id, sprout_id)) are internal/pki's farmerbox.go. This file only
// adds the NATS plumbing. internal/ingredients/cmd's FRun seals cmd.run
// through pki directly, since natsapi imports it.
//
// Which boundaries are sealed is a per-boundary decision, and a boundary
// can only move to ciphertext once the sprout-side code sending or
// receiving it moves in the same change: a one-sided change just breaks
// that boundary. Sealed today: cmd.run (both directions) and a sprout's
// box key submission (boxkeys.go). Still plaintext: see
// docs/BUILD-STATUS.md's workstream J entry.
import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// ErrDecryptFailed means a payload didn't open under any of the tenant's
// current keys and the sprout's currently-valid box keys, or opened but
// was for another purpose or sprout. Deliberately generic — like
// pki.ErrEnrollmentFailed, this shouldn't become an oracle
// distinguishing "wrong key" from "corrupt ciphertext" from "tampered
// payload" for a caller on a compromised bus.
var ErrDecryptFailed = payloadbox.ErrOpen

// PublishEncryptedTo seals v for sproutID under purpose (pki.SealToSprout)
// and publishes it to subject with the payloadbox.Header marker. The
// sealed replacement for natsConn.Publish(subject, plaintextJSON) at a
// farmer->sprout payload boundary.
func PublishEncryptedTo(tenantID, sproutID, subject, purpose string, v any) error {
	nc := natsConnFor(tenantID)
	if nc == nil {
		return fmt.Errorf("natsapi: NATS connection not available")
	}
	data, _, err := pki.SealToSprout(tenantID, sproutID, purpose, "", v)
	if err != nil {
		return fmt.Errorf("natsapi: sealing payload for %s: %w", sproutID, err)
	}
	msg := nats.NewMsg(subject)
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Data = data
	return nc.PublishMsg(msg)
}

// DecryptEncryptedFrom opens data, a sealed payload sproutID sent under
// purpose, and JSON-unmarshals its body into v (unless v is nil). It
// returns the opened message so the caller can check its freshness
// (IssuedAt) or which request it answers (ReplyTo).
func DecryptEncryptedFrom(tenantID, sproutID, purpose string, data []byte, v any) (*payloadbox.Message, error) {
	msg, err := pki.OpenFromSprout(tenantID, sproutID, purpose, data)
	if err != nil {
		if errors.Is(err, payloadbox.ErrOpen) {
			return nil, ErrDecryptFailed
		}
		return nil, err
	}
	if v != nil {
		if err := json.Unmarshal(msg.Body, v); err != nil {
			return nil, fmt.Errorf("natsapi: decoding payload from %s: %w", sproutID, err)
		}
	}
	return msg, nil
}
