package natsapi

// Shared NaCl box (X25519) encrypt/decrypt helper for
// docs/design/imas-payload-encryption-design.md (workstream J): "best
// done by building it into the shared request/response helper layer so
// encryption is transparent to individual handlers rather than opt-in
// per handler."
//
// FLAG FOR SECURITY REVIEW per the task brief — this is cryptographic
// code defending against a compromised DMZ bus (see the design doc's
// "Why this exists").
//
// Key material comes from internal/pki: the tenant's keypair
// (pki.GetTenantX25519KeyPair, OpenBao-custodied — see tenantbox.go) and
// a sprout's current box public key(s) (pki.ValidSproutBoxKeys, which
// returns the active key plus any former key still inside its
// post-rotation grace window). One tenant keypair reused across every
// sprout still gives each (tenant, sprout) pair its own derived shared
// secret — see the design doc's "Design" section for why that's safe.
//
// Wiring this into a given handler's actual dispatch is a per-handler
// decision, not automatic: see this repo's PR description for which
// farmer<->sprout payload boundaries this change wires up and which are
// deliberately left on plaintext for now (a boundary can only move to
// ciphertext once the sprout-side code sending/receiving it is updated
// to match — a one-sided change would just break that boundary, not
// secure it).
import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/pki"
)

// ErrDecryptFailed means a payload didn't open under any of a sprout's
// currently-valid box keys (its active key, or a former key still inside
// its post-rotation grace window). Deliberately generic — like
// pki.ErrEnrollmentFailed, this shouldn't become an oracle distinguishing
// "wrong key" from "corrupt ciphertext" from "tampered payload" for a
// caller on a compromised bus.
var ErrDecryptFailed = errors.New("natsapi: failed to decrypt payload")

// EncryptedEnvelope is the wire shape a NaCl box-sealed payload travels in
// on subjects this workstream covers, replacing a handler's plaintext
// JSON body. Both fields marshal as standard base64 (encoding/json's
// default for []byte).
type EncryptedEnvelope struct {
	// Nonce is the 24-byte NaCl box nonce, freshly random per message
	// (box.Seal's contract: never reused with the same key pair).
	Nonce []byte `json:"n"`
	// Ciphertext is box.Seal's output: the sealed message plus its
	// 16-byte Poly1305 authentication tag.
	Ciphertext []byte `json:"c"`
}

func decodeBoxPubKey(b64 string) (*[32]byte, error) {
	pub, err := pki.DecodeBoxPubKey(b64)
	if err != nil {
		return nil, fmt.Errorf("natsapi: invalid box public key: %w", err)
	}
	return pub, nil
}

// sealForSprout seals plaintext addressed to sproutID: box.Seal under the
// tenant's private key and the sprout's current *active* box public key
// (a rotation's grace-period keys are only ever a decrypt-side concern —
// see the design doc's "Key rotation": farmer always encrypts new
// outbound traffic under whatever the sprout most recently told it is
// current).
func sealForSprout(tenantID, sproutID string, plaintext []byte) ([]byte, error) {
	_, tenantPriv, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("natsapi: loading tenant keypair: %w", err)
	}
	activePub, _, err := pki.ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		return nil, fmt.Errorf("natsapi: loading box key for sprout %s: %w", sproutID, err)
	}
	sproutPub, err := decodeBoxPubKey(activePub)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("natsapi: generating nonce: %w", err)
	}
	sealed := box.Seal(nil, plaintext, &nonce, sproutPub, tenantPriv)

	return json.Marshal(EncryptedEnvelope{Nonce: nonce[:], Ciphertext: sealed})
}

// openFromSprout opens an EncryptedEnvelope (JSON-encoded in envelope)
// received from sproutID, trying the sprout's active box key first and
// then any former key still inside its post-rotation grace window (the
// design doc's "grace period... both old and new public keys accepted
// for a short overlap window").
func openFromSprout(tenantID, sproutID string, envelope []byte) ([]byte, error) {
	var env EncryptedEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: decoding envelope: %v", ErrDecryptFailed, err)
	}
	if len(env.Nonce) != 24 {
		return nil, fmt.Errorf("%w: invalid nonce length", ErrDecryptFailed)
	}
	var nonce [24]byte
	copy(nonce[:], env.Nonce)

	_, tenantPriv, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("natsapi: loading tenant keypair: %w", err)
	}
	active, grace, err := pki.ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		return nil, fmt.Errorf("natsapi: loading box key for sprout %s: %w", sproutID, err)
	}

	candidates := make([]string, 0, 1+len(grace))
	candidates = append(candidates, active)
	candidates = append(candidates, grace...)

	for _, candidate := range candidates {
		pub, decodeErr := decodeBoxPubKey(candidate)
		if decodeErr != nil {
			continue
		}
		if plaintext, ok := box.Open(nil, env.Ciphertext, &nonce, pub, tenantPriv); ok {
			return plaintext, nil
		}
	}
	return nil, ErrDecryptFailed
}

// PublishEncryptedTo JSON-marshals v, seals it for sproutID (see
// sealForSprout), and publishes the result to subject. The transparent
// replacement for natsConn.Publish(subject, plaintextJSON) at a
// farmer->sprout payload boundary this workstream covers.
func PublishEncryptedTo(tenantID, sproutID, subject string, v any) error {
	nc := natsConnFor(tenantID)
	if nc == nil {
		return fmt.Errorf("natsapi: NATS connection not available")
	}
	plaintext, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("natsapi: marshaling payload for %s: %w", sproutID, err)
	}
	ciphertext, err := sealForSprout(tenantID, sproutID, plaintext)
	if err != nil {
		return err
	}
	return nc.Publish(subject, ciphertext)
}

// DecryptEncryptedFrom opens data — an inbound NATS message payload from
// sproutID, wire-shaped as EncryptedEnvelope — and JSON-unmarshals the
// result into v. The transparent counterpart handlers use when receiving
// a sprout-originated payload this workstream covers.
func DecryptEncryptedFrom(tenantID, sproutID string, data []byte, v any) error {
	plaintext, err := openFromSprout(tenantID, sproutID, data)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(plaintext, v)
}
