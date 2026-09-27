// Package payloadbox is the wire format and cryptographic core of
// docs/design/imas-payload-encryption-design.md (workstream J): NaCl box
// (X25519 + XSalsa20-Poly1305) sealed payloads between farmer and a
// sprout, so a compromised DMZ bus sees routing metadata and ciphertext,
// never content.
//
// FLAG FOR SECURITY REVIEW. This package does no key custody and no I/O.
// Farmer's side (tenant keypair from OpenBao, sprout box public keys from
// PXC) is internal/pki's tenantbox.go and farmerbox.go; the sprout's side
// (its own private key and its pinned tenant public key, both on local
// disk) is internal/pki's sproutbox.go. Both sides share this file, so
// the two ends of a boundary can't drift apart.
//
// What box alone does not give, and this package adds:
//
//   - Direction and purpose binding. box's shared key is symmetric:
//     DH(tenant_priv, sprout_pub) == DH(sprout_priv, tenant_pub), so
//     anything farmer seals to a sprout would also open as if the sprout
//     had sent it, and vice versa. A bus that reflects a farmer->sprout
//     command back at farmer as a "reply" (or a sprout's reply back at the
//     sprout as a "command") would otherwise be accepted. Every Message
//     carries a Purpose ("f2s.cmd.run", "s2f.cmd.run", ...), and Open
//     refuses one that isn't the purpose the caller expects.
//   - Recipient binding. Message.SproutID is checked against the sprout
//     the caller expects. The keys already bind the (tenant, sprout) pair
//     (sprout_id is only unique per tenant, but no two sprouts share a
//     box key), so this is defence in depth.
//   - Replay and freshness. Every Message has a random ID and an
//     IssuedAt; ReplayGuard rejects stale messages and IDs it has already
//     seen. A reply names the request it answers (ReplyTo), so a bus
//     can't answer a new request with an old reply.
//
// Envelope.Copies exists for key rotation: while a tenant keypair rotation
// is inside its grace window, farmer seals one copy under the new tenant
// key and one under the previous one, and the sprout opens whichever its
// pinned tenant key matches. Open tries every (copy, key pair)
// combination, so no key identifier travels on the wire.
package payloadbox

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Header is the NATS message header that marks a payload as a sealed
// Envelope. Its only value today is HeaderBox1. It is a hint for picking
// the decoding path and for diagnostics, never a security decision: a
// receiver that requires sealed payloads refuses a message without it,
// and one with it must still Open successfully.
const (
	Header     = "Imas-Payload"
	HeaderBox1 = "box1"
)

// ErrorHeader is set, with an empty body, on a reply to a sealed request
// the responder refused. Its values are the ErrorCode* constants: fixed
// codes, never error text, so the bus learns nothing it couldn't already
// infer from the refusal itself.
const ErrorHeader = "Imas-Payload-Error"

const (
	// ErrorCodeOpenFailed: the request didn't open, was for another
	// purpose or sprout, was stale, or was a replay. Deliberately one
	// code for all of those (see ErrOpen).
	ErrorCodeOpenFailed = "open-failed"
	// ErrorCodeEncryptionRequired: a plaintext request reached a
	// responder that only accepts sealed ones.
	ErrorCodeEncryptionRequired = "encryption-required"
	// ErrorCodeNoKeys: a sealed request reached a responder that has no
	// keys to open it with (a sprout enrolled before workstream J).
	ErrorCodeNoKeys = "no-keys"
	// ErrorCodeInternal: the responder opened the request but failed to
	// produce a sealed reply.
	ErrorCodeInternal = "internal"
)

// Purposes. The prefix names the direction: f2s is farmer to sprout, s2f
// sprout to farmer. A new boundary gets its own pair; never reuse one
// across boundaries, since the purpose is what stops a message sealed for
// one boundary being accepted on another.
const (
	PurposeCmdRunRequest  = "f2s.cmd.run"
	PurposeCmdRunResponse = "s2f.cmd.run"
	// PurposeBoxKeySubmit is a sprout reporting a new box public key of
	// its own, sealed under its current (still valid) key.
	PurposeBoxKeySubmit = "s2f.boxkey.pub"
	// PurposeTenantKeyContinuity is farmer telling a sprout, under a
	// tenant key the sprout has pinned, which tenant key replaces it.
	PurposeTenantKeyContinuity = "f2s.tenantkey.continuity"
)

// Version is the only Envelope and Message version this package reads or
// writes.
const Version = 1

// MaxCopies bounds how many sealed copies one Envelope may carry, and so
// how many box.Open attempts a receiver makes per candidate key pair.
const MaxCopies = 16

// MaxEnvelopeBytes bounds how much Open reads; NATS's own default
// max_payload is 1 MiB.
const MaxEnvelopeBytes = 4 << 20

// ErrOpen is the single error Open returns for every failure: bad JSON,
// no copy opens under any candidate key, wrong version, purpose or
// sprout. Deliberately generic (like pki.ErrEnrollmentFailed), so it
// can't become an oracle for someone probing through a compromised bus.
var ErrOpen = errors.New("payloadbox: payload did not open")

// KeyPair is one (peer public key, own private key) pair: for farmer,
// (sprout_pub, tenant_priv); for a sprout, (tenant_pub, sprout_priv).
type KeyPair struct {
	PeerPub *[32]byte
	Priv    *[32]byte
}

// Message is the authenticated plaintext inside every sealed copy.
type Message struct {
	V        int    `json:"v"`
	Purpose  string `json:"p"`
	SproutID string `json:"sid"`
	// ID is 128 random bits, hex. Replay protection keys on it.
	ID string `json:"id"`
	// ReplyTo is the ID of the request this message answers; empty for
	// a request.
	ReplyTo string `json:"re,omitempty"`
	// IssuedAt is the sender's clock, Unix seconds.
	IssuedAt int64           `json:"iat"`
	Body     json.RawMessage `json:"b"`
}

// Envelope is the wire format: JSON, []byte fields as standard base64.
type Envelope struct {
	V      int      `json:"v"`
	Copies []Sealed `json:"s"`
}

// Sealed is one box.Seal output and its nonce.
type Sealed struct {
	// Nonce is 24 random bytes, fresh per copy (box.Seal requires a
	// nonce never be reused under the same key pair).
	Nonce []byte `json:"n"`
	// Box is box.Seal's output: ciphertext plus the 16-byte Poly1305 tag.
	Box []byte `json:"c"`
}

// now is time.Now, swappable in tests.
var now = time.Now

// NewID returns a fresh random message ID.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("payloadbox: generating message id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// NewMessage builds a Message for purpose, addressed to (or sent by)
// sproutID, with a fresh ID and IssuedAt, and body JSON-marshalled.
func NewMessage(purpose, sproutID, replyTo string, body any) (Message, error) {
	id, err := NewID()
	if err != nil {
		return Message{}, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return Message{}, fmt.Errorf("payloadbox: encoding body: %w", err)
	}
	return Message{
		V: Version, Purpose: purpose, SproutID: sproutID, ID: id, ReplyTo: replyTo,
		IssuedAt: now().Unix(), Body: b,
	}, nil
}

// Seal seals msg once per key pair in pairs, each copy under a fresh
// random nonce, and returns the JSON Envelope.
func Seal(msg Message, pairs []KeyPair) ([]byte, error) {
	if len(pairs) == 0 {
		return nil, errors.New("payloadbox: no key pairs to seal under")
	}
	if len(pairs) > MaxCopies {
		return nil, fmt.Errorf("payloadbox: %d key pairs exceeds the %d-copy limit", len(pairs), MaxCopies)
	}
	if msg.V != Version || msg.Purpose == "" || msg.SproutID == "" || msg.ID == "" {
		return nil, errors.New("payloadbox: message is missing its version, purpose, sprout id or id")
	}
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("payloadbox: encoding message: %w", err)
	}
	env := Envelope{V: Version, Copies: make([]Sealed, 0, len(pairs))}
	for _, p := range pairs {
		if p.PeerPub == nil || p.Priv == nil {
			return nil, errors.New("payloadbox: nil key in key pair")
		}
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, fmt.Errorf("payloadbox: generating nonce: %w", err)
		}
		env.Copies = append(env.Copies, Sealed{
			Nonce: nonce[:],
			Box:   box.Seal(nil, plaintext, &nonce, p.PeerPub, p.Priv),
		})
	}
	return json.Marshal(env)
}

// Expect is what Open checks an opened Message against.
type Expect struct {
	Purpose  string
	SproutID string
}

// Open opens data, a JSON Envelope, under the first candidate key pair
// any of its copies opens with, and checks the Message's version,
// purpose and sprout ID against want. Freshness and replay are the
// caller's (ReplayGuard, or ReplyTo matching). Every failure is ErrOpen.
func Open(data []byte, candidates []KeyPair, want Expect) (*Message, error) {
	if len(data) > MaxEnvelopeBytes || len(candidates) == 0 {
		return nil, ErrOpen
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, ErrOpen
	}
	if env.V != Version || len(env.Copies) == 0 || len(env.Copies) > MaxCopies {
		return nil, ErrOpen
	}
	for _, c := range env.Copies {
		if len(c.Nonce) != 24 || len(c.Box) < box.Overhead {
			continue
		}
		var nonce [24]byte
		copy(nonce[:], c.Nonce)
		for _, k := range candidates {
			if k.PeerPub == nil || k.Priv == nil {
				continue
			}
			plaintext, ok := box.Open(nil, c.Box, &nonce, k.PeerPub, k.Priv)
			if !ok {
				continue
			}
			var msg Message
			if err := json.Unmarshal(plaintext, &msg); err != nil {
				return nil, ErrOpen
			}
			if msg.V != Version || msg.Purpose != want.Purpose || msg.SproutID != want.SproutID || msg.ID == "" {
				return nil, ErrOpen
			}
			return &msg, nil
		}
	}
	return nil, ErrOpen
}
