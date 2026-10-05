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
//   - Tenant binding. Every Message names the tenant it belongs to
//     (Message.TenantID), and Open refuses one for any tenant but the one
//     the caller expects (Expect.TenantID, which must be set). sprout_id
//     is only unique per tenant, so without this a message farmer sealed
//     for tenant B's "web01" would be accepted by tenant A's "web01"
//     whenever the keys allowed it to open there at all (two tenants
//     sharing a keypair, or a sprout box key registered in both: security
//     review 2026-10, H3). The sprout pins its tenant at enrollment and
//     farmer checks the tenant of everything it opens.
//   - Recipient key binding. Every sealed copy names the box public key it
//     was sealed to (Message.RecipientKey, KeyID of that key), and Open
//     refuses a copy whose RecipientKey isn't the public half of the
//     private key that opened it. Callers can't forget this check: Open
//     derives the key itself. It also binds direction a second way: a
//     farmer->sprout message names the sprout's key, so reflected back at
//     farmer it names a key farmer doesn't hold.
//   - Sprout binding. Message.SproutID is checked against the sprout the
//     caller expects. The keys already bind the (tenant, sprout) pair
//     (no two sprouts share a box key), so this is defence in depth.
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
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
	// PurposeCookRequest is farmer's recipe dispatch on
	// imas.sprouts.<id>.cook, and PurposeCookResponse the sprout's Ack
	// (internal/cook's sealed.go).
	PurposeCookRequest  = "f2s.cook"
	PurposeCookResponse = "s2f.cook"
	// PurposeCookNudgeRequest is farmer's resync nudge on
	// imas.sprouts.<id>.recipe.nudge, and PurposeCookNudgeResponse the
	// sprout's Ack. A pair of its own, not the cook pair: a nudge must
	// never be accepted as a dispatch, or a dispatch as a nudge.
	PurposeCookNudgeRequest  = "f2s.cook.nudge"
	PurposeCookNudgeResponse = "s2f.cook.nudge"
	// PurposeStagedRecipe is the staged copy of a recipe dispatch farmer
	// writes to the sprout's own key in the recipe bucket, which the
	// sprout pulls over GET /files/ (internal/cook's stage.go and
	// stagedfetch.go; security review 2026-10-b, B1). One-way: there is
	// no reply. Its own purpose, not PurposeCookRequest: a staged copy
	// has no replay-guard window (the sprout's handled-jobs file and
	// StagedRecipeMaxAge bound it instead), so a captured sealed dispatch
	// must never open as a staged recipe, or the reverse.
	PurposeStagedRecipe = "f2s.staged"
	// PurposeBoxKeySubmit is a sprout reporting a new box public key of
	// its own, sealed under its current (still valid) key.
	PurposeBoxKeySubmit = "s2f.boxkey.pub"
	// PurposeTenantKeyContinuity is farmer telling a sprout, under a
	// tenant key the sprout has pinned, which tenant key replaces it.
	PurposeTenantKeyContinuity = "f2s.tenantkey.continuity"
	// PurposeEnrollProof is a sprout proving, at enrollment, that it holds
	// the private half of the box public key it enrolled with
	// (internal/pki's enroll.go). Sealed under that key, so only its
	// holder (or the tenant key's) could have produced it.
	PurposeEnrollProof = "s2f.enroll.proof"
)

// Control-plane purposes (docs/design/imas-payload-encryption-design.md,
// "Sealing the control plane", J.1). Two more direction prefixes: c2f/f2c
// is the imas CLI to farmer and back, a2f/f2a the SaaS API to farmer and
// back. Every request is a Call (control.go), bound to its method and its
// NATS subject; every reply is a Reply bound to the request's ID.
// Message.SproutID carries the non-farmer principal's ID: a user's NKey
// public key for c2f/f2c, PrincipalSaaSAPI for a2f/f2a, the sprout ID for
// s2f.refresh and f2s.refresh. A principal of one kind can't pass for another, because
// each kind has purposes of its own.
const (
	// PurposeCLIRequest is a CLI user's sealed imas.api.<method> request,
	// and PurposeCLIReply farmer's sealed reply to it (to any c2f
	// purpose).
	PurposeCLIRequest = "c2f.api"
	PurposeCLIReply   = "f2c.api"
	// PurposeCLIUserKeySubmit is a CLI user reporting a new CLI box public
	// key of their own, sealed under their current key: the CLI's
	// counterpart of PurposeBoxKeySubmit (imas auth rotate-key).
	PurposeCLIUserKeySubmit = "c2f.userkey.pub"

	// The SaaS API's requests on internal.tenant.provision,
	// internal.tenant.deprovision and internal.sprout.action.
	PurposeSaaSTenantProvision   = "a2f.tenant.provision"
	PurposeSaaSTenantDeprovision = "a2f.tenant.deprovision"
	PurposeSaaSSproutAction      = "a2f.sprout.action"
	// Farmer's results: the asynchronous provisioning results published
	// on internal.tenant.(de)provisioned.<job_id>, and the reply to
	// internal.sprout.action. A result is sealed as a Call (bound to its
	// subject, which names the job), the reply as a Reply.
	PurposeSaaSTenantProvisioned   = "f2a.tenant.provisioned"
	PurposeSaaSTenantDeprovisioned = "f2a.tenant.deprovisioned"
	PurposeSaaSSproutActionReply   = "f2a.sprout.action"

	// PurposeRefresh is a box-ready sprout's sealed proof on POST
	// /v1/refresh (Decision C), replacing the NKey signature the bus can
	// obtain from a CONNECT nonce.
	PurposeRefresh = "s2f.refresh"
	// PurposeRefreshReply is farmer's sealed answer to it (J.2): a Reply
	// bound by ReplyTo to the request's ID, carrying the new gateway JWT,
	// sealed to the sprout's active box key.
	PurposeRefreshReply = "f2s.refresh"
)

// PrincipalHeader names the principal a sealed control-plane request
// claims to come from: a user's NKey public key, or PrincipalSaaSAPI. A
// hint telling farmer which registered box keys to try, never trusted on
// its own: the request must open under that principal's key, and its
// Message.SproutID must equal the header.
const PrincipalHeader = "Imas-Principal"

// PrincipalSaaSAPI is the principal ID (Message.SproutID) of the SaaS
// API. The SaaS API's purposes are its own, so no user or sprout ID can
// stand in for it either way.
const PrincipalSaaSAPI = "saasapi"

// PlatformTenantID is Message.TenantID on a2f/f2a messages, which belong
// to the deployment, not to one tenant: they are sealed under the
// platform key, not a tenant key. '@' is outside the tenant ID alphabet
// ([0-9A-Za-z_-], internal/pki IsValidTenantID), so no tenant can be
// named this. The tenant a SaaS API request concerns travels in its
// params and is checked at the point of effect, as today.
const PlatformTenantID = "@platform"

// Version is the only Envelope and Message version this package reads or
// writes. 2 added Message.TenantID and Message.RecipientKey; a version 1
// envelope, which binds neither, never opens.
const Version = 2

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
	V       int    `json:"v"`
	Purpose string `json:"p"`
	// TenantID is the tenant the message belongs to: the sprout's
	// tenant, for both directions. Open refuses any other.
	TenantID string `json:"tid"`
	SproutID string `json:"sid"`
	// RecipientKey is KeyID of the box public key this copy was sealed
	// to: the sprout's box key for f2s, the tenant's for s2f. Seal sets
	// it per copy; whatever the caller put there is overwritten.
	RecipientKey string `json:"rk"`
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

// KeyID identifies a box public key without revealing anything the key
// itself doesn't: the first 16 bytes of SHA-256 over a domain tag and the
// key, unpadded base64url.
func KeyID(pub *[32]byte) string {
	h := sha256.New()
	h.Write([]byte("imas-payloadbox-key-id-v1\n"))
	h.Write(pub[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

// keyIDOfPriv is KeyID of priv's public half.
func keyIDOfPriv(priv *[32]byte) (string, bool) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", false
	}
	var p [32]byte
	copy(p[:], pub)
	return KeyID(&p), true
}

// NewMessage builds a Message for purpose, in tenantID, addressed to (or
// sent by) sproutID, with a fresh ID and IssuedAt, and body
// JSON-marshalled.
func NewMessage(purpose, tenantID, sproutID, replyTo string, body any) (Message, error) {
	id, err := NewID()
	if err != nil {
		return Message{}, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return Message{}, fmt.Errorf("payloadbox: encoding body: %w", err)
	}
	return Message{
		V: Version, Purpose: purpose, TenantID: tenantID, SproutID: sproutID, ID: id, ReplyTo: replyTo,
		IssuedAt: now().Unix(), Body: b,
	}, nil
}

// Seal seals msg once per key pair in pairs, each copy under a fresh
// random nonce and naming its own recipient key (Message.RecipientKey,
// KeyID of the pair's PeerPub), and returns the JSON Envelope.
func Seal(msg Message, pairs []KeyPair) ([]byte, error) {
	if len(pairs) == 0 {
		return nil, errors.New("payloadbox: no key pairs to seal under")
	}
	if len(pairs) > MaxCopies {
		return nil, fmt.Errorf("payloadbox: %d key pairs exceeds the %d-copy limit", len(pairs), MaxCopies)
	}
	if msg.V != Version || msg.Purpose == "" || msg.TenantID == "" || msg.SproutID == "" || msg.ID == "" {
		return nil, errors.New("payloadbox: message is missing its version, purpose, tenant id, sprout id or id")
	}
	env := Envelope{V: Version, Copies: make([]Sealed, 0, len(pairs))}
	for _, p := range pairs {
		if p.PeerPub == nil || p.Priv == nil {
			return nil, errors.New("payloadbox: nil key in key pair")
		}
		msg.RecipientKey = KeyID(p.PeerPub)
		plaintext, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("payloadbox: encoding message: %w", err)
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

// Expect is what Open checks an opened Message against. Every field is
// required: an empty one matches nothing, so a caller that forgets the
// tenant fails closed.
//
// The recipient key is checked too, but not from here: Open compares the
// Message's RecipientKey with the public half of the candidate private
// key that opened it, so it can't be left out or set wrongly.
type Expect struct {
	Purpose  string
	TenantID string
	SproutID string
}

// Open opens data, a JSON Envelope, under the first candidate key pair
// any of its copies opens with, and checks the Message's version,
// purpose, tenant, sprout ID and recipient key: purpose, tenant and
// sprout against want, the recipient key against the candidate private
// key that opened the copy. Freshness and replay are the caller's
// (ReplayGuard, or ReplyTo matching). Every failure is ErrOpen.
func Open(data []byte, candidates []KeyPair, want Expect) (*Message, error) {
	if len(data) > MaxEnvelopeBytes || len(candidates) == 0 {
		return nil, ErrOpen
	}
	if want.Purpose == "" || want.TenantID == "" || want.SproutID == "" {
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
			if msg.V != Version || msg.Purpose != want.Purpose || msg.TenantID != want.TenantID ||
				msg.SproutID != want.SproutID || msg.ID == "" {
				return nil, ErrOpen
			}
			if rk, ok := keyIDOfPriv(k.Priv); !ok || msg.RecipientKey != rk {
				return nil, ErrOpen
			}
			return &msg, nil
		}
	}
	return nil, ErrOpen
}
