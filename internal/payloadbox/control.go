package payloadbox

// Sealed control-plane requests and replies
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", J.1). FLAG FOR SECURITY REVIEW.
//
// A Call is a request farmer acts on, from the imas CLI (c2f) or the SaaS
// API (a2f), or an asynchronous result farmer publishes to the SaaS API
// (f2a.tenant.(de)provisioned). A Reply answers one Call. Both are
// ordinary Messages whose Body is a CallBody or ReplyBody, so they get
// everything Seal and Open already give (purpose, tenant, principal and
// recipient key binding, fresh IDs). What this file adds:
//
//   - Method and subject binding. The body names the method and the full
//     NATS subject it was sent on, and OpenCall refuses one whose method
//     or subject isn't the one the receiver derived from the subject the
//     message actually arrived on. Without it a bus could move a sealed
//     jobs.list onto imas.api.jobs.delete, or a provisioning result for
//     one job onto another job's subject.
//   - Reply binding. A Reply must name the ID of the request it answers
//     (Message.ReplyTo), and a Call must name none, so neither can pass
//     for the other even if a purpose were reused by mistake.
//
// Freshness and replay are the receiver's: farmer runs every Call through
// a ReplayGuard and, for a method that changes state, a cluster-wide claim
// (internal/natsapi's sealedapi.go); a requester accepts only the Reply
// whose ReplyTo is the request it just sent. These helpers do no I/O and
// hold no keys: both ends call them with the key pairs their side owns.

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// CallBody is the authenticated body of a Call.
type CallBody struct {
	// Method is the method name: the subject after its fixed prefix
	// ("jobs.list" on imas.api.jobs.list, "tenant.provision" on
	// internal.tenant.provision).
	Method string `json:"method"`
	// Subject is the full NATS subject the Call was published on.
	Subject string          `json:"subject"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ReplyBody is the authenticated body of a Reply. A handler's error
// travels here, inside the box, never in a plaintext header: only a
// failure to open the request uses ErrorHeader's fixed codes.
type ReplyBody struct {
	Method  string          `json:"method"`
	Subject string          `json:"subject"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	// Continuity is reserved for f2c.tenantkey.continuity (the shell
	// section's Decision 1): a proof, sealed to the CLI's box key under
	// each retained earlier tenant key, that the current tenant key
	// succeeds the one the CLI pinned. Not produced yet (J.4).
	Continuity json.RawMessage `json:"continuity,omitempty"`
}

// Call is everything SealCall needs.
type Call struct {
	Purpose string
	// TenantID is the tenant whose key the Call is sealed to, or
	// PlatformTenantID for an a2f/f2a Call.
	TenantID string
	// Principal is the non-farmer end's ID (Message.SproutID): the
	// sender of a c2f/a2f/s2f Call, the recipient of an f2a one.
	Principal string
	Method    string
	Subject   string
	// Params is JSON-marshalled into CallBody.Params; nil omits it.
	Params any
}

// Reply is everything SealReply needs.
type Reply struct {
	Purpose   string
	TenantID  string
	Principal string
	// ReplyTo is the ID of the Call this answers. Required.
	ReplyTo string
	Method  string
	Subject string
	// Result is JSON-marshalled into ReplyBody.Result; nil omits it.
	Result     any
	Error      string
	Continuity json.RawMessage
}

// CallExpect is what OpenCall checks an opened Call against. Every field
// is required: an empty one matches nothing.
type CallExpect struct {
	Purpose   string
	TenantID  string
	Principal string
	Method    string
	Subject   string
}

// ReplyExpect is what OpenReply checks an opened Reply against. Every
// field is required.
type ReplyExpect struct {
	Purpose   string
	TenantID  string
	Principal string
	ReplyTo   string
	Method    string
	Subject   string
}

func marshalOptional(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	if raw, ok := v.(json.RawMessage); ok {
		if len(raw) == 0 {
			return nil, nil
		}
		if !json.Valid(raw) {
			return nil, errors.New("payloadbox: raw JSON is not valid")
		}
		return raw, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("payloadbox: encoding: %w", err)
	}
	return b, nil
}

// SealCall seals c once per key pair (Seal) and returns the envelope and
// the Call's message ID, which the Reply must name.
func SealCall(c Call, pairs []KeyPair) (data []byte, msgID string, err error) {
	if c.Method == "" || c.Subject == "" {
		return nil, "", errors.New("payloadbox: a call needs its method and subject")
	}
	params, err := marshalOptional(c.Params)
	if err != nil {
		return nil, "", err
	}
	msg, err := NewMessage(c.Purpose, c.TenantID, c.Principal, "",
		CallBody{Method: c.Method, Subject: c.Subject, Params: params})
	if err != nil {
		return nil, "", err
	}
	data, err = Seal(msg, pairs)
	if err != nil {
		return nil, "", err
	}
	return data, msg.ID, nil
}

// OpenCall opens data under the candidate key pairs (Open) and checks it
// is a Call matching want: purpose, tenant and principal by Open, then no
// ReplyTo, and the body's method and subject. Every failure is ErrOpen.
// Freshness and replay are the caller's (ReplayGuard).
func OpenCall(data []byte, candidates []KeyPair, want CallExpect) (*Message, *CallBody, error) {
	if want.Method == "" || want.Subject == "" {
		return nil, nil, ErrOpen
	}
	msg, err := Open(data, candidates, Expect{Purpose: want.Purpose, TenantID: want.TenantID, SproutID: want.Principal})
	if err != nil {
		return nil, nil, ErrOpen
	}
	if msg.ReplyTo != "" {
		return nil, nil, ErrOpen
	}
	var body CallBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return nil, nil, ErrOpen
	}
	if body.Method != want.Method || body.Subject != want.Subject {
		return nil, nil, ErrOpen
	}
	return msg, &body, nil
}

// SealReply seals r once per key pair (Seal).
func SealReply(r Reply, pairs []KeyPair) ([]byte, error) {
	if r.ReplyTo == "" || r.Method == "" || r.Subject == "" {
		return nil, errors.New("payloadbox: a reply needs the request id, method and subject it answers")
	}
	result, err := marshalOptional(r.Result)
	if err != nil {
		return nil, err
	}
	msg, err := NewMessage(r.Purpose, r.TenantID, r.Principal, r.ReplyTo, ReplyBody{
		Method: r.Method, Subject: r.Subject, Result: result, Error: r.Error, Continuity: r.Continuity,
	})
	if err != nil {
		return nil, err
	}
	return Seal(msg, pairs)
}

// OpenReply opens data under the candidate key pairs (Open) and checks it
// is the Reply want describes: purpose, tenant and principal by Open, then
// ReplyTo, and the body's method and subject. Every failure is ErrOpen.
func OpenReply(data []byte, candidates []KeyPair, want ReplyExpect) (*Message, *ReplyBody, error) {
	if want.ReplyTo == "" || want.Method == "" || want.Subject == "" {
		return nil, nil, ErrOpen
	}
	msg, err := Open(data, candidates, Expect{Purpose: want.Purpose, TenantID: want.TenantID, SproutID: want.Principal})
	if err != nil {
		return nil, nil, ErrOpen
	}
	if msg.ReplyTo != want.ReplyTo {
		return nil, nil, ErrOpen
	}
	var body ReplyBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return nil, nil, ErrOpen
	}
	if body.Method != want.Method || body.Subject != want.Subject {
		return nil, nil, ErrOpen
	}
	return msg, &body, nil
}

// Fingerprint is how a box public key is shown to a person (imas auth
// keygen, admin listings): KeyID, prefixed so it can't be mistaken for
// the key itself.
func Fingerprint(pub *[32]byte) string { return "box1:" + KeyID(pub) }

// ErrWeakKey means a box public key is one whose Diffie-Hellman output
// is the same whatever the private key: the all-zero point or another of
// low order. A box under such a key is one anybody can seal and open.
var ErrWeakKey = errors.New("payloadbox: box public key is a low-order point")

// checkScalar is any clamped X25519 scalar: a low-order point multiplied
// by it is the identity, which curve25519.X25519 refuses.
var checkScalar = [32]byte{8: 1, 31: 64}

// CheckPublicKey refuses a box public key that must never be registered
// for a principal or accepted as a peer's ephemeral key (ErrWeakKey).
func CheckPublicKey(pub *[32]byte) error {
	if pub == nil {
		return ErrWeakKey
	}
	if _, err := curve25519.X25519(checkScalar[:], pub[:]); err != nil {
		return ErrWeakKey
	}
	return nil
}
