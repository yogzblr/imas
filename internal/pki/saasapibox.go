package pki

// The SaaS API's end of sealed SaaS API <-> farmer traffic
// (docs/design/imas-payload-encryption-design.md, Decision B, J.1 and
// J.4): its own box private key and the platform public key(s) it pins,
// both handed to it out of band (platformbox.go's file comment), never
// over the bus. internal/saasapi seals every internal.* request, and opens
// every reply and result, through it (J.4, rollout step 5): sealed only,
// with no plaintext fallback in either direction. FLAG FOR SECURITY REVIEW.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// SaaSAPIBox holds the SaaS API's keys. Safe for concurrent use.
type SaaSAPIBox struct {
	priv *[32]byte
	// platformPubs are the platform public keys the SaaS API pins, the
	// one it seals to first. More than one only across a platform key
	// rotation, until the SaaS API's next rollout re-pins.
	platformPubs []*[32]byte
	// guard refuses a stale or replayed farmer result
	// (f2a.tenant.(de)provisioned). The SaaS API's provisioning state
	// machine makes a replayed genuine result harmless; the guard is
	// defence in depth, as the design asks.
	guard *payloadbox.ReplayGuard
}

// NewSaaSAPIBox builds the SaaS API's end from its box private key and
// the pinned platform public keys (standard base64). The pins must be
// sound keys and not the SaaS API's own.
func NewSaaSAPIBox(priv *[32]byte, platformPubs ...string) (*SaaSAPIBox, error) {
	if priv == nil {
		return nil, errors.New("pki: SaaS API box private key is required")
	}
	if len(platformPubs) == 0 {
		return nil, errors.New("pki: at least one pinned platform public key is required")
	}
	own, err := boxPubFromPriv(priv)
	if err != nil {
		return nil, err
	}
	ownKey, err := decodeBoxKeyHalf(own)
	if err != nil {
		return nil, err
	}
	b := &SaaSAPIBox{priv: priv, guard: payloadbox.NewReplayGuard()}
	for _, p := range platformPubs {
		k, err := decodePinnedBoxPub(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("pki: pinned platform public key: %w", err)
		}
		// Compared as keys, not strings: the same key written another way
		// is still the SaaS API's own.
		if *k == *ownKey {
			return nil, errors.New("pki: the pinned platform key is the SaaS API's own key")
		}
		b.platformPubs = append(b.platformPubs, k)
	}
	return b, nil
}

// LoadSaaSAPIBox reads the private key from privFile (standard base64, the
// format the keygen Job's secret carries) and pins platformPubs.
func LoadSaaSAPIBox(privFile string, platformPubs ...string) (*SaaSAPIBox, error) {
	raw, err := readBoxPrivKey(privFile)
	if err != nil {
		return nil, err
	}
	var k [32]byte
	copy(k[:], raw)
	wipe(raw)
	return NewSaaSAPIBox(&k, platformPubs...)
}

func (b *SaaSAPIBox) sealPairs() []payloadbox.KeyPair {
	pairs := make([]payloadbox.KeyPair, 0, len(b.platformPubs))
	for _, p := range b.platformPubs {
		pairs = append(pairs, payloadbox.KeyPair{PeerPub: p, Priv: b.priv})
	}
	return pairs
}

// SealRequest seals a Call to farmer (a2f.tenant.provision,
// a2f.tenant.deprovision or a2f.sprout.action) for method on subject, one
// copy per pinned platform key, and returns its message ID for
// OpenReply.
func (b *SaaSAPIBox) SealRequest(purpose, method, subject string, params any) (data []byte, msgID string, err error) {
	return payloadbox.SealCall(payloadbox.Call{
		Purpose: purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		Method: method, Subject: subject, Params: params,
	}, b.sealPairs())
}

// OpenReply opens farmer's sealed reply (f2a.sprout.action) to the
// request whose ID is replyTo. Any failure is payloadbox.ErrOpen.
func (b *SaaSAPIBox) OpenReply(purpose, method, subject, replyTo string, data []byte) (*payloadbox.ReplyBody, error) {
	_, body, err := payloadbox.OpenReply(data, b.sealPairs(), payloadbox.ReplyExpect{
		Purpose: purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		ReplyTo: replyTo, Method: method, Subject: subject,
	})
	return body, err
}

// OpenResult opens an asynchronous farmer result (f2a.tenant.provisioned
// or f2a.tenant.deprovisioned) that arrived on subject, and accepts it
// once, within ±payloadbox.DefaultMaxSkew (payloadbox.ErrStale,
// payloadbox.ErrReplayed otherwise).
func (b *SaaSAPIBox) OpenResult(purpose, method, subject string, data []byte) (*payloadbox.CallBody, error) {
	msg, body, err := payloadbox.OpenCall(data, b.sealPairs(), payloadbox.CallExpect{
		Purpose: purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		Method: method, Subject: subject,
	})
	if err != nil {
		return nil, err
	}
	if err := b.guard.Accept(msg); err != nil {
		return nil, err
	}
	return body, nil
}

// SealSaaSAPIRequest seals params as the SaaS API's request on subject
// (internal.tenant.provision, internal.tenant.deprovision or
// internal.sprout.action), bound to that subject's purpose and method
// (SaaSAPIRequestWire), and returns the envelope and its message ID, which
// farmer's reply must name. Every call is a new message: a fresh random
// ID and the current time, so a re-send (the outbox sweeper's) is never a
// replay of an earlier one.
func (b *SaaSAPIBox) SealSaaSAPIRequest(subject string, params any) (data []byte, msgID string, err error) {
	w, ok := SaaSAPIRequestWire(subject)
	if !ok {
		return nil, "", fmt.Errorf("pki: %q is not a SaaS API request subject", subject)
	}
	return b.SealRequest(w.Purpose, w.Method, w.Subject, params)
}

// OpenSproutActionReply opens farmer's sealed reply to the
// internal.sprout.action request whose ID is requestID
// (SproutActionReplyWire). Any failure, a reply to another request
// included, is payloadbox.ErrOpen.
func (b *SaaSAPIBox) OpenSproutActionReply(requestID string, data []byte) (*payloadbox.ReplyBody, error) {
	w := SproutActionReplyWire()
	return b.OpenReply(w.Purpose, w.Method, w.Subject, requestID, data)
}

// OpenTenantResult opens farmer's sealed provisioning result for jobID,
// as it arrived on subject: it must be jobID's result subject
// (TenantResultWire), and the result must be sealed to that subject, so a
// result for one job can't be moved onto another's. It is accepted once,
// within ±payloadbox.DefaultMaxSkew of this clock (payloadbox.ErrStale,
// payloadbox.ErrReplayed). Every other failure is payloadbox.ErrOpen.
func (b *SaaSAPIBox) OpenTenantResult(deprovision bool, jobID, subject string, data []byte) (*payloadbox.CallBody, error) {
	w, err := TenantResultWire(deprovision, jobID)
	if err != nil || w.Subject != subject {
		return nil, payloadbox.ErrOpen
	}
	return b.OpenResult(w.Purpose, w.Method, w.Subject, data)
}
