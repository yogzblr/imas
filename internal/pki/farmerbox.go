package pki

// Farmer's end of sealed farmer<->sprout payloads
// (docs/design/imas-payload-encryption-design.md, workstream J): the key
// lookups around internal/payloadbox's Seal and Open. Lives here, not in
// internal/natsapi, because both natsapi's handlers and
// internal/ingredients/cmd's FRun (which natsapi imports) seal payloads.
//
// FLAG FOR SECURITY REVIEW. Keys: the tenant's keypair(s) from
// TenantBoxKeys (the current one, plus the previous one inside a
// rotation's grace window) and the sprout's box public key(s) from
// ValidSproutBoxKeys (its active key, plus a former one inside its own
// grace window). Every lookup is by (tenant_id, sprout_id), never
// sprout_id alone (CLAUDE.md, "Tenant safety"), and every message
// sealed or opened here names tenant_id (payloadbox.Message.TenantID):
// farmer seals the tenant into everything and refuses anything that
// names another (security review 2026-10, H3).

import (
	"errors"
	"time"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// SealToSprout seals body for sproutID under purpose, returning the
// envelope and the message ID (a reply's ReplyTo must match it). It
// seals to the sprout's *active* box key only: a sprout's grace-period
// keys are for opening what it sent before it rotated, not for new
// traffic. One copy per tenant key TenantBoxKeys returns, so a sprout
// that hasn't re-pinned since a rotation still opens it.
//
// ErrNoActiveBoxKey means the sprout has no box key on record — it
// enrolled before workstream J and can't open anything; any other error
// means the payload must not be sent.
func SealToSprout(tenantID, sproutID, purpose, replyTo string, body any) (data []byte, msgID string, err error) {
	active, _, err := ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		return nil, "", err
	}
	sproutPub, err := DecodeBoxPubKey(active)
	if err != nil {
		return nil, "", err
	}
	tenantKeys, err := TenantBoxKeys(tenantID)
	if err != nil {
		return nil, "", err
	}
	pairs := make([]payloadbox.KeyPair, 0, len(tenantKeys))
	for _, k := range tenantKeys {
		pairs = append(pairs, payloadbox.KeyPair{PeerPub: sproutPub, Priv: k.Priv})
	}
	msg, err := payloadbox.NewMessage(purpose, tenantID, sproutID, replyTo, body)
	if err != nil {
		return nil, "", err
	}
	data, err = payloadbox.Seal(msg, pairs)
	if err != nil {
		return nil, "", err
	}
	return data, msg.ID, nil
}

// tenantBoxRereadAfter is how old a cached tenant key set must be before
// a payload that doesn't open under it triggers a re-read from OpenBao
// (in case the sprout re-pinned to a key another replica rotated to).
// Stops a bus replaying garbage from turning each message into an
// OpenBao round trip.
const tenantBoxRereadAfter = 5 * time.Second

// OpenFromSprout opens data, an envelope sproutID sent under purpose,
// trying every tenant key TenantBoxKeys returns against every box key
// ValidSproutBoxKeys returns for the sprout. Any failure to open is
// payloadbox.ErrOpen; freshness is the caller's to check (a reply's
// ReplyTo, or a timestamp window).
func OpenFromSprout(tenantID, sproutID, purpose string, data []byte) (*payloadbox.Message, error) {
	active, grace, err := ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		if errors.Is(err, ErrNoActiveBoxKey) {
			return nil, payloadbox.ErrOpen
		}
		return nil, err
	}
	var sproutPubs []*[32]byte
	for _, p := range append([]string{active}, grace...) {
		if pub, err := DecodeBoxPubKey(p); err == nil {
			sproutPubs = append(sproutPubs, pub)
		}
	}
	want := payloadbox.Expect{Purpose: purpose, TenantID: tenantID, SproutID: sproutID}
	open := func() (*payloadbox.Message, error) {
		tenantKeys, err := TenantBoxKeys(tenantID)
		if err != nil {
			return nil, err
		}
		var candidates []payloadbox.KeyPair
		for _, tk := range tenantKeys {
			for _, sp := range sproutPubs {
				candidates = append(candidates, payloadbox.KeyPair{PeerPub: sp, Priv: tk.Priv})
			}
		}
		return payloadbox.Open(data, candidates, want)
	}
	msg, err := open()
	if !errors.Is(err, payloadbox.ErrOpen) {
		return msg, err
	}
	if !tenantBoxCachedLongerThan(tenantID, tenantBoxRereadAfter) {
		return nil, err
	}
	InvalidateTenantBoxKeys(tenantID)
	return open()
}

// tenantBoxCachedLongerThan reports whether tenantID's cached key set
// was loaded more than d ago.
func tenantBoxCachedLongerThan(tenantID string, d time.Duration) bool {
	e := tenantBoxEntryFor(tenantID)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.set != nil && time.Since(e.set.loaded) > d
}

// openEnrollProof opens proof, a sprout's enrollment proof of possession
// (payloadbox.PurposeEnrollProof) for sproutID in tenantID, under every
// tenant key TenantBoxKeys returns paired with sproutPub, the box public
// key the sprout is enrolling with: not one on record, which is the
// point. Any failure is payloadbox.ErrOpen; the caller checks the body
// and freshness (enroll.go's verifyEnrollProof).
func openEnrollProof(tenantID, sproutID, sproutPub string, proof []byte) (*payloadbox.Message, error) {
	sp, err := DecodeBoxPubKey(sproutPub)
	if err != nil {
		return nil, payloadbox.ErrOpen
	}
	tenantKeys, err := TenantBoxKeys(tenantID)
	if err != nil {
		return nil, err
	}
	candidates := make([]payloadbox.KeyPair, 0, len(tenantKeys))
	for _, tk := range tenantKeys {
		candidates = append(candidates, payloadbox.KeyPair{PeerPub: sp, Priv: tk.Priv})
	}
	return payloadbox.Open(proof, candidates,
		payloadbox.Expect{Purpose: payloadbox.PurposeEnrollProof, TenantID: tenantID, SproutID: sproutID})
}
