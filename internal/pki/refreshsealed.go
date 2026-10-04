package pki

// Sealed refresh proofs (docs/design/imas-payload-encryption-design.md,
// "Sealing the control plane", Decision C, J.1). FLAG FOR SECURITY
// REVIEW.
//
// The NKey proof on POST /v1/refresh (RefreshSigningPayload) is a
// signature by the same seed that signs the bus's CONNECT nonce, so a
// compromised bus can get one made and refresh as any sprout. The sealed
// proof replaces it: a payloadbox message (purpose s2f.refresh, sid the
// sprout ID, body {nkey_pub, timestamp}) sealed with the sprout's box key
// to its pinned tenant key. Only the holder of that box key can make one,
// and that key signs no bus nonce.
//
// Building blocks only: RefreshSprout doesn't call OpenSealedRefresh yet
// and the sprout doesn't send one (rollout step 3). Owner decision
// 2026-10-04: at step 3 the sealed proof is the only one accepted, with
// no NKey-only fallback and no per-sprout ratchet, and a sprout with no
// box key is refused (re-enrol it), not downgraded.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// sealedRefreshBody is a sealed refresh proof's body.
type sealedRefreshBody struct {
	NKeyPub   string `json:"nkey_pub"`
	Timestamp int64  `json:"timestamp"`
}

// SproutSealedRefresh builds this sprout's sealed refresh proof for
// sproutID, whose NKey public key is nkeyPub (SproutSealForFarmer: the
// current box key, to the pinned tenant key and tenant).
func SproutSealedRefresh(sproutID, nkeyPub string) ([]byte, error) {
	return SproutSealForFarmer(sproutID, payloadbox.PurposeRefresh, "",
		sealedRefreshBody{NKeyPub: nkeyPub, Timestamp: enrollNow().Unix()})
}

// errSealedRefreshStale: the proof's timestamp or issue time is outside
// EnrollSigMaxSkew. Logged locally only.
var errSealedRefreshStale = errors.New("sealed refresh proof is outside the freshness window")

// OpenSealedRefresh verifies sealed, a sealed refresh proof sent with
// nkeyPub, and returns the accepted sprout it proves to be. The proof
// must open under one of the sprout's valid box keys and one of the
// tenant's retained keys (back to the last severing rotation, as a
// continuity proof reaches, so a sprout whose pin is out of date can
// still refresh and re-pin); name nkeyPub; be fresh (±EnrollSigMaxSkew,
// both its timestamp and its issue time); and not have been claimed
// before on any replica (ClaimSealedMessage). Every failure is
// ErrEnrollmentFailed, like every other refresh failure, with the reason
// in farmer's log only.
func OpenSealedRefresh(ctx context.Context, nkeyPub string, sealed []byte) (tenantID, sproutID string, err error) {
	if !nkeys.IsValidPublicUserKey(nkeyPub) || len(sealed) == 0 {
		log.Warnf("refresh: rejected a malformed sealed refresh")
		return "", "", ErrEnrollmentFailed
	}
	tenantID, sproutID, err = SproutIDAndTenantForNKey(nkeyPub)
	if err != nil {
		log.Warnf("refresh: nkey_pub %s is not an accepted sprout", nkeyPub)
		return "", "", ErrEnrollmentFailed
	}
	msg, err := openSealedRefresh(tenantID, sproutID, sealed)
	if err != nil {
		log.Warnf("refresh: sealed proof for sprout %s in tenant %s didn't open: %v", sproutID, tenantID, err)
		return "", "", ErrEnrollmentFailed
	}
	var body sealedRefreshBody
	if err := json.Unmarshal(msg.Body, &body); err != nil || body.NKeyPub != nkeyPub {
		log.Warnf("refresh: sealed proof for sprout %s names another NKey", sproutID)
		return "", "", ErrEnrollmentFailed
	}
	now := enrollNow()
	for _, t := range []int64{body.Timestamp, msg.IssuedAt} {
		if d := now.Sub(time.Unix(t, 0)); d > EnrollSigMaxSkew || d < -EnrollSigMaxSkew {
			log.Warnf("refresh: sealed proof for sprout %s: %v", sproutID, errSealedRefreshStale)
			return "", "", ErrEnrollmentFailed
		}
	}
	if err := ClaimSealedMessage(ctx, tenantID, sproutID, msg.ID); err != nil {
		log.Warnf("refresh: sealed proof for sprout %s not claimed: %v", sproutID, err)
		return "", "", ErrEnrollmentFailed
	}
	return tenantID, sproutID, nil
}

// openSealedRefresh opens sealed under every retained tenant key against
// every valid box key of the sprout, re-reading the tenant's keys once if
// the cached set is old enough.
func openSealedRefresh(tenantID, sproutID string, sealed []byte) (*payloadbox.Message, error) {
	active, grace, err := ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		return nil, err
	}
	var sproutPubs []*[32]byte
	for _, p := range append([]string{active}, grace...) {
		if pub, err := DecodeBoxPubKey(p); err == nil {
			sproutPubs = append(sproutPubs, pub)
		}
	}
	want := payloadbox.Expect{Purpose: payloadbox.PurposeRefresh, TenantID: tenantID, SproutID: sproutID}
	open := func() (*payloadbox.Message, error) {
		set, err := loadTenantKeySet(tenantID)
		if err != nil {
			return nil, err
		}
		privs := []*[32]byte{set.current.priv}
		for _, p := range set.previous {
			privs = append(privs, p.priv)
		}
		var candidates []payloadbox.KeyPair
		for _, tk := range privs {
			for _, sp := range sproutPubs {
				candidates = append(candidates, payloadbox.KeyPair{PeerPub: sp, Priv: tk})
			}
		}
		return payloadbox.Open(sealed, candidates, want)
	}
	msg, err := open()
	if !errors.Is(err, payloadbox.ErrOpen) || !tenantBoxCachedLongerThan(tenantID, tenantBoxRereadAfter) {
		return msg, err
	}
	InvalidateTenantBoxKeys(tenantID)
	return open()
}
