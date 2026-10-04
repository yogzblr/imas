package pki

// Sealed gateway JWT refresh: POST /v1/refresh
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", Decision C; J.1 built the proof, J.2 wires it in). FLAG FOR
// SECURITY REVIEW.
//
// The refresh used to be authenticated by the sprout's NKey signature
// over RefreshSigningPayload. The same seed signs the bus's CONNECT
// nonce, which a compromised bus chooses, so the bus could get a valid
// refresh proof made and mint gateway JWTs for any sprout, which read the
// sprout's staged rendered recipe from /files/. Now:
//
//   - Request: {nkey_pub, sealed}. sealed is a payloadbox message,
//     purpose s2f.refresh, sid the sprout ID, tid its pinned tenant, body
//     {nkey_pub, timestamp}, sealed with the sprout's box key to its
//     pinned tenant key (SproutSealedRefresh). The box key signs no bus
//     nonce, so nothing the bus can obtain opens as one.
//   - Farmer (RefreshSprout) looks the sprout up by nkey_pub, giving
//     (tenant_id, sprout_id); opens the message under the sprout's valid
//     box keys (active, and any in grace) and every retained tenant key
//     back to the last severing rotation; requires a request (no
//     ReplyTo), the same nkey_pub, and a timestamp and issue time within
//     EnrollSigMaxSkew; and claims the message ID once, cluster-wide
//     (ClaimSealedMessage, Valkey, fail closed). Only then does it mint.
//   - Reply: {sealed}. A payloadbox Reply, purpose f2s.refresh, ReplyTo
//     the request's ID, its Result the RefreshResponse (gateway JWT, User
//     JWT, tenant ID and key, continuity proof), sealed to the sprout's
//     active box key under the tenant key the request opened with (the
//     one the sprout has pinned). The sprout accepts only the reply that
//     opens under its pinned tenant key and names its own request, so a
//     DMZ that sees the HTTP exchange (Envoy terminates TLS) learns no
//     gateway JWT from it, and can't answer with an old reply.
//
// Owner decisions, 2026-10-04: this is the only refresh farmer accepts.
// There is no NKey-only fallback and no per-sprout ratchet, and a sprout
// with no box key on record (or no keys or pins of its own) is refused:
// it re-enrolls. Every failure is ErrEnrollmentFailed on the wire, with
// the reason in farmer's log only.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// PurposeRefreshReply is farmer's sealed answer to an s2f.refresh
// (payloadbox.PurposeRefresh). Defined here rather than beside the other
// purposes in internal/payloadbox, which J.2 uses without changing; to
// payloadbox it is an ordinary purpose string, bound and checked like
// any other. The f2s prefix keeps it apart from the request it answers:
// box keys are symmetric, so a reply reflected back at farmer must not
// open as a request.
const PurposeRefreshReply = "f2s.refresh"

// RefreshMethod and RefreshSubject are what a refresh reply binds as its
// method and subject (payloadbox.ReplyBody): the HTTP route it answers.
const (
	RefreshMethod  = "refresh"
	RefreshSubject = "POST /v1/refresh"
)

// maxRefreshCopies bounds how many sealed copies a refresh envelope may
// carry. The sprout sends one, or two while a box key rotation is
// pending; more is refused before any box is opened, so a caller can't
// make farmer try payloadbox.MaxCopies copies against every key pair.
const maxRefreshCopies = 2

// sealedRefreshBody is a sealed refresh proof's body.
type sealedRefreshBody struct {
	NKeyPub   string `json:"nkey_pub"`
	Timestamp int64  `json:"timestamp"`
}

// ---- the sprout's side -------------------------------------------------

// SproutSealedRefresh builds this sprout's sealed refresh request for
// sproutID, whose NKey public key is nkeyPub, and returns it with its
// message ID, which farmer's reply must name. It is sealed under the
// pinned tenant key and tenant (as SproutSealForFarmer seals), with the
// sprout's current box key, and also with its pending one while a box
// key rotation is in progress: farmer may already have recorded the
// pending key and, once the current one leaves farmer's grace window,
// opens only that copy. A copy farmer has no key for simply doesn't open.
func SproutSealedRefresh(sproutID, nkeyPub string) (sealed []byte, msgID string, err error) {
	keys, err := loadSproutBoxKeys()
	if err != nil {
		return nil, "", err
	}
	defer keys.wipe()
	msg, err := payloadbox.NewMessage(payloadbox.PurposeRefresh, keys.tenantID, sproutID, "",
		sealedRefreshBody{NKeyPub: nkeyPub, Timestamp: enrollClock().Unix()})
	if err != nil {
		return nil, "", err
	}
	pairs := []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: keys.current}}
	if keys.pending != nil {
		pairs = append(pairs, payloadbox.KeyPair{PeerPub: keys.tenantPub, Priv: keys.pending})
	}
	sealed, err = payloadbox.Seal(msg, pairs)
	if err != nil {
		return nil, "", err
	}
	return sealed, msg.ID, nil
}

// sproutOpenRefreshReply opens data, farmer's sealed reply to the refresh
// request msgID that sproutID sent, under the pinned tenant key and
// tenant and each of the sprout's box keys (current, pending, previous),
// and returns its result. One that opens under the pending key promotes
// it, as any farmer payload does: farmer seals only to a key it has
// recorded. Every failure to open is payloadbox.ErrOpen; an error farmer
// sealed into the reply is returned as one.
func sproutOpenRefreshReply(sproutID, msgID string, data []byte) (*RefreshResponse, error) {
	keys, err := loadSproutBoxKeys()
	if err != nil {
		return nil, err
	}
	defer keys.wipe()
	want := payloadbox.ReplyExpect{
		Purpose: PurposeRefreshReply, TenantID: keys.tenantID, Principal: sproutID,
		ReplyTo: msgID, Method: RefreshMethod, Subject: RefreshSubject,
	}
	var body *payloadbox.ReplyBody
	pendingPub := ""
	for _, priv := range []*[32]byte{keys.current, keys.pending, keys.previous} {
		if priv == nil {
			continue
		}
		_, b, err := payloadbox.OpenReply(data, []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: priv}}, want)
		if err != nil {
			continue
		}
		if priv == keys.pending {
			if pendingPub, err = boxPubFromPriv(priv); err != nil {
				return nil, err
			}
		}
		body = b
		break
	}
	if body == nil {
		return nil, payloadbox.ErrOpen
	}
	promoteAfterOpen(pendingPub)
	if body.Error != "" {
		return nil, fmt.Errorf("pki: farmer refused the refresh: %s", body.Error)
	}
	var res RefreshResponse
	if err := json.Unmarshal(body.Result, &res); err != nil {
		return nil, payloadbox.ErrOpen
	}
	return &res, nil
}

// ---- farmer's side -----------------------------------------------------

// errSealedRefreshStale: the proof's timestamp or issue time is outside
// EnrollSigMaxSkew. Logged locally only.
var errSealedRefreshStale = errors.New("sealed refresh proof is outside the freshness window")

// openedRefresh is a sealed refresh request that verified: whose it is,
// its message ID, and the tenant private key it opened under (the key
// the sprout has pinned, which the reply is sealed with).
type openedRefresh struct {
	tenantID, sproutID, msgID string
	tenantPriv                *[32]byte
}

// OpenSealedRefresh verifies sealed, a sealed refresh request sent with
// nkeyPub, and returns the accepted sprout it proves to be, after
// claiming it (see verifySealedRefresh). RefreshSprout is the endpoint;
// this is its verification alone.
func OpenSealedRefresh(ctx context.Context, nkeyPub string, sealed []byte) (tenantID, sproutID string, err error) {
	o, err := verifySealedRefresh(ctx, nkeyPub, sealed)
	if err != nil {
		return "", "", err
	}
	return o.tenantID, o.sproutID, nil
}

// verifySealedRefresh checks sealed, a sealed refresh request sent with
// nkeyPub. nkeyPub must be an accepted sprout's; the request must open
// under one of that sprout's valid box keys and one of its tenant's
// retained keys (back to the last severing rotation, as a continuity
// proof reaches, so a sprout whose pin is out of date can still refresh
// and re-pin); be a request, not a reply; name nkeyPub; be fresh
// (±EnrollSigMaxSkew, both its timestamp and its issue time); and not
// have been claimed before on any replica (ClaimSealedMessage, which
// fails closed without Valkey). Every failure is ErrEnrollmentFailed,
// with the reason in farmer's log only.
func verifySealedRefresh(ctx context.Context, nkeyPub string, sealed []byte) (*openedRefresh, error) {
	if !nkeys.IsValidPublicUserKey(nkeyPub) || len(sealed) == 0 || len(sealed) > payloadbox.MaxEnvelopeBytes {
		log.Warnf("refresh: rejected a malformed sealed refresh")
		return nil, ErrEnrollmentFailed
	}
	var env payloadbox.Envelope
	if err := json.Unmarshal(sealed, &env); err != nil || len(env.Copies) == 0 || len(env.Copies) > maxRefreshCopies {
		log.Warnf("refresh: rejected a sealed refresh that is not a refresh envelope")
		return nil, ErrEnrollmentFailed
	}
	tenantID, sproutID, err := SproutIDAndTenantForNKey(nkeyPub)
	if err != nil {
		log.Warnf("refresh: nkey_pub %s is not an accepted sprout", nkeyPub)
		return nil, ErrEnrollmentFailed
	}
	msg, tenantPriv, err := openSealedRefresh(tenantID, sproutID, sealed)
	if err != nil {
		log.Warnf("refresh: sealed request for sprout %s in tenant %s didn't open: %v", sproutID, tenantID, err)
		return nil, ErrEnrollmentFailed
	}
	if msg.ReplyTo != "" {
		log.Warnf("refresh: sealed request for sprout %s names a request it answers", sproutID)
		return nil, ErrEnrollmentFailed
	}
	var body sealedRefreshBody
	if err := json.Unmarshal(msg.Body, &body); err != nil || body.NKeyPub != nkeyPub {
		log.Warnf("refresh: sealed request for sprout %s names another NKey", sproutID)
		return nil, ErrEnrollmentFailed
	}
	now := enrollNow()
	for _, t := range []int64{body.Timestamp, msg.IssuedAt} {
		if d := now.Sub(time.Unix(t, 0)); d > EnrollSigMaxSkew || d < -EnrollSigMaxSkew {
			log.Warnf("refresh: sealed request for sprout %s: %v", sproutID, errSealedRefreshStale)
			return nil, ErrEnrollmentFailed
		}
	}
	if err := ClaimSealedMessage(ctx, tenantID, sproutID, msg.ID); err != nil {
		log.Warnf("refresh: sealed request for sprout %s not claimed: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	return &openedRefresh{tenantID: tenantID, sproutID: sproutID, msgID: msg.ID, tenantPriv: tenantPriv}, nil
}

// openSealedRefresh opens sealed under each retained tenant key, newest
// first, against every valid box key of the sprout, and returns the
// message and the tenant private key it opened under. It re-reads the
// tenant's keys once if the cached set is old enough. A sprout with no
// active box key opens nothing.
func openSealedRefresh(tenantID, sproutID string, sealed []byte) (*payloadbox.Message, *[32]byte, error) {
	active, grace, err := ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		return nil, nil, err
	}
	var sproutPubs []*[32]byte
	for _, p := range append([]string{active}, grace...) {
		if pub, err := DecodeBoxPubKey(p); err == nil {
			sproutPubs = append(sproutPubs, pub)
		}
	}
	if len(sproutPubs) == 0 {
		return nil, nil, payloadbox.ErrOpen
	}
	want := payloadbox.Expect{Purpose: payloadbox.PurposeRefresh, TenantID: tenantID, SproutID: sproutID}
	open := func() (*payloadbox.Message, *[32]byte, error) {
		set, err := loadTenantKeySet(tenantID)
		if err != nil {
			return nil, nil, err
		}
		privs := []*[32]byte{set.current.priv}
		for _, p := range set.previous {
			privs = append(privs, p.priv)
		}
		for _, tk := range privs {
			candidates := make([]payloadbox.KeyPair, 0, len(sproutPubs))
			for _, sp := range sproutPubs {
				candidates = append(candidates, payloadbox.KeyPair{PeerPub: sp, Priv: tk})
			}
			if msg, err := payloadbox.Open(sealed, candidates, want); err == nil {
				return msg, tk, nil
			}
		}
		return nil, nil, payloadbox.ErrOpen
	}
	msg, tk, err := open()
	if !errors.Is(err, payloadbox.ErrOpen) || !tenantBoxCachedLongerThan(tenantID, tenantBoxRereadAfter) {
		return msg, tk, err
	}
	InvalidateTenantBoxKeys(tenantID)
	return open()
}

// RefreshRequest is one POST /v1/refresh request: the sprout's NKey
// public key, which says which sprout it claims to be, and its sealed
// request, which proves it.
type RefreshRequest struct {
	NKeyPub string
	Sealed  json.RawMessage
}

// RefreshSprout handles one sealed refresh: it verifies req
// (verifySealedRefresh), reissues the sprout's identity with a freshly
// minted gateway JWT (reissueExistingIdentity), and returns the reply
// sealed to the sprout (sealRefreshReply). An unknown, denied, rejected
// or deleted nkey_pub, a sprout with no box key on record, a request that
// doesn't open, is stale or was seen before, and an NKey-signed request
// of the old contract all fail the same way, ErrEnrollmentFailed.
func RefreshSprout(ctx context.Context, req RefreshRequest) (json.RawMessage, error) {
	o, err := verifySealedRefresh(ctx, req.NKeyPub, req.Sealed)
	if err != nil {
		return nil, err
	}
	res, err := reissueExistingIdentity(ctx, o.tenantID, o.sproutID, req.NKeyPub, true)
	if err != nil {
		return nil, err
	}
	reply, err := sealRefreshReply(o, RefreshResponse{
		SproutID: res.SproutID, TenantID: res.TenantID, JWT: res.JWT, GatewayJWT: res.GatewayJWT,
		NKeyIdentity: req.NKeyPub, TenantX25519Pub: res.TenantX25519Pub,
		TenantX25519Continuity: res.TenantX25519Continuity,
	})
	if err != nil {
		log.Errorf("refresh: sealing the reply to sprout %s in tenant %s: %v", o.sproutID, o.tenantID, err)
		return nil, ErrEnrollmentFailed
	}
	log.Debugf("refresh: issued a fresh gateway JWT for sprout %s", o.sproutID)
	return reply, nil
}

// sealRefreshReply seals res as the reply to o: to the sprout's active
// box key (as SealToSprout seals, so a reply under a pending key is the
// sprout's confirmation that farmer recorded it), under the tenant key
// o's request opened with, which is the one the sprout has pinned. A
// continuity proof inside it carries the sprout to the current tenant key.
func sealRefreshReply(o *openedRefresh, res RefreshResponse) (json.RawMessage, error) {
	active, _, err := ValidSproutBoxKeys(o.tenantID, o.sproutID)
	if err != nil {
		return nil, err
	}
	sproutPub, err := DecodeBoxPubKey(active)
	if err != nil {
		return nil, err
	}
	return payloadbox.SealReply(payloadbox.Reply{
		Purpose: PurposeRefreshReply, TenantID: o.tenantID, Principal: o.sproutID,
		ReplyTo: o.msgID, Method: RefreshMethod, Subject: RefreshSubject, Result: res,
	}, []payloadbox.KeyPair{{PeerPub: sproutPub, Priv: o.tenantPriv}})
}
