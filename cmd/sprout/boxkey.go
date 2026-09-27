package main

// Farmer-triggered payload-encryption key rotation, the sprout's end of
// the bus (docs/design/imas-payload-encryption-design.md's "Key
// rotation", workstream J). The key custody (generating the new key,
// keeping the old one, switching over) is internal/pki's sproutbox.go:
// see its "Box key rotation" section.
//
// FLAG FOR SECURITY REVIEW. The sprout rotates only when farmer's trigger
// arrives (farmer's handlePKIRotateBoxKey, MethodPKIRotateBoxKey), never
// on a schedule or on its own judgement: periodic rotation, if wanted,
// belongs to whatever drives that admin method.
//
// The trigger is an empty message on a subject anything that can publish
// on the bus can publish on, and the sprout acts on it unauthenticated.
// Accepted: it carries nothing to forge, and all a forged one can do is
// make the sprout rotate early. The new key is generated here and its
// private half never leaves the sprout; the submission is sealed under
// the current key, so only this sprout can have sent it; farmer never
// re-activates a superseded key (pki.RotateSproutBoxKey); and a trigger
// while a rotation is unconfirmed resubmits the same key, and one inside
// the last rotation's grace window is refused
// (pki.ErrSproutBoxKeyRotationTooSoon), so repeated forged triggers
// don't churn keys.

import (
	"errors"

	"github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// boxKeyRotateSubject is where farmer's rotate trigger arrives
// (internal/natsapi's SproutBoxKeyRotateCmd).
func boxKeyRotateSubject(id string) string { return "imas.sprouts." + id + ".boxkey.rotate" }

// boxKeySubmitSubject is where the sprout submits its new public key
// (internal/natsapi's SproutBoxKeySubmitPattern).
func boxKeySubmitSubject(id string) string { return "imas.sprouts." + id + ".boxkey.pub" }

// subscribeBoxKeyRotate rotates this sprout's box key each time farmer's
// trigger arrives on nc. Triggers are handled one at a time, in order.
func subscribeBoxKeyRotate(nc *nats.Conn, sproutID string) error {
	_, err := nc.Subscribe(boxKeyRotateSubject(sproutID), func(*nats.Msg) {
		// The body is ignored: farmer's trigger has none, and nothing in
		// one could be trusted.
		rotateBoxKey(nc, sproutID)
	})
	return err
}

// rotateBoxKey starts (or resumes) a rotation and publishes its sealed
// submission. The new key takes over only once farmer seals to it, so a
// failure here, or a submission lost on the way, leaves the sprout on its
// current key; farmer triggering again resubmits the same new key.
func rotateBoxKey(nc *nats.Conn, sproutID string) {
	submission, pub, err := pki.BeginSproutBoxKeyRotation(sproutID)
	if errors.Is(err, pki.ErrSproutBoxKeyRotationTooSoon) {
		log.Warnf("box key rotation: ignoring a rotate trigger: %v", err)
		return
	}
	if err != nil {
		log.Errorf("box key rotation: %v", err)
		return
	}
	msg := nats.NewMsg(boxKeySubmitSubject(sproutID))
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Data = submission
	if err := nc.PublishMsg(msg); err != nil {
		log.Errorf("box key rotation: submitting the new key: %v", err)
		return
	}
	log.Noticef("box key rotation: submitted new payload-encryption key %s; it becomes current once farmer seals to it", pub)
}

// userJWTGrantsPub reports whether userJWT lets its holder publish on
// subject. Exact grants only, which is how the sprout's are written.
func userJWTGrantsPub(userJWT, subject string) bool {
	uc, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		return false
	}
	return uc.Pub.Allow.Contains(subject) && !uc.Pub.Deny.Contains(subject)
}
