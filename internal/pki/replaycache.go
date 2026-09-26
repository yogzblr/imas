package pki

// Replay cache for proof-of-possession signatures
// (docs/design/imas-envoy-enrollment-design.md, "Replay cache").
//
// FLAG FOR SECURITY REVIEW. A signed /v1/enroll or /v1/refresh request
// verifies for as long as its timestamp stays inside EnrollSigMaxSkew, so
// on its own a captured request could be resubmitted for up to that long
// to mint fresh gateway JWTs. claimSignedPayload makes every verified
// payload single-use: the first request to claim it proceeds, and any
// later request carrying the same payload fails, whichever farmer replica
// it lands on.
//
// It is a PXC table rather than an in-process map because farmer runs as
// several replicas behind Envoy (see store.go's doc comment): a map would
// let a resubmission routed to a different replica through, and would
// forget every claim on a restart.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync/atomic"
	"time"

	log "github.com/yogzblr/imas/internal/log"
)

// seenSignatureRow is the `pki_seen_signatures` table: one row per signed
// payload a farmer has accepted, kept until that payload's timestamp can
// no longer pass verifyTimestampedNKeySig on any replica.
//
// Digest is hex SHA-256 of the signed payload, not of nkey_sig. Keying on
// the payload rejects a resubmission however its signature is encoded
// (base64url decoding tolerates non-zero trailing bits, so one signature
// has several string forms). It is globally unique by construction, since
// the payload carries its domain tag, nkey_pub and timestamp, so it is not
// keyed on (tenant_id, sprout_id): a request isn't tied to a tenant until
// after it has been claimed.
type seenSignatureRow struct {
	Digest    string `gorm:"column:digest;primaryKey;size:64"`
	ExpiresAt int64  `gorm:"column:expires_at;not null;index"`
}

func (seenSignatureRow) TableName() string { return "pki_seen_signatures" }

// replayCacheClockMargin extends each row's lifetime past the end of its
// timestamp's skew window, to cover clock differences between farmer
// replicas: one replica must not sweep a row while another, whose clock
// runs behind, would still accept its payload.
const replayCacheClockMargin = time.Minute

// replaySweepInterval bounds how often one replica deletes expired rows.
const replaySweepInterval = time.Minute

// lastReplaySweep is the Unix time of this replica's last sweep.
var lastReplaySweep atomic.Int64

// claimSignedPayload records payload, signed at timestamp, as used. It
// returns nil only for the first claim of a payload. A resubmitted
// payload fails, and so does any database error: either way the caller
// must reject the request (fail closed). Call it only after the payload's
// signature has verified, and before anything is issued.
//
// A plain INSERT is used, not an upsert: a duplicate primary key is an
// error on every driver, whereas an upsert's affected-row count depends on
// driver flags (MySQL's clientFoundRows). A Galera certification conflict
// between two replicas claiming the same payload at once is also an error,
// so exactly one of them wins.
func claimSignedPayload(payload []byte, timestamp int64) error {
	now := enrollNow()
	sweepExpiredSignatures(now)
	sum := sha256.Sum256(payload)
	row := seenSignatureRow{
		Digest:    hex.EncodeToString(sum[:]),
		ExpiresAt: time.Unix(timestamp, 0).Add(EnrollSigMaxSkew + replayCacheClockMargin).Unix(),
	}
	return db.Create(&row).Error
}

// sweepExpiredSignatures deletes rows no replica can still need, at most
// once per replaySweepInterval per replica. A failed sweep is only logged:
// stale rows can't cause a wrong accept, since their payloads' timestamps
// already fail the skew check.
func sweepExpiredSignatures(now time.Time) {
	last := lastReplaySweep.Load()
	if now.Unix()-last < int64(replaySweepInterval/time.Second) || !lastReplaySweep.CompareAndSwap(last, now.Unix()) {
		return
	}
	if err := db.Where("expires_at < ?", now.Unix()).Delete(&seenSignatureRow{}).Error; err != nil {
		log.Warnf("replay cache: sweeping expired signatures: %v", err)
	}
}
