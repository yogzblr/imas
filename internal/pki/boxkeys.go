package pki

// Sprout X25519 box public key storage and rotation lifecycle — the
// "sprout_pub" half of docs/design/imas-payload-encryption-design.md
// (workstream J). Storage location matches the design doc's "Storage"
// section: sprout_pub lives in PXC, alongside (but not inside) the
// sprout's pki_nkeys identity row, since a sprout can hold more than one
// valid box public key at once during a rotation's grace-period overlap
// — something pki_nkeys' one-row-per-sprout shape (store.go) doesn't
// support.
//
// FLAG FOR SECURITY REVIEW per the task brief: this is the storage and
// state-machine half of the payload-encryption key material. Rotation is
// deliberately sprout-initiated only (see RotateSproutBoxKey's doc
// comment) — nothing here ever generates or receives a sprout's private
// key, matching the design doc's explicit rejection of an earlier,
// unsafe framing that would have had farmer generate/hold sprout private
// keys.
//
// State names (active/grace/revoked) are deliberately analogous to, but
// not literally the same table as, pki_nkeys' accepted/denied/rejected
// states (store.go, nats.go's Accept/Deny/Reject/Unaccept lifecycle):
// the grace-period overlap this design requires — a sprout briefly having
// *two* simultaneously valid box keys while in-flight messages under the
// old key are still being decrypted — has no equivalent in the NKey
// lifecycle, which enforces exactly one state per sprout at a time
// (nkeyRow's primary key is (tenant_id, sprout_id), not including the key
// itself). This file keeps the same operational shape (tenant-scoped,
// state-column, defer-free explicit transitions in one transaction) as
// pki.go's Accept/Deny/Reject rather than inventing a different pattern.
import (
	"encoding/base64"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	log "github.com/yogzblr/imas/internal/log"
)

// sproutBoxKeyRow is the `pki_sprout_box_keys` table in the farmer schema.
// Unlike nkeyRow, pub is part of the primary key: a sprout can have more
// than one row (an active key and, during a rotation's grace window, the
// previous key too).
type sproutBoxKeyRow struct {
	TenantID   string     `gorm:"column:tenant_id;primaryKey;size:191"`
	SproutID   string     `gorm:"column:sprout_id;primaryKey;size:253"`
	Pub        string     `gorm:"column:pub;primaryKey;size:64"`
	State      string     `gorm:"column:state;size:16;not null;index"`
	GraceUntil *time.Time `gorm:"column:grace_until"`
}

func (sproutBoxKeyRow) TableName() string { return "pki_sprout_box_keys" }

const (
	boxKeyStateActive  = "active"
	boxKeyStateGrace   = "grace"
	boxKeyStateRevoked = "revoked"
)

// ErrNoActiveBoxKey means a sprout has no active X25519 box public key on
// record — either it has never enrolled with one, or (a code bug, since
// rotation always installs a new active key in the same transaction it
// graces the old one) it was left keyless.
var ErrNoActiveBoxKey = fmt.Errorf("pki: sprout has no active box public key")

// ErrBoxKeySuperseded means a rotation named a box key this sprout
// already rotated away from.
var ErrBoxKeySuperseded = fmt.Errorf("pki: box public key was already superseded and can't be made active again")

// decodeBoxPub validates and decodes a standard-base64-encoded 32-byte
// X25519 public key, as submitted both at enrollment (enroll.go's
// sproutPub parameter) and at rotation (RotateSproutBoxKey).
func decodeBoxPub(pub string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return out, fmt.Errorf("pki: invalid box public key encoding: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("pki: box public key must be 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// DecodeBoxPubKey is decodeBoxPub's exported form, for callers outside
// this package (internal/natsapi's shared encrypt/decrypt helper) that
// need the same validation this package applies to a box public key
// before using it in a NaCl box operation.
func DecodeBoxPubKey(pub string) (*[32]byte, error) {
	out, err := decodeBoxPub(pub)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// upsertSproutBoxKeyActive records pub as sproutID's active X25519 box
// public key, called from enroll.go's bootstrap path (design doc
// "Bootstrap": sprout_pub rides the enrollment round trip). Safe to call
// repeatedly with the same pub — an idempotent enrollment replay (see
// Enroll's step-1 idempotency check) re-asserts the same row rather than
// erroring.
func upsertSproutBoxKeyActive(tenantID, sproutID, pub string) error {
	if _, err := decodeBoxPub(pub); err != nil {
		return err
	}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}, {Name: "pub"}},
		DoUpdates: clause.AssignmentColumns([]string{"state", "grace_until"}),
	}).Create(&sproutBoxKeyRow{
		TenantID: tenantID, SproutID: sproutID, Pub: pub, State: boxKeyStateActive, GraceUntil: nil,
	}).Error
}

// RotateSproutBoxKey implements the design doc's sprout-initiated
// rotation, the *only* way a sprout's box key ever changes: the sprout
// generates a new keypair locally (its private half never leaves it, not
// even now, not even encrypted) and submits only the new public key here.
// Farmer may trigger a rotation (see internal/natsapi's rotate-trigger
// handler), but that only asks the sprout to do this — it never supplies
// or receives key material of its own.
//
// The previously active key moves to a grace-period overlap window
// (graceDuration, config.BoxKeyGraceDuration) rather than being revoked
// outright, so messages already encrypted under it and still in flight
// keep decrypting correctly until the window closes. Idempotent: rotating
// to a key that is already active is a no-op, so a sprout retrying a
// dropped rotation confirmation doesn't grace its own current key. A key
// that has been superseded (grace or revoked) is never made active
// again (ErrBoxKeySuperseded), so replaying an old submission can't roll
// a sprout back to it.
func RotateSproutBoxKey(tenantID, sproutID, newPub string, graceDuration time.Duration) error {
	if _, err := decodeBoxPub(newPub); err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var existing []sproutBoxKeyRow
		if err := tx.Where("tenant_id = ? AND sprout_id = ? AND pub = ?", tenantID, sproutID, newPub).
			Find(&existing).Error; err != nil {
			return err
		}
		// (tenant_id, sprout_id, pub) is the primary key: at most one row.
		if len(existing) > 0 {
			if existing[0].State == boxKeyStateActive {
				return nil
			}
			return ErrBoxKeySuperseded
		}
		var rows []sproutBoxKeyRow
		if err := tx.Where("tenant_id = ? AND sprout_id = ? AND state = ?", tenantID, sproutID, boxKeyStateActive).
			Find(&rows).Error; err != nil {
			return err
		}
		graceUntil := time.Now().UTC().Add(graceDuration)
		for _, r := range rows {
			if err := tx.Model(&sproutBoxKeyRow{}).
				Where("tenant_id = ? AND sprout_id = ? AND pub = ?", tenantID, sproutID, r.Pub).
				Updates(map[string]any{"state": boxKeyStateGrace, "grace_until": graceUntil}).Error; err != nil {
				return err
			}
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}, {Name: "pub"}},
			DoUpdates: clause.AssignmentColumns([]string{"state", "grace_until"}),
		}).Create(&sproutBoxKeyRow{
			TenantID: tenantID, SproutID: sproutID, Pub: newPub, State: boxKeyStateActive, GraceUntil: nil,
		}).Error
	})
}

// ValidSproutBoxKeys returns sproutID's current active X25519 box public
// key plus any former key(s) still inside their post-rotation grace
// window — every key internal/natsapi's decrypt helper should try, per
// the design doc's grace-period overlap. Returns ErrNoActiveBoxKey if the
// sprout has never enrolled a box key (e.g. it enrolled before this
// workstream shipped).
//
// As a side effect, this lazily sweeps any grace-period row whose window
// has closed to "revoked" — there is no separate background sweeper;
// like internal/certs's RotateTLSCerts, the check is cheap enough to do
// on the read path instead of running a timer. A sweep failure is logged
// and otherwise ignored: an expired grace row is excluded from the
// result either way (the query below only asks for grace_until in the
// future), so it doesn't affect correctness, only how long a stale
// "grace" label lingers for admin listing purposes.
func ValidSproutBoxKeys(tenantID, sproutID string) (active string, grace []string, err error) {
	now := time.Now().UTC()

	if sweepErr := db.Model(&sproutBoxKeyRow{}).
		Where("tenant_id = ? AND sprout_id = ? AND state = ? AND grace_until <= ?", tenantID, sproutID, boxKeyStateGrace, now).
		Update("state", boxKeyStateRevoked).Error; sweepErr != nil {
		log.Warnf("pki: failed to sweep expired grace-period box keys for sprout %s: %v", sproutID, sweepErr)
	}

	var rows []sproutBoxKeyRow
	if err := db.Where(
		"tenant_id = ? AND sprout_id = ? AND (state = ? OR (state = ? AND grace_until > ?))",
		tenantID, sproutID, boxKeyStateActive, boxKeyStateGrace, now,
	).Find(&rows).Error; err != nil {
		return "", nil, err
	}
	for _, r := range rows {
		switch r.State {
		case boxKeyStateActive:
			active = r.Pub
		case boxKeyStateGrace:
			grace = append(grace, r.Pub)
		}
	}
	if active == "" {
		return "", nil, ErrNoActiveBoxKey
	}
	return active, grace, nil
}
