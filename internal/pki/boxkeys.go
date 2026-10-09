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
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// sproutBoxKeyRow is the `pki_sprout_box_keys` table in the farmer schema.
// Unlike nkeyRow, pub is part of the primary key: a sprout can have more
// than one row (an active key and, during a rotation's grace window, the
// previous key too).
//
// At most one row per (tenant_id, sprout_id) is active, and the schema
// enforces it (security review 2026-10, H1): active_slot is 1 on the
// active row and NULL on every other (the CHECK constraint ties it to
// state), and (tenant_id, sprout_id, active_slot) is unique. NULLs never
// collide in a unique index, on MySQL or sqlite, so any number of grace
// and revoked rows fit beside the one active row. Every write that makes a
// row active or stops it being active sets both columns together
// (newActiveBoxKeyRow, boxKeyInactiveColumns). The CHECK says "IS NOT
// NULL" explicitly because a CHECK whose expression is NULL passes:
// "active_slot = 1" alone would let an active row with no slot through.
type sproutBoxKeyRow struct {
	TenantID   string     `gorm:"column:tenant_id;primaryKey;size:191;uniqueIndex:idx_pki_sprout_box_keys_one_active,priority:1"`
	SproutID   string     `gorm:"column:sprout_id;primaryKey;size:253;uniqueIndex:idx_pki_sprout_box_keys_one_active,priority:2"`
	Pub        string     `gorm:"column:pub;primaryKey;size:64;index:idx_pki_sprout_box_keys_pub"`
	State      string     `gorm:"column:state;size:16;not null;index;check:chk_pki_sprout_box_keys_active_slot,(state = 'active' AND active_slot IS NOT NULL AND active_slot = 1) OR (state <> 'active' AND active_slot IS NULL)"`
	GraceUntil *time.Time `gorm:"column:grace_until"`
	ActiveSlot *int8      `gorm:"column:active_slot;uniqueIndex:idx_pki_sprout_box_keys_one_active,priority:3"`
}

func (sproutBoxKeyRow) TableName() string { return "pki_sprout_box_keys" }

const (
	boxKeyStateActive  = "active"
	boxKeyStateGrace   = "grace"
	boxKeyStateRevoked = "revoked"
)

// boxKeyActiveSlot is active_slot's value on the active row.
var boxKeyActiveSlot int8 = 1

// newActiveBoxKeyRow is pub as sproutID's active row.
func newActiveBoxKeyRow(tenantID, sproutID, pub string) *sproutBoxKeyRow {
	slot := boxKeyActiveSlot
	return &sproutBoxKeyRow{
		TenantID: tenantID, SproutID: sproutID, Pub: pub,
		State: boxKeyStateActive, GraceUntil: nil, ActiveSlot: &slot,
	}
}

// boxKeyUpsertColumns are the columns an upsert of an active row
// overwrites on a (tenant_id, sprout_id, pub) conflict.
var boxKeyUpsertColumns = []string{"state", "grace_until", "active_slot"}

// boxKeyInactiveColumns moves a row to state (grace or revoked), with
// graceUntil (nil for revoked), clearing its active slot.
func boxKeyInactiveColumns(state string, graceUntil *time.Time) map[string]any {
	return map[string]any{"state": state, "grace_until": graceUntil, "active_slot": nil}
}

// ErrNoActiveBoxKey means a sprout has no active X25519 box public key on
// record — either it has never enrolled with one, or (a code bug, since
// rotation always installs a new active key in the same transaction it
// graces the old one) it was left keyless.
var ErrNoActiveBoxKey = fmt.Errorf("pki: sprout has no active box public key")

// ErrBoxKeySuperseded means a rotation named a box key this sprout
// already rotated away from.
var ErrBoxKeySuperseded = fmt.Errorf("pki: box public key was already superseded and can't be made active again")

// ErrMultipleActiveBoxKeys means more than one box key row is active for
// one (tenant_id, sprout_id). The schema's unique constraint should make
// that impossible; if it happens anyway, nothing is sealed to or opened
// from the sprout until it is resolved, rather than guessing which key is
// the sprout's (security review 2026-10, H1).
var ErrMultipleActiveBoxKeys = fmt.Errorf("pki: sprout has more than one active box public key; refusing to use any")

// ErrBoxKeySubmissionNotActive means a box key submission was sealed
// under a key that is not the sprout's active one (a grace key) and named
// a key other than the active one. Only the active key may change which
// key is active; a grace key may only re-assert it (security review
// 2026-10, M3).
var ErrBoxKeySubmissionNotActive = fmt.Errorf("pki: box key submission was not sealed under the sprout's active key")

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
//
// Any other active row for the sprout is revoked in the same transaction,
// not graced: an enrollment is a new trust anchor, and a key already on
// record under this ID belongs to whatever held the ID before (a freed
// sprout ID can be enrolled again; security review 2026-10, H1). So
// exactly one key is active afterwards.
func upsertSproutBoxKeyActive(tenantID, sproutID, pub string) error {
	if _, err := decodeBoxPub(pub); err != nil {
		return err
	}
	// Retried on a deadlock (retryOnDeadlock): sprouts enrolled in the same
	// second run this transaction concurrently, and the revoke above, which
	// matches no row on a first key, locks an index gap that the other
	// transactions' inserts then wait on (PXC reports that, and a Galera
	// certification conflict, as error 1213). The transaction was rolled
	// back, and the proof and binding were claimed before this call, so a
	// dropped write would leave the sprout without a way to enrol.
	return retryOnDeadlock(func() error {
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&sproutBoxKeyRow{}).
				Where("tenant_id = ? AND sprout_id = ? AND state = ? AND pub <> ?", tenantID, sproutID, boxKeyStateActive, pub).
				Updates(boxKeyInactiveColumns(boxKeyStateRevoked, nil)).Error; err != nil {
				return err
			}
			return tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}, {Name: "pub"}},
				DoUpdates: clause.AssignmentColumns(boxKeyUpsertColumns),
			}).Create(newActiveBoxKeyRow(tenantID, sproutID, pub)).Error
		})
	})
}

// deadlockRetries is how many times retryOnDeadlock runs a write, and
// deadlockBackoff the pause after the first failed attempt (it grows with
// each one). Variables for tests.
var (
	deadlockRetries = 6
	deadlockBackoff = 25 * time.Millisecond
)

// retryOnDeadlock runs write, again if it fails with MySQL/PXC's deadlock
// error 1213 (ER_LOCK_DEADLOCK, which Galera also returns for a
// certification conflict), up to deadlockRetries times. write must be one
// whole transaction: the server rolled the failed one back, so repeating
// it is safe. Any other error is returned at once. The pause grows with
// each attempt and differs per call, so two transactions that collided
// don't collide again in step.
func retryOnDeadlock(write func() error) error {
	var err error
	for attempt := range deadlockRetries {
		if err = write(); err == nil || !isDeadlockError(err) {
			return err
		}
		if pause := deadlockBackoff * time.Duration(attempt+1); pause > 0 && attempt < deadlockRetries-1 {
			time.Sleep(pause + time.Duration(rand.Int64N(int64(pause))))
		}
	}
	return err
}

// isDeadlockError reports whether err is error 1213. Matched on
// go-sql-driver's fixed "Error 1213" message prefix rather than its typed
// *mysql.MySQLError, to avoid importing the driver directly here (it's
// MPL-2.0; see CLAUDE.md's licensing rule), as internal/jobs does.
func isDeadlockError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Error 1213")
}

// revokeSproutBoxKeysTx revokes every box key of sproutID in tenantID
// inside tx, active and grace alike: DeleteNKey and AcceptNKey's replace
// path (retireSproutTx). The rows are kept, revoked, so a key that was
// once this sprout's is never made active again by a rotation
// (ErrBoxKeySuperseded).
func revokeSproutBoxKeysTx(tx *gorm.DB, tenantID, sproutID string) error {
	return tx.Model(&sproutBoxKeyRow{}).
		Where("tenant_id = ? AND sprout_id = ? AND state <> ?", tenantID, sproutID, boxKeyStateRevoked).
		Updates(boxKeyInactiveColumns(boxKeyStateRevoked, nil)).Error
}

// moveSproutBoxKeysTx moves every box key row of sprout from to sprout to,
// both in tenantID, inside tx: AcceptNKey's replace path renames
// <base>_<n> to <base>, and the host's box keys go with it. The caller has
// already revoked to's own rows (retireSproutTx), so to has no active row
// left for a moved active row to collide with. A row whose pub is already
// on record under to is not moved but dropped: that pub belonged to the
// retired host, so it stays revoked there, and the moving host is left
// without that key (fail closed: it has to rotate or re-enrol).
func moveSproutBoxKeysTx(tx *gorm.DB, tenantID, from, to string) error {
	var rows []sproutBoxKeyRow
	if err := tx.Where("tenant_id = ? AND sprout_id = ?", tenantID, from).Find(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		var n int64
		if err := tx.Model(&sproutBoxKeyRow{}).
			Where("tenant_id = ? AND sprout_id = ? AND pub = ?", tenantID, to, r.Pub).Count(&n).Error; err != nil {
			return err
		}
		q := tx.Model(&sproutBoxKeyRow{}).Where("tenant_id = ? AND sprout_id = ? AND pub = ?", tenantID, from, r.Pub)
		if n > 0 {
			log.Warnf("pki: sprout %s's box key is already on record under %s in tenant %s; not moving it", from, to, tenantID)
			if err := q.Delete(&sproutBoxKeyRow{}).Error; err != nil {
				return err
			}
			continue
		}
		if err := q.Update("sprout_id", to).Error; err != nil {
			return err
		}
	}
	return nil
}

// RotateSproutBoxKey implements the design doc's sprout-initiated
// rotation, the *only* way a sprout's box key ever changes: the sprout
// generates a new keypair locally (its private half never leaves it, not
// even now, not even encrypted) and submits only the new public key here.
// Farmer may trigger a rotation (see internal/natsapi's rotate-trigger
// handler), but that only asks the sprout to do this — it never supplies
// or receives key material of its own. The sprout's side is
// sproutbox.go's BeginSproutBoxKeyRotation; the sprout keeps sealing with
// its old key until farmer seals something to the new one.
//
// This records newPub unconditionally; a submission from the bus goes
// through RecordSproutBoxKeySubmission, which first checks which key it
// was sealed under.
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
		return rotateSproutBoxKeyTx(tx, tenantID, sproutID, newPub, graceDuration)
	})
}

// OpenBoxKeySubmission opens data, a box key submission sproutID sent
// (purpose s2f.boxkey.pub), and returns the opened message and sealedUnder,
// the sprout box key it opened under, for RecordSproutBoxKeySubmission to
// check. It tries the sprout's active key first and then each grace key on
// its own, so it knows which one opened it. Any failure to open is
// payloadbox.ErrOpen; freshness is the caller's to check.
func OpenBoxKeySubmission(tenantID, sproutID string, data []byte) (msg *payloadbox.Message, sealedUnder string, err error) {
	active, grace, err := ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		if errors.Is(err, ErrNoActiveBoxKey) {
			return nil, "", payloadbox.ErrOpen
		}
		return nil, "", err
	}
	for _, key := range append([]string{active}, grace...) {
		msg, err := openFromSproutUnder(tenantID, sproutID, payloadbox.PurposeBoxKeySubmit, data, []string{key})
		if err == nil {
			return msg, key, nil
		}
		if !errors.Is(err, payloadbox.ErrOpen) {
			return nil, "", err
		}
	}
	return nil, "", payloadbox.ErrOpen
}

// RecordSproutBoxKeySubmission records newPub, from a box key submission
// that opened under the sprout's box key sealedUnder
// (OpenBoxKeySubmission), as sproutID's active key. FLAG FOR SECURITY
// REVIEW (security review 2026-10, M3): only a submission sealed under
// the sprout's *active* key rotates. One sealed under a grace key may
// only re-assert the key that is already active (a sprout retrying a
// submission farmer already recorded: the retry is sealed under the key
// that has since gone to grace), which changes nothing; anything else is
// ErrBoxKeySubmissionNotActive. Otherwise a leaked old key, for example
// from a VM snapshot, could take over the sprout's sealed channel for the
// whole grace window after a rotation meant to retire it. The check and
// the rotation run in one transaction, so a concurrent rotation can't
// slip between them.
func RecordSproutBoxKeySubmission(tenantID, sproutID, sealedUnder, newPub string, graceDuration time.Duration) error {
	if _, err := decodeBoxPub(newPub); err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var active []sproutBoxKeyRow
		if err := tx.Where("tenant_id = ? AND sprout_id = ? AND state = ?", tenantID, sproutID, boxKeyStateActive).
			Find(&active).Error; err != nil {
			return err
		}
		switch {
		case len(active) == 0:
			return ErrNoActiveBoxKey
		case len(active) > 1:
			return ErrMultipleActiveBoxKeys
		case active[0].Pub == sealedUnder:
			return rotateSproutBoxKeyTx(tx, tenantID, sproutID, newPub, graceDuration)
		case active[0].Pub == newPub:
			return nil
		default:
			return ErrBoxKeySubmissionNotActive
		}
	})
}

// rotateSproutBoxKeyTx is RotateSproutBoxKey inside tx.
func rotateSproutBoxKeyTx(tx *gorm.DB, tenantID, sproutID, newPub string, graceDuration time.Duration) error {
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
	graceUntil := time.Now().UTC().Add(graceDuration)
	if err := tx.Model(&sproutBoxKeyRow{}).
		Where("tenant_id = ? AND sprout_id = ? AND state = ?", tenantID, sproutID, boxKeyStateActive).
		Updates(boxKeyInactiveColumns(boxKeyStateGrace, &graceUntil)).Error; err != nil {
		return err
	}
	return tx.Create(newActiveBoxKeyRow(tenantID, sproutID, newPub)).Error
}

// ValidSproutBoxKeys returns sproutID's current active X25519 box public
// key plus any former key(s) still inside their post-rotation grace
// window — every key internal/natsapi's decrypt helper should try, per
// the design doc's grace-period overlap. Returns ErrNoActiveBoxKey if the
// sprout has never enrolled a box key (e.g. it enrolled before this
// workstream shipped), or had its keys revoked (DeleteNKey). Fails closed
// with ErrMultipleActiveBoxKeys if more than one row is active, rather
// than picking one: which one a query returns last depends on row order.
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
	).Order("pub").Find(&rows).Error; err != nil {
		return "", nil, err
	}
	actives := 0
	for _, r := range rows {
		switch r.State {
		case boxKeyStateActive:
			active = r.Pub
			actives++
		case boxKeyStateGrace:
			grace = append(grace, r.Pub)
		}
	}
	if actives > 1 {
		log.Errorf("pki: sprout %s in tenant %s has %d active box keys; refusing to seal to or open from it", sproutID, tenantID, actives)
		return "", nil, ErrMultipleActiveBoxKeys
	}
	if active == "" {
		return "", nil, ErrNoActiveBoxKey
	}
	return active, grace, nil
}
