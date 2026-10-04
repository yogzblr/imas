package auth

// The users store and the CLI box key store, in the farmer schema
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", J.1). FLAG FOR SECURITY REVIEW.
//
// Users. A user registered through auth.users.add used to be written to
// farmer's local config file (jety.WriteConfig) and mirrored into
// rbac_user_roles. That isn't consistent across farmer replicas: each has
// its own file (in the Helm chart a read-only ConfigMap, so the write
// fails outright), and every farmer start wipes the tenant's
// rbac_user_roles rows and reloads them from its own file, so a user added
// on one replica vanishes, and a user removed on one comes back, when
// another restarts (docs/BUILD-STATUS.md, Open item 11). So a registered
// user's durable record is now an auth_users row, shared by every replica;
// LoadPolicy re-applies those rows after the config reload, and
// AddUser/RemoveUser write nothing to the config file. The config file's
// users and pubkeys sections remain the out-of-band bootstrap (the first
// admin), read-only to the API.
//
// CLI box keys. Each user authenticates sealed requests with an X25519 key
// of their own (imas auth keygen), whose private half never leaves the
// CLI host. auth_cli_box_keys holds the public halves, keyed on
// (tenant_id, user_id): the tenant is the one whose box key the user's
// requests are sealed to, so a key registered in one tenant opens nothing
// in another. At most one key per (tenant_id, user_id) is active (the
// schema enforces it with active_slot, as pki_sprout_box_keys does); a
// rotation moves the old one to grace for CLIBoxKeyGrace and it is then
// retired. A key once registered, to any principal in any tenant, is
// never registered again (the pub column is unique across the table),
// and a retired key never becomes active again.
//
// Every query keys on (tenant_id, user_id), except two, deliberately:
// the uniqueness check on pub, which must see every principal, and
// revoking all of a user's keys when the user is removed from the
// deployment-wide policy (a user ID is an NKey public key, so it names one
// key holder in every tenant, not a name two tenants could both use).

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// userRow is the `auth_users` table: users registered through the API.
type userRow struct {
	TenantID  string    `gorm:"column:tenant_id;primaryKey;size:191"`
	UserID    string    `gorm:"column:user_id;primaryKey;size:191"`
	RoleName  string    `gorm:"column:role_name;size:191;not null"`
	Username  string    `gorm:"column:username;size:191"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (userRow) TableName() string { return "auth_users" }

// cliBoxKeyRow is the `auth_cli_box_keys` table. The CHECK ties
// active_slot to status NULL-safely, as chk_pki_sprout_box_keys_active_slot
// does: active_slot is 1 on the active row and NULL on every other.
type cliBoxKeyRow struct {
	TenantID   string     `gorm:"column:tenant_id;primaryKey;size:191;uniqueIndex:idx_auth_cli_box_keys_one_active,priority:1"`
	UserID     string     `gorm:"column:user_id;primaryKey;size:191;uniqueIndex:idx_auth_cli_box_keys_one_active,priority:2"`
	Pub        string     `gorm:"column:pub;primaryKey;size:64;uniqueIndex:idx_auth_cli_box_keys_pub"`
	Status     string     `gorm:"column:status;size:16;not null;check:chk_auth_cli_box_keys_active_slot,(status = 'active' AND active_slot IS NOT NULL AND active_slot = 1) OR (status <> 'active' AND active_slot IS NULL)"`
	ActiveSlot *int8      `gorm:"column:active_slot;uniqueIndex:idx_auth_cli_box_keys_one_active,priority:3"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	RotatedAt  *time.Time `gorm:"column:rotated_at"`
	GraceUntil *time.Time `gorm:"column:grace_until"`
}

func (cliBoxKeyRow) TableName() string { return "auth_cli_box_keys" }

// CLI box key statuses.
const (
	CLIBoxKeyActive  = "active"
	CLIBoxKeyGrace   = "grace"
	CLIBoxKeyRetired = "retired"
)

// CLIBoxKeyGraceDuration is how long a rotated-away CLI box key keeps
// opening requests: the design's 15 minutes, three times the freshness
// window, so a request sealed just before a rotation still opens.
const CLIBoxKeyGraceDuration = 15 * time.Minute

var activeSlot int8 = 1

// Models returns the GORM models this package owns. internal/pki's
// Models includes them (see its doc comment), so internal/pxc's list of
// the farmer schema, and the migration parity test, see them.
func Models() []any { return []any{&userRow{}, &cliBoxKeyRow{}} }

// db is the farmer-schema GORM handle. Nil until SetDB is called;
// internal/pki's SetDB calls it, so farmer wires it at startup without a
// call of its own.
var db *gorm.DB

// SetDB installs the GORM handle the users and CLI box key stores use.
func SetDB(d *gorm.DB) { db = d }

var (
	// ErrStoreNotConfigured: no database handle (SetDB never called).
	ErrStoreNotConfigured = errors.New("auth: users store is not configured")
	// ErrUserInConfig: the user is defined in farmer's config file, which
	// the API can't change consistently across replicas. Remove them
	// there, on every replica.
	ErrUserInConfig = errors.New("auth: user is defined in farmer's config file; remove it there")
	// ErrUnknownUser: a CLI box key was registered for a user no policy
	// knows.
	ErrUnknownUser = errors.New("auth: user is not registered")

	ErrNoActiveCLIBoxKey = errors.New("auth: user has no active CLI box key")
	// ErrMultipleActiveCLIBoxKeys: the schema should make it impossible;
	// if it happens, nothing opens for the user rather than a guess.
	ErrMultipleActiveCLIBoxKeys = errors.New("auth: user has more than one active CLI box key; refusing to use any")
	// ErrCLIBoxKeyExists: the user already has a different active key.
	// Replacing it is a rotation, sealed under the current key.
	ErrCLIBoxKeyExists = errors.New("auth: user already has an active CLI box key; rotate it instead")
	// ErrCLIBoxKeyInUse: the key is, or was, registered to a principal.
	ErrCLIBoxKeyInUse = errors.New("auth: box public key is already registered")
	// ErrCLIBoxKeySuperseded: a rotation named a key the user already
	// rotated away from.
	ErrCLIBoxKeySuperseded = errors.New("auth: CLI box key was already superseded and can't be made active again")
	// ErrCLIBoxKeySubmissionNotActive: a rotation sealed under a grace
	// key named a key other than the active one. Only the active key may
	// change which key is active (as for sprouts, security review
	// 2026-10, M3).
	ErrCLIBoxKeySubmissionNotActive = errors.New("auth: CLI box key submission was not sealed under the user's active key")
)

// usersTenantID is the tenant the deployment-wide policy's users belong
// to: the same seam internal/rbac uses for rbac_user_roles, so a user
// AddUser registers lands where the policy looks. CLI users are
// deployment-wide operators (owner decision 2026-10-04), so their CLI box
// keys live in this tenant too, and their sealed requests open on its
// connection (J.3).
func usersTenantID() string {
	if config.FarmerOrganization != "" {
		return config.FarmerOrganization
	}
	return "default"
}

// DecodeCLIBoxPub validates pub, a standard-base64 32-byte X25519 public
// key, refusing a low-order point (payloadbox.CheckPublicKey).
func DecodeCLIBoxPub(pub string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("auth: CLI box public key must be 32 bytes, standard base64")
	}
	var k [32]byte
	copy(k[:], raw)
	if err := payloadbox.CheckPublicKey(&k); err != nil {
		return nil, err
	}
	return &k, nil
}

func isDuplicate(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	// Neither driver here translates errors for GORM: MySQL says
	// "Duplicate entry", sqlite "UNIQUE constraint failed".
	s := err.Error()
	return strings.Contains(s, "Duplicate entry") || strings.Contains(s, "UNIQUE constraint failed")
}

// ---- users -------------------------------------------------------------

// RegisteredUser returns userID's registration in tenantID.
func RegisteredUser(tenantID, userID string) (role, username string, found bool, err error) {
	if db == nil {
		return "", "", false, ErrStoreNotConfigured
	}
	var rows []userRow
	if err := db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Limit(1).Find(&rows).Error; err != nil {
		return "", "", false, err
	}
	if len(rows) == 0 {
		return "", "", false, nil
	}
	return rows[0].RoleName, rows[0].Username, true, nil
}

// RegisteredUsers returns every user registered in tenantID: user ID to
// role name, and user ID to username for those that have one.
func RegisteredUsers(tenantID string) (roles, usernames map[string]string, err error) {
	if db == nil {
		return nil, nil, ErrStoreNotConfigured
	}
	var rows []userRow
	if err := db.Where("tenant_id = ?", tenantID).Order("user_id").Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	roles, usernames = map[string]string{}, map[string]string{}
	for _, r := range rows {
		roles[r.UserID] = r.RoleName
		if r.Username != "" {
			usernames[r.UserID] = r.Username
		}
	}
	return roles, usernames, nil
}

// registerUser records userID in tenantID with roleName, and, if boxPub
// isn't empty, its first CLI box key, in one transaction. ErrUserExists
// if the user is already registered there.
func registerUser(tenantID, userID, roleName, username, boxPub string) error {
	if db == nil {
		return ErrStoreNotConfigured
	}
	return db.Transaction(func(tx *gorm.DB) error {
		row := userRow{TenantID: tenantID, UserID: userID, RoleName: roleName, Username: username, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			if isDuplicate(err) {
				return ErrUserExists
			}
			return err
		}
		if boxPub == "" {
			return nil
		}
		return registerCLIBoxKeyTx(tx, tenantID, userID, boxPub)
	})
}

// deregisterUser removes userID's registration in tenantID and revokes
// every CLI box key the user holds, in every tenant, in one transaction.
// found is false if the user wasn't registered there.
func deregisterUser(tenantID, userID string) (found bool, err error) {
	if db == nil {
		return false, ErrStoreNotConfigured
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&userRow{})
		if res.Error != nil {
			return res.Error
		}
		found = res.RowsAffected > 0
		if !found {
			return nil
		}
		return retireCLIBoxKeysTx(tx, "user_id = ?", userID)
	})
	return found, err
}

// ---- CLI box keys --------------------------------------------------------

// CLIBoxKey is one row of a user's CLI box key history.
type CLIBoxKey struct {
	Pub         string     `json:"pub"`
	Fingerprint string     `json:"fingerprint"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
	GraceUntil  *time.Time `json:"grace_until,omitempty"`
}

// CLIBoxKeys returns userID's CLI box keys in tenantID, newest first.
func CLIBoxKeys(tenantID, userID string) ([]CLIBoxKey, error) {
	if db == nil {
		return nil, ErrStoreNotConfigured
	}
	sweepCLIBoxKeys(tenantID, userID)
	var rows []cliBoxKeyRow
	if err := db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]CLIBoxKey, 0, len(rows))
	for _, r := range rows {
		k := CLIBoxKey{Pub: r.Pub, Status: r.Status, CreatedAt: r.CreatedAt, RotatedAt: r.RotatedAt, GraceUntil: r.GraceUntil}
		if pub, err := DecodeCLIBoxPub(r.Pub); err == nil {
			k.Fingerprint = payloadbox.Fingerprint(pub)
		}
		out = append(out, k)
	}
	return out, nil
}

// CLIBoxKeyRegistered reports whether pub is, or ever was, registered as
// any user's CLI box key in any tenant.
func CLIBoxKeyRegistered(pub string) (bool, error) {
	if db == nil {
		return false, ErrStoreNotConfigured
	}
	var n int64
	if err := db.Model(&cliBoxKeyRow{}).Where("pub = ?", pub).Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// RegisterCLIBoxKey records pub as userID's first CLI box key in tenantID:
// a key on its own for a user who has none (auth.users.add registers the
// user and their key together, AddUser). The
// user must be known to the policy. Registering the key that is already
// the user's active one is a no-op; any other key while one is active is
// ErrCLIBoxKeyExists, since replacing a key is a rotation, sealed under
// the current one. A key registered to anyone, ever, is
// ErrCLIBoxKeyInUse. The caller checks the key isn't a sprout's, a
// tenant's or the platform's (internal/pki's RegisterCLIBoxKey).
func RegisterCLIBoxKey(tenantID, userID, pub string) error {
	if db == nil {
		return ErrStoreNotConfigured
	}
	if lookupRole(userID) == nil {
		if _, _, found, err := RegisteredUser(tenantID, userID); err != nil || !found {
			if err != nil {
				return err
			}
			return ErrUnknownUser
		}
	}
	return db.Transaction(func(tx *gorm.DB) error {
		return registerCLIBoxKeyTx(tx, tenantID, userID, pub)
	})
}

func registerCLIBoxKeyTx(tx *gorm.DB, tenantID, userID, pub string) error {
	if tenantID == "" || userID == "" {
		return errors.New("auth: tenant and user are required")
	}
	if _, err := DecodeCLIBoxPub(pub); err != nil {
		return err
	}
	var active []cliBoxKeyRow
	if err := tx.Where("tenant_id = ? AND user_id = ? AND status = ?", tenantID, userID, CLIBoxKeyActive).Find(&active).Error; err != nil {
		return err
	}
	switch {
	case len(active) > 1:
		return ErrMultipleActiveCLIBoxKeys
	case len(active) == 1 && active[0].Pub == pub:
		return nil
	case len(active) == 1:
		return ErrCLIBoxKeyExists
	}
	return createActiveCLIBoxKeyTx(tx, tenantID, userID, pub)
}

func createActiveCLIBoxKeyTx(tx *gorm.DB, tenantID, userID, pub string) error {
	slot := activeSlot
	row := cliBoxKeyRow{
		TenantID: tenantID, UserID: userID, Pub: pub, Status: CLIBoxKeyActive,
		ActiveSlot: &slot, CreatedAt: time.Now().UTC(),
	}
	if err := tx.Create(&row).Error; err != nil {
		if isDuplicate(err) {
			return ErrCLIBoxKeyInUse
		}
		return err
	}
	return nil
}

// sweepCLIBoxKeys retires userID's grace keys whose window has closed. A
// failure only leaves a stale label: an expired grace key is excluded
// from ValidCLIBoxKeys either way.
func sweepCLIBoxKeys(tenantID, userID string) {
	_ = db.Model(&cliBoxKeyRow{}).
		Where("tenant_id = ? AND user_id = ? AND status = ? AND grace_until <= ?", tenantID, userID, CLIBoxKeyGrace, time.Now().UTC()).
		Updates(map[string]any{"status": CLIBoxKeyRetired, "active_slot": nil}).Error
}

// ValidCLIBoxKeys returns userID's active CLI box key in tenantID and any
// still inside their grace window: every key a sealed request from the
// user may open under. ErrNoActiveCLIBoxKey if there is none: such a user
// can't make sealed requests, and nothing falls back to a weaker
// check.
func ValidCLIBoxKeys(tenantID, userID string) (active string, grace []string, err error) {
	if db == nil {
		return "", nil, ErrStoreNotConfigured
	}
	sweepCLIBoxKeys(tenantID, userID)
	now := time.Now().UTC()
	var rows []cliBoxKeyRow
	if err := db.Where("tenant_id = ? AND user_id = ? AND (status = ? OR (status = ? AND grace_until > ?))",
		tenantID, userID, CLIBoxKeyActive, CLIBoxKeyGrace, now).Order("pub").Find(&rows).Error; err != nil {
		return "", nil, err
	}
	actives := 0
	for _, r := range rows {
		switch r.Status {
		case CLIBoxKeyActive:
			active = r.Pub
			actives++
		case CLIBoxKeyGrace:
			grace = append(grace, r.Pub)
		}
	}
	if actives > 1 {
		return "", nil, ErrMultipleActiveCLIBoxKeys
	}
	if active == "" {
		return "", nil, ErrNoActiveCLIBoxKey
	}
	return active, grace, nil
}

// RecordCLIBoxKeySubmission records newPub, from a c2f.userkey.pub
// submission that opened under the user's key sealedUnder, as userID's
// active key in tenantID, moving the old one to grace for graceDuration.
// As for sprouts: only a submission sealed under the *active* key
// rotates; one sealed under a grace key may only re-assert the active key
// (a CLI retrying a rotation farmer already recorded); anything else is
// ErrCLIBoxKeySubmissionNotActive. A key the user rotated away from is
// never made active again (ErrCLIBoxKeySuperseded), and a key registered
// to anyone else is ErrCLIBoxKeyInUse. The check and the change run in
// one transaction.
func RecordCLIBoxKeySubmission(tenantID, userID, sealedUnder, newPub string, graceDuration time.Duration) error {
	if db == nil {
		return ErrStoreNotConfigured
	}
	if _, err := DecodeCLIBoxPub(newPub); err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var active []cliBoxKeyRow
		if err := tx.Where("tenant_id = ? AND user_id = ? AND status = ?", tenantID, userID, CLIBoxKeyActive).Find(&active).Error; err != nil {
			return err
		}
		switch {
		case len(active) == 0:
			return ErrNoActiveCLIBoxKey
		case len(active) > 1:
			return ErrMultipleActiveCLIBoxKeys
		case active[0].Pub == newPub:
			return nil
		case active[0].Pub != sealedUnder:
			return ErrCLIBoxKeySubmissionNotActive
		}
		var existing []cliBoxKeyRow
		if err := tx.Where("tenant_id = ? AND user_id = ? AND pub = ?", tenantID, userID, newPub).Find(&existing).Error; err != nil {
			return err
		}
		if len(existing) > 0 {
			return ErrCLIBoxKeySuperseded
		}
		now := time.Now().UTC()
		graceUntil := now.Add(graceDuration)
		if err := tx.Model(&cliBoxKeyRow{}).
			Where("tenant_id = ? AND user_id = ? AND pub = ? AND status = ?", tenantID, userID, active[0].Pub, CLIBoxKeyActive).
			Updates(map[string]any{"status": CLIBoxKeyGrace, "active_slot": nil, "rotated_at": now, "grace_until": graceUntil}).Error; err != nil {
			return err
		}
		return createActiveCLIBoxKeyTx(tx, tenantID, userID, newPub)
	})
}

// RevokeCLIBoxKeys retires every CLI box key userID holds in tenantID at
// once, active and grace alike: a stolen key, or an admin's reset before
// registering a fresh one. The rows stay, so no revoked key is reused.
func RevokeCLIBoxKeys(tenantID, userID string) error {
	if db == nil {
		return ErrStoreNotConfigured
	}
	return retireCLIBoxKeysTx(db, "tenant_id = ? AND user_id = ?", tenantID, userID)
}

func retireCLIBoxKeysTx(tx *gorm.DB, where string, args ...any) error {
	now := time.Now().UTC()
	q := tx.Model(&cliBoxKeyRow{}).Where(where, args...).Where("status <> ?", CLIBoxKeyRetired)
	if err := q.Updates(map[string]any{
		"status": CLIBoxKeyRetired, "active_slot": nil, "grace_until": nil,
		"rotated_at": gorm.Expr("COALESCE(rotated_at, ?)", now),
	}).Error; err != nil {
		return fmt.Errorf("auth: revoking CLI box keys: %w", err)
	}
	return nil
}
