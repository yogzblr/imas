package pki

// The SaaS API's own NATS identity — a narrowly-scoped User under the SYS
// Account, carrying exactly the platform-level internal.* subjects
// internal/saasapi needs to drive tenant provisioning and sprout actions
// through farmer. See
// docs/design/imas-internal-api-account.md for why SYS (rather than the
// legacy tenant Account, or a new dedicated one), and why these
// permissions and nothing more.
//
// FLAG FOR SECURITY REVIEW: this mints a new privileged, cross-tenant
// credential. Its only guard against $SYS-level administrative reach is
// saasAPIUserPermissions below — NATS enforces a User's JWT permissions
// uniformly, $SYS.> included, but being in the SYS Account means a widened
// allow-list here would be far worse than the same mistake in a tenant
// Account. TestSaaSAPIUserPermissions_ExactAllowLists pins the exact
// lists, and saasapi_user_integration_test.go proves the scoping against a
// live bus.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	saasAPIUserName = "imas-saasapi"
	// saasAPIUserSeedName is the loadRequiredSeed name, so
	// IMAS_NATS_SAASAPI_USER_SEED_FILE / IMAS_NATS_SAASAPI_USER_SEED
	// supply the seed (OpenBao via ESO); farmer never generates one.
	saasAPIUserSeedName = "SAASAPI_USER"

	// EnvSaaSAPIUserJWTTTL is how long a minted SaaS API User JWT is
	// valid (its exp), a Go duration from MinSaaSAPIUserJWTTTL to
	// MaxSaaSAPIUserJWTTTL; DefaultSaaSAPIUserJWTTTL when unset.
	EnvSaaSAPIUserJWTTTL = "IMAS_SAASAPI_USER_JWT_TTL"
	// DefaultSaaSAPIUserJWTTTL is the SaaS API User JWT's lifetime.
	DefaultSaaSAPIUserJWTTTL = 24 * time.Hour
	// MinSaaSAPIUserJWTTTL and MaxSaaSAPIUserJWTTTL bound
	// EnvSaaSAPIUserJWTTTL. The refresh CronJob must run more often
	// than a third of it.
	MinSaaSAPIUserJWTTTL = time.Hour
	MaxSaaSAPIUserJWTTTL = 30 * 24 * time.Hour
)

// saasAPINow is the clock the SaaS API User JWT's exp and its renewal
// are read from; tests move it.
var saasAPINow = time.Now

// saasAPIUserJWTTTL reads EnvSaaSAPIUserJWTTTL.
func saasAPIUserJWTTTL() (time.Duration, error) {
	v := os.Getenv(EnvSaaSAPIUserJWTTTL)
	if v == "" {
		return DefaultSaaSAPIUserJWTTTL, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < MinSaaSAPIUserJWTTTL || d > MaxSaaSAPIUserJWTTTL {
		return 0, fmt.Errorf("%s=%q: want a Go duration from %v to %v", EnvSaaSAPIUserJWTTTL, v, MinSaaSAPIUserJWTTTL, MaxSaaSAPIUserJWTTTL)
	}
	return d, nil
}

// saasAPIUserJWTFresh reports whether a JWT expiring at exp (Unix
// seconds) needs no renewal at now under a ttl lifetime: it has an exp,
// more than a third of ttl is left, and it does not outlive a JWT minted
// now (a ttl that was shortened since). The same two-thirds rule as the
// gateway JWT's refresh (enrollclient.go).
func saasAPIUserJWTFresh(exp int64, now time.Time, ttl time.Duration) bool {
	if exp == 0 {
		return false
	}
	left := time.Unix(exp, 0).Sub(now)
	return left > ttl/3 && left <= ttl+time.Minute
}

// saasAPIUserPermissions is the SaaS API's entire NATS reach: publish the
// three tenant request subjects (provision, deprovision, purge) and
// internal.sprout.action; subscribe to the
// tenant flows' per-job result subjects and to its own reply inboxes.
//
// The inbox grant is scoped to controlplane.SaaSAPIInboxWildcard
// (_INBOX.saasapi.>), never a bare _INBOX.>: every SYS user's default
// inbox lives under _INBOX, so the bare form would let this credential
// subscribe to farmer's own SYS user's replies. The SaaS API has to dial
// with nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix) for its
// requests to get replies at all. Pub on the inbox is deliberately not
// granted: replies come from farmer.
//
// Deliberately absent: imas.> (any tenant's business traffic), $SYS.>
// (server administration), subscribe on any internal.* request subject
// (only farmer receives requests), and the internal.sprout.* subjects
// that have no farmer handler yet (mint, revoke, enrolled,
// internal.sprouts.list) — add each here when its handler lands.
func saasAPIUserPermissions() jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			controlplane.SubjectTenantProvision,
			controlplane.SubjectTenantDeprovision,
			controlplane.SubjectTenantPurge,
			controlplane.SubjectSproutAction,
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			controlplane.SubjectTenantProvisionedWildcard,
			controlplane.SubjectTenantDeprovisionedWildcard,
			controlplane.SubjectTenantPurgedWildcard,
			controlplane.SaaSAPIInboxWildcard,
		}},
	}
}

// saasAPIUserConnectionTypes restricts the credential to plain NATS
// client connections: the SaaS API connects from inside the control
// plane, never through Envoy's DMZ websocket route, and never as a
// leafnode/MQTT client.
func saasAPIUserConnectionTypes() jwt.StringList {
	return jwt.StringList{jwt.ConnectionTypeStandard}
}

// saasAPIUserJWTIsCurrent reports whether an already-minted User JWT
// still matches what EnsureSaaSAPICredential would mint now: same subject
// key, issued by the SYS Account's own key, the exact same
// permissions/connection types, and not due for renewal at now under a
// ttl lifetime (saasAPIUserJWTFresh). PublishSaaSAPICredential compares
// the published JWT with it, so a change to saasAPIUserPermissions is
// published on the next run rather than shadowed by a stale JWT, and a
// JWT is replaced before it expires.
func saasAPIUserJWTIsCurrent(uc *jwt.UserClaims, pub, sysAccountPub string, now time.Time, ttl time.Duration) bool {
	if uc.Subject != pub || uc.Issuer != sysAccountPub || uc.IssuerAccount != "" {
		return false
	}
	if !saasAPIUserJWTFresh(uc.Expires, now, ttl) {
		return false
	}
	want := saasAPIUserPermissions()
	return reflect.DeepEqual(uc.Pub.Allow, want.Pub.Allow) &&
		reflect.DeepEqual(uc.Sub.Allow, want.Sub.Allow) &&
		len(uc.Pub.Deny) == 0 && len(uc.Sub.Deny) == 0 &&
		uc.Resp == nil &&
		reflect.DeepEqual(uc.AllowedConnectionTypes, saasAPIUserConnectionTypes())
}

// EnsureSaaSAPICredential returns the SaaS API's NATS User JWT and NKey
// seed, minting the JWT afresh (one Transit signature). It writes no
// file: the JWT reaches saasapi through PublishSaaSAPICredential, which
// compares claims, not bytes. Idempotent: call at every farmer boot.
//
// The JWT expires (security review 2026-10, L14): exp is
// EnvSaaSAPIUserJWTTTL (default 24h) after it is minted, so a rotated-out
// key also stops working on its own, even on a bus that has not yet
// received the SYS Account JWT that revokes it. It is renewed by the same
// path that publishes it: the publisher (the Helm post-deploy Job, and
// its refresh CronJob on a schedule) writes a new one once a third of the
// lifetime is left, and ESO plus Reloader hand it to saasapi.
//
// The User is signed directly by the SYS Account's identity key, exactly
// like imas-farmer-sys-push (jwtauth.go) — no Account JWT change, and so
// no resolver push, is needed for the bus to accept it; the SYS Account
// JWT it chains to is already seeded into every bus node's resolver by
// ConfigureNats.
//
// Rotation: saasapi records the key it runs with in
// saas.saasapi_credential_state (RecordSaaSAPICredential); a rotation
// moves the old key to prev_pub. This reads that row and adds prev_pub to
// the SYS Account JWT's revocation list, which is re-signed, held in
// memory, and pushed to the bus resolver over the same pushAccountUpdate path
// every tenant Account update uses — otherwise the old credential would
// stay valid until the User JWT's exp. Whenever the
// SYS Account JWT carries any revocation, it is (re-)pushed on every
// call, so a push that failed at one boot is retried at the next rather
// than leaving a rotated-out key live on the bus. Without a database (the
// publish Job, which has none) there is no rotation state to apply; a
// failed read is logged and treated the same way.
//
// A push failure is returned as an error, but only after the new
// credential has been minted: the returned JWT/seed are still valid,
// and the caller should log rather than abort.
func EnsureSaaSAPICredential() (userJWT string, seed []byte, err error) {
	// ensurePlatformAuth takes authMu itself; call it first, then take
	// authMu for the section below that re-signs the SYS Account JWT —
	// the one ensurePlatformAuth holds under that lock. Only the platform part is needed (the SaaS API credential Job
	// signs with the SYS account key alone); the SYS user is loaded only
	// for a push.
	mat, err := ensurePlatformAuth()
	if err != nil {
		return "", nil, fmt.Errorf("bootstrapping NATS auth material: %w", err)
	}
	var state *SaaSAPICredentialState
	if db != nil {
		// A read failure leaves this call without a key to revoke, as an
		// absent row does; revocations already on the SYS Account are
		// still pushed below, and the next boot reads again.
		if state, err = readSaaSAPICredentialState(context.Background()); err != nil {
			log.Errorf("SaaS API NATS credential: reading the rotation state (%s), so no rotated-out key is revoked this time: %v", saasAPICredentialStateTable, err)
			state = nil
		}
	}

	signed, seed, sysJWT, push, err := ensureSaaSAPICredentialLocked(mat, state)
	if err != nil {
		return "", nil, err
	}
	if push {
		authMu.Lock()
		uerr := ensureSysUserLocked(mat)
		authMu.Unlock()
		if uerr != nil {
			return signed, seed, fmt.Errorf("pushing the SYS Account JWT (SaaS API key rotation) to the bus resolver: %w", uerr)
		}
		if perr := pushAccountUpdate(mat, sysJWT); perr != nil {
			return signed, seed, fmt.Errorf("pushing the SYS Account JWT (SaaS API key rotation) to the bus resolver: %w", perr)
		}
		log.Infof("Pushed the SYS Account JWT (SaaS API credential revocations) to the bus resolver.")
	}
	return signed, seed, nil
}

func ensureSaaSAPICredentialLocked(mat *natsAuthMaterial, state *SaaSAPICredentialState) (userJWT string, seed []byte, sysJWT string, push bool, err error) {
	authMu.Lock()
	defer authMu.Unlock()

	kp, err := loadRequiredSeed(saasAPIUserSeedName)
	if err != nil {
		return "", nil, "", false, fmt.Errorf("loading the SaaS API NKey seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return "", nil, "", false, err
	}
	if nkeys.Prefix(pub) != nkeys.PrefixByteUser {
		return "", nil, "", false, fmt.Errorf("SaaS API NKey seed is not a User key")
	}
	seed, err = kp.Seed()
	if err != nil {
		return "", nil, "", false, err
	}

	// Start from the newest SYS Account JWT, held or in the accounts
	// bucket, under authMu rather than trusting mat's snapshot: another
	// EnsureSaaSAPICredential call, here or on another replica, may have
	// added a revocation since ensurePlatformAuth returned. A failed
	// bucket read is an error: re-signing an older copy could drop a
	// revocation of an earlier rotated-out key.
	opSigningPub, err := mat.operatorSigningKP.PublicKey()
	if err != nil {
		return "", nil, "", false, err
	}
	sysClaims, sysJWT, _, err := resignBase(context.Background(), mat.sysAccountPub, mat.sysAccountJWT, false, issuedBy(opSigningPub))
	if err != nil {
		return "", nil, "", false, fmt.Errorf("loading the SYS Account JWT: %w", err)
	}
	if sysClaims.Subject != mat.sysAccountPub {
		return "", nil, "", false, fmt.Errorf("the SYS Account JWT doesn't match the SYS Account key")
	}

	sysChanged := false
	if state != nil && state.PrevPub != "" && state.PrevPub != pub && ensureUserRevoked(sysClaims, state.PrevPub) {
		log.Infof("SaaS API NATS key rotated: revoking previous key %s on the SYS Account.", state.PrevPub)
		sysChanged = true
	}
	// Clear any stale revocation for the current key (e.g. a seed rotated
	// back to a previously-revoked one) — otherwise a JWT minted in the
	// same second as that revocation would be rejected.
	if ensureUserGranted(sysClaims, pub) {
		sysChanged = true
	}

	ttl, err := saasAPIUserJWTTTL()
	if err != nil {
		return "", nil, "", false, err
	}
	uc := jwt.NewUserClaims(pub)
	uc.Expires = saasAPINow().Add(ttl).Unix()
	uc.Name = saasAPIUserName
	uc.Permissions = saasAPIUserPermissions()
	uc.AllowedConnectionTypes = saasAPIUserConnectionTypes()
	userJWT, err = uc.Encode(mat.sysAccountKP)
	if err != nil {
		return "", nil, "", false, err
	}

	if sysChanged {
		// Strictly newer iat than the SYS Account JWT it replaces (see
		// syncNatsAuth).
		waitPastIssuedAt(sysClaims.IssuedAt)
		sysJWT, err = sysClaims.Encode(mat.operatorSigningKP)
		if err != nil {
			return "", nil, "", false, fmt.Errorf("re-signing the SYS Account JWT: %w", err)
		}
		if err := holdAccountJWT(sysJWT, false); err != nil {
			return "", nil, "", false, err
		}
		mat.sysAccountJWT = sysJWT
	}
	return userJWT, seed, sysJWT, sysChanged || len(sysClaims.Revocations) > 0, nil
}

// SaaS API credential rotation state (P21 slice 3, docs/briefs/P21-
// slice3-farmer-saasapi-state.md §4.3). FLAG FOR SECURITY REVIEW: this
// row decides which SaaS API key farmer revokes on the SYS Account.
//
// saas.saasapi_credential_state (migration saas 00008) holds one row, id
// 1: the public key saasapi runs with (current_pub), the one it ran with
// before the last rotation (prev_pub), when that was, and a version. Only
// saasapi writes it (RecordSaaSAPICredential, on saasapi's own schema);
// farmer has SELECT on saas.* and reads prev_pub in
// EnsureSaaSAPICredential. It replaces the User JWT file farmer once kept
// on local disk and read its previous public key from.
//
// A rotation takes the row lease (internal/lease), re-reads, and moves
// current_pub to prev_pub with an UPDATE conditional on the version it
// read and on still holding the lease, so of two replicas rotating at
// once exactly one wins; the other finds the key already current.

// ErrSaaSAPICredentialBusy reports that another saasapi replica holds the
// rotation lease, or took it over mid-rotation. Retryable.
var ErrSaaSAPICredentialBusy = errors.New("pki: SaaS API credential state is being rotated by another replica; retry")

// ErrSaaSAPICredentialRotatedOut reports a key that the row already names
// as rotated out (prev_pub). Recording it again would rotate back to a key
// farmer revokes, and revoke the current one: a replica still running
// with the old seed must not undo the rotation.
var ErrSaaSAPICredentialRotatedOut = errors.New("pki: SaaS API key was rotated out; refusing to rotate back to it")

const (
	// saasAPICredentialRowID is the state table's single row.
	saasAPICredentialRowID = 1
	// saasAPICredentialLeaseTTL bounds how long a dead rotator blocks the
	// row: a rotation is two reads and one UPDATE.
	saasAPICredentialLeaseTTL = 30 * time.Second
	// saasAPICredentialStateTable is the state table as farmer reads it,
	// on its own connection: qualified with the saas schema, like
	// saas.enrollment_keys (enroll.go).
	saasAPICredentialStateTable = "saas." + string(lease.SaasapiCredentialState)
)

// SaaSAPICredentialState is the saasapi_credential_state row.
type SaaSAPICredentialState struct {
	// CurrentPub is the SaaS API User key saasapi last recorded.
	CurrentPub string
	// PrevPub is the key CurrentPub replaced; empty before any rotation.
	PrevPub string
	// RotatedAt is when CurrentPub was recorded.
	RotatedAt time.Time
	// Version increases by one with every rotation.
	Version int64
}

// saasAPICredentialStateRow is a saas.saasapi_credential_state row
// (migration saas 00008). The table comes from the migration; this model
// is only how the code reads and writes it.
type saasAPICredentialStateRow struct {
	ID         int        `gorm:"column:id;primaryKey;autoIncrement:false;type:tinyint"`
	CurrentPub string     `gorm:"column:current_pub;size:64;not null"`
	PrevPub    *string    `gorm:"column:prev_pub;size:64"`
	RotatedAt  time.Time  `gorm:"column:rotated_at;not null;autoUpdateTime:false"`
	Version    int64      `gorm:"column:version;not null"`
	LeaseOwner *string    `gorm:"column:lease_owner;size:128"`
	LeaseUntil *time.Time `gorm:"column:lease_until"`
}

func (saasAPICredentialStateRow) TableName() string { return string(lease.SaasapiCredentialState) }

func (r *saasAPICredentialStateRow) state() *SaaSAPICredentialState {
	st := &SaaSAPICredentialState{CurrentPub: r.CurrentPub, RotatedAt: r.RotatedAt, Version: r.Version}
	if r.PrevPub != nil {
		st.PrevPub = *r.PrevPub
	}
	return st
}

// SaaSAPICredentialStateModels returns the model of the
// saasapi_credential_state table, for test databases built with
// AutoMigrate. Production's table comes from migration saas 00008.
func SaaSAPICredentialStateModels() []any { return []any{&saasAPICredentialStateRow{}} }

// loadSaaSAPICredentialState reads the row from table on gdb; nil, with no
// error, when saasapi has recorded no credential yet.
func loadSaaSAPICredentialState(ctx context.Context, gdb *gorm.DB, table string) (*SaaSAPICredentialState, error) {
	var row saasAPICredentialStateRow
	err := gdb.WithContext(ctx).Table(table).Where("id = ?", saasAPICredentialRowID).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return row.state(), nil
}

// readSaaSAPICredentialState is how farmer reads the row: through the
// package's database, from the saas schema. Tests replace it, since
// sqlite has no saas schema.
var readSaaSAPICredentialState = func(ctx context.Context) (*SaaSAPICredentialState, error) {
	return loadSaaSAPICredentialState(ctx, db, saasAPICredentialStateTable)
}

// SaaSAPICredentialRecorder is saasapi's writer of the credential state,
// on saasapi's own database (the saas schema).
type SaaSAPICredentialRecorder struct {
	db     *gorm.DB
	leases *lease.Leases
	// owner is this replica's lease owner prefix; each Record call adds
	// its own token (see callOwner).
	owner string
	now   func() time.Time
	// beforeUpdate, if set, runs with the lease held, after the re-read
	// and before the conditional UPDATE (tests: a rotator that stalls past
	// its lease).
	beforeUpdate func()
}

// NewSaaSAPICredentialRecorder returns the recorder on saasDB, saasapi's
// connection to the saas schema.
func NewSaaSAPICredentialRecorder(saasDB *gorm.DB) *SaaSAPICredentialRecorder {
	return &SaaSAPICredentialRecorder{db: saasDB, leases: lease.New(saasDB, nil), owner: replicaOwner(), now: time.Now}
}

// State returns the recorded state; nil when none is recorded yet.
func (r *SaaSAPICredentialRecorder) State(ctx context.Context) (*SaaSAPICredentialState, error) {
	return loadSaaSAPICredentialState(ctx, r.db, string(lease.SaasapiCredentialState))
}

// callOwner is the lease owner of one Record call: the replica's owner
// plus a random token, so two calls on one replica never share a lease.
func (r *SaaSAPICredentialRecorder) callOwner() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return r.owner + "-" + hex.EncodeToString(b[:])
}

// Record records pub, the public key of the SaaS API User credential
// saasapi runs with, as current. If another key is current, that key
// becomes prev_pub (a rotation), which farmer then revokes. rotated
// reports whether this call changed the row. Recording the key that is
// already current changes nothing; recording the one already rotated out
// fails with ErrSaaSAPICredentialRotatedOut. Losing the rotation to
// another replica that recorded a different key fails with
// ErrSaaSAPICredentialBusy.
func (r *SaaSAPICredentialRecorder) Record(ctx context.Context, pub string) (st *SaaSAPICredentialState, rotated bool, err error) {
	if !nkeys.IsValidPublicUserKey(pub) {
		return nil, false, errors.New("pki: SaaS API credential key is not a valid user public key")
	}
	st, err = r.State(ctx)
	if err != nil {
		return nil, false, err
	}
	if st == nil {
		// The first credential: no rotation, nothing to lease. Of two
		// replicas inserting at once, one row wins; the other re-reads.
		row := saasAPICredentialStateRow{ID: saasAPICredentialRowID, CurrentPub: pub, RotatedAt: dbTimeUTC(r.now()), Version: 1}
		res := r.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
		if res.Error != nil {
			return nil, false, fmt.Errorf("pki: recording the SaaS API credential: %w", res.Error)
		}
		if res.RowsAffected == 1 {
			log.Infof("Recorded the SaaS API NATS key %s.", pub)
			return row.state(), true, nil
		}
		if st, err = r.State(ctx); err != nil || st == nil {
			return nil, false, fmt.Errorf("pki: reading the SaaS API credential state: %v", err)
		}
	}
	if err := checkRecordable(st, pub); err != nil || st.CurrentPub == pub {
		return st, false, err
	}

	owner := r.callOwner()
	key := []any{saasAPICredentialRowID}
	got, err := r.leases.Acquire(ctx, lease.SaasapiCredentialState, key, owner, saasAPICredentialLeaseTTL)
	if err != nil {
		return nil, false, fmt.Errorf("pki: taking the SaaS API credential lease: %w", err)
	}
	if !got {
		return nil, false, ErrSaaSAPICredentialBusy
	}
	defer func() {
		if _, rerr := r.leases.Release(context.WithoutCancel(ctx), lease.SaasapiCredentialState, key, owner); rerr != nil {
			log.Debugf("pki: releasing the SaaS API credential lease: %v", rerr)
		}
	}()

	// Re-read with the lease held: another replica may have rotated while
	// this one waited.
	if st, err = r.State(ctx); err != nil {
		return nil, false, err
	}
	if st == nil {
		return nil, false, errors.New("pki: SaaS API credential state row disappeared")
	}
	if err := checkRecordable(st, pub); err != nil || st.CurrentPub == pub {
		return st, false, err
	}
	if r.beforeUpdate != nil {
		r.beforeUpdate()
	}
	next := &SaaSAPICredentialState{CurrentPub: pub, PrevPub: st.CurrentPub, RotatedAt: dbTimeUTC(r.now()), Version: st.Version + 1}
	res := r.db.WithContext(ctx).Model(&saasAPICredentialStateRow{}).
		Where("id = ? AND version = ? AND lease_owner = ?", saasAPICredentialRowID, st.Version, owner).
		UpdateColumns(map[string]any{
			"current_pub": next.CurrentPub,
			"prev_pub":    next.PrevPub,
			"rotated_at":  next.RotatedAt,
			"version":     next.Version,
		})
	if res.Error != nil {
		return nil, false, fmt.Errorf("pki: rotating the SaaS API credential: %w", res.Error)
	}
	if res.RowsAffected != 1 {
		// The lease lapsed and another replica rotated: its row wins.
		return nil, false, fmt.Errorf("pki: lost the SaaS API credential rotation: %w", ErrSaaSAPICredentialBusy)
	}
	log.Infof("SaaS API NATS key rotated from %s to %s (version %d).", next.PrevPub, next.CurrentPub, next.Version)
	return next, true, nil
}

// checkRecordable refuses pub when st names it as rotated out.
func checkRecordable(st *SaaSAPICredentialState, pub string) error {
	if st.PrevPub == pub && st.CurrentPub != pub {
		return ErrSaaSAPICredentialRotatedOut
	}
	return nil
}
