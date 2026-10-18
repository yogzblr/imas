package pki

// Maps imas's accept/deny/reject/unaccept sprout lifecycle onto NATS JWT
// issuance and revocation, per docs/design/imas-nats-jwt-auth-design.md's
// "Revocation semantics" open item.
//
// Two independent pieces of state are kept in sync here, and it's worth
// keeping them distinct:
//   - The tenant Account's revocation list (inside its signed JWT) is what
//     the bus actually enforces. A pubkey with a revocation entry can never
//     authenticate with a User JWT issued at or before that timestamp,
//     regardless of whether such a JWT exists. Changing this list is the
//     only thing that requires re-signing the Account JWT and pushing it to
//     the resolver (see resolver.go) — that's the expensive, network-facing
//     operation.
//   - Each sprout's own signed User JWT is minted once and kept so it can
//     be handed back out (by the enrollment and refresh endpoints)
//     without re-signing: in the private sprout JWT bucket, indexed in
//     PXC (MintOrReuseUserJWT, below). The farmer's own User JWTs are
//     signed on first use and held in memory (accountjwts.go). No User
//     JWT is written to a file. Minting or reusing one never itself
//     requires a push: the resolver never stores User JWTs, only Account
//     JWTs.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// AllowAllPermissions is the grant of farmer's own User in each tenant
// Account (farmerUserJWT): all of imas.> and its inboxes. Exported so
// tools/loadtest's requester that plays core mints the same grant from
// this one definition.
func AllowAllPermissions() jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"imas.>", "_INBOX.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"imas.>", "_INBOX.>"}},
	}
}

// SproutPermissions is the whole grant of sprout id's User JWT, the one
// definition MintOrReuseUserJWT mints, the sprout checks its persisted JWT
// against (SproutUserJWTHasFullGrant) and tools/loadtest's fixture mints
// its simulated sprouts with.
func SproutPermissions(id string) jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"imas.sprouts.announce." + id,
			"_INBOX.>",
			"imas.cook." + id + ".>",
			"imas.sprouts." + id + ".facts",
			// Submit a new payload-encryption public key after farmer
			// triggers a box key rotation (cmd/sprout's boxkey.go).
			// Farmer only records a submission sealed under this
			// sprout's active box key (internal/natsapi's
			// handleBoxKeySubmit), so the grant lets the sprout submit;
			// what it submits still has to open.
			SproutBoxKeySubmitSubject(id),
			// Ship this sprout's own log entries over its bus connection
			// (internal/log.UseNATSConn), one subject per level. Outside
			// imas.sprouts.<id>.>, so the sprout never receives its own
			// logs back through its Sub grant.
			sproutLogPublishGrant(id),
			// Sealed shell (J.5): the sprout's s2f frames,
			// imas.shell.sprout.<id>.<session_id>.s2f. Outside
			// imas.sprouts.<id>.>, so the sprout never receives its own
			// frames; farmer's f2s frames and the sealed shell.start
			// arrive inside its Sub grant. Every frame is sealed under
			// per-session keys, so the grant lets the sprout publish; what
			// it publishes still has to open at farmer. Before this grant
			// shell couldn't work at all for a sprout with a per-sprout
			// JWT. Already-enrolled sprouts get it through the
			// MintOrReuseUserJWT re-mint on their next refresh, and reconnect
			// with it at their next heartbeat (cmd/sprout's heartbeatGate).
			SproutShellPublishGrant(id),
			// Periodic liveness heartbeat (internal/heartbeat): exactly
			// this sprout's own subject, never a wildcard, so one sprout
			// can't make another look online. Farmer takes the sprout ID
			// from the subject, never the body, and only refreshes a key
			// for an accepted sprout of the tenant the message arrived
			// in. Outside imas.sprouts.<id>.>, so the sprout never
			// receives its own heartbeats. A User JWT minted before this
			// grant is re-minted where it is next served
			// (MintOrReuseUserJWT compares the whole permission set).
			SproutHeartbeatSubject(id),
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			"imas.sprouts." + id + ".>",
		}},
	}
}

// SproutHeartbeatSubjectPrefix is the subject prefix sprout heartbeats are
// published under: imas.heartbeat.sprout.<id>, in the sprout's tenant
// Account. No fixed token sits where a sprout ID does, so
// reservedSproutIDs needs no entry for it.
const SproutHeartbeatSubjectPrefix = "imas.heartbeat.sprout."

// SproutHeartbeatSubjectPattern is the single-token wildcard farmer
// subscribes to, per tenant connection, to receive every sprout's
// heartbeat. Farmer must still derive the sprout ID from the subject's
// last token and validate it (IsValidSproutID).
const SproutHeartbeatSubjectPattern = SproutHeartbeatSubjectPrefix + "*"

// SproutHeartbeatSubject is where sprout id publishes its periodic
// heartbeat, and the only heartbeat subject its User JWT may publish to.
func SproutHeartbeatSubject(id string) string {
	return SproutHeartbeatSubjectPrefix + id
}

// SproutLogSubjectPrefix is the subject prefix sprout id publishes its log
// entries under: imas.logs.sprouts.<id>.<LEVEL>, in its tenant's Account.
func SproutLogSubjectPrefix(id string) string {
	return "imas.logs.sprouts." + id
}

// SproutBoxKeySubmitSubject is where sprout id submits a new box public
// key (internal/natsapi's SproutBoxKeySubmitPattern).
func SproutBoxKeySubmitSubject(id string) string {
	return "imas.sprouts." + id + ".boxkey.pub"
}

// SproutShellPublishGrant is sprout id's publish grant for its sealed
// shell frames (internal/shell's SproutOutSubjectPrefix plus ".>").
func SproutShellPublishGrant(id string) string {
	return "imas.shell.sprout." + id + ".>"
}

func sproutLogPublishGrant(id string) string {
	return SproutLogSubjectPrefix(id) + ".>"
}

// SproutUserJWTGrantsLogs reports whether userJWT lets sprout id publish
// its log entries. A sprout whose User JWT was minted before
// SproutPermissions carried the grant keeps using it until a refresh
// fetches the re-minted one and the sprout reconnects with it (at its
// next heartbeat, cmd/sprout's heartbeatGate); until then shipping
// logs would draw a permissions violation for every entry.
func SproutUserJWTGrantsLogs(userJWT, id string) bool {
	uc, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		return false
	}
	grant := sproutLogPublishGrant(id)
	return uc.Pub.Allow.Contains(grant) && !uc.Pub.Deny.Contains(grant)
}

// SproutUserJWTHasFullGrant reports whether userJWT carries exactly the
// grant SproutPermissions(id) names, every subject and nothing else, the
// same comparison MintOrReuseUserJWT makes before it reuses a JWT. A JWT
// it reports false for is one farmer re-mints on the next refresh: any
// grant added to SproutPermissions since the JWT was minted (heartbeat,
// logs, box key, shell, or a later one) makes it stale, not only the
// heartbeat grant.
func SproutUserJWTHasFullGrant(userJWT, id string) bool {
	uc, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(uc.Permissions, SproutPermissions(id))
}

// ensureUserGranted clears any revocation entry for pubkey in ac. It
// reports whether it actually changed ac (i.e. a push is now needed).
func ensureUserGranted(ac *jwt.AccountClaims, pubkey string) bool {
	if _, revoked := ac.Revocations[pubkey]; revoked {
		ac.ClearRevocation(pubkey)
		return true
	}
	return false
}

// ensureUserRevoked adds a revocation entry (effective now) for pubkey in
// ac, if one isn't already present. It reports whether it actually changed
// ac (i.e. a push is now needed).
func ensureUserRevoked(ac *jwt.AccountClaims, pubkey string) bool {
	if _, revoked := ac.Revocations[pubkey]; revoked {
		return false
	}
	ac.Revoke(pubkey)
	return true
}

// revokeUnlessAccepted revokes key, filed under sproutID in state
// (unaccepted, denied or rejected), on ac, unless another row of the same
// tenant has it accepted (accepted maps each accepted row's NKey to its
// sprout ID). Then it changes nothing and logs: a second row naming an
// accepted NKey, for example one a legacy PUT /pki/putnkey filed as
// rejected under another ID, must never revoke the sprout that row
// accepted (security review 2026-10, L12). A deleted or replaced sprout's
// NKey is still revoked through the tenant's revoked list
// (applyRevokedNKeys), which this does not touch. It reports whether it
// changed ac.
func revokeUnlessAccepted(ac *jwt.AccountClaims, tenantID, sproutID, state, key string, accepted map[string]string) bool {
	if owner, ok := accepted[key]; ok {
		log.Warnf("sprout %s in tenant %s is %s with the NKey sprout %s is accepted with; not revoking it", sproutID, tenantID, state, owner)
		return false
	}
	return ensureUserRevoked(ac, key)
}

// applyRevokedNKeys puts every NKey on tenantID's revoked list
// (pki_revoked_nkeys, filled by DeleteNKey and AcceptNKey's replace path)
// into ac's revocations, at its recorded time or later, and reports
// whether it changed ac. FLAG FOR SECURITY REVIEW (security review
// 2026-10, H1): this is what keeps a deleted or replaced sprout's User JWT
// refused. Revocations derived from pki_nkeys rows can't, since the row is
// gone. Callers apply it after granting accepted sprouts, and never grant
// an NKey that is on the list (revoked), so the list always wins.
func applyRevokedNKeys(ac *jwt.AccountClaims, revoked map[string]int64) bool {
	changed := false
	for key, at := range revoked {
		if ac.Revocations == nil {
			ac.Revocations = jwt.RevocationList{}
		}
		if cur, ok := ac.Revocations[key]; ok && cur >= at {
			continue
		}
		ac.Revocations[key] = at
		changed = true
	}
	return changed
}

// syncNatsAuth recomputes the tenant Account's User JWTs and revocation
// list from the current accept/deny/reject/unaccept directory state (the
// same "rebuild from directory state" shape the old NKey-allow-list
// ReloadNKeys used), re-signing the Account JWT, and holding it in memory,
// if its revocation list changed. It starts from the newest of the held
// and the accounts bucket's copy (loadTenantClaims). Comparing the
// farmer's own User JWT's permissions on its next use is what makes a
// change to AllowAllPermissions reach it (farmerUserJWT). It reports
// whether the Account JWT changed (i.e. whether ReloadNKeys needs to push
// an update to the bus).
func syncNatsAuth(mat *natsAuthMaterial) (bool, error) {
	ac, err := loadTenantClaims(mat)
	if err != nil {
		return false, err
	}

	changed := false

	farmerKey, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		log.Fatalf("Could not load the Farmer's NKey, aborting")
	}
	log.Tracef("Loaded farmer's public key: %s", farmerKey)
	if ensureUserGranted(ac, farmerKey) {
		changed = true
	}

	imasKeys, err := auth.GetPubkeysByRole("admin")
	if err != nil {
		log.Errorf("Could not load the imas cli's NKey(s), please edit the config")
	} else {
		log.Tracef("Loaded imas cli's public key(s): %v", imasKeys)
	}
	for _, key := range imasKeys {
		if ensureUserGranted(ac, key) {
			changed = true
		}
	}

	// Read before anything is granted: if it can't be read, a revoked
	// NKey that is somehow still accepted must not be granted (fail
	// closed).
	revoked, err := revokedNKeys(currentTenantID())
	if err != nil {
		return false, err
	}

	accepted := map[string]string{}
	for _, s := range GetNKeysByType(currentTenantID(), "accepted").Sprouts {
		log.Tracef("Syncing accepted sprout `%s` onto the tenant Account JWT", s.SproutID)
		key, errGet := GetNKey(currentTenantID(), s.SproutID)
		if errGet != nil {
			log.Errorf("failed to get NKey for sprout %s: %v", s.SproutID, errGet)
			continue
		}
		accepted[key] = s.SproutID
		if _, isRevoked := revoked[key]; isRevoked {
			log.Errorf("sprout %s is accepted with a revoked NKey; keeping it revoked", s.SproutID)
			continue
		}
		// The sprout's User JWT is minted on demand, where it is served
		// (MintOrReuseUserJWT), not here for every accepted sprout.
		if ensureUserGranted(ac, key) {
			changed = true
		}
	}

	for _, state := range []string{"unaccepted", "denied", "rejected"} {
		for _, s := range GetNKeysByType(currentTenantID(), state).Sprouts {
			key, errGet := GetNKey(currentTenantID(), s.SproutID)
			if errGet != nil {
				log.Errorf("failed to get NKey for sprout %s: %v", s.SproutID, errGet)
				continue
			}
			if revokeUnlessAccepted(ac, currentTenantID(), s.SproutID, state, key, accepted) {
				changed = true
			}
		}
	}
	if applyRevokedNKeys(ac, revoked) {
		changed = true
	}

	log.Tracef("Completed syncing authorized clients onto the tenant Account JWT.")

	if changed {
		// A strictly newer iat than the JWT this replaces (§7.3 step 1):
		// the jti hashes only subject, issuer, name and iat, so a re-sign
		// in the same second would read as the same JWT to the bus
		// loaders and the resolver sync. A JWT minted by this same call
		// was never published, so it needn't be outranked.
		if !mat.tenantMinted {
			waitPastIssuedAt(ac.IssuedAt)
		}
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return false, encErr
		}
		if holdErr := holdAccountJWT(signed, false); holdErr != nil {
			return false, holdErr
		}
		mat.tenantJWT = signed
		mat.tenantMinted = false
	} else {
		// Unchanged: hold the JWT it started from (the bucket's, or a
		// minimal mint that already is the tenant's state) as synced.
		if holdErr := holdAccountJWT(mat.tenantJWT, false); holdErr != nil {
			return false, holdErr
		}
	}
	return changed, nil
}

// FarmerUserJWT returns the farmer's own signed User JWT under the legacy
// tenant's Account, signing it on first use and holding it in memory
// (farmerUserJWT, accountjwts.go). It is the legacy tenant's
// FarmerUserJWTForTenant: the per-tenant bus connection authenticates
// with it alongside the farmer's NKey seed — the same User-JWT-plus-seed
// shape ConnectSystemAccount uses for the SYS push connection. Nothing is
// read from or written to disk, so it works on any replica from its first
// call.
func FarmerUserJWT() (string, error) {
	mat, err := ensureNatsAuth()
	if err != nil {
		return "", err
	}
	return farmerUserJWT(mat.tenantPub, mat.tenantSigningKP)
}

// Per-sprout User JWT store (P21 slice 3, docs/briefs/P21-slice3-farmer-
// saasapi-state.md §4.2). FLAG FOR SECURITY REVIEW: this decides which
// User JWT a sprout is handed, and serialises minting across farmer
// replicas.
//
// A sprout's signed User JWT lives in the private sprout JWT bucket
// (IMAS_S3_SPROUT_JWT_BUCKET) under <tenant>/<sprout>/<jwt_sha256>.jwt,
// never on local disk, and is indexed by one farmer.sprout_user_jwt row
// per (tenant_id, sprout_id): a sprout ID is unique per tenant only. The
// row says which key the JWT was minted for (user_pubkey, the source of
// truth), where it is (object_key) and its hash (jwt_sha256), so a
// replica checks what it fetched before handing it out. The row's lease
// columns serialise minting: of N replicas enrolling the same sprout at
// once, one mints and the others reuse its JWT.
//
// A replica that dies after the PUT and before the row UPDATE leaves an
// object no row points at; harmless, since the key carries the hash and
// the next minter writes its own. Its lease lapses at lease_until.

// SproutJWTBucketEnv names the private bucket sprout User JWTs are kept
// in. It must be neither the recipe bucket (GET /files/ serves every key
// in it) nor the job bucket.
const SproutJWTBucketEnv = "IMAS_S3_SPROUT_JWT_BUCKET"

// ErrSproutJWTBusy reports that another replica holds the sprout's mint
// lease and did not finish within the poll window, or that this replica
// lost the lease mid-mint. Retryable: the caller should answer 503 with a
// Retry-After and let the sprout try again.
var ErrSproutJWTBusy = errors.New("pki: sprout user JWT is being minted by another replica; retry")

// ErrSproutJWTStoreNotConfigured reports that no sprout JWT bucket is set.
var ErrSproutJWTStoreNotConfigured = errors.New("pki: sprout user JWT store not configured (" + SproutJWTBucketEnv + ")")

const (
	// sproutJWTLeaseTTL bounds how long a dead minter blocks a sprout: a
	// mint is one Transit sign and one PUT.
	sproutJWTLeaseTTL = 30 * time.Second
	// sproutJWTPollWait is how long a caller that lost the lease waits for
	// the winner's JWT before giving up with ErrSproutJWTBusy.
	sproutJWTPollWait = 5 * time.Second
	// sproutJWTPollInterval is the re-check interval within that wait.
	sproutJWTPollInterval = 200 * time.Millisecond
	// sproutJWTRenewWindow re-mints a JWT that expires within it. Sprout
	// User JWTs carry no expiry today, so this applies only once one does.
	sproutJWTRenewWindow = 24 * time.Hour
	// maxSproutJWTSize bounds the object read back; a sprout User JWT is
	// well under 2 KiB.
	maxSproutJWTSize = 16 << 10
)

// sproutUserJWTRow is a farmer.sprout_user_jwt row (migration farmer
// 00005). The table comes from the migration; this model is only how the
// store reads and writes it. Its columns match the migration except that
// it declares no default for updated_at, which the migration sets to
// CURRENT_TIMESTAMP(3): sqlite, which this package's tests build the table
// in, rejects that default, and the store always sets updated_at itself.
// That is why internal/migrations' baseline check still skips this table.
type sproutUserJWTRow struct {
	TenantID   string     `gorm:"column:tenant_id;primaryKey;size:64"`
	SproutID   string     `gorm:"column:sprout_id;primaryKey;size:253"`
	ObjectKey  *string    `gorm:"column:object_key;size:512"`
	UserPubkey *string    `gorm:"column:user_pubkey;size:64"`
	JWTSHA256  *string    `gorm:"column:jwt_sha256;type:char(64)"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
	LeaseOwner *string    `gorm:"column:lease_owner;size:128"`
	LeaseUntil *time.Time `gorm:"column:lease_until"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;not null;autoUpdateTime:false"`
}

// TableName is the table the row lives in.
func (sproutUserJWTRow) TableName() string { return string(lease.SproutUserJWT) }

// SproutJWTModels returns the model of the sprout_user_jwt table, for
// test databases built with AutoMigrate. Production's table comes from
// migration farmer 00005.
func SproutJWTModels() []any { return []any{&sproutUserJWTRow{}} }

// sproutJWTObjects is the part of *objectstore.Store the store uses.
type sproutJWTObjects interface {
	GetLimited(ctx context.Context, key string, limit int64) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
}

// sproutJWTIssuer returns the Account a tenant's sprout User JWTs are
// issued under: its public key and the signing pair (Transit) to sign
// with.
type sproutJWTIssuer func(ctx context.Context, tenantID string) (accountPub string, kp nkeys.KeyPair, err error)

// sproutJWTStore is one replica's view of the store.
type sproutJWTStore struct {
	db      *gorm.DB
	objects sproutJWTObjects
	leases  *lease.Leases
	// owner is this replica's lease owner prefix; each mintOrReuse call
	// takes the lease under its own token (callOwner).
	owner  string
	issuer sproutJWTIssuer
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	// afterPut, if set, runs after the object PUT and before the row
	// UPDATE. Tests only: an error stands for the replica dying there, so
	// mintLeased returns it without updating the row or releasing the
	// lease.
	afterPut func() error
}

var (
	sproutJWTObjectsMu  sync.Mutex
	sproutJWTObjectsSet sproutJWTObjects
)

// SetSproutJWTStore installs the bucket sprout User JWTs are kept in. Nil
// clears it, so the next use opens the bucket named by
// IMAS_S3_SPROUT_JWT_BUCKET again.
func SetSproutJWTStore(s *objectstore.Store) {
	sproutJWTObjectsMu.Lock()
	defer sproutJWTObjectsMu.Unlock()
	if s == nil {
		sproutJWTObjectsSet = nil
		return
	}
	sproutJWTObjectsSet = s
}

// sproutJWTBucket returns the installed bucket, or opens the one
// IMAS_S3_SPROUT_JWT_BUCKET names on the configured S3 endpoint.
func sproutJWTBucket() (sproutJWTObjects, error) {
	sproutJWTObjectsMu.Lock()
	defer sproutJWTObjectsMu.Unlock()
	if sproutJWTObjectsSet != nil {
		return sproutJWTObjectsSet, nil
	}
	bucket := os.Getenv(SproutJWTBucketEnv)
	if bucket == "" {
		return nil, ErrSproutJWTStoreNotConfigured
	}
	if bucket == config.S3Bucket || bucket == config.S3JobBucket {
		return nil, fmt.Errorf("%w: bucket %q must be private to sprout JWTs, not the recipe or job bucket", ErrSproutJWTStoreNotConfigured, bucket)
	}
	s, err := objectstore.Open(objectstore.Config{
		Endpoint:        config.S3Endpoint,
		AccessKeyID:     config.S3AccessKeyID,
		SecretAccessKey: config.S3SecretAccessKey,
		UseSSL:          config.S3UseSSL,
		Bucket:          bucket,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSproutJWTStoreNotConfigured, err)
	}
	sproutJWTObjectsSet = s
	return s, nil
}

var (
	replicaOwnerOnce sync.Once
	replicaOwnerID   string
)

// replicaOwner is this process's lease owner: its host name (the pod
// name) plus a random suffix, so two processes on one host differ.
func replicaOwner() string {
	replicaOwnerOnce.Do(func() {
		host, _ := os.Hostname()
		if len(host) > 64 {
			host = host[:64]
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		replicaOwnerID = host + "-" + hex.EncodeToString(b[:])
	})
	return replicaOwnerID
}

// callOwner is the lease owner of one mintOrReuse call: the replica's
// owner plus a random token. Two calls on one replica must not share an
// owner, or the second would take the first's lease as its own (Acquire
// lets the holder re-take it) and both would mint; and a mint outliving
// its lease could release or overwrite a later one.
func (s *sproutJWTStore) callOwner() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return s.owner + "-" + hex.EncodeToString(b[:])
}

// defaultSproutJWTStore is the store on the package's database and
// bucket.
func defaultSproutJWTStore() (*sproutJWTStore, error) {
	if db == nil {
		return nil, errors.New("pki: no database configured")
	}
	objs, err := sproutJWTBucket()
	if err != nil {
		return nil, err
	}
	return &sproutJWTStore{
		db:      db,
		objects: objs,
		leases:  lease.New(db, nil),
		owner:   replicaOwner(),
		issuer:  tenantSproutJWTIssuer,
		now:     time.Now,
		sleep:   sleepCtx,
	}, nil
}

// sleepCtx waits d, or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// tenantSproutJWTIssuer is the tenant's own Account (tenant.go) or, for
// the legacy current tenant with no per-tenant Account of its own (no
// Account recorded on its pki_tenants row), the legacy Account, matching
// where its sprouts' JWTs were issued before.
func tenantSproutJWTIssuer(_ context.Context, tenantID string) (string, nkeys.KeyPair, error) {
	if tenantID != currentTenantID() || hasOwnTenantAccount(tenantID) {
		tam, err := loadTenantAccountMaterial(tenantID)
		if err != nil {
			return "", nil, err
		}
		return tam.pub, tam.signingKP, nil
	}
	mat, err := ensureNatsAuth()
	if err != nil {
		return "", nil, err
	}
	return mat.tenantPub, mat.tenantSigningKP, nil
}

// sproutJWTObjectKey is the bucket key of a sprout's JWT with hash sum.
func sproutJWTObjectKey(tenantID, sproutID, sum string) string {
	return tenantID + "/" + sproutID + "/" + sum + ".jwt"
}

// MintOrReuseUserJWT returns the User JWT for sprout sproutID of tenant
// tenantID, issued to pubkey under the tenant's Account, minting it only
// if none is stored for that key with the current permissions. The sprout
// must be accepted in that tenant with exactly pubkey, and pubkey must
// not be revoked: the store never issues a JWT for any other key.
//
// The error wraps ErrSproutJWTBusy when another replica is minting it and
// did not finish in time; the caller should ask the sprout to retry.
func MintOrReuseUserJWT(ctx context.Context, tenantID, sproutID, pubkey string) (string, error) {
	s, err := defaultSproutJWTStore()
	if err != nil {
		return "", err
	}
	return s.mintOrReuse(ctx, tenantID, sproutID, pubkey)
}

// GetSproutUserJWT returns the User JWT of sprout id of the legacy
// current tenant: for an accepted sprout as MintOrReuseUserJWT does
// (minting it if due), for any other the one stored, if any, without
// minting.
func GetSproutUserJWT(id string) (string, error) {
	if !IsValidSproutID(id) {
		return "", ErrSproutIDInvalid
	}
	s, err := defaultSproutJWTStore()
	if err != nil {
		return "", err
	}
	tenant := currentTenantID()
	row, err := s.findNKey(tenant, id)
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	if row.State == stateAccepted {
		return s.mintOrReuse(ctx, tenant, id, row.NKey)
	}
	signed, ok, err := s.reuse(ctx, tenant, id, row.NKey, SproutPermissions(id))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrSproutIDNotFound
	}
	return signed, nil
}

// findNKey reads the sprout's pki_nkeys row through the store's database.
func (s *sproutJWTStore) findNKey(tenantID, sproutID string) (*nkeyRow, error) {
	var row nkeyRow
	err := s.db.Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSproutIDNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// checkEligible fails unless the sprout is accepted in tenantID with
// exactly pubkey and pubkey is not on the tenant's revoked list.
func (s *sproutJWTStore) checkEligible(tenantID, sproutID, pubkey string) error {
	row, err := s.findNKey(tenantID, sproutID)
	if err != nil {
		return err
	}
	if row.State != stateAccepted || row.NKey != pubkey {
		return fmt.Errorf("pki: sprout %s in tenant %s is not accepted with that NKey", sproutID, tenantID)
	}
	var n int64
	if err := s.db.Model(&revokedNKeyRow{}).Where("tenant_id = ? AND nkey = ?", tenantID, pubkey).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("pki: sprout %s in tenant %s: %w", sproutID, tenantID, ErrNKeyRevoked)
	}
	return nil
}

// mintOrReuse is MintOrReuseUserJWT on this replica's store.
func (s *sproutJWTStore) mintOrReuse(ctx context.Context, tenantID, sproutID, pubkey string) (string, error) {
	if !IsValidTenantID(tenantID) {
		return "", ErrTenantIDInvalid
	}
	if !IsValidSproutID(sproutID) {
		return "", ErrSproutIDInvalid
	}
	if !nkeys.IsValidPublicUserKey(pubkey) {
		return "", errors.New("pki: sprout NKey is not a valid user public key")
	}
	if err := s.checkEligible(tenantID, sproutID, pubkey); err != nil {
		return "", err
	}
	perms := SproutPermissions(sproutID)
	key := []any{tenantID, sproutID}

	owner := s.callOwner()
	deadline := s.now().Add(sproutJWTPollWait)
	inserted := false
	for {
		if signed, ok, err := s.reuse(ctx, tenantID, sproutID, pubkey, perms); err != nil || ok {
			return signed, err
		}
		if !inserted {
			// INSERT IGNORE: the lease needs the row to exist.
			row := sproutUserJWTRow{TenantID: tenantID, SproutID: sproutID, UpdatedAt: dbTimeUTC(s.now())}
			if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return "", fmt.Errorf("pki: recording sprout JWT row: %w", err)
			}
			inserted = true
		}
		got, err := s.leases.Acquire(ctx, lease.SproutUserJWT, key, owner, sproutJWTLeaseTTL)
		if err != nil {
			return "", fmt.Errorf("pki: taking sprout JWT lease: %w", err)
		}
		if got {
			return s.mintLeased(ctx, tenantID, sproutID, pubkey, owner, perms)
		}
		if !s.now().Before(deadline) {
			return "", fmt.Errorf("sprout %s in tenant %s: %w", sproutID, tenantID, ErrSproutJWTBusy)
		}
		if err := s.sleep(ctx, sproutJWTPollInterval); err != nil {
			return "", err
		}
	}
}

// mintLeased runs with the lease held: it re-reads (another replica may
// have minted while this one waited), else mints, PUTs and records the
// JWT. It releases the lease on return, even if ctx was cancelled (the
// caller went away), so a retry need not wait for lease_until.
func (s *sproutJWTStore) mintLeased(ctx context.Context, tenantID, sproutID, pubkey, owner string, perms jwt.Permissions) (string, error) {
	key := []any{tenantID, sproutID}
	died := false
	defer func() {
		if died {
			return
		}
		if _, err := s.leases.Release(context.WithoutCancel(ctx), lease.SproutUserJWT, key, owner); err != nil {
			log.Debugf("pki: releasing sprout JWT lease for %s in tenant %s: %v", sproutID, tenantID, err)
		}
	}()
	if signed, ok, err := s.reuse(ctx, tenantID, sproutID, pubkey, perms); err != nil || ok {
		return signed, err
	}
	accountPub, kp, err := s.issuer(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("pki: loading tenant %s's signing key: %w", tenantID, err)
	}
	uc := jwt.NewUserClaims(pubkey)
	uc.Name = sproutID
	uc.IssuerAccount = accountPub
	uc.Permissions = perms
	signed, err := uc.Encode(kp)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(signed))
	sum := hex.EncodeToString(digest[:])
	objKey := sproutJWTObjectKey(tenantID, sproutID, sum)
	if err := s.objects.Put(ctx, objKey, []byte(signed)); err != nil {
		return "", fmt.Errorf("pki: storing sprout JWT: %w", err)
	}
	if s.afterPut != nil {
		if err := s.afterPut(); err != nil {
			died = true
			return "", err
		}
	}
	r := s.db.WithContext(ctx).Model(&sproutUserJWTRow{}).
		Where("tenant_id = ? AND sprout_id = ? AND lease_owner = ?", tenantID, sproutID, owner).
		UpdateColumns(map[string]any{
			"object_key":  objKey,
			"user_pubkey": pubkey,
			"jwt_sha256":  sum,
			"expires_at":  nil,
			"updated_at":  dbTimeUTC(s.now()),
		})
	if r.Error != nil {
		return "", fmt.Errorf("pki: recording sprout JWT: %w", r.Error)
	}
	if r.RowsAffected != 1 {
		// The lease lapsed and another replica took it: its row wins.
		return "", fmt.Errorf("sprout %s in tenant %s: lease lost while minting: %w", sproutID, tenantID, ErrSproutJWTBusy)
	}
	// Check again, after signing: a deny, delete or revocation that
	// committed before this read is caught here, and one that commits
	// after it is revoked on the Account at or after this JWT's issue
	// time, which the bus then refuses (a revocation covers every JWT
	// issued at or before it). Lifecycle changes don't take the mint
	// lease, so without this a sprout denied while its JWT was being
	// minted could be handed one issued after its revocation. The stored
	// object is never served: every caller checks eligibility first.
	if err := s.checkEligible(tenantID, sproutID, pubkey); err != nil {
		return "", fmt.Errorf("pki: sprout %s in tenant %s changed state while its JWT was minted: %w", sproutID, tenantID, err)
	}
	return signed, nil
}

// reuse returns the stored JWT if the row says it was minted for pubkey,
// it is not within the renew window, the object's hash matches the row
// and it carries perms. ok is false, with no error, when a mint is due
// (no row, pending row, other key, stale permissions, expiring, missing
// or mismatched object).
func (s *sproutJWTStore) reuse(ctx context.Context, tenantID, sproutID, pubkey string, perms jwt.Permissions) (string, bool, error) {
	var row sproutUserJWTRow
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("pki: reading sprout JWT row: %w", err)
	}
	if row.UserPubkey == nil || *row.UserPubkey != pubkey || row.JWTSHA256 == nil || row.ObjectKey == nil {
		return "", false, nil
	}
	if row.ExpiresAt != nil && !s.now().Add(sproutJWTRenewWindow).Before(*row.ExpiresAt) {
		return "", false, nil
	}
	if *row.ObjectKey != sproutJWTObjectKey(tenantID, sproutID, *row.JWTSHA256) {
		log.Warnf("pki: sprout JWT row for %s in tenant %s names an unexpected object; re-minting", sproutID, tenantID)
		return "", false, nil
	}
	b, err := s.objects.GetLimited(ctx, *row.ObjectKey, maxSproutJWTSize)
	if objectstore.IsNotExist(err) {
		log.Warnf("pki: sprout JWT object for %s in tenant %s is missing; re-minting", sproutID, tenantID)
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("pki: fetching sprout JWT: %w", err)
	}
	digest := sha256.Sum256(b)
	if hex.EncodeToString(digest[:]) != *row.JWTSHA256 {
		log.Warnf("pki: sprout JWT object for %s in tenant %s does not match its recorded hash; re-minting", sproutID, tenantID)
		return "", false, nil
	}
	uc, err := jwt.DecodeUserClaims(string(bytes.TrimSpace(b)))
	if err != nil || uc.Subject != pubkey || !reflect.DeepEqual(uc.Permissions, perms) {
		return "", false, nil
	}
	return string(b), true, nil
}

// dbTimeUTC is t as a datetime(3) column stores it.
func dbTimeUTC(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }
