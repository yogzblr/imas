package saasapi

import "time"

// TenantStatus is the tenant lifecycle state exposed by GET
// /tenants/{tenant_id}/status (design doc §1.1).
type TenantStatus string

const (
	TenantStatusPending     TenantStatus = "pending"
	TenantStatusActive      TenantStatus = "active"
	TenantStatusFailed      TenantStatus = "failed"
	TenantStatusOffboarding TenantStatus = "offboarding"
	TenantStatusOffboarded  TenantStatus = "offboarded"
	// TenantStatusPurged: the tenant's data is erased (S6). Only the
	// tombstone is left: this row (name and plan cleared), its
	// provisioning jobs, and farmer's deleted marker and locked-out
	// Account JWT. Final.
	TenantStatusPurged TenantStatus = "purged"
)

// Tenant is the `saas.tenants` table (design doc §4.2).
//
// OffboardedAt is when the tenant's deprovision result was applied, the
// start of its retention delay (SAASAPI_TENANT_PURGE_AFTER); migration
// saas/00010 backfilled it from updated_at for tenants already offboarded,
// and a tenant offboarded by an older release has it NULL, so the sweeper
// reads COALESCE(offboarded_at, updated_at). PurgeClaimedAt is written
// when a purge job is started for the tenant, by the sweeper or the
// operator route, in the same transaction and conditional on the value
// read, so two starts on different PXC nodes write the same row and
// Galera certification refuses one; it also spaces the sweeper's
// retries a day apart. Neither is part of GET /tenants/{id}.
type Tenant struct {
	ID             string       `gorm:"column:id;primaryKey;size:32" json:"tenant_id"`
	Name           string       `gorm:"column:name;size:255;not null" json:"name"`
	Status         TenantStatus `gorm:"column:status;size:32;not null;index" json:"status"`
	PlanID         string       `gorm:"column:plan_id;size:64" json:"plan_id,omitempty"`
	CreatedAt      time.Time    `gorm:"column:created_at" json:"created_at"`
	UpdatedAt      time.Time    `gorm:"column:updated_at" json:"updated_at"`
	OffboardedAt   *time.Time   `gorm:"column:offboarded_at" json:"-"`
	PurgeClaimedAt *time.Time   `gorm:"column:purge_claimed_at" json:"-"`
}

func (Tenant) TableName() string { return "tenants" }

// ProvisioningJobType distinguishes tenant provisioning, deprovisioning
// (offboarding) and purge (erasure, S6) outbox rows. Its values are
// controlplane.TenantJob's.
type ProvisioningJobType string

const (
	ProvisioningJobProvision   ProvisioningJobType = "provision"
	ProvisioningJobDeprovision ProvisioningJobType = "deprovision"
	ProvisioningJobPurge       ProvisioningJobType = "purge"
)

// ProvisioningJobStatus is the outbox row's own status, independent of
// (but driving) the tenant's TenantStatus.
type ProvisioningJobStatus string

const (
	ProvisioningJobPending   ProvisioningJobStatus = "pending"
	ProvisioningJobSucceeded ProvisioningJobStatus = "succeeded"
	ProvisioningJobFailed    ProvisioningJobStatus = "failed"
)

// ProvisioningJob is the `saas.provisioning_jobs` outbox table (design doc
// §4.2, §4 "Async pattern"). Every async tenant operation (create/delete)
// writes a row here rather than relying on a bare NATS publish, since NATS
// core (no JetStream) gives no redelivery guarantee.
//
// provisioning.go's applyProvisioningResult moves a job out of "pending"
// when farmer's internal.tenant.{de,}provisioned.{job_id} result arrives
// (§2.2). Attempts counts publishes and LastDispatchedAt records the
// latest; the outbox sweeper (sweeper.go) re-publishes a job still pending
// after a backoff measured from it, and fails the job once Attempts
// reaches its limit. LeaseOwner/LeaseUntil are the sweeper's row lease
// (migration saas/00006); never part of the API.
type ProvisioningJob struct {
	ID        string                `gorm:"column:id;primaryKey;size:36" json:"id"`
	TenantID  string                `gorm:"column:tenant_id;size:32;not null;index" json:"tenant_id"`
	Type      ProvisioningJobType   `gorm:"column:type;size:32;not null" json:"type"`
	Status    ProvisioningJobStatus `gorm:"column:status;size:32;not null" json:"status"`
	Attempts  int                   `gorm:"column:attempts;not null;default:0" json:"attempts"`
	LastError string                `gorm:"column:last_error;type:text" json:"last_error,omitempty"`
	// Warning qualifies a succeeded job: a fixed, caller-safe message
	// (controlplane.PublicWarningMessage) for a result that reached its end
	// state by an unusual path — e.g. deprovisioning a tenant farmer never
	// provisioned. Surfaced by GET /tenants/{id}/status.
	Warning          string     `gorm:"column:warning;type:text" json:"warning,omitempty"`
	CreatedAt        time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"column:updated_at" json:"updated_at"`
	LastDispatchedAt *time.Time `gorm:"column:last_dispatched_at" json:"-"`
	LeaseOwner       string     `gorm:"column:lease_owner;size:64;not null;default:''" json:"-"`
	LeaseUntil       *time.Time `gorm:"column:lease_until" json:"-"`
	// PurgeTrigger is a purge job's controlplane.PurgeTrigger* (retention
	// or operator), sent with every publish of it; '' on other jobs
	// (migration saas/00010).
	PurgeTrigger string `gorm:"column:purge_trigger;size:16;not null;default:''" json:"-"`
}

func (ProvisioningJob) TableName() string { return "provisioning_jobs" }

// EnrollmentKey is the `saas.enrollment_keys` table (design doc §4.2,
// §3.1). Only key_id is ever stored in plaintext; the secret half of the
// issued token is stored solely as its SHA-256 hash (KeyHash) — see
// idgen.go/enrollment_keys.go, both explicitly flagged for security
// review per the task brief.
type EnrollmentKey struct {
	// KeyID is the public, indexed lookup part of the
	// {key_id}.{secret}.{tenant_key_fingerprint} token (§3.1,
	// internal/jointoken) — safe to log and store in plaintext.
	KeyID      string     `gorm:"column:key_id;primaryKey;size:32" json:"key_id"`
	TenantID   string     `gorm:"column:tenant_id;size:32;not null;index" json:"tenant_id"`
	KeyHash    string     `gorm:"column:key_hash;size:64;not null" json:"-"`
	Expiry     time.Time  `gorm:"column:expiry;not null" json:"expires_at"`
	MaxUses    int        `gorm:"column:max_uses;not null" json:"max_uses"`
	UsedCount  int        `gorm:"column:used_count;not null;default:0" json:"used_count"`
	Revoked    bool       `gorm:"column:revoked;not null;default:false" json:"revoked"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"created_at"`
	LastUsedAt *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
}

func (EnrollmentKey) TableName() string { return "enrollment_keys" }

// AssetLink is the `saas.asset_links` table (design doc §4.2, §1.3): the
// only place the cloud platform's asset_id enters the system.
//
// Uniqueness:
//   - (tenant_id, sprout_id) is UNIQUE — one sprout carries at most one
//     asset_id. This is per tenant, not global as §4.2's sketch has it,
//     because farmer's pki_nkeys only keys a sprout_id per tenant: two
//     tenants may each have a sprout named "web-01", and both must be
//     able to link it.
//   - asset_id is globally UNIQUE — the cloud platform generates it externally and
//     it identifies one VM across all tenants, so it resolves to at most
//     one sprout anywhere.
//
// Every query that resolves a caller-supplied sprout_id or asset_id
// against this table includes tenant_id in its WHERE clause (§4 "Tenant
// safety"); see asset_links.go.
type AssetLink struct {
	ID       string    `gorm:"column:id;primaryKey;size:32" json:"-"`
	TenantID string    `gorm:"column:tenant_id;size:32;not null;uniqueIndex:idx_asset_links_tenant_sprout,priority:1" json:"tenant_id"`
	SproutID string    `gorm:"column:sprout_id;size:253;not null;uniqueIndex:idx_asset_links_tenant_sprout,priority:2" json:"sprout_id"`
	AssetID  string    `gorm:"column:asset_id;size:191;not null;uniqueIndex" json:"asset_id"`
	LinkedAt time.Time `gorm:"column:linked_at;not null" json:"linked_at"`
}

func (AssetLink) TableName() string { return "asset_links" }

// FleetVersion is the `saas.fleet_versions` table (design doc §4.3,
// §1.8, §2.5): the cloud platform's own catalog of sprout releases, one row per
// version, OS, arch and package type. It is deliberately not upstream
// imas's GitHub release feed — a version only becomes approvable by a
// tenant once the cloud platform has registered it here.
//
// The catalog is global, not per tenant: every tenant chooses from the
// same list, and tenant_update_policy records which version each tenant
// has approved. Rows are written only by the operator-plane release
// registration (fleet_releases.go), together with the version's
// FleetReleaseChecksums row. A registered row is never changed afterwards
// except to revoke it.
//
// The trust root is the release's GPG-signed checksums.txt
// (FleetReleaseChecksums, P22), which the sprout verifies itself (signing
// design D20). FileName and ChecksumSHA256 are what the registration
// checked against that checksums.txt; the sprout derives the file name
// and takes the hash from the signed file, never from these columns.
// There is no URL: the sprout downloads from the repository configured in
// the sprout itself (requirement 20).
type FleetVersion struct {
	ID      string `gorm:"column:id;primaryKey;size:32" json:"-"`
	Version string `gorm:"column:version;size:64;not null;uniqueIndex:idx_fleet_versions_version_os_arch_type,priority:1" json:"version"`
	OS      string `gorm:"column:os;size:32;not null;uniqueIndex:idx_fleet_versions_version_os_arch_type,priority:2" json:"os"`
	Arch    string `gorm:"column:arch;size:32;not null;uniqueIndex:idx_fleet_versions_version_os_arch_type,priority:3" json:"arch"`
	// PackageType is the installer the sprout uses for FileName: deb,
	// rpm or msi. Part of the row's key, since one linux/amd64 binary
	// ships as both a .deb and an .rpm; a sprout asks for its own type.
	PackageType      string `gorm:"column:package_type;size:16;not null;uniqueIndex:idx_fleet_versions_version_os_arch_type,priority:4" json:"package_type"`
	FileName         string `gorm:"column:file_name;size:255;not null" json:"file_name"`
	ChecksumSHA256   string `gorm:"column:checksum_sha256;size:64;not null" json:"checksum_sha256"`
	MinSproutVersion string `gorm:"column:min_sprout_version;size:64;not null" json:"min_sprout_version"`
	// Signature held the pre-P22 per-row Ed25519 signature. Unused since
	// P22 slice 2: registration writes '', nothing reads it, and a later
	// migration drops the column.
	Signature string `gorm:"column:signature;size:128;not null;default:''" json:"-"`
	// Revoked withdraws the version (every row of it at once, POST
	// /v1/operator/fleet-releases/{version}/revoke): no manifest is served
	// for it, no rollout is created for it, and no tenant can newly
	// approve it. It is never cleared.
	Revoked    bool      `gorm:"column:revoked;not null;default:false" json:"revoked"`
	ReleasedAt time.Time `gorm:"column:released_at;not null;index" json:"released_at"`
	Notes      string    `gorm:"column:notes;type:text" json:"notes,omitempty"`
}

// releaseKey is r's identity within a version: os/arch/package_type,
// the unique key of saas.fleet_versions besides the version.
func (r FleetVersion) releaseKey() string {
	return r.OS + "/" + r.Arch + "/" + r.PackageType
}

func (FleetVersion) TableName() string { return "fleet_versions" }

// FleetReleaseChecksums is the `saas.fleet_release_checksums` table
// (migration 00007, P22): one row per release version holding the
// release's checksums.txt byte for byte and checksums.txt.sig in standard
// padded base64, as registered with the version's FleetVersion rows.
// saasapi checks checksums.txt's shape and that it lists every
// registered package with its checksum, but never verifies the signature:
// the sprout is the only verifier (signing design D20). Farmer serves both
// in GET /v1/sprout/update-manifest (internal/fleetcatalog). A row is
// never changed after it is written.
type FleetReleaseChecksums struct {
	Version      string    `gorm:"column:version;primaryKey;size:64"`
	ChecksumsTxt string    `gorm:"column:checksums_txt;type:mediumtext;not null"`
	ChecksumsSig string    `gorm:"column:checksums_sig;type:text;not null"`
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
}

func (FleetReleaseChecksums) TableName() string { return "fleet_release_checksums" }

// TenantUpdatePolicy is the `saas.tenant_update_policy` table (design doc
// §4.3, §1.8): one row per tenant, keyed by tenant_id alone since it holds
// no sprout-level state. A tenant without a row has the default policy —
// no approved version, auto_update off — so no sprout of theirs is ever
// updated until they explicitly approve a version.
//
// ApprovedVersion, when set, names a FleetVersion.Version. The rollout
// window is a pair of absolute UTC instants, both set or both NULL.
//
// UpdatedAt moves only when the policy itself is written (PATCH
// .../update-policy). RolloutClaimedAt is written by claimRollout when an
// update rollout starts, and by nothing else: it exists so that two claims
// committed on different PXC nodes write the same row and Galera
// certification refuses one (fleet_update_dispatch.go). It is never part
// of the API (migration saas/00005).
type TenantUpdatePolicy struct {
	TenantID           string     `gorm:"column:tenant_id;primaryKey;size:32" json:"tenant_id"`
	ApprovedVersion    *string    `gorm:"column:approved_version;size:64" json:"approved_version"`
	AutoUpdate         bool       `gorm:"column:auto_update;not null;default:false" json:"auto_update"`
	RolloutWindowStart *time.Time `gorm:"column:rollout_window_start" json:"rollout_window_start"`
	RolloutWindowEnd   *time.Time `gorm:"column:rollout_window_end" json:"rollout_window_end"`
	UpdatedAt          time.Time  `gorm:"column:updated_at" json:"updated_at"`
	RolloutClaimedAt   *time.Time `gorm:"column:rollout_claimed_at" json:"-"`
}

func (TenantUpdatePolicy) TableName() string { return "tenant_update_policy" }

// AssetActionItemStatus is one §1.5 batch item's status, as returned by
// GET /tenants/{tenant_id}/sprouts/actions/{batch_id}.
//
// The outbox distinction that matters is queued vs. dispatching (see
// sprout_actions.go's dispatchItem): a queued item has provably never
// reached farmer and is safe to (re-)dispatch; a dispatching item's
// request has been sent, so if it stays dispatching (this process died
// before the reply, or the reply was lost) its outcome is unknown and it
// must never be blindly re-sent — cmd.run isn't idempotent.
type AssetActionItemStatus string

const (
	// ActionItemUnresolved: the asset_id didn't resolve to a sprout in
	// the caller's tenant (never linked, linked elsewhere, or its sprout
	// is gone). Never dispatched.
	ActionItemUnresolved AssetActionItemStatus = "unresolved"
	// ActionItemQueued: resolved and recorded, not yet sent to farmer.
	ActionItemQueued AssetActionItemStatus = "queued"
	// ActionItemDispatching: sent to farmer; no reply recorded yet.
	ActionItemDispatching AssetActionItemStatus = "dispatching"
	// ActionItemRunning: farmer accepted it and returned a jid (a cook);
	// the job itself hasn't been seen to finish.
	ActionItemRunning AssetActionItemStatus = "running"
	// ActionItemSucceeded: a cmd.run that exited 0, or a job that
	// finished successfully.
	ActionItemSucceeded AssetActionItemStatus = "succeeded"
	// ActionItemFailed: anything that ended badly; ErrorCode says what.
	ActionItemFailed AssetActionItemStatus = "failed"
	// ActionItemUnresponsiveAfterUpdate: a self_update (§1.8) was
	// accepted, but the sprout never reported the update's outcome
	// before its rollout wave's deadline. It's kept apart from failed
	// (design doc §2.3) because the operator's response is different: the
	// sprout may be unable to reconnect, or its backup/restore path may
	// already have recovered it.
	ActionItemUnresponsiveAfterUpdate AssetActionItemStatus = "unresponsive_after_update"
)

// terminal reports whether s is an end state: nothing further will move
// an item out of it.
func (s AssetActionItemStatus) terminal() bool {
	switch s {
	case ActionItemUnresolved, ActionItemSucceeded, ActionItemFailed, ActionItemUnresponsiveAfterUpdate:
		return true
	}
	return false
}

// AssetActionBatch is the `saas.asset_action_batches` table (design doc
// §4.2, §1.5): one row per POST .../sprouts/actions, the outbox parent of
// its AssetActionItem rows.
//
// ActionParams is the farmer-side internal.sprout.action params exactly as
// dispatched (see sprout_actions.go's translateAction), kept so the outbox
// sweeper (sweeper.go) can re-send a queued item unchanged. It holds the command
// line the caller supplied (never environment variables: the API accepts
// none), so it is never returned by the API. RequestedAssetIDs is the JSON array of the
// batch's deduplicated asset_ids, in request order.
//
// A §1.8 fleet update rollout is a batch with ActionType self_update
// (fleet_update_dispatch.go). Its ActionParams are built from the version
// catalog, and RolloutBatchSize and RolloutGate record the wave size and
// gate it was created with. Both are zero for a §1.5 batch. They're
// columns on this table, not a new one: design doc §4.3 has update
// dispatch reuse the §1.5 tables.
//
// LeaseOwner/LeaseUntil are the batch's row lease (sweeper.go, migration
// saas/00006): whoever dispatches the batch, the process that created it
// or the outbox sweeper of any replica, holds it and renews it while it
// works, so no two processes dispatch or roll out the same batch at once.
// LeaseUntil NULL means no one holds it. Never part of the API.
type AssetActionBatch struct {
	ID                string     `gorm:"column:id;primaryKey;size:32"`
	TenantID          string     `gorm:"column:tenant_id;size:32;not null;index"`
	ActionType        string     `gorm:"column:action_type;size:32;not null"`
	ActionParams      string     `gorm:"column:action_params;type:text;not null"`
	RequestedAssetIDs string     `gorm:"column:requested_asset_ids;type:text;not null"`
	RolloutBatchSize  int        `gorm:"column:rollout_batch_size;not null;default:0"`
	RolloutGate       string     `gorm:"column:rollout_gate;size:32;not null;default:''"`
	CreatedAt         time.Time  `gorm:"column:created_at"`
	LeaseOwner        string     `gorm:"column:lease_owner;size:64;not null;default:''"`
	LeaseUntil        *time.Time `gorm:"column:lease_until"`
}

func (AssetActionBatch) TableName() string { return "asset_action_batches" }

// AssetActionItem is the `saas.asset_action_items` table (design doc
// §4.2, §1.5): one row per requested asset_id in a batch.
//
// TenantID isn't in §4.2's sketch. It's carried on every item, alongside
// the batch's own, so that every item query and conditional status update
// can carry tenant_id in its WHERE clause (§4 "Tenant safety"), and so an
// item's sprout_id is never meaningful without its tenant: sprout_id is
// only unique per tenant.
//
// Position is the asset_id's index in the request, so GET returns items
// in request order. SproutID and JID are empty until known. ErrorCode is
// a fixed code (controlplane.ErrorCode or one of sprout_actions.go's own),
// never error text. ExitCode is set only for a completed cmd.run.
//
// DispatchedAt is when the item was claimed for sending (queued ->
// dispatching), on the dispatching saasapi's clock, and is cleared if the
// bus proved the request was never delivered (back to queued). It is set
// on every item that was ever handed to farmer, so a resumed update
// rollout (sweeper.go) can tell which items were sent and measure their
// wave deadline from it. PlannedAtTarget is set on a self_update item
// whose sprout already reported the target version when the rollout was
// planned (planUpdateItems' atTarget): its update job's success is then
// proof enough (judgeUpdateItem). Both from migration saas/00006.
//
// idx_asset_action_items_tenant_status (tenant_id, status), from migration
// saas/00009, serves the count of a tenant's pending items that
// POST .../sprouts/actions checks against its backlog cap (backlog.go).
type AssetActionItem struct {
	BatchID         string                `gorm:"column:batch_id;primaryKey;size:32"`
	AssetID         string                `gorm:"column:asset_id;primaryKey;size:191"`
	TenantID        string                `gorm:"column:tenant_id;size:32;not null;index:idx_asset_action_items_tenant_status,priority:1"`
	Position        int                   `gorm:"column:position;not null"`
	SproutID        string                `gorm:"column:sprout_id;size:253;not null;default:''"`
	JID             string                `gorm:"column:jid;size:64;not null;default:''"`
	Status          AssetActionItemStatus `gorm:"column:status;size:32;not null;index;index:idx_asset_action_items_tenant_status,priority:2"`
	ErrorCode       string                `gorm:"column:error_code;size:64;not null;default:''"`
	ExitCode        *int                  `gorm:"column:exit_code"`
	Attempts        int                   `gorm:"column:attempts;not null;default:0"`
	CreatedAt       time.Time             `gorm:"column:created_at"`
	UpdatedAt       time.Time             `gorm:"column:updated_at"`
	DispatchedAt    *time.Time            `gorm:"column:dispatched_at"`
	PlannedAtTarget bool                  `gorm:"column:planned_at_target;not null;default:false"`
}

func (AssetActionItem) TableName() string { return "asset_action_items" }
