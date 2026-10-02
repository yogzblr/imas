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
)

// Tenant is the `saas.tenants` table (design doc §4.2).
type Tenant struct {
	ID        string       `gorm:"column:id;primaryKey;size:32" json:"tenant_id"`
	Name      string       `gorm:"column:name;size:255;not null" json:"name"`
	Status    TenantStatus `gorm:"column:status;size:32;not null;index" json:"status"`
	PlanID    string       `gorm:"column:plan_id;size:64" json:"plan_id,omitempty"`
	CreatedAt time.Time    `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time    `gorm:"column:updated_at" json:"updated_at"`
}

func (Tenant) TableName() string { return "tenants" }

// ProvisioningJobType distinguishes tenant provisioning from deprovisioning
// (offboarding) outbox rows.
type ProvisioningJobType string

const (
	ProvisioningJobProvision   ProvisioningJobType = "provision"
	ProvisioningJobDeprovision ProvisioningJobType = "deprovision"
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
// (§2.2); Attempts counts dispatches, for a future re-dispatch sweeper to
// bound on (see docs/design/imas-internal-api-account.md).
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
	Warning   string    `gorm:"column:warning;type:text" json:"warning,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (ProvisioningJob) TableName() string { return "provisioning_jobs" }

// EnrollmentKey is the `saas.enrollment_keys` table (design doc §4.2,
// §3.1). Only key_id is ever stored in plaintext; the secret half of the
// issued token is stored solely as its SHA-256 hash (KeyHash) — see
// idgen.go/enrollment_keys.go, both explicitly flagged for security
// review per the task brief.
type EnrollmentKey struct {
	// KeyID is the public, indexed lookup half of the {key_id}.{secret}
	// token (§3.1) — safe to log and store in plaintext.
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
// only place CloudXP's asset_id enters the system.
//
// Uniqueness:
//   - (tenant_id, sprout_id) is UNIQUE — one sprout carries at most one
//     asset_id. This is per tenant, not global as §4.2's sketch has it,
//     because farmer's pki_nkeys only keys a sprout_id per tenant: two
//     tenants may each have a sprout named "web-01", and both must be
//     able to link it.
//   - asset_id is globally UNIQUE — CloudXP generates it externally and
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
// §1.8): CloudXP's own published catalog of sprout versions. It is
// deliberately not upstream imas's GitHub release feed — a version only
// becomes approvable by a tenant once CloudXP has published it here.
//
// The catalog is global, not per tenant: every tenant chooses from the
// same list, and tenant_update_policy records which entry each tenant
// has approved. Nothing in this package writes it; see fleet_updates.go.
// Rows are written by cmd/fleetreleaser, the only holder of sign
// capability on the imas-fleet-signing Transit key (§2.5).
type FleetVersion struct {
	ID      string `gorm:"column:id;primaryKey;size:32" json:"-"`
	Version string `gorm:"column:version;size:64;not null;uniqueIndex" json:"version"`
	// ArtifactURL is where the release pipeline published the sprout
	// binary, for the dispatch path (fleet_update_dispatch.go) to hand to
	// a sprout.
	// Not part of GET /versions' response; see fleetVersionItem.
	ArtifactURL    string    `gorm:"column:artifact_url;size:2048;not null" json:"-"`
	ChecksumSHA256 string    `gorm:"column:checksum_sha256;size:64;not null" json:"checksum_sha256"`
	ReleasedAt     time.Time `gorm:"column:released_at;not null;index" json:"released_at"`
	Notes          string    `gorm:"column:notes;type:text" json:"notes,omitempty"`
	// Signature is cmd/fleetreleaser's Ed25519 signature over the
	// fleetsign.Manifest canonical message
	// version|os|arch|file_name|checksum_sha256|min_sprout_version, in
	// fleetsign.EncodeSignature's "v<key version>:<base64>" format (§2.5).
	// This table can't hold os, arch, file_name or min_sprout_version yet
	// (FU.3), so no row verifies and dispatch refuses them all. A row written before this
	// column existed gets "" from AutoMigrate's default, and "" is always
	// refused for dispatch — by saasapi here, by farmer, and by the
	// sprout — never treated as checksum-only trust. Not part of GET
	// /versions' response.
	Signature string `gorm:"column:signature;size:128;not null;default:''" json:"-"`
}

func (FleetVersion) TableName() string { return "fleet_versions" }

// TenantUpdatePolicy is the `saas.tenant_update_policy` table (design doc
// §4.3, §1.8): one row per tenant, keyed by tenant_id alone since it holds
// no sprout-level state. A tenant without a row has the default policy —
// no approved version, auto_update off — so no sprout of theirs is ever
// updated until they explicitly approve a version.
//
// ApprovedVersion, when set, names a FleetVersion.Version. The rollout
// window is a pair of absolute UTC instants, both set or both NULL.
type TenantUpdatePolicy struct {
	TenantID           string     `gorm:"column:tenant_id;primaryKey;size:32" json:"tenant_id"`
	ApprovedVersion    *string    `gorm:"column:approved_version;size:64" json:"approved_version"`
	AutoUpdate         bool       `gorm:"column:auto_update;not null;default:false" json:"auto_update"`
	RolloutWindowStart *time.Time `gorm:"column:rollout_window_start" json:"rollout_window_start"`
	RolloutWindowEnd   *time.Time `gorm:"column:rollout_window_end" json:"rollout_window_end"`
	UpdatedAt          time.Time  `gorm:"column:updated_at" json:"updated_at"`
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
// dispatched (see sprout_actions.go's translateAction), kept so a future
// outbox sweeper can re-send a queued item unchanged. It holds the command
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
type AssetActionBatch struct {
	ID                string    `gorm:"column:id;primaryKey;size:32"`
	TenantID          string    `gorm:"column:tenant_id;size:32;not null;index"`
	ActionType        string    `gorm:"column:action_type;size:32;not null"`
	ActionParams      string    `gorm:"column:action_params;type:text;not null"`
	RequestedAssetIDs string    `gorm:"column:requested_asset_ids;type:text;not null"`
	RolloutBatchSize  int       `gorm:"column:rollout_batch_size;not null;default:0"`
	RolloutGate       string    `gorm:"column:rollout_gate;size:32;not null;default:''"`
	CreatedAt         time.Time `gorm:"column:created_at"`
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
type AssetActionItem struct {
	BatchID   string                `gorm:"column:batch_id;primaryKey;size:32"`
	AssetID   string                `gorm:"column:asset_id;primaryKey;size:191"`
	TenantID  string                `gorm:"column:tenant_id;size:32;not null"`
	Position  int                   `gorm:"column:position;not null"`
	SproutID  string                `gorm:"column:sprout_id;size:253;not null;default:''"`
	JID       string                `gorm:"column:jid;size:64;not null;default:''"`
	Status    AssetActionItemStatus `gorm:"column:status;size:32;not null"`
	ErrorCode string                `gorm:"column:error_code;size:64;not null;default:''"`
	ExitCode  *int                  `gorm:"column:exit_code"`
	Attempts  int                   `gorm:"column:attempts;not null;default:0"`
	CreatedAt time.Time             `gorm:"column:created_at"`
	UpdatedAt time.Time             `gorm:"column:updated_at"`
}

func (AssetActionItem) TableName() string { return "asset_action_items" }
