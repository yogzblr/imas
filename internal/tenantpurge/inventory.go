package tenantpurge

// The inventory of a tenant's data (S6 decision 2). Everything a tenant
// owns is in one of the purge lists below, or in a keep list with the
// reason it stays. inventory_test.go checks the lists against the
// schema (every migration and GORM model with a tenant_id column), the
// object key roots and the Valkey key prefixes in the code: adding any of
// those without deciding here fails it.

// FarmerTables are the farmer-schema tables farmer deletes a purged
// tenant's rows from (tenant_id equality), in this order.
var FarmerTables = []string{
	"props",
	"pki_nkeys",
	"pki_revoked_nkeys",
	"pki_cli_admin_keys",
	"pki_sprout_box_keys",
	"sprout_user_jwt",
	"auth_users",
	"auth_cli_box_keys",
	"rbac_roles",
	"rbac_user_roles",
	"rbac_cohorts",
	"job_status",
}

// SaasTables are the saas-schema tables saasapi deletes a purged tenant's
// rows from (tenant_id equality), in this order, when it applies farmer's
// successful purge result. saasapi is the only writer of the saas schema:
// farmer's database user has SELECT on it and nothing more.
var SaasTables = []string{
	"asset_action_items",
	"asset_action_batches",
	"asset_links",
	"enrollment_keys",
	"tenant_update_policy",
}

// KeepTables are the tables that hold something of a tenant that stays,
// keyed "<schema>.<table>", with the reason. The tombstone (S6 decision
// 1): it keeps the tenant ID from ever being reused and the tenant locked
// out.
var KeepTables = map[string]string{
	"saas.tenants":           "the tombstone: the tenant's row stays, status purged, its name and plan cleared, so its ID is never reused",
	"saas.provisioning_jobs": "the tombstone: the record of the tenant's provision, deprovision and purge jobs (IDs, statuses, fixed messages)",
	"farmer.pki_tenants":     "the tombstone: the deleted marker that refuses any later provision or enrolment for the ID, its name replaced by the ID",
	"farmer.job_leases":      "pushall:<tenant_id> is the lease under which every replica re-pushes the tombstone's lock-out; it holds no tenant data and is re-created on demand",
}

// Object store buckets (farmer's configuration names them).
const (
	// BucketRecipes is IMAS_S3_BUCKET: tenant recipes, recipe audit,
	// staged recipes.
	BucketRecipes = "recipes"
	// BucketJobs is IMAS_S3_JOB_BUCKET: job output.
	BucketJobs = "jobs"
	// BucketSproutJWTs is IMAS_S3_SPROUT_JWT_BUCKET: sprout User JWTs,
	// keyed <tenant_id>/<sprout_id>/<jwt_sha256>.jwt.
	BucketSproutJWTs = "sprout_jwts"
)

// ObjectPrefix is one tenant prefix in one bucket.
type ObjectPrefix struct {
	// Category is the purge count's key, e.g. "objects.recipes".
	Category string
	Bucket   string
	Prefix   string
}

// Object key roots: the first key segment, the tenant ID's segment
// following it.
const (
	RootTenants = "tenants/" // tenants/<t>/recipes/, tenants/<t>/recipe-audit/, and any other tenant object
	RootSprouts = "sprouts/" // sprouts/<t>/<sprout>/ staged recipes
	RootJobs    = "jobs/"    // jobs/<t>/<sprout>/<jid>/ job output
)

// PurgeRoots are the object key roots whose <root><tenant_id>/ subtree is
// deleted, by bucket. The sprout JWT bucket has no root: the tenant ID is
// its first segment.
var PurgeRoots = map[string][]string{
	BucketRecipes:    {RootTenants, RootSprouts},
	BucketJobs:       {RootJobs},
	BucketSproutJWTs: {""},
}

// KeepRoots are object key roots that hold something of a tenant that
// stays, or that look like a root and are not per tenant, with the reason.
var KeepRoots = map[string]string{
	"accounts/": "the accounts bucket: the tombstone's locked-out Account JWT (re-signed with nothing but the ID and the lock-out) stays, so a bus node started empty loads the tenant locked out",
}

// ObjectPrefixes returns tenantID's prefixes in every purged bucket, in
// purge order.
func ObjectPrefixes(tenantID string) []ObjectPrefix {
	return []ObjectPrefix{
		{Category: "objects.recipes", Bucket: BucketRecipes, Prefix: RootTenants + tenantID + "/"},
		{Category: "objects.staged_recipes", Bucket: BucketRecipes, Prefix: RootSprouts + tenantID + "/"},
		{Category: "objects.jobs", Bucket: BucketJobs, Prefix: RootJobs + tenantID + "/"},
		{Category: "objects.sprout_jwts", Bucket: BucketSproutJWTs, Prefix: tenantID + "/"},
	}
}

// Valkey key prefixes (internal/heartbeat's).
const (
	ValkeyHeartbeatPrefix = "imas:heartbeat:"
	ValkeyAcceptedPrefix  = "imas:accepted:"
)

// PurgeValkeyPrefixes are the Valkey key prefixes whose keys for the
// tenant are deleted; each key is <prefix>{<tenant_id>:<sprout_id>}.
var PurgeValkeyPrefixes = []string{ValkeyHeartbeatPrefix, ValkeyAcceptedPrefix}

// KeepValkeyPrefixes are the Valkey key prefixes not deleted, with the
// reason.
var KeepValkeyPrefixes = map[string]string{
	"imas:replay:":            "enrolment and refresh replay claims and sealed-message claims: keyed by a hash or a message ID, each with a TTL of minutes, so they expire by themselves",
	"imas:saasapi:ratelimit:": "saasapi's rate-limit buckets: each expires when it would be full again, within seconds to minutes",
}

// ValkeyCategory is the purge count key for a Valkey prefix.
func ValkeyCategory(prefix string) string {
	switch prefix {
	case ValkeyHeartbeatPrefix:
		return "valkey.heartbeat"
	case ValkeyAcceptedPrefix:
		return "valkey.accepted"
	}
	return "valkey.other"
}

// ValkeyPattern is the SCAN pattern matching tenantID's keys under
// prefix: the hash tag's tenant part ends at ':', which no tenant ID
// contains, and a tenant ID holds none of SCAN's glob characters.
func ValkeyPattern(prefix, tenantID string) string {
	return prefix + "{" + tenantID + ":*"
}

// KVPaths are the OpenBao KV v2 secrets holding a tenant's material,
// <tenant_id> standing for the tenant: its payload-encryption keypair
// (internal/pki tenantbox.go, farmer's IMAS_TENANTBOX_OPENBAO_* client),
// one secret per tenant under farmer.openbao.tenantBox.kvMount and
// kvPath. The purge's KV step deletes it whole, every version and its
// metadata (internal/pki PurgeTenantBoxKeys).
var KVPaths = []string{
	"<kvMount>/data/<kvPath>/tenants/<tenant_id>",
}

// Transit: a tenant's two keys, nats-tsign-<tenant_id> and
// nats-tacct-<tenant_id> (internal/pki/natskeys TenantSigningKey and
// TenantAccountKey), are destroyed last (internal/pki DestroyTenantKeys).
