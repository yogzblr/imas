package rbac

// PXC-backed storage for role, user, and cohort *definitions*.
//
// Previously RoleStore/UserRoleMap/Registry held these purely as
// process-local maps, populated once at startup from the farmer YAML
// config and never written again at runtime except through Registry's own
// membership cache. Every farmer replica read its own config file
// independently, so in principle this was already consistent as long as
// every replica ran with the same config — but any config write path
// (AddUser/RemoveUser in internal/auth, or a future admin API) would only
// ever land on whichever replica handled the request. This file makes
// role/user/cohort *definitions* read-through against the shared `farmer`
// schema in PXC instead, so every replica agrees on the current policy
// regardless of which replica last wrote it.
//
// This does NOT touch Registry's separate, explicitly-refreshed cohort
// *membership* cache (cohort.go's cache field, fed by Refresh/RefreshAll):
// that's a bounded, timer-driven performance cache over a computed result
// (which sprouts currently match a cohort), not a cache of stored
// definitions, and every refresh already recomputes it from the current
// (now PXC-backed) cohort definitions and the current (already
// PXC-backed, see internal/props) prop values.
//
// tenant_id scoping (workstream A.1, FLAG FOR SECURITY REVIEW): every
// query here includes tenant_id in the same WHERE clause as the row's own
// key, following the same tenantID() seam as internal/props/store.go.

import (
	"encoding/json"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/config"
)

// roleRow is the `rbac_roles` table in the farmer schema. Rules is stored
// as JSON since a role's rule list has no fixed arity.
type roleRow struct {
	TenantID string `gorm:"column:tenant_id;primaryKey;size:191"`
	Name     string `gorm:"column:name;primaryKey;size:191"`
	Rules    string `gorm:"column:rules;type:text"`
}

func (roleRow) TableName() string { return "rbac_roles" }

// userRoleRow is the `rbac_user_roles` table: pubkey -> role assignment
// plus an optional display username.
type userRoleRow struct {
	TenantID string `gorm:"column:tenant_id;primaryKey;size:191"`
	Pubkey   string `gorm:"column:pubkey;primaryKey;size:191"`
	RoleName string `gorm:"column:role_name;size:191;not null"`
	Username string `gorm:"column:username;size:191"`
}

func (userRoleRow) TableName() string { return "rbac_user_roles" }

// cohortRow is the `rbac_cohorts` table. Members/Match/Compound are
// mutually-exclusive-by-Type payloads, stored as JSON for the same reason
// as roleRow.Rules.
type cohortRow struct {
	TenantID string `gorm:"column:tenant_id;primaryKey;size:191"`
	Name     string `gorm:"column:name;primaryKey;size:191"`
	Type     string `gorm:"column:type;size:32;not null"`
	Members  string `gorm:"column:members;type:text"`
	Match    string `gorm:"column:match_rule;type:text"`
	Compound string `gorm:"column:compound;type:text"`
}

func (cohortRow) TableName() string { return "rbac_cohorts" }

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (see
// cmd/farmer/main.go and internal/pxc).
func Models() []any { return []any{&roleRow{}, &userRoleRow{}, &cohortRow{}} }

// db is the shared farmer-schema GORM handle. Nil until SetDB is called.
var db *gorm.DB

// SetDB installs the GORM handle this package reads and writes through.
// Call once at startup, after internal/pxc.OpenDB.
func SetDB(d *gorm.DB) { db = d }

// tenantID resolves the current tenant scope for every query in this
// package. See internal/props/store.go's doc comment for why this isn't
// yet a per-request value.
func tenantID() string {
	if config.FarmerOrganization != "" {
		return config.FarmerOrganization
	}
	return "default"
}

// roleRowFrom uses r.TenantID when set, falling back to the package's
// current-tenant seam otherwise — see Role's TenantID doc comment
// (role.go) for why a Role built directly in Go (e.g. the builtin roles
// below) normally leaves TenantID unset and picks it up here.
func roleRowFrom(r *Role) roleRow {
	tid := r.TenantID
	if tid == "" {
		tid = tenantID()
	}
	rules, _ := json.Marshal(r.Rules)
	return roleRow{TenantID: tid, Name: r.Name, Rules: string(rules)}
}

func (row roleRow) toRole() *Role {
	r := &Role{Name: row.Name, TenantID: row.TenantID}
	json.Unmarshal([]byte(row.Rules), &r.Rules)
	return r
}

// cohortRowFrom uses c.TenantID when set, falling back to the package's
// current-tenant seam otherwise — see cohortRowFrom's sibling, roleRowFrom.
func cohortRowFrom(c *Cohort) cohortRow {
	tid := c.TenantID
	if tid == "" {
		tid = tenantID()
	}
	row := cohortRow{TenantID: tid, Name: c.Name, Type: string(c.Type)}
	if c.Members != nil {
		b, _ := json.Marshal(c.Members)
		row.Members = string(b)
	}
	if c.Match != nil {
		b, _ := json.Marshal(c.Match)
		row.Match = string(b)
	}
	if c.Compound != nil {
		b, _ := json.Marshal(c.Compound)
		row.Compound = string(b)
	}
	return row
}

func (row cohortRow) toCohort() *Cohort {
	c := &Cohort{Name: row.Name, Type: CohortType(row.Type), TenantID: row.TenantID}
	if row.Members != "" {
		json.Unmarshal([]byte(row.Members), &c.Members)
	}
	if row.Match != "" {
		c.Match = &DynamicMatch{}
		json.Unmarshal([]byte(row.Match), c.Match)
	}
	if row.Compound != "" {
		c.Compound = &CompoundExpr{}
		json.Unmarshal([]byte(row.Compound), c.Compound)
	}
	return c
}

func upsertRoleRow(row roleRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"rules"}),
	}).Create(&row).Error
}

func upsertUserRoleRow(row userRoleRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "pubkey"}},
		DoUpdates: clause.AssignmentColumns([]string{"role_name", "username"}),
	}).Create(&row).Error
}

func upsertCohortRow(row cohortRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"type", "members", "match_rule", "compound"}),
	}).Create(&row).Error
}
