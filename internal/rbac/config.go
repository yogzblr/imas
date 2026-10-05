package rbac

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/taigrr/jety"
)

// ErrDuplicatePubkey is returned when the same pubkey appears under
// multiple roles in the users/pubkeys config sections.
var ErrDuplicatePubkey = errors.New("duplicate pubkey assignment")

// ErrDuplicateUsername is returned when two or more pubkeys share the
// same username in the users config section.
var ErrDuplicateUsername = errors.New("duplicate username")

// RoleStore reads and writes role definitions straight through to PXC
// (see store.go) — it holds no state of its own beyond the tenant it was
// constructed for, so every method call reflects every replica's writes.
//
// tenantID is fixed at construction — see Registry's identical doc comment
// (cohort.go) for the same current-tenant-by-default convention.
type RoleStore struct {
	tenantID string
}

// NewRoleStore returns a RoleStore scoped to the current tenant (see
// tenantID in store.go).
func NewRoleStore() *RoleStore {
	return NewRoleStoreForTenant(tenantID())
}

// NewRoleStoreForTenant returns a RoleStore scoped explicitly to tenantID.
// See Registry.NewRegistryForTenant's doc comment (cohort.go) — same
// workstream E groundwork, not yet wired into any production call site.
func NewRoleStoreForTenant(tenantID string) *RoleStore {
	return &RoleStore{tenantID: tenantID}
}

// Register adds a role to the store, replacing any existing role with
// the same name. Validates the role before registration.
func (rs *RoleStore) Register(r *Role) error {
	if r.TenantID == "" {
		r.TenantID = rs.tenantID
	}
	if err := r.Validate(); err != nil {
		return err
	}
	return upsertRoleRow(roleRowFrom(r))
}

// Get retrieves a role by name.
func (rs *RoleStore) Get(name string) (*Role, error) {
	var row roleRow
	if err := db.Where("tenant_id = ? AND name = ?", rs.tenantID, name).First(&row).Error; err != nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownRole, name)
	}
	return row.toRole(), nil
}

// List returns all role names.
func (rs *RoleStore) List() []string {
	var rows []roleRow
	db.Where("tenant_id = ?", rs.tenantID).Find(&rows)
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.Name)
	}
	return names
}

// BuiltinViewerRole returns the built-in "viewer" role with read-only
// permissions. This role grants view and user_read actions with wildcard
// scope — enough to list sprouts, view jobs/props/cohorts, and call
// whoami, but no write operations (cook, cmd, pki, etc.).
func BuiltinViewerRole() *Role {
	return &Role{
		Name: "viewer",
		Rules: []Rule{
			{Action: ActionView, Scope: "*"},
			{Action: ActionUserRead, Scope: "*"},
		},
	}
}

// BuiltinOperatorRole returns the built-in "operator" role with
// operational permissions. Operators can view everything and perform
// scoped write operations (cook, cmd, test, props, job_admin) but cannot
// manage PKI keys or user accounts, and cannot open a shell: shell is
// granted only by a role that names it (owner decision on J.5, Open
// question 4 in docs/design/imas-payload-encryption-design.md).
func BuiltinOperatorRole() *Role {
	return &Role{
		Name: "operator",
		Rules: []Rule{
			{Action: ActionView, Scope: "*"},
			{Action: ActionCook, Scope: "*"},
			{Action: ActionCmd, Scope: "*"},
			{Action: ActionTest, Scope: "*"},
			{Action: ActionProps, Scope: "*"},
			{Action: ActionJobAdmin, Scope: "*"},
			{Action: ActionUserRead, Scope: "*"},
		},
	}
}

// LoadRolesFromConfig reads the "roles" section from the farmer config
// and returns a populated RoleStore. Returns an empty store if the
// section is missing.
//
// Built-in roles (currently just "viewer") are always registered unless
// the config defines a role with the same name, allowing admins to
// override built-in definitions.
//
// Expected config format:
//
//	roles:
//	  sre-team:
//	    - action: admin
//	  dev-team:
//	    - action: view
//	      scope: "*"
//	    - action: cook
//	      scope: "cohort:staging"
//	    - action: cmd
//	      scope: "cohort:dev"
//	  readonly:
//	    - action: view
//	    - action: user_read
func LoadRolesFromConfig() (*RoleStore, error) {
	store := NewRoleStore()

	// Config is the authoritative snapshot: clear any previously persisted
	// roles for this tenant first, so a role removed from config doesn't
	// linger in PXC across a reload the way it never could in the old
	// in-memory map (each reload built a fresh one from scratch).
	db.Where("tenant_id = ?", store.tenantID).Delete(&roleRow{})

	// Register built-in roles first. Config-defined roles with the same
	// name will override these below.
	builtins := []*Role{BuiltinViewerRole(), BuiltinOperatorRole()}
	for _, b := range builtins {
		_ = store.Register(b) // built-ins are always valid
	}

	raw := jety.GetStringMap("roles")
	if len(raw) == 0 {
		return store, nil
	}

	for name, v := range raw {
		role, err := parseRoleEntry(name, v)
		if err != nil {
			return nil, fmt.Errorf("parsing role %q: %w", name, err)
		}
		if err := store.Register(role); err != nil {
			return nil, fmt.Errorf("registering role %q: %w", name, err)
		}
	}

	return store, nil
}

func parseRoleEntry(name string, raw any) (*Role, error) {
	role := &Role{Name: name}

	rulesRaw, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("role %q: rules must be a list", name)
	}

	for i, ruleRaw := range rulesRaw {
		m, ok := ruleRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("role %q rule %d: must be a map", name, i)
		}

		actionStr, _ := m["action"].(string)
		action, err := ParseAction(strings.TrimSpace(actionStr))
		if err != nil {
			return nil, fmt.Errorf("role %q rule %d: %w", name, i, err)
		}

		scope, _ := m["scope"].(string)
		scope = strings.TrimSpace(scope)
		if scope == "" {
			scope = "*"
		}

		rule := Rule{Action: action, Scope: scope}
		role.Rules = append(role.Rules, rule)
	}

	return role, nil
}

// UserRoleMap reads and writes pubkey -> role/username assignments
// straight through to PXC (see store.go), the same read-through shape as
// RoleStore above.
//
// tenantID is fixed at construction — see RoleStore's identical doc
// comment above.
type UserRoleMap struct {
	tenantID string
}

// NewUserRoleMap returns a UserRoleMap scoped to the current tenant.
func NewUserRoleMap() *UserRoleMap {
	return NewUserRoleMapForTenant(tenantID())
}

// NewUserRoleMapForTenant returns a UserRoleMap scoped explicitly to
// tenantID. See RoleStore.NewRoleStoreForTenant's doc comment — same
// workstream E groundwork.
func NewUserRoleMapForTenant(tenantID string) *UserRoleMap {
	return &UserRoleMap{tenantID: tenantID}
}

// Set assigns a role to a pubkey.
func (m *UserRoleMap) Set(pubkey, roleName string) {
	upsertUserRoleRow(userRoleRow{TenantID: m.tenantID, Pubkey: pubkey, RoleName: roleName, Username: m.Username(pubkey)})
}

// SetUsername assigns a human-readable username to a pubkey.
func (m *UserRoleMap) SetUsername(pubkey, username string) {
	upsertUserRoleRow(userRoleRow{TenantID: m.tenantID, Pubkey: pubkey, RoleName: m.RoleName(pubkey), Username: username})
}

// Delete removes a pubkey from the map. Returns true if the key existed.
func (m *UserRoleMap) Delete(pubkey string) bool {
	res := db.Where("tenant_id = ? AND pubkey = ?", m.tenantID, pubkey).Delete(&userRoleRow{})
	return res.Error == nil && res.RowsAffected > 0
}

// RoleName returns the role name for a pubkey, or empty string if not found.
func (m *UserRoleMap) RoleName(pubkey string) string {
	var row userRoleRow
	if err := db.Where("tenant_id = ? AND pubkey = ?", m.tenantID, pubkey).First(&row).Error; err != nil {
		return ""
	}
	return row.RoleName
}

// Username returns the human-readable username for a pubkey, or empty
// string if no username is configured.
func (m *UserRoleMap) Username(pubkey string) string {
	var row userRoleRow
	if err := db.Where("tenant_id = ? AND pubkey = ?", m.tenantID, pubkey).First(&row).Error; err != nil {
		return ""
	}
	return row.Username
}

// All returns the full map of pubkey → role name.
func (m *UserRoleMap) All() map[string]string {
	var rows []userRoleRow
	db.Where("tenant_id = ?", m.tenantID).Find(&rows)
	result := make(map[string]string, len(rows))
	for _, row := range rows {
		result[row.Pubkey] = row.RoleName
	}
	return result
}

// AllWithUsernames returns a map of pubkey → username for all users
// that have a username configured.
func (m *UserRoleMap) AllWithUsernames() map[string]string {
	var rows []userRoleRow
	db.Where("tenant_id = ? AND username != ''", m.tenantID).Find(&rows)
	result := make(map[string]string, len(rows))
	for _, row := range rows {
		result[row.Pubkey] = row.Username
	}
	return result
}

// LoadUsersFromConfig reads the "users" section from the farmer config.
//
// Supported formats:
//
// Simple format (list of pubkey strings):
//
//	users:
//	  sre-team:
//	    - APUBKEY1...
//	  dev-team:
//	    - APUBKEY2...
//
// Rich format (maps with pubkey + optional username):
//
//	users:
//	  admin:
//	    - pubkey: APUBKEY1...
//	      username: alice
//	    - pubkey: APUBKEY2...
//	      username: bob
//
// Mixed format (both strings and maps in the same list):
//
//	users:
//	  admin:
//	    - APUBKEY1...
//	    - pubkey: APUBKEY2...
//	      username: bob
//
// Also reads legacy format:
//
//	pubkeys:
//	  admin:
//	    - APUBKEY1...
//
// Legacy pubkeys.admin maps to a built-in "admin" role if no explicit
// role definition exists (backward compatibility).
func LoadUsersFromConfig() *UserRoleMap {
	m := NewUserRoleMap()

	// Config is the authoritative snapshot for this tenant; see
	// LoadRolesFromConfig's identical clear-before-reload comment.
	db.Where("tenant_id = ?", m.tenantID).Delete(&userRoleRow{})

	// New format: users.<role> = [pubkeys or {pubkey, username} maps...]
	usersMap := jety.GetStringMap("users")
	for roleName, v := range usersMap {
		entries := parseUserEntries(v)
		for _, e := range entries {
			m.Set(e.Pubkey, roleName)
			if e.Username != "" {
				m.SetUsername(e.Pubkey, e.Username)
			}
		}
	}

	// Legacy format: pubkeys.<role> = [pubkeys...]
	pubkeysMap := jety.GetStringMap("pubkeys")
	for roleName, v := range pubkeysMap {
		keys := parseStringSlice(v)
		for _, k := range keys {
			// Don't override if already set from users section.
			if m.RoleName(k) == "" {
				m.Set(k, roleName)
			}
		}
	}

	return m
}

// userEntry holds a parsed user entry from config.
type userEntry struct {
	Pubkey   string
	Username string
}

// parseUserEntries parses a list that may contain plain pubkey strings
// or maps with {pubkey, username} fields.
func parseUserEntries(v any) []userEntry {
	if v == nil {
		return nil
	}

	items, ok := v.([]any)
	if !ok {
		// Single string
		if s, ok := v.(string); ok {
			return []userEntry{{Pubkey: s}}
		}
		return nil
	}

	var entries []userEntry
	for _, item := range items {
		switch val := item.(type) {
		case string:
			entries = append(entries, userEntry{Pubkey: val})
		case map[string]any:
			pk, _ := val["pubkey"].(string)
			name, _ := val["username"].(string)
			if pk != "" {
				entries = append(entries, userEntry{Pubkey: pk, Username: name})
			}
		}
	}
	return entries
}

// ValidateUserUniqueness checks the users and pubkeys config sections for
// pubkeys that appear under more than one role. Returns an error listing
// every duplicate pubkey and the roles it was assigned to. This catches
// misconfigurations that would silently overwrite role assignments.
func ValidateUserUniqueness() error {
	// Collect all pubkey → []role mappings from both config sections.
	seen := make(map[string][]string) // pubkey → list of role names

	usersMap := jety.GetStringMap("users")
	for roleName, v := range usersMap {
		entries := parseUserEntries(v)
		for _, e := range entries {
			seen[e.Pubkey] = append(seen[e.Pubkey], "users."+roleName)
		}
	}

	pubkeysMap := jety.GetStringMap("pubkeys")
	for roleName, v := range pubkeysMap {
		keys := parseStringSlice(v)
		for _, k := range keys {
			seen[k] = append(seen[k], "pubkeys."+roleName)
		}
	}

	// Find duplicates.
	var dupes []string
	for pubkey, roles := range seen {
		if len(roles) > 1 {
			sort.Strings(roles)
			// Truncate long pubkeys for readability.
			display := pubkey
			if len(display) > 16 {
				display = display[:16] + "..."
			}
			dupes = append(dupes, fmt.Sprintf("  %s → [%s]", display, strings.Join(roles, ", ")))
		}
	}
	if len(dupes) == 0 {
		return nil
	}

	sort.Strings(dupes)
	return fmt.Errorf("%w: the following pubkeys are assigned to multiple roles:\n%s",
		ErrDuplicatePubkey, strings.Join(dupes, "\n"))
}

// ValidateUsernameUniqueness checks the "users" config section for
// entries where two or more pubkeys share the same username. Duplicate
// usernames would make audit logs ambiguous and prevent reliable
// identification. Returns an error listing every conflicting username and
// the pubkeys that claim it. Empty/missing usernames are ignored.
func ValidateUsernameUniqueness() error {
	seen := make(map[string][]string) // username → list of pubkeys

	usersMap := jety.GetStringMap("users")
	for _, v := range usersMap {
		entries := parseUserEntries(v)
		for _, e := range entries {
			if e.Username == "" {
				continue
			}
			seen[e.Username] = append(seen[e.Username], e.Pubkey)
		}
	}

	var dupes []string
	for username, pubkeys := range seen {
		if len(pubkeys) > 1 {
			sort.Strings(pubkeys)
			// Truncate pubkeys for readability.
			truncated := make([]string, len(pubkeys))
			for i, pk := range pubkeys {
				if len(pk) > 16 {
					truncated[i] = pk[:16] + "..."
				} else {
					truncated[i] = pk
				}
			}
			dupes = append(dupes, fmt.Sprintf("  %q → [%s]", username, strings.Join(truncated, ", ")))
		}
	}
	if len(dupes) == 0 {
		return nil
	}

	sort.Strings(dupes)
	return fmt.Errorf("%w: the following usernames are assigned to multiple pubkeys:\n%s",
		ErrDuplicateUsername, strings.Join(dupes, "\n"))
}

// LoadCohortsFromConfig reads the "cohorts" section from the farmer config
// (via jety) and returns a populated Registry. It does not fail on an
// empty or missing cohorts section — it simply returns an empty registry.
func LoadCohortsFromConfig() (*Registry, error) {
	registry := NewRegistry()

	// Config is the authoritative snapshot for this tenant; see
	// LoadRolesFromConfig's identical clear-before-reload comment. The
	// membership cache is separate from stored definitions (see cohort.go)
	// and is left untouched here.
	db.Where("tenant_id = ?", registry.tenantID).Delete(&cohortRow{})

	raw := jety.GetStringMap("cohorts")
	if len(raw) == 0 {
		return registry, nil
	}

	for name, v := range raw {
		cohort, err := parseCohortEntry(name, v)
		if err != nil {
			return nil, fmt.Errorf("parsing cohort %q: %w", name, err)
		}
		if err := registry.Register(cohort); err != nil {
			return nil, fmt.Errorf("registering cohort %q: %w", name, err)
		}
	}

	return registry, nil
}

func parseCohortEntry(name string, raw any) (*Cohort, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: cohort %q value is not a map", ErrInvalidCohort, name)
	}

	cohort := &Cohort{Name: name}

	typeStr, _ := m["type"].(string)
	switch CohortType(typeStr) {
	case CohortTypeStatic:
		cohort.Type = CohortTypeStatic
		cohort.Members = parseStringSlice(m["members"])
	case CohortTypeDynamic:
		cohort.Type = CohortTypeDynamic
		match, err := parseDynamicMatch(m["match"])
		if err != nil {
			return nil, fmt.Errorf("cohort %q: %w", name, err)
		}
		cohort.Match = match
	case CohortTypeCompound:
		cohort.Type = CohortTypeCompound
		compound, err := parseCompoundExpr(m["compound"])
		if err != nil {
			return nil, fmt.Errorf("cohort %q: %w", name, err)
		}
		cohort.Compound = compound
	default:
		return nil, fmt.Errorf("%w: unknown type %q for cohort %q", ErrInvalidCohort, typeStr, name)
	}

	return cohort, nil
}

func parseStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return s
	default:
		return nil
	}
}

func parseDynamicMatch(v any) (*DynamicMatch, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: dynamic match is nil", ErrInvalidCohort)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: match is not a map", ErrInvalidCohort)
	}
	propName, _ := m["prop_name"].(string)
	propValue, _ := m["prop_value"].(string)
	if propName == "" {
		return nil, fmt.Errorf("%w: match requires prop_name", ErrInvalidCohort)
	}
	return &DynamicMatch{
		PropName:  propName,
		PropValue: propValue,
	}, nil
}

func parseCompoundExpr(v any) (*CompoundExpr, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: compound expression is nil", ErrInvalidCohort)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: compound is not a map", ErrInvalidCohort)
	}
	opStr, _ := m["operator"].(string)
	op := Operator(opStr)
	if err := validateOperator(op); err != nil {
		return nil, err
	}
	operands := parseStringSlice(m["operands"])
	if len(operands) < 2 {
		return nil, fmt.Errorf("%w", ErrMissingOperands)
	}
	return &CompoundExpr{
		Operator: op,
		Operands: operands,
	}, nil
}
