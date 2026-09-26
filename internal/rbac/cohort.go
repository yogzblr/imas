// Package rbac provides role-based access control for imas, including
// cohort definitions that group sprouts by static membership, dynamic
// property matching, or boolean combinations of other cohorts.
package rbac

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/props"
)

// CohortType distinguishes how a cohort's membership is determined.
type CohortType string

const (
	// CohortTypeStatic contains an explicit list of sprout IDs.
	CohortTypeStatic CohortType = "static"
	// CohortTypeDynamic matches sprouts whose props satisfy a condition.
	CohortTypeDynamic CohortType = "dynamic"
	// CohortTypeCompound combines other cohorts with boolean logic.
	CohortTypeCompound CohortType = "compound"
)

// Operator defines boolean combinators for compound cohorts.
type Operator string

const (
	// OperatorAND returns the intersection of its operands.
	OperatorAND Operator = "AND"
	// OperatorOR returns the union of its operands.
	OperatorOR Operator = "OR"
	// OperatorEXCEPT returns Left minus Right.
	OperatorEXCEPT Operator = "EXCEPT"
)

// MaxNestingDepth limits how deep compound cohort resolution can recurse.
// This prevents runaway resolution in deeply nested configurations.
const MaxNestingDepth = 16

var (
	ErrCohortNotFound    = errors.New("cohort not found")
	ErrCircularReference = errors.New("circular cohort reference detected")
	ErrMaxDepthExceeded  = errors.New("maximum cohort nesting depth exceeded")
	ErrInvalidCohort     = errors.New("invalid cohort definition")
	ErrInvalidOperator   = errors.New("invalid compound operator")
	ErrMissingOperands   = errors.New("compound cohort requires at least two operands")
	ErrSelfReference     = errors.New("cohort references itself")
)

// DynamicMatch describes a property-based membership rule.
// A sprout is a member if its property named PropName equals PropValue.
type DynamicMatch struct {
	PropName  string `json:"propName" yaml:"prop_name"`
	PropValue string `json:"propValue" yaml:"prop_value"`
}

// CompoundExpr describes a boolean combination of named cohorts.
type CompoundExpr struct {
	Operator Operator `json:"operator" yaml:"operator"`
	Operands []string `json:"operands" yaml:"operands"`
}

// Cohort is the primary unit of sprout grouping in imas RBAC.
//
// TenantID identifies which tenant this cohort belongs to — see Role's
// TenantID doc comment (role.go) for the same zero-value-means-"current
// tenant" convention and its FLAG FOR SECURITY REVIEW caveat.
type Cohort struct {
	Name     string        `json:"name" yaml:"name"`
	Type     CohortType    `json:"type" yaml:"type"`
	Members  []string      `json:"members,omitempty" yaml:"members,omitempty"`
	Match    *DynamicMatch `json:"match,omitempty" yaml:"match,omitempty"`
	Compound *CompoundExpr `json:"compound,omitempty" yaml:"compound,omitempty"`
	TenantID string        `json:"tenantId,omitempty" yaml:"-"`
}

// Validate checks that the cohort definition is internally consistent.
func (c *Cohort) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidCohort)
	}
	switch c.Type {
	case CohortTypeStatic:
		// Members list may be empty (no sprouts yet).
		return nil
	case CohortTypeDynamic:
		if c.Match == nil {
			return fmt.Errorf("%w: dynamic cohort %q requires a match rule", ErrInvalidCohort, c.Name)
		}
		if c.Match.PropName == "" {
			return fmt.Errorf("%w: dynamic cohort %q match requires prop_name", ErrInvalidCohort, c.Name)
		}
		return nil
	case CohortTypeCompound:
		if c.Compound == nil {
			return fmt.Errorf("%w: compound cohort %q requires a compound expression", ErrInvalidCohort, c.Name)
		}
		if err := validateOperator(c.Compound.Operator); err != nil {
			return fmt.Errorf("%w: cohort %q: %w", ErrInvalidCohort, c.Name, err)
		}
		if len(c.Compound.Operands) < 2 {
			return fmt.Errorf("%w: cohort %q", ErrMissingOperands, c.Name)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown type %q for cohort %q", ErrInvalidCohort, c.Type, c.Name)
	}
}

func validateOperator(op Operator) error {
	switch op {
	case OperatorAND, OperatorOR, OperatorEXCEPT:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperator, op)
	}
}

// CachedMembership holds the resolved members and last-refreshed time for a cohort.
type CachedMembership struct {
	Members       []string  `json:"members"`
	LastRefreshed time.Time `json:"lastRefreshed"`
}

// RefreshResult describes the outcome of refreshing a single cohort.
type RefreshResult struct {
	Name          string    `json:"name"`
	Members       []string  `json:"members"`
	LastRefreshed time.Time `json:"lastRefreshed"`
}

// Registry resolves membership queries against cohort *definitions* held
// in PXC (see store.go) — read-through, no local map of definitions. It
// still holds its own explicitly-refreshed membership cache (below), which
// is a distinct, bounded, timer-driven performance feature rather than a
// cache of the definitions themselves; see store.go's doc comment for why
// the two aren't the same "in-memory cache" the PXC migration targets.
//
// tenantID is fixed at construction (NewRegistry/NewRegistryForTenant) and
// used for every query this Registry issues — see store.go's tenantID()
// doc comment for why a Registry built via the bare NewRegistry() resolves
// to "the current tenant" rather than a per-request value.
type Registry struct {
	mu       sync.RWMutex
	cache    map[string]*CachedMembership
	tenantID string
}

// NewRegistry creates a cohort registry scoped to the current tenant (see
// tenantID in store.go).
func NewRegistry() *Registry {
	return NewRegistryForTenant(tenantID())
}

// NewRegistryForTenant creates a cohort registry scoped explicitly to
// tenantID, independent of the package's "current tenant" seam. Workstream
// E groundwork: nothing in this repo constructs one of these yet (cohort
// loading is still wired through the current-tenant path — see
// LoadCohortsFromConfig in config.go), but real per-request/per-tenant
// dispatch needs a Registry that doesn't implicitly follow whatever
// config.FarmerOrganization happens to be at call time.
func NewRegistryForTenant(tenantID string) *Registry {
	return &Registry{
		cache:    make(map[string]*CachedMembership),
		tenantID: tenantID,
	}
}

// getCohort reads a single cohort definition from PXC, scoped to tenantID.
func getCohort(tenantID, name string) (*Cohort, error) {
	var row cohortRow
	if err := db.Where("tenant_id = ? AND name = ?", tenantID, name).First(&row).Error; err != nil {
		return nil, fmt.Errorf("%w: %q", ErrCohortNotFound, name)
	}
	return row.toCohort(), nil
}

// listCohorts reads every cohort definition for tenantID from PXC.
func listCohorts(tenantID string) map[string]*Cohort {
	var rows []cohortRow
	db.Where("tenant_id = ?", tenantID).Find(&rows)
	result := make(map[string]*Cohort, len(rows))
	for _, row := range rows {
		result[row.Name] = row.toCohort()
	}
	return result
}

// Register adds a cohort to the registry, replacing any existing cohort
// with the same name. It validates the cohort before registration and
// checks for direct self-references.
func (r *Registry) Register(c *Cohort) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Type == CohortTypeCompound {
		for _, op := range c.Compound.Operands {
			if op == c.Name {
				return fmt.Errorf("%w: cohort %q lists itself as an operand", ErrSelfReference, c.Name)
			}
		}
	}
	if c.TenantID == "" {
		c.TenantID = r.tenantID
	}
	if err := upsertCohortRow(cohortRowFrom(c)); err != nil {
		return err
	}
	// Invalidate the membership cache for this cohort since its definition
	// changed.
	r.mu.Lock()
	delete(r.cache, c.Name)
	r.mu.Unlock()
	return nil
}

// ValidateReferences checks that all compound cohort operands reference
// cohorts that exist in the registry, and that no reference chains exceed
// MaxNestingDepth. Call after all cohorts are registered.
// Returns the first error encountered.
func (r *Registry) ValidateReferences() error {
	errs := r.ValidateReferencesAll()
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// ValidateReferencesAll checks all compound cohort references and returns
// every validation error found (missing operands, circular references,
// exceeded nesting depth). Returns nil if all references are valid.
func (r *Registry) ValidateReferencesAll() []error {
	cohorts := listCohorts(r.tenantID)
	var errs []error
	for name, c := range cohorts {
		if c.Type != CohortTypeCompound {
			continue
		}
		for _, op := range c.Compound.Operands {
			if _, ok := cohorts[op]; !ok {
				errs = append(errs, fmt.Errorf("%w: cohort %q references unknown operand %q", ErrCohortNotFound, name, op))
			}
		}
	}
	// Check depth of every compound cohort.
	for name, c := range cohorts {
		if c.Type != CohortTypeCompound {
			continue
		}
		depth, err := computeDepth(cohorts, name, make(map[string]bool))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if depth > MaxNestingDepth {
			errs = append(errs, fmt.Errorf("%w: cohort %q has depth %d", ErrMaxDepthExceeded, name, depth))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// computeDepth returns the maximum nesting depth for a cohort.
// Static and dynamic cohorts have depth 0. Compound cohorts have
// 1 + max(operand depths).
func computeDepth(cohorts map[string]*Cohort, name string, visited map[string]bool) (int, error) {
	if visited[name] {
		return 0, fmt.Errorf("%w: %q", ErrCircularReference, name)
	}
	c, ok := cohorts[name]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrCohortNotFound, name)
	}
	if c.Type != CohortTypeCompound {
		return 0, nil
	}
	visited[name] = true
	maxChild := 0
	for _, op := range c.Compound.Operands {
		d, err := computeDepth(cohorts, op, visited)
		if err != nil {
			return 0, err
		}
		if d > maxChild {
			maxChild = d
		}
	}
	delete(visited, name)
	return 1 + maxChild, nil
}

// Get returns a cohort by name.
func (r *Registry) Get(name string) (*Cohort, error) {
	return getCohort(r.tenantID, name)
}

// List returns the names of all registered cohorts.
func (r *Registry) List() []string {
	cohorts := listCohorts(r.tenantID)
	names := make([]string, 0, len(cohorts))
	for name := range cohorts {
		names = append(names, name)
	}
	return names
}

// GetCachedMembership returns the cached membership for a cohort, if available.
func (r *Registry) GetCachedMembership(name string) (*CachedMembership, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cm, ok := r.cache[name]
	return cm, ok
}

// Refresh re-evaluates a named cohort against the current set of sprout IDs
// and caches the resolved membership with a timestamp. Returns the refresh result.
func (r *Registry) Refresh(name string, allSproutIDs []string) (*RefreshResult, error) {
	if _, err := getCohort(r.tenantID, name); err != nil {
		return nil, fmt.Errorf("%w: %q", ErrCohortNotFound, name)
	}

	members, err := r.Resolve(name, allSproutIDs)
	if err != nil {
		return nil, fmt.Errorf("refreshing cohort %q: %w", name, err)
	}

	memberList := make([]string, 0, len(members))
	for id := range members {
		memberList = append(memberList, id)
	}
	sort.Strings(memberList)

	now := time.Now().UTC()
	r.mu.Lock()
	r.cache[name] = &CachedMembership{
		Members:       memberList,
		LastRefreshed: now,
	}
	r.mu.Unlock()

	return &RefreshResult{
		Name:          name,
		Members:       memberList,
		LastRefreshed: now,
	}, nil
}

// RefreshAll re-evaluates all registered cohorts and caches their membership.
func (r *Registry) RefreshAll(allSproutIDs []string) ([]RefreshResult, error) {
	names := r.List()
	sort.Strings(names)

	results := make([]RefreshResult, 0, len(names))
	var firstErr error

	for _, name := range names {
		result, err := r.Refresh(name, allSproutIDs)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		results = append(results, *result)
	}

	return results, firstErr
}

// Resolve evaluates a named cohort and returns the set of sprout IDs
// that belong to it. allSproutIDs must contain every known sprout ID
// (needed to evaluate dynamic cohorts). It detects circular references
// and enforces MaxNestingDepth.
func (r *Registry) Resolve(name string, allSproutIDs []string) (map[string]bool, error) {
	visited := make(map[string]bool)
	return r.resolve(name, allSproutIDs, visited, 0)
}

func (r *Registry) resolve(name string, allSproutIDs []string, visited map[string]bool, depth int) (map[string]bool, error) {
	if depth > MaxNestingDepth {
		return nil, fmt.Errorf("%w: resolving %q at depth %d", ErrMaxDepthExceeded, name, depth)
	}
	if visited[name] {
		return nil, fmt.Errorf("%w: %q", ErrCircularReference, name)
	}
	visited[name] = true

	c, err := getCohort(r.tenantID, name)
	if err != nil {
		return nil, err
	}

	switch c.Type {
	case CohortTypeStatic:
		return resolveStatic(c), nil
	case CohortTypeDynamic:
		return resolveDynamic(r.tenantID, c, allSproutIDs), nil
	case CohortTypeCompound:
		return r.resolveCompound(c, allSproutIDs, visited, depth)
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidCohort, c.Type)
	}
}

func resolveStatic(c *Cohort) map[string]bool {
	result := make(map[string]bool, len(c.Members))
	for _, id := range c.Members {
		result[id] = true
	}
	return result
}

// resolveDynamic evaluates a dynamic cohort's membership by reading each
// candidate sprout's properties within tenantID — the calling Registry's
// own tenant (see Registry.tenantID), not props' package-global seam. A
// Registry explicitly constructed for tenant A must never resolve
// membership against tenant B's (or the legacy tenant's) prop values; see
// docs/design/imas-tenant-context-threading.md.
func resolveDynamic(tenantID string, c *Cohort, allSproutIDs []string) map[string]bool {
	result := make(map[string]bool)
	for _, sproutID := range allSproutIDs {
		getProp := props.GetStringPropFuncForTenant(tenantID, sproutID)
		val := getProp(c.Match.PropName)
		if matchesPropValue(val, c.Match.PropValue) {
			result[sproutID] = true
		}
	}
	return result
}

// matchesPropValue checks if a sprout's property value matches the expected value.
// It supports exact match and glob-style prefix/suffix wildcards.
func matchesPropValue(actual, expected string) bool {
	if expected == "*" {
		return actual != ""
	}
	if strings.HasPrefix(expected, "*") && strings.HasSuffix(expected, "*") {
		return strings.Contains(actual, expected[1:len(expected)-1])
	}
	if strings.HasPrefix(expected, "*") {
		return strings.HasSuffix(actual, expected[1:])
	}
	if strings.HasSuffix(expected, "*") {
		return strings.HasPrefix(actual, expected[:len(expected)-1])
	}
	return actual == expected
}

func (r *Registry) resolveCompound(c *Cohort, allSproutIDs []string, visited map[string]bool, depth int) (map[string]bool, error) {
	if len(c.Compound.Operands) < 2 {
		return nil, fmt.Errorf("%w: cohort %q", ErrMissingOperands, c.Name)
	}

	// Resolve first operand.
	// Copy visited map for each operand to allow shared references (but
	// still detect direct cycles through our own name).
	result, err := r.resolve(c.Compound.Operands[0], allSproutIDs, copyVisited(visited), depth+1)
	if err != nil {
		return nil, fmt.Errorf("resolving operand %q of cohort %q: %w", c.Compound.Operands[0], c.Name, err)
	}

	for _, operandName := range c.Compound.Operands[1:] {
		operandSet, err := r.resolve(operandName, allSproutIDs, copyVisited(visited), depth+1)
		if err != nil {
			return nil, fmt.Errorf("resolving operand %q of cohort %q: %w", operandName, c.Name, err)
		}

		switch c.Compound.Operator {
		case OperatorAND:
			result = intersect(result, operandSet)
		case OperatorOR:
			result = union(result, operandSet)
		case OperatorEXCEPT:
			result = except(result, operandSet)
		}
	}

	return result, nil
}

func copyVisited(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func intersect(a, b map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for id := range a {
		if b[id] {
			result[id] = true
		}
	}
	return result
}

func union(a, b map[string]bool) map[string]bool {
	result := make(map[string]bool, len(a)+len(b))
	for id := range a {
		result[id] = true
	}
	for id := range b {
		result[id] = true
	}
	return result
}

func except(a, b map[string]bool) map[string]bool {
	result := make(map[string]bool, len(a))
	for id := range a {
		if !b[id] {
			result[id] = true
		}
	}
	return result
}
