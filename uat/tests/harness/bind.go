package harness

import (
	"context"
	"errors"
	"fmt"
)

// Owner decisions, 2026-10-06:
//
//   - "UAT.4 binds tenants 1 and 2; harness binds only run-created tenants
//     not in core.json." The harness never binds tenants 1 and 2; it checks
//     they are bound (CheckTenantClaims).
//   - "bind-tenant.sh gains a create-user-and-bind mode for scratch users
//     (via kubectl exec); #134 uses it for T1, T4, T5; no admin API on the
//     edge." That mode is UAT.3b's (PR #132) and was not on its branch, nor
//     documented, when this was written (its head was 9ace6c7, whose
//     bind-tenant.sh binds only tenants 1 and 2). So ScratchUser below
//     doesn't call it yet: it has one seam where it will, and until then
//     returns ErrNoScratchUsers unless a Keycloak admin REST identity is
//     configured (keycloak.json's admin, for a deployment whose admin API
//     is reachable). Env.Bind already holds the arguments every
//     uat/hub/core script takes (<kubeconfig> <endpoints.json>
//     <state-dir>).

// ErrNoScratchUsers is returned by Fleet.ScratchUser when the harness has
// no way to map a user to a tenant created during the run.
var ErrNoScratchUsers = errors.New("no way to map a Keycloak user to a tenant created during the run: " +
	"keycloak.json has no admin identity (UAT.3b's edge doesn't route Keycloak's admin API), and " +
	"bind-tenant.sh's create-user-and-bind mode (owner decision, 2026-10-06) wasn't documented in PR #132 " +
	"when this harness was written, so it isn't wired in yet (open question in PR #134)")

// CanMakeScratchUsers reports whether ScratchUser can work.
func (f *Fleet) CanMakeScratchUsers() bool { return f.Tokens.HasAdmin() }

// ScratchUser makes a realm user whose tokens carry tenantID as
// organization.id, for a tenant the test created (T1, T4, T5). Delete it
// when done.
func (f *Fleet) ScratchUser(ctx context.Context, tenantID string) (*ScratchUser, error) {
	if f.Tokens.HasAdmin() {
		return f.Tokens.ScratchUser(ctx, tenantID)
	}
	// The seam for bind-tenant.sh's create-user-and-bind mode, once PR
	// #132 documents its interface.
	return nil, ErrNoScratchUsers
}

// CheckTenantClaims fetches each tenant's admin token and checks its
// organization.id is the tenant's ID: without that, every tenant route
// answers 403 and nothing else can run. UAT.4 binds tenants 1 and 2
// (uat/hub/core/bind-tenant.sh); the harness doesn't.
func (f *Fleet) CheckTenantClaims(ctx context.Context) error {
	for _, n := range []int{1, 2} {
		tok, err := f.Tokens.Tenant(ctx, n, RoleAdmin)
		if err != nil {
			return fmt.Errorf("tenant %d's admin token: %w", n, err)
		}
		c, err := DecodeClaims(tok)
		if err != nil {
			return fmt.Errorf("tenant %d's admin token: %w", n, err)
		}
		org, _ := c["organization"].(map[string]any)
		got, _ := org["id"].(string)
		if got != f.TenantID(n) {
			return fmt.Errorf("tenant %d's admin token carries organization.id %q, not the tenant's ID %q: "+
				"the tenant's users aren't bound to it (UAT.4 binds tenants 1 and 2 with uat/hub/core/bind-tenant.sh)", n, got, f.TenantID(n))
		}
	}
	return nil
}
