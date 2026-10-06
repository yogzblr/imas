package harness

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// BindTenants runs uat/hub/core/bind-tenant.sh once for each of the run's
// tenants that core.json doesn't already record as bound to its tenant ID
// (owner decision, 2026-10-06: "the harness calls bind-tenant.sh once per
// tenant"), then drops the cached tokens so the next ones carry the new
// organization.id. It returns the tenants it bound. With the binding not
// configured (Env.Bind.Enabled), it binds nothing and says so in skipped;
// CheckTenantClaims then tells whether someone else (UAT.4) did.
func (f *Fleet) BindTenants(ctx context.Context) (bound []int, skipped string, err error) {
	b := f.Env.Bind
	if !b.Enabled() {
		return nil, fmt.Sprintf("bind-tenant.sh not run: missing %v", b.Missing()), nil
	}
	for _, n := range []int{1, 2} {
		id := f.TenantID(n)
		if id == "" {
			return bound, "", fmt.Errorf("tenant %d has no tenant ID to bind", n)
		}
		if f.Env.Core != nil && f.Env.Core.Tenants[strconv.Itoa(n)] == id {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		out, err := exec.CommandContext(cctx, b.Script, b.Kubeconfig, b.Endpoints, b.StateDir, strconv.Itoa(n), id).CombinedOutput()
		cancel()
		if err != nil {
			return bound, "", fmt.Errorf("bind-tenant.sh for tenant %d (%s): %v: %s", n, id, err, tail(out, 800))
		}
		bound = append(bound, n)
		if f.Env.Core != nil {
			if f.Env.Core.Tenants == nil {
				f.Env.Core.Tenants = map[string]string{}
			}
			f.Env.Core.Tenants[strconv.Itoa(n)] = id
		}
	}
	if len(bound) > 0 {
		f.Tokens.Forget()
	}
	return bound, "", nil
}

// CheckTenantClaims fetches each tenant's admin token and checks its
// organization.id is the tenant's ID: without that, every tenant route
// answers 403 and nothing else can run.
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
			return fmt.Errorf("tenant %d's admin token carries organization.id %q, not the tenant's ID %q: the user isn't bound to its tenant (uat/hub/core/bind-tenant.sh)", n, got, f.TenantID(n))
		}
	}
	return nil
}
