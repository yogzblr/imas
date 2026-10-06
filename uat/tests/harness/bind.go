package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Owner decisions, 2026-10-06:
//
//   - "UAT.4 binds tenants 1 and 2; harness binds only run-created tenants
//     not in core.json." The harness never binds tenants 1 and 2; it checks
//     they are bound (CheckTenantClaims).
//   - "bind-tenant.sh gains a create-user-and-bind mode for scratch users
//     (via kubectl exec); #134 uses it for T1, T4, T5; no admin API on the
//     edge." ScratchUser runs that mode (uat/hub/core/bind-tenant.sh, PR
//     #132 from its head e2d8ee1):
//
//	bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> --scratch-user <username> <admin|readonly> <tenant_id>
//
//     It creates the user if absent with a generated password in
//     <state>/core/sensitive/keycloak/scratch/<username>.password (0600),
//     grants the recipe roles of the role, sets organization_id to the
//     tenant, records it in core.json's scratch_users, and prints one JSON
//     line {"username", "tenant_id", "role", "password_file"}, never the
//     password. uat/hub/core has no delete for scratch users, so they stay
//     in the realm until the run is torn down.

// ErrNoScratchUsers is returned by Fleet.ScratchUser when the harness has
// no way to map a user to a tenant created during the run.
var ErrNoScratchUsers = errors.New("no way to map a Keycloak user to a tenant created during the run: " +
	"bind-tenant.sh's scratch mode needs the core kubeconfig ($IMAS_UAT_CORE_KUBECONFIG), the endpoints file " +
	"($IMAS_UAT_ENDPOINTS) and the state directory (or harness.json's bind_tenant), and keycloak.json has no " +
	"admin for Keycloak's admin REST API (UAT.3b's edge doesn't route it)")

// scratchPrefix starts every scratch user's name, as bind-tenant.sh's
// scratch mode requires (scratch-[a-z0-9][a-z0-9-]{0,50}).
const scratchPrefix = "scratch-"

// CanMakeScratchUsers reports whether ScratchUser can work.
func (f *Fleet) CanMakeScratchUsers() bool { return f.Env.Bind.Enabled() || f.Tokens.HasAdmin() }

// ScratchUser makes an admin user (both recipe roles) whose tokens carry
// tenantID as organization.id, for a tenant the test created (T1, T4,
// T5): through bind-tenant.sh's scratch mode when it is configured, else
// through Keycloak's admin REST API when keycloak.json has an admin. Delete
// it when done.
func (f *Fleet) ScratchUser(ctx context.Context, tenantID string) (*ScratchUser, error) {
	switch {
	case f.Env.Bind.Enabled():
		return f.bindScratchUser(ctx, scratchPrefix+randomLower(12), "admin", tenantID)
	case f.Tokens.HasAdmin():
		return f.Tokens.ScratchUser(ctx, tenantID)
	default:
		return nil, ErrNoScratchUsers
	}
}

// scratchAnswer is the JSON line bind-tenant.sh's scratch mode prints.
type scratchAnswer struct {
	Username     string `json:"username"`
	TenantID     string `json:"tenant_id"`
	Role         string `json:"role"`
	PasswordFile string `json:"password_file"`
}

func (f *Fleet) bindScratchUser(ctx context.Context, name, role, tenantID string) (*ScratchUser, error) {
	b := f.Env.Bind
	args := []string{b.Kubeconfig, b.Endpoints, b.StateDir, "--scratch-user", name, role, tenantID}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var stdout, stderr []byte
	var err error
	if f.BindExec != nil {
		stdout, stderr, err = f.BindExec(cctx, args)
	} else {
		var so, se bytes.Buffer
		cmd := exec.CommandContext(cctx, b.Script, args...)
		cmd.Stdout, cmd.Stderr = &so, &se
		cmd.WaitDelay = time.Second
		err = cmd.Run()
		stdout, stderr = so.Bytes(), se.Bytes()
	}
	if err != nil {
		return nil, fmt.Errorf("bind-tenant.sh --scratch-user %s %s %s: %v: %s", name, role, tenantID, err, tail(stderr, 600))
	}
	var ans scratchAnswer
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[len(lines)-1])), &ans); err != nil {
		return nil, fmt.Errorf("bind-tenant.sh --scratch-user printed no JSON line: %s", tail(stdout, 300))
	}
	if ans.Username != name || ans.TenantID != tenantID || ans.Role != role || ans.PasswordFile == "" {
		return nil, fmt.Errorf("bind-tenant.sh --scratch-user answered for %q in %q as %q, want %q in %q as %q",
			ans.Username, ans.TenantID, ans.Role, name, tenantID, role)
	}
	pwFile := ans.PasswordFile
	if !filepath.IsAbs(pwFile) {
		pwFile = filepath.Join(b.StateDir, pwFile)
	}
	raw, err := os.ReadFile(pwFile)
	if err != nil {
		return nil, fmt.Errorf("reading the scratch user's password file: %w", err)
	}
	// bind-tenant.sh feeds the file's first line to Keycloak.
	pw := strings.TrimRight(strings.SplitN(string(raw), "\n", 2)[0], "\r")
	if pw == "" {
		return nil, fmt.Errorf("the scratch user's password file %s is empty", pwFile)
	}
	return &ScratchUser{TenantID: tenantID, User: Credentials{Username: name, Password: pw}, NoDelete: true, k: f.Tokens}, nil
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
