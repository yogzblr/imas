package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

// The core hub's outputs (UAT.3b, uat/hub/core, owner decision of
// 2026-10-06: "#132 writes keycloak.json (with tenant_attribute),
// core.json, credentials.json; the harness calls bind-tenant.sh once per
// tenant"). install.sh writes <state>/core/out/core.json (not secret) and
// <state>/core/sensitive/credentials.json (SENSITIVE); bind-tenant.sh maps
// UAT tenant 1 or 2 to a saasapi tenant ID by setting the users' realm
// attribute organization_id, which the test client maps to the
// organization.id claim, and records it in core.json's tenants.
const (
	FileCore        = "core.json"
	FileCredentials = "credentials.json"
	// CoreTenantAttribute is the realm user attribute UAT.3b's realm maps
	// to organization.id.
	CoreTenantAttribute = "organization_id"
)

// Environment variables for bind-tenant.sh (see BindConfig).
const (
	EnvBindTenant        = "IMAS_UAT_BIND_TENANT"
	EnvBindTenantDefault = "IMAS_UAT_BIND_TENANT_DEFAULT"
	EnvCoreKubeconfig    = "IMAS_UAT_CORE_KUBECONFIG"
	EnvEndpoints         = "IMAS_UAT_ENDPOINTS"
)

// CoreJSON is the part of uat/hub/core's out/core.json the harness reads.
type CoreJSON struct {
	SaaSAPIURL string `json:"saasapi_url"`
	CAFile     string `json:"ca_file"`
	Keycloak   struct {
		Issuer      string `json:"issuer"`
		TokenURL    string `json:"token_url"`
		Realm       string `json:"realm"`
		Audience    string `json:"audience"`
		ClientID    string `json:"client_id"`
		ReadRole    string `json:"read_role"`
		WriteRole   string `json:"write_role"`
		TenantClaim string `json:"tenant_claim"`
	} `json:"keycloak"`
	Users map[string]struct {
		Tenant FlexInt  `json:"tenant"`
		Roles  []string `json:"roles"`
	} `json:"users"`
	// Tenants maps "1" and "2" to the saasapi tenant IDs bind-tenant.sh
	// bound them to.
	Tenants      map[string]string `json:"tenants"`
	SensitiveDir string            `json:"sensitive_dir"`
}

// CredentialsJSON is the part of uat/hub/core's sensitive/credentials.json
// the harness reads. Every field is a secret.
type CredentialsJSON struct {
	InternalAuthSecret string `json:"internal_auth_secret"`
	Keycloak           struct {
		ClientSecret string            `json:"client_secret"`
		Passwords    map[string]string `json:"passwords"`
		MasterAdmin  Credentials       `json:"master_admin"`
	} `json:"keycloak"`
}

// BindConfig is how the harness runs uat/hub/core/bind-tenant.sh:
//
//	bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>
//
// Each field comes from harness.json's bind_tenant, else the environment
// ($IMAS_UAT_BIND_TENANT or run.sh's default for Script,
// $IMAS_UAT_CORE_KUBECONFIG, $IMAS_UAT_ENDPOINTS), else, for StateDir, the
// state root the core.json was found under.
type BindConfig struct {
	Script     string `json:"script,omitempty"`
	Kubeconfig string `json:"kubeconfig,omitempty"`
	Endpoints  string `json:"endpoints,omitempty"`
	StateDir   string `json:"state_dir,omitempty"`
}

// Enabled reports whether everything bind-tenant.sh needs is known.
func (b BindConfig) Enabled() bool {
	return b.Script != "" && b.Kubeconfig != "" && b.Endpoints != "" && b.StateDir != ""
}

// Missing names what keeps the binding off.
func (b BindConfig) Missing() []string {
	var m []string
	if b.Script == "" {
		m = append(m, "the bind-tenant.sh path ("+EnvBindTenant+")")
	}
	if b.Kubeconfig == "" {
		m = append(m, "the core kubeconfig ("+EnvCoreKubeconfig+")")
	}
	if b.Endpoints == "" {
		m = append(m, "the endpoints file ("+EnvEndpoints+")")
	}
	if b.StateDir == "" {
		m = append(m, "the state directory (bind_tenant.state_dir)")
	}
	return m
}

// findCore looks for core.json in the material directory itself, then in
// the state-root layout <dir>/core/out/core.json. It returns the parsed
// file, its path and the state root it implies ("" when it implies none).
func findCore(dir string) (*CoreJSON, string, string, error) {
	for _, c := range []struct{ path, root string }{
		{filepath.Join(dir, FileCore), ""},
		{filepath.Join(dir, "core", "out", FileCore), dir},
	} {
		raw, err := os.ReadFile(c.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", "", fmt.Errorf("harness: reading %s: %w", c.path, err)
		}
		var core CoreJSON
		if err := json.Unmarshal(raw, &core); err != nil {
			return nil, "", "", fmt.Errorf("harness: %s: %w", c.path, err)
		}
		root := c.root
		if root == "" && core.SensitiveDir != "" {
			// <root>/core/sensitive
			root = filepath.Dir(filepath.Dir(core.SensitiveDir))
		}
		return &core, c.path, root, nil
	}
	return nil, "", "", nil
}

// findCredentials looks for credentials.json in the material directory,
// then <dir>/core/sensitive/, then core.json's sensitive_dir.
func findCredentials(dir string, core *CoreJSON) (*CredentialsJSON, error) {
	paths := []string{filepath.Join(dir, FileCredentials), filepath.Join(dir, "core", "sensitive", FileCredentials)}
	if core != nil && core.SensitiveDir != "" {
		paths = append(paths, filepath.Join(core.SensitiveDir, FileCredentials))
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("harness: reading %s: %w", p, err)
		}
		var c CredentialsJSON
		if err := json.Unmarshal(raw, &c); err != nil {
			// Never quote the file: it is all secrets.
			return nil, fmt.Errorf("harness: %s is not the credentials JSON object", p)
		}
		return &c, nil
	}
	return nil, nil
}

// keycloakFromCore builds the Keycloak settings from core.json and
// credentials.json. A user holding the write role is its tenant's admin,
// one holding only the read role its read only user.
//
// No Admin is set: UAT.3b administers Keycloak only through kubectl exec
// (its edge proxy never routes /admin or the master realm), so the admin
// REST API scratch users need isn't reachable from the runner, even though
// credentials.json holds the master admin.
func keycloakFromCore(core *CoreJSON, creds *CredentialsJSON) KeycloakConfig {
	kc := KeycloakConfig{
		Issuer:          core.Keycloak.Issuer,
		ClientID:        core.Keycloak.ClientID,
		TenantAttribute: CoreTenantAttribute,
		Tenants:         map[string]KeycloakTenant{},
	}
	if creds != nil {
		kc.ClientSecret = creds.Keycloak.ClientSecret
	}
	read, write := core.Keycloak.ReadRole, core.Keycloak.WriteRole
	if read == "" {
		read = "imas-recipes-read"
	}
	if write == "" {
		write = "imas-recipes-write"
	}
	for name, u := range core.Users {
		key := strconv.Itoa(int(u.Tenant))
		t := kc.Tenants[key]
		c := Credentials{Username: name}
		if creds != nil {
			c.Password = creds.Keycloak.Passwords[name]
		}
		switch {
		case slices.Contains(u.Roles, write):
			t.Admin = c
		case slices.Contains(u.Roles, read):
			t.ReadOnly = c
		}
		kc.Tenants[key] = t
	}
	// core.json's tenants are not copied here: they are what bind-tenant.sh
	// last recorded, the fallback of Env.TenantID (loadTenants), and what
	// Fleet.BindTenants compares the run's tenant IDs with.
	return kc
}

// mergeKeycloak lays over's non-empty fields over base.
func mergeKeycloak(base, over KeycloakConfig) KeycloakConfig {
	str := func(b, o string) string {
		if o != "" {
			return o
		}
		return b
	}
	cred := func(b, o Credentials) Credentials {
		return Credentials{Username: str(b.Username, o.Username), Password: str(b.Password, o.Password)}
	}
	out := base
	out.Issuer = str(base.Issuer, over.Issuer)
	out.ClientID = str(base.ClientID, over.ClientID)
	out.ClientSecret = str(base.ClientSecret, over.ClientSecret)
	out.TenantAttribute = str(base.TenantAttribute, over.TenantAttribute)
	if over.Admin != nil {
		out.Admin = over.Admin
	}
	if over.OtherAudienceClient != nil {
		out.OtherAudienceClient = over.OtherAudienceClient
	}
	out.Tenants = map[string]KeycloakTenant{}
	for k, t := range base.Tenants {
		out.Tenants[k] = t
	}
	for k, o := range over.Tenants {
		b := out.Tenants[k]
		out.Tenants[k] = KeycloakTenant{
			TenantID: str(b.TenantID, o.TenantID),
			Admin:    cred(b.Admin, o.Admin),
			ReadOnly: cred(b.ReadOnly, o.ReadOnly),
		}
	}
	return out
}
