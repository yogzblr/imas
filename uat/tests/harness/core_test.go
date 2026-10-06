package harness

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

// The shapes uat/hub/core (UAT.3b, PR #132) writes: out/core.json and
// sensitive/credentials.json, from its install.sh.
const sampleCore = `{
  "release_tag": "v0.1.0-rc.4", "version": "0.1.0-rc.4", "namespace": "imas", "release": "imas",
  "saasapi_url": "https://uatab12cd-core.centralindia.cloudapp.azure.com",
  "internal_auth_header": "X-Internal-Auth",
  "ca_file": "CA_FILE",
  "sprout_bus_url": "wss://x",
  "keycloak": {"issuer": "https://uatab12cd-core.centralindia.cloudapp.azure.com/realms/imas-uat",
    "jwks_url": "j", "token_url": "t", "realm": "imas-uat", "audience": "imas-saasapi",
    "client_id": "imas-uat-tests", "read_role": "imas-recipes-read", "write_role": "imas-recipes-write",
    "tenant_claim": "organization.id"},
  "users": {
    "t1-admin":  {"tenant": "1", "roles": ["imas-recipes-read", "imas-recipes-write"]},
    "t1-reader": {"tenant": "1", "roles": ["imas-recipes-read"]},
    "t2-admin":  {"tenant": "2", "roles": ["imas-recipes-read", "imas-recipes-write"]},
    "t2-reader": {"tenant": "2", "roles": ["imas-recipes-read"]}
  },
  "tenants": TENANTS,
  "bootstrap_admin": {"pubkey": "U..."},
  "sensitive_dir": "SENSITIVE"
}`

const sampleCredentials = `{
  "note": "SENSITIVE",
  "internal_auth_secret": "bff-secret\n",
  "keycloak": {"client_secret": "client-secret\n",
    "passwords": {"t1-admin": "p1", "t1-reader": "p2", "t2-admin": "p3", "t2-reader": "p4"},
    "master_admin": {"username": "admin", "password": "master"}},
  "bootstrap_admin": {}, "openbao_init_file": "/x"
}`

// stateRoot writes uat.json at root and the core hub's outputs under
// root/core, the way install.sh lays them out.
func stateRoot(t *testing.T, tenants string) string {
	t.Helper()
	root := t.TempDir()
	out, sens := filepath.Join(root, "core", "out"), filepath.Join(root, "core", "sensitive")
	for _, d := range []string{out, sens} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s := fakestack.New() // for a CA certificate
	t.Cleanup(s.Close)
	ca := filepath.Join(out, "uat-ca.crt")
	writeFile(t, ca, string(mustRead(t, s)))
	core := strings.NewReplacer("CA_FILE", ca, "SENSITIVE", sens, "TENANTS", tenants).Replace(sampleCore)
	writeFile(t, filepath.Join(out, FileCore), core)
	writeFile(t, filepath.Join(sens, FileCredentials), sampleCredentials)
	writeFile(t, filepath.Join(root, FileUAT), sampleUAT)
	return root
}

func mustRead(t *testing.T, s *fakestack.Stack) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := s.WriteMaterial(dir, ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, FileCA))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func clearBindEnv(t *testing.T) {
	for _, v := range []string{EnvBindTenant, EnvBindTenantDefault, EnvCoreKubeconfig, EnvEndpoints, EnvVMCtl, EnvVMCtlDefault} {
		t.Setenv(v, "")
	}
}

func TestLoadCoreLayout(t *testing.T) {
	clearBindEnv(t)
	root := stateRoot(t, `{"1": "t_aaaaaaaaaaaaaaaa", "2": "t_bbbbbbbbbbbbbbbb"}`)
	env, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	k := env.Keycloak
	if k.Issuer != "https://uatab12cd-core.centralindia.cloudapp.azure.com/realms/imas-uat" || k.ClientID != "imas-uat-tests" ||
		k.ClientSecret != "client-secret\n" || k.TenantAttribute != CoreTenantAttribute || k.Admin != nil {
		t.Errorf("keycloak %+v", k)
	}
	t1, t2 := k.Tenants["1"], k.Tenants["2"]
	if t1.Admin != (Credentials{"t1-admin", "p1"}) || t1.ReadOnly != (Credentials{"t1-reader", "p2"}) ||
		t2.Admin != (Credentials{"t2-admin", "p3"}) || t2.ReadOnly != (Credentials{"t2-reader", "p4"}) {
		t.Errorf("users %+v %+v", t1, t2)
	}
	if env.InternalAuth != "bff-secret" || env.CAPool == nil || env.SaaSAPIURL != "https://uatab12cd-core.centralindia.cloudapp.azure.com" {
		t.Errorf("secret %q CA %v saasapi %s", env.InternalAuth, env.CAPool != nil, env.SaaSAPIURL)
	}
	// tenants.json (sampleUAT's material doesn't have one here): core.json's tenants.
	if env.TenantID(1) != "t_aaaaaaaaaaaaaaaa" || env.TenantID(2) != "t_bbbbbbbbbbbbbbbb" {
		t.Errorf("tenants %q %q", env.TenantID(1), env.TenantID(2))
	}
	if env.Bind.StateDir != root || env.Bind.Enabled() {
		t.Errorf("bind %+v", env.Bind)
	}
	if !strings.Contains(strings.Join(env.Bind.Missing(), " "), EnvCoreKubeconfig) {
		t.Errorf("missing %v", env.Bind.Missing())
	}

	t.Setenv(EnvBindTenantDefault, "/repo/uat/hub/core/bind-tenant.sh")
	t.Setenv(EnvCoreKubeconfig, "/run/core.kubeconfig")
	t.Setenv(EnvEndpoints, "/run/endpoints.json")
	env, err = LoadDir(root)
	if err != nil || !env.Bind.Enabled() || env.Bind.Script != "/repo/uat/hub/core/bind-tenant.sh" {
		t.Errorf("bind from the environment: %+v %v", env.Bind, err)
	}
}

func TestLoadCoreLayoutUnbound(t *testing.T) {
	clearBindEnv(t)
	root := stateRoot(t, `{}`)
	if _, err := LoadDir(root); err == nil || !strings.Contains(err.Error(), "bind-tenant.sh") {
		t.Errorf("no tenant IDs anywhere: %v", err)
	}
	// UAT.4's tenants.json gives them; core.json not yet bound.
	writeFile(t, filepath.Join(root, FileTenants), `{"1": "t_cccccccccccccccc", "2": "t_dddddddddddddddd"}`)
	env, err := LoadDir(root)
	if err != nil || env.TenantID(1) != "t_cccccccccccccccc" {
		t.Fatalf("%v %v", env, err)
	}
}

func TestLoadCoreFlatWithKeycloakOverlay(t *testing.T) {
	clearBindEnv(t)
	root := stateRoot(t, `{"1": "t_aaaaaaaaaaaaaaaa", "2": "t_bbbbbbbbbbbbbbbb"}`)
	// core.json copied next to uat.json: credentials.json is found through
	// its sensitive_dir, and the state root from it too.
	dir := t.TempDir()
	b, _ := os.ReadFile(filepath.Join(root, "core", "out", FileCore))
	writeFile(t, filepath.Join(dir, FileCore), string(b))
	writeFile(t, filepath.Join(dir, FileUAT), sampleUAT)
	writeFile(t, filepath.Join(dir, FileKeycloak), `{"tenant_attribute": "org_attr",
		"other_audience_client": {"client_id": "other"},
		"tenants": {"2": {"readonly": {"username": "someone-else", "password": "x"}}}}`)
	env, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	k := env.Keycloak
	if k.TenantAttribute != "org_attr" || k.OtherAudienceClient == nil || k.ClientID != "imas-uat-tests" {
		t.Errorf("overlay %+v", k)
	}
	if k.Tenants["2"].ReadOnly.Username != "someone-else" || k.Tenants["2"].Admin.Username != "t2-admin" || env.InternalAuth != "bff-secret" {
		t.Errorf("merge %+v", k.Tenants)
	}
	if env.Bind.StateDir != root {
		t.Errorf("state dir %q, want %q", env.Bind.StateDir, root)
	}
}

func TestLoadNeedsKeycloakOrCore(t *testing.T) {
	clearBindEnv(t)
	dir := material(t, map[string]string{FileKeycloak: ""})
	os.Remove(filepath.Join(dir, FileKeycloak))
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "core.json") {
		t.Errorf("%v", err)
	}
}

func TestBindTenants(t *testing.T) {
	needShell(t)
	f, _ := fakeFleet(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := filepath.Join(dir, "bind-tenant.sh")
	writeFile(t, script, "#!/usr/bin/env bash\necho \"$*\" >> "+ShQuote(log)+"\n[ \"$4\" != 9 ]\n")
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	c := context.Background()

	if bound, skipped, err := f.BindTenants(c); err != nil || bound != nil || !strings.Contains(skipped, "not run") {
		t.Errorf("disabled: %v %q %v", bound, skipped, err)
	}

	f.Env.Bind = BindConfig{Script: script, Kubeconfig: "/k", Endpoints: "/e", StateDir: "/s"}
	f.Env.Core = &CoreJSON{Tenants: map[string]string{"2": f.TenantID(2)}}
	if _, err := f.Tokens.Tenant(c, 1, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	bound, skipped, err := f.BindTenants(c)
	if err != nil || skipped != "" || len(bound) != 1 || bound[0] != 1 {
		t.Fatalf("bound %v %q %v", bound, skipped, err)
	}
	calls, _ := os.ReadFile(log)
	if string(calls) != "/k /e /s 1 "+f.TenantID(1)+"\n" {
		t.Errorf("calls %q", calls)
	}
	if len(f.Tokens.cache) != 0 {
		t.Error("the token cache should be dropped after a binding")
	}
	// Recorded now: a second call binds nothing.
	if bound, _, err := f.BindTenants(c); err != nil || len(bound) != 0 {
		t.Errorf("second call %v %v", bound, err)
	}

	writeFile(t, script, "#!/usr/bin/env bash\necho 'no user t1-admin' >&2\nexit 1\n")
	f.Env.Core = nil
	if _, _, err := f.BindTenants(c); err == nil || !strings.Contains(err.Error(), "no user t1-admin") {
		t.Errorf("a failing script: %v", err)
	}
}

func TestCheckTenantClaims(t *testing.T) {
	f, _ := fakeFleet(t)
	if err := f.CheckTenantClaims(ctx(t)); err != nil {
		t.Errorf("bound tenants: %v", err)
	}
	f.Env.tenantIDs[2] = "t_zzzzzzzzzzzzzzzz"
	if err := f.CheckTenantClaims(ctx(t)); err == nil || !strings.Contains(err.Error(), "bind-tenant.sh") {
		t.Errorf("an unbound tenant: %v", err)
	}
}
