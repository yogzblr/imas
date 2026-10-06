package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
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

// keycloak.json where uat/hub/core writes it (PR #132): next to
// credentials.json in core/sensitive.
func TestLoadCoreSensitiveKeycloakJSON(t *testing.T) {
	clearBindEnv(t)
	root := stateRoot(t, `{}`)
	writeFile(t, filepath.Join(root, "core", "sensitive", FileKeycloak), `{
	  "issuer": "https://uatab12cd-core.centralindia.cloudapp.azure.com/realms/imas-uat",
	  "client_id": "imas-uat-tests", "client_secret": "cs", "tenant_attribute": "organization_id",
	  "other_audience_client": {"client_id": "imas-uat-other-audience", "client_secret": "os"},
	  "tenants": {
	    "1": {"admin": {"username": "t1-admin", "password": "p1"}, "readonly": {"username": "t1-reader", "password": "p2"}, "tenant_id": "t_eeeeeeeeeeeeeeee"},
	    "2": {"admin": {"username": "t2-admin", "password": "p3"}, "readonly": {"username": "t2-reader", "password": "p4"}, "tenant_id": "t_ffffffffffffffff"}
	  }
	}`)
	env, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	k := env.Keycloak
	if k.ClientSecret != "cs" || k.OtherAudienceClient == nil || k.OtherAudienceClient.ClientID != "imas-uat-other-audience" ||
		k.OtherAudienceClient.ClientSecret != "os" || k.Admin != nil {
		t.Errorf("keycloak %+v", k)
	}
	if env.TenantID(1) != "t_eeeeeeeeeeeeeeee" || env.TenantID(2) != "t_ffffffffffffffff" {
		t.Errorf("tenants %q %q", env.TenantID(1), env.TenantID(2))
	}
}

func TestScratchUserSeam(t *testing.T) {
	f, _ := fakeFleet(t)
	if !f.CanMakeScratchUsers() {
		t.Fatal("the fake's keycloak.json has an admin")
	}
	u, err := f.ScratchUser(ctx(t), "t_gggggggggggggggg")
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Delete(ctx(t))
	f.Tokens.cfg.Admin = nil
	if f.CanMakeScratchUsers() {
		t.Error("no admin, but scratch users")
	}
	if _, err := f.ScratchUser(ctx(t), "t_x"); !errors.Is(err, ErrNoScratchUsers) || !strings.Contains(err.Error(), EnvCoreKubeconfig) {
		t.Errorf("%v", err)
	}
	if _, err := f.Tokens.Tenant(ctx(t), 1, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	f.Tokens.Forget()
	if len(f.Tokens.cache) != 0 {
		t.Error("Forget kept tokens")
	}
}

func TestCheckTenantClaims(t *testing.T) {
	f, _ := fakeFleet(t)
	if err := f.CheckTenantClaims(ctx(t)); err != nil {
		t.Errorf("bound tenants: %v", err)
	}
	f.Env.tenantIDs[2] = "t_zzzzzzzzzzzzzzzz"
	if err := f.CheckTenantClaims(ctx(t)); err == nil || !strings.Contains(err.Error(), "UAT.4 binds") {
		t.Errorf("an unbound tenant: %v", err)
	}
}

// bind-tenant.sh --scratch-user (PR #132): the arguments, the JSON line,
// the password file, and a token that carries the tenant.
func TestScratchUserThroughBindTenant(t *testing.T) {
	f, stack := fakeFleet(t)
	f.Tokens.cfg.Admin = nil
	state := t.TempDir()
	f.Env.Bind = BindConfig{Script: "/unused", Kubeconfig: "/k", Endpoints: "/e", StateDir: state}
	if !f.CanMakeScratchUsers() {
		t.Fatal("bind-tenant.sh configured, but no scratch users")
	}
	var got []string
	answer := func(args []string, pwFile, line string) ([]byte, []byte, error) {
		got = args
		if pwFile != "" {
			if err := os.MkdirAll(filepath.Dir(pwFile), 0o700); err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(pwFile, []byte("s3cret-pw\n"), 0o600); err != nil {
				return nil, nil, err
			}
		}
		return []byte(line), []byte("bound\n"), nil
	}
	f.BindExec = func(_ context.Context, args []string) ([]byte, []byte, error) {
		name, tenant := args[4], args[6]
		stack.AddUser(name, "s3cret-pw", tenant)
		pw := filepath.Join(state, "core", "sensitive", "keycloak", "scratch", name+".password")
		return answer(args, pw, `{"username":"`+name+`","tenant_id":"`+tenant+`","role":"admin","password_file":"`+pw+`"}`+"\n")
	}
	u, err := f.ScratchUser(ctx(t), "t_hhhhhhhhhhhhhhhh")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 || got[0] != "/k" || got[1] != "/e" || got[2] != state || got[3] != "--scratch-user" ||
		!regexp.MustCompile(`^scratch-[a-z0-9][a-z0-9-]{0,50}$`).MatchString(got[4]) || got[5] != "admin" || got[6] != "t_hhhhhhhhhhhhhhhh" {
		t.Errorf("arguments %q", got)
	}
	if u.User.Password != "s3cret-pw" || !u.NoDelete || u.TenantID != "t_hhhhhhhhhhhhhhhh" {
		t.Errorf("user %+v", u)
	}
	tok, err := u.Token(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := DecodeClaims(tok)
	if org, _ := c["organization"].(map[string]any); org["id"] != "t_hhhhhhhhhhhhhhhh" {
		t.Errorf("token organization %v", c["organization"])
	}
	if err := u.Delete(ctx(t)); err != nil {
		t.Errorf("Delete of a bind-tenant.sh user is a no-op: %v", err)
	}

	for name, exec := range map[string]func(context.Context, []string) ([]byte, []byte, error){
		"script fails": func(context.Context, []string) ([]byte, []byte, error) {
			return nil, []byte("t_x is tenant 1 or 2"), errors.New("exit status 1")
		},
		"no JSON": func(_ context.Context, args []string) ([]byte, []byte, error) { return answer(args, "", "done\n") },
		"another user": func(_ context.Context, args []string) ([]byte, []byte, error) {
			return answer(args, "", `{"username":"scratch-other","tenant_id":"`+args[6]+`","role":"admin","password_file":"/x"}`)
		},
		"no password file": func(_ context.Context, args []string) ([]byte, []byte, error) {
			return answer(args, "", `{"username":"`+args[4]+`","tenant_id":"`+args[6]+`","role":"admin","password_file":"/nonexistent/pw"}`)
		},
	} {
		f.BindExec = exec
		if _, err := f.ScratchUser(ctx(t), "t_iiiiiiiiiiiiiiii"); err == nil {
			t.Errorf("%s: want an error", name)
		} else if name == "script fails" && !strings.Contains(err.Error(), "tenant 1 or 2") {
			t.Errorf("%s: the error lacks the script's stderr: %v", name, err)
		}
	}
}

// The real exec path: a script with bind-tenant.sh's arguments and output.
func TestScratchUserRunsTheScript(t *testing.T) {
	needShell(t)
	f, _ := fakeFleet(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "bind-tenant.sh")
	writeFile(t, script, `#!/usr/bin/env bash
set -eu
[ "$4" = --scratch-user ] || exit 2
pwf="$3/$5.password"
printf 'pw-from-file\n' > "$pwf"
echo "log line" >&2
printf '{"username":"%s","tenant_id":"%s","role":"%s","password_file":"%s"}\n' "$5" "$7" "$6" "$pwf"
`)
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	f.Env.Bind = BindConfig{Script: script, Kubeconfig: "/k", Endpoints: "/e", StateDir: dir}
	u, err := f.ScratchUser(ctx(t), "t_jjjjjjjjjjjjjjjj")
	if err != nil || u.User.Password != "pw-from-file" || !strings.HasPrefix(u.User.Username, "scratch-") {
		t.Errorf("%+v %v", u, err)
	}
}
