package fakestack

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// Hosts is the contract's six sprouts: one per OS in each tenant, the two
// tenants' sprouts of one OS sharing a sprout ID.
var Hosts = []struct {
	VM, OS, SproutID string
	Tenant           int
}{
	{"t1-ubuntu", "ubuntu", "ubuntu-01", 1}, {"t1-alma", "alma", "alma-01", 1}, {"t1-win", "windows", "win-01", 1},
	{"t2-ubuntu", "ubuntu", "ubuntu-01", 2}, {"t2-alma", "alma", "alma-01", 2}, {"t2-win", "windows", "win-01", 2},
}

// AddContractHosts adds Hosts to the stack.
func (s *Stack) AddContractHosts() {
	for _, h := range Hosts {
		s.AddHost(h.VM, h.Tenant, h.OS, h.SproutID)
	}
}

// WriteCoreMaterial writes a material directory in the state-root layout
// of uat/hub/core (UAT.3b, PR #132): uat.json and harness.json at the top,
// core/out/core.json and core/out/uat-ca.crt (not secret), and
// core/sensitive/credentials.json and keycloak.json. Tenants 1 and 2 are
// recorded as bound, as bind-tenant.sh leaves them after UAT.4 ran it.
// There is no Keycloak admin, as with UAT.3b's edge; harness.json's
// bind_tenant names a fake bind-tenant.sh with the scratch mode (it needs
// curl).
func (s *Stack) WriteCoreMaterial(dir, vmctl string) error {
	if err := s.WriteMaterial(dir, vmctl); err != nil {
		return err
	}
	for _, f := range []string{"keycloak.json", "internal-auth-secret", "uat-ca.pem"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	out, sens := filepath.Join(dir, "core", "out"), filepath.Join(dir, "core", "sensitive")
	for _, d := range []string{out, sens} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Server.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(out, "uat-ca.crt"), ca, 0o644); err != nil {
		return err
	}
	users := map[string]any{}
	pw := map[string]string{}
	for n := 1; n <= 2; n++ {
		users[fmt.Sprintf("t%d-admin", n)] = map[string]any{"tenant": fmt.Sprint(n), "roles": []string{ReadRole, WriteRole}}
		users[fmt.Sprintf("t%d-reader", n)] = map[string]any{"tenant": fmt.Sprint(n), "roles": []string{ReadRole}}
		pw[fmt.Sprintf("t%d-admin", n)], pw[fmt.Sprintf("t%d-reader", n)] = "pw", "pw"
	}
	core := map[string]any{
		"release_tag": "v0.0.0-fake", "saasapi_url": s.Server.URL, "internal_auth_header": "X-Internal-Auth",
		"ca_file": filepath.Join(out, "uat-ca.crt"),
		"keycloak": map[string]string{"issuer": s.Issuer(), "token_url": s.Issuer() + "/protocol/openid-connect/token",
			"realm": Realm, "audience": Audience, "client_id": ClientID, "read_role": ReadRole, "write_role": WriteRole,
			"tenant_claim": "organization.id"},
		"users":         users,
		"tenants":       map[string]string{"1": TenantID(1), "2": TenantID(2)},
		"sensitive_dir": sens,
	}
	creds := map[string]any{
		"note": "SENSITIVE", "internal_auth_secret": InternalSecret + "\n",
		"keycloak": map[string]any{"client_secret": "", "passwords": pw,
			"master_admin": map[string]string{"username": AdminUser, "password": AdminPassword}},
	}
	// keycloak.json as uat/hub/core writes it (PR #132, head 9ace6c7):
	// no admin block, tenant IDs once bound.
	tenant := func(n int) map[string]any {
		return map[string]any{
			"admin":     map[string]string{"username": fmt.Sprintf("t%d-admin", n), "password": "pw"},
			"readonly":  map[string]string{"username": fmt.Sprintf("t%d-reader", n), "password": "pw"},
			"tenant_id": TenantID(n),
		}
	}
	kc := map[string]any{
		"issuer": s.Issuer(), "client_id": ClientID, "client_secret": "", "tenant_attribute": "organization_id",
		"other_audience_client": map[string]string{"client_id": "imas-uat-other-audience", "client_secret": ""},
		"tenants":               map[string]any{"1": tenant(1), "2": tenant(2)},
	}
	// A bind-tenant.sh with only the scratch mode (PR #132, head e2d8ee1:
	// same arguments, same JSON line, the password in a 0600 file), which
	// makes the user through the fake's admin API with curl, and the
	// kubeconfig and endpoints files it is given (never read).
	bind := filepath.Join(dir, "bind-tenant.sh")
	script := fmt.Sprintf(fakeBindTenant, filepath.Join(out, "uat-ca.crt"), s.Server.URL, Realm)
	if err := os.WriteFile(bind, []byte(script), 0o700); err != nil {
		return err
	}
	for _, f := range []string{"core.kubeconfig", "endpoints.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}\n"), 0o600); err != nil {
			return err
		}
	}
	hj := filepath.Join(dir, "harness.json")
	var harness map[string]any
	if b, err := os.ReadFile(hj); err == nil {
		_ = json.Unmarshal(b, &harness)
	}
	if harness == nil {
		harness = map[string]any{}
	}
	harness["bind_tenant"] = map[string]string{"script": bind, "kubeconfig": filepath.Join(dir, "core.kubeconfig"),
		"endpoints": filepath.Join(dir, "endpoints.json"), "state_dir": dir}
	for path, v := range map[string]any{filepath.Join(out, "core.json"): core, filepath.Join(sens, "credentials.json"): creds,
		filepath.Join(sens, "keycloak.json"): kc, hj: harness} {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// WriteMaterial writes a material directory (uat/tests/README.md) for the
// stack into dir: uat.json, keycloak.json, internal-auth-secret,
// uat-ca.pem and harness.json. vmctl, if not empty, is written into
// harness.json as the vmctl.sh to use.
func (s *Stack) WriteMaterial(dir, vmctl string) error {
	u, err := url.Parse(s.Server.URL)
	if err != nil {
		return err
	}
	sprouts := map[string]any{}
	s.mu.Lock()
	for vm, h := range s.hosts {
		conn := "ssh"
		if h.OS == "windows" {
			conn = "winrm"
		}
		sprouts[vm] = map[string]any{"tenant": h.Tenant, "os": h.OS, "connection": conn, "id": "fake/" + vm,
			"private_ip": "10.60.3.10", "public_ip": "127.0.0.1", "admin_user": "uat"}
	}
	s.mu.Unlock()
	host := map[string]string{"private_ip": "127.0.0.1", "public_ip": "127.0.0.1", "fqdn": u.Hostname(), "admin_user": "uat"}
	dmz, core := map[string]string{"name": "uat-dmz"}, map[string]string{"name": "uat-core"}
	for k, v := range host {
		dmz[k], core[k] = v, v
	}
	files := map[string]any{
		"uat.json": map[string]any{"run_id": "fake01", "region": "local", "resource_group": "none",
			"dmz": dmz, "core": core, "sprouts": sprouts},
		"keycloak.json": map[string]any{
			"issuer": s.Issuer(), "client_id": ClientID, "tenant_attribute": TenantAttribute,
			"admin":                 map[string]string{"realm": "master", "client_id": "admin-cli", "username": AdminUser, "password": AdminPassword},
			"other_audience_client": map[string]string{"client_id": "other-client"},
			"tenants": map[string]any{
				"1": map[string]any{"tenant_id": TenantID(1), "admin": map[string]string{"username": "t1-admin", "password": "pw"}, "readonly": map[string]string{"username": "t1-reader", "password": "pw"}},
				"2": map[string]any{"tenant_id": TenantID(2), "admin": map[string]string{"username": "t2-admin", "password": "pw"}, "readonly": map[string]string{"username": "t2-reader", "password": "pw"}},
			},
		},
		"harness.json": map[string]any{"saasapi_url": s.Server.URL, "envoy_url": s.Server.URL},
	}
	if vmctl != "" {
		files["harness.json"].(map[string]any)["vmctl"] = vmctl
	}
	for name, v := range files {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "internal-auth-secret"), []byte(InternalSecret+"\n"), 0o600); err != nil {
		return err
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Server.Certificate().Raw})
	if ca == nil {
		return fmt.Errorf("encoding the server certificate")
	}
	return os.WriteFile(filepath.Join(dir, "uat-ca.pem"), ca, 0o600)
}

// fakeBindTenant is bind-tenant.sh's scratch mode for the fake stack.
const fakeBindTenant = `#!/usr/bin/env bash
# bind-tenant.sh for the fake stack: --scratch-user only.
set -euo pipefail
[ "${4:-}" = --scratch-user ] && [ $# -eq 7 ] || { echo "fake bind-tenant.sh: only --scratch-user" >&2; exit 2; }
user=$5 role=$6 tenant=$7
dir="$3/core/sensitive/keycloak/scratch"
(umask 077 && mkdir -p "$dir")
pwf="$dir/$user.password"
[ -s "$pwf" ] || (umask 077 && head -c 18 /dev/urandom | base64 | tr -d '/+=\n' > "$pwf")
printf '{"username":"%%s","enabled":true,"attributes":{"organization_id":["%%s"]},"credentials":[{"type":"password","value":"%%s"}]}' \
	"$user" "$tenant" "$(head -n1 "$pwf")" |
	curl -sS --fail --cacert %q -H 'Authorization: Bearer fake' -H 'Content-Type: application/json' \
		--data-binary @- "%s/admin/realms/%s/users" >/dev/null
echo "bound $user to $tenant" >&2
printf '{"username":"%%s","tenant_id":"%%s","role":"%%s","password_file":"%%s"}\n' "$user" "$tenant" "$role" "$pwf"
`
