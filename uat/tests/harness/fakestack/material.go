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
				"1": map[string]any{"tenant_id": TenantID(1), "admin": map[string]string{"username": "t1-admin", "password": "pw"}, "readonly": map[string]string{"username": "t1-ro", "password": "pw"}},
				"2": map[string]any{"tenant_id": TenantID(2), "admin": map[string]string{"username": "t2-admin", "password": "pw"}, "readonly": map[string]string{"username": "t2-ro", "password": "pw"}},
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
