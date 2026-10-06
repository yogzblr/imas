package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleUAT = `{
  "run_id": "ab12cd", "region": "centralindia", "resource_group": "imas-uat-ab12cd",
  "dmz":  {"name": "uat-dmz",  "private_ip": "10.60.1.4", "public_ip": "20.0.0.1", "fqdn": "uatab12cd-dmz.centralindia.cloudapp.azure.com"},
  "core": {"name": "uat-core", "private_ip": "10.60.2.4", "public_ip": "20.0.0.2", "fqdn": "uatab12cd-core.centralindia.cloudapp.azure.com"},
  "sprouts": {
    "t2-win":    {"tenant": "2", "os": "windows", "connection": "winrm", "private_ip": "10.60.3.6"},
    "t1-ubuntu": {"tenant": 1, "os": "ubuntu", "connection": "ssh", "private_ip": "10.60.3.4"},
    "t1-alma":   {"tenant": 1, "os": "alma", "connection": "ssh", "private_ip": "10.60.3.5"}
  },
  "bastion": {"name": "b"}, "subnets": {"dmz": "10.60.1.0/24"}
}`

const sampleKeycloak = `{
  "issuer": "https://uatab12cd-core.centralindia.cloudapp.azure.com/realms/imas-uat",
  "client_id": "uat-tests", "tenant_attribute": "tenant_id",
  "tenants": {
    "1": {"tenant_id": "t_aaaaaaaaaaaaaaaa", "admin": {"username": "a1", "password": "p"}, "readonly": {"username": "r1", "password": "p"}},
    "2": {"admin": {"username": "a2", "password": "p"}}
  },
  "something_new": true
}`

// material writes a material directory with the given files.
func material(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	base := map[string]string{
		FileUAT:          sampleUAT,
		FileKeycloak:     sampleKeycloak,
		FileInternalAuth: "s3cret\n",
		FileTenants:      `{"2": {"tenant_id": "t_bbbbbbbbbbbbbbbb"}, "1": "t_ignored"}`,
	}
	for k, v := range files {
		base[k] = v
	}
	for name, content := range base {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadDir(t *testing.T) {
	t.Setenv(EnvVMCtl, "")
	t.Setenv(EnvVMCtlDefault, "/repo/uat/access/vmctl.sh")
	t.Setenv(EnvReleaseTag, "v0.1.0-rc.4")
	env, err := LoadDir(material(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if env.InternalAuth != "s3cret" {
		t.Errorf("internal auth %q", env.InternalAuth)
	}
	if env.SaaSAPIURL != "https://uatab12cd-core.centralindia.cloudapp.azure.com" || env.EnvoyURL != "https://uatab12cd-dmz.centralindia.cloudapp.azure.com" {
		t.Errorf("default URLs %s %s", env.SaaSAPIURL, env.EnvoyURL)
	}
	// keycloak.json's tenant_id wins over tenants.json; tenants.json fills
	// the gap.
	if env.TenantID(1) != "t_aaaaaaaaaaaaaaaa" || env.TenantID(2) != "t_bbbbbbbbbbbbbbbb" {
		t.Errorf("tenant IDs %q %q", env.TenantID(1), env.TenantID(2))
	}
	var names []string
	for _, s := range env.Sprouts {
		names = append(names, s.Name())
	}
	if got := strings.Join(names, " "); got != "t1-ubuntu t1-alma t2-windows.t2-win" {
		t.Errorf("sprouts in order: %s", got)
	}
	if env.Sprouts[2].Tenant != 2 || !env.Sprouts[2].IsWindows() || env.Sprouts[2].Family() != FamilyWindows {
		t.Errorf("windows sprout %+v", env.Sprouts[2])
	}
	if env.Sprouts[0].AssetID != "uat-ab12cd-t1-ubuntu" {
		t.Errorf("asset ID %q", env.Sprouts[0].AssetID)
	}
	if env.VMCtlPath != "/repo/uat/access/vmctl.sh" || env.ReleaseTag != "v0.1.0-rc.4" {
		t.Errorf("vmctl %q tag %q", env.VMCtlPath, env.ReleaseTag)
	}
	if env.CAPool != nil {
		t.Errorf("no uat-ca.pem should mean the system roots")
	}
	host, port, err := env.SproutEnvoyHostPort()
	if err != nil || host != "uatab12cd-dmz.centralindia.cloudapp.azure.com" || port != "443" {
		t.Errorf("envoy %s %s %v", host, port, err)
	}
	if len(env.CoreProbePorts()) == 0 {
		t.Error("no default core probe ports")
	}
	if got := env.Tenants(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("tenants %v", got)
	}
}

func TestLoadDirOverrides(t *testing.T) {
	t.Setenv(EnvVMCtl, "")
	t.Setenv(EnvVMCtlDefault, "/default/vmctl.sh")
	dir := material(t, map[string]string{
		FileSettings: `{"saasapi_url": "https://saas.example/", "envoy_url": "https://envoy.example:8443",
			"vmctl": "rig/vmctl.sh", "core_probe_ports": [443], "restart": {"farmer": {"command": "true"}}}`,
		FileSprouts: `{"t1-alma": {"sprout_id": "alma-01", "asset_id": "custom-asset"}}`,
	})
	env, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if env.SaaSAPIURL != "https://saas.example" || env.EnvoyURL != "https://envoy.example:8443" {
		t.Errorf("URLs %s %s", env.SaaSAPIURL, env.EnvoyURL)
	}
	if env.VMCtlPath != filepath.Join(dir, "rig/vmctl.sh") {
		t.Errorf("harness.json's vmctl should beat the default: %s", env.VMCtlPath)
	}
	if _, port, _ := env.SproutEnvoyHostPort(); port != "8443" {
		t.Errorf("envoy port %s", port)
	}
	for _, s := range env.Sprouts {
		if s.VM == "t1-alma" && (s.SproutID != "alma-01" || s.AssetID != "custom-asset") {
			t.Errorf("override not applied: %+v", s)
		}
	}
	t.Setenv(EnvVMCtl, "/explicit/vmctl.sh")
	if env, err = LoadDir(dir); err != nil || env.VMCtlPath != "/explicit/vmctl.sh" {
		t.Errorf("$IMAS_UAT_VMCTL should win: %v %v", env, err)
	}
}

func TestLoadDirErrors(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no secret", map[string]string{FileInternalAuth: "  \n"}, "is empty"},
		{"unknown harness.json field", map[string]string{FileSettings: `{"saasapi": "x"}`}, "unknown field"},
		{"sprouts.json names a missing VM", map[string]string{FileSprouts: `{"t9-x": {}}`}, "doesn't have"},
		{"no tenant 2 ID", map[string]string{FileTenants: `{}`}, "no tenant ID for tenant 2"},
		{"bad tenant", map[string]string{FileUAT: `{"sprouts": {"x": {"tenant": 3, "os": "ubuntu"}}}`}, "tenant must be 1 or 2"},
		{"bad os", map[string]string{FileUAT: `{"sprouts": {"x": {"tenant": 1, "os": "suse"}}}`}, "os must be"},
		{"no admin", map[string]string{FileKeycloak: `{"issuer": "https://k/realms/r", "client_id": "c", "tenants": {"1": {"tenant_id": "t_a"}}}`}, "admin needs"},
		{"bad issuer", map[string]string{FileKeycloak: `{"issuer": "https://k/auth", "client_id": "c"}`}, "/realms/"},
		{"bad CA", map[string]string{FileCA: "not pem"}, "no PEM"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadDir(material(t, c.files))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
	t.Run("no dir variable", func(t *testing.T) {
		t.Setenv(EnvDir, "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), EnvDir) {
			t.Errorf("want an error naming %s, got %v", EnvDir, err)
		}
	})
	t.Run("missing uat.json", func(t *testing.T) {
		if _, err := LoadDir(t.TempDir()); err == nil {
			t.Error("want an error")
		}
	})
}

func TestParseUATWrapped(t *testing.T) {
	for name, raw := range map[string]string{
		"bare":       sampleUAT,
		"value":      `{"sensitive": false, "type": "object", "value": ` + sampleUAT + `}`,
		"all output": `{"uat": {"sensitive": false, "value": ` + sampleUAT + `}}`,
	} {
		u, err := ParseUAT([]byte(raw))
		if err != nil || u.RunID != "ab12cd" || len(u.Sprouts) != 3 || u.DMZ.PrivateIP != "10.60.1.4" {
			t.Errorf("%s: %+v %v", name, u, err)
		}
	}
	if _, err := ParseUAT([]byte(`[]`)); err == nil {
		t.Error("an array should be refused")
	}
}

func TestSplitIssuer(t *testing.T) {
	for issuer, want := range map[string][2]string{
		"https://h/realms/imas-uat":         {"https://h", "imas-uat"},
		"https://h:8443/auth/realms/r/":     {"https://h:8443/auth", "r"},
		"https://core.example/realms/x?y=1": {"https://core.example", "x"},
	} {
		base, realm, err := splitIssuer(issuer)
		if err != nil || base != want[0] || realm != want[1] {
			t.Errorf("%s: %s %s %v", issuer, base, realm, err)
		}
	}
	for _, bad := range []string{"", "/realms/x", "https://h/", "https://h/realms/", "https://h/realms/a/b"} {
		if _, _, err := splitIssuer(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestSproutHelpers(t *testing.T) {
	w := Sprout{VM: "t2-win", Tenant: 2, OS: OSWindows}
	l := Sprout{VM: "t1-ubuntu", Tenant: 1, OS: OSUbuntu}
	if w.TempPath("x") != `C:\Windows\Temp\x` || l.TempPath("x") != "/var/tmp/x" {
		t.Errorf("temp paths %s %s", w.TempPath("x"), l.TempPath("x"))
	}
	if w.Name() != "t2-windows.t2-win" || l.Name() != "t1-ubuntu" {
		t.Errorf("names %s %s", w.Name(), l.Name())
	}
	if DefaultAssetID("AB12", "T1-Ubuntu") != "uat-ab12-t1-ubuntu" || DefaultAssetID("", "vm") != "uat-vm" {
		t.Error("DefaultAssetID")
	}
}
