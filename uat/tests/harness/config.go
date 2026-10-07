package harness

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Environment variables the harness reads.
const (
	// EnvDir names the material directory (uat/tests/README.md).
	EnvDir = "IMAS_UAT_DIR"
	// EnvVMCtl is the path of the vmctl.sh to use (the Access interface of
	// the plan's Shared contract). run.sh defaults it to uat/access/vmctl.sh;
	// the local rig (UAT.8) points it at its own.
	EnvVMCtl = "IMAS_UAT_VMCTL"
	// EnvVMCtlDefault is the vmctl.sh used when neither $IMAS_UAT_VMCTL
	// nor harness.json names one; run.sh sets it to uat/access/vmctl.sh.
	EnvVMCtlDefault = "IMAS_UAT_VMCTL_DEFAULT"
	// EnvReleaseTag, when set, is the release (vX.Y.Z or vX.Y.Z-rc.N) the
	// sprouts must be running (scenario S1).
	EnvReleaseTag = "IMAS_UAT_RELEASE_TAG"
)

// File names inside the material directory.
const (
	FileUAT          = "uat.json"
	FileKeycloak     = "keycloak.json"
	FileSettings     = "harness.json"
	FileTenants      = "tenants.json"
	FileSprouts      = "sprouts.json"
	FileInternalAuth = "internal-auth-secret"
	FileCA           = "uat-ca.pem"
)

// Operating systems of the contract's sprouts, as uat.json names them.
const (
	OSUbuntu  = "ubuntu"
	OSAlma    = "alma"
	OSWindows = "windows"
)

// Families group the OSes by the shell a host script is written for.
const (
	FamilyLinux   = "linux"
	FamilyWindows = "windows"
)

// Host is a hub VM (dmz or core) in uat.json.
type Host struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	PrivateIP string `json:"private_ip"`
	PublicIP  string `json:"public_ip"`
	FQDN      string `json:"fqdn"`
	AdminUser string `json:"admin_user"`
}

// SproutVM is one entry of uat.json's sprouts map (keyed by VM name).
type SproutVM struct {
	Tenant     FlexInt `json:"tenant"`
	OS         string  `json:"os"`
	Connection string  `json:"connection"`
	ID         string  `json:"id"`
	PrivateIP  string  `json:"private_ip"`
	PublicIP   string  `json:"public_ip"`
	AdminUser  string  `json:"admin_user"`
}

// UAT is the tofu output uat object of the Shared contract. Fields the
// harness doesn't use (bastion, subnets) are kept raw.
type UAT struct {
	RunID         string              `json:"run_id"`
	Region        string              `json:"region"`
	ResourceGroup string              `json:"resource_group"`
	DMZ           Host                `json:"dmz"`
	Core          Host                `json:"core"`
	Sprouts       map[string]SproutVM `json:"sprouts"`
	Bastion       json.RawMessage     `json:"bastion,omitempty"`
	Subnets       json.RawMessage     `json:"subnets,omitempty"`
}

// FlexInt decodes a JSON number or a string holding one ("1"), since the
// contract says "tenant 1 or 2" without fixing the type.
type FlexInt int

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("not an integer: %s", b)
	}
	*f = FlexInt(n)
	return nil
}

// Credentials is a Keycloak user of the realm.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c Credentials) set() bool { return c.Username != "" && c.Password != "" }

// ClientCreds is a Keycloak client. ClientSecret is empty for a public client.
type ClientCreds struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// KeycloakAdmin is an identity allowed to manage users in the test realm,
// used only to create scratch users for tenants a test creates (T1, T4,
// T5). Either Username/Password (password grant) or ClientSecret (client
// credentials grant of a service account client) is given. Realm is where
// that identity lives: "master" for the bootstrap admin, or the test realm
// for a service account with realm-management roles.
type KeycloakAdmin struct {
	Realm        string `json:"realm"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
}

// KeycloakTenant is one of the run's two tenants: its saasapi tenant ID
// and its users. Admin holds both recipe roles; ReadOnly holds only the
// read role.
type KeycloakTenant struct {
	TenantID string      `json:"tenant_id,omitempty"`
	Admin    Credentials `json:"admin"`
	ReadOnly Credentials `json:"readonly"`
}

// KeycloakConfig is keycloak.json.
type KeycloakConfig struct {
	// Issuer is the realm URL, exactly the token's iss
	// (https://<core fqdn>/realms/imas-uat).
	Issuer string `json:"issuer"`
	// ClientID and ClientSecret are the client the tests get user tokens
	// from (password grant, "direct access grants" on), whose tokens carry
	// saasapi's audience.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	// TenantAttribute is the user attribute the realm maps to the
	// organization.id claim. Needed only for scratch users.
	TenantAttribute string `json:"tenant_attribute,omitempty"`
	// Admin manages scratch users. Optional: without it, the scenarios
	// that need a token for a tenant they create skip with that reason.
	Admin *KeycloakAdmin `json:"admin,omitempty"`
	// OtherAudienceClient issues tokens without saasapi's audience
	// (scenario X1). Optional.
	OtherAudienceClient *ClientCreds `json:"other_audience_client,omitempty"`
	// Tenants is keyed "1" and "2".
	Tenants map[string]KeycloakTenant `json:"tenants"`
}

// RestartCommand is a command run on a hub VM through vmctl.sh to restart
// a workload (scenarios L2 and L3).
type RestartCommand struct {
	VM      string `json:"vm"`
	Command string `json:"command"`
}

// Settings is harness.json. Every field is optional.
type Settings struct {
	// SaaSAPIURL is saasapi's base URL, without /v1. Default
	// https://<core fqdn>.
	SaaSAPIURL string `json:"saasapi_url,omitempty"`
	// EnvoyURL is Envoy's base URL as the runner reaches it. Default
	// https://<dmz fqdn>:8443 (DefaultEnvoyPort: Envoy is node port 8443,
	// owner decision 2026-10-06; 443 is core's).
	EnvoyURL string `json:"envoy_url,omitempty"`
	// SproutEnvoyAddress is host:port of Envoy as the sprouts reach it
	// (the positive control of X3). Default: EnvoyURL's host and port, and
	// DefaultEnvoyPort when EnvoyURL names none.
	SproutEnvoyAddress string `json:"sprout_envoy_address,omitempty"`
	// CAFile is the run's CA, relative to the material directory. Default
	// uat-ca.pem if present, else the system roots.
	CAFile string `json:"ca_file,omitempty"`
	// InternalAuthSecretFile holds saasapi's X-Internal-Auth secret.
	// Default internal-auth-secret.
	InternalAuthSecretFile string `json:"internal_auth_secret_file,omitempty"`
	// VMCtl is the vmctl.sh path, when $IMAS_UAT_VMCTL is not set. It
	// wins over $IMAS_UAT_VMCTL_DEFAULT (run.sh's uat/access/vmctl.sh).
	VMCtl string `json:"vmctl,omitempty"`
	// CoreProbePorts are the ports X3 checks a sprout can't open on core.
	CoreProbePorts []int `json:"core_probe_ports,omitempty"`
	// Restart overrides the commands of DefaultRestartCommands, keyed
	// "farmer", "farmerbus" and "envoy".
	Restart map[string]RestartCommand `json:"restart,omitempty"`
	// BindTenant says how to run uat/hub/core/bind-tenant.sh.
	BindTenant BindConfig `json:"bind_tenant,omitempty"`
}

// SproutOverride is one entry of sprouts.json, keyed by VM name.
type SproutOverride struct {
	SproutID string `json:"sprout_id,omitempty"`
	AssetID  string `json:"asset_id,omitempty"`
}

// Sprout is one sprout of the run.
type Sprout struct {
	VM         string
	Tenant     int
	OS         string
	Connection string
	PrivateIP  string
	PublicIP   string
	// SproutID is the ID farmer gave the sprout: from sprouts.json, or
	// read from the host by Fleet.Prepare. Empty until then.
	SproutID string
	// AssetID is the asset ID the harness links to the sprout:
	// sprouts.json's, or "uat-<run_id>-<vm>".
	AssetID string
}

// Family is FamilyWindows or FamilyLinux.
func (s Sprout) Family() string {
	if s.OS == OSWindows {
		return FamilyWindows
	}
	return FamilyLinux
}

// IsWindows reports whether the sprout runs Windows.
func (s Sprout) IsWindows() bool { return s.OS == OSWindows }

// Name is the sprout's subtest name: "t<tenant>-<os>", with ".<vm>"
// appended when the VM is named otherwise, so a report line can always
// read the OS and the tenant from it.
func (s Sprout) Name() string {
	base := fmt.Sprintf("t%d-%s", s.Tenant, s.OS)
	if s.VM != base {
		return base + "." + s.VM
	}
	return base
}

// TempDir is a directory every sprout of the family can write to as the
// sprout's user (root, or LocalSystem).
func (s Sprout) TempDir() string {
	if s.IsWindows() {
		return `C:\Windows\Temp`
	}
	return "/var/tmp"
}

// TempPath joins name to TempDir with the host's separator.
func (s Sprout) TempPath(name string) string {
	if s.IsWindows() {
		return s.TempDir() + `\` + name
	}
	return s.TempDir() + "/" + name
}

// Env is everything the harness loaded from the material directory.
type Env struct {
	Dir          string
	UATFile      string
	UAT          UAT
	Keycloak     KeycloakConfig
	Settings     Settings
	InternalAuth string
	// CAPool is the run's CA, or nil for the system roots.
	CAPool *x509.CertPool
	// VMCtlPath is the vmctl.sh the harness runs; empty if none was given
	// (scenarios that need it then fail, naming the variable).
	VMCtlPath  string
	ReleaseTag string
	SaaSAPIURL string
	EnvoyURL   string
	// Sprouts in a stable order: tenant, OS, VM name.
	Sprouts []Sprout
	// Core is uat/hub/core's core.json when one was found, at CorePath.
	Core     *CoreJSON
	CorePath string
	// Bind is how to run bind-tenant.sh; see BindConfig.
	Bind      BindConfig
	tenantIDs map[int]string
}

// TenantID is the saasapi ID of tenant 1 or 2, or "" if unknown.
func (e *Env) TenantID(n int) string { return e.tenantIDs[n] }

// Tenants lists the tenant numbers that have sprouts or an ID, ascending.
func (e *Env) Tenants() []int {
	seen := map[int]bool{}
	for n := range e.tenantIDs {
		seen[n] = true
	}
	for _, s := range e.Sprouts {
		seen[s.Tenant] = true
	}
	var out []int
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// Load reads the material directory named by $IMAS_UAT_DIR.
func Load() (*Env, error) {
	dir := os.Getenv(EnvDir)
	if dir == "" {
		return nil, fmt.Errorf("harness: %s is not set; it names the directory holding uat.json, keycloak.json and the rest (uat/tests/README.md)", EnvDir)
	}
	return LoadDir(dir)
}

// LoadDir reads a material directory. $IMAS_UAT_VMCTL and
// $IMAS_UAT_RELEASE_TAG are read from the environment.
func LoadDir(dir string) (*Env, error) {
	env := &Env{Dir: dir, UATFile: filepath.Join(dir, FileUAT), tenantIDs: map[int]string{}}

	raw, err := os.ReadFile(env.UATFile)
	if err != nil {
		return nil, fmt.Errorf("harness: reading %s: %w", env.UATFile, err)
	}
	if env.UAT, err = ParseUAT(raw); err != nil {
		return nil, fmt.Errorf("harness: %s: %w", env.UATFile, err)
	}
	if err := readJSON(filepath.Join(dir, FileSettings), &env.Settings, false, true); err != nil {
		return nil, err
	}

	// Keycloak: uat/hub/core's core.json and credentials.json, with
	// keycloak.json, when there is one, laid over them.
	core, corePath, stateRoot, err := findCore(dir)
	if err != nil {
		return nil, err
	}
	creds, err := findCredentials(dir, core)
	if err != nil {
		return nil, err
	}
	env.Core, env.CorePath = core, corePath
	var kcFile KeycloakConfig
	kcPath := findKeycloakJSON(dir, core)
	haveKC := kcPath != ""
	if haveKC {
		if err := readJSON(kcPath, &kcFile, true, false); err != nil {
			return nil, err
		}
	}
	switch {
	case core != nil:
		env.Keycloak = mergeKeycloak(keycloakFromCore(core, creds), kcFile)
	case haveKC:
		env.Keycloak = kcFile
	default:
		return nil, fmt.Errorf("harness: %s has neither keycloak.json nor core.json (uat/hub/core's out/core.json, here or under core/out/)", dir)
	}

	secretFile := env.Settings.InternalAuthSecretFile
	if secretFile == "" {
		secretFile = FileInternalAuth
	}
	secret, err := os.ReadFile(resolve(dir, secretFile))
	switch {
	case err == nil:
		env.InternalAuth = strings.TrimSpace(string(secret))
	case errors.Is(err, os.ErrNotExist) && env.Settings.InternalAuthSecretFile == "" && creds != nil:
		env.InternalAuth = strings.TrimSpace(creds.InternalAuthSecret)
	default:
		return nil, fmt.Errorf("harness: reading saasapi's internal auth secret (%s, or internal_auth_secret in credentials.json): %w", secretFile, err)
	}
	if env.InternalAuth == "" {
		return nil, fmt.Errorf("harness: saasapi's internal auth secret is empty")
	}

	caFile := env.Settings.CAFile
	if caFile == "" && core != nil && core.CAFile != "" {
		if _, err := os.Stat(filepath.Join(dir, FileCA)); err != nil {
			caFile = core.CAFile
			if !filepath.IsAbs(caFile) {
				caFile = filepath.Join(filepath.Dir(corePath), caFile)
			}
		}
	}
	if env.CAPool, err = loadCA(dir, caFile); err != nil {
		return nil, err
	}

	env.Bind = env.Settings.BindTenant
	if v := os.Getenv(EnvBindTenant); v != "" {
		env.Bind.Script = v
	}
	if env.Bind.Script == "" {
		env.Bind.Script = os.Getenv(EnvBindTenantDefault)
	}
	if env.Bind.Kubeconfig == "" {
		env.Bind.Kubeconfig = os.Getenv(EnvCoreKubeconfig)
	}
	if env.Bind.Endpoints == "" {
		env.Bind.Endpoints = os.Getenv(EnvEndpoints)
	}
	if env.Bind.StateDir == "" {
		env.Bind.StateDir = stateRoot
	}

	env.VMCtlPath = os.Getenv(EnvVMCtl)
	if env.VMCtlPath == "" && env.Settings.VMCtl != "" {
		env.VMCtlPath = resolve(dir, env.Settings.VMCtl)
	}
	if env.VMCtlPath == "" {
		env.VMCtlPath = os.Getenv(EnvVMCtlDefault)
	}
	env.ReleaseTag = os.Getenv(EnvReleaseTag)

	env.SaaSAPIURL = strings.TrimRight(env.Settings.SaaSAPIURL, "/")
	if env.SaaSAPIURL == "" && core != nil {
		env.SaaSAPIURL = strings.TrimRight(core.SaaSAPIURL, "/")
	}
	if env.SaaSAPIURL == "" && env.UAT.Core.FQDN != "" {
		env.SaaSAPIURL = "https://" + env.UAT.Core.FQDN
	}
	env.EnvoyURL = strings.TrimRight(env.Settings.EnvoyURL, "/")
	if env.EnvoyURL == "" && env.UAT.DMZ.FQDN != "" {
		env.EnvoyURL = "https://" + net.JoinHostPort(env.UAT.DMZ.FQDN, DefaultEnvoyPort)
	}
	if env.SaaSAPIURL == "" {
		return nil, errors.New("harness: no saasapi URL: set saasapi_url in harness.json or core.fqdn in uat.json")
	}
	if env.EnvoyURL == "" {
		return nil, errors.New("harness: no Envoy URL: set envoy_url in harness.json or dmz.fqdn in uat.json")
	}

	if err := env.loadTenants(); err != nil {
		return nil, err
	}
	if err := env.loadSprouts(); err != nil {
		return nil, err
	}
	if err := env.validateKeycloak(); err != nil {
		return nil, err
	}
	return env, nil
}

// ParseUAT decodes tofu's uat output. It accepts the object itself
// (tofu output -json uat), or wrapped as {"value": {...}} or
// {"uat": {"value": {...}}} (tofu output -json).
func ParseUAT(raw []byte) (UAT, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return UAT{}, fmt.Errorf("not a JSON object: %w", err)
	}
	if inner, ok := probe["uat"]; ok {
		raw = inner
		probe = nil
		if err := json.Unmarshal(raw, &probe); err != nil {
			return UAT{}, fmt.Errorf("uat is not an object: %w", err)
		}
	}
	if v, ok := probe["value"]; ok {
		if _, hasSprouts := probe["sprouts"]; !hasSprouts {
			raw = v
		}
	}
	var u UAT
	if err := json.Unmarshal(raw, &u); err != nil {
		return UAT{}, err
	}
	if len(u.Sprouts) == 0 {
		return UAT{}, errors.New("no sprouts")
	}
	for name, s := range u.Sprouts {
		if s.Tenant != 1 && s.Tenant != 2 {
			return UAT{}, fmt.Errorf("sprout %s: tenant must be 1 or 2, got %d", name, s.Tenant)
		}
		switch s.OS {
		case OSUbuntu, OSAlma, OSWindows:
		default:
			return UAT{}, fmt.Errorf("sprout %s: os must be ubuntu, alma or windows, got %q", name, s.OS)
		}
	}
	return u, nil
}

func (e *Env) loadTenants() error {
	for key, t := range e.Keycloak.Tenants {
		n, err := strconv.Atoi(key)
		if err != nil {
			return fmt.Errorf("harness: keycloak.json tenants: key %q is not 1 or 2", key)
		}
		if t.TenantID != "" {
			e.tenantIDs[n] = t.TenantID
		}
	}
	var ids map[string]json.RawMessage
	if err := readJSON(filepath.Join(e.Dir, FileTenants), &ids, false, false); err != nil {
		return err
	}
	for key, raw := range ids {
		n, err := strconv.Atoi(key)
		if err != nil {
			return fmt.Errorf("harness: tenants.json: key %q is not 1 or 2", key)
		}
		// {"1": "t_..."} or {"1": {"tenant_id": "t_..."}}.
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			var obj struct {
				TenantID string `json:"tenant_id"`
			}
			if err := json.Unmarshal(raw, &obj); err != nil {
				return fmt.Errorf("harness: tenants.json: %q: %w", key, err)
			}
			id = obj.TenantID
		}
		if id != "" && e.tenantIDs[n] == "" {
			e.tenantIDs[n] = id
		}
	}
	if e.Core != nil {
		for key, id := range e.Core.Tenants {
			if n, err := strconv.Atoi(key); err == nil && id != "" && e.tenantIDs[n] == "" {
				e.tenantIDs[n] = id
			}
		}
	}
	for _, n := range []int{1, 2} {
		if e.tenantIDs[n] == "" {
			return fmt.Errorf("harness: no tenant ID for tenant %d: set tenants.%d.tenant_id in keycloak.json, %q in tenants.json, or bind it with bind-tenant.sh (core.json's tenants)", n, n, strconv.Itoa(n))
		}
	}
	return nil
}

func (e *Env) loadSprouts() error {
	var overrides map[string]SproutOverride
	if err := readJSON(filepath.Join(e.Dir, FileSprouts), &overrides, false, true); err != nil {
		return err
	}
	for name := range overrides {
		if _, ok := e.UAT.Sprouts[name]; !ok {
			return fmt.Errorf("harness: sprouts.json names %q, which uat.json doesn't have", name)
		}
	}
	for name, vm := range e.UAT.Sprouts {
		s := Sprout{
			VM: name, Tenant: int(vm.Tenant), OS: vm.OS, Connection: vm.Connection,
			PrivateIP: vm.PrivateIP, PublicIP: vm.PublicIP,
		}
		o := overrides[name]
		s.SproutID = o.SproutID
		s.AssetID = o.AssetID
		if s.AssetID == "" {
			s.AssetID = DefaultAssetID(e.UAT.RunID, name)
		}
		e.Sprouts = append(e.Sprouts, s)
	}
	sort.Slice(e.Sprouts, func(i, j int) bool {
		a, b := e.Sprouts[i], e.Sprouts[j]
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		if a.OS != b.OS {
			return osOrder(a.OS) < osOrder(b.OS)
		}
		return a.VM < b.VM
	})
	return nil
}

func osOrder(os string) int {
	switch os {
	case OSUbuntu:
		return 0
	case OSAlma:
		return 1
	default:
		return 2
	}
}

// DefaultAssetID is the asset ID the harness links to a sprout when
// sprouts.json gives none. Asset IDs are global in saasapi, so it carries
// the run ID and the VM name, which differ between the two tenants'
// sprouts that share a sprout ID.
func DefaultAssetID(runID, vm string) string {
	id := "uat-" + strings.ToLower(runID) + "-" + strings.ToLower(vm)
	if runID == "" {
		id = "uat-" + strings.ToLower(vm)
	}
	return id
}

func (e *Env) validateKeycloak() error {
	k := &e.Keycloak
	if k.Issuer == "" || k.ClientID == "" {
		return errors.New("harness: keycloak.json needs issuer and client_id")
	}
	if _, _, err := splitIssuer(k.Issuer); err != nil {
		return fmt.Errorf("harness: keycloak.json issuer: %w", err)
	}
	for _, n := range []int{1, 2} {
		t := k.Tenants[strconv.Itoa(n)]
		if !t.Admin.set() {
			return fmt.Errorf("harness: keycloak.json tenants.%d.admin needs username and password", n)
		}
	}
	return nil
}

// DefaultEnvoyPort is the port Envoy answers on when nothing says
// otherwise: the DMZ node port 8443 (Shared contract, owner decisions
// 2026-10-06). It is not 443, which is core's saasapi and Keycloak port.
const DefaultEnvoyPort = "8443"

// SproutEnvoyHostPort is the host and port of Envoy as a sprout dials it.
func (e *Env) SproutEnvoyHostPort() (string, string, error) {
	if a := e.Settings.SproutEnvoyAddress; a != "" {
		return net.SplitHostPort(a)
	}
	u, err := url.Parse(e.EnvoyURL)
	if err != nil {
		return "", "", err
	}
	port := u.Port()
	if port == "" {
		port = DefaultEnvoyPort
	}
	return u.Hostname(), port, nil
}

// CoreProbePorts are the ports scenario X3 expects a sprout can't open on
// core: harness.json's, or saasapi and Keycloak's 443, farmer's API 5405,
// the Kubernetes API 6443, saasapi's own 8081, OpenBao's 8200, PXC's 3306
// and SSH.
func (e *Env) CoreProbePorts() []int {
	if len(e.Settings.CoreProbePorts) > 0 {
		return e.Settings.CoreProbePorts
	}
	return []int{22, 443, 3306, 5405, 6443, 8081, 8200}
}

// readJSON decodes path into v. A missing optional file leaves v alone.
// strict refuses unknown fields: on for the files this harness defines
// (harness.json, sprouts.json), off for the ones other briefs write.
func readJSON(path string, v any, required, strict bool) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("harness: reading %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("harness: %s: %w", path, err)
	}
	return nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

func loadCA(dir, file string) (*x509.CertPool, error) {
	explicit := file != ""
	if !explicit {
		file = FileCA
	}
	pem, err := os.ReadFile(resolve(dir, file))
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("harness: reading the CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("harness: %s holds no PEM certificate", file)
	}
	return pool, nil
}

// splitIssuer splits a Keycloak issuer URL into the server base URL and
// the realm: https://h/realms/r gives https://h and r, and
// https://h/auth/realms/r gives https://h/auth and r.
func splitIssuer(issuer string) (base, realm string, err error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("%q is not an absolute URL", issuer)
	}
	i := strings.LastIndex(u.Path, "/realms/")
	if i < 0 {
		return "", "", fmt.Errorf("%q has no /realms/<realm> path", issuer)
	}
	realm = strings.Trim(u.Path[i+len("/realms/"):], "/")
	if realm == "" || strings.Contains(realm, "/") {
		return "", "", fmt.Errorf("%q has no single realm after /realms/", issuer)
	}
	u.Path = u.Path[:i]
	u.RawQuery, u.Fragment = "", ""
	return strings.TrimRight(u.String(), "/"), realm, nil
}
