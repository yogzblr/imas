// Package core holds the UAT core hub's static checks (UAT.3b): the
// imas-uat realm file against what saasapi expects, and helm template of
// deploy/helm/farmer with values/farmer-uat.yaml and of the UAT-only chart
// in chart/, rendered with the run values the scripts themselves produce
// (gen-values.sh, extras_set_args) from testdata/endpoints.json.
//
// The helm tests skip when helm, bash or jq is missing, unless
// IMAS_REQUIRE_HELM=1 (as CI sets for the chart tests). Nothing here
// reaches a cluster.
package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	endpointsFile = "testdata/endpoints.json"
	adminFile     = "testdata/admin.json"
	releaseTag    = "v0.1.0-rc.4"
	version       = "0.1.0-rc.4"
	coreFQDN      = "uatabc123-core.centralindia.cloudapp.azure.com"
	coreIP        = "10.60.2.4"
	dmzFQDN       = "uatabc123-dmz.centralindia.cloudapp.azure.com"
	dmzIP         = "10.60.1.4"
	issuer        = "https://" + coreFQDN + "/realms/imas-uat"
)

// --- helpers -------------------------------------------------------------

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

// dig walks nested maps by key.
func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func str(v any, keys ...string) string {
	s, _ := dig(v, keys...).(string)
	return s
}

// libConstants reads NAME=value lines from lib/common.sh.
func libConstants(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("lib/common.sh")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]*)=([A-Za-z0-9._-]+)\s*(#.*)?$`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = m[2]
	}
	return out
}

type realmFile struct {
	Realm      string            `json:"realm"`
	Attributes map[string]string `json:"attributes"`
	Roles      struct {
		Realm []struct {
			Name string `json:"name"`
		} `json:"realm"`
	} `json:"roles"`
	Clients []struct {
		ClientID        string `json:"clientId"`
		ProtocolMappers []struct {
			ProtocolMapper string            `json:"protocolMapper"`
			Config         map[string]string `json:"config"`
		} `json:"protocolMappers"`
	} `json:"clients"`
	Users []struct {
		Username   string   `json:"username"`
		RealmRoles []string `json:"realmRoles"`
	} `json:"users"`
}

func loadRealm(t *testing.T) realmFile {
	t.Helper()
	var r realmFile
	readJSON(t, "chart/files/imas-uat-realm.json", &r)
	return r
}

// --- no tools needed -------------------------------------------------------

// TestRealmMatchesSaaSAPI ties the realm to what saasapi reads: the role
// names the farmer chart gives saasapi (its defaults and this layout's
// values), the audience and the organization.id claim.
func TestRealmMatchesSaaSAPI(t *testing.T) {
	r := loadRealm(t)
	if r.Realm != "imas-uat" {
		t.Errorf("realm %q, want imas-uat", r.Realm)
	}
	if r.Attributes["frontendUrl"] != "${UAT_KEYCLOAK_URL}" {
		t.Errorf("frontendUrl %q: the issuer base must be the per-run core FQDN URL", r.Attributes["frontendUrl"])
	}
	chartDefaults := readYAML(t, "../../../deploy/helm/farmer/values.yaml")
	uat := readYAML(t, "values/farmer-uat.yaml")
	readRole := str(chartDefaults, "saasapi", "recipes", "readRole")
	writeRole := str(chartDefaults, "saasapi", "recipes", "writeRole")
	if readRole == "" || writeRole == "" {
		t.Fatal("deploy/helm/farmer/values.yaml has no saasapi.recipes.readRole/writeRole")
	}
	if got := str(uat, "saasapi", "recipes", "readRole"); got != readRole {
		t.Errorf("values/farmer-uat.yaml readRole %q, chart default %q", got, readRole)
	}
	if got := str(uat, "saasapi", "recipes", "writeRole"); got != writeRole {
		t.Errorf("values/farmer-uat.yaml writeRole %q, chart default %q", got, writeRole)
	}
	var roles []string
	for _, x := range r.Roles.Realm {
		roles = append(roles, x.Name)
	}
	if strings.Join(roles, ",") != readRole+","+writeRole {
		t.Errorf("realm roles %v, want [%s %s]", roles, readRole, writeRole)
	}
	has := func(rs []string, want string) bool {
		for _, x := range rs {
			if x == want {
				return true
			}
		}
		return false
	}
	for _, u := range r.Users {
		admin := strings.HasSuffix(u.Username, "-admin")
		if !has(u.RealmRoles, readRole) || has(u.RealmRoles, writeRole) != admin {
			t.Errorf("user %s roles %v", u.Username, u.RealmRoles)
		}
	}
	lib := libConstants(t)
	var aud, org bool
	for _, c := range r.Clients {
		if c.ClientID != lib["TESTS_CLIENT"] {
			continue
		}
		for _, m := range c.ProtocolMappers {
			switch m.ProtocolMapper {
			case "oidc-audience-mapper":
				aud = m.Config["included.client.audience"] == lib["SAASAPI_AUDIENCE"]
			case "oidc-usermodel-attribute-mapper":
				org = m.Config["claim.name"] == "organization.id" && m.Config["user.attribute"] == "organization_id"
			}
		}
	}
	if !aud {
		t.Errorf("client %s has no audience mapper for %s", lib["TESTS_CLIENT"], lib["SAASAPI_AUDIENCE"])
	}
	if !org {
		t.Errorf("client %s does not map organization_id to organization.id (docs/api/saasapi.md)", lib["TESTS_CLIENT"])
	}
}

// TestValuesMatchLib keeps values/farmer-uat.yaml and lib/common.sh's names
// in step: the scripts create what the chart is told to use.
func TestValuesMatchLib(t *testing.T) {
	lib := libConstants(t)
	v := readYAML(t, "values/farmer-uat.yaml")
	for path, name := range map[string]string{
		"objectStore.bucket":                    "RECIPE_BUCKET",
		"objectStore.jobBucket":                 "JOB_BUCKET",
		"objectStore.credentialsSecret":         "S3_FARMER_SECRET",
		"saasapi.recipes.credentialsSecret":     "S3_SAASAPI_SECRET",
		"saasapi.recipes.readRole":              "READ_ROLE",
		"saasapi.recipes.writeRole":             "WRITE_ROLE",
		"saasapi.internalAuthSecret.secretName": "INTERNAL_AUTH_SECRET",
		"natsSeeds.secretName":                  "SEEDS_SECRET",
		"tls.secretName":                        "FARMER_TLS_SECRET",
		"openbaoBootstrap.tokenSecretName":      "OPENBAO_ROOT_SECRET",
		"farmer.bootstrapAdmin.username":        "BOOTSTRAP_ADMIN_NAME",
	} {
		if got := str(v, strings.Split(path, ".")...); got == "" || got != lib[name] {
			t.Errorf("%s = %q, lib/common.sh %s = %q", path, got, name, lib[name])
		}
	}
	want := lib["MINIO_SVC"] + "." + lib["UAT_NS"] + ".svc.cluster.local:9000"
	if got := str(v, "objectStore", "endpoint"); got != want {
		t.Errorf("objectStore.endpoint %q, want %q", got, want)
	}
	if dig(v, "openbao", "server", "dev", "enabled") != false {
		t.Error("openbao.server.dev.enabled must be false: the UAT OpenBao is initialised and unsealed for real")
	}
	if dig(v, "objectStore", "useSSL") != false {
		t.Error("objectStore.useSSL: MinIO is plain HTTP inside the cluster")
	}
	extras := readYAML(t, "chart/values.yaml")
	for path, want := range map[string]string{
		"farmer.serviceName":        lib["FARMER_FULLNAME"],
		"farmer.saasapiServiceName": lib["SAASAPI_FULLNAME"],
		"farmer.namespace":          lib["CORE_NS"],
		"farmer.release":            lib["CORE_RELEASE"],
		"farmer.tlsSecretName":      lib["FARMER_TLS_SECRET"],
		"minio.rootSecret":          lib["MINIO_ROOT_SECRET"],
		"keycloak.realm":            lib["REALM"],
		"keycloak.adminSecret":      lib["KEYCLOAK_ADMIN_SECRET"],
		"keycloak.realmEnvSecret":   lib["KEYCLOAK_REALM_SECRET"],
	} {
		if got := str(extras, strings.Split(path, ".")...); got != want {
			t.Errorf("chart/values.yaml %s = %q, want %q", path, got, want)
		}
	}
	for _, img := range []string{str(extras, "minio", "image"), str(extras, "keycloak", "image"), str(extras, "edge", "image")} {
		if !regexp.MustCompile(`^[a-z0-9./-]+:[A-Za-z0-9._-]+$`).MatchString(img) || strings.HasSuffix(img, ":latest") {
			t.Errorf("image %q is not pinned to a tag", img)
		}
	}
}

// --- helm -------------------------------------------------------------------

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("IMAS_REQUIRE_HELM") == "1" {
				t.Fatalf("%s not on PATH and IMAS_REQUIRE_HELM=1", tool)
			}
			t.Skipf("%s not on PATH", tool)
		}
	}
}

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// docs splits a rendered manifest stream into objects keyed "Kind/name".
func docs(t *testing.T, manifest []byte) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	dec := yaml.NewDecoder(bytes.NewReader(manifest))
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decoding rendered manifest: %v", err)
		}
		if d == nil {
			continue
		}
		out[str(d, "kind")+"/"+str(d, "metadata", "name")] = d
	}
	return out
}

func get(t *testing.T, objs map[string]map[string]any, key string) map[string]any {
	t.Helper()
	o, ok := objs[key]
	if !ok {
		t.Fatalf("rendered manifest has no %s", key)
	}
	return o
}

func containers(o map[string]any) []map[string]any {
	var out []map[string]any
	spec := dig(o, "spec", "template", "spec")
	for _, k := range []string{"containers", "initContainers"} {
		l, _ := dig(spec, k).([]any)
		for _, c := range l {
			if m, ok := c.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func envOf(c map[string]any) map[string]string {
	out := map[string]string{}
	l, _ := c["env"].([]any)
	for _, e := range l {
		m, _ := e.(map[string]any)
		name, _ := m["name"].(string)
		if v, ok := m["value"].(string); ok {
			out[name] = v
		} else if ref := str(m, "valueFrom", "secretKeyRef", "name"); ref != "" {
			out[name] = "secret:" + ref + "/" + str(m, "valueFrom", "secretKeyRef", "key")
		}
	}
	return out
}

func container(t *testing.T, o map[string]any, name string) map[string]any {
	t.Helper()
	for _, c := range containers(o) {
		if c["name"] == name {
			return c
		}
	}
	t.Fatalf("%s has no container %s", str(o, "metadata", "name"), name)
	return nil
}

// farmerChart returns a renderable copy of deploy/helm/farmer: as is when
// `helm dependency build` has filled charts/ (CI does), or with the
// subcharts stripped, which still renders every template of the chart.
func farmerChart(t *testing.T) (dir string, withSubcharts bool) {
	t.Helper()
	src, _ := filepath.Abs("../../../deploy/helm/farmer")
	if tgz, _ := filepath.Glob(filepath.Join(src, "charts", "*.tgz")); len(tgz) >= 4 {
		return src, true
	}
	dst := filepath.Join(t.TempDir(), "farmer")
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte("\ndependencies:"))
	if i < 0 {
		t.Fatal("Chart.yaml has no dependencies block")
	}
	if err := os.WriteFile(filepath.Join(dst, "Chart.yaml"), b[:i+1], 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dst, "Chart.lock"))
	return dst, false
}

func runValues(t *testing.T) string {
	t.Helper()
	out := run(t, "bash", "gen-values.sh", endpointsFile, adminFile, releaseTag)
	p := filepath.Join(t.TempDir(), "values-run.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFarmerChartRender renders deploy/helm/farmer the way install.sh
// installs it and checks the values that matter for this layout.
func TestFarmerChartRender(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")
	chart, full := farmerChart(t)
	args := []string{"template", "imas-core", chart, "-n", "imas-core", "--kube-version", "1.31.0",
		"-f", "values/farmer-uat.yaml", "-f", runValues(t)}
	objs := docs(t, run(t, "helm", args...))
	run(t, "helm", append([]string{"lint", chart, "--kube-version", "1.31.0"}, args[5:]...)...)

	// saasapi: Keycloak issuer, JWKS and audience on the core FQDN; the UAT
	// CA for that HTTPS fetch; the recipe roles of the realm; MinIO.
	saasapi := get(t, objs, "Deployment/imas-core-farmer-saasapi")
	se := envOf(container(t, saasapi, "saasapi"))
	for k, want := range map[string]string{
		"SAASAPI_JWT_ISSUER":               issuer,
		"SAASAPI_KEYCLOAK_JWKS_URL":        issuer + "/protocol/openid-connect/certs",
		"SAASAPI_JWT_AUDIENCE":             "imas-saasapi",
		"SSL_CERT_FILE":                    "/etc/imas-uat-ca/ca.crt",
		"SAASAPI_RECIPES_READ_ROLE":        "imas-recipes-read",
		"SAASAPI_RECIPES_WRITE_ROLE":       "imas-recipes-write",
		"SAASAPI_RECIPES_S3_ENDPOINT":      "imas-uat-minio.imas-uat.svc.cluster.local:9000",
		"SAASAPI_RECIPES_S3_BUCKET":        "imas-recipes",
		"SAASAPI_RECIPES_JOB_BUCKET":       "imas-jobs",
		"SAASAPI_RECIPES_S3_USE_SSL":       "false",
		"SAASAPI_RECIPES_CREDENTIAL_CHECK": "true",
		"SAASAPI_RECIPES_S3_ACCESS_KEY_ID": "secret:imas-uat-s3-saasapi/access-key-id",
		"SAASAPI_NATS_URL":                 "tls://dmz.uat.imas.internal:8442",
	} {
		if se[k] != want {
			t.Errorf("saasapi %s = %q, want %q", k, se[k], want)
		}
	}
	if !strings.Contains(mustJSON(t, saasapi), `"name":"imas-uat-ca"`) {
		t.Error("saasapi doesn't mount the imas-uat-ca ConfigMap")
	}

	// farmer: object store, the sprout bus URL, its TLS from cert-manager.
	farmer := get(t, objs, "Deployment/imas-core-farmer")
	fe := envOf(container(t, farmer, "farmer"))
	for k, want := range map[string]string{
		"IMAS_S3_ENDPOINT":      "imas-uat-minio.imas-uat.svc.cluster.local:9000",
		"IMAS_S3_BUCKET":        "imas-recipes",
		"IMAS_S3_JOB_BUCKET":    "imas-jobs",
		"IMAS_S3_ACCESS_KEY_ID": "secret:imas-uat-s3-farmer/access-key-id",
	} {
		if fe[k] != want {
			t.Errorf("farmer %s = %q, want %q", k, fe[k], want)
		}
	}
	if !strings.Contains(mustJSON(t, farmer), `"secretName":"imas-farmer-tls"`) {
		t.Error("farmer doesn't mount tls.secretName imas-farmer-tls (tls.mode=secret)")
	}
	cfg := str(get(t, objs, "ConfigMap/imas-core-farmer"), "data", "farmer")
	for _, want := range []string{
		"farmerbusurl: tls://dmz.uat.imas.internal:8442",
		"sproutbusurls:\n- wss://" + dmzFQDN + ":8443/\n",
		"rootca: /etc/imas/tls/ca.crt",
		"AC4LMP7I2FYLWGY5GIB52A4XCFFFSB2QTZ65B3A4G6OK5GYWRJSKH74C",
		"Go0DiL9Y7s+Dp1mSizpp9n5xXuotDZzeqF6iGfIyt1c=",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("farmer config lacks %q", want)
		}
	}

	// The bus egress rule of farmer's and saasapi's own policies names the
	// DMZ private address and the node port (bus.egressCIDRs), and only
	// that: the chart's pod selector can't match a bus on another cluster.
	for _, key := range []string{"NetworkPolicy/imas-core-farmer", "NetworkPolicy/imas-core-farmer-saasapi"} {
		pol := mustJSON(t, get(t, objs, key))
		if !strings.Contains(pol, `"cidr":"`+dmzIP+`/32"`) || !strings.Contains(pol, `"port":8442`) {
			t.Errorf("%s has no bus egress to %s/32 on 8442: %s", key, dmzIP, pol)
		}
	}

	// Images: the release's version, never latest.
	for key, o := range objs {
		for _, c := range containers(o) {
			img, _ := c["image"].(string)
			if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
				t.Errorf("%s runs %q", key, img)
			}
			if strings.HasPrefix(img, "ghcr.io/yogzblr/imas-") && !strings.HasSuffix(img, ":"+version) {
				t.Errorf("%s runs %q, want tag %s", key, img, version)
			}
		}
	}

	// OpenBao: the chart's bootstrap Job uses the token Secret
	// openbao-bootstrap.sh creates, and no dev root token Secret exists.
	job := get(t, objs, "Job/imas-core-farmer-openbao-bootstrap")
	if got := envOf(container(t, job, "bootstrap"))["BAO_TOKEN"]; got != "secret:imas-uat-openbao-root/token" {
		t.Errorf("openbao-bootstrap BAO_TOKEN from %q", got)
	}
	if _, ok := objs["Secret/imas-core-farmer-openbao-bootstrap"]; ok {
		t.Error("the dev-mode root token Secret is rendered: dev mode must be off")
	}
	if !strings.Contains(mustJSON(t, job), "transit/keys/imas-gateway-jwt type=ed25519") {
		t.Error("the chart's bootstrap no longer names transit/keys/imas-gateway-jwt type=ed25519; openbao-bootstrap.sh must follow")
	}

	if !full {
		t.Log("subcharts not built (helm dependency build deploy/helm/farmer): OpenBao, PXC and Valkey not rendered")
		return
	}
	ob := get(t, objs, "StatefulSet/imas-core-openbao")
	if r := dig(ob, "spec", "replicas"); r != 1 {
		t.Errorf("OpenBao replicas %v", r)
	}
	if s := mustJSON(t, ob); strings.Contains(s, "-dev") || strings.Contains(s, "BAO_DEV_ROOT_TOKEN_ID") {
		t.Error("OpenBao renders in dev mode")
	}
	if c := str(get(t, objs, "ConfigMap/imas-core-openbao-config"), "data", "extraconfig-from-values.hcl"); !strings.Contains(c, `storage "file"`) {
		t.Errorf("OpenBao config is not standalone file storage:\n%s", c)
	}
	pxc := get(t, objs, "PerconaXtraDBCluster/imas-core-pxc")
	if dig(pxc, "spec", "pxc", "size") != 1 || dig(pxc, "spec", "haproxy", "size") != 1 {
		t.Errorf("PXC sizes: pxc %v haproxy %v, want 1 and 1", dig(pxc, "spec", "pxc", "size"), dig(pxc, "spec", "haproxy", "size"))
	}
	if r := dig(get(t, objs, "Deployment/imas-core-valkey"), "spec", "replicas"); r != 1 {
		t.Errorf("Valkey replicas %v", r)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestExtrasChartRender renders chart/ with the --set flags install.sh
// builds (extras_set_args) and checks the cross-cluster wiring and that the
// Keycloak issuer is exactly saasapi's.
func TestExtrasChartRender(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")
	setArgs := strings.Fields(string(run(t, "bash", "-c",
		`set -euo pipefail; . lib/common.sh; ENDPOINTS="$1"; load_endpoints; extras_set_args`, "_", endpointsFile)))
	args := append([]string{"template", "imas-uat-core", "chart", "-n", "imas-uat", "--kube-version", "1.31.0"}, setArgs...)
	objs := docs(t, run(t, "helm", args...))
	run(t, "helm", append([]string{"lint", "chart", "--kube-version", "1.31.0"}, setArgs...)...)

	// Keycloak's issuer = KC_HOSTNAME (and the realm frontendUrl) + /realms/imas-uat.
	kcEnv := envOf(container(t, get(t, objs, "Deployment/imas-uat-keycloak"), "keycloak"))
	if got := kcEnv["KC_HOSTNAME"] + "/realms/imas-uat"; got != issuer {
		t.Errorf("Keycloak issuer would be %q, saasapi expects %q", got, issuer)
	}
	if kcEnv["UAT_KEYCLOAK_URL"] != kcEnv["KC_HOSTNAME"] {
		t.Errorf("realm frontendUrl %q differs from KC_HOSTNAME %q", kcEnv["UAT_KEYCLOAK_URL"], kcEnv["KC_HOSTNAME"])
	}
	realm, err := os.ReadFile("chart/files/imas-uat-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := str(get(t, objs, "ConfigMap/imas-uat-keycloak-realm"), "data", "imas-uat-realm.json"); strings.TrimSpace(got) != strings.TrimSpace(string(realm)) {
		t.Error("the realm ConfigMap is not the realm file")
	}

	// farmer's certificate covers its Service, the core FQDN and IP.
	cert := mustJSON(t, get(t, objs, "Certificate/imas-farmer-tls"))
	for _, want := range []string{`"imas-core-farmer.imas-core.svc.cluster.local"`, `"core.uat.imas.internal"`, `"` + coreFQDN + `"`, `"` + coreIP + `"`, `"name":"imas-uat-ca"`} {
		if !strings.Contains(cert, want) {
			t.Errorf("Certificate imas-farmer-tls lacks %s", want)
		}
	}
	if !strings.Contains(mustJSON(t, get(t, objs, "Certificate/imas-uat-edge-tls")), `"`+coreFQDN+`"`) {
		t.Error("the edge certificate is not for the core FQDN")
	}

	// The bus is dialled by the DMZ's private name (farmer chart bus.host),
	// on the DMZ node port 8442 (owner decisions, 2026-10-06): no Service
	// or EndpointSlice stands in for it on this cluster.
	for key := range objs {
		if strings.HasPrefix(key, "EndpointSlice/") || strings.HasPrefix(key, "Service/imas-dmz-nats-bus") {
			t.Errorf("%s: the bus is reached by its private name, not through a stand-in Service", key)
		}
	}
	for _, o := range objs {
		if str(o, "kind") == "Service" && str(o, "spec", "type") == "ExternalName" {
			t.Errorf("an ExternalName Service is left: %s", mustJSON(t, o))
		}
	}
	for _, key := range []string{"NetworkPolicy/imas-uat-farmer-cross-cluster", "NetworkPolicy/imas-uat-saasapi-cross-cluster"} {
		if s := mustJSON(t, get(t, objs, key)); !strings.Contains(s, `"port":8442`) {
			t.Errorf("%s doesn't open the DMZ bus node port 8442", key)
		}
	}

	// Policies open the DMZ address only.
	for _, key := range []string{"NetworkPolicy/imas-uat-farmer-cross-cluster", "NetworkPolicy/imas-uat-saasapi-cross-cluster", "NetworkPolicy/imas-uat-edge"} {
		if s := mustJSON(t, get(t, objs, key)); !strings.Contains(s, `"cidr":"`+dmzIP+`/32"`) {
			t.Errorf("%s doesn't name the DMZ address", key)
		}
	}
	for key, o := range objs {
		if strings.HasPrefix(key, "NetworkPolicy/") && strings.Contains(mustJSON(t, o), `"cidr":"0.0.0.0/0"`) {
			t.Errorf("%s opens 0.0.0.0/0", key)
		}
	}

	// The edge: hostPorts 443 and 5405, Keycloak's realm routed, not /admin.
	edge := get(t, objs, "Deployment/imas-uat-edge")
	es := mustJSON(t, edge)
	for _, want := range []string{`"hostPort":443`, `"hostPort":5405`} {
		if !strings.Contains(es, want) {
			t.Errorf("edge lacks %s", want)
		}
	}
	// No core node port mode (owner decision, 2026-10-06).
	if t2 := str(get(t, objs, "Service/imas-uat-edge"), "spec", "type"); t2 != "ClusterIP" {
		t.Errorf("edge Service type %q, want ClusterIP", t2)
	}
	envoy := str(get(t, objs, "ConfigMap/imas-uat-edge"), "data", "envoy.yaml")
	var ec map[string]any
	if err := yaml.Unmarshal([]byte(envoy), &ec); err != nil {
		t.Fatalf("edge envoy.yaml: %v", err)
	}
	if !strings.Contains(envoy, `prefix: "/realms/imas-uat/"`) || !strings.Contains(envoy, `prefix: "/v1/"`) {
		t.Error("edge doesn't route /v1/ and /realms/imas-uat/")
	}
	if strings.Contains(envoy, "/admin") || strings.Contains(envoy, "/realms/master") {
		t.Error("edge exposes Keycloak administration")
	}
	if !strings.Contains(envoy, "imas-core-farmer-saasapi.imas-core.svc.cluster.local") || !strings.Contains(envoy, "imas-core-farmer.imas-core.svc.cluster.local") {
		t.Error("edge upstreams are not the farmer chart's Services")
	}
}

// withObjectStore writes a copy of testdata/endpoints.json with the given
// object_store object and returns its path.
func withObjectStore(t *testing.T, os_ map[string]any) string {
	t.Helper()
	var ep map[string]any
	readJSON(t, endpointsFile, &ep)
	ep["object_store"] = os_
	b, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "endpoints.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestObjectStoreEndpointVariable: the S3 endpoint is a variable
// (object_store.* in the endpoints file). The default is RustFS in imas-uat;
// "external" deploys no store and points farmer and saasapi at the given
// endpoint, with egress narrowed to the given CIDRs.
func TestObjectStoreEndpointVariable(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")

	// Default: unchanged behaviour.
	var def map[string]any
	readJSON(t, runValues(t), &def)
	if got := str(def, "objectStore", "endpoint"); got != "imas-uat-minio.imas-uat.svc.cluster.local:9000" {
		t.Errorf("default objectStore.endpoint %q", got)
	}
	if dig(def, "objectStore", "useSSL") != false {
		t.Error("default objectStore.useSSL is not false")
	}
	if dig(def, "networkPolicy") != nil {
		t.Error("default run values narrow the object store egress")
	}

	// External.
	ext := withObjectStore(t, map[string]any{
		"mode": "external", "endpoint": "s3gw.example.internal:7070", "use_ssl": true,
		"egress_cidrs": []string{"10.70.0.0/24"},
	})
	out := run(t, "bash", "gen-values.sh", ext, adminFile, releaseTag)
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if got := str(v, "objectStore", "endpoint"); got != "s3gw.example.internal:7070" {
		t.Errorf("objectStore.endpoint %q", got)
	}
	if dig(v, "objectStore", "useSSL") != true {
		t.Error("objectStore.useSSL is not true")
	}
	if s := mustJSON(t, dig(v, "networkPolicy", "external", "objectStore")); s != `[{"ipBlock":{"cidr":"10.70.0.0/24"}}]` {
		t.Errorf("networkPolicy.external.objectStore = %s", s)
	}
	setArgs := strings.Fields(string(run(t, "bash", "-c",
		`set -euo pipefail; . lib/common.sh; ENDPOINTS="$1"; load_endpoints; extras_set_args`, "_", ext)))
	objs := docs(t, run(t, "helm", append([]string{"template", "imas-uat-core", "chart", "-n", "imas-uat", "--kube-version", "1.31.0"}, setArgs...)...))
	for _, key := range []string{"Deployment/imas-uat-minio", "Service/imas-uat-minio", "PersistentVolumeClaim/imas-uat-rustfs-data", "NetworkPolicy/imas-uat-minio"} {
		if _, ok := objs[key]; ok {
			t.Errorf("external mode still renders %s", key)
		}
	}
	// The default still renders the store.
	defArgs := strings.Fields(string(run(t, "bash", "-c",
		`set -euo pipefail; . lib/common.sh; ENDPOINTS="$1"; load_endpoints; extras_set_args`, "_", endpointsFile)))
	defObjs := docs(t, run(t, "helm", append([]string{"template", "imas-uat-core", "chart", "-n", "imas-uat", "--kube-version", "1.31.0"}, defArgs...)...))
	for _, key := range []string{"Deployment/imas-uat-minio", "Service/imas-uat-minio", "PersistentVolumeClaim/imas-uat-rustfs-data", "NetworkPolicy/imas-uat-minio"} {
		get(t, defObjs, key)
	}
}

// TestObjectStoreEndpointRejected: bad object_store input stops load_endpoints.
func TestObjectStoreEndpointRejected(t *testing.T) {
	requireTools(t, "bash", "jq")
	for name, o := range map[string]map[string]any{
		"unknown mode":          {"mode": "minio"},
		"external, no endpoint": {"mode": "external"},
		"scheme in endpoint":    {"endpoint": "https://s3.example.internal"},
		"bad use_ssl":           {"use_ssl": "yes"},
		"bad cidr":              {"egress_cidrs": []string{"not-a-cidr"}},
	} {
		p := withObjectStore(t, o)
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . lib/common.sh; ENDPOINTS="$1"; load_endpoints`, "_", p)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Errorf("%s: load_endpoints accepted it: %s", name, out)
		}
	}
}
