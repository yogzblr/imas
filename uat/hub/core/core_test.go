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
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	endpointsFile = "testdata/endpoints.json"
	adminFile     = "testdata/admin.json"
	loaderPubFile = "testdata/bus-loader-user.pub"
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
		"objectStore.sproutJWTBucket":           "SPROUT_JWT_BUCKET",
		"objectStore.credentialsSecret":         "S3_FARMER_SECRET",
		"saasapi.recipes.credentialsSecret":     "S3_SAASAPI_SECRET",
		"saasapi.recipes.readRole":              "READ_ROLE",
		"saasapi.recipes.writeRole":             "WRITE_ROLE",
		"saasapi.internalAuthSecret.secretName": "INTERNAL_AUTH_SECRET",
		"natsSeeds.secretName":                  "SEEDS_SECRET",
		"natsTrust.configMapName":               "NATS_TRUST_CONFIGMAP",
		"tls.secretName":                        "FARMER_TLS_SECRET",
		"openbaoBootstrap.tokenSecretName":      "OPENBAO_ROOT_SECRET",
		"farmer.bootstrapAdmin.username":        "BOOTSTRAP_ADMIN_NAME",
		"saasapi.operator.tls.secretName":       "OPERATOR_TLS_SECRET",
		"saasapi.operator.token.secretName":     "OPERATOR_TOKEN_SECRET",
	} {
		if got := str(v, strings.Split(path, ".")...); got == "" || got != lib[name] {
			t.Errorf("%s = %q, lib/common.sh %s = %q", path, got, name, lib[name])
		}
	}
	// Names the UAT takes from the farmer chart's defaults instead of
	// setting them: seeds.sh and rustfs-setup.sh create what they name.
	chartDefaults := readYAML(t, "../../../deploy/helm/farmer/values.yaml")
	for path, name := range map[string]string{
		"farmer.nkeySecret.secretName":   "FARMER_NKEY_SECRET",
		"farmer.nkeySecret.key":          "FARMER_NKEY_KEY",
		"accountStore.bucket":            "ACCOUNTS_BUCKET",
		"accountStore.credentialsSecret": "S3_ACCOUNTS_WRITER_SECRET",
		"valkey.auth.secretName":         "VALKEY_AUTH_SECRET",
		"valkey.auth.key":                "VALKEY_AUTH_KEY",
	} {
		if got := str(v, strings.Split(path, ".")...); got != "" {
			t.Errorf("values/farmer-uat.yaml sets %s = %q: the UAT uses the chart default", path, got)
		}
		if got := str(chartDefaults, strings.Split(path, ".")...); got == "" || got != lib[name] {
			t.Errorf("chart default %s = %q, lib/common.sh %s = %q", path, got, name, lib[name])
		}
	}
	buckets := map[string]bool{}
	for _, b := range []string{lib["RECIPE_BUCKET"], lib["JOB_BUCKET"], lib["SPROUT_JWT_BUCKET"], lib["ACCOUNTS_BUCKET"]} {
		if buckets[b] {
			t.Errorf("bucket %q is used twice: recipes, jobs, sprout JWTs and accounts must all differ", b)
		}
		buckets[b] = true
	}
	want := lib["RUSTFS_SVC"] + "." + lib["UAT_NS"] + ".svc.cluster.local:9000"
	if got := str(v, "objectStore", "endpoint"); got != want {
		t.Errorf("objectStore.endpoint %q, want %q", got, want)
	}
	// P20 option C: the operator plane is on, so the registration hook can
	// run; the token's key is the one saasapi-secrets.sh writes. The
	// dispatch flags are off in the layout; gen-values.sh sets them.
	if dig(v, "saasapi", "operator", "enabled") != true {
		t.Error("saasapi.operator.enabled must be true: finish.sh registers the sprout release through it")
	}
	if got := str(v, "saasapi", "operator", "token", "currentKey"); got != "current" {
		t.Errorf("saasapi.operator.token.currentKey %q, want current (saasapi-secrets.sh)", got)
	}
	if dig(v, "farmer", "selfUpdate", "enabled") != false || dig(v, "saasapi", "fleetUpdateDispatch", "enabled") != false {
		t.Error("values/farmer-uat.yaml must leave both dispatch flags off: gen-values.sh turns them on from dispatch_flags")
	}
	if chartPort, _ := dig(chartDefaults, "saasapi", "operator", "port").(int); strconv.Itoa(chartPort) != lib["SAASAPI_OPERATOR_PORT"] {
		t.Errorf("saasapi.operator.port chart default %v, lib/common.sh SAASAPI_OPERATOR_PORT %q", chartPort, lib["SAASAPI_OPERATOR_PORT"])
	}
	if lib["SAASAPI_OPERATOR_FULLNAME"] != lib["SAASAPI_FULLNAME"]+"-operator" {
		t.Errorf("SAASAPI_OPERATOR_FULLNAME %q, want %q (imas-farmer.saasapi.operatorFullname)", lib["SAASAPI_OPERATOR_FULLNAME"], lib["SAASAPI_FULLNAME"]+"-operator")
	}
	if lib["SPROUT_RELEASE_CONFIGMAP"] != lib["FARMER_FULLNAME"]+"-sprout-release" {
		t.Errorf("SPROUT_RELEASE_CONFIGMAP %q, want %q (sprout-release-register-job.yaml)", lib["SPROUT_RELEASE_CONFIGMAP"], lib["FARMER_FULLNAME"]+"-sprout-release")
	}
	// Unit S5: the UAT runs Valkey with a password, like production.
	if dig(v, "valkey", "auth", "enabled") != true || dig(v, "valkey", "auth", "allowInsecure") != nil {
		t.Error("values/farmer-uat.yaml must keep valkey.auth.enabled true (and not set allowInsecure): the UAT follows the production path")
	}
	if dig(v, "openbao", "server", "dev", "enabled") != false {
		t.Error("openbao.server.dev.enabled must be false: the UAT OpenBao is initialised and unsealed for real")
	}
	// Unit T5 (I2): that OpenBao listens on plain http (tls_disable), so
	// imas's clients refuse it unless told otherwise; the chart default
	// stays false.
	if dig(v, "openbaoClient", "allowInsecure") != true {
		t.Error("values/farmer-uat.yaml must set openbaoClient.allowInsecure: true: its OpenBao is plain http, which farmer's clients refuse otherwise")
	}
	if dig(v, "objectStore", "useSSL") != false {
		t.Error("objectStore.useSSL: RustFS is plain HTTP inside the cluster")
	}
	// OpenBao: single-node raft (2.7.1 has no "file" backend), node_id
	// fixed, api_addr and cluster_addr on the pod's Services, and the
	// subchart's BAO_API_ADDR / BAO_CLUSTER_ADDR (which win over the file)
	// the same two addresses.
	checkOpenBaoRaft(t, lib, str(v, "openbao", "server", "standalone", "config"),
		str(v, "openbao", "server", "ha", "apiAddr"), str(v, "openbao", "server", "ha", "clusterAddr"))
	extras := readYAML(t, "chart/values.yaml")
	for path, want := range map[string]string{
		"farmer.serviceName":                lib["FARMER_FULLNAME"],
		"farmer.saasapiServiceName":         lib["SAASAPI_FULLNAME"],
		"farmer.namespace":                  lib["CORE_NS"],
		"farmer.release":                    lib["CORE_RELEASE"],
		"farmer.tlsSecretName":              lib["FARMER_TLS_SECRET"],
		"farmer.operatorTLSSecretName":      lib["OPERATOR_TLS_SECRET"],
		"farmer.saasapiOperatorServiceName": lib["SAASAPI_OPERATOR_FULLNAME"],
		"rustfs.rootSecret":                 lib["RUSTFS_ROOT_SECRET"],
		"keycloak.realm":                    lib["REALM"],
		"keycloak.adminSecret":              lib["KEYCLOAK_ADMIN_SECRET"],
		"keycloak.realmEnvSecret":           lib["KEYCLOAK_REALM_SECRET"],
	} {
		if got := str(extras, strings.Split(path, ".")...); got != want {
			t.Errorf("chart/values.yaml %s = %q, want %q", path, got, want)
		}
	}
	// The DMZ's loader reads the accounts bucket at <core private IP>:9000
	// (uat/hub/dmz/install.sh's default, uat/tofu accounts_store_port).
	if dig(extras, "core", "accountsStorePort") != 9000 {
		t.Errorf("chart/values.yaml core.accountsStorePort = %v, want 9000 (uat/hub/dmz dmz.account_store.endpoint default)", dig(extras, "core", "accountsStorePort"))
	}
	for _, img := range []string{str(extras, "rustfs", "image"), str(extras, "keycloak", "image"), str(extras, "edge", "image")} {
		if !regexp.MustCompile(`^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`).MatchString(img) || strings.Contains(img, ":latest") {
			t.Errorf("image %q is not pinned to a tag and its sha256 digest (P13)", img)
		}
	}
}

// TestFinishScript runs test/finish_test.sh: finish.sh against stub
// kubectl, helm and curl. It fails when the registration Job fails, when no
// Job rendered or one is left failed or unfinished, and unless the operator
// API then holds release_tag exactly as the chart stamped it (R1).
func TestFinishScript(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	out, err := exec.Command("bash", "test/finish_test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("test/finish_test.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// TestValidateObjectStore runs test/object_store_test.sh:
// validate-object-store.sh's put, get and list matrix over the four scoped
// credentials, against a curl that answers with the UAT policies, for RustFS
// (in its pod) and for Versity Gateway (through a port-forward, HA run), and
// the deliberate policy holes it must name (P13).
func TestValidateObjectStore(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "openssl", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	out, err := exec.Command("bash", "test/object_store_test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("test/object_store_test.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// A script that backgrounds kubectl port-forward and polls its log with
// sed must create the log first: the shell opens the redirect only in the
// forked child, so the first sed can run before the file exists, and
// under set -e and pipefail the script then exits with nothing but sed's
// error (seen as a flaky TestValidateObjectStore on a loaded machine).
func TestPortForwardLogExistsBeforeKubectl(t *testing.T) {
	scripts, err := filepath.Glob("*.sh")
	if err != nil {
		t.Fatal(err)
	}
	pf := regexp.MustCompile(`(?m)^\s*kubectl [^>]*port-forward [^>]*(>>?)"([^"]+)" 2>&1 &$`)
	found := 0
	for _, s := range scripts {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pf.FindAllSubmatchIndex(b, -1) {
			found++
			log := string(b[m[4]:m[5]])
			if m[3]-m[2] != 2 {
				t.Errorf("%s: kubectl port-forward truncates %s with >; create it first and append with >>", s, log)
			}
			if !strings.Contains(string(b[:m[0]]), `: >"`+log+`"`) {
				t.Errorf("%s: %s is not created (: >\"%s\") before kubectl port-forward starts", s, log, log)
			}
		}
	}
	if found < 2 {
		t.Errorf("found %d backgrounded kubectl port-forward lines, want at least 2 (operator-release.sh, validate-object-store.sh)", found)
	}
}

// TestStatusLine: check.sh's "must refuse" checks compare the status and
// the error code of saasapi's JSON body (P13), so a 401 from anything but
// saasapi does not pass as saasapi's refusal.
func TestStatusLine(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	for _, c := range []struct{ code, body, want string }{
		{"401", `{"error":"unauthorized","message":"unauthorized"}`, "401 unauthorized"},
		{"403", `{"error":"forbidden","message":"forbidden"}`, "403 forbidden"},
		{"200", `{"versions":[]}`, "200"},
		{"401", `<html>401 Authorization Required</html>`, "401"},
		{"401", ``, "401"},
		{"401", `{"error":"Bad Thing; rm -rf"}`, "401"},
	} {
		f := filepath.Join(t.TempDir(), "body")
		if err := os.WriteFile(f, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := string(run(t, "bash", "-c", `. lib/common.sh; status_line "$1" "$2"`, "_", c.code, f)); got != c.want {
			t.Errorf("status_line %s %q = %q, want %q", c.code, c.body, got, c.want)
		}
	}
}

// TestShellcheck lints every script and stub of uat/hub/core.
func TestShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not on PATH")
	}
	files, err := filepath.Glob("*.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"test/*.sh", "test/stubs/*", "test/finish-stubs/*", "test/object-store-stubs/*"} {
		more, _ := filepath.Glob(g)
		files = append(files, more...)
	}
	files = append(files, "lib/common.sh")
	if out, err := exec.Command("shellcheck", append([]string{"-x"}, files...)...).CombinedOutput(); err != nil {
		t.Errorf("shellcheck: %v\n%s", err, out)
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
	out := run(t, "bash", "gen-values.sh", endpointsFile, adminFile, releaseTag, loaderPubFile)
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
	// CA for that HTTPS fetch; the recipe roles of the realm; RustFS.
	saasapi := get(t, objs, "Deployment/imas-core-farmer-saasapi")
	se := envOf(container(t, saasapi, "saasapi"))
	for k, want := range map[string]string{
		"SAASAPI_JWT_ISSUER":               issuer,
		"SAASAPI_KEYCLOAK_JWKS_URL":        issuer + "/protocol/openid-connect/certs",
		"SAASAPI_JWT_AUDIENCE":             "imas-saasapi",
		"SSL_CERT_FILE":                    "/etc/imas-uat-ca/ca.crt",
		"SAASAPI_RECIPES_READ_ROLE":        "imas-recipes-read",
		"SAASAPI_RECIPES_WRITE_ROLE":       "imas-recipes-write",
		"SAASAPI_RECIPES_S3_ENDPOINT":      "imas-uat-rustfs.imas-uat.svc.cluster.local:9000",
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
		"IMAS_S3_ENDPOINT":               "imas-uat-rustfs.imas-uat.svc.cluster.local:9000",
		"IMAS_S3_BUCKET":                 "imas-recipes",
		"IMAS_S3_JOB_BUCKET":             "imas-jobs",
		"IMAS_S3_SPROUT_JWT_BUCKET":      "imas-sprout-jwts",
		"IMAS_S3_ACCESS_KEY_ID":          "secret:imas-uat-s3-farmer/access-key-id",
		"IMAS_ACCOUNTS_S3_BUCKET":        "imas-accounts",
		"IMAS_ACCOUNTS_S3_ACCESS_KEY_ID": "secret:imas-farmer-accounts-writer/access-key-id",
		"IMAS_FARMER_NKEY_SEED_FILE":     "/var/run/secrets/imas/farmer-nkey/farmer.nk",
		"IMAS_VALKEY_PASSWORD_FILE":      "/var/run/secrets/imas/valkey/password",
	} {
		if fe[k] != want {
			t.Errorf("farmer %s = %q, want %q", k, fe[k], want)
		}
	}
	// Unit S5: both Valkey clients read the password from Secret
	// imas-valkey-auth (saasapi-secrets.sh), as a file.
	if se["SAASAPI_VALKEY_PASSWORD_FILE"] != "/var/run/secrets/imas/valkey/password" {
		t.Errorf("saasapi SAASAPI_VALKEY_PASSWORD_FILE = %q", se["SAASAPI_VALKEY_PASSWORD_FILE"])
	}
	for name, d := range map[string]map[string]any{"farmer": farmer, "saasapi": saasapi} {
		if !strings.Contains(mustJSON(t, d), `"secretName":"`+libConstants(t)["VALKEY_AUTH_SECRET"]+`"`) {
			t.Errorf("%s doesn't mount Secret %s", name, libConstants(t)["VALKEY_AUTH_SECRET"])
		}
	}
	// farmer's NKey: Secret imas-farmer-nkey, key farmer.nk, which seeds.sh
	// creates (no PVC: farmer is stateless).
	if fj := mustJSON(t, farmer); !strings.Contains(fj, `"secretName":"imas-farmer-nkey"`) || !strings.Contains(fj, `"key":"farmer.nk"`) {
		t.Error("farmer doesn't mount Secret imas-farmer-nkey, key farmer.nk")
	}
	for key := range objs {
		if strings.HasPrefix(key, "PersistentVolumeClaim/imas-core-farmer") {
			t.Errorf("%s: farmer is stateless", key)
		}
	}
	if vct := dig(farmer, "spec", "volumeClaimTemplates"); vct != nil {
		t.Errorf("farmer has volumeClaimTemplates %v", vct)
	}
	if !strings.Contains(mustJSON(t, farmer), `"secretName":"imas-farmer-tls"`) {
		t.Error("farmer doesn't mount tls.secretName imas-farmer-tls (tls.mode=secret)")
	}
	cfg := str(get(t, objs, "ConfigMap/imas-core-farmer"), "data", "farmer")
	for _, want := range []string{
		"farmerbusurl: tls://dmz.uat.imas.internal:8442",
		"sproutbusurls:\n- wss://dmz.uat.imas.internal:8443/\n",
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

	// P21 slice 1: farmer gets the two user seeds seeds.sh makes and no
	// trust chain seed, reads the trust ConfigMap and signs through Transit.
	for _, name := range []string{"SYS_USER", "SAASAPI_USER"} {
		if fe["IMAS_NATS_"+name+"_SEED_FILE"] == "" {
			t.Errorf("farmer has no IMAS_NATS_%s_SEED_FILE (seeds.sh makes it)", name)
		}
	}
	for key, o := range objs {
		for _, c := range containers(o) {
			for name := range envOf(c) {
				for _, gone := range []string{"OPERATOR", "OPERATOR_SIGNING", "SYS_ACCOUNT", "TENANT", "TENANT_SIGNING"} {
					if name == "IMAS_NATS_"+gone+"_SEED_FILE" || name == "IMAS_NATS_"+gone+"_SEED" {
						t.Errorf("%s container %v sets %s", key, c["name"], name)
					}
				}
			}
		}
	}
	if fe["IMAS_NATS_TRUST_DIR"] != "/var/run/imas/nats-trust" || fe["IMAS_NATSSIGN_OPENBAO_ADDR"] == "" {
		t.Errorf("farmer IMAS_NATS_TRUST_DIR %q, IMAS_NATSSIGN_OPENBAO_ADDR %q", fe["IMAS_NATS_TRUST_DIR"], fe["IMAS_NATSSIGN_OPENBAO_ADDR"])
	}
	// Unit T5 (I2): every imas OpenBao client in the release accepts the
	// UAT's plain-http OpenBao, or farmer, the Jobs and nats-trust stop at
	// startup.
	for key, o := range objs {
		for _, c := range containers(o) {
			env := envOf(c)
			for name, addr := range env {
				prefix, ok := strings.CutSuffix(name, "_OPENBAO_ADDR")
				if !ok || !strings.HasPrefix(name, "IMAS_") {
					continue
				}
				if env[prefix+"_OPENBAO_ALLOW_INSECURE"] != "true" {
					t.Errorf("%s container %v: %s=%q without %s_OPENBAO_ALLOW_INSECURE=true", key, c["name"], name, addr, prefix)
				}
			}
		}
	}
	if !strings.Contains(mustJSON(t, farmer), `"name":"imas-nats-trust"`) {
		t.Error("farmer doesn't mount ConfigMap imas-nats-trust")
	}
	// Design T4, as rendered: the Job's nats-trust step writes the trust
	// ConfigMap, then the Job deletes the ephemeral policy and revokes the
	// token openbao-bootstrap.sh handed it (check.sh confirms on the cluster).
	container(t, job, "prepare")
	nte := envOf(container(t, job, "nats-trust"))
	if got := nte["IMAS_NATSBOOT_TRUST_CONFIGMAP"]; got != "imas-nats-trust" {
		t.Errorf("nats-trust writes ConfigMap %q, want imas-nats-trust", got)
	}
	// The DMZ bus loader's user: seeds.sh's public key, so the trust
	// carries bus-loader-user.jwt.
	lp, err := os.ReadFile(loaderPubFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := nte["IMAS_NATSBOOT_BUS_LOADER_USER_PUB"]; got == "" || got != strings.TrimSpace(string(lp)) {
		t.Errorf("nats-trust IMAS_NATSBOOT_BUS_LOADER_USER_PUB = %q, want %s's key", got, loaderPubFile)
	}
	js := mustJSON(t, job)
	for _, want := range []string{"bao policy delete imas-nats-bootstrap", "bao token revoke -self"} {
		if !strings.Contains(js, want) {
			t.Errorf("the bootstrap Job no longer runs %q; check.sh's T4 checks assume it", want)
		}
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
	// The config and env the subchart renders: raft, and the addresses.
	be := envOf(container(t, ob, "openbao"))
	checkOpenBaoRaft(t, libConstants(t), str(get(t, objs, "ConfigMap/imas-core-openbao-config"), "data", "extraconfig-from-values.hcl"),
		be["BAO_API_ADDR"], be["BAO_CLUSTER_ADDR"])
	if _, ok := objs["Service/imas-core-openbao-internal"]; !ok {
		t.Error("no Service imas-core-openbao-internal: cluster_addr names the pod on it")
	}
	pxc := get(t, objs, "PerconaXtraDBCluster/imas-core-pxc")
	if dig(pxc, "spec", "pxc", "size") != 1 || dig(pxc, "spec", "haproxy", "size") != 1 {
		t.Errorf("PXC sizes: pxc %v haproxy %v, want 1 and 1", dig(pxc, "spec", "pxc", "size"), dig(pxc, "spec", "haproxy", "size"))
	}
	vk := get(t, objs, "Deployment/imas-core-valkey")
	if r := dig(vk, "spec", "replicas"); r != 1 {
		t.Errorf("Valkey replicas %v", r)
	}
	// Unit S5: the bundled Valkey takes its password from the same Secret
	// and never evicts.
	if !strings.Contains(mustJSON(t, vk), `"secretName":"`+libConstants(t)["VALKEY_AUTH_SECRET"]+`"`) {
		t.Errorf("Valkey doesn't read Secret %s", libConstants(t)["VALKEY_AUTH_SECRET"])
	}
	if c := str(get(t, objs, "ConfigMap/imas-core-valkey-config"), "data", "valkey.conf"); !strings.Contains(c, "maxmemory-policy noeviction") {
		t.Errorf("Valkey config %q lacks maxmemory-policy noeviction", c)
	}
}

// checkOpenBaoRaft checks the UAT OpenBao config (values or rendered):
// single-node raft on the data volume with a fixed node_id, and api_addr
// and cluster_addr on the Services of release CORE_RELEASE in CORE_NS,
// equal to the BAO_API_ADDR and BAO_CLUSTER_ADDR the pod gets (they win
// over the file). OpenBao 2.7.1 refuses the "file" backend.
func checkOpenBaoRaft(t *testing.T, lib map[string]string, cfg, apiEnv, clusterEnv string) {
	t.Helper()
	ns, sts := lib["CORE_NS"], lib["OPENBAO_STS"]
	wantAPI := "http://" + sts + "." + ns + ".svc:8200"
	wantCluster := "https://" + lib["OPENBAO_POD"] + "." + sts + "-internal." + ns + ".svc:8201"
	if strings.Contains(cfg, `storage "file"`) {
		t.Errorf("OpenBao config uses the file backend, which 2.7.1 rejects:\n%s", cfg)
	}
	attr := func(name string) string {
		m := regexp.MustCompile(`(?m)^\s*` + name + `\s*=\s*"([^"]*)"`).FindStringSubmatch(cfg)
		if m == nil {
			return ""
		}
		return m[1]
	}
	if !regexp.MustCompile(`(?m)^\s*storage\s+"raft"\s*\{`).MatchString(cfg) || strings.Count(cfg, "storage ") != 1 {
		t.Errorf("OpenBao config is not exactly one raft storage block:\n%s", cfg)
	}
	for name, want := range map[string]string{
		"path": "/openbao/data", "node_id": lib["OPENBAO_POD"],
		"api_addr": wantAPI, "cluster_addr": wantCluster,
	} {
		if got := attr(name); got != want {
			t.Errorf("OpenBao config %s = %q, want %q", name, got, want)
		}
	}
	if apiEnv != wantAPI || clusterEnv != wantCluster {
		t.Errorf("BAO_API_ADDR %q / BAO_CLUSTER_ADDR %q differ from the config's %q / %q", apiEnv, clusterEnv, wantAPI, wantCluster)
	}
}

// subchartKeys are passed to the farmer chart's subcharts as is; their
// keys are the subcharts' to check.
var subchartKeys = map[string]bool{"openbao": true, "pxc": true, "pxc-operator": true, "valkey": true}

// unknownKeys lists the paths in uat that chart's values.yaml does not
// have. A chart value that is a non-empty map is walked; anything else
// (a scalar, a list, an empty map or null) accepts whatever is below it.
func unknownKeys(uat, chart map[string]any, prefix string, skip map[string]bool) []string {
	var out []string
	for k, v := range uat {
		if prefix == "" && skip[k] {
			continue
		}
		c, ok := chart[k]
		if !ok {
			out = append(out, prefix+k)
			continue
		}
		um, uok := v.(map[string]any)
		cm, cok := c.(map[string]any)
		if uok && cok && len(cm) > 0 {
			out = append(out, unknownKeys(um, cm, prefix+k+".", nil)...)
		}
	}
	return out
}

// stampedFarmerChart is a copy of deploy/helm/farmer as the release
// publishes it for releaseTag: appVersion the release's version and the
// stamped files/sprout-release.json (packaging/helm/stamp-sprout-release.sh)
// that finish.sh's `helm upgrade --set sproutRelease.register=true`
// registers.
func stampedFarmerChart(t *testing.T) string {
	t.Helper()
	src, _ := farmerChart(t)
	dir := filepath.Join(t.TempDir(), "farmer")
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	b = regexp.MustCompile(`(?m)^appVersion: .*$`).ReplaceAll(b, []byte(`appVersion: "`+version+`"`))
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	deb := "imas-sprout_" + version + "_linux_amd64.deb"
	rel := map[string]any{
		"version":            releaseTag,
		"min_sprout_version": "v0.0.1",
		"packages": []map[string]string{{"os": "linux", "arch": "amd64", "package_type": "deb",
			"file_name": deb, "checksum_sha256": strings.Repeat("a", 64)}},
		"checksums_txt": strings.Repeat("a", 64) + "  " + deb + "\n",
		"checksums_sig": "c2lnbmF0dXJl",
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "sprout-release.json"), []byte(mustJSON(t, rel)), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// renderCore renders chart (a stamped farmer chart) as install.sh and
// finish.sh do: values/farmer-uat.yaml, gen-values.sh's output with
// IMAS_UAT_DISPATCH_FLAGS=flags, and --set sproutRelease.register=register.
func renderCore(t *testing.T, chart, flags string, register bool) map[string]map[string]any {
	t.Helper()
	cmd := exec.Command("bash", "gen-values.sh", endpointsFile, adminFile, releaseTag, loaderPubFile)
	cmd.Env = append(os.Environ(), "IMAS_UAT_DISPATCH_FLAGS="+flags)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gen-values.sh with IMAS_UAT_DISPATCH_FLAGS=%s: %v", flags, err)
	}
	p := filepath.Join(t.TempDir(), "values-run.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return docs(t, run(t, "helm", "template", "imas-core", chart, "-n", "imas-core", "--kube-version", "1.31.0",
		"-f", "values/farmer-uat.yaml", "-f", p, "--set", "sproutRelease.register="+strconv.FormatBool(register)))
}

// TestFarmerChartRenderOperatorAndFlags (P20 option C, R1): with the UAT
// values the operator plane is on, so finish.sh's upgrade renders the
// registration hook Job, wired to the operator TLS Secret's ca.crt and the
// token Secret saasapi-secrets.sh makes; install.sh's register=false renders
// none. dispatch_flags on turns both fleet update flags on, off leaves both
// off.
func TestFarmerChartRenderOperatorAndFlags(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")
	lib := libConstants(t)
	chart := stampedFarmerChart(t)
	for _, c := range []struct {
		flags string
		want  string
	}{{"on", "true"}, {"off", "false"}, {"", "false"}} {
		objs := renderCore(t, chart, c.flags, true)
		se := envOf(container(t, get(t, objs, "Deployment/"+lib["SAASAPI_FULLNAME"]), "saasapi"))
		fe := envOf(container(t, get(t, objs, "Deployment/"+lib["FARMER_FULLNAME"]), "farmer"))
		if se["SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED"] != c.want || fe["IMAS_SELF_UPDATE_ENABLED"] != c.want {
			t.Errorf("IMAS_UAT_DISPATCH_FLAGS=%q: SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=%q, IMAS_SELF_UPDATE_ENABLED=%q, want both %s",
				c.flags, se["SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED"], fe["IMAS_SELF_UPDATE_ENABLED"], c.want)
		}
		if se["SAASAPI_OPERATOR_LISTEN_ADDR"] == "" {
			t.Errorf("IMAS_UAT_DISPATCH_FLAGS=%q: saasapi has no SAASAPI_OPERATOR_LISTEN_ADDR: the operator plane is off", c.flags)
		}
		sj := mustJSON(t, get(t, objs, "Deployment/"+lib["SAASAPI_FULLNAME"]))
		for _, secret := range []string{lib["OPERATOR_TLS_SECRET"], lib["OPERATOR_TOKEN_SECRET"]} {
			if !strings.Contains(sj, `"secretName":"`+secret+`"`) {
				t.Errorf("saasapi does not mount Secret %s", secret)
			}
		}
		svc := get(t, objs, "Service/"+lib["SAASAPI_OPERATOR_FULLNAME"])
		if !strings.Contains(mustJSON(t, dig(svc, "spec", "ports")), `"port":`+lib["SAASAPI_OPERATOR_PORT"]) {
			t.Errorf("Service %s does not serve port %s", lib["SAASAPI_OPERATOR_FULLNAME"], lib["SAASAPI_OPERATOR_PORT"])
		}
		job := get(t, objs, "Job/"+lib["FARMER_FULLNAME"]+"-sprout-release-register")
		je := envOf(container(t, job, "register"))
		if want := "https://" + lib["SAASAPI_OPERATOR_FULLNAME"] + ".imas-core.svc.cluster.local:" + lib["SAASAPI_OPERATOR_PORT"]; je["IMAS_SPROUT_RELEASE_SAASAPI_URL"] != want {
			t.Errorf("registration Job URL %q, want %q (the name on the operator certificate)", je["IMAS_SPROUT_RELEASE_SAASAPI_URL"], want)
		}
		jj := mustJSON(t, job)
		for _, want := range []string{`"secretName":"` + lib["OPERATOR_TOKEN_SECRET"] + `"`, `"key":"current"`, `"secretName":"` + lib["OPERATOR_TLS_SECRET"] + `"`, `"key":"ca.crt"`} {
			if !strings.Contains(jj, want) {
				t.Errorf("registration Job lacks %s", want)
			}
		}
		req := str(get(t, objs, "ConfigMap/"+lib["SPROUT_RELEASE_CONFIGMAP"]), "data", "request.json")
		var body map[string]any
		if err := json.Unmarshal([]byte(req), &body); err != nil || body["version"] != releaseTag || body["checksums_sig"] != "c2lnbmF0dXJl" {
			t.Errorf("ConfigMap %s request.json %q: want release %s with its checksums_sig (%v)", lib["SPROUT_RELEASE_CONFIGMAP"], req, releaseTag, err)
		}
	}
	// install.sh's first install: no registration yet (saasapi is not up
	// until the DMZ bus is).
	objs := renderCore(t, chart, "off", false)
	for key := range objs {
		if strings.Contains(key, "sprout-release") {
			t.Errorf("sproutRelease.register=false still renders %s", key)
		}
	}
}

// TestUATValuesKnownToChart: every farmer-chart key the UAT sets, in
// values/farmer-uat.yaml and in gen-values.sh's output, exists in the
// chart's values.yaml. The chart has no schema, so a key it dropped
// (farmer.persistence when farmer became stateless) would otherwise be
// ignored without a word.
func TestUATValuesKnownToChart(t *testing.T) {
	requireTools(t, "bash", "jq")
	chart := readYAML(t, "../../../deploy/helm/farmer/values.yaml")
	var run map[string]any
	readJSON(t, runValues(t), &run)
	var haRun map[string]any
	readJSON(t, haRunValues(t), &haRun)
	for name, v := range map[string]map[string]any{
		"values/farmer-uat.yaml": readYAML(t, "values/farmer-uat.yaml"), "gen-values.sh": run,
		"values/values-ha.yaml": readYAML(t, "values/values-ha.yaml"), "gen-values.sh (HA)": haRun,
	} {
		if bad := unknownKeys(v, chart, "", subchartKeys); len(bad) > 0 {
			t.Errorf("%s sets keys deploy/helm/farmer/values.yaml does not have: %v", name, bad)
		}
	}
	if dig(readYAML(t, "values/farmer-uat.yaml"), "farmer", "persistence") != nil {
		t.Error("values/farmer-uat.yaml still sets farmer.persistence: farmer has no PVC")
	}
	// The guard itself: a dropped key is caught.
	if bad := unknownKeys(map[string]any{"farmer": map[string]any{"persistence": map[string]any{"size": "1Gi"}}}, chart, "", subchartKeys); len(bad) != 1 || bad[0] != "farmer.persistence" {
		t.Errorf("unknownKeys missed farmer.persistence: %v", bad)
	}
}

// TestFarmerChartNotes renders the chart's NOTES (which `helm template`
// skips) with the UAT values: no warning about a value the UAT must set.
func TestFarmerChartNotes(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")
	src, _ := farmerChart(t)
	dir := filepath.Join(t.TempDir(), "farmer")
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	notes, err := os.ReadFile(filepath.Join(dir, "templates", "NOTES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "notes-under-test.txt"), notes, 0o644); err != nil {
		t.Fatal(err)
	}
	cm := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-under-test\ndata:\n  notes: {{ tpl (.Files.Get \"files/notes-under-test.txt\") . | quote }}\n"
	if err := os.WriteFile(filepath.Join(dir, "templates", "notes-under-test.yaml"), []byte(cm), 0o644); err != nil {
		t.Fatal(err)
	}
	objs := docs(t, run(t, "helm", "template", "imas-core", dir, "-n", "imas-core", "--kube-version", "1.31.0",
		"-f", "values/farmer-uat.yaml", "-f", runValues(t), "--show-only", "templates/notes-under-test.yaml"))
	n := str(get(t, objs, "ConfigMap/notes-under-test"), "data", "notes")
	for _, warning := range []string{"objectStore.sproutJWTBucket is empty", "bus.egressCIDRs is empty"} {
		if strings.Contains(n, warning) {
			t.Errorf("NOTES warns %q with the UAT values:\n%s", warning, n)
		}
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
	// saasapi's operator listener: the operator Service's names only, from
	// the UAT CA (whose ca.crt the registration Job verifies it with).
	opCert := get(t, objs, "Certificate/imas-saasapi-operator-tls")
	if got := mustJSON(t, dig(opCert, "spec", "dnsNames")); got != `["imas-core-farmer-saasapi-operator","imas-core-farmer-saasapi-operator.imas-core","imas-core-farmer-saasapi-operator.imas-core.svc","imas-core-farmer-saasapi-operator.imas-core.svc.cluster.local"]` {
		t.Errorf("operator certificate dnsNames %s", got)
	}
	if str(opCert, "metadata", "namespace") != "imas-core" || str(opCert, "spec", "secretName") != "imas-saasapi-operator-tls" || str(opCert, "spec", "issuerRef", "name") != "imas-uat-ca" {
		t.Errorf("operator certificate: %s", mustJSON(t, opCert))
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

	// RustFS: the S3 port is hostPort 9000, and its policy admits the DMZ
	// private address there (the bus's account loader, design D22) and no
	// other address: the one DMZ-to-core path besides farmer's API.
	if !strings.Contains(mustJSON(t, get(t, objs, "Deployment/imas-uat-rustfs")), `"containerPort":9000,"hostPort":9000`) {
		t.Error("RustFS's S3 port is not hostPort 9000")
	}
	mp := get(t, objs, "NetworkPolicy/imas-uat-rustfs")
	var blocks []string
	for _, r := range dig(mp, "spec", "ingress").([]any) {
		for _, f := range dig(r, "from").([]any) {
			if c := str(f, "ipBlock", "cidr"); c != "" {
				blocks = append(blocks, c+" "+mustJSON(t, dig(r, "ports")))
			}
		}
	}
	if want := dmzIP + `/32 [{"port":9000,"protocol":"TCP"}]`; len(blocks) != 1 || blocks[0] != want {
		t.Errorf("RustFS address ingress %v, want exactly [%s]", blocks, want)
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
// object_store object and returns its path. With accountStore, it also sets
// dmz.account_store.endpoint (required in external mode).
func withObjectStore(t *testing.T, os_ map[string]any, accountStore ...string) string {
	t.Helper()
	var ep map[string]any
	readJSON(t, endpointsFile, &ep)
	ep["object_store"] = os_
	for _, a := range accountStore {
		ep["dmz"].(map[string]any)["account_store"] = map[string]any{"endpoint": a}
	}
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
	if got := str(def, "objectStore", "endpoint"); got != "imas-uat-rustfs.imas-uat.svc.cluster.local:9000" {
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
	}, "s3gw.example.internal:7070")
	out := run(t, "bash", "gen-values.sh", ext, adminFile, releaseTag, loaderPubFile)
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
	for _, key := range []string{"Deployment/imas-uat-rustfs", "Service/imas-uat-rustfs", "PersistentVolumeClaim/imas-uat-rustfs-data", "NetworkPolicy/imas-uat-rustfs"} {
		if _, ok := objs[key]; ok {
			t.Errorf("external mode still renders %s", key)
		}
	}
	// The default still renders the store.
	defArgs := strings.Fields(string(run(t, "bash", "-c",
		`set -euo pipefail; . lib/common.sh; ENDPOINTS="$1"; load_endpoints; extras_set_args`, "_", endpointsFile)))
	defObjs := docs(t, run(t, "helm", append([]string{"template", "imas-uat-core", "chart", "-n", "imas-uat", "--kube-version", "1.31.0"}, defArgs...)...))
	for _, key := range []string{"Deployment/imas-uat-rustfs", "Service/imas-uat-rustfs", "PersistentVolumeClaim/imas-uat-rustfs-data", "NetworkPolicy/imas-uat-rustfs"} {
		get(t, defObjs, key)
	}
}

// TestObjectStoreEndpointRejected: bad object_store input stops load_endpoints.
func TestObjectStoreEndpointRejected(t *testing.T) {
	requireTools(t, "bash", "jq")
	for name, o := range map[string]map[string]any{
		"unknown mode":                            {"mode": "minio"},
		"external, no endpoint":                   {"mode": "external"},
		"external, no dmz.account_store.endpoint": {"mode": "external", "endpoint": "s3gw.example.internal:7070"},
		"scheme in endpoint":                      {"endpoint": "https://s3.example.internal"},
		"bad use_ssl":                             {"use_ssl": "yes"},
		"bad cidr":                                {"egress_cidrs": []string{"not-a-cidr"}},
	} {
		p := withObjectStore(t, o)
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . lib/common.sh; ENDPOINTS="$1"; load_endpoints`, "_", p)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Errorf("%s: load_endpoints accepted it: %s", name, out)
		}
	}
}
