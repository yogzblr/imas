// Package farmerchart tests the deploy/helm/farmer Helm chart by rendering
// it with the helm CLI and asserting on the manifests, including that it
// stays in step with the reviewed reference files it was built from
// (deploy/farmer, deploy/saasapi, deploy/fleetreleaser/policies). The tests
// skip when helm is not on PATH, so `go test ./...` stays green on
// machines without it; run them locally with helm v3 installed.
//
// The subcharts (OpenBao, PXC, Valkey) are fetched by `helm dependency
// build` and are not in the repo. Without them the chart is rendered with
// its dependencies stripped, which renders every template of this chart;
// TestSubchartsRender additionally renders the real subcharts when
// charts/ has been populated.
package farmerchart

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type obj = map[string]any

// required are the values the chart can't default (ci/default-values.yaml).
var required = []string{
	"--set", "bus.serviceName=imas-dmz-nats-bus",
	"--set", "bus.sproutBusURLs[0]=wss://bus.imas.example.com:443/",
	"--set", "saasapi.jwt.keycloakJWKSURL=https://kc.example.com/realms/x/protocol/openid-connect/certs",
	"--set", "saasapi.jwt.issuer=https://kc.example.com/realms/x",
	"--set", "saasapi.jwt.audience=imas-saasapi",
}

func chartDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate chart directory")
	}
	return filepath.Dir(file)
}

func repoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(chartDir(t), "..", "..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func helmBin(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not on PATH; skipping chart rendering tests")
	}
	return helm
}

// depsVendored reports whether charts/ holds every dependency archive.
func depsVendored(t *testing.T) bool {
	for _, p := range []string{"openbao-*.tgz", "pxc-operator-*.tgz", "pxc-db-*.tgz", "valkey-*.tgz"} {
		if m, _ := filepath.Glob(filepath.Join(chartDir(t), "charts", p)); len(m) == 0 {
			return false
		}
	}
	return true
}

// strippedChart copies the chart to a temp dir without its dependencies
// block (and without charts/), so it renders without the subcharts.
func strippedChart(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "farmer")
	src := chartDir(t)
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "charts" && d.IsDir() {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if rel == "Chart.yaml" {
			i := bytes.Index(b, []byte("\ndependencies:"))
			if i < 0 {
				t.Fatal("Chart.yaml has no dependencies block")
			}
			b = b[:i+1]
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func runHelm(t *testing.T, chart string, args ...string) ([]obj, error) {
	t.Helper()
	return renderAs(t, "t", "imas-core", chart, args...)
}

// renderAs runs `helm template` for any chart, release and namespace.
func renderAs(t *testing.T, release, namespace, chart string, args ...string) ([]obj, error) {
	t.Helper()
	cmd := exec.Command(helmBin(t), append([]string{"template", release, chart,
		"--namespace", namespace, "--kube-version", "1.30.0"}, args...)...)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.New(stderr.String())
	}
	dec := yaml.NewDecoder(&out)
	var docs []obj
	for {
		var d obj
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("parsing rendered YAML: %v", err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	for _, d := range docs {
		if n, _ := get(d, "metadata", "name").(string); !dns1123.MatchString(n) {
			t.Errorf("%v name %q is not a valid Kubernetes name", d["kind"], n)
		}
	}
	return docs, nil
}

// dns1123 is a DNS-1123 subdomain: what the API server requires of most
// object names (helm template doesn't check).
var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// render renders the chart without subcharts, with the required values
// first so args can override them.
func render(t *testing.T, args ...string) ([]obj, error) {
	t.Helper()
	helmBin(t)
	return runHelm(t, strippedChart(t), append(slices.Clone(required), args...)...)
}

func mustRender(t *testing.T, args ...string) []obj {
	t.Helper()
	docs, err := render(t, args...)
	if err != nil {
		t.Fatalf("helm template failed: %v", err)
	}
	return docs
}

func mustFail(t *testing.T, wantSubstr string, args ...string) {
	t.Helper()
	_, err := render(t, args...)
	if err == nil {
		t.Fatalf("expected render to fail with %q, it succeeded", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("render failed, but not with %q:\n%v", wantSubstr, err)
	}
}

func ciValues(t *testing.T, name string) string {
	return filepath.Join(chartDir(t), "ci", name)
}

func find(t *testing.T, docs []obj, kind, name string) obj {
	t.Helper()
	var hits []obj
	for _, d := range docs {
		if d["kind"] == kind && get(d, "metadata", "name") == name {
			hits = append(hits, d)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one %s %s, got %d", kind, name, len(hits))
	}
	return hits[0]
}

func findPrefix(t *testing.T, docs []obj, kind, prefix string) obj {
	t.Helper()
	var hits []obj
	for _, d := range docs {
		if n, _ := get(d, "metadata", "name").(string); d["kind"] == kind && strings.HasPrefix(n, prefix) {
			hits = append(hits, d)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one %s %s*, got %d", kind, prefix, len(hits))
	}
	return hits[0]
}

func has(docs []obj, kind, name string) bool {
	for _, d := range docs {
		if d["kind"] == kind && get(d, "metadata", "name") == name {
			return true
		}
	}
	return false
}

// get walks nested maps and list indexes (int path elements).
func get(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(obj)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func podSpec(w obj) obj { return get(w, "spec", "template", "spec").(obj) }

func container(t *testing.T, w obj, name string) obj {
	t.Helper()
	for _, c := range podSpec(w)["containers"].([]any) {
		if c.(obj)["name"] == name {
			return c.(obj)
		}
	}
	t.Fatalf("no container %q", name)
	return nil
}

func envMap(c obj) map[string]obj {
	m := map[string]obj{}
	for _, e := range c["env"].([]any) {
		m[e.(obj)["name"].(string)] = e.(obj)
	}
	return m
}

func envValues(c obj) map[string]string {
	m := map[string]string{}
	for k, e := range envMap(c) {
		v, _ := e["value"].(string)
		m[k] = v
	}
	return m
}

func byName(list any) map[string]obj {
	m := map[string]obj{}
	l, _ := list.([]any)
	for _, v := range l {
		m[v.(obj)["name"].(string)] = v.(obj)
	}
	return m
}

func farmerDeploy(t *testing.T, docs []obj) obj { return find(t, docs, "Deployment", "t-farmer") }

func farmerConfig(t *testing.T, docs []obj) obj {
	t.Helper()
	var cfg obj
	if err := yaml.Unmarshal([]byte(get(find(t, docs, "ConfigMap", "t-farmer"), "data", "farmer").(string)), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func readYAMLDocs(t *testing.T, rel string) []obj {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(repoFile(t, rel)))
	var docs []obj
	for {
		var d obj
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("%s: %v", rel, err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func TestDefaultsRender(t *testing.T) {
	docs := mustRender(t, "-f", ciValues(t, "default-values.yaml"))
	for _, want := range []struct{ kind, name string }{
		{"Deployment", "t-farmer"}, {"Service", "t-farmer"}, {"ConfigMap", "t-farmer"},
		{"ServiceAccount", "t-farmer"},
		{"PersistentVolumeClaim", "t-farmer-data"},
		{"Deployment", "t-farmer-saasapi"}, {"Service", "t-farmer-saasapi"},
		{"ServiceAccount", "t-farmer-saasapi"}, {"PodDisruptionBudget", "t-farmer-saasapi"},
		{"ServiceAccount", "imas-saasapi-cred-publisher"}, {"Job", "t-farmer-saasapi-credential-publish"},
		{"NetworkPolicy", "imas-saasapi-cred-publisher"},
		{"NetworkPolicy", "t-farmer"}, {"NetworkPolicy", "t-farmer-saasapi"},
		{"Secret", "t-farmer-db"}, {"Job", "t-farmer-openbao-bootstrap"},
		{"ConfigMap", "t-farmer-openbao-policies"}, {"Secret", "t-farmer-openbao-bootstrap"},
	} {
		if !has(docs, want.kind, want.name) {
			t.Errorf("missing %s %s", want.kind, want.name)
		}
	}
	findPrefix(t, docs, "Job", "t-farmer-db-bootstrap-")
	if has(docs, "ExternalSecret", "imas-farmer-nats-seeds") {
		t.Error("ExternalSecrets rendered with externalSecrets.enabled=false")
	}
	pvc := find(t, docs, "PersistentVolumeClaim", "t-farmer-data")
	if get(pvc, "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
		t.Error("FarmerPKI PVC is not kept on uninstall")
	}
	d := farmerDeploy(t, docs)
	if get(d, "spec", "replicas") != 1 || get(d, "spec", "strategy", "type") != "Recreate" {
		t.Errorf("farmer must be 1 replica with Recreate: %v %v", get(d, "spec", "replicas"), get(d, "spec", "strategy"))
	}
}

func TestValidationFailures(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		{"postgresql key", "postgresql.* is not a value of this chart", []string{"--set", "postgresql.enabled=true"}},
		{"no bus service", "bus.serviceName is required", []string{"--set", "bus.serviceName="}},
		{"no sprout bus urls", "bus.sproutBusURLs is required", []string{"--set", "bus.sproutBusURLs=null"}},
		{"non-wss sprout url", "must be a wss:// URL", []string{"--set", "bus.sproutBusURLs[0]=tls://bus:5406"}},
		{"bad organization", "not a valid tenant ID", []string{"--set", "organization=imas farmer"}},
		{"no seed secret", "natsSeeds.secretName is required", []string{"--set", "natsSeeds.secretName="}},
		{"missing saasapi seed", "natsSeeds.seeds.SAASAPI_USER is required", []string{"--set", "natsSeeds.seeds.SAASAPI_USER=null"}},
		{"missing operator seed", "natsSeeds.seeds.OPERATOR is required", []string{"--set", "natsSeeds.seeds.OPERATOR="}},
		{"bad seed name", "must match", []string{"--set", "natsSeeds.extraSeeds.bad-name=x.nk"}},
		{"two farmers", "farmer.replicaCount must be 1", []string{"--set", "farmer.replicaCount=2"}},
		{"bare number window", "must be a quoted duration", []string{"--set", "farmer.jobs.reconcileWindow=7200"}},
		{"fractional burst", "burst must be a whole number", []string{"--set", "saasapi.enrollmentKeys.rateLimit.burst=2.5"}},
		{"bad tls mode", "tls.mode must be", []string{"--set", "tls.mode=selfsigned"}},
		{"tls secret without name", "tls.secretName is required", []string{"--set", "tls.mode=secret", "--set", "tls.secretName="}},
		{"external openbao without addr", "openbaoClient.addr is required", []string{"--set", "openbao.enabled=false"}},
		{"token auth without secret", "tokenSecretName is required", []string{"--set", "openbaoClient.authMethod=token"}},
		{"external pxc without host", "database.host is required", []string{"--set", "pxc.enabled=false"}},
		{"external pxc without dsn secret", "database.existingSecret is required", []string{"--set", "pxc.enabled=false", "--set", "database.host=pxc"}},
		{"both bus CAs", "set only one of bus.ca", []string{"--set", "bus.ca.secretName=a", "--set", "bus.ca.configMapName=b"}},
		{"shared bucket", "jobBucket must differ", []string{"--set", "objectStore.bucket=b", "--set", "objectStore.jobBucket=b"}},
		{"no keycloak", "saasapi.jwt.keycloakJWKSURL is required", []string{"--set", "saasapi.jwt.keycloakJWKSURL="}},
		{"no saasapi creds", "natsCredentials.secretName is required", []string{"--set", "saasapi.natsCredentials.secretName="}},
		{"bad db identifier", "must match ^[A-Za-z0-9_]{1,32}$", []string{"--set", "database.farmer.user=farmer'--"}},

		// The publisher's boundary (deploy/farmer/README.md, "OpenBao policy").
		{"publisher path equals seed path", "must be different", []string{"--set", "credentialPublisher.kvPath=platform/imas/nats-seeds"}},
		{"publisher path under seed path", "must be different", []string{"--set", "externalSecrets.seedPath=platform/imas"}},
		{"publisher path has no default", "credentialPublisher.kvPath is required", []string{"--set", "credentialPublisher.kvPath="}},
		{"publisher runs as farmer", "must not be farmer's ServiceAccount", []string{"--set", "credentialPublisher.serviceAccountName=t-farmer"}},
		{"publisher runs as saasapi", "must not be saasapi's ServiceAccount", []string{"--set", "credentialPublisher.serviceAccountName=t-farmer-saasapi"}},
		{"publisher role is farmer's", "is also one of farmer's OpenBao roles", []string{"--set", "credentialPublisher.k8sRole=imas-farmer-gateway"}},

		// The bootstrap writes reviewed policies verbatim; values that
		// would point a client outside them are refused.
		{"bootstrap non-dev without token", "openbaoBootstrap.tokenSecretName is required", []string{"--set", "openbao.server.dev.enabled=false"}},
		{"bootstrap moved publisher path", "Keep credentialPublisher.kvMount=secret", []string{"--set", "credentialPublisher.kvPath=other/path"}},
		{"bootstrap renamed fleet key", "Keep *.openbao.fleetSign.transitMount=transit", []string{"--set", "farmer.openbao.fleetSign.keyName=other"}},
		{"bootstrap farmerbus without SA", "farmerbus.serviceAccountName is required", []string{"--set", "openbaoBootstrap.farmerbus.enabled=true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { mustFail(t, tc.want, tc.args...) })
	}
}

// deploy/farmer/farmer-deployment-nats-seeds.patch.yaml: every env var,
// mount and volume the reference patch adds is on the rendered farmer
// Deployment. The chart projects the four bus-trust seeds too (the
// nats chart needs them byte-identical), so its items are a superset.
func TestFarmerMatchesSeedPatch(t *testing.T) {
	ref := readYAMLDocs(t, "deploy/farmer/farmer-deployment-nats-seeds.patch.yaml")[0]
	refC := get(ref, "spec", "template", "spec", "containers", 0).(obj)
	d := farmerDeploy(t, mustRender(t))
	c := container(t, d, "farmer")
	got := envValues(c)
	for name, e := range envMap(refC) {
		if got[name] != e["value"] {
			t.Errorf("%s = %q, reference %q", name, got[name], e["value"])
		}
	}
	mounts := map[string]obj{}
	for _, m := range c["volumeMounts"].([]any) {
		mounts[m.(obj)["name"].(string)] = m.(obj)
	}
	for _, m := range refC["volumeMounts"].([]any) {
		m := m.(obj)
		g := mounts[m["name"].(string)]
		if g == nil || g["mountPath"] != m["mountPath"] || g["readOnly"] != m["readOnly"] {
			t.Errorf("mount %v: got %v", m, g)
		}
	}
	vols := byName(podSpec(d)["volumes"])
	for name, v := range byName(get(ref, "spec", "template", "spec", "volumes")) {
		g := vols[name]
		if get(g, "secret", "secretName") != get(v, "secret", "secretName") || get(g, "secret", "defaultMode") != get(v, "secret", "defaultMode") {
			t.Errorf("volume %s: got %v, reference %v", name, g, v)
		}
		items := map[string]string{}
		for _, it := range get(g, "secret", "items").([]any) {
			items[it.(obj)["key"].(string)] = it.(obj)["path"].(string)
		}
		for _, it := range get(v, "secret", "items").([]any) {
			if items[it.(obj)["key"].(string)] != it.(obj)["path"] {
				t.Errorf("volume %s: item %v missing", name, it)
			}
		}
		if len(items) != 6 {
			t.Errorf("seed volume projects %d keys, want the 6 in natsSeeds.seeds", len(items))
		}
	}
}

// deploy/farmer/saasapi-credential-publish-job.yaml: rendered with the
// reference's own placeholders filled in (external OpenBao at the same
// address, the same CA ConfigMap), the chart's Job, ServiceAccount and
// NetworkPolicy match it field for field. The chart may add only
// IMAS_SAASAPI_CRED_OPENBAO_K8S_MOUNT (its default value) and pod labels.
func TestPublishJobMatchesReference(t *testing.T) {
	ref := readYAMLDocs(t, "deploy/farmer/saasapi-credential-publish-job.yaml")
	refByKind := map[string]obj{}
	for _, d := range ref {
		refByKind[d["kind"].(string)] = d
	}
	docs := mustRender(t, "--set", "openbao.enabled=false",
		"--set", "openbaoClient.addr=https://openbao.openbao.svc:8200",
		"--set", "openbaoClient.caConfigMap=openbao-ca",
		"--set", "farmer.image.repository=REPLACE_WITH_FARMER_IMAGE")

	sa := find(t, docs, "ServiceAccount", "imas-saasapi-cred-publisher")
	if sa["automountServiceAccountToken"] != false {
		t.Error("publisher ServiceAccount automounts its token")
	}
	for _, d := range docs {
		if (d["kind"] == "RoleBinding" || d["kind"] == "ClusterRoleBinding") && strings.Contains(yamlString(t, d), "imas-saasapi-cred-publisher") {
			t.Errorf("%s grants the publisher Kubernetes RBAC", d["kind"])
		}
	}

	job := find(t, docs, "Job", "t-farmer-saasapi-credential-publish")
	rj := refByKind["Job"]
	for _, k := range []string{"helm.sh/hook", "helm.sh/hook-weight", "helm.sh/hook-delete-policy", "argocd.argoproj.io/hook", "argocd.argoproj.io/hook-delete-policy"} {
		if get(job, "metadata", "annotations", k) != get(rj, "metadata", "annotations", k) {
			t.Errorf("annotation %s = %v, reference %v", k, get(job, "metadata", "annotations", k), get(rj, "metadata", "annotations", k))
		}
	}
	for _, k := range []string{"backoffLimit", "activeDeadlineSeconds", "ttlSecondsAfterFinished"} {
		if get(job, "spec", k) != get(rj, "spec", k) {
			t.Errorf("spec.%s = %v, reference %v", k, get(job, "spec", k), get(rj, "spec", k))
		}
	}
	ps, rps := podSpec(job), podSpec(rj)
	for _, k := range []string{"restartPolicy", "serviceAccountName", "automountServiceAccountToken", "securityContext"} {
		if yamlString(t, ps[k]) != yamlString(t, rps[k]) {
			t.Errorf("pod %s = %v, reference %v", k, ps[k], rps[k])
		}
	}
	if get(job, "spec", "template", "metadata", "labels", "app.kubernetes.io/name") != "imas-saasapi-cred-publisher" {
		t.Error("publisher pod lost its reference name label (its NetworkPolicy selects on it)")
	}
	c, rc := container(t, job, "publish"), get(rps, "containers", 0).(obj)
	if !strings.HasPrefix(c["image"].(string), "REPLACE_WITH_FARMER_IMAGE:") {
		t.Errorf("publisher image %v is not farmer's", c["image"])
	}
	for _, k := range []string{"args", "securityContext", "resources", "volumeMounts"} {
		if yamlString(t, c[k]) != yamlString(t, rc[k]) {
			t.Errorf("container %s:\n%s\nreference:\n%s", k, yamlString(t, c[k]), yamlString(t, rc[k]))
		}
	}
	got, want := envValues(c), envValues(rc)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("env %s = %q, reference %q", k, got[k], v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok && k != "IMAS_SAASAPI_CRED_OPENBAO_K8S_MOUNT" {
			t.Errorf("env %s not in the reference", k)
		}
	}
	if yamlString(t, ps["volumes"]) != yamlString(t, rps["volumes"]) {
		t.Errorf("volumes:\n%s\nreference:\n%s", yamlString(t, ps["volumes"]), yamlString(t, rps["volumes"]))
	}

	np := find(t, docs, "NetworkPolicy", "imas-saasapi-cred-publisher")
	rnp := refByKind["NetworkPolicy"]
	if get(np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name") != "imas-saasapi-cred-publisher" {
		t.Error("NetworkPolicy doesn't select the publisher pods")
	}
	if l, _ := get(np, "spec", "ingress").([]any); len(l) != 0 {
		t.Error("publisher NetworkPolicy allows ingress")
	}
	if got, want := egressPorts(np), egressPorts(rnp); !slices.Equal(got, want) {
		t.Errorf("egress ports %v, reference %v", got, want)
	}
	if yamlString(t, get(np, "spec", "egress", 0, "to")) != yamlString(t, get(rnp, "spec", "egress", 0, "to")) {
		t.Errorf("OpenBao egress peer %v, reference %v", get(np, "spec", "egress", 0, "to"), get(rnp, "spec", "egress", 0, "to"))
	}
}

func egressPorts(np obj) []int {
	var ports []int
	for _, r := range get(np, "spec", "egress").([]any) {
		for _, p := range get(r, "ports").([]any) {
			ports = append(ports, get(p, "port").(int))
		}
	}
	return ports
}

func yamlString(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// deploy/farmer/externalsecrets.yaml: every data entry of both reference
// ExternalSecrets is rendered the same (secret key, remote key, property).
func TestExternalSecretsMatchReference(t *testing.T) {
	docs := mustRender(t, "--set", "externalSecrets.enabled=true")
	for _, ref := range readYAMLDocs(t, "deploy/farmer/externalsecrets.yaml") {
		name := get(ref, "metadata", "name").(string)
		es := find(t, docs, "ExternalSecret", name)
		for _, k := range []string{"refreshInterval", "secretStoreRef", "target"} {
			if yamlString(t, get(es, "spec", k)) != yamlString(t, get(ref, "spec", k)) {
				t.Errorf("%s spec.%s = %v, reference %v", name, k, get(es, "spec", k), get(ref, "spec", k))
			}
		}
		gotData := map[string]string{}
		for _, d := range get(es, "spec", "data").([]any) {
			gotData[d.(obj)["secretKey"].(string)] = yamlString(t, d.(obj)["remoteRef"])
		}
		for _, d := range get(ref, "spec", "data").([]any) {
			key := d.(obj)["secretKey"].(string)
			if gotData[key] != yamlString(t, d.(obj)["remoteRef"]) {
				t.Errorf("%s %s: remoteRef %s, reference %s", name, key, gotData[key], yamlString(t, d.(obj)["remoteRef"]))
			}
		}
	}
	// The seed ExternalSecret carries every seed farmer mounts.
	es := find(t, docs, "ExternalSecret", "imas-farmer-nats-seeds")
	if n := len(get(es, "spec", "data").([]any)); n != 6 {
		t.Errorf("seed ExternalSecret has %d entries, want 6", n)
	}
}

// The reviewed policies travel into the chart verbatim.
func TestPoliciesMatchReference(t *testing.T) {
	for _, name := range []string{"imas-fleet-signer.hcl", "imas-fleet-verify.hcl"} {
		want := repoFile(t, filepath.Join("deploy/fleetreleaser/policies", name))
		got, err := os.ReadFile(filepath.Join(chartDir(t), "files", "openbao-policies", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("files/openbao-policies/%s differs from deploy/fleetreleaser/policies/%s", name, name)
		}
	}

	// The publisher's policy is the ```hcl block in deploy/farmer/README.md
	// ("The Job's policy ... allows this and nothing else").
	readme := string(repoFile(t, "deploy/farmer/README.md"))
	m := regexp.MustCompile("(?s)`imas-saasapi-cred-publisher`,\\s+allows\\s+this\\s+and\\s+nothing\\s+else:\\*\\*\\s*```hcl\n(.*?)```").FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("deploy/farmer/README.md no longer has the publisher policy block")
	}
	got, err := os.ReadFile(filepath.Join(chartDir(t), "files", "openbao-policies", "imas-saasapi-cred-publisher.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	if policyStatements(string(got)) != policyStatements(m[1]) {
		t.Errorf("imas-saasapi-cred-publisher.hcl:\n%s\nREADME:\n%s", policyStatements(string(got)), policyStatements(m[1]))
	}

	// And the ConfigMap the bootstrap reads carries them unchanged.
	cm := find(t, mustRender(t), "ConfigMap", "t-farmer-openbao-policies")
	for _, name := range []string{"imas-fleet-signer.hcl", "imas-fleet-verify.hcl", "imas-saasapi-cred-publisher.hcl"} {
		want, _ := os.ReadFile(filepath.Join(chartDir(t), "files", "openbao-policies", name))
		if strings.TrimSuffix(get(cm, "data", name).(string), "\n") != strings.TrimSuffix(string(want), "\n") {
			t.Errorf("ConfigMap %s differs from the file", name)
		}
	}
}

// policyStatements drops comments and blank lines.
func policyStatements(hcl string) string {
	var out []string
	for _, l := range strings.Split(hcl, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// The farmer-only policies: exact paths, no wildcards, nothing on the
// fleet signing key's sign path or the publisher's KV path.
func TestFarmerPoliciesAreExact(t *testing.T) {
	cm := find(t, mustRender(t, "--set", "openbaoBootstrap.farmerbus.enabled=true",
		"--set", "openbaoBootstrap.farmerbus.serviceAccountName=imas-dmz-nats-bus"), "ConfigMap", "t-farmer-openbao-policies")
	want := map[string][]string{
		"imas-farmer-gateway.hcl":   {`path "transit/sign/imas-gateway-jwt"`, `path "transit/keys/imas-gateway-jwt"`},
		"imas-farmer-tenantbox.hcl": {`path "secret/data/imas/tenant-x25519"`},
		"imas-farmer-certs.hcl":     {`path "pki/issue/imas-farmer"`},
		"imas-farmerbus-certs.hcl":  {`path "pki/issue/imas-farmerbus"`},
	}
	for name, paths := range want {
		body, _ := get(cm, "data", name).(string)
		if body == "" {
			t.Errorf("policy %s not rendered", name)
			continue
		}
		var got []string
		for _, l := range strings.Split(policyStatements(body), "\n") {
			if strings.HasPrefix(l, "path ") {
				got = append(got, strings.TrimSuffix(l, " {"))
			}
		}
		if !slices.Equal(got, paths) {
			t.Errorf("%s paths %v, want %v", name, got, paths)
		}
		if strings.ContainsAny(policyStatements(body), "*+") {
			t.Errorf("%s has a wildcard", name)
		}
	}
}

// bootstrapRoles parses the bootstrap script's `role <name> <sa> <ns>
// <policy> <ttl> <maxttl>` lines.
func bootstrapRoles(t *testing.T, docs []obj) map[string][]string {
	t.Helper()
	return bootstrapRolesFor(t, docs, "t-farmer-openbao-bootstrap")
}

func bootstrapRolesFor(t *testing.T, docs []obj, jobName string) map[string][]string {
	t.Helper()
	job := find(t, docs, "Job", jobName)
	script := get(container(t, job, "bootstrap"), "args", 0).(string)
	roles := map[string][]string{}
	for _, l := range strings.Split(script, "\n") {
		f := strings.Fields(l)
		if len(f) == 7 && f[0] == "role" {
			roles[f[1]] = f[2:]
		}
	}
	return roles
}

// One role per client, one policy per role, each bound only to the
// ServiceAccount that client runs as. The publisher's role (the only KV
// write) is bound to the publisher's ServiceAccount alone, with a short
// TTL; nothing binds the fleet signer policy.
func TestBootstrapRoles(t *testing.T) {
	roles := bootstrapRoles(t, mustRender(t))
	want := map[string][]string{
		"imas-farmer-certs":           {"t-farmer", "imas-core", "imas-farmer-certs", "20m", "1h"},
		"imas-farmer-gateway":         {"t-farmer", "imas-core", "imas-farmer-gateway", "20m", "1h"},
		"imas-farmer-fleet-verify":    {"t-farmer", "imas-core", "imas-fleet-verify", "20m", "1h"},
		"imas-farmer-tenantbox":       {"t-farmer", "imas-core", "imas-farmer-tenantbox", "20m", "1h"},
		"imas-saasapi-cred-publisher": {"imas-saasapi-cred-publisher", "imas-core", "imas-saasapi-cred-publisher", "5m", "5m"},
	}
	if len(roles) != len(want) {
		t.Errorf("roles %v, want %v", roles, want)
	}
	for name, w := range want {
		if !slices.Equal(roles[name], w) {
			t.Errorf("role %s = %v, want %v", name, roles[name], w)
		}
	}
	for name, r := range roles {
		if r[2] == "imas-fleet-signer" {
			t.Errorf("role %s binds the fleet signer policy", name)
		}
	}

	// Fleet dispatch adds saasapi's verify-only role; tls.mode=secret drops
	// farmer's PKI role.
	roles = bootstrapRoles(t, mustRender(t, "--set", "saasapi.fleetUpdateDispatch.enabled=true", "--set", "tls.mode=secret"))
	if !slices.Equal(roles["imas-saasapi-fleet-verify"], []string{"t-farmer-saasapi", "imas-core", "imas-fleet-verify", "20m", "1h"}) {
		t.Errorf("saasapi fleet verify role = %v", roles["imas-saasapi-fleet-verify"])
	}
	if _, ok := roles["imas-farmer-certs"]; ok {
		t.Error("PKI role created in tls.mode=secret")
	}
}

// farmer never holds the KV-write identity: no IMAS_SAASAPI_CRED_* env,
// none of its roles is the publisher's, and its ServiceAccount isn't the
// publisher's. Same for saasapi.
func TestFarmerNeverGetsPublisherIdentity(t *testing.T) {
	for _, args := range [][]string{nil, {"-f", ciValues(t, "external-values.yaml")}, {"-f", ciValues(t, "token-auth-values.yaml")}} {
		docs := mustRender(t, args...)
		for _, name := range []string{"t-farmer", "t-farmer-saasapi"} {
			d := find(t, docs, "Deployment", name)
			if podSpec(d)["serviceAccountName"] == "imas-saasapi-cred-publisher" {
				t.Errorf("%s runs as the publisher ServiceAccount", name)
			}
			for _, c := range podSpec(d)["containers"].([]any) {
				env, _ := c.(obj)["env"].([]any)
				for _, e := range env {
					n := e.(obj)["name"].(string)
					if strings.HasPrefix(n, "IMAS_SAASAPI_CRED_") || strings.HasPrefix(n, "IMAS_FLEETRELEASER_") {
						t.Errorf("%s has %s", name, n)
					}
					if strings.HasSuffix(n, "_K8S_ROLE") && e.(obj)["value"] == "imas-saasapi-cred-publisher" {
						t.Errorf("%s logs in with the publisher role via %s", name, n)
					}
					if strings.HasSuffix(n, "_SEED") {
						t.Errorf("%s has a raw seed env var %s; only _SEED_FILE is allowed", name, n)
					}
					if key, _ := get(e, "valueFrom", "secretKeyRef", "key").(string); key == "publisher-token" {
						t.Errorf("%s reads the publisher's token", name)
					}
				}
			}
		}
	}
}

// The chart never renders key material: no Secret it renders carries a
// seed, and every seed reaches a process as a _SEED_FILE path.
func TestSeedsAreReferencesOnly(t *testing.T) {
	docs := mustRender(t, "--set", "externalSecrets.enabled=true")
	seedKeys := []string{"operator.nk", "operator-signing.nk", "sys-account.nk", "tenant.nk", "tenant-signing.nk", "saasapi-user.nk", "nats-user.nk"}
	for _, d := range docs {
		if d["kind"] != "Secret" {
			continue
		}
		for k := range get(d, "stringData").(obj) {
			if slices.Contains(seedKeys, k) {
				t.Errorf("Secret %v carries seed %s", get(d, "metadata", "name"), k)
			}
		}
	}
	env := envValues(container(t, farmerDeploy(t, docs), "farmer"))
	for name, key := range map[string]string{
		"OPERATOR": "operator.nk", "OPERATOR_SIGNING": "operator-signing.nk", "SYS_ACCOUNT": "sys-account.nk",
		"TENANT": "tenant.nk", "TENANT_SIGNING": "tenant-signing.nk", "SAASAPI_USER": "saasapi-user.nk",
	} {
		if got := env["IMAS_NATS_"+name+"_SEED_FILE"]; got != "/var/run/secrets/imas/nats/"+key {
			t.Errorf("IMAS_NATS_%s_SEED_FILE = %q", name, got)
		}
	}
	// saasapi mounts only its own seed.
	sv := byName(podSpec(find(t, docs, "Deployment", "t-farmer-saasapi"))["volumes"])
	items := get(sv["nats-credentials"], "secret", "items").([]any)
	if get(sv["nats-credentials"], "secret", "secretName") != "imas-saasapi-nats" || len(items) != 1 || get(items[0], "key") != "nats-user.nk" {
		t.Errorf("saasapi credential volume: %v", sv["nats-credentials"])
	}
	for _, v := range sv {
		if get(v, "secret", "secretName") == "imas-farmer-nats-seeds" {
			t.Error("saasapi mounts farmer's seed Secret")
		}
	}
}

// Job names become a label value (job-name), so they must stay within 63
// characters whatever the release is called.
func TestLongReleaseName(t *testing.T) {
	helmBin(t)
	cmd := exec.Command(helmBin(t), append([]string{"template", strings.Repeat("r", 53), strippedChart(t),
		"--namespace", "imas-core", "--kube-version", "1.30.0"}, required...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var d obj
		if err := dec.Decode(&d); err != nil {
			break
		}
		if n, _ := get(d, "metadata", "name").(string); d["kind"] == "Job" && len(n) > 63 {
			t.Errorf("Job name %q is %d characters", n, len(n))
		}
	}
}

// Reaching the bus (#18): farmerinterface is only farmer's bind address;
// farmer dials farmerbusurl, the bus Service FQDN, and verifies the bus
// certificate against its host unless bus.tlsServerName names another.
// saasapi dials the same URL. No relay, no hostAliases.
func TestBusAddress(t *testing.T) {
	docs := mustRender(t, "--set", "bus.namespace=dmz", "--set", "bus.port=7422")
	url := "tls://imas-dmz-nats-bus.dmz.svc.cluster.local:7422"
	cfg := farmerConfig(t, docs)
	if cfg["farmerinterface"] != "0.0.0.0" || cfg["farmerbusurl"] != url || cfg["farmerbusport"] != "7422" {
		t.Errorf("farmerinterface/farmerbusurl/farmerbusport = %v/%v/%v", cfg["farmerinterface"], cfg["farmerbusurl"], cfg["farmerbusport"])
	}
	if _, ok := cfg["farmerbustlsservername"]; ok {
		t.Error("farmerbustlsservername set by default; it should follow farmerbusurl's host")
	}
	d := farmerDeploy(t, docs)
	if podSpec(d)["hostAliases"] != nil {
		t.Error("farmer still pins a host with hostAliases")
	}
	if n := len(podSpec(d)["containers"].([]any)); n != 1 {
		t.Errorf("farmer pod has %d containers; the bus relay sidecar is gone", n)
	}
	for _, doc := range docs {
		if n, _ := get(doc, "metadata", "name").(string); strings.Contains(n, "relay") {
			t.Errorf("%v %s still rendered", doc["kind"], n)
		}
	}
	if env := envValues(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi")); env["SAASAPI_NATS_URL"] != url {
		t.Errorf("SAASAPI_NATS_URL = %q, want farmer's %s", env["SAASAPI_NATS_URL"], url)
	}

	cfg = farmerConfig(t, mustRender(t, "--set", "bus.tlsServerName=bus.example.internal"))
	if cfg["farmerbustlsservername"] != "bus.example.internal" {
		t.Errorf("farmerbustlsservername = %v", cfg["farmerbustlsservername"])
	}
	mustFail(t, "must be a DNS name", "--set", "bus.tlsServerName=tls://bus:5406")
}

func TestFarmerConfigFile(t *testing.T) {
	docs := mustRender(t, "--set", "farmer.extraConfig.farmerorganization=evil",
		"--set", "farmer.extraConfig.cohortrefreshinterval=1m",
		"--set", "farmer.adminPubKeys[0]=UADMIN")
	cfg := farmerConfig(t, docs)
	if cfg["farmerorganization"] != "imas" {
		t.Errorf("extraConfig overrode a chart-managed key: %v", cfg["farmerorganization"])
	}
	if cfg["cohortrefreshinterval"] != "1m" {
		t.Error("extraConfig key not merged")
	}
	if !slices.Equal(cfg["sproutbusurls"].([]any), []any{"wss://bus.imas.example.com:443/"}) {
		t.Errorf("sproutbusurls = %v", cfg["sproutbusurls"])
	}
	if get(cfg, "pubkeys", "admin", 0) != "UADMIN" {
		t.Errorf("pubkeys = %v", cfg["pubkeys"])
	}
	for k, want := range map[string]string{
		"farmerpki": "/var/lib/imas/farmer/pki/", "nkeyfarmerprivfile": "/var/lib/imas/farmer/pki/farmer.nkey",
		"auditlogdir": "/var/lib/imas/farmer/audit", "gatewaytransitkeyname": "imas-gateway-jwt",
		"rootca": "/var/run/imas/tls/tls-rootca.pem",
	} {
		if cfg[k] != want {
			t.Errorf("%s = %v, want %s", k, cfg[k], want)
		}
	}
	// No connection strings in the file: they'd override the env vars.
	for _, k := range []string{"pxcdsn", "valkeyaddrs", "s3secretaccesskey"} {
		if _, ok := cfg[k]; ok {
			t.Errorf("config file sets %s", k)
		}
	}
	c := container(t, farmerDeploy(t, docs), "farmer")
	for _, m := range c["volumeMounts"].([]any) {
		if m := m.(obj); m["mountPath"] == "/etc/imas/farmer" && m["readOnly"] != true {
			t.Error("/etc/imas/farmer must be mounted read-only (jety.WriteConfig would dump env vars, IMAS_PXC_DSN included, into it)")
		}
	}
	if podSpec(farmerDeploy(t, docs))["enableServiceLinks"] != false {
		t.Error("enableServiceLinks must be false (config.LoadConfig folds every env var into the config)")
	}
}

// deploy/farmer/deployment.env.job-reconcile.yaml semantics.
func TestReconcileWindow(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "2h"},
		{[]string{"--set-string", "farmer.jobs.reconcileWindow=90m"}, "90m"},
		{[]string{"--set", "farmer.jobs.reconcileWindow="}, ""},
		{[]string{"--set", "farmer.jobs.reconcileWindow=null"}, ""},
	} {
		env := envMap(container(t, farmerDeploy(t, mustRender(t, tc.args...)), "farmer"))
		e, ok := env["IMAS_JOB_RECONCILE_WINDOW"]
		if tc.want == "" {
			if ok {
				t.Errorf("%v: IMAS_JOB_RECONCILE_WINDOW rendered", tc.args)
			}
		} else if !ok || e["value"] != tc.want {
			t.Errorf("%v: IMAS_JOB_RECONCILE_WINDOW = %v, want %s", tc.args, e, tc.want)
		}
	}
}

// deploy/saasapi/deployment.env.rate-limit.yaml semantics.
func TestSaasapiRateLimitEnv(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		rate, burst string
	}{
		{nil, "1", "5"},
		{[]string{"--set", "saasapi.enrollmentKeys.rateLimit.perSecond=0.5"}, "0.5", "5"},
		{[]string{"--set", "saasapi.enrollmentKeys.rateLimit.burst=1000000"}, "1", "1000000"},
		{[]string{"--set", "saasapi.enrollmentKeys.rateLimit.perSecond=null", "--set", "saasapi.enrollmentKeys.rateLimit.burst=null"}, "", ""},
	} {
		env := envMap(container(t, find(t, mustRender(t, tc.args...), "Deployment", "t-farmer-saasapi"), "saasapi"))
		for name, want := range map[string]string{"SAASAPI_ENROLLMENT_KEY_RATE_LIMIT": tc.rate, "SAASAPI_ENROLLMENT_KEY_RATE_BURST": tc.burst} {
			e, ok := env[name]
			if want == "" && ok {
				t.Errorf("%v: %s rendered for a null value", tc.args, name)
			}
			if want != "" && (!ok || e["value"] != want) {
				t.Errorf("%v: %s = %v, want %s", tc.args, name, e, want)
			}
		}
	}
}

// farmer and saasapi share PXC and Valkey: both DSNs point at the same
// host, both Valkey lists are identical (saasapi reads farmer's heartbeat
// keys).
func TestSharedDependencies(t *testing.T) {
	check := func(t *testing.T, docs []obj, dsnSecret, valkey string) {
		t.Helper()
		f := envMap(container(t, farmerDeploy(t, docs), "farmer"))
		s := envMap(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))
		if get(f["IMAS_PXC_DSN"], "valueFrom", "secretKeyRef", "name") != dsnSecret ||
			get(s["SAASAPI_DSN"], "valueFrom", "secretKeyRef", "name") != dsnSecret {
			t.Errorf("DSN Secrets: %v / %v, want %s", f["IMAS_PXC_DSN"], s["SAASAPI_DSN"], dsnSecret)
		}
		if f["IMAS_VALKEY_ADDRS"]["value"] != valkey || s["SAASAPI_VALKEY_ADDRS"]["value"] != valkey {
			t.Errorf("Valkey: %v / %v, want %s", f["IMAS_VALKEY_ADDRS"], s["SAASAPI_VALKEY_ADDRS"], valkey)
		}
	}
	t.Run("bundled", func(t *testing.T) {
		docs := mustRender(t)
		check(t, docs, "t-farmer-db", "t-valkey.imas-core.svc.cluster.local:6379")
		sec := find(t, docs, "Secret", "t-farmer-db")
		fdsn := get(sec, "stringData", "farmer-dsn").(string)
		sdsn := get(sec, "stringData", "saasapi-dsn").(string)
		re := regexp.MustCompile(`^(\w+):([A-Za-z0-9]{32})@tcp\(t-pxc-haproxy\.imas-core\.svc\.cluster\.local:3306\)/(\w+)\?parseTime=true&charset=utf8mb4&loc=UTC$`)
		fm, sm := re.FindStringSubmatch(fdsn), re.FindStringSubmatch(sdsn)
		if fm == nil || sm == nil || fm[1] != "farmer_svc" || fm[3] != "farmer" || sm[1] != "saas_svc" || sm[3] != "saas" {
			t.Fatalf("DSNs: %q / %q", fdsn, sdsn)
		}
		if fm[2] != get(sec, "stringData", "farmer-password") || sm[2] != get(sec, "stringData", "saasapi-password") || fm[2] == sm[2] {
			t.Error("DSN passwords don't match the stored ones, or are shared")
		}
	})
	t.Run("external", func(t *testing.T) {
		docs := mustRender(t, "-f", ciValues(t, "external-values.yaml"))
		check(t, docs, "imas-core-db", "valkey-0.valkey.valkey.svc.cluster.local:6379,valkey-1.valkey.valkey.svc.cluster.local:6379")
		for _, d := range docs {
			if d["kind"] == "Secret" || d["kind"] == "Job" && d["metadata"].(obj)["name"] != "t-farmer-saasapi-credential-publish" {
				t.Errorf("external mode rendered %s %v", d["kind"], get(d, "metadata", "name"))
			}
		}
		env := envValues(container(t, farmerDeploy(t, docs), "farmer"))
		for _, k := range []string{"IMAS_GATEWAY_OPENBAO_ADDR", "IMAS_FLEETSIGN_OPENBAO_ADDR", "IMAS_TENANTBOX_OPENBAO_ADDR"} {
			if env[k] != "https://openbao.openbao.svc:8200" {
				t.Errorf("%s = %q", k, env[k])
			}
		}
		if env["IMAS_GATEWAY_OPENBAO_CACERT"] != "/var/run/secrets/openbao-ca/ca.crt" {
			t.Error("external OpenBao CA not wired")
		}
		if _, ok := env["IMAS_CERTS_OPENBAO_ADDR"]; ok {
			t.Error("tls.mode=secret still configures the PKI client")
		}
		if env["IMAS_S3_BUCKET"] != "imas-recipes" || env["IMAS_S3_JOB_BUCKET"] != "imas-jobs" {
			t.Errorf("S3 env: %v", env)
		}
	})
	t.Run("no valkey", func(t *testing.T) {
		docs := mustRender(t, "--set", "valkey.enabled=false")
		if _, ok := envMap(container(t, farmerDeploy(t, docs), "farmer"))["IMAS_VALKEY_ADDRS"]; ok {
			t.Error("IMAS_VALKEY_ADDRS rendered with no Valkey")
		}
		if _, ok := envMap(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))["SAASAPI_VALKEY_ADDRS"]; ok {
			t.Error("SAASAPI_VALKEY_ADDRS rendered with no Valkey (saasapi would refuse to start on \"\")")
		}
	})
}

// The db-bootstrap Job is named by a hash of its pod template: stable
// across renders (so an upgrade with nothing changed is a no-op, even
// though the generated passwords aren't in it), new when the spec changes.
func TestDBBootstrapJob(t *testing.T) {
	name := func(args ...string) string {
		return get(findPrefix(t, mustRender(t, args...), "Job", "t-farmer-db-bootstrap-"), "metadata", "name").(string)
	}
	a, b := name(), name()
	if a != b {
		t.Errorf("db-bootstrap name not stable across renders: %s / %s", a, b)
	}
	if c := name("--set", "database.saasapi.user=saas2"); c == a {
		t.Error("db-bootstrap name unchanged after a spec change")
	}
	job := findPrefix(t, mustRender(t), "Job", "t-farmer-db-bootstrap-")
	if get(job, "metadata", "annotations", "helm.sh/hook") != nil {
		t.Error("db-bootstrap must not be a hook: it waits on saasapi, which would block helm install")
	}
	c := container(t, job, "bootstrap")
	script := get(c, "args", 0).(string)
	for _, want := range []string{
		"GRANT ALL    ON \\`$FARMER_DB\\`.* TO '$FARMER_USER'@'%';",
		"GRANT SELECT ON \\`$SAAS_DB\\`.*   TO '$FARMER_USER'@'%';",
		"GRANT ALL    ON \\`$SAAS_DB\\`.*   TO '$SAAS_USER'@'%';",
		"GRANT SELECT ON \\`$FARMER_DB\\`.* TO '$SAAS_USER'@'%';",
		"GRANT UPDATE (used_count, last_used_at) ON \\`$SAAS_DB\\`.\\`enrollment_keys\\` TO '$FARMER_USER'@'%';",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap SQL lacks %s", want)
		}
	}
	env := envMap(c)
	if get(env["ROOT_PASSWORD"], "valueFrom", "secretKeyRef", "name") != "t-pxc-secrets" {
		t.Errorf("root password Secret %v", env["ROOT_PASSWORD"])
	}
	if strings.Contains(yamlString(t, job), "stringData") || strings.Contains(script, "--password") || strings.Contains(script, "MYSQL_PWD") {
		t.Error("a password may reach the Job spec or argv")
	}
	// No bootstrap with externally supplied DSNs: the chart can't know the passwords.
	for _, d := range mustRender(t, "--set", "database.existingSecret=mine") {
		if n, _ := get(d, "metadata", "name").(string); strings.HasPrefix(n, "t-farmer-db") {
			t.Errorf("rendered %s with database.existingSecret", n)
		}
	}
}

// saasapi's bus CA: an explicit source wins; else farmer's TLS Secret's
// ca.crt only (never its key); else fetched from OpenBao PKI.
func TestSaasapiBusCA(t *testing.T) {
	vol := func(docs []obj) obj {
		return byName(podSpec(find(t, docs, "Deployment", "t-farmer-saasapi"))["volumes"])["bus-ca"]
	}
	docs := mustRender(t)
	if get(vol(docs), "emptyDir") == nil || get(podSpec(find(t, docs, "Deployment", "t-farmer-saasapi")), "initContainers", 0, "name") != "fetch-bus-ca" {
		t.Error("openbao mode: bus CA not fetched from OpenBao")
	}
	docs = mustRender(t, "--set", "tls.mode=secret")
	v := vol(docs)
	if get(v, "secret", "secretName") != "imas-farmer-tls" || len(get(v, "secret", "items").([]any)) != 1 || get(v, "secret", "items", 0, "key") != "ca.crt" {
		t.Errorf("secret mode bus CA volume: %v", v)
	}
	if podSpec(find(t, docs, "Deployment", "t-farmer-saasapi"))["initContainers"] != nil {
		t.Error("secret mode still fetches the CA")
	}
	v = vol(mustRender(t, "--set", "bus.ca.configMapName=bus-ca", "--set", "bus.ca.key=root.pem"))
	if get(v, "configMap", "name") != "bus-ca" || get(v, "configMap", "items", 0, "key") != "root.pem" || get(v, "configMap", "items", 0, "path") != "ca.crt" {
		t.Errorf("configMap bus CA volume: %v", v)
	}
}

// Token auth: each client reads its own key; the publisher reads its own
// Secret.
func TestTokenAuth(t *testing.T) {
	docs := mustRender(t, "-f", ciValues(t, "token-auth-values.yaml"))
	f := envMap(container(t, farmerDeploy(t, docs), "farmer"))
	for name, key := range map[string]string{
		"IMAS_CERTS_OPENBAO_TOKEN": "certs-token", "IMAS_GATEWAY_OPENBAO_TOKEN": "gateway-token",
		"IMAS_FLEETSIGN_OPENBAO_TOKEN": "farmer-fleetsign-token", "IMAS_TENANTBOX_OPENBAO_TOKEN": "tenantbox-token",
	} {
		ref := get(f[name], "valueFrom", "secretKeyRef").(obj)
		if ref["name"] != "imas-core-openbao-tokens" || ref["key"] != key {
			t.Errorf("%s from %v", name, ref)
		}
	}
	if _, ok := f["IMAS_GATEWAY_OPENBAO_K8S_ROLE"]; ok {
		t.Error("token auth still sets a Kubernetes role")
	}
	if byName(podSpec(farmerDeploy(t, docs))["volumes"])["openbao-auth"] != nil {
		t.Error("token auth still mounts a projected token")
	}
	s := envMap(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))
	if get(s["IMAS_FLEETSIGN_OPENBAO_TOKEN"], "valueFrom", "secretKeyRef", "key") != "saasapi-fleetsign-token" || s["SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED"]["value"] != "true" {
		t.Errorf("saasapi fleet dispatch env: %v", s)
	}
	p := envMap(container(t, find(t, docs, "Job", "t-farmer-saasapi-credential-publish"), "publish"))
	ref := get(p["IMAS_SAASAPI_CRED_OPENBAO_TOKEN"], "valueFrom", "secretKeyRef").(obj)
	if ref["name"] != "imas-publisher-openbao-token" || ref["key"] != "publisher-token" {
		t.Errorf("publisher token from %v", ref)
	}
}

// NetworkPolicies: farmer only takes the DMZ Envoy on its API port and
// only dials the bus, PXC, Valkey, OpenBao and DNS; saasapi reaches
// OpenBao only when it needs it.
func TestNetworkPolicy(t *testing.T) {
	docs := mustRender(t)
	fnp := find(t, docs, "NetworkPolicy", "t-farmer")
	if got := egressPorts(fnp); !slices.Equal(got, []int{5406, 3306, 6379, 8200, 53, 53}) {
		t.Errorf("farmer egress ports %v", got)
	}
	in := get(fnp, "spec", "ingress", 0).(obj)
	if get(in, "ports", 0, "port") != 5405 || get(in, "from", 0, "podSelector", "matchLabels", "app.kubernetes.io/component") != "envoy" ||
		get(in, "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "imas-dmz" {
		t.Errorf("farmer ingress %v", in)
	}
	bus := get(fnp, "spec", "egress", 0, "to", 0).(obj)
	if get(bus, "podSelector", "matchLabels", "app.kubernetes.io/component") != "bus" {
		t.Errorf("farmer bus egress peer %v", bus)
	}

	// saasapi, secret TLS mode, no fleet dispatch: no OpenBao at all.
	docs = mustRender(t, "--set", "tls.mode=secret")
	if got := egressPorts(find(t, docs, "NetworkPolicy", "t-farmer-saasapi")); !slices.Equal(got, []int{5406, 3306, 6379, 53, 53, 443}) {
		t.Errorf("saasapi egress ports %v", got)
	}
	// External dependencies use the configured peers.
	docs = mustRender(t, "-f", ciValues(t, "external-values.yaml"))
	for _, r := range get(find(t, docs, "NetworkPolicy", "t-farmer"), "spec", "egress").([]any) {
		port := get(r, "ports", 0, "port")
		peer := get(r, "to", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")
		want := map[any]string{3306: "pxc", 6379: "valkey", 8200: "openbao"}[port]
		if want != "" && peer != want {
			t.Errorf("port %v egress peer %v, want namespace %s", port, peer, want)
		}
	}
	if !has(mustRender(t, "--set", "networkPolicy.enabled=false"), "NetworkPolicy", "imas-saasapi-cred-publisher") {
		t.Error("the publisher's NetworkPolicy is part of its reviewed boundary and must not follow networkPolicy.enabled")
	}
}

// With `helm dependency build` run, the real subcharts render and the
// Service names this chart derives match theirs.
func TestSubchartsRender(t *testing.T) {
	helmBin(t)
	if !depsVendored(t) {
		t.Skip("charts/ not populated; run `helm dependency build deploy/helm/farmer` to include the subcharts")
	}
	docs, err := runHelm(t, chartDir(t), required...)
	if err != nil {
		t.Fatalf("helm template with subcharts failed: %v", err)
	}
	for _, want := range []struct{ kind, name string }{
		{"Service", "t-openbao"}, {"Service", "t-valkey"},
		{"PerconaXtraDBCluster", "t-pxc"}, {"Deployment", "t-pxc-operator"},
	} {
		if !has(docs, want.kind, want.name) {
			t.Errorf("subchart %s %s missing", want.kind, want.name)
		}
	}
	env := envValues(container(t, farmerDeploy(t, docs), "farmer"))
	if env["IMAS_GATEWAY_OPENBAO_ADDR"] != "http://t-openbao.imas-core.svc.cluster.local:8200" ||
		env["IMAS_VALKEY_ADDRS"] != "t-valkey.imas-core.svc.cluster.local:6379" {
		t.Errorf("derived subchart addresses: %v", env)
	}
	pxc := find(t, docs, "PerconaXtraDBCluster", "t-pxc")
	if get(pxc, "spec", "haproxy", "enabled") != true {
		t.Error("HAProxy off: t-pxc-haproxy wouldn't exist")
	}
	if get(pxc, "spec", "secretsName") != "t-pxc-secrets" {
		t.Errorf("PXC secretsName %v: db-bootstrap reads the root password from t-pxc-secrets", get(pxc, "spec", "secretsName"))
	}

	// The toggles: each subchart follows its own enabled flag, and the
	// operator follows pxc.enabled unless pxc-operator.enabled is set.
	for _, tc := range []struct {
		args []string
		want map[string]bool
	}{
		{[]string{"--set", "pxc.enabled=false", "--set", "database.host=pxc", "--set", "database.existingSecret=dsn"},
			map[string]bool{"PerconaXtraDBCluster/t-pxc": false, "Deployment/t-pxc-operator": false, "StatefulSet/t-openbao": true, "Service/t-valkey": true}},
		{[]string{"--set", "pxc-operator.enabled=false"},
			map[string]bool{"PerconaXtraDBCluster/t-pxc": true, "Deployment/t-pxc-operator": false}},
		{[]string{"--set", "openbao.enabled=false", "--set", "openbaoClient.addr=https://bao:8200", "--set", "valkey.enabled=false"},
			map[string]bool{"StatefulSet/t-openbao": false, "Service/t-valkey": false, "PerconaXtraDBCluster/t-pxc": true}},
	} {
		docs, err := runHelm(t, chartDir(t), append(slices.Clone(required), tc.args...)...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		for kn, want := range tc.want {
			kind, name, _ := strings.Cut(kn, "/")
			if has(docs, kind, name) != want {
				t.Errorf("%v: %s present = %v, want %v", tc.args, kn, !want, want)
			}
		}
	}
}

// Chart.lock (written by `helm dependency update`) pins exactly the
// dependencies Chart.yaml declares. helm itself refuses a lock whose digest
// is stale; this catches the drift in `go test`, before anyone runs helm.
func TestChartLockMatchesChartYaml(t *testing.T) {
	var chart, lock struct {
		Dependencies []struct{ Name, Version, Repository string }
		Digest       string
	}
	for _, f := range []struct {
		name string
		into any
	}{{"Chart.yaml", &chart}, {"Chart.lock", &lock}} {
		b, err := os.ReadFile(filepath.Join(chartDir(t), f.name))
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(b, f.into); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
	}
	if !strings.HasPrefix(lock.Digest, "sha256:") {
		t.Errorf("Chart.lock digest %q", lock.Digest)
	}
	if len(chart.Dependencies) != len(lock.Dependencies) {
		t.Fatalf("Chart.yaml has %d dependencies, Chart.lock %d", len(chart.Dependencies), len(lock.Dependencies))
	}
	for i, d := range chart.Dependencies {
		if l := lock.Dependencies[i]; l != d {
			t.Errorf("dependency %d: Chart.yaml %+v, Chart.lock %+v", i, d, l)
		}
	}
}

// matches reports whether a LabelSelector's matchLabels all appear in labels.
func matches(selector any, labels map[string]any) bool {
	ml, _ := get(selector, "matchLabels").(obj)
	if len(ml) == 0 {
		return false
	}
	for k, v := range ml {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func podLabels(w obj) map[string]any { return get(w, "spec", "template", "metadata", "labels").(obj) }

func nsLabels(ns string) map[string]any { return obj{"kubernetes.io/metadata.name": ns} }

// allows reports whether a NetworkPolicy rule list ("ingress" peers under
// "from", "egress" under "to") admits pods with podLbls in namespace ns
// (or in the policy's own namespace when a peer has no namespaceSelector)
// on port.
func allows(np obj, direction string, ns string, podLbls map[string]any, port int) bool {
	peersKey := map[string]string{"ingress": "from", "egress": "to"}[direction]
	own := get(np, "metadata", "namespace")
	for _, r := range get(np, "spec", direction).([]any) {
		portOK := false
		for _, p := range get(r, "ports").([]any) {
			if get(p, "port") == port {
				portOK = true
			}
		}
		if !portOK {
			continue
		}
		peers, _ := get(r, peersKey).([]any)
		if len(peers) == 0 {
			return true
		}
		for _, p := range peers {
			nsSel, podSel := get(p, "namespaceSelector"), get(p, "podSelector")
			nsOK := (nsSel == nil && own == ns) || (nsSel != nil && matches(nsSel, nsLabels(ns)))
			// No podSelector, or an empty one ({}), selects every pod.
			podML, _ := get(podSel, "matchLabels").(obj)
			podOK := len(podML) == 0 || matches(podSel, podLbls)
			if nsOK && podOK {
				return true
			}
		}
	}
	return false
}

// The contract with deploy/helm/nats as it is on this branch: both charts
// rendered side by side (DMZ release imas-dmz in imas-dmz, core release
// imas-core in imas-core, the bus certificate from this chart's OpenBao
// PKI) must agree on every name, port, selector, seed and SAN the other
// one relies on.
func TestContractWithNatsChart(t *testing.T) {
	helmBin(t)
	farmerFQDN := "imas-core-farmer.imas-core.svc.cluster.local"
	dmz, err := renderAs(t, "imas-dmz", "imas-dmz", filepath.Join(chartDir(t), "..", "nats"),
		"--set", "bus.tls.mode=openbao", "--set", "envoy.upstreams.farmerAPI.host="+farmerFQDN)
	if err != nil {
		t.Fatalf("nats chart: %v", err)
	}
	core, err := renderAs(t, "imas-core", "imas-core", strippedChart(t), append(slices.Clone(required),
		"--set", "openbaoBootstrap.farmerbus.enabled=true",
		"--set", "openbaoBootstrap.farmerbus.serviceAccountName=imas-dmz-nats-bus")...)
	if err != nil {
		t.Fatalf("farmer chart: %v", err)
	}

	bus := find(t, dmz, "StatefulSet", "imas-dmz-nats-bus")
	busSvc := find(t, dmz, "Service", "imas-dmz-nats-bus")
	envoy := find(t, dmz, "Deployment", "imas-dmz-nats-envoy")
	var busCfg obj
	if err := yaml.Unmarshal([]byte(get(find(t, dmz, "ConfigMap", "imas-dmz-nats-bus"), "data", "farmer").(string)), &busCfg); err != nil {
		t.Fatal(err)
	}
	farmer := find(t, core, "Deployment", "imas-core-farmer")
	saasapi := find(t, core, "Deployment", "imas-core-farmer-saasapi")
	var coreCfg obj
	if err := yaml.Unmarshal([]byte(get(find(t, core, "ConfigMap", "imas-core-farmer"), "data", "farmer").(string)), &coreCfg); err != nil {
		t.Fatal(err)
	}
	// The nats chart's bus Service, by FQDN.
	fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", get(busSvc, "metadata", "name"), get(busSvc, "metadata", "namespace"))

	// Addressing: farmer's farmerbusurl and saasapi's URL name the nats
	// chart's bus Service and its client port; farmer still binds 0.0.0.0.
	busPort := 0
	for _, p := range get(busSvc, "spec", "ports").([]any) {
		if get(p, "name") == "client" {
			busPort = get(p, "port").(int)
		}
	}
	busURL := fmt.Sprintf("tls://%s:%d", fqdn, busPort)
	if coreCfg["farmerbusurl"] != busURL || coreCfg["farmerinterface"] != "0.0.0.0" {
		t.Errorf("farmer dials %v (binds %v); the bus is %s", coreCfg["farmerbusurl"], coreCfg["farmerinterface"], busURL)
	}
	if env := envValues(container(t, saasapi, "saasapi")); env["SAASAPI_NATS_URL"] != busURL {
		t.Errorf("SAASAPI_NATS_URL = %s, want %s", env["SAASAPI_NATS_URL"], busURL)
	}
	// TLS: the bus certificate covers the name farmer verifies (config.
	// BusTLSServerName: farmerbustlsservername, else farmerbusurl's host)
	// and the one saasapi verifies (its URL's host).
	farmerName := fqdn
	if n, ok := coreCfg["farmerbustlsservername"].(string); ok && n != "" {
		farmerName = n
	}
	hosts, _ := busCfg["certhosts"].([]any)
	for _, n := range []string{farmerName, fqdn} {
		if !slices.Contains(hosts, any(n)) {
			t.Errorf("bus certhosts %v lack %s", hosts, n)
		}
	}
	// Trust chain: same organization, same seed Secret, same NAME -> key
	// for every seed the bus mounts.
	if busCfg["farmerorganization"] != coreCfg["farmerorganization"] {
		t.Errorf("farmerorganization: bus %v, core %v", busCfg["farmerorganization"], coreCfg["farmerorganization"])
	}
	busVols, farmerVols := byName(podSpec(bus)["volumes"]), byName(podSpec(farmer)["volumes"])
	if get(busVols["nats-seeds"], "secret", "secretName") != get(farmerVols["nats-seeds"], "secret", "secretName") {
		t.Error("the charts mount different seed Secrets")
	}
	busEnv, farmerEnv := envValues(container(t, bus, "farmerbus")), envValues(container(t, farmer, "farmer"))
	for k, v := range busEnv {
		if strings.HasSuffix(k, "_SEED_FILE") && farmerEnv[k] != v {
			t.Errorf("%s: bus %q, farmer %q", k, v, farmerEnv[k])
		}
	}
	// Network: each side's policy admits the other on the right port.
	dmzBusNP := find(t, dmz, "NetworkPolicy", "imas-dmz-nats-bus")
	dmzEnvoyNP := find(t, dmz, "NetworkPolicy", "imas-dmz-nats-envoy")
	coreFarmerNP := find(t, core, "NetworkPolicy", "imas-core-farmer")
	coreSaasNP := find(t, core, "NetworkPolicy", "imas-core-farmer-saasapi")
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"bus admits farmer on the client port", allows(dmzBusNP, "ingress", "imas-core", podLabels(farmer), busPort)},
		{"bus admits saasapi on the client port", allows(dmzBusNP, "ingress", "imas-core", podLabels(saasapi), busPort)},
		{"farmer may dial the bus", allows(coreFarmerNP, "egress", "imas-dmz", podLabels(bus), busPort)},
		{"saasapi may dial the bus", allows(coreSaasNP, "egress", "imas-dmz", podLabels(bus), busPort)},
		{"farmer admits Envoy on its API port", allows(coreFarmerNP, "ingress", "imas-dmz", podLabels(envoy), 5405)},
		{"Envoy may dial farmer's API port", allows(dmzEnvoyNP, "egress", "imas-core", podLabels(farmer), 5405)},
	} {
		if !c.ok {
			t.Errorf("NetworkPolicy: %s", c.name)
		}
	}
	// Envoy's upstream is this chart's farmer Service.
	var envoyCfg obj
	if err := yaml.Unmarshal([]byte(get(find(t, dmz, "ConfigMap", "imas-dmz-nats-envoy"), "data", "envoy.yaml").(string)), &envoyCfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range get(envoyCfg, "static_resources", "clusters").([]any) {
		if get(c, "name") == "farmer_api" {
			a := get(c, "load_assignment", "endpoints", 0, "lb_endpoints", 0, "endpoint", "address", "socket_address").(obj)
			found = a["address"] == farmerFQDN && a["port_value"] == get(find(t, core, "Service", "imas-core-farmer"), "spec", "ports", 0, "port")
		}
	}
	if !found {
		t.Error("the nats chart's farmer_api cluster doesn't point at this chart's farmer Service and port")
	}
	// Gateway JWT lifetime: the nats chart sizes Envoy's /v1/refresh bucket
	// from gatewayJwtTtlSeconds, which must equal farmer's gatewayjwtttl.
	var natsValues obj
	if err := yaml.Unmarshal(repoFile(t, "deploy/helm/nats/values.yaml"), &natsValues); err != nil {
		t.Fatal(err)
	}
	ttl, err := time.ParseDuration(fmt.Sprint(coreCfg["gatewayjwtttl"]))
	if err != nil || get(natsValues, "envoy", "refreshRateLimit", "gatewayJwtTtlSeconds") != int(ttl.Seconds()) {
		t.Errorf("gatewayjwtttl %v, nats chart gatewayJwtTtlSeconds %v", coreCfg["gatewayjwtttl"], get(natsValues, "envoy", "refreshRateLimit", "gatewayJwtTtlSeconds"))
	}
	// OpenBao: the bus logs in with, and issues from, exactly the roles
	// this chart's bootstrap creates.
	var projAudience any
	for _, v := range podSpec(bus)["volumes"].([]any) {
		if get(v, "name") == "openbao-auth" {
			projAudience = get(v, "projected", "sources", 0, "serviceAccountToken", "audience")
		}
	}
	roles := bootstrapRolesFor(t, core, "imas-core-farmer-openbao-bootstrap")
	br := roles[busEnv["IMAS_CERTS_OPENBAO_K8S_ROLE"]]
	if !slices.Equal(br[:3], []string{get(podSpec(bus), "serviceAccountName").(string), "imas-dmz", "imas-farmerbus-certs"}) {
		t.Errorf("bus login role %s = %v", busEnv["IMAS_CERTS_OPENBAO_K8S_ROLE"], br)
	}
	job := find(t, core, "Job", "imas-core-farmer-openbao-bootstrap")
	script := get(container(t, job, "bootstrap"), "args", 0).(string)
	if !strings.Contains(script, busEnv["IMAS_CERTS_OPENBAO_PKI_MOUNT"]+"/roles/"+busEnv["IMAS_CERTS_OPENBAO_ROLE"]) {
		t.Errorf("bootstrap doesn't create the PKI role %s/%s the bus issues from", busEnv["IMAS_CERTS_OPENBAO_PKI_MOUNT"], busEnv["IMAS_CERTS_OPENBAO_ROLE"])
	}
	if !strings.Contains(script, `audience="`+fmt.Sprint(projAudience)+`"`) {
		t.Errorf("roles' audience doesn't match the bus's projected token audience %v", projAudience)
	}
	m := regexp.MustCompile(`imas-farmerbus \\\n\s+allowed_domains="([^"]+)"`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("no allowed_domains for imas-farmerbus")
	}
	for _, h := range hosts {
		ok := false
		for _, d := range strings.Split(m[1], ",") {
			if d == h || strings.HasPrefix(d, "*.") && strings.HasSuffix(h.(string), d[1:]) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("PKI role imas-farmerbus can't issue the bus's SAN %v", h)
		}
	}
}
