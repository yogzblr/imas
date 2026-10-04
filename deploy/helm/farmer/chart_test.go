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
	"strconv"
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
		{"Job", "t-farmer-db-migrate"}, {"Job", "t-farmer-db-migrate-check"}, {"NetworkPolicy", "t-farmer-db-migrate"},
		{"ConfigMap", "t-farmer-openbao-policies"}, {"Secret", "t-farmer-openbao-bootstrap"},
	} {
		if !has(docs, want.kind, want.name) {
			t.Errorf("missing %s %s", want.kind, want.name)
		}
	}
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
		{"string source limit", "maxSourceBytes must be a positive whole number", []string{"--set-string", "farmer.recipes.templateLimits.maxSourceBytes=1Mi"}},
		{"zero output limit", "maxRenderedBytes must be a positive whole number", []string{"--set", "farmer.recipes.templateLimits.maxRenderedBytes=0"}},
		{"fractional value limit", "maxValueBytes must be a positive whole number", []string{"--set", "farmer.recipes.templateLimits.maxValueBytes=1.5"}},
		{"null range limit", "maxRangeIterations must be a positive whole number", []string{"--set", "farmer.recipes.templateLimits.maxRangeIterations=null"}},
		{"bare number timeout", "renderTimeout must be a quoted duration", []string{"--set", "farmer.recipes.templateLimits.renderTimeout=2"}},
		{"unitless timeout", "renderTimeout must be a quoted duration", []string{"--set-string", "farmer.recipes.templateLimits.renderTimeout=2"}},
		{"fractional burst", "burst must be a whole number", []string{"--set", "saasapi.enrollmentKeys.rateLimit.burst=2.5"}},
		// Recipe upload (REC.1): saasapi's own, separate credential.
		{"recipes without credential", "saasapi.recipes.credentialsSecret is required", []string{"--set", "saasapi.recipes.enabled=true", "--set", "objectStore.endpoint=minio:9000", "--set", "objectStore.bucket=recipes"}},
		{"recipes with farmer's credential", "must not be objectStore.credentialsSecret", []string{"--set", "saasapi.recipes.enabled=true", "--set", "objectStore.endpoint=minio:9000", "--set", "objectStore.bucket=recipes", "--set", "objectStore.credentialsSecret=s3", "--set", "saasapi.recipes.credentialsSecret=s3"}},
		{"recipes without bucket", "needs objectStore.endpoint and objectStore.bucket", []string{"--set", "saasapi.recipes.enabled=true", "--set", "saasapi.recipes.credentialsSecret=saasapi-s3"}},
		{"one recipe role", "readRole and writeRole must both be set and differ", []string{"--set", "saasapi.recipes.writeRole=imas-recipes-read"}},
		{"fractional recipe cap", "saasapi.recipes.maxCount must be a positive whole number", []string{"--set", "saasapi.recipes.maxCount=1.5"}},
		{"zero recipe burst", "saasapi.recipes.writeRateLimit.burst must be a whole number", []string{"--set", "saasapi.recipes.writeRateLimit.burst=0"}},
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
		{"one user for both schemas", "must name different schemas and different users", []string{"--set", "database.saasapi.user=farmer_svc"}},
		{"one schema for both", "must name different schemas and different users", []string{"--set", "database.saasapi.name=farmer"}},
		{"old bootstrap values", "database.bootstrap.* was replaced by database.migrate.*", []string{"--set", "database.bootstrap.enabled=false"}},
		{"bad migrate wait", "database.migrate.wait", []string{"--set", "database.migrate.wait=10"}},
		{"bad root user", "database.migrate.rootUser", []string{"--set", "database.migrate.rootUser=root@%"}},

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
// fleet signing key's sign path or the publisher's KV path. The one
// exception is the tenantbox policy's per-tenant path, whose last
// segment is the tenant ID: a single "+" (exactly one segment), never
// "*", and only there.
func TestFarmerPoliciesAreExact(t *testing.T) {
	cm := find(t, mustRender(t, "--set", "openbaoBootstrap.farmerbus.enabled=true",
		"--set", "openbaoBootstrap.farmerbus.serviceAccountName=imas-dmz-nats-bus"), "ConfigMap", "t-farmer-openbao-policies")
	want := map[string][]string{
		"imas-farmer-gateway.hcl": {`path "transit/sign/imas-gateway-jwt"`, `path "transit/keys/imas-gateway-jwt"`},
		// Only the per-tenant secrets: no read of the base path, where the
		// deleted legacy shared keypair lived (security review 2026-10, H3).
		// Plus, read only, the platform keypair and the control-plane
		// public keys (J.1), and never the SaaS API's private key.
		"imas-farmer-tenantbox.hcl": {
			`path "secret/data/imas/tenant-x25519/tenants/+"`,
			`path "secret/data/imas/tenant-x25519/platform"`,
			`path "secret/data/imas/tenant-x25519/controlplane-pub"`,
		},
		"imas-farmer-certs.hcl":    {`path "pki/issue/imas-farmer"`},
		"imas-farmerbus-certs.hcl": {`path "pki/issue/imas-farmerbus"`},
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
		stmts := policyStatements(body)
		if name == "imas-farmer-tenantbox.hcl" {
			stmts = strings.Replace(stmts, `imas/tenant-x25519/tenants/+"`, `imas/tenant-x25519/tenants/TENANT"`, 1)
		}
		if strings.ContainsAny(stmts, "*+") {
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
		// On by default since J.4.
		"imas-controlplane-box-keygen": {"imas-controlplane-box-keygen", "imas-core", "imas-controlplane-box-keygen", "5m", "5m"},
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
		"--set", "farmer.extraConfig.cohortrefreshinterval=1m")
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
	if _, ok := cfg["pubkeys"]; ok {
		t.Errorf("pubkeys = %v; the chart renders no NKey-only admins", cfg["pubkeys"])
	}
	if _, ok := cfg["users"]; ok {
		t.Errorf("users = %v without farmer.bootstrapAdmin", cfg["users"])
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

// farmer.recipes.templateLimits renders the IMAS_RECIPE_* variables
// internal/config reads into cook.SetRenderLimits, with cook's defaults.
func TestRecipeTemplateLimitsEnv(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want map[string]string
	}{
		{nil, map[string]string{
			"IMAS_RECIPE_MAX_SOURCE_BYTES":     "262144",
			"IMAS_RECIPE_MAX_RENDERED_BYTES":   "1048576",
			"IMAS_RECIPE_MAX_VALUE_BYTES":      "262144",
			"IMAS_RECIPE_RENDER_TIMEOUT":       "2s",
			"IMAS_RECIPE_MAX_RANGE_ITERATIONS": "10000",
		}},
		{[]string{
			"--set", "farmer.recipes.templateLimits.maxSourceBytes=131072",
			"--set", "farmer.recipes.templateLimits.maxRenderedBytes=4194304",
			"--set", "farmer.recipes.templateLimits.maxValueBytes=65536",
			"--set-string", "farmer.recipes.templateLimits.renderTimeout=500ms",
			"--set", "farmer.recipes.templateLimits.maxRangeIterations=2000",
		}, map[string]string{
			"IMAS_RECIPE_MAX_SOURCE_BYTES":     "131072",
			"IMAS_RECIPE_MAX_RENDERED_BYTES":   "4194304",
			"IMAS_RECIPE_MAX_VALUE_BYTES":      "65536",
			"IMAS_RECIPE_RENDER_TIMEOUT":       "500ms",
			"IMAS_RECIPE_MAX_RANGE_ITERATIONS": "2000",
		}},
	} {
		env := envValues(container(t, farmerDeploy(t, mustRender(t, tc.args...)), "farmer"))
		for name, want := range tc.want {
			if env[name] != want {
				t.Errorf("%v: %s = %q, want %q", tc.args, name, env[name], want)
			}
		}
	}
}

// Recipe upload (REC.1): saasapi validates uploads under farmer's own
// render limits, and with recipes on gets its own object-store credential
// (never farmer's), the secret key as a file only.
func TestSaasapiRecipesEnv(t *testing.T) {
	limits := []string{"IMAS_RECIPE_MAX_SOURCE_BYTES", "IMAS_RECIPE_MAX_RENDERED_BYTES", "IMAS_RECIPE_MAX_VALUE_BYTES",
		"IMAS_RECIPE_RENDER_TIMEOUT", "IMAS_RECIPE_MAX_RANGE_ITERATIONS"}

	// One set of limits for both (owner decision, 2026-10-04): saasapi's
	// upload validator gets exactly farmer's farmer.recipes.templateLimits,
	// at the defaults and with every value overridden, and there is no
	// saasapi-side override (a saasapi.recipes.templateLimits value is
	// ignored).
	overridden := []string{
		"--set", "farmer.recipes.templateLimits.maxSourceBytes=131072",
		"--set", "farmer.recipes.templateLimits.maxRenderedBytes=4194304",
		"--set", "farmer.recipes.templateLimits.maxValueBytes=65536",
		"--set-string", "farmer.recipes.templateLimits.renderTimeout=500ms",
		"--set", "farmer.recipes.templateLimits.maxRangeIterations=2000",
	}
	for _, tc := range []struct {
		args []string
		want []string // in the order of limits
	}{
		{nil, []string{"262144", "1048576", "262144", "2s", "10000"}},
		{overridden, []string{"131072", "4194304", "65536", "500ms", "2000"}},
		{append(slices.Clone(overridden), "--set", "saasapi.recipes.templateLimits.maxSourceBytes=1"),
			[]string{"131072", "4194304", "65536", "500ms", "2000"}},
	} {
		docs := mustRender(t, tc.args...)
		s := envValues(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))
		f := envValues(container(t, farmerDeploy(t, docs), "farmer"))
		for i, name := range limits {
			if s[name] != tc.want[i] || f[name] != tc.want[i] {
				t.Errorf("%v: %s: saasapi %q, farmer %q; want both %q", tc.args, name, s[name], f[name], tc.want[i])
			}
		}
	}

	// Off (the default): roles and caps, but no store.
	docs := mustRender(t)
	s := envValues(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))
	for name, want := range map[string]string{
		"SAASAPI_RECIPES_READ_ROLE": "imas-recipes-read", "SAASAPI_RECIPES_WRITE_ROLE": "imas-recipes-write",
		"SAASAPI_RECIPES_MAX_COUNT": "500", "SAASAPI_RECIPES_MAX_TOTAL_BYTES": "20971520",
		"SAASAPI_RECIPES_WRITE_RATE_LIMIT": "1", "SAASAPI_RECIPES_WRITE_RATE_BURST": "10",
	} {
		if s[name] != want {
			t.Errorf("%s = %q, want %q", name, s[name], want)
		}
	}
	if _, ok := s["SAASAPI_RECIPES_S3_ENDPOINT"]; ok {
		t.Error("recipe store configured with saasapi.recipes.enabled=false")
	}

	// On.
	docs = mustRender(t, "--set", "saasapi.recipes.enabled=true", "--set", "saasapi.recipes.credentialsSecret=saasapi-s3",
		"--set", "objectStore.endpoint=minio.storage:9000", "--set", "objectStore.bucket=imas-recipes",
		"--set", "objectStore.credentialsSecret=farmer-s3", "--set", "objectStore.useSSL=false")
	d := find(t, docs, "Deployment", "t-farmer-saasapi")
	c := container(t, d, "saasapi")
	env := envMap(c)
	for name, want := range map[string]string{
		"SAASAPI_RECIPES_S3_ENDPOINT": "minio.storage:9000", "SAASAPI_RECIPES_S3_BUCKET": "imas-recipes",
		"SAASAPI_RECIPES_S3_USE_SSL":                "false",
		"SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE": "/var/run/secrets/imas/recipes-s3/secret-access-key",
	} {
		if v, _ := env[name]["value"].(string); v != want {
			t.Errorf("%s = %v, want %s", name, env[name], want)
		}
	}
	if get(env["SAASAPI_RECIPES_S3_ACCESS_KEY_ID"], "valueFrom", "secretKeyRef", "name") != "saasapi-s3" {
		t.Errorf("access key id: %v", env["SAASAPI_RECIPES_S3_ACCESS_KEY_ID"])
	}
	if _, ok := env["SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY"]; ok {
		t.Error("the secret key is in the environment; it must only be a file")
	}
	// No farmer credential anywhere on saasapi.
	if strings.Contains(yamlString(t, d), "farmer-s3") {
		t.Error("saasapi references farmer's object-store credential")
	}
	vols := byName(podSpec(d)["volumes"])
	if get(vols["recipes-s3"], "secret", "secretName") != "saasapi-s3" {
		t.Errorf("recipes-s3 volume: %v", vols["recipes-s3"])
	}
	if items, _ := get(vols["recipes-s3"], "secret", "items").([]any); len(items) != 1 || get(items[0], "key") != "secret-access-key" {
		t.Errorf("recipes-s3 items: %v", items)
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

// The wave gate's clock-skew margin is emitted only when set, so saasapi's
// own default (30s) applies otherwise.
func TestSaasapiFleetUpdateClockSkewEnv(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"--set", "saasapi.fleetUpdateDispatch.clockSkew=45s"}, "45s"},
	} {
		env := envMap(container(t, find(t, mustRender(t, tc.args...), "Deployment", "t-farmer-saasapi"), "saasapi"))
		e, ok := env["SAASAPI_FLEET_UPDATE_CLOCK_SKEW"]
		if tc.want == "" && ok {
			t.Errorf("%v: SAASAPI_FLEET_UPDATE_CLOCK_SKEW rendered unset: %v", tc.args, e)
		}
		if tc.want != "" && (!ok || e["value"] != tc.want) {
			t.Errorf("%v: SAASAPI_FLEET_UPDATE_CLOCK_SKEW = %v, want %s", tc.args, e, tc.want)
		}
	}
}

// The outbox sweeper is on unless turned off, and its tuning is emitted
// only when set, so saasapi's own defaults apply otherwise.
func TestSaasapiOutboxSweeperEnv(t *testing.T) {
	names := []string{"SAASAPI_OUTBOX_SWEEP_INTERVAL", "SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER",
		"SAASAPI_OUTBOX_ACTION_STALE_AFTER", "SAASAPI_OUTBOX_MAX_ATTEMPTS", "SAASAPI_OUTBOX_LEASE_TTL",
		"SAASAPI_OUTBOX_ACTION_MAX_AGE"}
	for _, tc := range []struct {
		args    []string
		enabled string
		want    []string
	}{
		{nil, "true", []string{"", "", "", "", "", ""}},
		{[]string{"--set", "saasapi.outboxSweeper.enabled=false"}, "false", []string{"", "", "", "", "", ""}},
		{[]string{"--set", "saasapi.outboxSweeper.interval=10s", "--set", "saasapi.outboxSweeper.provisioningStaleAfter=5m",
			"--set", "saasapi.outboxSweeper.actionStaleAfter=90s", "--set", "saasapi.outboxSweeper.maxAttempts=3",
			"--set", "saasapi.outboxSweeper.leaseTTL=1m", "--set", "saasapi.outboxSweeper.actionMaxAge=10m"},
			"true", []string{"10s", "5m", "90s", "3", "1m", "10m"}},
	} {
		env := envMap(container(t, find(t, mustRender(t, tc.args...), "Deployment", "t-farmer-saasapi"), "saasapi"))
		if e := env["SAASAPI_OUTBOX_SWEEPER_ENABLED"]; e == nil || e["value"] != tc.enabled {
			t.Errorf("%v: SAASAPI_OUTBOX_SWEEPER_ENABLED = %v, want %s", tc.args, e, tc.enabled)
		}
		for i, name := range names {
			e, ok := env[name]
			if tc.want[i] == "" && ok {
				t.Errorf("%v: %s rendered unset: %v", tc.args, name, e)
			}
			if tc.want[i] != "" && (!ok || e["value"] != tc.want[i]) {
				t.Errorf("%v: %s = %v, want %s", tc.args, name, e, tc.want[i])
			}
		}
	}
}

// Farmer's own self_update switch (security review L1) is always
// rendered, and off by default.
func TestFarmerSelfUpdateEnv(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "false"},
		{[]string{"--set", "farmer.selfUpdate.enabled=true"}, "true"},
		{[]string{"--set", "farmer.selfUpdate.enabled=false"}, "false"},
		{[]string{"--set", "farmer.selfUpdate.enabled=null"}, "false"},
	} {
		env := envMap(container(t, farmerDeploy(t, mustRender(t, tc.args...)), "farmer"))
		if e := env["IMAS_SELF_UPDATE_ENABLED"]; e == nil || e["value"] != tc.want {
			t.Errorf("%v: IMAS_SELF_UPDATE_ENABLED = %v, want %s", tc.args, e, tc.want)
		}
	}
	// saasapi's dispatch flag doesn't turn farmer's on.
	env := envMap(container(t, farmerDeploy(t, mustRender(t, "--set", "saasapi.fleetUpdateDispatch.enabled=true")), "farmer"))
	if e := env["IMAS_SELF_UPDATE_ENABLED"]; e == nil || e["value"] != "false" {
		t.Errorf("with saasapi dispatch on: IMAS_SELF_UPDATE_ENABLED = %v, want false", e)
	}
}

// Dispatch concurrency (security review M5) in farmer and saasapi: the
// documented defaults are rendered, overrides pass through, null emits
// nothing.
func TestDispatchConcurrencyEnv(t *testing.T) {
	for _, svc := range []struct {
		name, prefix string
		deploy       func(t *testing.T, docs []obj) obj
		vars         []string
	}{
		{"farmer", "farmer.sproutActions", func(t *testing.T, docs []obj) obj { return farmerDeploy(t, docs) },
			[]string{"IMAS_SPROUT_ACTION_CONCURRENCY", "IMAS_SELF_UPDATE_CONCURRENCY", "IMAS_SPROUT_ACTION_TENANT_CONCURRENCY"}},
		{"saasapi", "saasapi.actionDispatch", func(t *testing.T, docs []obj) obj { return find(t, docs, "Deployment", "t-farmer-saasapi") },
			[]string{"SAASAPI_ACTION_DISPATCH_CONCURRENCY", "SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY", "SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY"}},
	} {
		keys := []string{"concurrency", "selfUpdateConcurrency", "tenantConcurrency"}
		for _, tc := range []struct {
			args []string
			want []string
		}{
			{nil, []string{"64", "16", "8"}},
			{[]string{"--set", svc.prefix + ".concurrency=128", "--set", svc.prefix + ".selfUpdateConcurrency=32", "--set", svc.prefix + ".tenantConcurrency=4"},
				[]string{"128", "32", "4"}},
			{[]string{"--set", svc.prefix + ".concurrency=null", "--set", svc.prefix + ".selfUpdateConcurrency=null", "--set", svc.prefix + ".tenantConcurrency=null"},
				[]string{"", "", ""}},
		} {
			env := envMap(container(t, svc.deploy(t, mustRender(t, tc.args...)), svc.name))
			for i, name := range svc.vars {
				e, ok := env[name]
				if tc.want[i] == "" && ok {
					t.Errorf("%s %v: %s (%s) rendered for null: %v", svc.name, tc.args, name, keys[i], e)
				}
				if tc.want[i] != "" && (!ok || e["value"] != tc.want[i]) {
					t.Errorf("%s %v: %s = %v, want %s", svc.name, tc.args, name, e, tc.want[i])
				}
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
		// No generated Secret and no eval OpenBao bootstrap; the schemas
		// are still migrated (TestDBMigrateJobs).
		// The control-plane keygen Job runs against the external OpenBao
		// too (on by default since J.4); its role and policy are ops'.
		jobs := map[any]bool{"t-farmer-saasapi-credential-publish": true, "t-farmer-db-migrate": true, "t-farmer-db-migrate-check": true,
			"t-farmer-controlplane-box-keys": true}
		for _, d := range docs {
			if d["kind"] == "Secret" || d["kind"] == "Job" && !jobs[get(d, "metadata", "name")] {
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

// The migrate hook Jobs (API design §4.1a): `up` on install and upgrade,
// `check` on rollback, each one pod running cmd/migrate.
func TestDBMigrateJobs(t *testing.T) {
	docs := mustRender(t, "--set", "database.migrate.backoffLimit=4", "--set", "database.migrate.activeDeadlineSeconds=1234")
	up, chk := find(t, docs, "Job", "t-farmer-db-migrate"), find(t, docs, "Job", "t-farmer-db-migrate-check")
	for _, tc := range []struct {
		job   obj
		hooks string
		args  []string
	}{
		// The bundled PXC doesn't exist at pre-install.
		{up, "post-install,pre-upgrade", []string{"up", "--wait=15m"}},
		{chk, "pre-rollback", []string{"check", "--wait=15m"}},
	} {
		name := get(tc.job, "metadata", "name")
		if got := get(tc.job, "metadata", "annotations", "helm.sh/hook"); got != tc.hooks {
			t.Errorf("%s hooks %v, want %s", name, got, tc.hooks)
		}
		if got := get(tc.job, "metadata", "annotations", "helm.sh/hook-delete-policy"); got != "before-hook-creation,hook-succeeded" {
			t.Errorf("%s hook-delete-policy %v", name, got)
		}
		if get(tc.job, "spec", "backoffLimit") != 4 || get(tc.job, "spec", "activeDeadlineSeconds") != 1234 {
			t.Errorf("%s backoffLimit/activeDeadlineSeconds not from values: %v %v", name, get(tc.job, "spec", "backoffLimit"), get(tc.job, "spec", "activeDeadlineSeconds"))
		}
		c := container(t, tc.job, "migrate")
		if c["image"] != "ghcr.io/yogzblr/imas-migrate:"+chartAppVersion(t) {
			t.Errorf("%s image %v, want the chart's appVersion", name, c["image"])
		}
		if yamlString(t, c["args"]) != yamlString(t, tc.args) {
			t.Errorf("%s args %v, want %v", name, c["args"], tc.args)
		}
		checkRestricted(t, tc.job)
		// The bus admits core pods by app.kubernetes.io/name; these must
		// not be among them.
		if l := get(tc.job, "spec", "template", "metadata", "labels", "app.kubernetes.io/name"); l != "imas-migrate" {
			t.Errorf("%s pod name label %v", name, l)
		}
		// Every credential is a file from a Secret volume: no secret env,
		// nothing in args.
		for _, e := range c["env"].([]any) {
			if get(e, "valueFrom") != nil {
				t.Errorf("%s env %v comes from a Secret; use the *_FILE form", name, get(e, "name"))
			}
		}
		db := byName(podSpec(tc.job)["volumes"])["db"]
		if get(db, "secret", "secretName") != "t-farmer-db" || get(db, "secret", "items", 0, "key") != "farmer-dsn" || get(db, "secret", "items", 1, "key") != "saasapi-dsn" {
			t.Errorf("%s DSN volume %v", name, db)
		}
	}
	if got := rootSecretOf(t, up); got != "t-pxc-secrets/root" {
		t.Errorf("up root Secret %q, want the operator's t-pxc-secrets/root", got)
	}
	if env := envValues(container(t, up, "migrate")); env["IMAS_MIGRATE_ROOT_PASSWORD_FILE"] != "/var/run/secrets/imas/pxc-root/password" || env["IMAS_MIGRATE_ROOT_USER"] != "root" ||
		env["IMAS_MIGRATE_FARMER_DSN_FILE"] != "/var/run/secrets/imas/db/farmer-dsn" || env["IMAS_MIGRATE_SAAS_DSN_FILE"] != "/var/run/secrets/imas/db/saasapi-dsn" {
		t.Errorf("up env %v", env)
	}
	// Rollback only reads: no root password.
	if got := rootSecretOf(t, chk); got != "" {
		t.Errorf("check mounts the root Secret %s", got)
	}
	if _, ok := envMap(container(t, chk, "migrate"))["IMAS_MIGRATE_ROOT_PASSWORD_FILE"]; ok {
		t.Error("check is given a root password")
	}
	if get(up, "metadata", "annotations", "argocd.argoproj.io/hook") != "Sync" {
		t.Errorf("Argo CD hook with the bundled PXC %v, want Sync", get(up, "metadata", "annotations", "argocd.argoproj.io/hook"))
	}
	if get(chk, "metadata", "annotations", "argocd.argoproj.io/hook") != nil {
		t.Error("the check Job must not become an Argo CD sync hook")
	}

	t.Run("operator secret name", func(t *testing.T) {
		if got := rootSecretOf(t, find(t, mustRender(t, "--set", "pxc.pxc.clusterSecretName=pxc-root"), "Job", "t-farmer-db-migrate")); got != "pxc-root/root" {
			t.Errorf("root Secret %q", got)
		}
	})
	t.Run("bundled PXC, own DSN secret", func(t *testing.T) {
		// cmd/migrate takes both accounts from the DSNs, so the root step
		// works with any DSN source.
		up := find(t, mustRender(t, "--set", "database.existingSecret=mine"), "Job", "t-farmer-db-migrate")
		if rootSecretOf(t, up) != "t-pxc-secrets/root" || get(byName(podSpec(up)["volumes"])["db"], "secret", "secretName") != "mine" {
			t.Errorf("root %q, DSNs %v", rootSecretOf(t, up), byName(podSpec(up)["volumes"])["db"])
		}
	})
	t.Run("external PXC", func(t *testing.T) {
		docs := mustRender(t, "-f", ciValues(t, "external-values.yaml"))
		up := find(t, docs, "Job", "t-farmer-db-migrate")
		if got := get(up, "metadata", "annotations", "helm.sh/hook"); got != "pre-install,pre-upgrade" {
			t.Errorf("hooks %v", got)
		}
		if get(up, "metadata", "annotations", "argocd.argoproj.io/hook") != "PreSync" {
			t.Errorf("Argo CD hook %v", get(up, "metadata", "annotations", "argocd.argoproj.io/hook"))
		}
		// No root Secret known: ops own the accounts and grants.
		if got := container(t, up, "migrate")["args"]; yamlString(t, got) != yamlString(t, []string{"up", "--wait=15m", "--skip-root"}) {
			t.Errorf("args %v", got)
		}
		if got := rootSecretOf(t, up); got != "" {
			t.Errorf("root Secret %q mounted with --skip-root", got)
		}
		if get(byName(podSpec(up)["volumes"])["db"], "secret", "secretName") != "imas-core-db" {
			t.Error("DSNs not from database.existingSecret")
		}
		np := find(t, docs, "NetworkPolicy", "t-farmer-db-migrate")
		if get(np, "metadata", "annotations", "helm.sh/hook") != "pre-install,pre-upgrade,pre-rollback" ||
			get(np, "spec", "egress", 0, "to", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "pxc" {
			t.Errorf("external NetworkPolicy %v", np)
		}

		up = find(t, mustRender(t, "-f", ciValues(t, "external-values.yaml"),
			"--set", "database.migrate.rootPasswordSecret=pxc-admin", "--set", "database.migrate.rootPasswordKey=pw",
			"--set", "database.migrate.rootUser=imas_admin"), "Job", "t-farmer-db-migrate")
		if got := rootSecretOf(t, up); got != "pxc-admin/pw" {
			t.Errorf("root Secret %q", got)
		}
		if strings.Contains(yamlString(t, container(t, up, "migrate")["args"]), "skip-root") || envValues(container(t, up, "migrate"))["IMAS_MIGRATE_ROOT_USER"] != "imas_admin" {
			t.Error("root step skipped, or wrong user, with a root Secret given")
		}
	})
	t.Run("digest and tag", func(t *testing.T) {
		img := func(args ...string) any {
			return container(t, find(t, mustRender(t, args...), "Job", "t-farmer-db-migrate"), "migrate")["image"]
		}
		if got := img("--set", "database.migrate.image.tag=1.2.3"); got != "ghcr.io/yogzblr/imas-migrate:1.2.3" {
			t.Errorf("image %v", got)
		}
		if got := img("--set", "database.migrate.image.digest=sha256:abc"); got != "ghcr.io/yogzblr/imas-migrate@sha256:abc" {
			t.Errorf("image %v", got)
		}
	})
	t.Run("long release name", func(t *testing.T) {
		docs, err := renderAs(t, strings.Repeat("r", 53), "imas-core", strippedChart(t), required...)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, d := range docs {
			if get(d, "metadata", "labels", "app.kubernetes.io/component") == "db-migrate" && d["kind"] == "Job" {
				names = append(names, get(d, "metadata", "name").(string))
			}
		}
		if len(names) != 2 || names[0] == names[1] {
			t.Errorf("migrate Job names %v: want two distinct", names)
		}
	})
}

// PXC's root password reaches the `up` pod and no other: farmer and
// saasapi run without it.
func TestRootSecretOnlyInMigrateJob(t *testing.T) {
	for _, args := range [][]string{nil, {"-f", ciValues(t, "external-values.yaml"), "--set", "database.migrate.rootPasswordSecret=pxc-admin"}} {
		docs := mustRender(t, args...)
		root, _, _ := strings.Cut(rootSecretOf(t, find(t, docs, "Job", "t-farmer-db-migrate")), "/")
		if root == "" {
			t.Fatalf("%v: no root Secret", args)
		}
		for _, d := range docs {
			if d["kind"] == "Job" && get(d, "metadata", "name") == "t-farmer-db-migrate" {
				continue
			}
			if strings.Contains(yamlString(t, d), root) {
				t.Errorf("%v: %v %v references the root Secret %s", args, d["kind"], get(d, "metadata", "name"), root)
			}
		}
	}
}

// The migrate pods reach PXC and DNS only, take no ingress, and their
// policy exists before they do: a hook at a lower weight, whatever
// networkPolicy.enabled says.
func TestDBMigrateNetworkPolicy(t *testing.T) {
	for _, args := range [][]string{nil, {"--set", "networkPolicy.enabled=false"}} {
		docs := mustRender(t, args...)
		np := find(t, docs, "NetworkPolicy", "t-farmer-db-migrate")
		if got := egressPorts(np); !slices.Equal(got, []int{3306, 53, 53}) {
			t.Errorf("%v: egress ports %v", args, got)
		}
		if l, ok := get(np, "spec", "ingress").([]any); !ok || len(l) != 0 {
			t.Errorf("%v: ingress %v", args, get(np, "spec", "ingress"))
		}
		if pt := get(np, "spec", "policyTypes"); yamlString(t, pt) != yamlString(t, []string{"Ingress", "Egress"}) {
			t.Errorf("%v: policyTypes %v", args, pt)
		}
		if got := get(np, "metadata", "annotations", "helm.sh/hook"); got != "post-install,pre-upgrade,pre-rollback" {
			t.Errorf("%v: hooks %v", args, got)
		}
		if get(np, "metadata", "annotations", "helm.sh/hook-weight") != "-10" ||
			get(find(t, docs, "Job", "t-farmer-db-migrate"), "metadata", "annotations", "helm.sh/hook-weight") != "-5" {
			t.Errorf("%v: the policy must be created before the Job", args)
		}
		sel := get(np, "spec", "podSelector", "matchLabels").(obj)
		for _, job := range []string{"t-farmer-db-migrate", "t-farmer-db-migrate-check"} {
			labels := get(find(t, docs, "Job", job), "spec", "template", "metadata", "labels").(obj)
			for k, v := range sel {
				if labels[k] != v {
					t.Errorf("%v: policy selector %v doesn't select %s's pods (%v)", args, sel, job, labels)
				}
			}
		}
	}
}

func chartAppVersion(t *testing.T) string {
	t.Helper()
	var c struct {
		AppVersion string `yaml:"appVersion"`
	}
	b, err := os.ReadFile(filepath.Join(chartDir(t), "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &c); err != nil || c.AppVersion == "" {
		t.Fatalf("Chart.yaml appVersion: %v", err)
	}
	return c.AppVersion
}

// rootSecretOf returns "secret/key" of a migrate Job's pxc-root volume, or
// "" if it has none.
func rootSecretOf(t *testing.T, job obj) string {
	t.Helper()
	v := byName(podSpec(job)["volumes"])["pxc-root"]
	if v == nil {
		return ""
	}
	if n := len(get(v, "secret", "items").([]any)); n != 1 || get(v, "secret", "items", 0, "path") != "password" {
		t.Errorf("pxc-root volume must project exactly the one key: %v", v)
	}
	return fmt.Sprintf("%v/%v", get(v, "secret", "secretName"), get(v, "secret", "items", 0, "key"))
}

// checkRestricted asserts the Pod Security "restricted" settings the
// chart's Jobs share, plus no ServiceAccount token.
func checkRestricted(t *testing.T, job obj) {
	t.Helper()
	ps := podSpec(job)
	name := get(job, "metadata", "name")
	if ps["automountServiceAccountToken"] != false || ps["restartPolicy"] != "Never" {
		t.Errorf("%s automountServiceAccountToken %v, restartPolicy %v", name, ps["automountServiceAccountToken"], ps["restartPolicy"])
	}
	if get(ps, "securityContext", "runAsNonRoot") != true || get(ps, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
		t.Errorf("%s pod securityContext %v", name, ps["securityContext"])
	}
	for _, c := range ps["containers"].([]any) {
		sc := get(c, "securityContext")
		if get(sc, "readOnlyRootFilesystem") != true || get(sc, "allowPrivilegeEscalation") != false ||
			yamlString(t, get(sc, "capabilities", "drop")) != yamlString(t, []string{"ALL"}) {
			t.Errorf("%s container securityContext %v", name, sc)
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
		t.Errorf("PXC secretsName %v: the migrate Job reads the root password from t-pxc-secrets", get(pxc, "spec", "secretsName"))
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

// ---------------------------------------------------------------------------
// Sprout release registration (FU.5, API design §2.5)
// ---------------------------------------------------------------------------

// operatorArgs turns on saasapi's operator plane with every value it
// requires.
var operatorArgs = []string{
	"--set", "saasapi.operator.enabled=true",
	"--set", "saasapi.operator.tls.secretName=saasapi-operator-tls",
	"--set", "saasapi.operator.token.secretName=saasapi-operator-token",
	"--set", "saasapi.operator.fleetReleaser.url=https://fleetreleaser.imas-signer.svc:9443",
	"--set", "saasapi.operator.fleetReleaser.tokenSecretName=saasapi-fleetreleaser-token",
}

// registerArgs turns the hook on: with a stamped release, the operator
// plane is all it needs.
var registerArgs = operatorArgs

// testRelease is what packaging/helm/stamp-sprout-release.sh writes, for
// the chart's own appVersion.
func testRelease(t *testing.T) string {
	t.Helper()
	v := chartAppVersion(t)
	return fmt.Sprintf(`{
  "version": "v%[1]s",
  "min_sprout_version": "v0.1.0",
  "packages": [
    {"os": "linux", "arch": "amd64", "package_type": "deb", "file_name": "imas-sprout_%[1]s_linux_amd64.deb", "checksum_sha256": "%[2]s"},
    {"os": "linux", "arch": "amd64", "package_type": "rpm", "file_name": "imas-sprout_%[1]s_linux_amd64.rpm", "checksum_sha256": "%[3]s"},
    {"os": "windows", "arch": "amd64", "package_type": "msi", "file_name": "imas-sprout-%[1]s-windows-x64.msi", "checksum_sha256": "%[4]s"}
  ]
}
`, v, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
}

// releaseChart is strippedChart with files/sprout-release.json set to
// release ("" removes it, whatever a local stamp run left behind), and
// NOTES.txt also rendered as ConfigMap notes-under-test: `helm template`
// doesn't render NOTES, so it goes through tpl.
func releaseChart(t *testing.T, release string) string {
	t.Helper()
	dir := strippedChart(t)
	f := filepath.Join(dir, "files", "sprout-release.json")
	if release == "" {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(f, []byte(release), 0o644); err != nil {
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
	return dir
}

func renderRelease(t *testing.T, release string, args ...string) ([]obj, error) {
	t.Helper()
	helmBin(t)
	return runHelm(t, releaseChart(t, release), append(slices.Clone(required), args...)...)
}

func mustRenderRelease(t *testing.T, release string, args ...string) []obj {
	t.Helper()
	docs, err := renderRelease(t, release, args...)
	if err != nil {
		t.Fatalf("helm template failed: %v", err)
	}
	return docs
}

func notes(t *testing.T, docs []obj) string {
	t.Helper()
	return get(find(t, docs, "ConfigMap", "notes-under-test"), "data", "notes").(string)
}

const registerJob = "t-farmer-sprout-release-register"

func registrarResources(docs []obj) []string {
	var got []string
	for _, d := range docs {
		if get(d, "metadata", "labels", "app.kubernetes.io/component") == "sprout-release-registrar" {
			got = append(got, fmt.Sprintf("%v/%v", d["kind"], get(d, "metadata", "name")))
		}
	}
	return got
}

// No files/sprout-release.json (a dev install from source): nothing of
// the hook renders, even with the operator plane on, and NOTES says so.
// With the file but without the operator plane, nothing renders either,
// and NOTES says the release is not registered and why.
func TestSproutReleaseSkippedWithoutFile(t *testing.T) {
	for _, args := range [][]string{nil, registerArgs} {
		docs := mustRenderRelease(t, "", args...)
		if got := registrarResources(docs); len(got) != 0 {
			t.Errorf("%v: rendered %v without files/sprout-release.json", args, got)
		}
		if n := notes(t, docs); !strings.Contains(n, "Sprout release registration: skipped. This chart has no files/sprout-release.json") {
			t.Errorf("%v: NOTES don't say the hook was skipped:\n%s", args, n)
		}
	}
	for _, tc := range []struct {
		why  string
		args []string
	}{
		{"saasapi.operator.enabled=false", nil},
		{"sproutRelease.register=false", append(slices.Clone(registerArgs), "--set", "sproutRelease.register=false")},
		{"saasapi.enabled=false", append(slices.Clone(registerArgs), "--set", "saasapi.enabled=false")},
	} {
		docs := mustRenderRelease(t, testRelease(t), tc.args...)
		if got := registrarResources(docs); len(got) != 0 {
			t.Errorf("%s: rendered %v", tc.why, got)
		}
		if n := notes(t, docs); !strings.Contains(n, "NOT registered") || !strings.Contains(n, tc.why) {
			t.Errorf("%s: NOTES don't say why:\n%s", tc.why, n)
		}
	}
	// The published chart's default: the file, the operator plane off.
	if _, err := renderRelease(t, testRelease(t)); err != nil {
		t.Errorf("a stamped chart with the defaults must render: %v", err)
	}
}

// Hook annotations and weights, the request body, and the pod's
// restrictions.
func TestSproutReleaseRegisterJob(t *testing.T) {
	docs := mustRenderRelease(t, testRelease(t), registerArgs...)
	if got := registrarResources(docs); !slices.Equal(got, []string{
		"NetworkPolicy/imas-sprout-release-registrar", "ServiceAccount/imas-sprout-release-registrar",
		"ConfigMap/t-farmer-sprout-release", "Job/" + registerJob,
	}) {
		t.Errorf("registrar resources %v", got)
	}
	job := find(t, docs, "Job", registerJob)
	ann := get(job, "metadata", "annotations").(obj)
	if ann["helm.sh/hook"] != "post-install,post-upgrade" {
		t.Errorf("hook %v: want post-install,post-upgrade (and never rollback: it doesn't unregister)", ann["helm.sh/hook"])
	}
	if ann["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded" {
		t.Errorf("hook-delete-policy %v: a failed run must be kept for its logs", ann["helm.sh/hook-delete-policy"])
	}
	if ann["argocd.argoproj.io/hook"] != "PostSync" || ann["argocd.argoproj.io/hook-delete-policy"] != "BeforeHookCreation" {
		t.Errorf("Argo CD annotations %v", ann)
	}
	// After every other post-install/post-upgrade hook: saasapi needs the
	// publish Job's JWT before it can serve.
	weight := func(d obj) int {
		w, err := strconv.Atoi(fmt.Sprint(get(d, "metadata", "annotations", "helm.sh/hook-weight")))
		if err != nil {
			t.Fatalf("%v hook-weight: %v", get(d, "metadata", "name"), err)
		}
		return w
	}
	for _, d := range docs {
		hooks, _ := get(d, "metadata", "annotations", "helm.sh/hook").(string)
		if d["kind"] == "Job" && get(d, "metadata", "name") != registerJob && strings.Contains(hooks, "post-") && weight(d) >= weight(job) {
			t.Errorf("hook %v (weight %d) runs no earlier than the registration (weight %d)", get(d, "metadata", "name"), weight(d), weight(job))
		}
	}
	if weight(job) <= weight(find(t, docs, "Job", "t-farmer-saasapi-credential-publish")) {
		t.Error("registration must run after the publish Job")
	}
	if a, b := get(job, "metadata", "annotations", "argocd.argoproj.io/sync-wave"), get(find(t, docs, "Job", "t-farmer-saasapi-credential-publish"), "metadata", "annotations", "argocd.argoproj.io/sync-wave"); a != "1" || b != nil {
		t.Errorf("Argo CD sync-waves: registration %v, publisher %v", a, b)
	}
	// A 409 (exit 2) fails the Job, and so the release, without a retry.
	if pfp := get(job, "spec", "podFailurePolicy", "rules", 0); get(pfp, "action") != "FailJob" ||
		get(pfp, "onExitCodes", "containerName") != "register" || get(pfp, "onExitCodes", "operator") != "In" ||
		yamlString(t, get(pfp, "onExitCodes", "values")) != yamlString(t, []int{2}) {
		t.Errorf("podFailurePolicy %v", get(job, "spec", "podFailurePolicy"))
	}
	checkRestricted(t, job)
	ps := podSpec(job)
	if ps["serviceAccountName"] != "imas-sprout-release-registrar" || ps["enableServiceLinks"] != false {
		t.Errorf("pod serviceAccountName %v, enableServiceLinks %v", ps["serviceAccountName"], ps["enableServiceLinks"])
	}
	if l := podLabels(job); l["app.kubernetes.io/name"] != "imas-sprout-release-registrar" {
		t.Errorf("pod name label %v: must not be the chart's, which the bus admits", l["app.kubernetes.io/name"])
	}
	c := container(t, job, "register")
	if c["image"] != "ghcr.io/yogzblr/imas-farmer:"+chartAppVersion(t) || c["command"] != nil ||
		yamlString(t, c["args"]) != yamlString(t, []string{"register-sprout-release"}) {
		t.Errorf("image %v, command %v, args %v: want farmer's image running register-sprout-release", c["image"], c["command"], c["args"])
	}
	env := envValues(c)
	for k, v := range map[string]string{
		"IMAS_SPROUT_RELEASE_SAASAPI_URL":     "https://t-farmer-saasapi-operator.imas-core.svc.cluster.local:8443",
		"IMAS_SPROUT_RELEASE_REQUEST_FILE":    "/etc/imas/sprout-release/request.json",
		"IMAS_SPROUT_RELEASE_ATTEMPTS":        "8",
		"IMAS_SPROUT_RELEASE_INITIAL_BACKOFF": "5s",
		"IMAS_SPROUT_RELEASE_MAX_BACKOFF":     "60s",
		"IMAS_SPROUT_RELEASE_REQUEST_TIMEOUT": "600s",
	} {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	if len(env) != 8 {
		t.Errorf("env %v: want exactly the IMAS_SPROUT_RELEASE_* settings", env)
	}
	if get(byName(c["volumeMounts"])["release"], "mountPath") != "/etc/imas/sprout-release" {
		t.Errorf("release mount %v", c["volumeMounts"])
	}

	// The body: the stamped release verbatim, plus channel and
	// min_sprout_version, and nothing else.
	cm := find(t, docs, "ConfigMap", "t-farmer-sprout-release")
	var body, stamped map[string]any
	if err := yaml.Unmarshal([]byte(get(cm, "data", "request.json").(string)), &body); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(testRelease(t)), &stamped); err != nil {
		t.Fatal(err)
	}
	stamped["channel"] = "stable"
	if yamlString(t, body) != yamlString(t, stamped) {
		t.Errorf("request body:\n%s\nwant:\n%s", yamlString(t, body), yamlString(t, stamped))
	}
	if len(get(cm, "data").(obj)) != 1 {
		t.Errorf("ConfigMap data %v: want request.json only", get(cm, "data"))
	}
	if !strings.Contains(notes(t, docs), "registers sprout release v"+chartAppVersion(t)+" (min_sprout_version v0.1.0, 3 package(s))") {
		t.Errorf("NOTES:\n%s", notes(t, docs))
	}

	// The operator Service fronts saasapi's operator port, not its API port.
	svc := find(t, docs, "Service", "t-farmer-saasapi-operator")
	if get(svc, "spec", "ports", 0, "port") != 8443 || get(svc, "spec", "ports", 0, "targetPort") != "operator" ||
		!matches(obj{"matchLabels": get(svc, "spec", "selector")}, podLabels(find(t, docs, "Deployment", "t-farmer-saasapi"))) {
		t.Errorf("operator Service %v", get(svc, "spec"))
	}
	ports := byName(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi")["ports"])
	if get(ports["operator"], "containerPort") != 8443 || get(ports["http"], "containerPort") != 8081 {
		t.Errorf("saasapi ports %v", ports)
	}
	if strings.Contains(yamlString(t, find(t, docs, "Service", "t-farmer-saasapi")), "8443") {
		t.Error("the gateway's saasapi Service exposes the operator port")
	}

	t.Run("values", func(t *testing.T) {
		job := find(t, mustRenderRelease(t, testRelease(t), append(slices.Clone(registerArgs),
			"--set", "sproutRelease.retry.attempts=3", "--set", "sproutRelease.retry.initialDelaySeconds=2",
			"--set", "sproutRelease.retry.maxDelaySeconds=9", "--set", "sproutRelease.requestTimeoutSeconds=77",
			"--set", "sproutRelease.backoffLimit=0", "--set", "sproutRelease.activeDeadlineSeconds=99",
			"--set", "sproutRelease.argoCDHooks=false", "--set", "farmer.image.tag=9.9.9",
			"--set", "farmer.imagePullSecrets[0].name=regcred",
			"--set", "saasapi.operator.port=9443")...), "Job", registerJob)
		env := envValues(container(t, job, "register"))
		for k, v := range map[string]string{"IMAS_SPROUT_RELEASE_ATTEMPTS": "3", "IMAS_SPROUT_RELEASE_INITIAL_BACKOFF": "2s", "IMAS_SPROUT_RELEASE_MAX_BACKOFF": "9s", "IMAS_SPROUT_RELEASE_REQUEST_TIMEOUT": "77s"} {
			if env[k] != v {
				t.Errorf("%s = %q, want %s", k, env[k], v)
			}
		}
		if !strings.HasSuffix(env["IMAS_SPROUT_RELEASE_SAASAPI_URL"], ":9443") {
			t.Errorf("IMAS_SPROUT_RELEASE_SAASAPI_URL %q", env["IMAS_SPROUT_RELEASE_SAASAPI_URL"])
		}
		if get(podSpec(job), "imagePullSecrets", 0, "name") != "regcred" {
			t.Errorf("imagePullSecrets %v: want farmer's", get(podSpec(job), "imagePullSecrets"))
		}
		if get(job, "spec", "backoffLimit") != 0 || get(job, "spec", "activeDeadlineSeconds") != 99 ||
			get(job, "metadata", "annotations", "argocd.argoproj.io/hook") != nil {
			t.Errorf("spec %v, annotations %v", get(job, "spec"), get(job, "metadata", "annotations"))
		}
		if img := container(t, job, "register")["image"]; img != "ghcr.io/yogzblr/imas-farmer:9.9.9" {
			t.Errorf("image %v: want farmer's", img)
		}
	})
}

// The operator token reaches exactly two pods: the hook Job, which mounts
// the current key and nothing else of any Secret but the operator CA, and
// saasapi, which checks it.
func TestSproutReleaseSecretWiring(t *testing.T) {
	docs := mustRenderRelease(t, testRelease(t), registerArgs...)
	job := find(t, docs, "Job", registerJob)
	ps := podSpec(job)
	vols := byName(ps["volumes"])
	var secrets []string
	for name, v := range vols {
		if s := get(v, "secret"); s != nil {
			secrets = append(secrets, fmt.Sprintf("%s=%v:%s", name, get(s, "secretName"), yamlString(t, get(s, "items"))))
		}
		if get(v, "projected") != nil {
			t.Errorf("projected volume %s: the Job holds no ServiceAccount token", name)
		}
	}
	slices.Sort(secrets)
	want := []string{
		"operator-token=saasapi-operator-token:" + yamlString(t, []obj{{"key": "current", "path": "token"}}),
		"saasapi-operator-ca=saasapi-operator-tls:" + yamlString(t, []obj{{"key": "ca.crt", "path": "ca.crt"}}),
	}
	if !slices.Equal(secrets, want) {
		t.Errorf("Secret volumes:\n%v\nwant:\n%v", secrets, want)
	}
	if get(vols["operator-token"], "secret", "defaultMode") != 0o440 {
		t.Errorf("token defaultMode %v", get(vols["operator-token"], "secret", "defaultMode"))
	}
	if get(ps, "securityContext", "fsGroup") != 65532 {
		t.Error("without fsGroup the non-root pod can't read the 0440 token file")
	}
	c := container(t, job, "register")
	for _, e := range c["env"].([]any) {
		if get(e, "valueFrom") != nil {
			t.Errorf("env %v comes from a Secret: the token is a file only", get(e, "name"))
		}
	}
	mounts := byName(c["volumeMounts"])
	env := envValues(c)
	if !strings.HasPrefix(env["IMAS_SPROUT_RELEASE_TOKEN_FILE"], get(mounts["operator-token"], "mountPath").(string)+"/") ||
		!strings.HasPrefix(env["IMAS_SPROUT_RELEASE_CA_FILE"], get(mounts["saasapi-operator-ca"], "mountPath").(string)+"/") {
		t.Errorf("token %q / CA %q outside their mounts %v", env["IMAS_SPROUT_RELEASE_TOKEN_FILE"], env["IMAS_SPROUT_RELEASE_CA_FILE"], mounts)
	}
	// Nothing of farmer's own: no config, PKI, seeds or data volume.
	if len(vols) != 3 || len(mounts) != 3 {
		t.Errorf("volumes %v / mounts %v: want release, operator-token and saasapi-operator-ca only", vols, mounts)
	}
	sa := find(t, docs, "ServiceAccount", "imas-sprout-release-registrar")
	if sa["automountServiceAccountToken"] != false {
		t.Error("registrar ServiceAccount automounts its token")
	}
	for _, d := range docs {
		if strings.HasSuffix(fmt.Sprint(d["kind"]), "RoleBinding") && strings.Contains(yamlString(t, d), "imas-sprout-release-registrar") {
			t.Errorf("%s grants the registrar RBAC", d["kind"])
		}
	}
	if strings.Contains(yamlString(t, find(t, docs, "Job", "t-farmer-openbao-bootstrap")), "imas-sprout-release-registrar") {
		t.Error("the registrar's ServiceAccount is bound to an OpenBao role")
	}

	// saasapi: the listener's key pair (not ca.crt), the token, and the
	// fleetreleaser client.
	sd := find(t, docs, "Deployment", "t-farmer-saasapi")
	sc := container(t, sd, "saasapi")
	senv := envValues(sc)
	for k, v := range map[string]string{
		"SAASAPI_OPERATOR_LISTEN_ADDR":     ":8443",
		"SAASAPI_OPERATOR_TLS_CERT_FILE":   "/var/run/secrets/imas/operator-tls/tls.crt",
		"SAASAPI_OPERATOR_TLS_KEY_FILE":    "/var/run/secrets/imas/operator-tls/tls.key",
		"SAASAPI_OPERATOR_TOKEN_FILE":      "/var/run/secrets/imas/operator-token/current",
		"SAASAPI_FLEETRELEASER_URL":        "https://fleetreleaser.imas-signer.svc:9443",
		"SAASAPI_FLEETRELEASER_TOKEN_FILE": "/var/run/secrets/imas/fleetreleaser/token",
		"IMAS_FLEETSIGN_OPENBAO_K8S_ROLE":  "imas-saasapi-fleet-verify",
	} {
		if senv[k] != v {
			t.Errorf("saasapi %s = %q, want %q", k, senv[k], v)
		}
	}
	for _, k := range []string{"SAASAPI_OPERATOR_TOKEN_PREVIOUS_FILE", "SAASAPI_FLEETRELEASER_CA_FILE"} {
		if _, ok := senv[k]; ok {
			t.Errorf("%s set without its value", k)
		}
	}
	svols := byName(podSpec(sd)["volumes"])
	if got := yamlString(t, get(svols["operator-tls"], "secret", "items")); got != yamlString(t, []obj{{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}}) {
		t.Errorf("saasapi operator-tls items %s", got)
	}
	if got := yamlString(t, get(svols["operator-token"], "secret", "items")); got != yamlString(t, []obj{{"key": "current", "path": "current"}}) {
		t.Errorf("saasapi operator-token items %s", got)
	}
	// Only the hook Job and saasapi name the operator token Secret.
	for _, d := range docs {
		n := get(d, "metadata", "name")
		if (d["kind"] == "Job" && n == registerJob) || (d["kind"] == "Deployment" && n == "t-farmer-saasapi") {
			continue
		}
		if strings.Contains(yamlString(t, d), "saasapi-operator-token") {
			t.Errorf("%v %v references the operator token Secret", d["kind"], n)
		}
	}
	// The verify-only role follows the operator plane.
	if roles := bootstrapRoles(t, docs); roles["imas-saasapi-fleet-verify"] == nil {
		t.Error("no imas-saasapi-fleet-verify role for the operator plane's key client")
	}

	t.Run("rotation and fleetreleaser CA", func(t *testing.T) {
		sd := find(t, mustRenderRelease(t, testRelease(t), append(slices.Clone(registerArgs),
			"--set", "saasapi.operator.token.previousKey=previous",
			"--set", "saasapi.operator.fleetReleaser.caConfigMap=fleetreleaser-ca")...), "Deployment", "t-farmer-saasapi")
		senv := envValues(container(t, sd, "saasapi"))
		if senv["SAASAPI_OPERATOR_TOKEN_PREVIOUS_FILE"] != "/var/run/secrets/imas/operator-token/previous" ||
			senv["SAASAPI_FLEETRELEASER_CA_FILE"] != "/var/run/secrets/imas/fleetreleaser-ca/ca.crt" {
			t.Errorf("env %v", senv)
		}
		vols := byName(podSpec(sd)["volumes"])
		if got := yamlString(t, get(vols["operator-token"], "secret", "items")); got != yamlString(t, []obj{{"key": "current", "path": "current"}, {"key": "previous", "path": "previous"}}) {
			t.Errorf("operator-token items %s", got)
		}
		if get(vols["fleetreleaser-ca"], "configMap", "name") != "fleetreleaser-ca" {
			t.Errorf("fleetreleaser-ca volume %v", vols["fleetreleaser-ca"])
		}
	})
}

// The hook pod reaches saasapi's operator port and DNS, nothing else,
// whatever networkPolicy.enabled says; saasapi's operator port admits the
// hook pod (and the configured extra peers) only.
func TestSproutReleaseNetworkPolicy(t *testing.T) {
	ns := "imas-core"
	registrar := obj{"app.kubernetes.io/name": "imas-sprout-release-registrar", "app.kubernetes.io/instance": "t", "app.kubernetes.io/component": "sprout-release-registrar"}
	saasapi := obj{"app.kubernetes.io/name": "farmer", "app.kubernetes.io/instance": "t", "app.kubernetes.io/component": "saasapi"}
	farmer := obj{"app.kubernetes.io/name": "farmer", "app.kubernetes.io/instance": "t", "app.kubernetes.io/component": "farmer"}
	for _, args := range [][]string{nil, {"--set", "networkPolicy.enabled=false"}} {
		docs := mustRenderRelease(t, testRelease(t), append(slices.Clone(registerArgs), args...)...)
		np := find(t, docs, "NetworkPolicy", "imas-sprout-release-registrar")
		if !matches(get(np, "spec", "podSelector"), podLabels(find(t, docs, "Job", registerJob))) {
			t.Errorf("%v: policy doesn't select the Job's pods", args)
		}
		if l, ok := get(np, "spec", "ingress").([]any); !ok || len(l) != 0 {
			t.Errorf("%v: ingress %v", args, get(np, "spec", "ingress"))
		}
		if pt := get(np, "spec", "policyTypes"); yamlString(t, pt) != yamlString(t, []string{"Ingress", "Egress"}) {
			t.Errorf("%v: policyTypes %v", args, pt)
		}
		if got := egressPorts(np); !slices.Equal(got, []int{8443, 53, 53}) {
			t.Errorf("%v: egress ports %v", args, got)
		}
		if !allows(np, "egress", ns, saasapi, 8443) {
			t.Errorf("%v: no egress to saasapi's operator port", args)
		}
		for _, c := range []struct {
			what string
			ns   string
			pod  obj
			port int
		}{
			{"farmer", ns, farmer, 8443},
			{"saasapi's API port", ns, saasapi, 8081},
			{"saasapi in another namespace", "elsewhere", saasapi, 8443},
			{"OpenBao", "openbao", obj{"app.kubernetes.io/name": "openbao"}, 8200},
			{"the bus", "imas-dmz", obj{"app.kubernetes.io/name": "nats", "app.kubernetes.io/component": "bus"}, 5406},
			{"fleetreleaser", "imas-signer", obj{"app.kubernetes.io/name": "fleetreleaser"}, 9443},
		} {
			if allows(np, "egress", c.ns, c.pod, c.port) {
				t.Errorf("%v: egress allowed to %s", args, c.what)
			}
		}
	}

	docs := mustRenderRelease(t, testRelease(t), append(slices.Clone(registerArgs),
		"--set", "networkPolicy.saasapiOperatorIngress.from[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=ops")...)
	snp := find(t, docs, "NetworkPolicy", "t-farmer-saasapi")
	if !allows(snp, "ingress", ns, registrar, 8443) || !allows(snp, "ingress", "ops", obj{"any": "pod"}, 8443) {
		t.Error("saasapi's operator port doesn't admit the hook Job or the configured peer")
	}
	for _, c := range []struct {
		what string
		ns   string
		pod  obj
	}{{"farmer", ns, farmer}, {"another namespace", "imas-dmz", registrar}, {"saasapi itself", ns, saasapi}} {
		if allows(snp, "ingress", c.ns, c.pod, 8443) {
			t.Errorf("saasapi's operator port admits %s", c.what)
		}
	}
	if !allows(snp, "ingress", "anywhere", obj{"any": "pod"}, 8081) {
		t.Error("saasapi's API port lost its default ingress")
	}
	// saasapi -> fleetreleaser, on the URL's port.
	if got := egressPorts(snp); !slices.Contains(got, 9443) {
		t.Errorf("saasapi egress ports %v: no fleetreleaser", got)
	}
	if allows(snp, "egress", "anywhere", obj{"any": "pod"}, 8443) {
		t.Error("saasapi egress opened on the operator port")
	}
}

func TestSproutReleaseValidation(t *testing.T) {
	v := chartAppVersion(t)
	rel := testRelease(t)
	cases := []struct {
		name, want, release string
		args                []string
	}{
		{"no min_sprout_version", "min_sprout_version \"\" is missing or not a canonical", strings.Replace(rel, `"min_sprout_version": "v0.1.0",`, "", 1), registerArgs},
		{"min_sprout_version not canonical", "is missing or not a canonical", strings.Replace(rel, `"min_sprout_version": "v0.1.0"`, `"min_sprout_version": "0.1.0"`, 1), registerArgs},
		{"min_sprout_version above version", "is above the release's version", strings.Replace(rel, `"min_sprout_version": "v0.1.0"`, `"min_sprout_version": "v99.0.0"`, 1), registerArgs},
		{"removed minSproutVersion value", "sproutRelease.minSproutVersion was removed", "", []string{"--set", "sproutRelease.minSproutVersion=v0.1.0"}},
		{"removed image value", "sproutRelease.image was removed", rel, append(slices.Clone(registerArgs), "--set", "sproutRelease.image.repository=curlimages/curl")},
		{"bad channel", "sproutRelease.channel", rel, append(slices.Clone(registerArgs), "--set", "sproutRelease.channel=Stable")},
		{"version without v", "re-stamp it", strings.Replace(rel, `"version": "v`+v, `"version": "`+v, 1), registerArgs},
		{"version not the chart's", "ship under one tag", strings.Replace(rel, `"version": "v`+v, `"version": "v`+v+"-rc.1", 1), registerArgs},
		{"unknown field", `unexpected field "channel"`, strings.Replace(rel, `"packages"`, `"channel": "x", "packages"`, 1), registerArgs},
		{"no packages", "has no packages", fmt.Sprintf(`{"version": "v%s", "min_sprout_version": "v0.1.0", "packages": []}`, v), registerArgs},
		{"not JSON", "is not a JSON object", "version: v" + v, registerArgs},
		{"SA is the publisher's", "another workload's ServiceAccount", rel, append(slices.Clone(registerArgs), "--set", "sproutRelease.serviceAccountName=imas-saasapi-cred-publisher")},
		{"SA is saasapi's", "another workload's ServiceAccount", rel, append(slices.Clone(registerArgs), "--set", "sproutRelease.serviceAccountName=t-farmer-saasapi")},
		{"zero attempts", "sproutRelease.retry.attempts", rel, append(slices.Clone(registerArgs), "--set", "sproutRelease.retry.attempts=0")},
		// The operator plane's own settings, file or no file.
		{"no operator TLS", "saasapi.operator.tls.secretName is required", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.tls.secretName=")},
		{"no operator token", "saasapi.operator.token.secretName is required", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.token.secretName=")},
		{"token Secret is the BFF's", "must be a Secret of its own", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.token.secretName=imas-saasapi-internal-auth")},
		{"token Secret is fleetreleaser's", "must be a Secret of its own", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.token.secretName=saasapi-fleetreleaser-token")},
		{"previousKey equals currentKey", "previousKey must differ", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.token.previousKey=current")},
		{"http fleetreleaser", "must be https://host[:port]", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.fleetReleaser.url=http://fleetreleaser:8443")},
		{"fleetreleaser path", "must be https://host[:port]", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.fleetReleaser.url=https://fleetreleaser:8443/v1/sign")},
		{"no fleetreleaser token", "fleetReleaser.tokenSecretName is required", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.fleetReleaser.tokenSecretName=")},
		{"operator port is the API port", "must differ from saasapi.port", "", append(slices.Clone(operatorArgs), "--set", "saasapi.operator.port=8081")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renderRelease(t, tc.release, tc.args...)
			if err == nil {
				t.Fatalf("expected the render to fail with %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("render failed, but not with %q:\n%v", tc.want, err)
			}
		})
	}
}

// packaging/helm/stamp-sprout-release.sh's output is what the chart
// registers: both versions keep their "v", min_sprout_version comes from
// packaging/helm/min-sprout-version and is at most the version by semver
// precedence, and the result renders as is.
func TestStampedReleaseRenders(t *testing.T) {
	helmBin(t)
	for _, tool := range []string{"bash", "jq", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	stampScript := filepath.Join(chartDir(t), "..", "..", "..", "packaging", "helm", "stamp-sprout-release.sh")
	// dist writes a release's packages and checksums.txt for version (no "v").
	dist := func(t *testing.T, version string) string {
		dir := t.TempDir()
		var sums strings.Builder
		for _, name := range []string{
			"imas-sprout_" + version + "_linux_amd64.deb", "imas-sprout_" + version + "_linux_amd64.rpm",
			"imas-sprout_" + version + "_linux_arm64.rpm", "imas-sprout-" + version + "-windows-x64.msi",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("sha256sum", filepath.Join(dir, name)).Output()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&sums, "%s  %s\n", strings.Fields(string(out))[0], name)
		}
		if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(sums.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// stamp runs the script; minFile "" means the repo's own.
	stamp := func(t *testing.T, tag, minFile string) (string, error) {
		out := filepath.Join(t.TempDir(), "sprout-release.json")
		args := []string{stampScript, dist(t, strings.TrimPrefix(tag, "v")), tag, out}
		if minFile != "" {
			args = append(args, minFile)
		}
		if b, err := exec.Command("bash", args...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("%v: %s", err, b)
		}
		b, err := os.ReadFile(out)
		return string(b), err
	}
	minFile := func(t *testing.T, content string) string {
		p := filepath.Join(t.TempDir(), "min-sprout-version")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// The repo's floor, end to end.
	var repoMin string
	for _, l := range strings.Split(string(repoFile(t, "packaging/helm/min-sprout-version")), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			repoMin = l
		}
	}
	v := chartAppVersion(t)
	stamped, err := stamp(t, "v"+v, "")
	if err != nil {
		t.Fatalf("stamp with the repo's packaging/helm/min-sprout-version: %v", err)
	}
	var file struct {
		Version          string `yaml:"version"`
		MinSproutVersion string `yaml:"min_sprout_version"`
	}
	if err := yaml.Unmarshal([]byte(stamped), &file); err != nil || file.Version != "v"+v || file.MinSproutVersion != repoMin {
		t.Errorf("stamped %+v (%v), want version v%s and min_sprout_version %q", file, err, v, repoMin)
	}
	docs := mustRenderRelease(t, stamped, registerArgs...)
	var body struct {
		Version          string           `yaml:"version"`
		MinSproutVersion string           `yaml:"min_sprout_version"`
		Packages         []map[string]any `yaml:"packages"`
	}
	if err := yaml.Unmarshal([]byte(get(find(t, docs, "ConfigMap", "t-farmer-sprout-release"), "data", "request.json").(string)), &body); err != nil {
		t.Fatal(err)
	}
	if body.Version != "v"+v || body.MinSproutVersion != repoMin || len(body.Packages) != 4 {
		t.Errorf("request version %q, min_sprout_version %q, %d packages", body.Version, body.MinSproutVersion, len(body.Packages))
	}
	for _, p := range body.Packages {
		if p["os"] == "windows" && (p["arch"] != "amd64" || p["package_type"] != "msi") {
			t.Errorf("windows package %v", p)
		}
	}

	for _, bad := range []string{"v" + v + "+build.1", "v0" + v, v} {
		if _, err := stamp(t, bad, ""); err == nil {
			t.Errorf("stamp accepted the non-canonical tag %q", bad)
		}
	}
	// Semver precedence, prereleases included: a floor above the tag is
	// refused, anything at or below it is stamped verbatim.
	for _, tc := range []struct {
		tag, min string
		ok       bool
	}{
		{"v1.0.0-rc.1", "v1.0.0", false},
		{"v1.0.0-rc.1", "v1.0.0-rc.2", false},
		{"v1.0.0-rc.1", "v1.0.0-rc.1", true},
		{"v1.0.0-rc.1", "v1.0.0-beta.11", true},
		{"v1.0.0-beta.11", "v1.0.0-beta.2", true},
		{"v1.0.0-beta.2", "v1.0.0-beta.11", false},
		{"v1.0.0-alpha.1", "v1.0.0-alpha.beta", false},
		{"v1.0.0-alpha", "v1.0.0-alpha.1", false},
		{"v1.0.0", "v1.0.0-rc.1", true},
		{"v0.10.0", "v0.9.9", true},
		{"v0.9.9", "v0.10.0", false},
		{"v2.0.0", "v1.99.0", true},
	} {
		out, err := stamp(t, tc.tag, minFile(t, "# floor\n\n"+tc.min+"\n"))
		if tc.ok != (err == nil) {
			t.Errorf("tag %s, floor %s: ok=%v, want %v (%v)", tc.tag, tc.min, err == nil, tc.ok, err)
			continue
		}
		if tc.ok && !strings.Contains(out, `"min_sprout_version": "`+tc.min+`"`) {
			t.Errorf("tag %s, floor %s: stamped\n%s", tc.tag, tc.min, out)
		}
		if !tc.ok && !strings.Contains(err.Error(), "is above the release's version") {
			t.Errorf("tag %s, floor %s: %v", tc.tag, tc.min, err)
		}
	}
	for _, tc := range []struct{ content, want string }{
		{"1.0.0\n", "not canonical semver"},
		{"v1.0\n", "not canonical semver"},
		{"v01.0.0\n", "not canonical semver"},
		{"v0.1.0\nv0.2.0\n", "exactly one version line"},
		{"# nothing\n", "exactly one version line"},
	} {
		if _, err := stamp(t, "v"+v, minFile(t, tc.content)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("floor file %q: %v, want %q", tc.content, err, tc.want)
		}
	}
	if _, err := stamp(t, "v"+v, filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "no ") {
		t.Errorf("missing floor file: %v", err)
	}
}

// policyBlocks maps each path in an HCL policy to its capabilities line.
func policyBlocks(hcl string) map[string]string {
	out := map[string]string{}
	var path string
	for _, l := range strings.Split(policyStatements(hcl), "\n") {
		switch {
		case strings.HasPrefix(l, "path "):
			path = strings.TrimSuffix(strings.TrimPrefix(l, "path "), " {")
		case strings.HasPrefix(l, "capabilities"):
			out[path] = l
		}
	}
	return out
}

// The control-plane keygen Job (J.1) is on by default since J.4, which
// gives its keys their consumers; turned off, it renders no Job, no
// ServiceAccount, no policy and no role.
func TestControlPlaneBoxKeysOnByDefault(t *testing.T) {
	docs := mustRender(t)
	if !has(docs, "Job", "t-farmer-controlplane-box-keys") || !has(docs, "ServiceAccount", "imas-controlplane-box-keygen") {
		t.Error("keygen Job not rendered by default")
	}
	off := mustRender(t, "--set", "controlPlaneBoxKeys.enabled=false")
	if has(off, "Job", "t-farmer-controlplane-box-keys") || has(off, "ServiceAccount", "imas-controlplane-box-keygen") {
		t.Error("keygen Job rendered while controlPlaneBoxKeys.enabled is false")
	}
	offCM := find(t, off, "ConfigMap", "t-farmer-openbao-policies")
	if _, ok := get(offCM, "data").(obj)["imas-controlplane-box-keygen.hcl"]; ok {
		t.Error("keygen policy rendered while disabled")
	}
	if _, ok := bootstrapRoles(t, off)["imas-controlplane-box-keygen"]; ok {
		t.Error("keygen role created while disabled")
	}
	cm := find(t, docs, "ConfigMap", "t-farmer-openbao-policies")
	// farmer reads, never writes, the platform key and the public keys,
	// and never the SaaS API's private key.
	blocks := policyBlocks(get(cm, "data", "imas-farmer-tenantbox.hcl").(string))
	for _, p := range []string{`"secret/data/imas/tenant-x25519/platform"`, `"secret/data/imas/tenant-x25519/controlplane-pub"`} {
		if blocks[p] != `capabilities = ["read"]` {
			t.Errorf("farmer's %s: %q, want read only", p, blocks[p])
		}
	}
	for p := range blocks {
		if strings.Contains(p, "saasapi-box") {
			t.Errorf("farmer's policy reaches the SaaS API's private key: %s", p)
		}
	}
}

func TestControlPlaneBoxKeysJob(t *testing.T) {
	docs := mustRender(t, "--set", "controlPlaneBoxKeys.enabled=true")
	job := find(t, docs, "Job", "t-farmer-controlplane-box-keys")
	ann := get(job, "metadata", "annotations").(obj)
	if ann["helm.sh/hook"] != "post-install,post-upgrade" || ann["helm.sh/hook-weight"] != "5" {
		t.Errorf("hook annotations %v: want post-install/post-upgrade, after the bootstrap (0), before the publisher (10)", ann)
	}
	ps := podSpec(job)
	if ps["serviceAccountName"] != "imas-controlplane-box-keygen" || ps["automountServiceAccountToken"] != false {
		t.Errorf("pod identity: %v %v", ps["serviceAccountName"], ps["automountServiceAccountToken"])
	}
	c := container(t, job, "keygen")
	if args := get(c, "args").([]any); len(args) != 1 || args[0] != "ensure-controlplane-box-keys" {
		t.Errorf("args %v", args)
	}
	env := envValues(c)
	if env["IMAS_CPBOX_OPENBAO_K8S_ROLE"] != "imas-controlplane-box-keygen" ||
		env["IMAS_CPBOX_OPENBAO_KV_MOUNT"] != "secret" || env["IMAS_CPBOX_OPENBAO_KV_PATH"] != "imas/tenant-x25519" {
		t.Errorf("env %v", env)
	}
	for name := range env {
		if strings.HasPrefix(name, "IMAS_NATS_") || strings.HasPrefix(name, "IMAS_TENANTBOX_") || strings.HasPrefix(name, "IMAS_SAASAPI_CRED_") {
			t.Errorf("the keygen Job has %s", name)
		}
	}
	for _, v := range ps["volumes"].([]any) {
		if get(v, "secret") != nil || get(v, "persistentVolumeClaim") != nil {
			t.Errorf("the keygen Job mounts %v", v)
		}
	}
	np := find(t, docs, "NetworkPolicy", "imas-controlplane-box-keygen")
	if ing := get(np, "spec", "ingress").([]any); len(ing) != 0 {
		t.Errorf("ingress %v", ing)
	}

	// Its policy: create and read the keypairs, never update them.
	cm := find(t, docs, "ConfigMap", "t-farmer-openbao-policies")
	blocks := policyBlocks(get(cm, "data", "imas-controlplane-box-keygen.hcl").(string))
	want := map[string]string{
		`"secret/data/imas/tenant-x25519/platform"`:         `capabilities = ["create", "read"]`,
		`"secret/data/imas/tenant-x25519/saasapi-box"`:      `capabilities = ["create", "read"]`,
		`"secret/data/imas/tenant-x25519/controlplane-pub"`: `capabilities = ["create", "read", "update"]`,
	}
	if len(blocks) != len(want) {
		t.Errorf("keygen policy paths %v", blocks)
	}
	for p, w := range want {
		if blocks[p] != w {
			t.Errorf("keygen policy %s: %q, want %q", p, blocks[p], w)
		}
	}
	roles := bootstrapRoles(t, docs)
	if !slices.Equal(roles["imas-controlplane-box-keygen"], []string{"imas-controlplane-box-keygen", "imas-core", "imas-controlplane-box-keygen", "5m", "5m"}) {
		t.Errorf("keygen role %v", roles["imas-controlplane-box-keygen"])
	}
	// farmer's ServiceAccount is bound to none of the keygen's identity.
	for name, r := range roles {
		if name != "imas-controlplane-box-keygen" && r[2] == "imas-controlplane-box-keygen" {
			t.Errorf("role %s binds the keygen policy", name)
		}
	}
}

func TestControlPlaneBoxKeysRefusesSharedIdentity(t *testing.T) {
	mustFail(t, "another workload's ServiceAccount", "--set", "controlPlaneBoxKeys.enabled=true",
		"--set", "controlPlaneBoxKeys.serviceAccountName=t-farmer")
	mustFail(t, "another workload's ServiceAccount", "--set", "controlPlaneBoxKeys.enabled=true",
		"--set", "controlPlaneBoxKeys.serviceAccountName=imas-saasapi-cred-publisher")
	mustFail(t, "another workload's OpenBao role", "--set", "controlPlaneBoxKeys.enabled=true",
		"--set", "controlPlaneBoxKeys.k8sRole=imas-farmer-tenantbox")
}

// The first admin is bootstrapped from a Helm value, never over the bus
// (J.3): farmer.bootstrapAdmin renders users.admin with the admin's NKey
// public key and CLI box key, which farmer imports at start
// (internal/auth's bootstrapkeys.go). An NKey-only admin can't make a
// sealed request, so farmer.adminPubKeys refuses to render.
func TestBootstrapAdmin(t *testing.T) {
	const (
		pubkey = "AB3CQ7X5ZV2JMR4FZYPG2ZLNZ6QX6S7HCLRT5JH4PO5ILHMYXM2AXUNG"
		boxpub = "2O0Y4D6rpqfWAeY+pn2AFOP0AkFqm2t8dNVO3uYFQUQ="
	)
	cfg := farmerConfig(t, mustRender(t, "--set", "farmer.bootstrapAdmin.pubkey="+pubkey,
		"--set", "farmer.bootstrapAdmin.boxpub="+boxpub, "--set", "farmer.bootstrapAdmin.username=root"))
	if get(cfg, "users", "admin", 0, "pubkey") != pubkey || get(cfg, "users", "admin", 0, "boxpub") != boxpub ||
		get(cfg, "users", "admin", 0, "username") != "root" {
		t.Errorf("users = %v", cfg["users"])
	}
	if _, ok := cfg["pubkeys"]; ok {
		t.Errorf("pubkeys = %v", cfg["pubkeys"])
	}
	// username is optional.
	cfg = farmerConfig(t, mustRender(t, "--set", "farmer.bootstrapAdmin.pubkey="+pubkey, "--set", "farmer.bootstrapAdmin.boxpub="+boxpub))
	if _, ok := get(cfg, "users", "admin", 0).(obj)["username"]; ok {
		t.Errorf("users = %v", cfg["users"])
	}

	mustFail(t, "boxpub is required", "--set", "farmer.bootstrapAdmin.pubkey="+pubkey)
	mustFail(t, "boxpub is required", "--set", "farmer.bootstrapAdmin.pubkey="+pubkey, "--set", "farmer.bootstrapAdmin.boxpub=not-a-key")
	mustFail(t, "not an NKey user public key", "--set", "farmer.bootstrapAdmin.boxpub="+boxpub)
	mustFail(t, "not an NKey user public key", "--set", "farmer.bootstrapAdmin.pubkey=UADMIN", "--set", "farmer.bootstrapAdmin.boxpub="+boxpub)
	mustFail(t, "farmer.adminPubKeys was removed", "--set", "farmer.adminPubKeys[0]="+pubkey)
}
