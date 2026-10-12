// Package natschart tests the deploy/helm/nats Helm chart by rendering it
// with the helm CLI and asserting on the manifests. The tests skip when
// helm is not on PATH, so `go test ./...` stays green on machines without
// it; run them locally with helm v3 installed. With IMAS_REQUIRE_HELM=1 (set
// by .github/workflows/ci.yml) a missing helm fails the tests instead.
package natschart

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/yogzblr/imas/internal/envoycheck"
)

type obj = map[string]any

func chartDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate chart directory")
	}
	return filepath.Dir(file)
}

// requiredArgs are the values the chart has no default for (the accounts
// bucket's endpoint and its egress); render passes them before the
// caller's own, so a test can still override or clear them.
var requiredArgs = []string{
	"--set", "accountStore.endpoint=s3.imas-core.example.internal:9000",
	"--set", "networkPolicy.accountStoreEgress.cidr=10.20.0.10/32",
	"--set", "networkPolicy.accountStoreEgress.port=9000",
}

// render runs `helm template` and returns the parsed documents, or the
// combined output as an error when rendering fails.
func render(t *testing.T, args ...string) ([]obj, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("IMAS_REQUIRE_HELM") == "1" {
			t.Fatal("helm not on PATH (IMAS_REQUIRE_HELM=1: chart tests must run, not skip)")
		}
		t.Skip("helm not on PATH; skipping chart rendering tests")
	}
	cmd := exec.Command(helm, append([]string{"template", "t", chartDir(t),
		"--namespace", "imas-dmz", "--kube-version", "1.30.0"}, append(slices.Clone(requiredArgs), args...)...)...)
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
	return docs, nil
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

// find returns the single document of kind whose name ends with suffix.
func find(t *testing.T, docs []obj, kind, suffix string) obj {
	t.Helper()
	var hits []obj
	for _, d := range docs {
		if d["kind"] == kind && strings.HasSuffix(get(d, "metadata", "name").(string), suffix) {
			hits = append(hits, d)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one %s named *%s, got %d", kind, suffix, len(hits))
	}
	return hits[0]
}

func has(docs []obj, kind, suffix string) bool {
	for _, d := range docs {
		if d["kind"] == kind && strings.HasSuffix(get(d, "metadata", "name").(string), suffix) {
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

func container(t *testing.T, workload obj) obj {
	t.Helper()
	c, ok := get(workload, "spec", "template", "spec", "containers", 0).(obj)
	if !ok {
		t.Fatal("workload has no containers")
	}
	return c
}

func envMap(c obj) map[string]string {
	m := map[string]string{}
	for _, e := range c["env"].([]any) {
		e := e.(obj)
		v, _ := e["value"].(string)
		m[e["name"].(string)] = v
	}
	return m
}

func envoyConfig(t *testing.T, docs []obj) obj {
	t.Helper()
	cm := find(t, docs, "ConfigMap", "-envoy")
	var cfg obj
	if err := yaml.Unmarshal([]byte(get(cm, "data", "envoy.yaml").(string)), &cfg); err != nil {
		t.Fatalf("envoy.yaml is not valid YAML: %v", err)
	}
	return cfg
}

func httpConnManager(cfg obj) obj {
	return get(cfg, "static_resources", "listeners", 0, "filter_chains", 0, "filters", 0, "typed_config").(obj)
}

func jwtAuthn(cfg obj) obj {
	for _, f := range httpConnManager(cfg)["http_filters"].([]any) {
		if f.(obj)["name"] == "envoy.filters.http.jwt_authn" {
			return f.(obj)["typed_config"].(obj)
		}
	}
	return nil
}

func TestDefaultsRender(t *testing.T) {
	docs := mustRender(t)
	for _, want := range []struct{ kind, suffix string }{
		{"StatefulSet", "-bus"}, {"Service", "-bus"}, {"Service", "-bus-headless"},
		{"ConfigMap", "-bus"}, {"ServiceAccount", "-bus"},
		{"Deployment", "-envoy"}, {"Service", "-envoy"}, {"ConfigMap", "-envoy"},
		{"NetworkPolicy", "-bus"}, {"NetworkPolicy", "-envoy"},
	} {
		if !has(docs, want.kind, want.suffix) {
			t.Errorf("missing %s *%s", want.kind, want.suffix)
		}
	}
	// A single bus node gets no PDB (it would block every drain).
	if has(docs, "PodDisruptionBudget", "-bus") {
		t.Error("bus PDB rendered for replicaCount=1")
	}
}

// The chart must never create key material: no Secret of any kind, and
// seeds only ever reach the process as _SEED_FILE paths. Since P21 slice
// 1 the bus holds no trust chain seed: a single node mounts none, a
// cluster only the fence user's (BUS_FENCE_USER).
func TestSeedsAreReferencesOnly(t *testing.T) {
	docs := mustRender(t)
	for _, d := range docs {
		if d["kind"] == "Secret" {
			t.Fatalf("chart rendered a Secret (%v); seeds must come from natsSeeds.secretName only", get(d, "metadata", "name"))
		}
	}
	sts := find(t, docs, "StatefulSet", "-bus")
	for k := range envMap(container(t, sts)) {
		if strings.HasSuffix(k, "_SEED") || strings.HasSuffix(k, "_SEED_FILE") {
			t.Errorf("single-node bus has seed env var %s; it needs none", k)
		}
	}
	for _, v := range get(sts, "spec", "template", "spec", "volumes").([]any) {
		if v.(obj)["name"] == "nats-seeds" {
			t.Errorf("single-node bus mounts a seed volume: %v", v)
		}
	}

	sts = find(t, mustRender(t, clusteredArgs...), "StatefulSet", "-bus")
	env := envMap(container(t, sts))
	if got := env["IMAS_NATS_BUS_FENCE_USER_SEED_FILE"]; got != "/var/run/secrets/imas/nats/bus-fence-user.nk" {
		t.Errorf("IMAS_NATS_BUS_FENCE_USER_SEED_FILE = %q", got)
	}
	for k := range env {
		if strings.HasSuffix(k, "_SEED") {
			t.Errorf("raw seed env var %s rendered; only _SEED_FILE is allowed", k)
		}
		if strings.HasSuffix(k, "_SEED_FILE") && k != "IMAS_NATS_BUS_FENCE_USER_SEED_FILE" {
			t.Errorf("bus has seed env var %s; only the fence user's", k)
		}
	}
	var seedVol obj
	for _, v := range get(sts, "spec", "template", "spec", "volumes").([]any) {
		if v.(obj)["name"] == "nats-seeds" {
			seedVol = v.(obj)
		}
	}
	if seedVol == nil || get(seedVol, "secret", "secretName") != "imas-farmer-nats-seeds" {
		t.Fatalf("nats-seeds volume not sourced from imas-farmer-nats-seeds: %v", seedVol)
	}
	// Only the listed key is projected (not e.g. farmer's sys-user.nk).
	if items := get(seedVol, "secret", "items").([]any); len(items) != 1 || get(items[0], "key") != "bus-fence-user.nk" {
		t.Errorf("seed volume projects %v, want bus-fence-user.nk only", items)
	}
}

// The bus reads the public trust ConfigMap (P21 slice 1): mounted
// read-only at IMAS_NATS_TRUST_DIR, from natsTrust.configMapName.
func TestNatsTrustMounts(t *testing.T) {
	for _, args := range [][]string{nil, {"--set", "natsTrust.configMapName=dmz-trust"}} {
		want := "imas-nats-trust"
		if args != nil {
			want = "dmz-trust"
		}
		sts := find(t, mustRender(t, args...), "StatefulSet", "-bus")
		c := container(t, sts)
		if got := envMap(c)["IMAS_NATS_TRUST_DIR"]; got != "/var/run/imas/nats-trust" {
			t.Errorf("IMAS_NATS_TRUST_DIR = %q", got)
		}
		mounted := false
		for _, m := range c["volumeMounts"].([]any) {
			if m.(obj)["name"] == "nats-trust" {
				mounted = m.(obj)["mountPath"] == "/var/run/imas/nats-trust" && m.(obj)["readOnly"] == true
			}
		}
		if !mounted {
			t.Error("trust ConfigMap not mounted read-only at /var/run/imas/nats-trust")
		}
		found := false
		for _, v := range get(sts, "spec", "template", "spec", "volumes").([]any) {
			if v.(obj)["name"] == "nats-trust" {
				found = get(v, "configMap", "name") == want && get(v, "configMap", "optional") == nil
			}
		}
		if !found {
			t.Errorf("nats-trust volume is not the required ConfigMap %s", want)
		}
	}
}

func TestExtraSeeds(t *testing.T) {
	docs := mustRender(t, "--set", "natsSeeds.extraSeeds.EXTRA_USER=extra-user.nk")
	env := envMap(container(t, find(t, docs, "StatefulSet", "-bus")))
	if env["IMAS_NATS_EXTRA_USER_SEED_FILE"] != "/var/run/secrets/imas/nats/extra-user.nk" {
		t.Errorf("extra seed not wired: %v", env)
	}
}

func TestValidationFailures(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		{"no seed secret", "natsSeeds.secretName is required", []string{"--set", "natsSeeds.secretName=", "--set", "natsSeeds.seeds.BUS_FENCE_USER=f.nk"}},
		{"cluster without fence user", "natsSeeds.seeds.BUS_FENCE_USER is required", []string{"--set", "bus.replicaCount=3", "--set", "bus.cluster.auth.secretName=r"}},
		{"bad trust configmap", "natsTrust.configMapName", []string{"--set", "natsTrust.configMapName=Bad_Name"}},
		{"bad seed name", "must match", []string{"--set", "natsSeeds.extraSeeds.bad-name=x.nk"}},
		{"removed operator seed", "natsSeeds seed OPERATOR was removed in P21 slice 1", []string{"--set", "natsSeeds.seeds.OPERATOR=operator.nk"}},
		{"removed operator signing seed", "natsSeeds seed OPERATOR_SIGNING was removed", []string{"--set", "natsSeeds.seeds.OPERATOR_SIGNING=operator-signing.nk"}},
		{"removed sys account seed", "natsSeeds seed SYS_ACCOUNT was removed", []string{"--set", "natsSeeds.seeds.SYS_ACCOUNT=sys-account.nk"}},
		{"removed tenant seed", "natsSeeds seed TENANT was removed", []string{"--set", "natsSeeds.seeds.TENANT=tenant.nk"}},
		{"removed tenant signing seed in extraSeeds", "natsSeeds seed TENANT_SIGNING was removed", []string{"--set", "natsSeeds.extraSeeds.TENANT_SIGNING=tenant-signing.nk"}},
		{"bad tenant id", "not a valid tenant ID", []string{"--set", "bus.organization=imas farmer"}},
		{"cluster without route credentials", "bus.cluster.auth.secretName is required", []string{"--set", "bus.replicaCount=3"}},
		{"two-node cluster", "bus.replicaCount=2 is refused", []string{"--set", "bus.replicaCount=2", "--set", "bus.cluster.auth.secretName=r"}},
		{"cluster on an image without routes", "routesSupported=false", []string{"--set", "bus.replicaCount=3", "--set", "bus.cluster.auth.secretName=r", "--set", "bus.cluster.routesSupported=false"}},
		{"bad route password key", "passwordKey", []string{"--set", "bus.replicaCount=3", "--set", "bus.cluster.auth.secretName=r", "--set", "bus.cluster.auth.passwordKey=a/b"}},
		{"zero max connections", "bus.maxConnections must be a whole number >= 1", []string{"--set", "bus.maxConnections=0"}},
		{"negative max connections", "bus.maxConnections must be a whole number >= 1", []string{"--set", "bus.maxConnections=-1"}},
		{"fractional max connections", "bus.maxConnections must be a whole number >= 1", []string{"--set", "bus.maxConnections=1.5"}},
		{"non-numeric max connections", "bus.maxConnections must be a whole number >= 1", []string{"--set", "bus.maxConnections=lots"}},
		{"unset max connections", "bus.maxConnections must be a whole number >= 1", []string{"--set", "bus.maxConnections=null"}},
		{"bad tls mode", "bus.tls.mode must be", []string{"--set", "bus.tls.mode=selfsigned"}},
		{"openbao token without secret", "tokenSecretName is required", []string{"--set", "bus.tls.mode=openbao", "--set", "bus.tls.openbao.authMethod=token"}},
		{"envoy without tls", "envoy.tls.secretName is required", []string{"--set", "envoy.tls.secretName="}},
		{"bad jwks source", "jwks.source must be", []string{"--set", "envoy.jwtAuthn.jwks.source=inline"}},
		{"local jwks empty", "needs jwks.local.inline or", []string{"--set", "envoy.jwtAuthn.jwks.source=local"}},
		{"local jwks not json", "must be a JSON JWKS", []string{"--set", "envoy.jwtAuthn.jwks.source=local", "--set", "envoy.jwtAuthn.jwks.local.inline=nope"}},
		{"jwks cluster without host", "upstreams.jwks.host is required", []string{"--set", "envoy.jwtAuthn.jwks.remote.cluster=jwks"}},
		{"refresh fleet size zero", "refreshRateLimit.fleetSize must be set and >= 1", []string{"--set", "envoy.refreshRateLimit.fleetSize=0"}},
		{"refresh fractional headroom", "refreshRateLimit.headroom must be a whole number", []string{"--set", "envoy.refreshRateLimit.headroom=1.5"}},
		{"refresh burst below interval", "burstSeconds must be >= fillIntervalSeconds", []string{"--set", "envoy.refreshRateLimit.fillIntervalSeconds=10", "--set", "envoy.refreshRateLimit.burstSeconds=5"}},
		{"refresh max below per-fill", "maxTokens must be >= tokensPerFill", []string{"--set", "envoy.refreshRateLimit.tokensPerFill=50", "--set", "envoy.refreshRateLimit.maxTokens=10"}},
		{"loader health port on a bus port", "loader.healthPort 8080 is already a bus port", []string{"--set", "loader.healthPort=8080"}},
		{"bad reconcile interval", "accountStore.reconcileInterval", []string{"--set", "accountStore.reconcileInterval=often"}},
		{"bad event subject", "accountStore.eventSubject", []string{"--set", "accountStore.eventSubject=imas.>"}},
		{"same reader secret keys", "must be different keys", []string{"--set", "accountStore.secretAccessKeyKey=access-key-id"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { mustFail(t, tc.want, tc.args...) })
	}
}

// busConfig returns the /etc/imas/farmer the bus ConfigMap renders.
func busConfig(t *testing.T, docs []obj) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(get(find(t, docs, "ConfigMap", "-bus"), "data", "farmer").(string)), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// bus.maxConnections becomes busmaxconnections (config.BusMaxConnections,
// nats-server's max_connections), as an integer, and is chart-managed.
func TestBusMaxConnections(t *testing.T) {
	if got := busConfig(t, mustRender(t))["busmaxconnections"]; got != 65536 {
		t.Errorf("default busmaxconnections = %#v, want 65536", got)
	}
	if got := busConfig(t, mustRender(t, "--set", "bus.maxConnections=250000"))["busmaxconnections"]; got != 250000 {
		t.Errorf("busmaxconnections = %#v, want 250000", got)
	}
	if got := busConfig(t, mustRender(t, "--set", "bus.extraConfig.busmaxconnections=-1"))["busmaxconnections"]; got != 65536 {
		t.Errorf("extraConfig overrode the chart-managed busmaxconnections: %#v", got)
	}
}

func TestBusConfigFile(t *testing.T) {
	docs := mustRender(t, "--set", "bus.extraConfig.farmerbusport=9999", "--set", "bus.extraConfig.certificatevalidtime=1h")
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(get(find(t, docs, "ConfigMap", "-bus"), "data", "farmer").(string)), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["farmerbusport"] != "5406" {
		t.Errorf("extraConfig overrode a chart-managed key: farmerbusport=%v", cfg["farmerbusport"])
	}
	if cfg["certificatevalidtime"] != "1h" {
		t.Errorf("extraConfig key not merged: %v", cfg)
	}
	if cfg["farmerorganization"] != "imas" || cfg["farmerpki"] != "/var/lib/imas/farmerbus/pki/" {
		t.Errorf("unexpected managed config: %v", cfg)
	}
	c := container(t, find(t, docs, "StatefulSet", "-bus"))
	for _, m := range c["volumeMounts"].([]any) {
		m := m.(obj)
		if m["mountPath"] == "/etc/imas/farmer" && m["readOnly"] != true {
			t.Error("/etc/imas/farmer must be mounted read-only (jety.WriteConfig would dump env vars into it)")
		}
	}
}

var clusteredArgs = []string{"--set", "bus.replicaCount=3", "--set", "bus.cluster.auth.secretName=farmerbus-route-auth",
	"--set", "natsSeeds.seeds.BUS_FENCE_USER=bus-fence-user.nk"}

func TestClustered(t *testing.T) {
	docs := mustRender(t, clusteredArgs...)
	sts := find(t, docs, "StatefulSet", "-bus")
	if get(sts, "spec", "replicas") != 3 || get(sts, "spec", "serviceName") != "t-nats-bus-headless" {
		t.Errorf("statefulset replicas/serviceName: %v / %v", get(sts, "spec", "replicas"), get(sts, "spec", "serviceName"))
	}
	c := container(t, sts)
	env := envMap(c)
	routes := strings.Split(env["IMAS_BUS_CLUSTER_ROUTES"], ",")
	if len(routes) != 3 || routes[2] != "tls://t-nats-bus-2.t-nats-bus-headless.imas-dmz.svc.cluster.local:6222" {
		t.Errorf("IMAS_BUS_CLUSTER_ROUTES = %v", routes)
	}
	for k, want := range map[string]string{
		"IMAS_BUS_CLUSTER_NAME":                "imas-bus",
		"IMAS_BUS_CLUSTER_PORT":                "6222",
		"IMAS_BUS_CLUSTER_ROUTE_USER":          "imas-bus-route",
		"IMAS_BUS_CLUSTER_ROUTE_PASSWORD_FILE": "/var/run/secrets/imas/bus-route/route-password",
		"IMAS_BUS_CLUSTER_ADVERTISE":           "$(POD_NAME).t-nats-bus-headless.imas-dmz.svc.cluster.local:6222",
		"IMAS_BUS_SERVER_NAME":                 "$(POD_NAME)",
		"IMAS_BUS_HEALTH_PORT":                 "8080",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}
	// $(POD_NAME) only expands if POD_NAME is defined earlier in the list.
	var order []string
	for _, e := range c["env"].([]any) {
		order = append(order, e.(obj)["name"].(string))
	}
	if i := slices.Index(order, "POD_NAME"); i < 0 || i > slices.Index(order, "IMAS_BUS_CLUSTER_ADVERTISE") || i > slices.Index(order, "IMAS_BUS_SERVER_NAME") {
		t.Errorf("POD_NAME must precede its references: %v", order)
	}
	for k := range env {
		if strings.Contains(k, "PASSWORD") && !strings.HasSuffix(k, "_FILE") {
			t.Errorf("route password passed as env var %s; only a _FILE path is allowed", k)
		}
	}
	var auth obj
	for _, v := range get(sts, "spec", "template", "spec", "volumes").([]any) {
		if v.(obj)["name"] == "route-auth" {
			auth = v.(obj)
		}
	}
	if get(auth, "secret", "secretName") != "farmerbus-route-auth" || len(get(auth, "secret", "items").([]any)) != 1 ||
		get(auth, "secret", "items", 0, "key") != "route-password" {
		t.Errorf("route-auth volume: %v", auth)
	}
	if !slices.Contains(containerPorts(c), 6222) {
		t.Error("no cluster containerPort")
	}
	for _, d := range docs {
		if d["kind"] == "Secret" {
			t.Fatalf("chart rendered a Secret (%v); route credentials come from bus.cluster.auth.secretName only", get(d, "metadata", "name"))
		}
	}
	if !has(docs, "PodDisruptionBudget", "-bus") {
		t.Error("no bus PDB for a 3-node cluster")
	}
}

func containerPorts(c obj) []int {
	var ports []int
	for _, p := range c["ports"].([]any) {
		ports = append(ports, get(p, "containerPort").(int))
	}
	return ports
}

func servicePorts(svc obj) []int {
	var ports []int
	for _, p := range get(svc, "spec", "ports").([]any) {
		ports = append(ports, get(p, "port").(int))
	}
	return ports
}

// The headless Service gives each pod the stable name its peers dial for
// routes; it carries the route port only when clustered. The client
// Service (core) and the Envoy Service (the DMZ edge) never do.
func TestClusteredServices(t *testing.T) {
	docs := mustRender(t, clusteredArgs...)
	hl := find(t, docs, "Service", "-bus-headless")
	if get(hl, "spec", "clusterIP") != "None" || get(hl, "spec", "publishNotReadyAddresses") != true {
		t.Errorf("headless Service: clusterIP=%v publishNotReadyAddresses=%v", get(hl, "spec", "clusterIP"), get(hl, "spec", "publishNotReadyAddresses"))
	}
	if !slices.Contains(servicePorts(hl), 6222) {
		t.Errorf("headless Service ports = %v, want the route port", servicePorts(hl))
	}
	if get(hl, "spec", "selector", "app.kubernetes.io/component") != "bus" {
		t.Errorf("headless Service selects %v", get(hl, "spec", "selector"))
	}
	if got := servicePorts(find(t, docs, "Service", "-bus")); slices.Contains(got, 6222) {
		t.Errorf("client Service exposes the route port: %v", got)
	}
	if got := servicePorts(find(t, docs, "Service", "-envoy")); slices.Contains(got, 6222) {
		t.Errorf("Envoy Service exposes the route port: %v", got)
	}

	single := mustRender(t)
	if got := servicePorts(find(t, single, "Service", "-bus-headless")); slices.Contains(got, 6222) {
		t.Errorf("single-node headless Service has a route port: %v", got)
	}
}

// Node port exposure for a core in another cluster (the UAT DMZ hub): the
// Envoy Service can pin its node port, and an opt-in bus "-core" Service
// exposes the client port alone, never the websocket port. Defaults render
// neither a pinned port nor the extra Service.
func TestExposureServices(t *testing.T) {
	defaults := mustRender(t)
	if has(defaults, "Service", "-bus-core") {
		t.Error("bus core Service rendered by default")
	}
	if np := get(find(t, defaults, "Service", "-envoy"), "spec", "ports", 0, "nodePort"); np != nil {
		t.Errorf("default Envoy Service pins nodePort %v", np)
	}

	docs := mustRender(t,
		"--set", "envoy.service.type=NodePort", "--set", "envoy.service.port=8443", "--set", "envoy.service.nodePort=8443",
		"--set", "bus.coreService.enabled=true", "--set", "bus.coreService.nodePort=8442", "--set", "bus.coreService.port=8442",
		"--set", "bus.coreService.externalTrafficPolicy=Local")
	envoy := find(t, docs, "Service", "-envoy")
	if get(envoy, "spec", "type") != "NodePort" || get(envoy, "spec", "ports", 0, "nodePort") != 8443 {
		t.Errorf("Envoy Service: type=%v ports=%v, want NodePort with nodePort 8443", get(envoy, "spec", "type"), get(envoy, "spec", "ports"))
	}
	core := find(t, docs, "Service", "-bus-core")
	ports, _ := get(core, "spec", "ports").([]any)
	if len(ports) != 1 {
		t.Fatalf("bus core Service ports = %v, want the client port only", ports)
	}
	if get(core, "spec", "type") != "NodePort" || get(core, "spec", "externalTrafficPolicy") != "Local" ||
		get(ports[0], "port") != 8442 || get(ports[0], "nodePort") != 8442 || get(ports[0], "targetPort") != "client" {
		t.Errorf("bus core Service spec = %v", get(core, "spec"))
	}
	if get(core, "spec", "selector", "app.kubernetes.io/component") != "bus" {
		t.Errorf("bus core Service selects %v", get(core, "spec", "selector"))
	}
	// The ClusterIP client Service is untouched: core in-cluster and Envoy
	// still use it, with both ports.
	if got := servicePorts(find(t, docs, "Service", "-bus")); !slices.Equal(got, []int{5406, 5407}) {
		t.Errorf("client Service ports = %v, want [5406 5407]", got)
	}

	// Unpinned and default port: Kubernetes picks the node port, the
	// Service port is the client port.
	lb := mustRender(t, "--set", "bus.coreService.enabled=true", "--set", "bus.coreService.type=LoadBalancer",
		"--set", "bus.coreService.loadBalancerSourceRanges={10.60.2.0/24}")
	lbCore := find(t, lb, "Service", "-bus-core")
	if get(lbCore, "spec", "ports", 0, "nodePort") != nil || get(lbCore, "spec", "ports", 0, "port") != 5406 {
		t.Errorf("unpinned bus core Service ports = %v", get(lbCore, "spec", "ports"))
	}
	if got := get(lbCore, "spec", "loadBalancerSourceRanges", 0); got != "10.60.2.0/24" {
		t.Errorf("loadBalancerSourceRanges = %v", get(lbCore, "spec", "loadBalancerSourceRanges"))
	}
}

func TestExposureValidation(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		{"envoy nodePort on ClusterIP", "envoy.service.nodePort needs envoy.service.type NodePort or LoadBalancer", []string{"--set", "envoy.service.nodePort=8443"}},
		{"envoy nodePort out of range", "envoy.service.nodePort must be between 0 and 65535", []string{"--set", "envoy.service.type=NodePort", "--set", "envoy.service.nodePort=70000"}},
		{"bus core Service as ClusterIP", "bus.coreService.type must be NodePort or LoadBalancer", []string{"--set", "bus.coreService.enabled=true", "--set", "bus.coreService.type=ClusterIP"}},
		{"bus core nodePort out of range", "bus.coreService.nodePort must be between 0 and 65535", []string{"--set", "bus.coreService.enabled=true", "--set", "bus.coreService.nodePort=-1"}},
		{"bus core port out of range", "bus.coreService.port must be between 0 and 65535", []string{"--set", "bus.coreService.enabled=true", "--set", "bus.coreService.port=70000"}},
		{"same node port twice", "a node port belongs to one Service", []string{"--set", "envoy.service.type=NodePort", "--set", "envoy.service.nodePort=8443",
			"--set", "bus.coreService.enabled=true", "--set", "bus.coreService.nodePort=8443"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { mustFail(t, c.want, c.args...) })
	}
}

// Route traffic stays between bus pods: one dedicated policy opens the
// route port, in and out, to this StatefulSet's pods only; no other
// policy mentions it, and Envoy cannot egress to it.
func TestRoutesNetworkPolicy(t *testing.T) {
	docs := mustRender(t, clusteredArgs...)
	np := find(t, docs, "NetworkPolicy", "-bus-routes")
	if get(np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") != "bus" {
		t.Errorf("routes policy selects %v", get(np, "spec", "podSelector"))
	}
	if pt := get(np, "spec", "policyTypes").([]any); len(pt) != 2 {
		t.Errorf("routes policy types = %v, want Ingress and Egress", pt)
	}
	for _, dir := range []struct{ rules, peer string }{{"ingress", "from"}, {"egress", "to"}} {
		rules := get(np, "spec", dir.rules).([]any)
		if len(rules) != 1 {
			t.Fatalf("routes policy %s rules = %d, want 1", dir.rules, len(rules))
		}
		peers := get(rules[0], dir.peer).([]any)
		if len(peers) != 1 || get(peers[0], "namespaceSelector") != nil || get(peers[0], "ipBlock") != nil {
			t.Errorf("routes policy %s peer must be a same-namespace podSelector only: %v", dir.rules, peers)
		}
		sel := get(peers[0], "podSelector", "matchLabels").(obj)
		if sel["app.kubernetes.io/component"] != "bus" || sel["app.kubernetes.io/instance"] != "t" {
			t.Errorf("routes policy %s peer selects %v", dir.rules, sel)
		}
		if got := policyPorts(np, dir.rules); !slices.Equal(got, []int{6222}) {
			t.Errorf("routes policy %s ports = %v", dir.rules, got)
		}
	}
	for _, name := range []string{"-bus", "-envoy"} {
		p := find(t, docs, "NetworkPolicy", name)
		for _, dir := range []string{"ingress", "egress"} {
			if slices.Contains(policyPorts(p, dir), 6222) {
				t.Errorf("NetworkPolicy *%s %s mentions the route port", name, dir)
			}
		}
	}
	// Single node: no route policy at all.
	if has(mustRender(t), "NetworkPolicy", "-bus-routes") {
		t.Error("routes NetworkPolicy rendered for replicaCount=1")
	}
}

// Readiness follows the fence (/readyz on the health port), clustered or
// not, and the probe port exists.
func TestBusHealthProbe(t *testing.T) {
	for _, args := range [][]string{nil, clusteredArgs} {
		c := container(t, find(t, mustRender(t, args...), "StatefulSet", "-bus"))
		if get(c, "readinessProbe", "httpGet", "path") != "/readyz" || get(c, "readinessProbe", "httpGet", "port") != "health" {
			t.Errorf("readinessProbe = %v", c["readinessProbe"])
		}
		if !slices.Contains(containerPorts(c), 8080) || envMap(c)["IMAS_BUS_HEALTH_PORT"] != "8080" {
			t.Errorf("health port not wired: ports %v", containerPorts(c))
		}
	}
}

func policyPorts(np obj, direction string) []int {
	var ports []int
	for _, r := range get(np, "spec", direction).([]any) {
		for _, p := range get(r, "ports").([]any) {
			ports = append(ports, get(p, "port").(int))
		}
	}
	return ports
}

// Bus <-> core traffic is limited to the documented ports: core -> bus
// client port, Envoy -> bus websocket port, Envoy -> farmer API port. The
// bus has no egress except DNS and the accounts bucket.
func TestNetworkPolicyPorts(t *testing.T) {
	docs := mustRender(t)
	bus := find(t, docs, "NetworkPolicy", "-bus")
	ingress := get(bus, "spec", "ingress").([]any)
	if len(ingress) != 2 {
		t.Fatalf("bus ingress rules = %d, want 2", len(ingress))
	}
	if get(ingress[0], "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "imas-core" ||
		get(ingress[0], "ports", 0, "port") != 5406 {
		t.Errorf("core -> bus rule wrong: %v", ingress[0])
	}
	if get(ingress[1], "from", 0, "podSelector", "matchLabels", "app.kubernetes.io/component") != "envoy" ||
		get(ingress[1], "ports", 0, "port") != 5407 {
		t.Errorf("envoy -> bus rule wrong: %v", ingress[1])
	}
	if got := policyPorts(bus, "egress"); !slices.Equal(got, []int{53, 53, 9000}) {
		t.Errorf("bus egress ports = %v, want DNS and the accounts bucket only", got)
	}

	envoy := find(t, docs, "NetworkPolicy", "-envoy")
	if got := policyPorts(envoy, "ingress"); !slices.Equal(got, []int{8443}) {
		t.Errorf("envoy ingress ports = %v", got)
	}
	if got := policyPorts(envoy, "egress"); !slices.Equal(got, []int{5407, 5405, 53, 53}) {
		t.Errorf("envoy egress ports = %v", got)
	}

	// openbao mode opens exactly one more egress, to OpenBao.
	docs = mustRender(t, "--set", "bus.tls.mode=openbao")
	if got := policyPorts(find(t, docs, "NetworkPolicy", "-bus"), "egress"); !slices.Equal(got, []int{53, 53, 9000, 8200}) {
		t.Errorf("openbao-mode bus egress ports = %v", got)
	}
}

func TestEnvoyJWTAuthn(t *testing.T) {
	cfg := envoyConfig(t, mustRender(t))
	ja := jwtAuthn(cfg)
	if ja == nil {
		t.Fatal("no jwt_authn filter")
	}
	prov := get(ja, "providers", "sprout_jwt").(obj)
	if prov["issuer"] != "imas-gateway" || prov["forward"] != true {
		t.Errorf("provider: %v", prov)
	}
	if got := get(prov, "remote_jwks", "http_uri", "uri"); got != "https://farmer.imas-core.svc.cluster.local:5405/v1/.well-known/jwks.json" {
		t.Errorf("remote_jwks uri = %v", got)
	}
	if get(prov, "claim_to_headers", 0, "header_name") != "x-imas-sprout-nkey" {
		t.Errorf("claim_to_headers: %v", prov["claim_to_headers"])
	}

	// Regression: every per-route requirement_name must exist in
	// requirement_map. Without the map (deploy/envoy/envoy.yaml before
	// PR #6) real Envoy answers every gated request with 403 "Wrong
	// requirement_name".
	reqMap, _ := ja["requirement_map"].(obj)
	routes := get(httpConnManager(cfg), "route_config", "virtual_hosts", 0, "routes").([]any)
	gated := 0
	for _, r := range routes {
		pr, _ := get(r, "typed_per_filter_config", "envoy.filters.http.jwt_authn").(obj)
		if pr == nil {
			t.Errorf("route %v has no jwt_authn per-route config", get(r, "match"))
			continue
		}
		if pr["disabled"] == true {
			if get(r, "match", "prefix") != "/v1/enroll" && get(r, "match", "path") != "/v1/refresh" {
				t.Errorf("jwt_authn disabled on %v; only /v1/enroll and /v1/refresh may be un-gated", get(r, "match"))
			}
			continue
		}
		name, _ := pr["requirement_name"].(string)
		if _, ok := reqMap[name]; !ok {
			t.Errorf("route %v requirement_name %q not in requirement_map %v", get(r, "match"), name, reqMap)
		}
		gated++
	}
	if gated != 3 {
		t.Errorf("gated routes = %d, want 3 (/files/, /v1/sprout/update-manifest and /)", gated)
	}

	// Client-supplied claim headers are stripped before any filter runs.
	muts := get(httpConnManager(cfg), "early_header_mutation_extensions", 0, "typed_config", "mutations").([]any)
	if get(muts, 0, "remove") != "x-imas-sprout-nkey" {
		t.Errorf("early header mutation: %v", muts)
	}
}

func TestEnvoyLocalJWKS(t *testing.T) {
	jwks := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"1"}]}`
	values := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(values, []byte("envoy:\n  jwtAuthn:\n    jwks:\n      source: local\n      local:\n        inline: '"+jwks+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	docs := mustRender(t, "-f", values)
	prov := get(jwtAuthn(envoyConfig(t, docs)), "providers", "sprout_jwt").(obj)
	if prov["remote_jwks"] != nil || get(prov, "local_jwks", "filename") != "/etc/envoy/jwks/jwks.json" {
		t.Errorf("local JWKS provider: %v", prov)
	}
	if get(find(t, docs, "ConfigMap", "-envoy"), "data", "jwks.json") != jwks {
		t.Error("inline JWKS not rendered into the ConfigMap")
	}
}

func TestEnvoyUpstreamTLS(t *testing.T) {
	clusters := func(docs []obj) []any {
		return get(envoyConfig(t, docs), "static_resources", "clusters").([]any)
	}
	for _, c := range clusters(mustRender(t)) {
		if get(c, "transport_socket", "typed_config", "common_tls_context") != nil {
			t.Errorf("cluster %v verifies upstream without a CA configured", get(c, "name"))
		}
	}
	for _, c := range clusters(mustRender(t, "--set", "envoy.upstreamTLS.caSecretName=core-ca")) {
		tc := get(c, "transport_socket", "typed_config").(obj)
		vc := get(tc, "common_tls_context", "validation_context")
		if vc == nil {
			t.Fatalf("cluster %v: no validation_context with a CA configured", get(c, "name"))
		}
		if get(vc, "match_typed_subject_alt_names", 0, "matcher", "exact") != tc["sni"] {
			t.Errorf("cluster %v: SAN matcher does not match sni %v", get(c, "name"), tc["sni"])
		}
	}
}

func TestOpenBaoTLSMode(t *testing.T) {
	docs := mustRender(t, "--set", "bus.tls.mode=openbao")
	sts := find(t, docs, "StatefulSet", "-bus")
	env := envMap(container(t, sts))
	for _, k := range []string{"IMAS_CERTS_OPENBAO_ADDR", "IMAS_CERTS_OPENBAO_ROLE", "IMAS_CERTS_OPENBAO_K8S_ROLE", "IMAS_CERTS_OPENBAO_K8S_JWT_PATH"} {
		if env[k] == "" {
			t.Errorf("%s not set in openbao mode", k)
		}
	}
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(get(find(t, docs, "ConfigMap", "-bus"), "data", "farmer").(string)), &cfg)
	hosts, _ := cfg["certhosts"].([]any)
	if !slices.Contains(hosts, any("t-nats-bus.imas-dmz.svc.cluster.local")) {
		t.Errorf("certhosts missing the bus Service FQDN: %v", hosts)
	}
}

func TestEnvoyDisabled(t *testing.T) {
	docs := mustRender(t, "--set", "envoy.enabled=false")
	if has(docs, "Deployment", "-envoy") || has(docs, "NetworkPolicy", "-envoy") {
		t.Error("Envoy resources rendered with envoy.enabled=false")
	}
	if n := len(get(find(t, docs, "NetworkPolicy", "-bus"), "spec", "ingress").([]any)); n != 1 {
		t.Errorf("bus ingress rules = %d, want 1 (core only)", n)
	}
}

// routesByMatch indexes a rendered route list by its match (prefix or
// exact path).
func routesByMatch(routes []any) map[string]obj {
	m := map[string]obj{}
	for _, r := range routes {
		key, _ := get(r, "match", "prefix").(string)
		if p, ok := get(r, "match", "path").(string); ok {
			key = "path:" + p
		}
		m[key] = r.(obj)
	}
	return m
}

func routeBucket(r obj) any {
	return get(r, "typed_per_filter_config", "envoy.filters.http.local_ratelimit", "token_bucket")
}

// The chart's /v1/refresh bucket reproduces deploy/envoy/README.md's
// worked examples (fill 1s, burst 300s, headroom 2).
func TestRefreshRateLimit(t *testing.T) {
	cases := []struct {
		fleet, ttl, replicas string
		perFill, max         int
	}{
		{"1000000", "86400", "4", 11, 3300},
		{"1000000", "3600", "4", 246, 73800},
		{"100000", "86400", "2", 3, 900},
	}
	for _, tc := range cases {
		docs := mustRender(t, "--set", "envoy.refreshRateLimit.fleetSize="+tc.fleet,
			"--set", "envoy.refreshRateLimit.gatewayJwtTtlSeconds="+tc.ttl,
			"--set", "envoy.refreshRateLimit.envoyReplicas="+tc.replicas)
		routes := get(httpConnManager(envoyConfig(t, docs)), "route_config", "virtual_hosts", 0, "routes").([]any)
		b := routeBucket(routesByMatch(routes)["path:/v1/refresh"])
		if get(b, "tokens_per_fill") != tc.perFill || get(b, "max_tokens") != tc.max || get(b, "fill_interval") != "1s" {
			t.Errorf("fleet %s ttl %s replicas %s: bucket %v, want %d/%d", tc.fleet, tc.ttl, tc.replicas, b, tc.perFill, tc.max)
		}
	}
	// envoyReplicas null follows envoy.replicaCount.
	docs := mustRender(t, "--set", "envoy.replicaCount=4")
	routes := get(httpConnManager(envoyConfig(t, docs)), "route_config", "virtual_hosts", 0, "routes").([]any)
	if b := routeBucket(routesByMatch(routes)["path:/v1/refresh"]); get(b, "tokens_per_fill") != 11 {
		t.Errorf("envoyReplicas null with replicaCount=4: bucket %v, want 11 per fill", b)
	}
	// Explicit overrides win.
	docs = mustRender(t, "--set", "envoy.refreshRateLimit.tokensPerFill=7", "--set", "envoy.refreshRateLimit.maxTokens=70")
	routes = get(httpConnManager(envoyConfig(t, docs)), "route_config", "virtual_hosts", 0, "routes").([]any)
	if b := routeBucket(routesByMatch(routes)["path:/v1/refresh"]); get(b, "tokens_per_fill") != 7 || get(b, "max_tokens") != 70 {
		t.Errorf("overrides: bucket %v", b)
	}
}

// The chart's routes must stay in step with the reviewed reference config
// deploy/envoy/envoy.yaml: same matches, in the same order, same jwt_authn
// gate per route, same cluster, and the same fixed /v1/enroll bucket.
// Rendered with the reference's own worked-example sizing (4 replicas), so
// the /v1/refresh bucket must match too.
func TestRoutesMatchReferenceEnvoyConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(chartDir(t), "..", "..", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ref obj
	if err := yaml.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	refRoutes := get(httpConnManager(ref), "route_config", "virtual_hosts", 0, "routes").([]any)
	docs := mustRender(t, "--set", "envoy.refreshRateLimit.envoyReplicas=4")
	gotRoutes := get(httpConnManager(envoyConfig(t, docs)), "route_config", "virtual_hosts", 0, "routes").([]any)
	if len(gotRoutes) != len(refRoutes) {
		t.Fatalf("chart has %d routes, reference has %d", len(gotRoutes), len(refRoutes))
	}
	for i := range refRoutes {
		want, got := refRoutes[i].(obj), gotRoutes[i].(obj)
		for _, path := range [][]any{
			{"match"},
			{"route", "cluster"},
			{"typed_per_filter_config", "envoy.filters.http.jwt_authn", "disabled"},
			{"typed_per_filter_config", "envoy.filters.http.jwt_authn", "requirement_name"},
			{"typed_per_filter_config", "envoy.filters.http.local_ratelimit", "token_bucket"},
			{"route", "retry_policy"},
		} {
			w, g := get(want, path...), get(got, path...)
			if !reflect.DeepEqual(w, g) {
				t.Errorf("route %d %v: chart %v, reference %v", i, path, g, w)
			}
		}
	}
	refJA, gotJA := jwtAuthn(ref), jwtAuthn(envoyConfig(t, docs))
	for _, k := range []string{"requirement_map", "rules"} {
		if !reflect.DeepEqual(refJA[k], gotJA[k]) {
			t.Errorf("jwt_authn %s: chart %v, reference %v", k, gotJA[k], refJA[k])
		}
	}
}

// TestEnrollRoutesDoNotRetry503: Envoy must pass farmer's 503 on
// /v1/enroll and /v1/refresh, and its Retry-After, to the sprout
// (internal/pki/enrollclient.go), never retry it itself. Checked for the
// chart with every ci values file and for the reference
// deploy/envoy/envoy.yaml.
func TestEnrollRoutesDoNotRetry503(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(chartDir(t), "ci", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no ci values files: %v", err)
	}
	for _, f := range files {
		cfg := envoyConfig(t, mustRender(t, "-f", f))
		for _, p := range envoycheck.BusyRetryProblems(cfg) {
			t.Errorf("%s: %s", filepath.Base(f), p)
		}
		// Not merely absent: the routes carry the explicit policy.
		for _, r := range get(httpConnManager(cfg), "route_config", "virtual_hosts", 0, "routes").([]any) {
			m := get(r, "match").(obj)
			if m["prefix"] == "/v1/enroll" || m["path"] == "/v1/refresh" {
				if on := get(r, "route", "retry_policy", "retry_on"); on != "connect-failure,refused-stream" {
					t.Errorf("%s: %v retry_on %v", filepath.Base(f), m, on)
				}
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(chartDir(t), "..", "..", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ref obj
	if err := yaml.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	for _, p := range envoycheck.BusyRetryProblems(ref) {
		t.Errorf("deploy/envoy/envoy.yaml: %s", p)
	}
}

// namedContainer returns the pod template's container called name.
func namedContainer(t *testing.T, workload obj, name string) obj {
	t.Helper()
	for _, c := range get(workload, "spec", "template", "spec", "containers").([]any) {
		if c.(obj)["name"] == name {
			return c.(obj)
		}
	}
	t.Fatalf("no container %q", name)
	return nil
}

func volumeByName(sts obj, name string) obj {
	for _, v := range get(sts, "spec", "template", "spec", "volumes").([]any) {
		if v.(obj)["name"] == name {
			return v.(obj)
		}
	}
	return nil
}

func mountPaths(c obj) map[string]string {
	m := map[string]string{}
	for _, v := range c["volumeMounts"].([]any) {
		m[v.(obj)["name"].(string)] = v.(obj)["mountPath"].(string)
	}
	return m
}

// The bus keeps no volume (P21 slice 2): the resolver's store is an
// emptyDir, rebuilt by the loader from the accounts bucket.
func TestNoPersistentVolumeClaim(t *testing.T) {
	for _, args := range [][]string{nil, clusteredArgs} {
		sts := find(t, mustRender(t, args...), "StatefulSet", "-bus")
		if v := get(sts, "spec", "volumeClaimTemplates"); v != nil {
			t.Errorf("volumeClaimTemplates rendered: %v", v)
		}
		if v := get(sts, "spec", "persistentVolumeClaimRetentionPolicy"); v != nil {
			t.Errorf("persistentVolumeClaimRetentionPolicy rendered: %v", v)
		}
		data := volumeByName(sts, "data")
		if data == nil || data["emptyDir"] == nil {
			t.Errorf("data volume is not an emptyDir: %v", data)
		}
		if got := mountPaths(container(t, sts))["data"]; got != "/var/lib/imas/farmerbus" {
			t.Errorf("data mounted at %q", got)
		}
	}
}

func TestLoaderSidecarRendered(t *testing.T) {
	sts := find(t, mustRender(t), "StatefulSet", "-bus")
	if c := container(t, sts); c["name"] != "farmerbus" {
		t.Fatalf("first container is %v, want farmerbus", c["name"])
	}
	l := namedContainer(t, sts, "loader")
	if get(l, "image") != "ghcr.io/yogzblr/imas-farmerbus:0.1.0" {
		t.Errorf("loader image = %v, want the bus image", get(l, "image"))
	}
	if cmd := get(l, "command").([]any); len(cmd) != 1 || cmd[0] != "/farmerbus-loader" {
		t.Errorf("loader command = %v", cmd)
	}
	env := envMap(l)
	for k, want := range map[string]string{
		"IMAS_LOADER_S3_ENDPOINT":               "s3.imas-core.example.internal:9000",
		"IMAS_LOADER_S3_USE_SSL":                "true",
		"IMAS_LOADER_S3_BUCKET":                 "imas-accounts",
		"IMAS_LOADER_S3_ACCESS_KEY_ID_FILE":     "/var/run/secrets/imas/accounts-reader/access-key-id",
		"IMAS_LOADER_S3_SECRET_ACCESS_KEY_FILE": "/var/run/secrets/imas/accounts-reader/secret-access-key",
		"IMAS_LOADER_NATS_URL":                  "tls://127.0.0.1:5406",
		"IMAS_LOADER_NATS_SERVER_NAME":          "t-nats-bus.imas-dmz.svc.cluster.local",
		"IMAS_LOADER_CA_FILE":                   "/var/run/imas/loader-ca/ca.crt",
		"IMAS_NATS_TRUST_DIR":                   "/var/run/imas/nats-trust",
		"IMAS_LOADER_SYS_USER_JWT_FILE":         "/var/run/imas/nats-trust/bus-loader-user.jwt",
		"IMAS_LOADER_SYS_USER_SEED_FILE":        "/var/run/secrets/imas/loader/user.nk",
		"IMAS_LOADER_EVENT_SUBJECT":             "imas.bus.accounts.changed",
		"IMAS_LOADER_RECONCILE_INTERVAL":        "30s",
		"IMAS_LOADER_FULL_RESYNC_INTERVAL":      "5m",
		"IMAS_LOADER_HEALTH_PORT":               "8081",
	} {
		if env[k] != want {
			t.Errorf("loader %s = %q, want %q", k, env[k], want)
		}
	}
	for k := range env {
		if strings.HasSuffix(k, "_SEED") || strings.HasSuffix(k, "SECRET_ACCESS_KEY") {
			t.Errorf("loader secret passed as env var %s; only a _FILE path is allowed", k)
		}
	}
	if !slices.Contains(containerPorts(l), 8081) {
		t.Errorf("loader ports = %v", containerPorts(l))
	}
	for probe, path := range map[string]string{"readinessProbe": "/readyz", "startupProbe": "/healthz", "livenessProbe": "/healthz"} {
		if get(l, probe, "httpGet", "path") != path || get(l, probe, "httpGet", "port") != "loader-health" {
			t.Errorf("loader %s = %v", probe, l[probe])
		}
	}
	if get(l, "readinessProbe", "periodSeconds") != 5 || get(l, "readinessProbe", "failureThreshold") != 3 ||
		get(l, "startupProbe", "periodSeconds") != 5 || get(l, "startupProbe", "failureThreshold") != 120 {
		t.Errorf("loader probe timing: readiness %v, startup %v", l["readinessProbe"], l["startupProbe"])
	}
	sc := l["securityContext"]
	if get(sc, "readOnlyRootFilesystem") != true || get(sc, "runAsNonRoot") != true ||
		get(sc, "allowPrivilegeEscalation") != false || get(sc, "capabilities", "drop", 0) != "ALL" {
		t.Errorf("loader securityContext = %v", sc)
	}
	mounts := map[string]bool{}
	for _, v := range l["volumeMounts"].([]any) {
		mounts[v.(obj)["name"].(string)] = true
		if v.(obj)["readOnly"] != true {
			t.Errorf("loader mount %v is writable", v)
		}
	}
	for _, want := range []string{"nats-trust", "loader-sys-user", "accounts-reader", "loader-ca"} {
		if !mounts[want] {
			t.Errorf("loader does not mount %s: %v", want, mounts)
		}
	}
	if mounts["tls"] || mounts["data"] || mounts["nats-seeds"] {
		t.Errorf("loader mounts more than it needs: %v", mounts)
	}
	// The loader's credentials reach the loader only, and each volume
	// projects only the keys it names.
	for name := range mountPaths(container(t, sts)) {
		if name == "loader-sys-user" || name == "accounts-reader" || name == "loader-ca" {
			t.Errorf("farmerbus mounts the loader's %s", name)
		}
	}
	for name, want := range map[string][]string{
		"loader-sys-user": {"user.nk"},
		"accounts-reader": {"access-key-id", "secret-access-key"},
		"loader-ca":       {"ca.crt"},
	} {
		v := volumeByName(sts, name)
		var keys []string
		for _, it := range get(v, "secret", "items").([]any) {
			keys = append(keys, get(it, "key").(string))
		}
		if !slices.Equal(keys, want) {
			t.Errorf("volume %s projects %v, want %v", name, keys, want)
		}
	}
	for name, secret := range map[string]string{
		"loader-sys-user": "imas-bus-loader-sys-user", "accounts-reader": "imas-bus-accounts-reader", "loader-ca": "imas-farmerbus-tls",
	} {
		if got := get(volumeByName(sts, name), "secret", "secretName"); got != secret {
			t.Errorf("volume %s from Secret %v, want %s", name, got, secret)
		}
	}

	// openbao mode: the CA is only in farmerbus's in-memory tls volume.
	sts = find(t, mustRender(t, "--set", "bus.tls.mode=openbao"), "StatefulSet", "-bus")
	l = namedContainer(t, sts, "loader")
	if got := envMap(l)["IMAS_LOADER_CA_FILE"]; got != "/var/run/imas/tls/tls-rootca.pem" {
		t.Errorf("openbao-mode IMAS_LOADER_CA_FILE = %q", got)
	}
	if got := mountPaths(l)["tls"]; got != "/var/run/imas/tls" {
		t.Errorf("openbao-mode loader tls mount = %q", got)
	}

	// Overrides: its own image, plain HTTP to the store, another port.
	sts = find(t, mustRender(t, "--set", "loader.image.repository=example.com/loader", "--set", "loader.image.tag=1.2.3",
		"--set", "accountStore.useSSL=false", "--set", "loader.healthPort=9091"), "StatefulSet", "-bus")
	l = namedContainer(t, sts, "loader")
	env = envMap(l)
	if get(l, "image") != "example.com/loader:1.2.3" || env["IMAS_LOADER_S3_USE_SSL"] != "false" ||
		env["IMAS_LOADER_HEALTH_PORT"] != "9091" || !slices.Contains(containerPorts(l), 9091) {
		t.Errorf("loader overrides not applied: image %v, env %v", get(l, "image"), env)
	}
}

// The topology ConfigMap carries the replica count the fence reads, equal
// to the StatefulSet's replicas and the number of routes, and is mounted
// as a directory (no subPath) so kubelet updates it in place.
func TestTopologyConfigMapReplicasMatch(t *testing.T) {
	for _, n := range []int{1, 3, 5} {
		args := []string{"--set", fmt.Sprintf("bus.replicaCount=%d", n)}
		if n > 1 {
			args = append(slices.Clone(clusteredArgs), args...)
		}
		docs := mustRender(t, args...)
		cm := find(t, docs, "ConfigMap", "-bus-topology")
		sts := find(t, docs, "StatefulSet", "-bus")
		if get(cm, "data", "replicas") != strconv.Itoa(n) || get(sts, "spec", "replicas") != n {
			t.Errorf("n=%d: topology replicas %v, StatefulSet replicas %v", n, get(cm, "data", "replicas"), get(sts, "spec", "replicas"))
		}
		c := container(t, sts)
		env := envMap(c)
		if n == 1 {
			if _, ok := env["IMAS_BUS_CLUSTER_SIZE_FILE"]; ok {
				t.Error("single node sets IMAS_BUS_CLUSTER_SIZE_FILE")
			}
			continue
		}
		if routes := strings.Split(env["IMAS_BUS_CLUSTER_ROUTES"], ","); len(routes) != n {
			t.Errorf("n=%d: %d routes", n, len(routes))
		}
		if env["IMAS_BUS_CLUSTER_SIZE_FILE"] != "/var/run/imas/bus-topology/replicas" {
			t.Errorf("IMAS_BUS_CLUSTER_SIZE_FILE = %q", env["IMAS_BUS_CLUSTER_SIZE_FILE"])
		}
		for _, m := range c["volumeMounts"].([]any) {
			if m.(obj)["name"] == "bus-topology" && (m.(obj)["mountPath"] != "/var/run/imas/bus-topology" || m.(obj)["subPath"] != nil) {
				t.Errorf("topology mount = %v", m)
			}
		}
		if get(volumeByName(sts, "bus-topology"), "configMap", "name") != "t-nats-bus-topology" {
			t.Errorf("bus-topology volume = %v", volumeByName(sts, "bus-topology"))
		}
		// Not in the checksum: only the bus config is.
		ann := get(sts, "spec", "template", "metadata", "annotations").(obj)
		for k := range ann {
			if strings.Contains(k, "topology") {
				t.Errorf("topology ConfigMap in the pod annotations: %s", k)
			}
		}
	}
}

func TestAccountStoreEgress(t *testing.T) {
	bus := find(t, mustRender(t, "--set", "networkPolicy.accountStoreEgress.cidr=192.0.2.7/32",
		"--set", "networkPolicy.accountStoreEgress.port=443"), "NetworkPolicy", "-bus")
	egress := get(bus, "spec", "egress").([]any)
	var found bool
	for _, r := range egress {
		if get(r, "to", 0, "ipBlock", "cidr") == "192.0.2.7/32" {
			found = get(r, "ports", 0, "port") == 443 && get(r, "ports", 0, "protocol") == "TCP" && len(get(r, "ports").([]any)) == 1
		}
	}
	if !found {
		t.Errorf("no egress rule to 192.0.2.7/32 on 443/TCP: %v", egress)
	}
	if got := policyPorts(bus, "egress"); !slices.Equal(got, []int{53, 53, 443}) {
		t.Errorf("bus egress ports = %v, want DNS and 443", got)
	}
	// No NetworkPolicy, no egress value needed.
	mustRender(t, "--set", "networkPolicy.enabled=false", "--set", "networkPolicy.accountStoreEgress.cidr=")
}

func TestValidationAccountStoreRequired(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		{"no endpoint", "accountStore.endpoint is required", []string{"--set", "accountStore.endpoint="}},
		{"endpoint with scheme", "without a scheme", []string{"--set", "accountStore.endpoint=https://s3.example.com"}},
		{"endpoint port too large", "accountStore.endpoint port must be between 1 and 65535", []string{"--set", "accountStore.endpoint=s3.example.com:99999"}},
		{"endpoint port zero", "accountStore.endpoint port must be between 1 and 65535", []string{"--set", "accountStore.endpoint=s3.example.com:0"}},
		{"no bucket", "accountStore.bucket is required", []string{"--set", "accountStore.bucket="}},
		{"bad bucket", "not a valid S3 bucket name", []string{"--set", "accountStore.bucket=Imas_Accounts"}},
		{"no reader secret", "accountStore.credentialsSecret is required", []string{"--set", "accountStore.credentialsSecret="}},
		{"bad reader key", "accountStore.accessKeyIdKey", []string{"--set", "accountStore.accessKeyIdKey=a/b"}},
		{"no loader secret", "loader.sysUserSecret is required", []string{"--set", "loader.sysUserSecret="}},
		{"bad loader seed key", "loader.sysUserSeedKey", []string{"--set", "loader.sysUserSeedKey=a/b"}},
		{"no egress cidr", "networkPolicy.accountStoreEgress.cidr is required", []string{"--set", "networkPolicy.accountStoreEgress.cidr="}},
		{"bad egress cidr", "is not a CIDR", []string{"--set", "networkPolicy.accountStoreEgress.cidr=s3.example.com"}},
		{"bad egress port", "accountStoreEgress.port must be", []string{"--set", "networkPolicy.accountStoreEgress.port=0"}},
		{"no trust configmap", "natsTrust.configMapName", []string{"--set", "natsTrust.configMapName="}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { mustFail(t, tc.want, tc.args...) })
	}
	// A cluster renders without any persistence value.
	mustRender(t, clusteredArgs...)
}
