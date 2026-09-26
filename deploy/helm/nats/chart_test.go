// Package natschart tests the deploy/helm/nats Helm chart by rendering it
// with the helm CLI and asserting on the manifests. The tests skip when
// helm is not on PATH, so `go test ./...` stays green on machines without
// it; run them locally with helm v3 installed.
package natschart

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// render runs `helm template` and returns the parsed documents, or the
// combined output as an error when rendering fails.
func render(t *testing.T, args ...string) ([]obj, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not on PATH; skipping chart rendering tests")
	}
	cmd := exec.Command(helm, append([]string{"template", "t", chartDir(t),
		"--namespace", "imas-dmz", "--kube-version", "1.30.0"}, args...)...)
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
// seeds only ever reach the process as _SEED_FILE paths.
func TestSeedsAreReferencesOnly(t *testing.T) {
	docs := mustRender(t)
	for _, d := range docs {
		if d["kind"] == "Secret" {
			t.Fatalf("chart rendered a Secret (%v); seeds must come from natsSeeds.secretName only", get(d, "metadata", "name"))
		}
	}
	sts := find(t, docs, "StatefulSet", "-bus")
	env := envMap(container(t, sts))
	for name, key := range map[string]string{
		"OPERATOR": "operator.nk", "OPERATOR_SIGNING": "operator-signing.nk",
		"SYS_ACCOUNT": "sys-account.nk", "TENANT": "tenant.nk", "TENANT_SIGNING": "tenant-signing.nk",
	} {
		if got := env["IMAS_NATS_"+name+"_SEED_FILE"]; got != "/var/run/secrets/imas/nats/"+key {
			t.Errorf("IMAS_NATS_%s_SEED_FILE = %q", name, got)
		}
	}
	for k := range env {
		if strings.HasSuffix(k, "_SEED") {
			t.Errorf("raw seed env var %s rendered; only _SEED_FILE is allowed", k)
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
	// Only the listed keys are projected (not e.g. saasapi-user.nk).
	if n := len(get(seedVol, "secret", "items").([]any)); n != 5 {
		t.Errorf("seed volume projects %d keys, want 5", n)
	}
}

func TestExtraSeeds(t *testing.T) {
	docs := mustRender(t, "--set", "natsSeeds.extraSeeds.TENANT_T_8F2A=tenant-t-8f2a.nk")
	env := envMap(container(t, find(t, docs, "StatefulSet", "-bus")))
	if env["IMAS_NATS_TENANT_T_8F2A_SEED_FILE"] != "/var/run/secrets/imas/nats/tenant-t-8f2a.nk" {
		t.Errorf("extra seed not wired: %v", env)
	}
}

func TestValidationFailures(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		{"no seed secret", "natsSeeds.secretName is required", []string{"--set", "natsSeeds.secretName="}},
		{"missing operator seed", "natsSeeds.seeds.OPERATOR is required", []string{"--set", "natsSeeds.seeds.OPERATOR=null"}},
		{"missing tenant signing seed", "natsSeeds.seeds.TENANT_SIGNING is required", []string{"--set", "natsSeeds.seeds.TENANT_SIGNING="}},
		{"bad seed name", "must match", []string{"--set", "natsSeeds.extraSeeds.bad-name=x.nk"}},
		{"bad tenant id", "not a valid tenant ID", []string{"--set", "bus.organization=imas farmer"}},
		{"unmeshed replicas", "cmd/farmerbus does not configure yet", []string{"--set", "bus.replicaCount=3"}},
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { mustFail(t, tc.want, tc.args...) })
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

func TestClustered(t *testing.T) {
	docs := mustRender(t, "--set", "bus.replicaCount=3", "--set", "bus.cluster.routesSupported=true")
	env := envMap(container(t, find(t, docs, "StatefulSet", "-bus")))
	routes := strings.Split(env["IMAS_BUS_CLUSTER_ROUTES"], ",")
	if len(routes) != 3 || routes[2] != "tls://t-nats-bus-2.t-nats-bus-headless.imas-dmz.svc.cluster.local:6222" {
		t.Errorf("IMAS_BUS_CLUSTER_ROUTES = %v", routes)
	}
	if env["IMAS_BUS_CLUSTER_NAME"] != "imas-bus" || env["IMAS_BUS_CLUSTER_PORT"] != "6222" {
		t.Errorf("cluster env: %v", env)
	}
	if !has(docs, "PodDisruptionBudget", "-bus") {
		t.Error("no bus PDB for a 3-node cluster")
	}
	np := find(t, docs, "NetworkPolicy", "-bus")
	if !slices.Contains(policyPorts(np, "ingress"), 6222) || !slices.Contains(policyPorts(np, "egress"), 6222) {
		t.Error("bus NetworkPolicy missing bus<->bus cluster port")
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
// bus has no egress except DNS.
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
	if got := policyPorts(bus, "egress"); !slices.Equal(got, []int{53, 53}) {
		t.Errorf("bus egress ports = %v, want DNS only", got)
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
	if got := policyPorts(find(t, docs, "NetworkPolicy", "-bus"), "egress"); !slices.Equal(got, []int{53, 53, 8200}) {
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
	if gated != 2 {
		t.Errorf("gated routes = %d, want 2 (/files/ and /)", gated)
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
