// Package dmzhub tests the UAT.3a DMZ hub scripts without a cluster:
//
//   - install.sh --render-only, against deploy/helm/nats packaged the way
//     the release packages it, with assertions on the Envoy certificate,
//     the ports and the farmer upstream in the render;
//   - install.sh's argument and endpoints checks;
//   - check.sh, with the real curl and openssl, against a fake Envoy that
//     answers the way deploy/envoy/envoy.yaml documents, and against fakes
//     that get one thing wrong.
//
// The tests skip when bash, jq, helm, curl or OpenSSL 3 are missing. With
// IMAS_REQUIRE_HELM=1 (set by .github/workflows/ci.yml) a missing helm, bash
// or jq fails the render tests instead, as in the chart tests.
package dmzhub

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type obj = map[string]any

const (
	testTag     = "v0.1.0-rc.4"
	testVersion = "0.1.0-rc.4"
)

func dir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate uat/hub/dmz")
	}
	return filepath.Dir(file)
}

// need skips (or, with IMAS_REQUIRE_HELM=1 and required set, fails) when a
// tool is missing.
func need(t *testing.T, required bool, tools ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash scripts; not run on Windows")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			if required && os.Getenv("IMAS_REQUIRE_HELM") == "1" {
				t.Fatalf("%s not on PATH (IMAS_REQUIRE_HELM=1: these tests must run, not skip)", tool)
			}
			t.Skipf("%s not on PATH", tool)
		}
	}
}

// packageChart packages deploy/helm/nats as publish-packages.yml does
// (chart version and appVersion both set to the release version).
func packageChart(t *testing.T, version, appVersion string) string {
	t.Helper()
	out := t.TempDir()
	cmd := exec.Command("helm", "package", filepath.Join(dir(t), "..", "..", "..", "deploy", "helm", "nats"),
		"--version", version, "--app-version", appVersion, "--destination", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helm package: %v\n%s", err, b)
	}
	return filepath.Join(out, "nats-"+version+".tgz")
}

// run runs a script of this directory with bash and returns its exit
// code, stdout and stderr.
func run(t *testing.T, env []string, script string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(dir(t), script)}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running %s: %v", script, err)
		}
		code = ee.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

func parseDocs(t *testing.T, path string) []obj {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	var docs []obj
	for {
		var d obj
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("parsing %s: %v", path, err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func find(t *testing.T, docs []obj, kind, name string) obj {
	t.Helper()
	for _, d := range docs {
		if d["kind"] == kind && get(d, "metadata", "name") == name {
			return d
		}
	}
	t.Fatalf("no %s %s rendered", kind, name)
	return nil
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

func strs(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, e := range l {
		out = append(out, fmt.Sprint(e))
	}
	return out
}

// byName returns the element of a list of maps whose "name" is name.
func byName(v any, name string) obj {
	l, _ := v.([]any)
	for _, e := range l {
		if m, ok := e.(obj); ok && m["name"] == name {
			return m
		}
	}
	return nil
}

type rendered struct {
	chart, manifests []obj
	outputs          obj
	envoy            obj // the Envoy config, parsed from its ConfigMap
}

// render runs install.sh --render-only and parses what it wrote.
func render(t *testing.T, endpoints string, extra ...string) rendered {
	t.Helper()
	need(t, true, "bash", "jq", "helm")
	tgz := packageChart(t, testVersion, testVersion)
	work := t.TempDir()
	if !filepath.IsAbs(endpoints) {
		endpoints = filepath.Join(dir(t), "testdata", endpoints)
	}
	args := append([]string{"--render-only", "--chart", tgz, "--release-tag", testTag,
		"--endpoints", endpoints, "--workdir", work}, extra...)
	if code, _, stderr := run(t, nil, "install.sh", args...); code != 0 {
		t.Fatalf("install.sh --render-only exited %d:\n%s", code, stderr)
	}
	var r rendered
	r.chart = parseDocs(t, filepath.Join(work, "rendered.yaml"))
	r.manifests = parseDocs(t, filepath.Join(work, "manifests.yaml"))
	b, err := os.ReadFile(filepath.Join(work, "dmz.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r.outputs); err != nil {
		t.Fatal(err)
	}
	cfg := get(find(t, r.chart, "ConfigMap", "imas-dmz-nats-envoy"), "data", "envoy.yaml").(string)
	if err := yaml.Unmarshal([]byte(cfg), &r.envoy); err != nil {
		t.Fatalf("parsing the rendered envoy.yaml: %v", err)
	}
	// helm lint, with the same two values files install.sh passes.
	values := filepath.Join(work, "values-run.yaml")
	cmd := exec.Command("helm", "lint", tgz, "--namespace", "imas-dmz", "--kube-version", "1.30.0",
		"-f", filepath.Join(dir(t), "values-uat.yaml"), "-f", values)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helm lint with the UAT values: %v\n%s", err, b)
	}
	return r
}

// envoyCluster returns the one endpoint address and port of an Envoy
// cluster, and its SNI.
func envoyCluster(t *testing.T, envoy obj, name string) (string, int, string) {
	t.Helper()
	c := byName(get(envoy, "static_resources", "clusters"), name)
	if c == nil {
		t.Fatalf("no Envoy cluster %s", name)
	}
	sa := get(c, "load_assignment", "endpoints", 0, "lb_endpoints", 0, "endpoint", "address", "socket_address")
	port, _ := get(sa, "port_value").(int)
	sni, _ := get(c, "transport_socket", "typed_config", "sni").(string)
	return fmt.Sprint(get(sa, "address")), port, sni
}

// matches reports whether selector is a subset of labels.
func matches(selector, labels any) bool {
	s, _ := selector.(obj)
	l, _ := labels.(obj)
	if len(s) == 0 {
		return false
	}
	for k, v := range s {
		if l[k] != v {
			return false
		}
	}
	return true
}

func containerPort(t *testing.T, workload obj, container, port string) int {
	t.Helper()
	c := byName(get(workload, "spec", "template", "spec", "containers"), container)
	p := byName(get(c, "ports"), port)
	if p == nil {
		t.Fatalf("%s has no port named %s", container, port)
	}
	return p["containerPort"].(int)
}

type want struct {
	dmzFQDN, dmzIP, coreIP, issuer string
	zone                           string // private DNS zone; empty: uat.imas.internal
	envoyPort, busPort, farmerPort int
	expose                         string
}

func checkRender(t *testing.T, r rendered, w want) {
	t.Helper()
	if w.zone == "" {
		w.zone = "uat.imas.internal"
	}
	dmzPrivate, corePrivate := "dmz."+w.zone, "core."+w.zone
	envoy := find(t, r.chart, "Deployment", "imas-dmz-nats-envoy")
	bus := find(t, r.chart, "StatefulSet", "imas-dmz-nats-bus")

	// Replicas of one, small requests, the release's image.
	for _, wl := range []obj{envoy, bus} {
		if n := get(wl, "spec", "replicas"); n != 1 {
			t.Errorf("%s replicas = %v, want 1", get(wl, "metadata", "name"), n)
		}
		res := get(wl, "spec", "template", "spec", "containers", 0, "resources")
		if get(res, "requests", "cpu") != "50m" || get(res, "requests", "memory") != "64Mi" || get(res, "limits", "memory") != "256Mi" {
			t.Errorf("%s resources = %v, want 50m/64Mi requests, 256Mi limit", get(wl, "metadata", "name"), res)
		}
	}
	if img := get(bus, "spec", "template", "spec", "containers", 0, "image"); img != "ghcr.io/yogzblr/imas-farmerbus:"+testVersion {
		t.Errorf("farmerbus image %v, want ghcr.io/yogzblr/imas-farmerbus:%s", img, testVersion)
	}
	for _, d := range r.chart {
		b, _ := yaml.Marshal(d)
		if regexp.MustCompile(`image: \S+:latest\b`).Match(b) {
			t.Errorf("%s %v pulls a :latest image", d["kind"], get(d, "metadata", "name"))
		}
	}
	if s := get(byName(get(bus, "spec", "template", "spec", "volumes"), "tls"), "secret", "secretName"); s != "imas-farmerbus-tls" {
		t.Errorf("bus TLS Secret %v, want imas-farmerbus-tls", s)
	}

	// The Envoy downstream certificate: the Secret the Deployment mounts
	// is the one the Certificate for the DMZ FQDN writes.
	if s := get(byName(get(envoy, "spec", "template", "spec", "volumes"), "tls"), "secret", "secretName"); s != "imas-envoy-dmz-tls" {
		t.Errorf("Envoy TLS Secret %v, want imas-envoy-dmz-tls", s)
	}
	edge := find(t, r.manifests, "Certificate", "imas-envoy-dmz-tls")
	if get(edge, "spec", "secretName") != "imas-envoy-dmz-tls" {
		t.Errorf("edge Certificate writes %v", get(edge, "spec", "secretName"))
	}
	// The private name sprouts use, and the public FQDN the runner checks.
	if got := strs(get(edge, "spec", "dnsNames")); !slices.Equal(got, []string{dmzPrivate, w.dmzFQDN}) {
		t.Errorf("edge Certificate dnsNames %v, want [%s %s]", got, dmzPrivate, w.dmzFQDN)
	}
	for _, c := range []obj{edge, find(t, r.manifests, "Certificate", "imas-farmerbus-tls")} {
		if ref := get(c, "spec", "issuerRef"); get(ref, "kind") != "ClusterIssuer" || get(ref, "name") != w.issuer {
			t.Errorf("%v issuerRef %v, want ClusterIssuer %s", get(c, "metadata", "name"), ref, w.issuer)
		}
	}
	busCert := find(t, r.manifests, "Certificate", "imas-farmerbus-tls")
	busFQDN := "imas-dmz-nats-bus.imas-dmz.svc.cluster.local"
	// The Service name Envoy dials and the private name farmer dials.
	if names := strs(get(busCert, "spec", "dnsNames")); !slices.Contains(names, busFQDN) || !slices.Contains(names, dmzPrivate) || slices.Contains(names, w.dmzFQDN) {
		t.Errorf("bus Certificate dnsNames %v: want %s and %s, not the public %s", names, busFQDN, dmzPrivate, w.dmzFQDN)
	}
	if ips := strs(get(busCert, "spec", "ipAddresses")); !slices.Equal(ips, []string{w.dmzIP}) {
		t.Errorf("bus Certificate ipAddresses %v, want [%s]", ips, w.dmzIP)
	}
	if u := strs(get(busCert, "spec", "usages")); !slices.Contains(u, "server auth") || !slices.Contains(u, "client auth") {
		t.Errorf("bus Certificate usages %v", u)
	}

	// The Envoy listener and its certificate files.
	l := get(r.envoy, "static_resources", "listeners", 0)
	if p := get(l, "address", "socket_address", "port_value"); p != 8443 {
		t.Errorf("Envoy listener port %v, want 8443", p)
	}
	tc := get(l, "filter_chains", 0, "transport_socket", "typed_config", "common_tls_context", "tls_certificates", 0)
	if get(tc, "certificate_chain", "filename") != "/etc/envoy/tls/tls.crt" || get(tc, "private_key", "filename") != "/etc/envoy/tls/tls.key" {
		t.Errorf("Envoy listener certificate %v", tc)
	}
	if p := containerPort(t, envoy, "envoy", "https"); p != 8443 {
		t.Errorf("Envoy container port %d, want 8443", p)
	}

	// Upstreams: farmer on the core private IP and its API port.
	for _, name := range []string{"farmer_api", "recipe_service"} {
		addr, port, sni := envoyCluster(t, r.envoy, name)
		if addr != w.coreIP || port != w.farmerPort || sni != corePrivate {
			t.Errorf("Envoy cluster %s = %s:%d sni %q, want %s:%d sni %q", name, addr, port, sni, w.coreIP, w.farmerPort, corePrivate)
		}
	}
	if addr, port, _ := envoyCluster(t, r.envoy, "nats_websocket"); addr != busFQDN || port != 5407 {
		t.Errorf("nats_websocket upstream %s:%d, want %s:5407", addr, port, busFQDN)
	}
	b, _ := yaml.Marshal(r.envoy)
	if jwks := fmt.Sprintf("https://%s:%d/v1/.well-known/jwks.json", w.coreIP, w.farmerPort); !bytes.Contains(b, []byte(jwks)) {
		t.Errorf("Envoy config does not fetch the JWKS from %s", jwks)
	}

	// Bus settings the farmer chart expects.
	var busCfg obj
	if err := yaml.Unmarshal([]byte(get(find(t, r.chart, "ConfigMap", "imas-dmz-nats-bus"), "data", "farmer").(string)), &busCfg); err != nil {
		t.Fatal(err)
	}
	if busCfg["farmerorganization"] != "imas" || busCfg["farmerbusport"] != "5406" || busCfg["farmerwsport"] != "5407" {
		t.Errorf("bus config %v: want organization imas, client port 5406, websocket 5407", busCfg)
	}
	busSvc := find(t, r.chart, "Service", "imas-dmz-nats-bus")
	if p := byName(get(busSvc, "spec", "ports"), "client"); p == nil || p["port"] != 5406 {
		t.Errorf("bus client Service port %v, want 5406 (the farmer chart's bus.port)", p)
	}

	// NetworkPolicy: Envoy may reach the core private IP on the API port.
	np := find(t, r.chart, "NetworkPolicy", "imas-dmz-nats-envoy")
	found := false
	for _, e := range get(np, "spec", "egress").([]any) {
		if get(e, "to", 0, "ipBlock", "cidr") == w.coreIP+"/32" && get(e, "ports", 0, "port") == w.farmerPort {
			found = true
		}
	}
	if !found {
		t.Errorf("Envoy NetworkPolicy has no egress to %s/32:%d", w.coreIP, w.farmerPort)
	}
	coreRule := find(t, r.manifests, "NetworkPolicy", "imas-dmz-nats-bus-uat-core")
	if !matches(get(coreRule, "spec", "podSelector", "matchLabels"), get(bus, "spec", "template", "metadata", "labels")) {
		t.Error("the core-to-bus NetworkPolicy does not select the bus pods")
	}
	if get(coreRule, "spec", "ingress", 0, "from", 0, "ipBlock", "cidr") != w.coreIP+"/32" ||
		get(coreRule, "spec", "ingress", 0, "ports", 0, "port") != containerPort(t, bus, "farmerbus", "client") {
		t.Errorf("core-to-bus rule %v, want %s/32 on the bus client port", get(coreRule, "spec", "ingress"), w.coreIP)
	}

	// Exposure: Envoy and the bus client port on the DMZ address.
	for _, e := range []struct {
		svc, target string
		port        int
		workload    obj
		container   string
	}{
		{"imas-dmz-nats-envoy-edge", "https", w.envoyPort, envoy, "envoy"},
		{"imas-dmz-nats-bus-core", "client", w.busPort, bus, "farmerbus"},
	} {
		s := find(t, r.manifests, "Service", e.svc)
		if !matches(get(s, "spec", "selector"), get(e.workload, "spec", "template", "metadata", "labels")) {
			t.Errorf("Service %s does not select %s's pods", e.svc, get(e.workload, "metadata", "name"))
		}
		p := get(s, "spec", "ports", 0)
		if get(p, "port") != e.port || get(p, "targetPort") != e.target {
			t.Errorf("Service %s port %v, want %d -> %s", e.svc, p, e.port, e.target)
		}
		containerPort(t, e.workload, e.container, e.target)
		if get(s, "spec", "externalTrafficPolicy") != "Local" {
			t.Errorf("Service %s externalTrafficPolicy %v, want Local", e.svc, get(s, "spec", "externalTrafficPolicy"))
		}
		// Envoy is a NodePort on its port, or a LoadBalancer on it with
		// the node port left to Kubernetes; the bus is always a NodePort.
		wantType := "NodePort"
		if e.svc == "imas-dmz-nats-envoy-edge" && w.expose == "loadbalancer" {
			wantType = "LoadBalancer"
		}
		// The node port is pinned in both types: the DMZ range is 8442-8443.
		if get(s, "spec", "type") != wantType || get(p, "nodePort") != e.port {
			t.Errorf("Service %s: type %v nodePort %v, want %s with node port %d", e.svc, get(s, "spec", "type"), get(p, "nodePort"), wantType, e.port)
		}
		if get(s, "spec", "externalIPs") != nil {
			t.Errorf("Service %s has externalIPs", e.svc)
		}
	}
	if get(r.outputs, "envoy", "exposure") != w.expose || get(r.outputs, "envoy", "load_balancer_address") != nil {
		t.Errorf("dmz.json envoy %v, want exposure %s and no load balancer address yet", get(r.outputs, "envoy"), w.expose)
	}

	// What the core side and enrolment read.
	if got := get(r.outputs, "envoy", "sprout_bus_url"); got != fmt.Sprintf("wss://%s:%d/", dmzPrivate, w.envoyPort) ||
		get(r.outputs, "envoy", "host") != dmzPrivate || get(r.outputs, "envoy", "public_host") != w.dmzFQDN {
		t.Errorf("dmz.json envoy %v: want sprouts on %s, the runner on %s", get(r.outputs, "envoy"), dmzPrivate, w.dmzFQDN)
	}
	if get(r.outputs, "bus", "farmerbusurl") != fmt.Sprintf("tls://%s:%d", dmzPrivate, w.busPort) ||
		get(r.outputs, "bus", "tls_server_name") != dmzPrivate || get(r.outputs, "bus", "address") != w.dmzIP ||
		get(r.outputs, "bus", "port") != float64(w.busPort) || get(r.outputs, "bus", "in_cluster", "fqdn") != busFQDN ||
		get(r.outputs, "bus", "in_cluster", "port") != float64(5406) {
		t.Errorf("dmz.json bus %v", get(r.outputs, "bus"))
	}
	if get(r.outputs, "chart_version") != testVersion {
		t.Errorf("dmz.json chart_version %v", get(r.outputs, "chart_version"))
	}
}

func TestRenderEndpoints(t *testing.T) {
	r := render(t, "endpoints.json")
	checkRender(t, r, want{
		dmzFQDN: "uatabc123-dmz.centralindia.cloudapp.azure.com", dmzIP: "10.60.1.4",
		coreIP: "10.60.2.4", issuer: "imas-uat-ca", envoyPort: 8443, busPort: 8442, farmerPort: 5405, expose: "nodeport",
	})
}

// --expose loadbalancer: Envoy behind a LoadBalancer Service on 8443, the
// bus still a NodePort for core.
func TestRenderLoadBalancer(t *testing.T) {
	r := render(t, "endpoints.json", "--expose", "loadbalancer")
	checkRender(t, r, want{
		dmzFQDN: "uatabc123-dmz.centralindia.cloudapp.azure.com", dmzIP: "10.60.1.4",
		coreIP: "10.60.2.4", issuer: "imas-uat-ca", envoyPort: 8443, busPort: 8442, farmerPort: 5405, expose: "loadbalancer",
	})
}

// UAT.2's endpoints file (PR #130) names the bus port bus_client.
func TestRenderUAT2Endpoints(t *testing.T) {
	r := render(t, "endpoints-uat2.json")
	checkRender(t, r, want{
		dmzFQDN: "uatab12cd34-dmz.centralindia.cloudapp.azure.com", dmzIP: "10.60.1.4",
		coreIP: "10.60.2.4", issuer: "imas-uat-ca", envoyPort: 8443, busPort: 8442, farmerPort: 5405, expose: "nodeport",
	})
}

// A tofu "uat" JSON with no ports and no issuer is a valid endpoints file:
// the chart README ports and the default issuer name apply.
func TestRenderTofuOutputDefaults(t *testing.T) {
	r := render(t, "tofu-uat.json")
	checkRender(t, r, want{
		dmzFQDN: "uatabc123-dmz.centralindia.cloudapp.azure.com", dmzIP: "10.60.1.4",
		coreIP: "10.60.2.4", issuer: "imas-uat-ca", envoyPort: 8443, busPort: 8442, farmerPort: 5405, expose: "nodeport",
	})
}

// Non-default ports flow from the endpoints file into the upstream, the
// policy and the exposure; NodePort mode pins the node ports.
func TestRenderNodePortAndPorts(t *testing.T) {
	r := render(t, "endpoints-nodeport.json", "--expose", "nodeport")
	checkRender(t, r, want{
		dmzFQDN: "dmz.uat.test", dmzIP: "172.18.0.3", coreIP: "172.18.0.4", zone: "rig.internal", issuer: "uat-root", envoyPort: 30443, busPort: 30406, farmerPort: 30405, expose: "nodeport",
	})
}

func writeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "endpoints.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func endpointsWith(mut func(obj)) obj {
	e := obj{
		"dmz":  obj{"private_ip": "10.60.1.4", "fqdn": "dmz.uat.test"},
		"core": obj{"private_ip": "10.60.2.4", "fqdn": "core.uat.test"},
	}
	if mut != nil {
		mut(e)
	}
	return e
}

func TestInstallRefuses(t *testing.T) {
	need(t, true, "bash", "jq", "helm")
	good := filepath.Join(dir(t), "testdata", "endpoints.json")
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc3 := packageChart(t, "0.1.0-rc.3", "0.1.0-rc.3")
	mixed := packageChart(t, testVersion, "0.1.0-rc.3")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no endpoints", []string{"--render-only", "--release-tag", testTag}, "--endpoints is required"},
		{"no tag", []string{"--render-only", "--endpoints", good}, "--release-tag is required"},
		{"latest", []string{"--render-only", "--endpoints", good, "--release-tag", "latest"}, "is not vX.Y.Z"},
		{"no v", []string{"--render-only", "--endpoints", good, "--release-tag", "0.1.0"}, "is not vX.Y.Z"},
		{"short", []string{"--render-only", "--endpoints", good, "--release-tag", "v0.1"}, "is not vX.Y.Z"},
		{"beta", []string{"--render-only", "--endpoints", good, "--release-tag", "v0.1.0-beta.1"}, "is not vX.Y.Z"},
		{"leading zero", []string{"--render-only", "--endpoints", good, "--release-tag", "v01.0.0"}, "is not vX.Y.Z"},
		{"bad expose", []string{"--render-only", "--endpoints", good, "--release-tag", testTag, "--expose", "externalip"}, "--expose must be nodeport or loadbalancer"},
		{"bad timeout", []string{"--kubeconfig", kubeconfig, "--endpoints", good, "--release-tag", testTag, "--timeout", "ten"}, "is not a duration"},
		{"no kubeconfig", []string{"--endpoints", good, "--release-tag", testTag}, "--kubeconfig is required"},
		{"local chart on install", []string{"--kubeconfig", kubeconfig, "--endpoints", good, "--release-tag", testTag, "--chart", rc3}, "--chart is only for --render-only"},
		{"render with kubeconfig", []string{"--render-only", "--kubeconfig", kubeconfig, "--endpoints", good, "--release-tag", testTag}, "touches no cluster"},
		{"two seed sources", []string{"--kubeconfig", kubeconfig, "--endpoints", good, "--release-tag", testTag, "--seeds-dir", "/x", "--seeds-from-kubeconfig", kubeconfig}, "not both"},
		{"unknown flag", []string{"--render-only", "--endpoints", good, "--release-tag", testTag, "--wait"}, "unknown argument"},
		{"dangling flag", []string{"--render-only", "--endpoints"}, "needs a value"},
		{"chart version", []string{"--render-only", "--chart", rc3, "--endpoints", good, "--release-tag", testTag}, "chart version is '0.1.0-rc.3', want 0.1.0-rc.4"},
		{"app version", []string{"--render-only", "--chart", mixed, "--endpoints", good, "--release-tag", testTag}, "appVersion is '0.1.0-rc.3', want 0.1.0-rc.4"},
		{"missing endpoints file", []string{"--render-only", "--endpoints", "/nonexistent.json", "--release-tag", testTag}, "is not readable"},
		{"no core", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { delete(e, "core") }))}, "with dmz and core objects"},
		{"bad core ip", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["core"].(obj)["private_ip"] = "10.60.2.400" }))}, "core.private_ip"},
		{"bad fqdn", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["dmz"].(obj)["fqdn"] = "dmz_host" }))}, "dmz.fqdn"},
		{"bad port", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["core"].(obj)["ports"] = obj{"farmer_api": 70000} }))}, "core.ports.farmer_api"},
		{"same ports", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["dmz"].(obj)["ports"] = obj{"envoy": 8442} }))}, "are both 8442"},
		{"bad zone", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["private_dns_zone"] = "uat imas" }))}, "private_dns_zone"},
		{"bad service type", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["dmz"].(obj)["envoy_service_type"] = "ClusterIP" }))}, "dmz.envoy_service_type"},
		{"bad issuer", []string{"--render-only", "--release-tag", testTag, "--endpoints", writeJSON(t, endpointsWith(func(e obj) { e["cluster_issuer"] = "UAT CA" }))}, "cluster_issuer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := run(t, nil, "install.sh", c.args...)
			if code == 0 || !strings.Contains(stderr, c.want) {
				t.Errorf("exit %d, stderr:\n%s\nwant a failure mentioning %q", code, stderr, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// check.sh against a fake Envoy.

type pki struct {
	caFile string
	cert   tls.Certificate
}

func newPKI(t *testing.T, host string, more ...string) pki {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "imas UAT test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: append([]string{host}, more...),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "uat-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return pki{caFile: caFile, cert: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}}
}

// fakeEnvoy answers like deploy/envoy/envoy.yaml with farmer behind it:
// jwt_authn refuses /files/, /v1/sprout/update-manifest and / with a 401
// and Envoy's reason; /v1/enroll and /v1/refresh pass to farmer, which
// answers an empty request 401 enrollment_failed; /v1/enroll has a bucket
// of 20 refilled every fill, /v1/refresh one of its own. Each fault breaks
// one of these.
type fakeEnvoy struct {
	fill   time.Duration
	faults map[string]bool

	mu            sync.Mutex
	enrollTokens  int
	refreshTokens int
	started       bool
	dryAt         time.Time // when the enroll bucket ran dry; zero while it has tokens
}

func (f *fakeEnvoy) take(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Envoy refills on a timer. The fake refills fill after the bucket ran
	// dry instead, so a slow machine cannot top it up in the middle of
	// check.sh's burst and turn the test flaky.
	if !f.started || (!f.dryAt.IsZero() && time.Since(f.dryAt) >= f.fill) {
		f.enrollTokens, f.refreshTokens, f.dryAt, f.started = 20, 300, time.Time{}, true
	}
	tokens := &f.enrollTokens
	if path == "/v1/refresh" && !f.faults["shared bucket"] {
		tokens = &f.refreshTokens
	}
	if f.faults["no rate limit"] && path == "/v1/enroll" {
		return true
	}
	if *tokens == 0 {
		return false
	}
	*tokens--
	if f.enrollTokens == 0 && f.dryAt.IsZero() {
		f.dryAt = time.Now()
	}
	return true
}

func (f *fakeEnvoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/enroll" || r.URL.Path == "/v1/refresh":
		if !f.take(r.URL.Path) {
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, "local_rate_limited")
			return
		}
		if f.faults["farmer down"] {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "no healthy upstream")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"enrollment_failed"}`+"\n")
	case strings.HasPrefix(r.URL.Path, "/files/") && f.faults["files open"]:
		io.WriteString(w, "recipe")
	default:
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "Jwt is missing")
			return
		}
		if f.faults["forged accepted"] {
			if r.Header.Get("Upgrade") != "" {
				w.WriteHeader(http.StatusSwitchingProtocols)
				return
			}
			io.WriteString(w, "accepted")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Jwt verification fails")
	}
}

var opensslThree = sync.OnceValue(func() bool {
	out, err := exec.Command("openssl", "version").Output()
	return err == nil && bytes.HasPrefix(out, []byte("OpenSSL 3"))
})

// runCheck starts a fake Envoy for host with the given faults and runs
// check.sh against it. caFile overrides the CA check.sh is given.
func runCheck(t *testing.T, host string, certHosts []string, faults []string, caFile string, args ...string) (int, string) {
	t.Helper()
	need(t, false, "bash", "jq", "curl", "openssl", "timeout")
	if !opensslThree() {
		t.Skip("OpenSSL 3 not on PATH")
	}
	p := newPKI(t, certHosts[0], certHosts[1:]...)
	f := &fakeEnvoy{fill: 2 * time.Second, faults: map[string]bool{}}
	for _, x := range faults {
		f.faults[x] = true
	}
	srv := httptest.NewUnstartedServer(f)
	// Clients that reject the certificate abort the handshake on purpose.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.cert}, NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var portNum int
	fmt.Sscan(port, &portNum)
	ep := writeJSON(t, obj{
		"dmz":  obj{"private_ip": "10.60.1.4", "public_ip": "127.0.0.1", "fqdn": host, "ports": obj{"envoy": portNum}},
		"core": obj{"private_ip": "10.60.2.4", "fqdn": "core.uat.test"},
	})
	if caFile == "" {
		caFile = p.caFile
	}
	code, stdout, stderr := run(t, nil, "check.sh", append([]string{"--endpoints", ep, "--ca-file", caFile}, args...)...)
	t.Logf("check.sh exit %d\n%s%s", code, stdout, stderr)
	return code, stdout
}

func TestCheckPassesAgainstEnvoyBehaviour(t *testing.T) {
	code, out := runCheck(t, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, nil, "", "--refill-wait", "6")
	if code != 0 {
		t.Fatalf("check.sh failed against a correct fake Envoy:\n%s", out)
	}
	for i := 1; i <= 12; i++ {
		if !regexp.MustCompile(fmt.Sprintf(`(?m)^PASS D%d `, i)).MatchString(out) {
			t.Errorf("D%d did not pass", i)
		}
	}
}

func TestCheckCatchesFaults(t *testing.T) {
	other := newPKI(t, "dmz.uat.test")
	cases := []struct {
		name, caFile string
		certHosts    []string
		faults       []string
		wantFail     []string
	}{
		{name: "files route open", faults: []string{"files open"}, wantFail: []string{"D3", "D4"}},
		{name: "forged token accepted", faults: []string{"forged accepted"}, wantFail: []string{"D4", "D6"}},
		{name: "enroll not rate limited", faults: []string{"no rate limit"}, wantFail: []string{"D9"}},
		{name: "farmer unreachable", faults: []string{"farmer down"}, wantFail: []string{"D8", "D10"}},
		{name: "refresh shares the enroll bucket", faults: []string{"shared bucket"}, wantFail: []string{"D10"}},
		{name: "another CA", caFile: other.caFile, wantFail: []string{"D1"}},
		{name: "certificate for another name", certHosts: []string{"other.uat.test", "dmz.uat.imas.internal"}, wantFail: []string{"D1"}},
		{name: "certificate without the private name", certHosts: []string{"dmz.uat.test"}, wantFail: []string{"D12"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			certHosts := c.certHosts
			if certHosts == nil {
				certHosts = []string{"dmz.uat.test", "dmz.uat.imas.internal"}
			}
			code, out := runCheck(t, "dmz.uat.test", certHosts, c.faults, c.caFile, "--refill-wait", "0")
			if code == 0 {
				t.Fatalf("check.sh passed against a fake with %q", c.name)
			}
			for _, id := range c.wantFail {
				if !regexp.MustCompile(fmt.Sprintf(`(?m)^FAIL %s `, id)).MatchString(out) {
					t.Errorf("want FAIL %s", id)
				}
			}
		})
	}
}

func TestCheckRefuses(t *testing.T) {
	need(t, false, "bash", "jq", "curl", "openssl", "timeout")
	ep := filepath.Join(dir(t), "testdata", "endpoints.json")
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no endpoints", []string{"--ca-file", notPEM}, "--endpoints is required"},
		{"no CA", []string{"--endpoints", ep}, "--ca-file is required"},
		{"CA not PEM", []string{"--endpoints", ep, "--ca-file", notPEM}, "not a PEM certificate"},
		{"bad refill wait", []string{"--endpoints", ep, "--ca-file", notPEM, "--refill-wait", "1m"}, "--refill-wait"},
		{"bad burst", []string{"--endpoints", ep, "--ca-file", notPEM, "--max-burst", "0"}, "--max-burst"},
		{"bad connect", []string{"--endpoints", ep, "--ca-file", newPKI(t, "dmz.uat.test").caFile, "--connect", "not an address"}, "--connect 'not an address' is not"},
		{"unknown flag", []string{"--insecure"}, "unknown argument"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := run(t, nil, "check.sh", c.args...)
			if code == 0 || !strings.Contains(stderr, c.want) {
				t.Errorf("exit %d, stderr:\n%s\nwant a failure mentioning %q", code, stderr, c.want)
			}
		})
	}
}

// TestLint runs shellcheck on the scripts and yamllint on the values file
// and on what install.sh generates, in both exposure modes. Each linter is
// skipped when it is not installed.
func TestLint(t *testing.T) {
	need(t, false, "bash")
	t.Run("shellcheck", func(t *testing.T) {
		need(t, false, "shellcheck")
		cmd := exec.Command("shellcheck", "-x", "install.sh", "check.sh", "lib.sh")
		cmd.Dir = dir(t)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("shellcheck: %v\n%s", err, b)
		}
	})
	t.Run("yamllint", func(t *testing.T) {
		need(t, false, "yamllint", "jq", "helm")
		tgz := packageChart(t, testVersion, testVersion)
		files := []string{filepath.Join(dir(t), "values-uat.yaml")}
		for _, c := range []struct{ endpoints, expose string }{
			{"endpoints.json", "loadbalancer"}, {"endpoints-nodeport.json", "nodeport"},
		} {
			work := t.TempDir()
			if code, _, stderr := run(t, nil, "install.sh", "--render-only", "--chart", tgz, "--release-tag", testTag,
				"--endpoints", filepath.Join(dir(t), "testdata", c.endpoints), "--expose", c.expose, "--workdir", work); code != 0 {
				t.Fatalf("install.sh --render-only: %s", stderr)
			}
			files = append(files, filepath.Join(work, "values-run.yaml"), filepath.Join(work, "manifests.yaml"))
		}
		if b, err := exec.Command("yamllint", append([]string{"-s"}, files...)...).CombinedOutput(); err != nil {
			t.Errorf("yamllint: %v\n%s", err, b)
		}
	})
}

// Stub kubectl and helm for TestInstallWithStubs: each logs its argv, one
// line per call. kubectl answers the few reads install.sh makes; helm
// hands show, template and lint to the real helm and "pulls" STUB_CHART.
const stubKubectl = `#!/usr/bin/env bash
printf 'kubectl %s\n' "$*" >>"$STUB_LOG"
args="$*"
case $args in
*"get secret imas-farmer-nats-seeds -o jsonpath={.data."*)
	key=${args##*jsonpath=\{.data.}
	key=${key%\}}
	key=${key//\\/}
	printf 'copied %s\n' "$key" >>"$STUB_LOG"
	printf 'SAAUATSTUBSEED%s\n' "$(printf '%s' "$key" | tr -dc 'a-z' | tr 'a-z' 'A-Z' | head -c 20)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | base64 -w0
	;;
*"get secret imas-farmerbus-tls -o jsonpath={.data.ca"*) printf 'LS0tLS1CRUdJTg==' ;;
*"get service imas-dmz-nats-envoy-edge -o jsonpath={.status.loadBalancer"*) printf '%s' "${STUB_LB:-}" ;;
*"get endpointslices"*) printf '10.244.0.7' ;;
*"create secret generic"*)
	for a in "$@"; do
		case $a in --from-file=*) f=${a#*=}; f=${f#*=}; printf 'seedfile %s %s\n' "${a%%=/*}" "$(cat "$f")" >>"$STUB_LOG" ;; esac
	done
	printf 'apiVersion: v1\nkind: Secret\n'
	;;
*"apply -f -"*) cat >/dev/null ;;
*"create namespace"*) printf 'apiVersion: v1\nkind: Namespace\n' ;;
esac
exit 0
`

const stubHelm = `#!/usr/bin/env bash
printf 'helm %s\n' "$*" >>"$STUB_LOG"
case $1 in
repo)
	stdin=$(cat)
	printf 'helm-stdin %s\n' "$stdin" >>"$STUB_LOG"
	;;
pull)
	while (($#)); do
		if [[ $1 == --destination ]]; then cp "$STUB_CHART" "$2/"; fi
		shift
	done
	;;
show | template | lint) exec "$REAL_HELM" "$@" ;;
esac
exit 0
`

func TestInstallWithStubs(t *testing.T) {
	need(t, true, "bash", "jq", "helm", "base64")
	realHelm, _ := exec.LookPath("helm")
	bin := t.TempDir()
	for name, body := range map[string]string{"kubectl": stubKubectl, "helm": stubHelm} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tgz := packageChart(t, testVersion, testVersion)
	kubeconfig := filepath.Join(t.TempDir(), "dmz.kubeconfig")
	coreKubeconfig := filepath.Join(t.TempDir(), "core.kubeconfig")
	for _, f := range []string{kubeconfig, coreKubeconfig} {
		if err := os.WriteFile(f, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const token = "bkua_uat_stub_unused_value"
	logFile := filepath.Join(t.TempDir(), "calls.log")
	work := t.TempDir()
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_LOG=" + logFile, "STUB_CHART=" + tgz, "REAL_HELM=" + realHelm,
		"IMAS_HELM_REGISTRY_TOKEN=" + token, "BUILDKITE_ORGANIZATION_SLUG=example-org",
	}
	code, _, stderr := run(t, env, "install.sh", "--kubeconfig", kubeconfig,
		"--endpoints", filepath.Join(dir(t), "testdata", "endpoints.json"), "--release-tag", testTag,
		"--seeds-from-kubeconfig", coreKubeconfig, "--workdir", work)
	if code != 0 {
		t.Fatalf("install.sh exited %d:\n%s", code, stderr)
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(b)), "\n")
	logText := string(b)

	// imashelm is public (owner's decision): no credential goes anywhere,
	// even with a token in the environment.
	if strings.Contains(logText, token) || strings.Contains(logText, "--password") || strings.Contains(logText, "--username") {
		t.Errorf("a registry credential was passed to helm:\n%s", logText)
	}
	if !regexp.MustCompile(`(?m)^helm repo add --force-update imas-uat-imashelm https://packages\.buildkite\.com/example-org/imashelm/helm$`).MatchString(logText) {
		t.Errorf("unexpected helm repo add:\n%s", logText)
	}
	if !regexp.MustCompile(`(?m)^helm pull imas-uat-imashelm/nats --version 0\.1\.0-rc\.4 --destination \S+$`).MatchString(logText) {
		t.Errorf("no exact-version helm pull:\n%s", logText)
	}
	if strings.Contains(logText, "--devel") {
		t.Error("helm was called with --devel")
	}

	// Only the five bus seeds are copied from core, and exactly what core holds.
	var copied []string
	for _, c := range calls {
		if k, ok := strings.CutPrefix(c, "copied "); ok {
			copied = append(copied, k)
		}
	}
	if want := []string{"operator.nk", "operator-signing.nk", "sys-account.nk", "tenant.nk", "tenant-signing.nk"}; !slices.Equal(copied, want) {
		t.Errorf("copied seeds %v, want %v", copied, want)
	}
	if strings.Contains(logText, "saasapi-user") {
		t.Error("saasapi-user.nk was read for the DMZ")
	}
	if n := strings.Count(logText, "seedfile --from-file=operator.nk SAAUATSTUBSEEDOPERATORNK"); n != 1 {
		t.Errorf("the operator seed reached the DMZ Secret %d times, want once", n)
	}

	// Order: issuer checked, seeds, certificates Ready, then the chart, then
	// the rollouts and the exposure endpoints.
	idx := func(sub string) int {
		for i, c := range calls {
			if strings.Contains(c, sub) {
				return i
			}
		}
		t.Errorf("no call containing %q", sub)
		return -1
	}
	order := []string{
		"get clusterissuer imas-uat-ca",
		"create secret generic imas-farmer-nats-seeds",
		"apply -f " + filepath.Join(work, "manifests.yaml"),
		"wait --for=condition=Ready certificate/imas-envoy-dmz-tls",
		"helm upgrade --install imas-dmz " + filepath.Join(work, "chart", "nats-"+testVersion+".tgz"),
		"rollout status statefulset/imas-dmz-nats-bus",
		"rollout status deployment/imas-dmz-nats-envoy",
		"kubernetes.io/service-name=imas-dmz-nats-envoy-edge",
		"kubernetes.io/service-name=imas-dmz-nats-bus-core",
	}
	for i := 1; i < len(order); i++ {
		if a, b := idx(order[i-1]), idx(order[i]); a >= b {
			t.Errorf("%q (call %d) should come before %q (call %d)", order[i-1], a, order[i], b)
		}
	}
	up := calls[idx("helm upgrade --install")]
	for _, want := range []string{"--namespace imas-dmz", "-f " + filepath.Join(dir(t), "values-uat.yaml") + " -f " + filepath.Join(work, "values-run.yaml"), "--kubeconfig " + kubeconfig} {
		if !strings.Contains(up, want) {
			t.Errorf("helm upgrade lacks %q: %s", want, up)
		}
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "kubectl ") && !strings.HasPrefix(c, "kubectl --kubeconfig "+kubeconfig+" ") &&
			!strings.HasPrefix(c, "kubectl --kubeconfig "+coreKubeconfig+" -n imas-core get secret imas-farmer-nats-seeds ") {
			t.Errorf("kubectl call without the DMZ kubeconfig: %s", c)
		}
	}
	// The temporary Helm home is not left in the work directory.
	if _, err := os.Stat(filepath.Join(work, "helm")); err == nil {
		t.Error("a Helm home was left in the work directory")
	}
	if b, err := os.ReadFile(filepath.Join(work, "dmz.json")); err != nil || !bytes.Contains(b, []byte(`"sprout_bus_url": "wss://dmz.uat.imas.internal:8443/"`)) {
		t.Errorf("dmz.json: %v\n%s", err, b)
	}
}

// --expose loadbalancer waits for the controller's address and records it;
// with no controller it fails, naming the alternative. The seed Secret is
// taken as it is (no seed option).
func TestInstallLoadBalancerWithStubs(t *testing.T) {
	need(t, true, "bash", "jq", "helm", "base64")
	realHelm, _ := exec.LookPath("helm")
	bin := t.TempDir()
	for name, body := range map[string]string{"kubectl": stubKubectl, "helm": stubHelm} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tgz := packageChart(t, testVersion, testVersion)
	kubeconfig := filepath.Join(t.TempDir(), "dmz.kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, lb string
		ok       bool
	}{{"address", "198.51.100.7", true}, {"no controller", "", false}} {
		t.Run(c.name, func(t *testing.T) {
			work := t.TempDir()
			env := []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"STUB_LOG=" + filepath.Join(t.TempDir(), "calls.log"), "STUB_CHART=" + tgz,
				"REAL_HELM=" + realHelm, "STUB_LB=" + c.lb,
			}
			code, _, stderr := run(t, env, "install.sh", "--kubeconfig", kubeconfig, "--expose", "loadbalancer",
				"--endpoints", filepath.Join(dir(t), "testdata", "endpoints.json"), "--release-tag", testTag,
				"--workdir", work, "--timeout", "5s")
			if !c.ok {
				if code == 0 || !strings.Contains(stderr, "got no load balancer address within 5s") {
					t.Fatalf("exit %d, want a failure naming the missing address:\n%s", code, stderr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("install.sh exited %d:\n%s", code, stderr)
			}
			var out obj
			b, err := os.ReadFile(filepath.Join(work, "dmz.json"))
			if err == nil {
				err = json.Unmarshal(b, &out)
			}
			if err != nil || get(out, "envoy", "exposure") != "loadbalancer" || get(out, "envoy", "load_balancer_address") != c.lb {
				t.Errorf("dmz.json envoy %v (%v), want loadbalancer at %s", get(out, "envoy"), err, c.lb)
			}
		})
	}
}

// With no --expose, the endpoints file's dmz.envoy_service_type decides
// (UAT.2's PR #130 writes it); --expose overrides it.
func TestRenderServiceTypeFromEndpoints(t *testing.T) {
	ep := writeJSON(t, obj{
		"dmz":  obj{"private_ip": "10.60.1.4", "fqdn": "dmz.uat.test", "envoy_service_type": "LoadBalancer"},
		"core": obj{"private_ip": "10.60.2.4", "fqdn": "core.uat.test"},
	})
	for _, c := range []struct {
		args []string
		want string
	}{{nil, "LoadBalancer"}, {[]string{"--expose", "nodeport"}, "NodePort"}} {
		r := render(t, ep, c.args...)
		s := find(t, r.manifests, "Service", "imas-dmz-nats-envoy-edge")
		if get(s, "spec", "type") != c.want || get(s, "spec", "ports", 0, "nodePort") != 8443 {
			t.Errorf("%v: Envoy Service %v node port %v, want %s on 8443", c.args, get(s, "spec", "type"), get(s, "spec", "ports", 0, "nodePort"), c.want)
		}
		if b := find(t, r.manifests, "Service", "imas-dmz-nats-bus-core"); get(b, "spec", "type") != "NodePort" || get(b, "spec", "ports", 0, "nodePort") != 8442 {
			t.Errorf("%v: bus Service %v, want NodePort 8442", c.args, get(b, "spec"))
		}
	}
}
