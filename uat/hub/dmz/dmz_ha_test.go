package dmzhub

// The HA DMZ hub (P24, brief H-azure-next-runs.md H4): install.sh with
// uat/k0s's endpoints for 3 + 3 nodes adds values-ha.yaml (a three-node bus
// cluster and three Envoys, spread one per node), names every bus pod on the
// bus certificate, admits core's traffic from every core node and the load
// balancer's probe, makes the fence user's and the route password's
// Secrets; check.sh's enrol burst follows the Envoy count.

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// uat/k0s's endpoints.json for 3 + 3 nodes (its own expected output).
func haEndpoints(t *testing.T) string {
	t.Helper()
	return filepath.Join(dir(t), "..", "..", "k0s", "testdata", "expected", "endpoints-ha.json")
}

func spreadOnePerNode(wl obj) bool {
	l, _ := get(wl, "spec", "template", "spec", "topologySpreadConstraints").([]any)
	for _, c := range l {
		m, _ := c.(obj)
		if m["topologyKey"] == "kubernetes.io/hostname" && m["whenUnsatisfiable"] == "DoNotSchedule" && m["maxSkew"] == 1 {
			return true
		}
	}
	return false
}

func TestRenderHA(t *testing.T) {
	r := render(t, haEndpoints(t))
	bus := find(t, r.chart, "StatefulSet", "imas-dmz-nats-bus")
	envoy := find(t, r.chart, "Deployment", "imas-dmz-nats-envoy")
	for _, wl := range []obj{bus, envoy} {
		name := get(wl, "metadata", "name")
		if n := get(wl, "spec", "replicas"); n != 3 {
			t.Errorf("%s replicas = %v, want 3", name, n)
		}
		if !spreadOnePerNode(wl) {
			t.Errorf("%s is not spread one per node (maxSkew 1, DoNotSchedule)", name)
		}
		find(t, r.chart, "PodDisruptionBudget", name.(string))
	}
	// /v1/enroll's local rate limit on the HA DMZ (W13, ruling out that
	// the HA replicas run without it): the three Envoys are one
	// Deployment, so they share one pod template and its one ConfigMap,
	// whose config carries the local_ratelimit HTTP filter and /v1/enroll's
	// bucket, 20 max, 20 per 60 s, enabled and enforced for every request.
	if cm := get(byName(get(envoy, "spec", "template", "spec", "volumes"), "config"), "configMap", "name"); cm != "imas-dmz-nats-envoy" {
		t.Errorf("the Envoys read their config from ConfigMap %v, want imas-dmz-nats-envoy", cm)
	}
	var filters, buckets int
	walkObjs(r.envoy, func(o obj) {
		if o["name"] == "envoy.filters.http.local_ratelimit" && o["typed_config"] != nil {
			filters++
		}
		if get(o, "match", "prefix") == "/v1/enroll" {
			l := get(o, "typed_per_filter_config", "envoy.filters.http.local_ratelimit")
			b := get(l, "token_bucket")
			if get(l, "stat_prefix") != "enroll_rate_limiter" || get(b, "max_tokens") != 20 || get(b, "tokens_per_fill") != 20 ||
				get(b, "fill_interval") != "60s" || get(l, "filter_enabled", "default_value", "numerator") != 100 ||
				get(l, "filter_enforced", "default_value", "numerator") != 100 {
				t.Errorf("/v1/enroll's rate limit on the HA DMZ: %v", l)
			}
			buckets++
		}
	})
	if filters != 1 || buckets != 1 {
		t.Errorf("the HA Envoy config has %d local_ratelimit HTTP filter(s) and %d /v1/enroll route(s), want 1 and 1", filters, buckets)
	}
	edge := find(t, r.manifests, "Service", "imas-dmz-nats-envoy-edge")
	if get(edge, "spec", "externalTrafficPolicy") != "Local" || get(edge, "spec", "type") != "NodePort" {
		t.Errorf("the Envoy edge Service: type %v, externalTrafficPolicy %v; want NodePort, Local",
			get(edge, "spec", "type"), get(edge, "spec", "externalTrafficPolicy"))
	}

	// The bus keeps no volume: the resolver directory is an emptyDir.
	if get(bus, "spec", "volumeClaimTemplates") != nil {
		t.Error("the bus has volume claim templates")
	}
	for _, d := range r.chart {
		if d["kind"] == "PersistentVolumeClaim" {
			t.Errorf("the DMZ render creates a PVC: %v", get(d, "metadata", "name"))
		}
	}
	if get(byName(get(bus, "spec", "template", "spec", "volumes"), "data"), "emptyDir") == nil {
		t.Error("the bus's resolver directory (volume data) is not an emptyDir")
	}
	// Clustered: the fence user's seed and the route password from the
	// Secrets install.sh makes.
	vols := get(bus, "spec", "template", "spec", "volumes")
	if s := get(byName(vols, "nats-seeds"), "secret", "secretName"); s != "imas-bus-fence-user" {
		t.Errorf("the bus's seeds come from %v, want imas-bus-fence-user", s)
	}
	if s := get(byName(vols, "route-auth"), "secret", "secretName"); s != "imas-bus-route-auth" {
		t.Errorf("the bus's route password comes from %v, want imas-bus-route-auth", s)
	}

	// The bus certificate names every pod (routes verify them) and every
	// DMZ address; mutual TLS needs client auth.
	cert := find(t, r.manifests, "Certificate", "imas-farmerbus-tls")
	names := strs(get(cert, "spec", "dnsNames"))
	for i := 0; i < 3; i++ {
		n := "imas-dmz-nats-bus-" + string(rune('0'+i)) + ".imas-dmz-nats-bus-headless.imas-dmz.svc.cluster.local"
		if !slices.Contains(names, n) {
			t.Errorf("bus certificate lacks %s", n)
		}
	}
	if ips := strs(get(cert, "spec", "ipAddresses")); !slices.Equal(ips, []string{"10.60.1.250", "10.60.1.4", "10.60.1.5", "10.60.1.6"}) {
		t.Errorf("bus certificate IPs %v", ips)
	}
	if !slices.Contains(strs(get(cert, "spec", "usages")), "client auth") {
		t.Error("bus certificate has no client auth (routes are mutual TLS)")
	}

	// Core's traffic arrives from its nodes; the probe keeps every node in
	// the bus's load-balancing rule.
	pol := find(t, r.manifests, "NetworkPolicy", "imas-dmz-nats-bus-uat-core")
	var cidrs []string
	for _, p := range get(pol, "spec", "ingress", 0, "from").([]any) {
		cidrs = append(cidrs, get(p, "ipBlock", "cidr").(string))
	}
	if want := []string{"10.60.2.4/32", "10.60.2.5/32", "10.60.2.6/32", "168.63.129.16/32"}; !slices.Equal(cidrs, want) {
		t.Errorf("bus ingress from %v, want %v", cidrs, want)
	}

	// Envoy reaches farmer, and the loader the accounts store, on the core
	// hub's internal load balancer.
	if host, port, _ := envoyCluster(t, r.envoy, "farmer_api"); host != "10.60.2.250" || port != 5405 {
		t.Errorf("Envoy's farmer_api upstream %s:%d, want 10.60.2.250:5405", host, port)
	}
	busEnv := map[string]string{}
	for _, c := range get(bus, "spec", "template", "spec", "containers").([]any) {
		for _, e := range get(c, "env").([]any) {
			if v, ok := get(e, "value").(string); ok {
				busEnv[get(e, "name").(string)] = v
			}
		}
	}
	if busEnv["IMAS_LOADER_S3_ENDPOINT"] != "10.60.2.250:9000" {
		t.Errorf("the loader reads the accounts bucket at %q, want 10.60.2.250:9000", busEnv["IMAS_LOADER_S3_ENDPOINT"])
	}
	if n := r.outputs["nodes"]; n != float64(3) {
		t.Errorf("dmz.json nodes = %v, want 3", n)
	}
	if a := get(r.outputs, "bus", "address"); a != "10.60.1.250" {
		t.Errorf("dmz.json bus.address = %v, want the internal load balancer's 10.60.1.250", a)
	}
}

// The single-node render is unchanged by the HA work: one node's address,
// no probe source, one pod name on the certificate.
func TestRenderSingleNodeHasNoHAPieces(t *testing.T) {
	r := render(t, "endpoints.json")
	pol := find(t, r.manifests, "NetworkPolicy", "imas-dmz-nats-bus-uat-core")
	from := get(pol, "spec", "ingress", 0, "from").([]any)
	if len(from) != 1 || get(from[0], "ipBlock", "cidr") != "10.60.2.4/32" {
		t.Errorf("single node: bus ingress from %v, want the core node only", from)
	}
	cert := find(t, r.manifests, "Certificate", "imas-farmerbus-tls")
	if ips := strs(get(cert, "spec", "ipAddresses")); !slices.Equal(ips, []string{"10.60.1.4"}) {
		t.Errorf("single node: bus certificate IPs %v", ips)
	}
	for _, n := range strs(get(cert, "spec", "dnsNames")) {
		if strings.Contains(n, "-bus-1.") {
			t.Errorf("single node: bus certificate names %s", n)
		}
	}
}

func TestInstallHAWithStubs(t *testing.T) {
	need(t, true, "bash", "jq", "helm", "base64", "openssl")
	realHelm, _ := exec.LookPath("helm")
	// The fence user's JWT is read from the copied trust ConfigMap.
	kubectl := strings.Replace(stubKubectl, `*"get configmap imas-nats-trust -o json"*)`,
		`*"get configmap imas-nats-trust -o jsonpath={.data.bus-fence-user"*) jq -j '.data["bus-fence-user.jwt"] // empty' "${STUB_TRUST:?}" ;;
*"get configmap imas-nats-trust -o json"*)`, 1)
	bin := t.TempDir()
	for name, body := range map[string]string{"kubectl": kubectl, "helm": stubHelm} {
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
	readerDir := t.TempDir()
	for name, v := range map[string]string{"access-key-id": "imas-bus-accounts-reader", "secret-access-key": "uatreadersecretvalue"} {
		if err := os.WriteFile(filepath.Join(readerDir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seeds := t.TempDir()
	loaderSeed, fenceSeed := filepath.Join(seeds, "loader.nk"), filepath.Join(seeds, "fence.nk")
	for f, v := range map[string]string{
		loaderSeed: "SUAUATSTUBLOADERSEEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
		fenceSeed:  "SUAUATSTUBFENCESEEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
	} {
		if err := os.WriteFile(f, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	trust := makeTrust(t)
	trust["bus-loader-user.jwt"] = trust["sys-account.jwt"]
	install := func(trustFiles map[string]string, extra ...string) (int, string, string, string) {
		logFile := filepath.Join(t.TempDir(), "calls.log")
		work := t.TempDir()
		env := []string{
			"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
			"STUB_LOG=" + logFile, "STUB_CHART=" + tgz, "REAL_HELM=" + realHelm, "STUB_TRUST=" + trustConfigMap(t, trustFiles),
		}
		args := append([]string{"--kubeconfig", kubeconfig, "--endpoints", haEndpoints(t), "--release-tag", testTag,
			"--seeds-from-kubeconfig", coreKubeconfig, "--workdir", work,
			"--accounts-reader-dir", readerDir, "--loader-seed", loaderSeed}, extra...)
		code, _, stderr := run(t, env, "install.sh", args...)
		b, _ := os.ReadFile(logFile)
		return code, stderr, string(b), work
	}

	// Core minted no fence user: refused before the chart.
	if code, stderr, log, _ := install(trust, "--fence-seed", fenceSeed); code == 0 || !strings.Contains(stderr, "no bus-fence-user.jwt") ||
		strings.Contains(log, "helm upgrade") {
		t.Errorf("an HA DMZ without the fence user's JWT: exit %d\n%s", code, stderr)
	}

	trust["bus-fence-user.jwt"] = trust["sys-account.jwt"]
	code, stderr, log, work := install(trust, "--fence-seed", fenceSeed)
	if code != 0 {
		t.Fatalf("install.sh (HA) exited %d:\n%s", code, stderr)
	}
	for _, want := range []string{
		"seedfile --from-file=bus-fence-user.nk SUAUATSTUBFENCESEED",
		"create secret generic imas-bus-fence-user",
		"create secret generic imas-bus-route-auth",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("no %q in the calls:\n%s", want, log)
		}
	}
	if !regexp.MustCompile(`(?m)^seedfile --from-file=route-password [0-9a-f]{64}$`).MatchString(log) {
		t.Errorf("the route password is not 64 hex characters:\n%s", log)
	}
	var up string
	for _, c := range strings.Split(log, "\n") {
		if strings.HasPrefix(c, "helm upgrade --install") {
			up = c
		}
	}
	if want := "-f " + filepath.Join(dir(t), "values-uat.yaml") + " -f " + filepath.Join(dir(t), "values-ha.yaml") + " -f " + filepath.Join(work, "values-run.yaml"); !strings.Contains(up, want) {
		t.Errorf("helm upgrade lacks %q: %s", want, up)
	}
	// The copied trust carries the fence user's JWT.
	if !strings.Contains(log, "trustfile --from-file=bus-fence-user.jwt ") {
		t.Errorf("bus-fence-user.jwt was not copied to the DMZ:\n%s", log)
	}

	// A Secret already there is kept (no fence seed file given, a route
	// password present): the stub answers every Secret read as present.
	stubbed := strings.Replace(kubectl, `*"get secret imas-bus-accounts-reader -o jsonpath="*`,
		`*"get secret imas-bus-fence-user -o jsonpath="* | *"get secret imas-bus-route-auth -o jsonpath="* | *"get secret imas-bus-accounts-reader -o jsonpath="*`, 1)
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(stubbed), 0o755); err != nil {
		t.Fatal(err)
	}
	code, stderr, log, _ = install(trust)
	if code != 0 {
		t.Fatalf("install.sh (HA) with the Secrets in place exited %d:\n%s", code, stderr)
	}
	if strings.Contains(log, "create secret generic imas-bus-fence-user") || strings.Contains(log, "create secret generic imas-bus-route-auth") {
		t.Errorf("existing fence and route Secrets were replaced:\n%s", log)
	}
}

// One Envoy per DMZ node behind the load balancer, each with its own enrol
// bucket: check.sh's default burst covers all of them (D9), where the
// single-node burst of 41 cannot, and D11 then finds every one refilled.
func TestCheckEnrollBurstFollowsEnvoys(t *testing.T) {
	code, out := runCheckN(t, 3, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, nil, "", "--refill-wait", "6")
	if code != 0 || !regexp.MustCompile(`(?m)^PASS D9 .*burst took [0-9.]+s \(24 in flight, 3 Envoy\(s\)\)$`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^PASS D11 .*6 of 6 probes reached farmer`).MatchString(out) {
		t.Fatalf("check.sh against three Envoys: exit %d\n%s", code, out)
	}
	code, out = runCheckN(t, 3, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, nil, "", "--refill-wait", "0", "--max-burst", "41")
	if code == 0 || !regexp.MustCompile(`(?m)^FAIL D9 .*no 429 after 41 requests in [0-9.]+s .*3 Envoy\(s\)`).MatchString(out) {
		t.Errorf("a burst of 41 against three Envoys: exit %d\n%s", code, out)
	}
}

// D11 must find every Envoy refilled, not only the one a probe reaches: an
// Envoy that stays dry fails it.
func TestCheckRefillCoversEveryEnvoy(t *testing.T) {
	code, out := runCheckN(t, 3, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, []string{"envoy 2 never refills"}, "", "--refill-wait", "4")
	if code == 0 || !regexp.MustCompile(`(?m)^FAIL D11 .* of 6 POST /v1/enroll still answered 429 .*not every Envoy's bucket refilled`).MatchString(out) {
		t.Errorf("one of three Envoys never refills: exit %d\n%s", code, out)
	}
}

// stubDate is date(1) with a fake clock for check.sh's burst timing (date
// +%s%3N): each call moves it STUB_CLOCK_STEP_MS on. Anything else goes to
// the real date.
const stubDate = `#!/usr/bin/env bash
if [[ $* == +%s%3N ]]; then
	n=$(cat "${STUB_CLOCK:?}" 2>/dev/null || echo 0)
	echo $((n + 1)) >"$STUB_CLOCK"
	echo $((1700000000000 + n * ${STUB_CLOCK_STEP_MS:?}))
	exit 0
fi
exec "${REAL_DATE:?}" "$@"
`

// A burst slower than the fill interval cannot show the limit: D9 says so
// rather than report a missing limit, and a burst that did see a 429 still
// passes with its duration.
func TestCheckSlowBurstIsNotAMissingLimit(t *testing.T) {
	realDate, err := exec.LookPath("date")
	if err != nil {
		t.Skip("date not on PATH")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "date"), []byte(stubDate), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("REAL_DATE", realDate)
	t.Setenv("STUB_CLOCK_STEP_MS", "45000")
	hosts := []string{"dmz.uat.test", "dmz.uat.imas.internal"}

	t.Setenv("STUB_CLOCK", filepath.Join(t.TempDir(), "clock"))
	code, out := runCheckN(t, 3, "dmz.uat.test", hosts, []string{"no rate limit"}, "", "--refill-wait", "0")
	if code == 0 || !regexp.MustCompile(`(?m)^FAIL D9 .*burst too slow to test the limit: 121 requests took 45\.0s`).MatchString(out) ||
		strings.Contains(out, "no 429 after") {
		t.Errorf("a 45 s burst without a 429: exit %d\n%s", code, out)
	}
	t.Setenv("STUB_CLOCK", filepath.Join(t.TempDir(), "clock"))
	if _, out := runCheckN(t, 3, "dmz.uat.test", hosts, nil, "", "--refill-wait", "0"); !regexp.MustCompile(`(?m)^PASS D9 .*burst took 45\.0s`).MatchString(out) {
		t.Errorf("a 45 s burst that drew a 429:\n%s", out)
	}
	t.Setenv("STUB_CLOCK", filepath.Join(t.TempDir(), "clock"))
	if _, out := runCheckN(t, 3, "dmz.uat.test", hosts, []string{"no rate limit"}, "", "--refill-wait", "0", "--max-burst", "5"); !regexp.MustCompile(`(?m)^FAIL D9 .*burst too slow`).MatchString(out) {
		t.Errorf("a slow short burst:\n%s", out)
	}
}

// fakeAdmin is an Envoy admin interface whose config_dump holds the reviewed
// reference listener (deploy/envoy/envoy.yaml, which the chart's routes and
// /v1/enroll bucket must match: deploy/helm/nats TestRoutesMatchReferenceEnvoyConfig),
// changed by mutate. Returns its port.
func fakeAdmin(t *testing.T, mutate func(listener obj)) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir(t), "..", "..", "..", "deploy", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ref obj
	if err := yaml.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	l := get(ref, "static_resources", "listeners", 0).(obj)
	if mutate != nil {
		mutate(l)
	}
	dump, err := json.Marshal(obj{"configs": []any{obj{
		"@type":            "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
		"static_listeners": []any{obj{"listener": l}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config_dump":
			w.Header().Set("Content-Type", "application/json")
			w.Write(dump)
		case "/stats":
			io.WriteString(w, "enroll_rate_limiter.http_local_rate_limit.enabled: 41\n"+
				"enroll_rate_limiter.http_local_rate_limit.enforced: 21\n"+
				"enroll_rate_limiter.http_local_rate_limit.ok: 20\n"+
				"enroll_rate_limiter.http_local_rate_limit.rate_limited: 21\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return port
}

// walkObjs calls f on every object under v.
func walkObjs(v any, f func(obj)) {
	switch x := v.(type) {
	case obj:
		f(x)
		for _, e := range x {
			walkObjs(e, f)
		}
	case []any:
		for _, e := range x {
			walkObjs(e, f)
		}
	}
}

// D16: check.sh reads every Envoy's config_dump through kubectl
// port-forward, finds /v1/enroll's filter and bucket in each, and keeps
// only the rate-limit pieces and the stats in the diagnostics directory.
func TestCheckEnvoyRateLimitConfig(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(stubCheckKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(t.TempDir(), "dmz.kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("STUB_TRUST", trustConfigMap(t, makeTrust(t)))
	t.Setenv("STUB_PODS", writeJSON(t, busPods(nil)))
	enrollBucket := func(set func(bucket obj)) func(obj) {
		return func(l obj) {
			walkObjs(l, func(o obj) {
				if get(o, "match", "prefix") == "/v1/enroll" {
					set(get(o, "typed_per_filter_config", "envoy.filters.http.local_ratelimit", "token_bucket").(obj))
				}
			})
		}
	}
	three := "imas-dmz-nats-envoy-a imas-dmz-nats-envoy-b imas-dmz-nats-envoy-c"
	cases := []struct {
		name     string
		nodes    int
		pods     string
		noAdmin  bool
		mutate   func(obj)
		wantFail string
	}{
		{name: "one Envoy", nodes: 1, pods: "imas-dmz-nats-envoy-a"},
		{name: "three Envoys", nodes: 3, pods: three},
		{name: "a missing Envoy", nodes: 3, pods: "imas-dmz-nats-envoy-a imas-dmz-nats-envoy-b", wantFail: "2 Envoy pod(s) Running, want 3"},
		{name: "a larger bucket", nodes: 3, pods: three, mutate: enrollBucket(func(b obj) { b["max_tokens"] = 2000 }), wantFail: "0 of 3 carry it"},
		{name: "a faster fill", nodes: 1, pods: "imas-dmz-nats-envoy-a", mutate: enrollBucket(func(b obj) { b["fill_interval"] = "1s" }), wantFail: "0 of 1 carry it"},
		{name: "no rate limit filter", nodes: 1, pods: "imas-dmz-nats-envoy-a", mutate: func(l obj) {
			walkObjs(l, func(o obj) {
				if fs, ok := o["http_filters"].([]any); ok {
					o["http_filters"] = slices.DeleteFunc(fs, func(f any) bool { return get(f, "name") == "envoy.filters.http.local_ratelimit" })
				}
			})
		}, wantFail: "0 of 1 carry it"},
		{name: "admin not reachable", nodes: 1, pods: "imas-dmz-nats-envoy-a", noAdmin: true, wantFail: "admin port 9901 not reachable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("STUB_ENVOY_PODS", c.pods)
			t.Setenv("STUB_ADMIN_PORT", "")
			if !c.noAdmin {
				t.Setenv("STUB_ADMIN_PORT", fakeAdmin(t, c.mutate))
			}
			diag := filepath.Join(t.TempDir(), "diag")
			code, out := runCheckN(t, c.nodes, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, nil, "",
				"--refill-wait", "0", "--kubeconfig", kubeconfig, "--diagnostics", diag)
			if c.wantFail == "" {
				if code != 0 || !regexp.MustCompile(fmt.Sprintf(`(?m)^PASS D16 +all %d Envoy\(s\) carry`, c.nodes)).MatchString(out) {
					t.Fatalf("exit %d, want PASS D16\n%s", code, out)
				}
				for _, p := range strings.Fields(c.pods) {
					d := filepath.Join(diag, "envoy", p)
					var rl obj
					b, err := os.ReadFile(filepath.Join(d, "rate-limit.json"))
					if err != nil || json.Unmarshal(b, &rl) != nil || len(rl["enroll_routes"].([]any)) != 1 || len(rl["http_filters"].([]any)) == 0 {
						t.Errorf("%s: rate-limit.json %s (%v)", p, b, err)
					}
					if b, err := os.ReadFile(filepath.Join(d, "stats.txt")); err != nil || !strings.Contains(string(b), "rate_limited: 21") {
						t.Errorf("%s: stats.txt %q (%v)", p, b, err)
					}
					if _, err := os.Stat(filepath.Join(d, "config_dump.full")); err == nil {
						t.Errorf("%s: the full config_dump was kept", p)
					}
				}
				return
			}
			if code == 0 || !regexp.MustCompile(`(?m)^FAIL D16 .*`+regexp.QuoteMeta(c.wantFail)).MatchString(out) {
				t.Errorf("exit %d, want FAIL D16 with %q\n%s", code, c.wantFail, out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// D9's burst against a simulated Envoy fleet, on a simulated clock.
//
// Each Envoy's /v1/enroll bucket holds 20 tokens at most and gets 20 per
// 60 s, in one of two ways: on a timer (20 at once every 60 s, each Envoy's
// timer at its own phase: the classic token bucket the brief assumed), or
// continuously (one token every 3 s: Envoy's timer-less atomic token
// bucket, the default since Envoy 1.31 and so in the chart's v1.35.3,
// runtime guard envoy.reloadable_features.no_timer_based_rate_limit_token_bucket).
// Either way one Envoy serves at most 40 requests in any window shorter than
// 60 s. Each request takes its own latency on a new connection, which the
// load balancer hands to a random Envoy; Envoy takes a token when the
// request reaches it (half way through its latency). The design under test
// is check.sh's own: its burst size, parallelism and "too slow" limit are
// read from the script.

type simEnvoy struct {
	continuous bool
	tokens     float64
	nextFill   float64 // timer: the next tick; continuous: the last update
}

func (e *simEnvoy) serve(at float64) bool {
	if e.continuous {
		e.tokens = min(20, e.tokens+(at-e.nextFill)*20/60)
		e.nextFill = at
	} else {
		for at >= e.nextFill {
			e.tokens = min(20, e.tokens+20)
			e.nextFill += 60
		}
	}
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

type simRequest struct {
	arrive float64
	envoy  int
}

// simBurst runs n requests, parallel in flight (1: one after the other),
// each taking latency(); returns the 429 count and the burst's duration.
func simBurst(rng *mathrand.Rand, continuous bool, envoys, n, parallel int, latency func() float64) (int, float64) {
	fleet := make([]*simEnvoy, envoys)
	for i := range fleet {
		// The phase of each Envoy's fill timer is unknown; D8's request may
		// already have taken a token.
		fleet[i] = &simEnvoy{continuous: continuous, tokens: float64(20 - rng.Intn(2)), nextFill: rng.Float64() * 60}
		if continuous {
			fleet[i].nextFill = 0
		}
	}
	free := make([]float64, parallel) // when each slot is free again
	reqs := make([]simRequest, 0, n)
	end := 0.0
	for i := 0; i < n; i++ {
		s := 0
		for j := range free {
			if free[j] < free[s] {
				s = j
			}
		}
		l := latency()
		reqs = append(reqs, simRequest{arrive: free[s] + l/2, envoy: rng.Intn(envoys)})
		free[s] += l
		end = max(end, free[s])
	}
	slices.SortStableFunc(reqs, func(a, b simRequest) int { return cmp.Compare(a.arrive, b.arrive) })
	limited := 0
	for _, r := range reqs {
		if !fleet[r.envoy].serve(r.arrive) {
			limited++
		}
	}
	return limited, end
}

// checkBurstDesign reads D9's parameters from check.sh.
func checkBurstDesign(t *testing.T) (parallel, slow int, burst func(envoys int) int) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir(t), "check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for name, p := range map[string]*int{"burst_parallel": &parallel, "burst_slow": &slow} {
		m := regexp.MustCompile(`(?m)^` + name + `=([0-9]+)$`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("check.sh sets no %s", name)
		}
		fmt.Sscan(m[1], p)
	}
	if !strings.Contains(src, `max_burst=${max_burst:-$((40 * envoys + 1))}`) {
		t.Fatal("check.sh's default burst is no longer 40 per Envoy plus one: update this simulation")
	}
	return parallel, slow, func(envoys int) int { return 40*envoys + 1 }
}

// simVerdict is D9's verdict on a burst, as check.sh words it.
func simVerdict(limited int, elapsed float64, slow int) string {
	switch {
	case limited > 0:
		return "PASS"
	case elapsed > float64(slow):
		return "burst too slow to test the limit"
	default:
		return "no 429"
	}
}

func TestEnrollBurstSimulation(t *testing.T) {
	parallel, slow, burst := checkBurstDesign(t)
	if parallel < 16 || parallel > 32 {
		t.Errorf("burst_parallel %d, want 16 to 32 in flight", parallel)
	}
	for _, continuous := range []bool{false, true} {
		mode := map[bool]string{false: "timer refill", true: "continuous refill"}[continuous]
		// The design: for 1, 3 and 5 Envoys, across seeds (fill phases,
		// D8's token, the spread) and latencies from a local 0.05 s up to
		// 3 s a request (five times the 0.6 s UAT run 41277641220 saw),
		// the burst ends inside the "too slow" limit, well inside one fill
		// interval, and always draws a 429.
		for _, envoys := range []int{1, 3, 5} {
			for _, lat := range []float64{0.05, 0.6, 1.5, 3} {
				worst := 0.0
				for seed := int64(0); seed < 2000; seed++ {
					rng := mathrand.New(mathrand.NewSource(seed))
					limited, elapsed := simBurst(rng, continuous, envoys, burst(envoys), parallel, func() float64 { return lat * (0.5 + rng.Float64()) })
					worst = max(worst, elapsed)
					if v := simVerdict(limited, elapsed, slow); v != "PASS" {
						t.Fatalf("%s, %d Envoy(s), %.2fs a request, seed %d: %s after %.1fs", mode, envoys, lat, seed, v, elapsed)
					}
				}
				if worst > float64(slow) {
					t.Errorf("%s, %d Envoy(s), %.2fs a request: a burst took %.1fs, over burst_slow %ds", mode, envoys, lat, worst, slow)
				}
			}
		}

		// The old design: one request after the other at 0.6 s. One Envoy:
		// 41 requests in 25 s, inside one interval, always a 429.
		fixed := func() float64 { return 0.6 }
		for seed := int64(0); seed < 2000; seed++ {
			if limited, elapsed := simBurst(mathrand.New(mathrand.NewSource(seed)), continuous, 1, 41, 1, fixed); simVerdict(limited, elapsed, slow) != "PASS" {
				t.Fatalf("%s, old design, one Envoy, seed %d: no 429 in %.1fs", mode, seed, elapsed)
			}
		}
		// Three: 121 requests in 73 s, longer than the interval. Whatever
		// slipped through, check.sh now calls such a burst too slow, not a
		// missing limit.
		misses := 0
		for seed := int64(0); seed < 2000; seed++ {
			limited, elapsed := simBurst(mathrand.New(mathrand.NewSource(seed)), continuous, 3, 121, 1, fixed)
			if limited == 0 {
				misses++
				if v := simVerdict(limited, elapsed, slow); v != "burst too slow to test the limit" {
					t.Fatalf("%s, old design, three Envoys, seed %d: %q after %.1fs, want the too slow verdict", mode, seed, v, elapsed)
				}
			}
		}
		t.Logf("%s, old design, three Envoys: %d of 2000 runs drew no 429", mode, misses)
		// Regression pin: with Envoy's continuous refill each Envoy earns
		// about 20 + 73/3 = 44 tokens over the old burst, 133 for three,
		// more than its 121 requests, so only an uneven spread drew a 429
		// and the old design missed in a large share of runs (UAT run
		// 41277641220 was one). With a timer refill it would almost never
		// have missed: H1 as first stated does not explain the run, the
		// continuous refill does.
		if continuous && misses < 200 {
			t.Errorf("%s, old design, three Envoys: only %d of 2000 runs drew no 429; the simulation no longer reproduces UAT run 41277641220", mode, misses)
		}
	}
}
