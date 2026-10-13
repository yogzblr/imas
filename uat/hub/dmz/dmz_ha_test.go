package dmzhub

// The HA DMZ hub (P24, brief H-azure-next-runs.md H4): install.sh with
// uat/k0s's endpoints for 3 + 3 nodes adds values-ha.yaml (a three-node bus
// cluster and three Envoys, spread one per node), names every bus pod on the
// bus certificate, admits core's traffic from every core node and the load
// balancer's probe, makes the fence user's and the route password's
// Secrets; check.sh's enrol burst follows the Envoy count.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
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
// single-node burst of 41 cannot.
func TestCheckEnrollBurstFollowsEnvoys(t *testing.T) {
	code, out := runCheckN(t, 3, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, nil, "", "--refill-wait", "6")
	if code != 0 || !regexp.MustCompile(`(?m)^PASS D9 `).MatchString(out) {
		t.Fatalf("check.sh against three Envoys: exit %d\n%s", code, out)
	}
	code, out = runCheckN(t, 3, "dmz.uat.test", []string{"dmz.uat.test", "dmz.uat.imas.internal"}, nil, "", "--refill-wait", "0", "--max-burst", "41")
	if code == 0 || !regexp.MustCompile(`(?m)^FAIL D9 .*3 Envoy\(s\)`).MatchString(out) {
		t.Errorf("a burst of 41 against three Envoys: exit %d\n%s", code, out)
	}
}
