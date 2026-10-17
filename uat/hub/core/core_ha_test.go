package core

// The HA core hub (P24, brief H-azure-next-runs.md H4): deploy/helm/farmer
// rendered as install.sh installs it on three core nodes
// (values/farmer-uat.yaml, values/values-ha.yaml, gen-values.sh's run values
// for uat/k0s's HA endpoints), and the UAT-only chart with the --set flags
// lib/common.sh gives it for the same endpoints.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	// uat/k0s's endpoints.json for 3 + 3 nodes (its own expected output).
	haEndpointsFile = "../../k0s/testdata/expected/endpoints-ha.json"
	fencePubFile    = "testdata/bus-fence-user.pub"
)

func haRunValues(t *testing.T) string {
	t.Helper()
	out := run(t, "bash", "gen-values.sh", haEndpointsFile, adminFile, releaseTag, loaderPubFile, fencePubFile)
	p := filepath.Join(t.TempDir(), "values-run.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// libValuesFiles is lib/common.sh's farmer_values_files for an endpoints
// file: the -f arguments install.sh passes before the run's values.
func libValuesFiles(t *testing.T, endpoints string) []string {
	t.Helper()
	out := run(t, "bash", "-c", `. lib/common.sh; ENDPOINTS="$1"; load_endpoints; farmer_values_files`, "_", endpoints)
	var args []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l == "-f" {
			args = append(args, l)
			continue
		}
		rel, err := filepath.Rel(mustAbs(t, "."), l)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, rel)
	}
	return args
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestValuesFilesFollowTheNodeCount: the HA overlay is added for a core hub
// of several nodes and never for one node.
func TestValuesFilesFollowTheNodeCount(t *testing.T) {
	requireTools(t, "bash", "jq")
	if got, want := libValuesFiles(t, endpointsFile), []string{"-f", "values/farmer-uat.yaml"}; !reflect.DeepEqual(got, want) {
		t.Errorf("one core node: values files %v, want %v", got, want)
	}
	if got, want := libValuesFiles(t, haEndpointsFile), []string{"-f", "values/farmer-uat.yaml", "-f", "values/values-ha.yaml"}; !reflect.DeepEqual(got, want) {
		t.Errorf("three core nodes: values files %v, want %v", got, want)
	}
}

// TestGenValuesHA: the run values for three DMZ nodes point the bus egress at
// the DMZ's internal load balancer, wait for three bus nodes, name the fence
// user, and leave the object store endpoint to Versity Gateway; and refuse a
// clustered bus without a fence key.
func TestGenValuesHA(t *testing.T) {
	requireTools(t, "bash", "jq")
	var v map[string]any
	if err := json.Unmarshal(run(t, "bash", "gen-values.sh", haEndpointsFile, adminFile, releaseTag, loaderPubFile, fencePubFile), &v); err != nil {
		t.Fatal(err)
	}
	fence, err := os.ReadFile(fencePubFile)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{
		"bus.egressCIDRs":            []any{"10.60.1.250/32"},
		"bus.expectedNodes":          float64(3),
		"bus.host":                   "dmz.uat.imas.internal",
		"natsTrust.busFenceUserPub":  strings.TrimSpace(string(fence)),
		"objectStore.endpoint":       "",
		"natsTrust.busLoaderUserPub": strings.TrimSpace(mustRead(t, loaderPubFile)),
	} {
		keys := []string{}
		keys = append(keys, strings.Split(path, ".")...)
		if got := dig(v, keys...); !reflect.DeepEqual(got, want) {
			t.Errorf("gen-values (HA) %s = %#v, want %#v", path, got, want)
		}
	}
	if dig(v, "objectStore", "useSSL") != nil {
		t.Error("gen-values (HA) sets objectStore.useSSL: Versity Gateway's Service is plain HTTP, the chart ignores it")
	}
	// One DMZ node: no fence user, no expected node count, as before.
	var one map[string]any
	if err := json.Unmarshal(run(t, "bash", "gen-values.sh", endpointsFile, adminFile, releaseTag, loaderPubFile), &one); err != nil {
		t.Fatal(err)
	}
	if dig(one, "bus", "expectedNodes") != nil || dig(one, "natsTrust", "busFenceUserPub") != nil {
		t.Errorf("gen-values (one node) sets the clustered bus's values: %v", one)
	}
	cmd := exec.Command("bash", "gen-values.sh", haEndpointsFile, adminFile, releaseTag, loaderPubFile)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "fence user's public key") {
		t.Errorf("gen-values for three DMZ nodes without a fence key: err %v, output %s", err, out)
	}
	cmd = exec.Command("bash", "gen-values.sh", haEndpointsFile, adminFile, releaseTag, loaderPubFile, loaderPubFile)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "must be different keys") {
		t.Errorf("gen-values with the loader's key as the fence key: err %v, output %s", err, out)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// spreadOneNode: a topology spread constraint over nodes, maxSkew 1,
// DoNotSchedule.
func spreadOneNode(o map[string]any) bool {
	l, _ := dig(o, "spec", "template", "spec", "topologySpreadConstraints").([]any)
	for _, c := range l {
		m, _ := c.(map[string]any)
		if m["topologyKey"] == "kubernetes.io/hostname" && m["whenUnsatisfiable"] == "DoNotSchedule" && dig(m, "maxSkew") == 1 {
			return true
		}
	}
	return false
}

func hasPVCVolume(o map[string]any) bool {
	l, _ := dig(o, "spec", "template", "spec", "volumes").([]any)
	for _, v := range l {
		if m, _ := v.(map[string]any); m["persistentVolumeClaim"] != nil {
			return true
		}
	}
	_, tmpl := dig(o, "spec", "volumeClaimTemplates").([]any)
	return tmpl
}

// TestFarmerChartRenderHA renders deploy/helm/farmer as install.sh installs
// it on an HA core hub and asserts the layout of brief H4.
func TestFarmerChartRenderHA(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")
	chart, full := farmerChart(t)
	if !full {
		if os.Getenv("IMAS_REQUIRE_HELM") == "1" {
			t.Fatal("the subcharts are not built (helm dependency build deploy/helm/farmer) and IMAS_REQUIRE_HELM=1")
		}
		t.Skip("subcharts not built (helm dependency build deploy/helm/farmer): OpenBao, PXC and Valkey can't be rendered")
	}
	args := append([]string{"template", "imas-core", chart, "-n", "imas-core", "--kube-version", "1.31.0"},
		append(libValuesFiles(t, haEndpointsFile), "-f", haRunValues(t))...)
	objs := docs(t, run(t, "helm", args...))
	run(t, "helm", append([]string{"lint", chart, "--kube-version", "1.31.0"}, args[5:]...)...)
	lib := libConstants(t)

	// Stateless: three replicas, spread one per node, a PDB, no volume.
	for _, name := range []string{lib["FARMER_FULLNAME"], lib["SAASAPI_FULLNAME"], lib["VERSITY_FULLNAME"]} {
		d := get(t, objs, "Deployment/"+name)
		if dig(d, "spec", "replicas") != 3 {
			t.Errorf("%s replicas = %v, want 3", name, dig(d, "spec", "replicas"))
		}
		if !spreadOneNode(d) {
			t.Errorf("%s is not spread one per node (maxSkew 1, DoNotSchedule)", name)
		}
		if hasPVCVolume(d) {
			t.Errorf("%s mounts a PersistentVolumeClaim", name)
		}
		get(t, objs, "PodDisruptionBudget/"+name)
	}
	if got := dig(get(t, objs, "PodDisruptionBudget/"+lib["FARMER_FULLNAME"]), "spec", "minAvailable"); got != 2 {
		t.Errorf("farmer PDB minAvailable = %v, want 2", got)
	}
	for k := range objs {
		if strings.HasPrefix(k, "PersistentVolumeClaim/") {
			t.Errorf("the HA render creates %s: volumes are the StatefulSets' own claims only", k)
		}
	}

	// PXC: 3 nodes, 3 HAProxy, no unsafeFlags, local volumes.
	pxc := get(t, objs, "PerconaXtraDBCluster/"+lib["PXC_CLUSTER"])
	if dig(pxc, "spec", "pxc", "size") != 3 || dig(pxc, "spec", "haproxy", "size") != 3 {
		t.Errorf("PXC size %v, HAProxy %v, want 3 and 3", dig(pxc, "spec", "pxc", "size"), dig(pxc, "spec", "haproxy", "size"))
	}
	if f := dig(pxc, "spec", "unsafeFlags"); f != nil {
		t.Errorf("PXC unsafeFlags = %v, want none", f)
	}
	if got := str(pxc, "spec", "pxc", "volumeSpec", "persistentVolumeClaim", "storageClassName"); got != "local-path" {
		t.Errorf("PXC storage class %q, want local-path", got)
	}

	// OpenBao: 3 raft pods, retry_join between them, the static seal from
	// the seal Secret, local volumes, a PDB, no standalone config.
	bao := get(t, objs, "StatefulSet/"+lib["OPENBAO_STS"])
	if dig(bao, "spec", "replicas") != 3 {
		t.Errorf("OpenBao replicas = %v, want 3", dig(bao, "spec", "replicas"))
	}
	if sc := claimClass(bao); sc != "local-path" {
		t.Errorf("OpenBao data volume storage class %q, want local-path", sc)
	}
	cfg := str(get(t, objs, "ConfigMap/imas-core-openbao-config"), "data", "extraconfig-from-values.hcl")
	for i := 0; i < 3; i++ {
		peer := "http://" + lib["OPENBAO_STS"] + "-" + string(rune('0'+i)) + "." + lib["OPENBAO_INTERNAL_SVC"] + ".imas-core.svc:8200"
		if !strings.Contains(cfg, `leader_api_addr = "`+peer+`"`) {
			t.Errorf("OpenBao config does not retry_join %s", peer)
		}
	}
	if !strings.Contains(cfg, `seal "static"`) || !strings.Contains(cfg, `current_key_id = "`+lib["OPENBAO_SEAL_KEY_ID"]+`"`) ||
		!strings.Contains(cfg, `current_key    = "file:///openbao/seal/seal.key"`) {
		t.Errorf("OpenBao config has no static seal from /openbao/seal/seal.key:\n%s", cfg)
	}
	sealVol := false
	vols, _ := dig(bao, "spec", "template", "spec", "volumes").([]any)
	for _, v := range vols {
		m, _ := v.(map[string]any)
		if str(m, "secret", "secretName") == lib["OPENBAO_SEAL_SECRET"] {
			sealVol = true
		}
	}
	if !sealVol {
		t.Errorf("OpenBao pods do not mount Secret %s", lib["OPENBAO_SEAL_SECRET"])
	}
	be := envOf(container(t, bao, "openbao"))
	if strings.Contains(be["BAO_API_ADDR"], "-0.") || strings.Contains(be["BAO_CLUSTER_ADDR"], "-0.") {
		t.Errorf("every OpenBao pod advertises pod 0's address: %v", be)
	}
	get(t, objs, "PodDisruptionBudget/"+lib["OPENBAO_STS"])

	// Valkey: the chart's replicated mode, a primary and two replicas, spread,
	// local volumes, a PDB.
	vk := get(t, objs, "StatefulSet/"+lib["VALKEY_NAME"])
	if dig(vk, "spec", "replicas") != 3 || !spreadOneNode(vk) {
		t.Errorf("Valkey replicas %v (want 3), spread %v", dig(vk, "spec", "replicas"), spreadOneNode(vk))
	}
	if sc := claimClass(vk); sc != "local-path" {
		t.Errorf("Valkey volume storage class %q, want local-path", sc)
	}
	if _, ok := objs["Deployment/"+lib["VALKEY_NAME"]]; ok {
		t.Error("Valkey is still a Deployment too")
	}
	get(t, objs, "PodDisruptionBudget/"+lib["VALKEY_NAME"])
	// Unit S5: every replica authenticates to the primary with the password
	// from Secret imas-valkey-auth, as user default.
	vinit := str(get(t, objs, "ConfigMap/"+lib["VALKEY_NAME"]+"-init-scripts"), "data", "init.sh")
	if !strings.Contains(vinit, `REPL_PASSWORD=$(get_user_password "default" "`+lib["VALKEY_AUTH_KEY"]+`")`) || !strings.Contains(vinit, `echo "masteruser default"`) {
		t.Error("Valkey replicas don't authenticate to the primary")
	}
	if !strings.Contains(mustJSON(t, vk), `"secretName":"`+lib["VALKEY_AUTH_SECRET"]+`"`) {
		t.Errorf("Valkey doesn't read Secret %s", lib["VALKEY_AUTH_SECRET"])
	}

	// Versity Gateway: on, its Secrets the ones install.sh makes, and the S3
	// endpoint of farmer and saasapi.
	gwEndpoint := lib["VERSITY_FULLNAME"] + ".imas-core.svc.cluster.local:" + lib["VERSITY_PORT"]
	fe := envOf(container(t, get(t, objs, "Deployment/"+lib["FARMER_FULLNAME"]), "farmer"))
	if fe["IMAS_S3_ENDPOINT"] != gwEndpoint || fe["IMAS_ACCOUNTS_S3_ENDPOINT"] != gwEndpoint {
		t.Errorf("farmer's S3 endpoints %q and %q, want the gateway %s", fe["IMAS_S3_ENDPOINT"], fe["IMAS_ACCOUNTS_S3_ENDPOINT"], gwEndpoint)
	}
	if fe["IMAS_BUS_EXPECTED_NODES"] != "3" {
		t.Errorf("farmer IMAS_BUS_EXPECTED_NODES = %q, want 3", fe["IMAS_BUS_EXPECTED_NODES"])
	}
	se := envOf(container(t, get(t, objs, "Deployment/"+lib["SAASAPI_FULLNAME"]), "saasapi"))
	if se["SAASAPI_RECIPES_S3_ENDPOINT"] != gwEndpoint {
		t.Errorf("saasapi's S3 endpoint %q, want the gateway %s", se["SAASAPI_RECIPES_S3_ENDPOINT"], gwEndpoint)
	}
	gwJSON, _ := json.Marshal(get(t, objs, "Deployment/"+lib["VERSITY_FULLNAME"]))
	for _, s := range []string{lib["VERSITY_AZURE_SECRET"], lib["VERSITY_ROOT_SECRET"], lib["S3_ACCOUNTS_READER_SECRET"],
		lib["S3_FARMER_SECRET"], lib["S3_SAASAPI_SECRET"], lib["S3_ACCOUNTS_WRITER_SECRET"]} {
		if !strings.Contains(string(gwJSON), `"`+s+`"`) {
			t.Errorf("Versity Gateway does not use Secret %s", s)
		}
	}
	get(t, objs, "Job/"+lib["VERSITY_FULLNAME"]+"-buckets")
	np, _ := json.Marshal(get(t, objs, "NetworkPolicy/"+lib["VERSITY_FULLNAME"]))
	if !strings.Contains(string(np), `"app.kubernetes.io/name":"imas-uat-edge"`) {
		t.Error("Versity Gateway's NetworkPolicy does not let the edge proxy in (the DMZ's accounts path)")
	}
	for k := range objs {
		if strings.Contains(k, "rustfs") {
			t.Errorf("the HA render names RustFS: %s", k)
		}
	}

	// The clustered bus's fence user is minted into the trust.
	var fenceEnv string
	for _, c := range containers(get(t, objs, "Job/imas-core-farmer-openbao-bootstrap")) {
		if v := envOf(c)["IMAS_NATSBOOT_BUS_FENCE_USER_PUB"]; v != "" {
			fenceEnv = v
		}
	}
	if fenceEnv != strings.TrimSpace(mustRead(t, fencePubFile)) {
		t.Errorf("the bootstrap Job's IMAS_NATSBOOT_BUS_FENCE_USER_PUB = %q, want %s's key", fenceEnv, fencePubFile)
	}
}

// claimClass is the storage class of a StatefulSet's first volume claim.
func claimClass(o map[string]any) string {
	l, _ := dig(o, "spec", "volumeClaimTemplates").([]any)
	if len(l) == 0 {
		return ""
	}
	return str(l[0], "spec", "storageClassName")
}

// TestExtrasChartRenderHA renders chart/ with lib/common.sh's --set flags
// for uat/k0s's HA endpoints: one edge per node, spread, a PDB, the accounts
// store's passthrough to Versity Gateway on 9000 instead of RustFS, and the
// cross-cluster policies naming every DMZ node and the load balancer probe.
func TestExtrasChartRenderHA(t *testing.T) {
	requireTools(t, "helm", "bash", "jq")
	out := run(t, "bash", "-c", `. lib/common.sh; ENDPOINTS="$1"; load_endpoints; extras_set_args`, "_", haEndpointsFile)
	setArgs := strings.Split(strings.TrimSpace(string(out)), "\n")
	args := append([]string{"template", "imas-uat-core", "chart", "-n", "imas-uat", "--kube-version", "1.31.0"}, setArgs...)
	objs := docs(t, run(t, "helm", args...))
	run(t, "helm", append([]string{"lint", "chart", "--kube-version", "1.31.0"}, setArgs...)...)

	edge := get(t, objs, "Deployment/imas-uat-edge")
	if dig(edge, "spec", "replicas") != 3 || !spreadOneNode(edge) {
		t.Errorf("edge replicas %v (want 3), spread %v", dig(edge, "spec", "replicas"), spreadOneNode(edge))
	}
	if str(edge, "spec", "strategy", "type") != "RollingUpdate" || dig(edge, "spec", "strategy", "rollingUpdate", "maxSurge") != 0 {
		t.Errorf("edge strategy %v: hostPorts need maxSurge 0", dig(edge, "spec", "strategy"))
	}
	get(t, objs, "PodDisruptionBudget/imas-uat-edge")
	ports, _ := json.Marshal(container(t, edge, "envoy")["ports"])
	if !strings.Contains(string(ports), `"containerPort":9000,"hostPort":9000,"name":"accounts-s3"`) {
		t.Errorf("edge has no accounts store hostPort 9000: %s", ports)
	}
	cfg := str(get(t, objs, "ConfigMap/imas-uat-edge"), "data", "envoy.yaml")
	if !strings.Contains(cfg, "imas-core-farmer-versity.imas-core.svc.cluster.local, port_value: 7070") {
		t.Error("edge does not pass the accounts store through to Versity Gateway's Service")
	}
	for k := range objs {
		if strings.Contains(k, "rustfs") {
			t.Errorf("the HA render deploys RustFS: %s", k)
		}
	}
	pol, _ := json.Marshal(get(t, objs, "NetworkPolicy/imas-uat-edge"))
	for _, ip := range []string{"10.60.1.4/32", "10.60.1.5/32", "10.60.1.6/32", "168.63.129.16/32"} {
		if !strings.Contains(string(pol), `"cidr":"`+ip+`"`) {
			t.Errorf("the edge policy does not admit %s (a DMZ node or the load balancer probe)", ip)
		}
	}
	for _, name := range []string{"imas-uat-farmer-cross-cluster", "imas-uat-saasapi-cross-cluster"} {
		p, _ := json.Marshal(get(t, objs, "NetworkPolicy/"+name))
		if !strings.Contains(string(p), `"cidr":"10.60.1.250/32"`) || strings.Contains(string(p), `"cidr":"10.60.1.4/32"`) {
			t.Errorf("%s does not send bus traffic to the DMZ's internal load balancer only: %s", name, p)
		}
	}
	tls := get(t, objs, "Certificate/imas-farmer-tls")
	ips, _ := dig(tls, "spec", "ipAddresses").([]any)
	var got []string
	for _, ip := range ips {
		got = append(got, ip.(string))
	}
	slices.Sort(got)
	if want := []string{"10.60.2.250", "10.60.2.4", "10.60.2.5", "10.60.2.6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("farmer certificate IPs %v, want %v", got, want)
	}

	// One node: no probe source, the DMZ's only node, one edge.
	out = run(t, "bash", "-c", `. lib/common.sh; ENDPOINTS="$1"; load_endpoints; extras_set_args`, "_", endpointsFile)
	one := docs(t, run(t, "helm", append([]string{"template", "imas-uat-core", "chart", "-n", "imas-uat", "--kube-version", "1.31.0"},
		strings.Split(strings.TrimSpace(string(out)), "\n")...)...))
	if e := get(t, one, "Deployment/imas-uat-edge"); dig(e, "spec", "replicas") != 1 || str(e, "spec", "strategy", "type") != "Recreate" {
		t.Errorf("one node: edge %v", dig(e, "spec"))
	}
	p1, _ := json.Marshal(get(t, one, "NetworkPolicy/imas-uat-edge"))
	if strings.Contains(string(p1), "168.63.129.16") || !strings.Contains(string(p1), `"cidr":"10.60.1.4/32"`) {
		t.Errorf("one node: the edge policy %s", p1)
	}
	if _, ok := one["PodDisruptionBudget/imas-uat-edge"]; ok {
		t.Error("one node: an edge PDB")
	}
}
