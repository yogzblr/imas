package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHANamesMatchTheHubScripts keeps the ha tier's names equal to the
// hub scripts' (uat/hub/core/lib/common.sh, uat/hub/dmz/lib.sh).
func TestHANamesMatchTheHubScripts(t *testing.T) {
	vars := map[string]string{}
	assign := regexp.MustCompile(`^([A-Z_]+)=("?)([^"\s#]*)("?)`)
	for _, f := range []string{"../../hub/core/lib/common.sh", "../../hub/dmz/lib.sh"} {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			if m := assign.FindStringSubmatch(sc.Text()); m != nil {
				v := m[3]
				for k, val := range vars {
					v = strings.ReplaceAll(v, "${"+k+"}", val)
				}
				vars[m[1]] = v
			}
		}
		fh.Close()
	}
	for script, want := range map[string]string{
		"CORE_NS": CoreNamespace, "CORE_RELEASE": CoreRelease, "UAT_NS": UATNamespace,
		"FARMER_FULLNAME": FarmerDeployment, "SAASAPI_FULLNAME": SaaSAPIDeployment, "OPENBAO_STS": OpenBaoStatefulSet,
		"PXC_CLUSTER": PXCCluster, "PXC_ROOT_SECRET": PXCRootSecret, "VALKEY_NAME": ValkeyName,
		"KEYCLOAK_DEPLOY": KeycloakDeployment, "EDGE_DEPLOY": EdgeDeployment,
		"DMZ_NAMESPACE": DMZNamespace, "DMZ_RELEASE": DMZRelease, "DMZ_BUS_NAME": BusStatefulSet, "DMZ_ENVOY_NAME": EnvoyDeployment,
	} {
		if vars[script] != want {
			t.Errorf("%s is %q in the hub scripts, %q in the harness", script, vars[script], want)
		}
	}
}

func TestResolveHAConfig(t *testing.T) {
	t.Setenv(EnvCoreKubeconfig, "")
	t.Setenv(EnvDMZKubeconfig, "/k/dmz")
	t.Setenv(EnvCoreChart, "")
	t.Setenv(EnvDMZChart, "/c/nats.tgz")
	t.Setenv(EnvCoreCheck, "")
	t.Setenv(EnvCoreCheckDefault, "/repo/uat/hub/core/check.sh")
	c := resolveHAConfig(HAConfig{}, BindConfig{Kubeconfig: "/k/core"}, &CoreJSON{Version: "1.2.3"}, "/state")
	want := HAConfig{CoreKubeconfig: "/k/core", DMZKubeconfig: "/k/dmz", CoreChart: "/state/core/chart/farmer-1.2.3.tgz",
		DMZChart: "/c/nats.tgz", CoreCheck: "/repo/uat/hub/core/check.sh"}
	if c != want {
		t.Errorf("got %+v\nwant %+v", c, want)
	}
	set := HAConfig{CoreKubeconfig: "/h/core", DMZKubeconfig: "/h/dmz", CoreChart: "/h/f.tgz", DMZChart: "/h/n.tgz", CoreCheck: "/h/check"}
	if c := resolveHAConfig(set, BindConfig{}, nil, ""); c != set {
		t.Errorf("harness.json's ha must win: %+v", c)
	}
	t.Setenv(EnvCoreCheck, "/x/check.sh")
	if c := resolveHAConfig(HAConfig{}, BindConfig{}, nil, ""); c.CoreCheck != "/x/check.sh" || c.CoreChart != "" {
		t.Errorf("env: %+v", c)
	}
}

// haUAT is an HA run's uat.json hubs.
func haUAT() UAT {
	return UAT{
		Core: Host{Name: "uat-core-1", NodeNames: []string{"uat-core-1", "uat-core-2", "uat-core-3"},
			NodePrivateIPs: []string{"10.0.2.4", "10.0.2.5", "10.0.2.6"}},
		DMZ: Host{Name: "uat-dmz-1", NodeNames: []string{"uat-dmz-1", "uat-dmz-2", "uat-dmz-3"},
			NodePrivateIPs: []string{"10.0.1.4", "10.0.1.5", "10.0.1.6"}},
	}
}

func TestFleetHA(t *testing.T) {
	f, _ := fakeFleet(t)
	if _, err := f.HA(); !errors.Is(err, ErrNotHA) {
		t.Fatalf("single-node hubs: %v", err)
	}
	f.Env.UAT.Core, f.Env.UAT.DMZ = haUAT().Core, haUAT().DMZ
	f.Env.HA = HAConfig{}
	if _, err := f.HA(); err == nil || !strings.Contains(err.Error(), EnvCoreKubeconfig) || !strings.Contains(err.Error(), EnvDMZKubeconfig) {
		t.Fatalf("missing kubeconfigs must be named: %v", err)
	}
	f.Env.HA = HAConfig{CoreKubeconfig: "/c", DMZKubeconfig: "/d"}
	h, err := f.HA()
	if err != nil || h.Core.Kubeconfig != "/c" || h.DMZ.Kubeconfig != "/d" {
		t.Fatalf("%+v %v", h, err)
	}
}

// pod is a line of a fake pod list.
func podItem(ns, name, node, component string, ready bool) map[string]any {
	st := "False"
	if ready {
		st = "True"
	}
	return map[string]any{
		"metadata": map[string]any{"namespace": ns, "name": name, "uid": name, "labels": map[string]string{"app.kubernetes.io/component": component}},
		"spec":     map[string]any{"nodeName": node},
		"status":   map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": st}}},
	}
}

func itemsJSON(items ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"items": items})
	return string(b)
}

const nodesJSON = `{"items":[
 {"metadata":{"name":"n1"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.2.4"}],"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"n2"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.2.5"}],"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"n3"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.2.6"}],"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"d1"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.4"}],"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"d2"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.5"}],"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"d3"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.6"}],"conditions":[{"type":"Ready","status":"False"}]}}]}`

func testHA(core, dmz *Kube) *HA {
	return &HA{Fleet: &Fleet{Env: &Env{UAT: haUAT()}}, Core: core, DMZ: dmz, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func TestStopNodeChoice(t *testing.T) {
	var corePods []map[string]any
	for i, n := range []string{"n1", "n2", "n3"} {
		s := strconv.Itoa(i)
		corePods = append(corePods,
			podItem(CoreNamespace, FarmerDeployment+"-abc"+s, n, "farmer", true),
			podItem(CoreNamespace, SaaSAPIDeployment+"-abc"+s, n, "saasapi", true),
			podItem(CoreNamespace, PXCCluster+"-pxc-"+s, n, "pxc", true),
			podItem(CoreNamespace, OpenBaoStatefulSet+"-"+s, n, "", true),
			podItem(CoreNamespace, ValkeyName+"-"+s, n, "", true))
	}
	corePods = append(corePods, podItem(UATNamespace, KeycloakDeployment+"-xyz", "n2", "keycloak", true))
	core, _ := fakeKube("core", func(args string, _ []byte) (string, error) {
		if strings.HasPrefix(args, "get nodes") {
			return nodesJSON, nil
		}
		return itemsJSON(corePods...), nil
	})
	dmz, _ := fakeKube("dmz", func(args string, _ []byte) (string, error) {
		if strings.HasPrefix(args, "get nodes") {
			return nodesJSON, nil
		}
		return itemsJSON(
			podItem(DMZNamespace, BusStatefulSet+"-0", "d1", "bus", true), podItem(DMZNamespace, EnvoyDeployment+"-a", "d1", "envoy", true),
			podItem(DMZNamespace, BusStatefulSet+"-1", "d2", "bus", true), podItem(DMZNamespace, EnvoyDeployment+"-b", "d2", "envoy", true),
			podItem(DMZNamespace, BusStatefulSet+"-2", "d3", "bus", true)), nil
	})
	h := testHA(core, dmz)
	vm, node, err := h.CoreStopNode(context.Background())
	if err != nil || vm.Name != "uat-core-3" || node != "n3" {
		t.Errorf("core: Valkey's primary is on n1 and Keycloak on n2, so n3: %v %s %v", vm, node, err)
	}
	vm, node, err = h.DMZStopNode(context.Background())
	if err != nil || vm.Name != "uat-dmz-2" || node != "d2" {
		t.Errorf("dmz: d3 has no Envoy, so d2: %v %s %v", vm, node, err)
	}
	// Keycloak beside the primary: two nodes fit, the first one wins.
	corePods[len(corePods)-1] = podItem(UATNamespace, KeycloakDeployment+"-xyz", "n1", "keycloak", true)
	if vm, _, _ := h.CoreStopNode(context.Background()); vm.Name != "uat-core-2" {
		t.Errorf("got %s", vm.Name)
	}
	// No farmer pod anywhere but n1.
	var noFarmer []map[string]any
	for _, p := range corePods {
		if p["metadata"].(map[string]any)["labels"].(map[string]string)["app.kubernetes.io/component"] != "farmer" {
			noFarmer = append(noFarmer, p)
		}
	}
	corePods = noFarmer
	if _, _, err := h.CoreStopNode(context.Background()); err == nil || !strings.Contains(err.Error(), "has no farmer pod") {
		t.Errorf("no candidate must say why: %v", err)
	}
	if vm, err := h.VMOfNode(context.Background(), dmz, h.Fleet.Env.UAT.DMZ, "d3"); err != nil || vm.Name != "uat-dmz-3" {
		t.Errorf("VMOfNode %v %v", vm, err)
	}
}

func TestCheckStateful(t *testing.T) {
	size := "2"
	sealed := "false"
	core, calls := fakeKube("core", func(args string, stdin []byte) (string, error) {
		switch {
		case strings.HasPrefix(args, "get secret"):
			return `{"data":{"root":"cm9vdHB3"}}`, nil
		case strings.Contains(args, "component=pxc"):
			return itemsJSON(podItem(CoreNamespace, PXCCluster+"-pxc-0", "n1", "pxc", true), podItem(CoreNamespace, PXCCluster+"-pxc-1", "n2", "pxc", true),
				podItem(CoreNamespace, PXCCluster+"-pxc-2", "n3", "pxc", false)), nil
		case strings.Contains(args, "name=openbao"):
			return itemsJSON(podItem(CoreNamespace, OpenBaoStatefulSet+"-0", "n1", "", true), podItem(CoreNamespace, OpenBaoStatefulSet+"-1", "n2", "", true)), nil
		case strings.Contains(args, "name=valkey"):
			return itemsJSON(podItem(CoreNamespace, ValkeyName+"-0", "n1", "", true), podItem(CoreNamespace, ValkeyName+"-2", "n2", "", true),
				podItem(CoreNamespace, ValkeyName+"-1", "n3", "", true)), nil
		case strings.HasPrefix(args, "exec") && strings.Contains(args, "mysql"):
			if string(stdin) != "rootpw\n" {
				return "", errors.New("the root password must come on stdin")
			}
			return "wsrep_cluster_size\t" + size + "\nwsrep_cluster_status\tPrimary\nwsrep_ready\tON\n", nil
		case strings.HasPrefix(args, "exec") && strings.Contains(args, "bao status"):
			self := strings.Contains(args, OpenBaoStatefulSet+"-1 ")
			return `{"sealed":` + sealed + `,"is_self":` + strconv.FormatBool(self) + `}`, nil
		case strings.HasPrefix(args, "exec") && strings.Contains(args, "info replication"):
			return "# Replication\r\nrole:master\r\nconnected_slaves:1\r\n", nil
		case strings.HasPrefix(args, "exec"):
			return "PONG\n", nil
		}
		return "", errors.New("unexpected " + args)
	})
	h := testHA(core, nil)
	rep, err := h.CheckStateful(context.Background(), "n3", 2)
	if err != nil {
		t.Fatalf("two of each serving: %v", err)
	}
	if rep.PXC != "2 nodes, Primary" || rep.OpenBao != "2 pods unsealed, 1 active" || rep.Valkey != "2 pods answer" {
		t.Errorf("%+v", rep)
	}
	for _, c := range *calls {
		if strings.Contains(c, "rootpw") {
			t.Errorf("the password reached a command line: %s", c)
		}
	}
	size, sealed = "3", "true"
	_, err = h.CheckStateful(context.Background(), "n3", 2)
	if err == nil || !strings.Contains(err.Error(), "wsrep_cluster_size 3") || !strings.Contains(err.Error(), "is sealed") {
		t.Errorf("a wrong size and a sealed pod must fail, named: %v", err)
	}
}

func TestWaitNodeBack(t *testing.T) {
	pending := true
	k, _ := fakeKube("dmz", func(args string, _ []byte) (string, error) {
		switch {
		case strings.HasPrefix(args, "get nodes"):
			return nodesJSON, nil
		case strings.Contains(args, "spec.nodeName=d2"):
			return itemsJSON(podItem(DMZNamespace, BusStatefulSet+"-1", "d2", "bus", true)), nil
		case pending:
			p := podItem(DMZNamespace, EnvoyDeployment+"-q", "", "envoy", false)
			p["status"].(map[string]any)["phase"] = "Pending"
			return itemsJSON(p), nil
		}
		return itemsJSON(), nil
	})
	h := testHA(nil, k)
	c := context.Background()
	if err := h.WaitNodeBack(c, k, "d2", []string{DMZNamespace}, 0); err == nil || !strings.Contains(err.Error(), "(Pending)") {
		t.Errorf("a Pending pod must keep the node not back: %v", err)
	}
	pending = false
	if err := h.WaitNodeBack(c, k, "d2", []string{DMZNamespace}, 0); err != nil {
		t.Errorf("back: %v", err)
	}
	if err := h.WaitNodeBack(c, k, "d3", nil, 0); err == nil || !strings.Contains(err.Error(), "not Ready") {
		t.Errorf("d3 is not Ready: %v", err)
	}
}

// chartBusPolicy is the bus NetworkPolicy as deploy/helm/nats renders it.
const chartBusPolicy = `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
 "metadata":{"name":"imas-dmz-nats-bus","namespace":"imas-dmz","resourceVersion":"7"},
 "spec":{"podSelector":{"matchLabels":{"app.kubernetes.io/component":"bus"}},"policyTypes":["Ingress","Egress"],
  "ingress":[{"from":[{"ipBlock":{"cidr":"10.0.2.0/24"}}],"ports":[{"protocol":"TCP","port":5406}]}],
  "egress":[{"to":[{"namespaceSelector":{},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}],"ports":[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}]},
   {"to":[{"ipBlock":{"cidr":"10.0.2.10/32"}}],"ports":[{"protocol":"TCP","port":9000}]}]}}`

func TestBlockAccountStore(t *testing.T) {
	var applied []byte
	k, calls := fakeKube("dmz", func(args string, stdin []byte) (string, error) {
		switch {
		case strings.HasPrefix(args, "get networkpolicy"):
			return chartBusPolicy, nil
		case strings.HasPrefix(args, "apply"):
			applied = stdin
		}
		return "", nil
	})
	h := testHA(nil, k)
	c := context.Background()
	unblock, err := h.BlockAccountStore(c, BusStatefulSet+"-2", 9000)
	if err != nil {
		t.Fatal(err)
	}
	var own netpol
	if err := json.Unmarshal(applied, &own); err != nil {
		t.Fatal(err)
	}
	sel, _ := json.Marshal(own.Spec.PodSelector)
	if own.Metadata["name"] != "imas-uat-ha5-imas-dmz-nats-bus-2" || string(sel) != `{"matchLabels":{"statefulset.kubernetes.io/pod-name":"imas-dmz-nats-bus-2"}}` ||
		len(own.Spec.Egress) != 1 || len(own.Spec.Ingress) != 1 || own.Metadata["resourceVersion"] != nil {
		t.Errorf("the pod's own policy: %s", applied)
	}
	if strings.Contains(string(applied), "9000") {
		t.Errorf("the account store egress must be gone: %s", applied)
	}
	want := `patch networkpolicy imas-dmz-nats-bus -n imas-dmz --type json -p [{"op":"add","path":"/spec/podSelector/matchExpressions","value":[{"key":"statefulset.kubernetes.io/pod-name","operator":"NotIn","values":["imas-dmz-nats-bus-2"]}]}]`
	if (*calls)[2] != want {
		t.Errorf("patch:\n%s\nwant\n%s", (*calls)[2], want)
	}
	if err := unblock(c); err != nil {
		t.Fatal(err)
	}
	last := strings.Join((*calls)[3:], "\n")
	if !strings.Contains(last, `"op":"remove","path":"/spec/podSelector/matchExpressions"`) ||
		!strings.Contains(last, "delete networkpolicy imas-uat-ha5-imas-dmz-nats-bus-2 -n imas-dmz --ignore-not-found") {
		t.Errorf("unblock: %s", last)
	}
	if _, err := h.BlockAccountStore(c, BusStatefulSet+"-2", 9443); err == nil {
		t.Error("a policy with no rule to the store's port must be refused")
	}
}

func TestLoaderStatusThroughForward(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"ready":true,"status":"ready","applied":4,"target":4,"lastIndexToken":"e1","counters":{"loader_pushes_total":9,"loader_s3_errors_total":2}}`))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var asked int
	dmz := &Kube{Hub: "dmz", Forward: func(_ context.Context, ns, pod string, p int) (int, func(), error) {
		asked = p
		n, _ := strconv.Atoi(port)
		return n, func() {}, nil
	}}
	h := testHA(nil, dmz)
	st, err := h.LoaderStatusOf(context.Background(), Pod{Name: "imas-dmz-nats-bus-0", Ports: map[string]map[string]int{}})
	if err != nil {
		t.Fatal(err)
	}
	if asked != DefaultLoaderHealth || !st.Ready || st.Applied != 4 || st.Pushes() != 9 || st.S3Errors() != 2 || st.LastIndexToken != "e1" {
		t.Errorf("%+v (port %d)", st, asked)
	}
}

func TestHelmUpgradeAndCoreCheck(t *testing.T) {
	var got []string
	h := testHA(nil, nil)
	h.Cfg = HAConfig{CoreKubeconfig: "/k/core", DMZKubeconfig: "/k/dmz", CoreChart: "/c/farmer.tgz", CoreCheck: "/repo/check.sh"}
	h.Helm = func(_ context.Context, args []string) ([]byte, error) { got = args; return nil, nil }
	if err := h.HelmUpgrade(context.Background(), "core", "farmer.podAnnotations."+UpgradeAnnotation+"=x"); err != nil {
		t.Fatal(err)
	}
	want := "upgrade imas-core /c/farmer.tgz --kubeconfig /k/core -n imas-core --reuse-values --wait --timeout 20m --set-string farmer.podAnnotations.imas\\.io/uat-ha3=x"
	if strings.Join(got, " ") != want {
		t.Errorf("helm %q", strings.Join(got, " "))
	}
	if err := h.HelmUpgrade(context.Background(), "dmz", "x=y"); err == nil || !strings.Contains(err.Error(), EnvDMZChart) {
		t.Errorf("no DMZ chart must be named: %v", err)
	}
	h.Fleet.Env.Bind = BindConfig{Endpoints: "/e.json", StateDir: "/state"}
	var script string
	var sargs []string
	h.Script = func(_ context.Context, p string, args []string) ([]byte, error) {
		script, sargs = p, args
		return []byte("PASS  x\n"), nil
	}
	out, err := h.RunCoreCheck(context.Background())
	if err != nil || string(out) != "PASS  x\n" || script != "/repo/check.sh" || strings.Join(sargs, " ") != "/k/core /e.json /state" {
		t.Errorf("core check %q %v %s %v", out, err, script, sargs)
	}
	h.Cfg.CoreCheck = ""
	if _, err := h.RunCoreCheck(context.Background()); err == nil {
		t.Error("no check.sh must be an error")
	}
	// A real script: its exit status decides.
	dir := t.TempDir()
	p := filepath.Join(dir, "check.sh")
	_ = os.WriteFile(p, []byte("#!/bin/sh\necho \"FAIL  T4: $3\"\nexit 1\n"), 0o700)
	h.Script = nil
	h.Cfg.CoreCheck = p
	out, err = h.RunCoreCheck(context.Background())
	if err == nil || !strings.Contains(string(out), "FAIL  T4: /state") {
		t.Errorf("a failing check: %q %v", out, err)
	}
}
