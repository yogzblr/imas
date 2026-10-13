package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Environment variables of the ha tier (HAConfig). $IMAS_UAT_CORE_KUBECONFIG
// (EnvCoreKubeconfig) is shared with bind-tenant.sh.
const (
	EnvDMZKubeconfig = "IMAS_UAT_DMZ_KUBECONFIG"
	EnvCoreChart     = "IMAS_UAT_CORE_CHART"
	EnvDMZChart      = "IMAS_UAT_DMZ_CHART"
	EnvCoreCheck     = "IMAS_UAT_CORE_CHECK"
	// EnvCoreCheckDefault is run.sh's uat/hub/core/check.sh.
	EnvCoreCheckDefault = "IMAS_UAT_CORE_CHECK_DEFAULT"
)

// HAConfig is how the ha tier reaches the hubs' clusters: harness.json's
// "ha", else the environment. The workflow sets the environment (its
// kubeconfigs and the charts uat/hub/core and uat/hub/dmz installed); the
// local rig may write harness.json instead.
type HAConfig struct {
	// CoreKubeconfig and DMZKubeconfig: $IMAS_UAT_CORE_KUBECONFIG and
	// $IMAS_UAT_DMZ_KUBECONFIG.
	CoreKubeconfig string `json:"core_kubeconfig,omitempty"`
	DMZKubeconfig  string `json:"dmz_kubeconfig,omitempty"`
	// CoreChart is the farmer chart the core hub was installed from
	// ($IMAS_UAT_CORE_CHART; default <state>/core/chart/farmer-<version>.tgz,
	// where install.sh pulled it). DMZChart is the nats chart of the DMZ
	// ($IMAS_UAT_DMZ_CHART; uat/hub/dmz's <workdir>/chart/nats-<version>.tgz).
	// HA3's helm upgrade uses them.
	CoreChart string `json:"core_chart,omitempty"`
	DMZChart  string `json:"dmz_chart,omitempty"`
	// CoreCheck is uat/hub/core/check.sh ($IMAS_UAT_CORE_CHECK, else
	// run.sh's default), which HA3 runs after the upgrade (design T4).
	CoreCheck string `json:"core_check,omitempty"`
}

func resolveHAConfig(set HAConfig, bind BindConfig, core *CoreJSON, stateRoot string) HAConfig {
	out := set
	or := func(v *string, env ...string) {
		for _, e := range env {
			if *v == "" {
				*v = os.Getenv(e)
			}
		}
	}
	or(&out.CoreKubeconfig, EnvCoreKubeconfig)
	if out.CoreKubeconfig == "" {
		out.CoreKubeconfig = bind.Kubeconfig
	}
	or(&out.DMZKubeconfig, EnvDMZKubeconfig)
	or(&out.CoreChart, EnvCoreChart)
	if out.CoreChart == "" && core != nil && core.Version != "" && stateRoot != "" {
		out.CoreChart = filepath.Join(stateRoot, "core", "chart", "farmer-"+core.Version+".tgz")
	}
	or(&out.DMZChart, EnvDMZChart)
	or(&out.CoreCheck, EnvCoreCheck, EnvCoreCheckDefault)
	return out
}

// The UAT hubs' fixed names: uat/hub/core/lib/common.sh and
// uat/hub/dmz/lib.sh (TestHANamesMatchTheHubScripts keeps them in step).
const (
	CoreNamespace      = "imas-core"
	CoreRelease        = "imas-core"
	UATNamespace       = "imas-uat"
	FarmerDeployment   = "imas-core-farmer"
	SaaSAPIDeployment  = "imas-core-farmer-saasapi"
	OpenBaoStatefulSet = "imas-core-openbao"
	PXCCluster         = "imas-core-pxc"
	PXCRootSecret      = "imas-core-pxc-secrets"
	ValkeyName         = "imas-core-valkey"
	KeycloakDeployment = "imas-uat-keycloak"
	EdgeDeployment     = "imas-uat-edge"

	DMZNamespace    = "imas-dmz"
	DMZRelease      = "imas-dmz"
	BusStatefulSet  = "imas-dmz-nats-bus"
	EnvoyDeployment = "imas-dmz-nats-envoy"

	// LoaderContainer is the bus pod's account loader sidecar
	// (deploy/helm/nats bus-statefulset.yaml); its health port is named
	// loader-health, 8081 by default (loader.healthPort).
	LoaderContainer     = "loader"
	DefaultLoaderHealth = 8081
	// BusContainer is the bus server's container; its client port is named
	// client (bus.ports.client).
	BusContainer = "farmerbus"
)

// ErrNotHA is the reason the ha tier skips on the single-node run.
var ErrNotHA = errors.New("the hubs run one node each: the ha tier needs the HA run (workflow input hub_nodes 3, uat/README.md \"HA run\")")

// HA is the ha tier's handle on the hubs: both clusters through kubectl,
// both hubs' VMs through vmctl.sh, and helm and the core check for HA3.
type HA struct {
	Fleet *Fleet
	Core  *Kube
	DMZ   *Kube
	Cfg   HAConfig
	// Helm, when set, replaces running helm: it gets the arguments and
	// returns combined output. For tests.
	Helm func(ctx context.Context, args []string) ([]byte, error)
	// Script, when set, replaces running a script (the core check). For
	// tests.
	Script func(ctx context.Context, path string, args []string) ([]byte, error)
	// HTTP fetches the loader's /status through a port-forward.
	HTTP *http.Client
}

// HA returns the fleet's HA handle, or ErrNotHA on single-node hubs, or an
// error naming what is missing to reach the clusters.
func (f *Fleet) HA() (*HA, error) {
	u := f.Env.UAT
	if !u.Core.HA() || !u.DMZ.HA() {
		return nil, ErrNotHA
	}
	c := f.Env.HA
	var miss []string
	if c.CoreKubeconfig == "" {
		miss = append(miss, "the core kubeconfig ($"+EnvCoreKubeconfig+")")
	}
	if c.DMZKubeconfig == "" {
		miss = append(miss, "the DMZ kubeconfig ($"+EnvDMZKubeconfig+")")
	}
	if len(miss) > 0 {
		return nil, fmt.Errorf("the ha tier cannot reach the hubs' clusters: no %s (harness.json's ha, or the environment)", strings.Join(miss, " and no "))
	}
	return &HA{
		Fleet: f,
		Core:  &Kube{Hub: "core", Kubeconfig: c.CoreKubeconfig},
		DMZ:   &Kube{Hub: "dmz", Kubeconfig: c.DMZKubeconfig},
		Cfg:   c,
		HTTP:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// NodeName maps a hub VM to its Kubernetes node: the node whose
// InternalIP is the VM's private address.
func (h *HA) NodeName(ctx context.Context, k *Kube, vm HubNode) (string, error) {
	nodes, err := k.Nodes(ctx)
	if err != nil {
		return "", err
	}
	for _, n := range nodes {
		if n.InternalIP == vm.PrivateIP || n.Name == vm.Name {
			return n.Name, nil
		}
	}
	return "", fmt.Errorf("%s: no node has VM %s's address %s", k.Hub, vm.Name, vm.PrivateIP)
}

// VMOfNode is NodeName's inverse over a hub's VMs.
func (h *HA) VMOfNode(ctx context.Context, k *Kube, hub Host, node string) (HubNode, error) {
	for _, vm := range hub.Nodes() {
		n, err := h.NodeName(ctx, k, vm)
		if err == nil && n == node {
			return vm, nil
		}
	}
	return HubNode{}, fmt.Errorf("%s: node %s is none of the hub's VMs", k.Hub, node)
}

// Live returns the pods that are not being deleted.
func Live(pods []Pod) []Pod {
	var out []Pod
	for _, p := range pods {
		if !p.Deleting {
			out = append(out, p)
		}
	}
	return out
}

// Selector is the label selector of the pods of a component.
func Selector(component string) string { return "app.kubernetes.io/component=" + component }

// WaitPodsReady waits until a workload's pods (by its selector) number
// want, are all Ready and none of them is one of gone (UIDs), or until
// timeout.
func WaitPodsReady(ctx context.Context, k *Kube, ns, selector string, want int, gone []string, timeout time.Duration) ([]Pod, error) {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		pods, err := k.Pods(ctx, ns, selector)
		if err == nil {
			live := Live(pods)
			ready := 0
			old := false
			for _, p := range live {
				if p.Ready {
					ready++
				}
				for _, g := range gone {
					if p.UID == g {
						old = true
					}
				}
			}
			if ready == want && len(live) == want && !old {
				return live, nil
			}
			last = fmt.Sprintf("%d pods, %d Ready (want %d)", len(live), ready, want)
			if old {
				last += ", the deleted pod still there"
			}
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: pods %s in %s not back within %s: %s", k.Hub, selector, ns, timeout, last)
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return nil, err
		}
	}
}

// --- the account loader's status ---------------------------------------------

// LoaderStatus is the account loader's /status (internal/accountloader
// Status): its state and counts, no JWTs.
type LoaderStatus struct {
	Ready          bool              `json:"ready"`
	State          string            `json:"status"`
	Applied        int               `json:"applied"`
	Target         int               `json:"target"`
	LastIndexToken string            `json:"lastIndexToken"`
	Counters       map[string]uint64 `json:"counters"`
}

// Pushes is the loader's push counter.
func (s LoaderStatus) Pushes() uint64 { return s.Counters["loader_pushes_total"] }

// S3Errors is the loader's object store error counter.
func (s LoaderStatus) S3Errors() uint64 { return s.Counters["loader_s3_errors_total"] }

// LoaderForward is a port-forward to a bus pod's loader health port.
type LoaderForward struct {
	h    *HA
	Pod  string
	addr string
	stop func()
}

// ForwardLoader forwards to a bus pod's loader health port (the bus
// NetworkPolicy admits nobody else to it).
func (h *HA) ForwardLoader(ctx context.Context, pod Pod) (*LoaderForward, error) {
	port := pod.Ports[LoaderContainer]["loader-health"]
	if port == 0 {
		port = DefaultLoaderHealth
	}
	local, stop, err := h.DMZ.PortForward(ctx, DMZNamespace, pod.Name, port)
	if err != nil {
		return nil, err
	}
	return &LoaderForward{h: h, Pod: pod.Name, addr: "127.0.0.1:" + strconv.Itoa(local), stop: stop}, nil
}

// Close ends the forward.
func (l *LoaderForward) Close() { l.stop() }

// Status reads /status.
func (l *LoaderForward) Status(ctx context.Context) (LoaderStatus, error) {
	var st LoaderStatus
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+l.addr+"/status", nil)
	if err != nil {
		return st, err
	}
	resp, err := l.h.HTTP.Do(req)
	if err != nil {
		return st, fmt.Errorf("loader of %s: %w", l.Pod, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("loader of %s: /status answered %d", l.Pod, resp.StatusCode)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("loader of %s: /status: %w", l.Pod, err)
	}
	return st, nil
}

// LoaderStatusOf reads one bus pod's loader status through a short-lived
// forward.
func (h *HA) LoaderStatusOf(ctx context.Context, pod Pod) (LoaderStatus, error) {
	f, err := h.ForwardLoader(ctx, pod)
	if err != nil {
		return LoaderStatus{}, err
	}
	defer f.Close()
	return f.Status(ctx)
}

// BusPods lists the bus's live pods.
func (h *HA) BusPods(ctx context.Context) ([]Pod, error) {
	pods, err := h.DMZ.Pods(ctx, DMZNamespace, Selector("bus"))
	return Live(pods), err
}

// BusAddr forwards to a bus pod's client port and returns the local
// address.
func (h *HA) BusAddr(ctx context.Context, pod Pod) (string, func(), error) {
	port := pod.Ports[BusContainer]["client"]
	if port == 0 {
		return "", nil, fmt.Errorf("bus pod %s has no port named client", pod.Name)
	}
	local, stop, err := h.DMZ.PortForward(ctx, DMZNamespace, pod.Name, port)
	if err != nil {
		return "", nil, err
	}
	return "127.0.0.1:" + strconv.Itoa(local), stop, nil
}

// ConnectEveryBusNode connects e to every bus pod and returns, by pod, nil
// for accepted or the error (ErrBusRefused for a refusal).
func (h *HA) ConnectEveryBusNode(ctx context.Context, e *Enrolment) (map[string]error, error) {
	pods, err := h.BusPods(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]error{}
	for _, p := range pods {
		addr, stop, err := h.BusAddr(ctx, p)
		if err != nil {
			return nil, err
		}
		out[p.Name] = BusConnect(ctx, addr, h.Fleet.Env.CAPool, e)
		stop()
	}
	return out, nil
}

// --- the stateful services ----------------------------------------------------

// StatefulReport is what CheckStateful found.
type StatefulReport struct {
	PXC, OpenBao, Valkey string
}

// CheckStateful checks, on the pods not on skipNode, that PXC, OpenBao and
// Valkey still serve: PXC's Galera cluster is Primary and ready with the
// expected size, every OpenBao pod is unsealed and exactly one is active,
// Valkey's pods answer and the primary has its connected replicas. want
// is the replicas each runs (2 while a node is stopped, 3 after).
func (h *HA) CheckStateful(ctx context.Context, skipNode string, want int) (StatefulReport, error) {
	var rep StatefulReport
	var errs []string
	// PXC.
	pw, err := h.Core.SecretValue(ctx, CoreNamespace, PXCRootSecret, "root")
	if err != nil {
		return rep, err
	}
	pxc, err := h.podsAway(ctx, "app.kubernetes.io/instance="+PXCCluster+",app.kubernetes.io/component=pxc", skipNode)
	if err != nil {
		return rep, err
	}
	if len(pxc) != want {
		errs = append(errs, fmt.Sprintf("PXC: %d Ready pods off the stopped node, want %d", len(pxc), want))
	}
	for _, p := range pxc {
		out, err := h.Core.ExecIn(ctx, CoreNamespace, p.Name, "pxc", append(pw, '\n'), "/bin/sh", "-ec",
			`IFS= read -r p || [ -n "$p" ]; MYSQL_PWD="$p" mysql -uroot -N -B -e "SHOW GLOBAL STATUS WHERE Variable_name IN ('wsrep_cluster_size','wsrep_cluster_status','wsrep_ready')"`)
		if err != nil {
			errs = append(errs, fmt.Sprintf("PXC %s: %v", p.Name, err))
			continue
		}
		st := parseTabbed(out)
		if st["wsrep_cluster_size"] != strconv.Itoa(want) || st["wsrep_cluster_status"] != "Primary" || st["wsrep_ready"] != "ON" {
			errs = append(errs, fmt.Sprintf("PXC %s: wsrep_cluster_size %s, wsrep_cluster_status %s, wsrep_ready %s (want %d, Primary, ON)",
				p.Name, st["wsrep_cluster_size"], st["wsrep_cluster_status"], st["wsrep_ready"], want))
		}
	}
	rep.PXC = fmt.Sprintf("%d nodes, Primary", len(pxc))
	// OpenBao.
	bao, err := h.podsAway(ctx, "app.kubernetes.io/name=openbao,app.kubernetes.io/instance="+CoreRelease+",component=server", skipNode)
	if err != nil {
		return rep, err
	}
	active := 0
	for _, p := range bao {
		out, err := h.Core.ExecIn(ctx, CoreNamespace, p.Name, "openbao", nil, "env", "BAO_ADDR=http://127.0.0.1:8200", "bao", "status", "-format=json")
		var st struct {
			Sealed bool `json:"sealed"`
			IsSelf bool `json:"is_self"`
		}
		// bao status exits 2 when sealed: the JSON still says why.
		if jerr := json.Unmarshal(out, &st); jerr != nil {
			errs = append(errs, fmt.Sprintf("OpenBao %s: bao status: %v", p.Name, firstErr(err, jerr)))
			continue
		}
		if st.Sealed {
			errs = append(errs, fmt.Sprintf("OpenBao %s is sealed", p.Name))
		}
		if st.IsSelf {
			active++
		}
	}
	if len(bao) != want || active != 1 {
		errs = append(errs, fmt.Sprintf("OpenBao: %d Ready pods off the stopped node with %d active, want %d with 1 active", len(bao), active, want))
	}
	rep.OpenBao = fmt.Sprintf("%d pods unsealed, 1 active", len(bao))
	// Valkey: the primary is pod 0 (uat/hub/core values-ha.yaml).
	vk, err := h.podsAway(ctx, "app.kubernetes.io/name=valkey,app.kubernetes.io/instance="+CoreRelease, skipNode)
	if err != nil {
		return rep, err
	}
	for _, p := range vk {
		out, err := h.Core.ExecIn(ctx, CoreNamespace, p.Name, "", nil, "/bin/sh", "-c",
			`valkey-cli ${VALKEY_PASSWORD:+-a "$VALKEY_PASSWORD" --no-auth-warning} ping`)
		if err != nil || strings.TrimSpace(string(out)) != "PONG" {
			errs = append(errs, fmt.Sprintf("Valkey %s does not answer PING: %v %s", p.Name, err, strings.TrimSpace(string(out))))
		}
		if p.Name == ValkeyName+"-0" {
			out, err := h.Core.ExecIn(ctx, CoreNamespace, p.Name, "", nil, "/bin/sh", "-c",
				`valkey-cli ${VALKEY_PASSWORD:+-a "$VALKEY_PASSWORD" --no-auth-warning} info replication`)
			info := parseColon(out)
			if err != nil || info["role"] != "master" || info["connected_slaves"] != strconv.Itoa(want-1) {
				errs = append(errs, fmt.Sprintf("Valkey primary %s: role %q, connected_slaves %q (want master, %d): %v", p.Name, info["role"], info["connected_slaves"], want-1, err))
			}
		}
	}
	if len(vk) != want {
		errs = append(errs, fmt.Sprintf("Valkey: %d Ready pods off the stopped node, want %d", len(vk), want))
	}
	rep.Valkey = fmt.Sprintf("%d pods answer", len(vk))
	if len(errs) > 0 {
		return rep, errors.New(strings.Join(errs, "; "))
	}
	return rep, nil
}

// podsAway lists the Ready core pods of a selector that are not on node.
func (h *HA) podsAway(ctx context.Context, selector, node string) ([]Pod, error) {
	pods, err := h.Core.Pods(ctx, CoreNamespace, selector)
	if err != nil {
		return nil, err
	}
	var out []Pod
	for _, p := range Live(pods) {
		if p.Node != node && p.Ready {
			out = append(out, p)
		}
	}
	return out, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// parseTabbed reads mysql -N -B output: name<TAB>value lines.
func parseTabbed(b []byte) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "\t"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// parseColon reads INFO output: name:value lines.
func parseColon(b []byte) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// --- choosing the node to stop -------------------------------------------------

// CoreStopNode picks the core VM HA2 stops: one hosting a farmer pod and a
// PXC, OpenBao and Valkey pod, but neither Valkey's primary (writes would
// wait for it) nor Keycloak (one pod, UAT only): uat/README.md "HA run".
func (h *HA) CoreStopNode(ctx context.Context) (HubNode, string, error) {
	pods, err := h.Core.Pods(ctx, "", "")
	if err != nil {
		return HubNode{}, "", err
	}
	byNode := map[string][]Pod{}
	for _, p := range Live(pods) {
		byNode[p.Node] = append(byNode[p.Node], p)
	}
	has := func(node, ns, prefix string) bool {
		for _, p := range byNode[node] {
			if p.Namespace == ns && strings.HasPrefix(p.Name, prefix) {
				return true
			}
		}
		return false
	}
	var why []string
	for _, vm := range h.Fleet.Env.UAT.Core.Nodes() {
		node, err := h.NodeName(ctx, h.Core, vm)
		if err != nil {
			return HubNode{}, "", err
		}
		switch {
		case has(node, CoreNamespace, ValkeyName+"-0"):
			why = append(why, vm.Name+" holds Valkey's primary")
		case has(node, UATNamespace, KeycloakDeployment+"-"):
			why = append(why, vm.Name+" holds Keycloak")
		case !hasFarmer(byNode[node]):
			why = append(why, vm.Name+" has no farmer pod")
		case !has(node, CoreNamespace, PXCCluster+"-pxc-") || !has(node, CoreNamespace, OpenBaoStatefulSet+"-") || !has(node, CoreNamespace, ValkeyName+"-"):
			why = append(why, vm.Name+" lacks a PXC, OpenBao or Valkey pod")
		default:
			return vm, node, nil
		}
	}
	return HubNode{}, "", fmt.Errorf("no core node fits: %s", strings.Join(why, "; "))
}

// hasFarmer reports whether a farmer pod is among pods (by its component
// label: saasapi's pods share the farmer Deployment's name prefix).
func hasFarmer(pods []Pod) bool {
	for _, p := range pods {
		if p.Namespace == CoreNamespace && p.Labels["app.kubernetes.io/component"] == "farmer" {
			return true
		}
	}
	return false
}

// DMZStopNode picks the DMZ VM HA2 stops: the last one hosting both a bus
// pod and an Envoy pod.
func (h *HA) DMZStopNode(ctx context.Context) (HubNode, string, error) {
	pods, err := h.DMZ.Pods(ctx, DMZNamespace, "")
	if err != nil {
		return HubNode{}, "", err
	}
	nodes := h.Fleet.Env.UAT.DMZ.Nodes()
	for i := len(nodes) - 1; i >= 0; i-- {
		node, err := h.NodeName(ctx, h.DMZ, nodes[i])
		if err != nil {
			return HubNode{}, "", err
		}
		bus, envoy := false, false
		for _, p := range Live(pods) {
			if p.Node != node {
				continue
			}
			switch p.Labels["app.kubernetes.io/component"] {
			case "bus":
				bus = true
			case "envoy":
				envoy = true
			}
		}
		if bus && envoy {
			return nodes[i], node, nil
		}
	}
	return HubNode{}, "", errors.New("no DMZ node holds both a bus pod and an Envoy pod")
}

// WaitNodeBack waits until a node is Ready, every pod on it is Ready (or
// finished), and no pod of the hub's namespaces is Pending, or until
// timeout.
func (h *HA) WaitNodeBack(ctx context.Context, k *Kube, node string, namespaces []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		last = ""
		nodes, err := k.Nodes(ctx)
		ready := false
		for _, n := range nodes {
			if n.Name == node {
				ready = n.Ready
			}
		}
		switch {
		case err != nil:
			last = err.Error()
		case !ready:
			last = "node " + node + " not Ready"
		default:
			pods, err := k.PodsOnNode(ctx, node)
			if err != nil {
				last = err.Error()
				break
			}
			var notReady []string
			for _, p := range Live(pods) {
				if p.Phase != "Succeeded" && !p.Ready {
					notReady = append(notReady, p.Namespace+"/"+p.Name)
				}
			}
			for _, ns := range namespaces {
				all, err := k.Pods(ctx, ns, "")
				if err != nil {
					last = err.Error()
					break
				}
				for _, p := range Live(all) {
					if p.Phase == "Pending" {
						notReady = append(notReady, p.Namespace+"/"+p.Name+" (Pending)")
					}
				}
			}
			if last == "" && len(notReady) == 0 {
				return nil
			}
			if last == "" {
				sort.Strings(notReady)
				last = "not Ready: " + strings.Join(notReady, ", ")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: node %s not back within %s: %s", k.Hub, node, timeout, last)
		}
		if err := sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}

// --- HA3: helm upgrade and the core check ----------------------------------------

// UpgradeAnnotation is the pod annotation HA3 changes.
const UpgradeAnnotation = "imas\\.io/uat-ha3"

// HelmUpgrade upgrades a hub's release with its values reused and the
// given --set-string values, waiting for every workload.
func (h *HA) HelmUpgrade(ctx context.Context, hub string, sets ...string) error {
	var kubeconfig, release, ns, chart string
	switch hub {
	case "core":
		kubeconfig, release, ns, chart = h.Cfg.CoreKubeconfig, CoreRelease, CoreNamespace, h.Cfg.CoreChart
	case "dmz":
		kubeconfig, release, ns, chart = h.Cfg.DMZKubeconfig, DMZRelease, DMZNamespace, h.Cfg.DMZChart
	default:
		return fmt.Errorf("unknown hub %q", hub)
	}
	if chart == "" {
		return fmt.Errorf("no chart for the %s hub's release (harness.json's ha, $%s or $%s)", hub, EnvCoreChart, EnvDMZChart)
	}
	args := []string{"upgrade", release, chart, "--kubeconfig", kubeconfig, "-n", ns, "--reuse-values", "--wait", "--timeout", "20m"}
	for _, s := range sets {
		args = append(args, "--set-string", s)
	}
	var out []byte
	var err error
	if h.Helm != nil {
		out, err = h.Helm(ctx, args)
	} else {
		cmd := exec.CommandContext(ctx, "helm", args...)
		cmd.WaitDelay = time.Second
		out, err = cmd.CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("helm upgrade %s: %v: %s", release, err, tail(out, 800))
	}
	return nil
}

// RunCoreCheck runs uat/hub/core/check.sh with the core kubeconfig, the
// endpoints file and the state directory, and fails unless it exits 0. Its
// output (one PASS or FAIL line per check, nothing secret) comes back.
func (h *HA) RunCoreCheck(ctx context.Context) ([]byte, error) {
	b := h.Fleet.Env.Bind
	if h.Cfg.CoreCheck == "" || h.Cfg.CoreKubeconfig == "" || b.Endpoints == "" || b.StateDir == "" {
		return nil, fmt.Errorf("cannot run uat/hub/core/check.sh: it needs its path ($%s), the core kubeconfig, the endpoints file ($%s) and the state directory", EnvCoreCheck, EnvEndpoints)
	}
	args := []string{h.Cfg.CoreKubeconfig, b.Endpoints, b.StateDir}
	if h.Script != nil {
		return h.Script(ctx, h.Cfg.CoreCheck, args)
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, h.Cfg.CoreCheck, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	return out.Bytes(), err
}

// --- HA5: keeping one bus pod's loader from the object store ----------------------

// PodNameLabel is the label the StatefulSet controller puts on each pod.
const PodNameLabel = "statefulset.kubernetes.io/pod-name"

// netpol is the part of a NetworkPolicy HA5 rewrites.
type netpol struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   map[string]any `json:"metadata"`
	Spec       struct {
		PodSelector map[string]any   `json:"podSelector"`
		PolicyTypes []string         `json:"policyTypes"`
		Ingress     []map[string]any `json:"ingress,omitempty"`
		Egress      []map[string]any `json:"egress,omitempty"`
	} `json:"spec"`
}

// BlockedPolicyName is the NetworkPolicy BlockAccountStore creates.
func BlockedPolicyName(pod string) string { return "imas-uat-ha5-" + pod }

// BlockAccountStore keeps one bus pod from opening a connection to the
// accounts bucket's endpoint, and nothing else: the chart's bus policy
// (deploy/helm/nats networkpolicy.yaml, which every bus pod matches) gets a
// matchExpressions excluding the pod, and a policy of the pod's own takes
// over with the same rules minus the egress to the account store's port.
// The routes policy still selects it, so the node stays routed (and not
// fenced). NetworkPolicies only stop new connections; HA5 cuts the open
// ones by restarting the core edge proxy that carries them. The returned
// function puts everything back.
func (h *HA) BlockAccountStore(ctx context.Context, pod string, storePort int) (func(context.Context) error, error) {
	var p netpol
	if err := h.DMZ.JSON(ctx, &p, "get", "networkpolicy", "-n", DMZNamespace, BusStatefulSet); err != nil {
		return nil, err
	}
	own, removed, err := blockedPolicy(p, pod, storePort)
	if err != nil {
		return nil, err
	}
	if removed == 0 {
		return nil, fmt.Errorf("NetworkPolicy %s has no egress rule to an address block on port %d (the account store)", BusStatefulSet, storePort)
	}
	manifest, err := json.Marshal(own)
	if err != nil {
		return nil, err
	}
	if err := h.DMZ.Apply(ctx, manifest); err != nil {
		return nil, err
	}
	excl := map[string]any{"key": PodNameLabel, "operator": "NotIn", "values": []string{pod}}
	if err := h.DMZ.Patch(ctx, DMZNamespace, "networkpolicy", BusStatefulSet, []PatchOp{
		{Op: "add", Path: "/spec/podSelector/matchExpressions", Value: []any{excl}},
	}); err != nil {
		_ = h.DMZ.Delete(ctx, DMZNamespace, "networkpolicy", BlockedPolicyName(pod))
		return nil, err
	}
	return func(ctx context.Context) error {
		err := h.DMZ.Patch(ctx, DMZNamespace, "networkpolicy", BusStatefulSet, []PatchOp{
			{Op: "remove", Path: "/spec/podSelector/matchExpressions"},
		})
		if derr := h.DMZ.Delete(ctx, DMZNamespace, "networkpolicy", BlockedPolicyName(pod)); err == nil {
			err = derr
		}
		return err
	}, nil
}

// blockedPolicy derives the pod's own policy from the chart's bus policy:
// selected by pod name, the egress rules that reach an address block on
// storePort dropped. It returns how many rules it dropped.
func blockedPolicy(chart netpol, pod string, storePort int) (netpol, int, error) {
	if len(chart.Spec.PolicyTypes) == 0 {
		return netpol{}, 0, errors.New("the bus NetworkPolicy has no policyTypes")
	}
	own := netpol{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}
	own.Metadata = map[string]any{
		"name": BlockedPolicyName(pod), "namespace": DMZNamespace,
		"labels": map[string]string{"app.kubernetes.io/part-of": "imas-uat", "imas.io/uat-scenario": "HA5"},
	}
	own.Spec.PodSelector = map[string]any{"matchLabels": map[string]string{PodNameLabel: pod}}
	own.Spec.PolicyTypes = chart.Spec.PolicyTypes
	own.Spec.Ingress = chart.Spec.Ingress
	removed := 0
	for _, rule := range chart.Spec.Egress {
		if reachesStore(rule, storePort) {
			removed++
			continue
		}
		own.Spec.Egress = append(own.Spec.Egress, rule)
	}
	return own, removed, nil
}

// reachesStore reports whether an egress rule allows an ipBlock on port.
func reachesStore(rule map[string]any, port int) bool {
	hasBlock := false
	if to, ok := rule["to"].([]any); ok {
		for _, peer := range to {
			if m, ok := peer.(map[string]any); ok && m["ipBlock"] != nil {
				hasBlock = true
			}
		}
	}
	if !hasBlock {
		return false
	}
	ports, _ := rule["ports"].([]any)
	for _, p := range ports {
		if m, ok := p.(map[string]any); ok {
			if n, ok := m["port"].(float64); ok && int(n) == port {
				return true
			}
		}
	}
	return false
}

// AccountStorePort reads the account store's port from a bus pod's loader
// environment (IMAS_LOADER_S3_ENDPOINT, host:port).
func AccountStorePort(p Pod) (int, error) {
	ep := p.Env[LoaderContainer]["IMAS_LOADER_S3_ENDPOINT"]
	i := strings.LastIndexByte(ep, ':')
	if i < 0 {
		return 0, fmt.Errorf("bus pod %s: the loader's IMAS_LOADER_S3_ENDPOINT %q has no port", p.Name, ep)
	}
	n, err := strconv.Atoi(ep[i+1:])
	if err != nil {
		return 0, fmt.Errorf("bus pod %s: IMAS_LOADER_S3_ENDPOINT %q: %w", p.Name, ep, err)
	}
	return n, nil
}

// ReconcileInterval reads a bus pod's loader reconcile interval
// (IMAS_LOADER_RECONCILE_INTERVAL; the loader's default 30 s when unset).
func ReconcileInterval(p Pod) (time.Duration, error) {
	v := p.Env[LoaderContainer]["IMAS_LOADER_RECONCILE_INTERVAL"]
	if v == "" {
		return 30 * time.Second, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("bus pod %s: IMAS_LOADER_RECONCILE_INTERVAL %q", p.Name, v)
	}
	return time.Duration(n) * time.Second, nil
}
