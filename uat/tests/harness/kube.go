package harness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kube runs kubectl against one hub's cluster (the ha tier, P24): the
// runner's kubeconfig for the hub, which reaches its API through the
// Bastion tunnel to the hub's API address (uat/k0s, "HA hubs"). Nothing
// it runs prints a secret: a Secret's value is read into memory
// (SecretValue) and handed to a pod on stdin (ExecIn), never on a command
// line.
type Kube struct {
	// Hub names the cluster in messages: "core" or "dmz".
	Hub string
	// Kubeconfig is passed as --kubeconfig.
	Kubeconfig string
	// Kubectl is the kubectl binary (default "kubectl").
	Kubectl string
	// Exec, when set, replaces running kubectl: it gets the arguments
	// after --kubeconfig and the stdin, and returns stdout, stderr and an
	// error for a non-zero exit. For tests.
	Exec func(ctx context.Context, args []string, stdin []byte) (stdout, stderr []byte, err error)
	// Forward, when set, replaces kubectl port-forward (PortForward). For
	// tests.
	Forward func(ctx context.Context, ns, pod string, port int) (local int, stop func(), err error)
}

// Run runs kubectl with args and returns its stdout. A non-zero exit is an
// error quoting the end of stderr.
func (k *Kube) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if k == nil || (k.Kubeconfig == "" && k.Exec == nil) {
		return nil, errors.New("no kubeconfig for this hub")
	}
	var stdout, stderr []byte
	var err error
	if k.Exec != nil {
		stdout, stderr, err = k.Exec(ctx, args, stdin)
	} else {
		// The kube tunnel and the login, renewed first when past
		// REFRESH_AFTER (W10).
		if ferr := sessionFreshness().Ensure(ctx); ferr != nil {
			fmt.Fprintf(os.Stderr, "uat harness: %s: %v; running kubectl anyway\n", k.Hub, ferr)
		}
		stdout, stderr, err = k.runKubectl(ctx, stdin, args)
	}
	if err != nil {
		return stdout, fmt.Errorf("%s: kubectl %s: %v: %s", k.Hub, describeArgs(args), err, tail(stderr, 600))
	}
	return stdout, nil
}

// runKubectl runs kubectl holding its kube tunnel's shared lock, so the
// session's supervisor never reopens the tunnel under it (W11); a refused
// connection while a kube tunnel is being reopened anyway is tried again
// for up to kubeReopenRetry.
func (k *Kube) runKubectl(ctx context.Context, stdin []byte, args []string) ([]byte, []byte, error) {
	bin := k.Kubectl
	if bin == "" {
		bin = "kubectl"
	}
	give := time.Now().Add(kubeReopenRetry)
	for {
		release := holdKubeTunnel(ctx, k.Kubeconfig)
		cmd := exec.CommandContext(ctx, bin, append([]string{"--kubeconfig", k.Kubeconfig}, args...)...)
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		cmd.WaitDelay = time.Second
		err := cmd.Run()
		release()
		if err == nil || !refusedOnTunnel(se.Bytes()) || !kubeReopening() || time.Now().After(give) || ctx.Err() != nil {
			return so.Bytes(), se.Bytes(), err
		}
		fmt.Fprintf(os.Stderr, "uat harness: %s: kubectl %s: connection refused while a kube tunnel is reopened; trying again\n", k.Hub, describeArgs(args))
		if serr := sleep(ctx, 2*time.Second); serr != nil {
			return so.Bytes(), se.Bytes(), err
		}
	}
}

// describeArgs is a kubectl command line for a message: the verb and its
// object, not every flag.
func describeArgs(args []string) string {
	if len(args) > 4 {
		args = args[:4]
	}
	return strings.Join(args, " ")
}

// JSON runs kubectl with args plus -o json and decodes its output into v.
func (k *Kube) JSON(ctx context.Context, v any, args ...string) error {
	out, err := k.Run(ctx, nil, append(args, "-o", "json")...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("%s: kubectl %s: decoding: %w", k.Hub, describeArgs(args), err)
	}
	return nil
}

// Pod is what the ha tier reads of a pod.
type Pod struct {
	Namespace string
	Name      string
	Node      string
	Phase     string
	// Ready is the pod's Ready condition.
	Ready bool
	// ReadySince is when the Ready condition last changed.
	ReadySince time.Time
	Deleting   bool
	Created    time.Time
	UID        string
	Labels     map[string]string
	// Containers are the containers' readiness, by name.
	Containers map[string]bool
	// Ports are the containers' named ports, by container then port name.
	Ports map[string]map[string]int
	// Env are the containers' literal environment values, by container.
	Env map[string]map[string]string
	// Owner is the kind of the pod's controller (ReplicaSet, StatefulSet,
	// DaemonSet, Job), empty when it has none.
	Owner string
}

type podJSON struct {
	Metadata struct {
		Namespace         string            `json:"namespace"`
		Name              string            `json:"name"`
		UID               string            `json:"uid"`
		Labels            map[string]string `json:"labels"`
		CreationTimestamp time.Time         `json:"creationTimestamp"`
		DeletionTimestamp *time.Time        `json:"deletionTimestamp"`
		OwnerReferences   []struct {
			Kind       string `json:"kind"`
			Controller bool   `json:"controller"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName   string `json:"nodeName"`
		Containers []struct {
			Name  string `json:"name"`
			Ports []struct {
				Name          string `json:"name"`
				ContainerPort int    `json:"containerPort"`
			} `json:"ports"`
			Env []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"env"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Conditions []struct {
			Type               string    `json:"type"`
			Status             string    `json:"status"`
			LastTransitionTime time.Time `json:"lastTransitionTime"`
		} `json:"conditions"`
		ContainerStatuses []struct {
			Name  string `json:"name"`
			Ready bool   `json:"ready"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (p podJSON) pod() Pod {
	out := Pod{
		Namespace: p.Metadata.Namespace, Name: p.Metadata.Name, UID: p.Metadata.UID,
		Node: p.Spec.NodeName, Phase: p.Status.Phase, Labels: p.Metadata.Labels,
		Created: p.Metadata.CreationTimestamp, Deleting: p.Metadata.DeletionTimestamp != nil,
		Containers: map[string]bool{}, Ports: map[string]map[string]int{}, Env: map[string]map[string]string{},
	}
	for _, o := range p.Metadata.OwnerReferences {
		if o.Controller {
			out.Owner = o.Kind
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" {
			out.Ready = c.Status == "True"
			out.ReadySince = c.LastTransitionTime
		}
	}
	for _, c := range p.Status.ContainerStatuses {
		out.Containers[c.Name] = c.Ready
	}
	for _, c := range p.Spec.Containers {
		ports := map[string]int{}
		for _, pt := range c.Ports {
			if pt.Name != "" {
				ports[pt.Name] = pt.ContainerPort
			}
		}
		out.Ports[c.Name] = ports
		env := map[string]string{}
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		out.Env[c.Name] = env
	}
	return out
}

// Pods lists the pods of ns matching a label selector ("" for every pod;
// ns "" for every namespace), sorted by name.
func (k *Kube) Pods(ctx context.Context, ns, selector string) ([]Pod, error) {
	args := []string{"get", "pods"}
	if ns == "" {
		args = append(args, "--all-namespaces")
	} else {
		args = append(args, "-n", ns)
	}
	if selector != "" {
		args = append(args, "-l", selector)
	}
	var list struct {
		Items []podJSON `json:"items"`
	}
	if err := k.JSON(ctx, &list, args...); err != nil {
		return nil, err
	}
	out := make([]Pod, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, it.pod())
	}
	sortPods(out)
	return out, nil
}

// PodsOnNode lists every pod scheduled on a node, in every namespace.
func (k *Kube) PodsOnNode(ctx context.Context, node string) ([]Pod, error) {
	var list struct {
		Items []podJSON `json:"items"`
	}
	if err := k.JSON(ctx, &list, "get", "pods", "--all-namespaces", "--field-selector", "spec.nodeName="+node); err != nil {
		return nil, err
	}
	out := make([]Pod, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, it.pod())
	}
	sortPods(out)
	return out, nil
}

// GetPod reads one pod; ok is false when it does not exist.
func (k *Kube) GetPod(ctx context.Context, ns, name string) (Pod, bool, error) {
	var p podJSON
	out, err := k.Run(ctx, nil, "get", "pod", "-n", ns, name, "--ignore-not-found", "-o", "json")
	if err != nil {
		return Pod{}, false, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return Pod{}, false, nil
	}
	if err := json.Unmarshal(out, &p); err != nil {
		return Pod{}, false, fmt.Errorf("%s: pod %s/%s: %w", k.Hub, ns, name, err)
	}
	return p.pod(), true, nil
}

func sortPods(p []Pod) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j-1].Namespace+"/"+p[j-1].Name > p[j].Namespace+"/"+p[j].Name; j-- {
			p[j-1], p[j] = p[j], p[j-1]
		}
	}
}

// DeletePod deletes a pod without waiting for it to go.
func (k *Kube) DeletePod(ctx context.Context, ns, name string) error {
	_, err := k.Run(ctx, nil, "delete", "pod", "-n", ns, name, "--wait=false")
	return err
}

// Node is what the ha tier reads of a node.
type Node struct {
	Name       string
	InternalIP string
	Ready      bool
}

// Nodes lists the cluster's nodes.
func (k *Kube) Nodes(ctx context.Context) ([]Node, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Addresses []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addresses"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := k.JSON(ctx, &list, "get", "nodes"); err != nil {
		return nil, err
	}
	var out []Node
	for _, it := range list.Items {
		n := Node{Name: it.Metadata.Name}
		for _, a := range it.Status.Addresses {
			if a.Type == "InternalIP" {
				n.InternalIP = a.Address
			}
		}
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" {
				n.Ready = c.Status == "True"
			}
		}
		out = append(out, n)
	}
	return out, nil
}

// Replicas reads a Deployment's or StatefulSet's spec.replicas and ready
// replicas. kind is "deployment" or "statefulset".
func (k *Kube) Replicas(ctx context.Context, ns, kind, name string) (want, ready int, err error) {
	var obj struct {
		Spec struct {
			Replicas *int `json:"replicas"`
		} `json:"spec"`
		Status struct {
			ReadyReplicas   int `json:"readyReplicas"`
			UpdatedReplicas int `json:"updatedReplicas"`
		} `json:"status"`
	}
	if err := k.JSON(ctx, &obj, "get", kind, "-n", ns, name); err != nil {
		return 0, 0, err
	}
	want = 1
	if obj.Spec.Replicas != nil {
		want = *obj.Spec.Replicas
	}
	return want, obj.Status.ReadyReplicas, nil
}

// Scale sets a workload's replicas.
func (k *Kube) Scale(ctx context.Context, ns, kind, name string, replicas int) error {
	_, err := k.Run(ctx, nil, "scale", "-n", ns, kind+"/"+name, "--replicas="+strconv.Itoa(replicas))
	return err
}

// ExecIn runs a command in a pod's container ("" for the default one),
// with stdin when it is not nil, and returns its stdout.
func (k *Kube) ExecIn(ctx context.Context, ns, pod, container string, stdin []byte, cmd ...string) ([]byte, error) {
	args := []string{"exec", "-n", ns, pod}
	if stdin != nil {
		args = append(args, "-i")
	}
	if container != "" {
		args = append(args, "-c", container)
	}
	args = append(append(args, "--"), cmd...)
	return k.Run(ctx, stdin, args...)
}

// SecretValue reads one key of a Secret, decoded. The value is never
// printed or put on a command line.
func (k *Kube) SecretValue(ctx context.Context, ns, name, key string) ([]byte, error) {
	var s struct {
		Data map[string][]byte `json:"data"`
	}
	if err := k.JSON(ctx, &s, "get", "secret", "-n", ns, name); err != nil {
		return nil, err
	}
	v, ok := s.Data[key]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("%s: Secret %s/%s has no key %s", k.Hub, ns, name, key)
	}
	return v, nil
}

// Apply applies a manifest (JSON or YAML) given on stdin.
func (k *Kube) Apply(ctx context.Context, manifest []byte) error {
	_, err := k.Run(ctx, manifest, "apply", "-f", "-")
	return err
}

// Patch applies a JSON patch to an object.
func (k *Kube) Patch(ctx context.Context, ns, kind, name string, ops []PatchOp) error {
	b, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	_, err = k.Run(ctx, nil, "patch", kind, name, "-n", ns, "--type", "json", "-p", string(b))
	return err
}

// PatchOp is one operation of a JSON patch (RFC 6902).
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// Delete deletes an object, ignoring one that is already gone.
func (k *Kube) Delete(ctx context.Context, ns, kind, name string) error {
	_, err := k.Run(ctx, nil, "delete", kind, name, "-n", ns, "--ignore-not-found", "--wait=true")
	return err
}

// RolloutRestart restarts a workload and waits for the rollout.
func (k *Kube) RolloutRestart(ctx context.Context, ns, kind, name string, timeout time.Duration) error {
	if _, err := k.Run(ctx, nil, "rollout", "restart", "-n", ns, kind+"/"+name); err != nil {
		return err
	}
	_, err := k.Run(ctx, nil, "rollout", "status", "-n", ns, kind+"/"+name, "--timeout", timeout.String())
	return err
}

// forwardLine is kubectl port-forward's first line for an IPv4 listener.
var forwardLine = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:([0-9]+) -> [0-9]+`)

// PortForward forwards a free local port on 127.0.0.1 to a pod's port
// (kubectl port-forward, which reaches the pod through the API server and
// the kubelet: no NetworkPolicy applies). stop ends it.
func (k *Kube) PortForward(ctx context.Context, ns, pod string, port int) (int, func(), error) {
	if k != nil && k.Forward != nil {
		return k.Forward(ctx, ns, pod, port)
	}
	if k == nil || k.Kubeconfig == "" {
		return 0, nil, errors.New("no kubeconfig for this hub")
	}
	bin := k.Kubectl
	if bin == "" {
		bin = "kubectl"
	}
	fctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(fctx, bin, "--kubeconfig", k.Kubeconfig, "port-forward", "-n", ns, "pod/"+pod,
		"--address", "127.0.0.1", ":"+strconv.Itoa(port))
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return 0, nil, err
	}
	var se bytes.Buffer
	cmd.Stderr = &se
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		return 0, nil, err
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = cmd.Wait()
		})
	}
	got := make(chan int, 1)
	go func() {
		sc := bufio.NewScanner(out)
		sent := false
		for sc.Scan() {
			if m := forwardLine.FindStringSubmatch(sc.Text()); m != nil && !sent {
				n, _ := strconv.Atoi(m[1])
				got <- n
				sent = true
			}
		}
		_, _ = io.Copy(io.Discard, out)
		if !sent {
			close(got)
		}
	}()
	select {
	case n, ok := <-got:
		if !ok {
			stop()
			return 0, nil, fmt.Errorf("%s: kubectl port-forward %s/%s %d ended: %s", k.Hub, ns, pod, port, tail(se.Bytes(), 400))
		}
		return n, stop, nil
	case <-time.After(30 * time.Second):
		stop()
		return 0, nil, fmt.Errorf("%s: kubectl port-forward %s/%s %d did not start within 30s: %s", k.Hub, ns, pod, port, tail(se.Bytes(), 400))
	case <-ctx.Done():
		stop()
		return 0, nil, ctx.Err()
	}
}
