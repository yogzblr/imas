package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeKube answers kubectl calls from a function of the joined arguments.
func fakeKube(hub string, answer func(args string, stdin []byte) (string, error)) (*Kube, *[]string) {
	var calls []string
	return &Kube{Hub: hub, Exec: func(_ context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		joined := strings.Join(args, " ")
		calls = append(calls, joined)
		out, err := answer(joined, stdin)
		if err != nil {
			return nil, []byte(err.Error()), err
		}
		return []byte(out), nil, nil
	}}, &calls
}

const podsJSON = `{"items":[
 {"metadata":{"namespace":"imas-dmz","name":"imas-dmz-nats-bus-1","uid":"u1","labels":{"app.kubernetes.io/component":"bus"},
   "creationTimestamp":"2026-10-13T10:00:00Z","ownerReferences":[{"kind":"StatefulSet","controller":true}]},
  "spec":{"nodeName":"uat-dmz-2","containers":[
   {"name":"farmerbus","ports":[{"name":"client","containerPort":5406}]},
   {"name":"loader","ports":[{"name":"loader-health","containerPort":8081}],
    "env":[{"name":"IMAS_LOADER_S3_ENDPOINT","value":"core.uat.imas.internal:9000"},{"name":"IMAS_LOADER_RECONCILE_INTERVAL","value":"30s"}]}]},
  "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True","lastTransitionTime":"2026-10-13T10:01:00Z"}],
   "containerStatuses":[{"name":"farmerbus","ready":true},{"name":"loader","ready":true}]}},
 {"metadata":{"namespace":"imas-dmz","name":"imas-dmz-nats-bus-0","uid":"u0","labels":{"app.kubernetes.io/component":"bus"},
   "deletionTimestamp":"2026-10-13T10:02:00Z"},
  "spec":{"nodeName":"uat-dmz-1","containers":[{"name":"farmerbus"}]},
  "status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}]}}
]}`

func TestKubePods(t *testing.T) {
	k, calls := fakeKube("dmz", func(args string, _ []byte) (string, error) { return podsJSON, nil })
	pods, err := k.Pods(context.Background(), "imas-dmz", Selector("bus"))
	if err != nil {
		t.Fatal(err)
	}
	if (*calls)[0] != "get pods -n imas-dmz -l app.kubernetes.io/component=bus -o json" {
		t.Errorf("call %q", (*calls)[0])
	}
	if len(pods) != 2 || pods[0].Name != "imas-dmz-nats-bus-0" || !pods[0].Deleting || pods[0].Ready {
		t.Fatalf("pods %+v", pods)
	}
	p := pods[1]
	if !p.Ready || p.Node != "uat-dmz-2" || p.Owner != "StatefulSet" || p.Ports["farmerbus"]["client"] != 5406 ||
		p.Ports[LoaderContainer]["loader-health"] != 8081 || !p.Containers["loader"] || p.UID != "u1" {
		t.Errorf("pod %+v", p)
	}
	if live := Live(pods); len(live) != 1 || live[0].Name != "imas-dmz-nats-bus-1" {
		t.Errorf("live %+v", live)
	}
	if port, err := AccountStorePort(p); err != nil || port != 9000 {
		t.Errorf("account store port %d %v", port, err)
	}
	if d, err := ReconcileInterval(p); err != nil || d != 30*time.Second {
		t.Errorf("reconcile %s %v", d, err)
	}
	p.Env[LoaderContainer]["IMAS_LOADER_RECONCILE_INTERVAL"] = "45"
	if d, _ := ReconcileInterval(p); d != 45*time.Second {
		t.Errorf("a bare number is seconds: %s", d)
	}
	delete(p.Env[LoaderContainer], "IMAS_LOADER_RECONCILE_INTERVAL")
	if d, _ := ReconcileInterval(p); d != 30*time.Second {
		t.Errorf("unset is the loader's 30 s: %s", d)
	}
	p.Env[LoaderContainer]["IMAS_LOADER_S3_ENDPOINT"] = "nohost"
	if _, err := AccountStorePort(p); err == nil {
		t.Error("an endpoint without a port must be an error")
	}
}

func TestKubeCommands(t *testing.T) {
	k, calls := fakeKube("core", func(args string, stdin []byte) (string, error) {
		switch {
		case strings.HasPrefix(args, "get secret"):
			return `{"data":{"root":"c2VjcmV0"}}`, nil
		case strings.HasPrefix(args, "exec"):
			return string(stdin), nil
		case strings.HasPrefix(args, "get pod -n x gone"):
			return "", nil
		case strings.HasPrefix(args, "get nodes"):
			return `{"items":[{"metadata":{"name":"uat-core-1"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.2.4"}],"conditions":[{"type":"Ready","status":"True"}]}}]}`, nil
		case strings.HasPrefix(args, "get deployment"):
			return `{"spec":{"replicas":3},"status":{"readyReplicas":2}}`, nil
		case strings.HasPrefix(args, "fail"):
			return "", errors.New("boom")
		}
		return "", nil
	})
	c := context.Background()
	v, err := k.SecretValue(c, "imas-core", "s", "root")
	if err != nil || string(v) != "secret" {
		t.Fatalf("secret %q %v", v, err)
	}
	if _, err := k.SecretValue(c, "imas-core", "s", "other"); err == nil {
		t.Error("a missing key must be an error")
	}
	out, err := k.ExecIn(c, "ns", "pod", "ctr", []byte("in"), "cat")
	if err != nil || string(out) != "in" || (*calls)[len(*calls)-1] != "exec -n ns pod -i -c ctr -- cat" {
		t.Errorf("exec %q %v %v", out, err, *calls)
	}
	if _, ok, err := k.GetPod(c, "x", "gone"); ok || err != nil {
		t.Errorf("a missing pod: %v %v", ok, err)
	}
	nodes, err := k.Nodes(c)
	if err != nil || len(nodes) != 1 || nodes[0].InternalIP != "10.0.2.4" || !nodes[0].Ready {
		t.Errorf("nodes %+v %v", nodes, err)
	}
	if want, ready, err := k.Replicas(c, "imas-core", "deployment", "imas-core-farmer"); want != 3 || ready != 2 || err != nil {
		t.Errorf("replicas %d %d %v", want, ready, err)
	}
	_ = k.Scale(c, "imas-core", "deployment", "imas-core-farmer", 0)
	_ = k.DeletePod(c, "ns", "p")
	_ = k.Patch(c, "ns", "networkpolicy", "np", []PatchOp{{Op: "remove", Path: "/spec/x"}})
	_ = k.RolloutRestart(c, "imas-uat", "deployment", "imas-uat-edge", time.Minute)
	got := strings.Join((*calls)[len(*calls)-5:], "\n")
	for _, want := range []string{
		"scale -n imas-core deployment/imas-core-farmer --replicas=0",
		"delete pod -n ns p --wait=false",
		`patch networkpolicy np -n ns --type json -p [{"op":"remove","path":"/spec/x"}]`,
		"rollout restart -n imas-uat deployment/imas-uat-edge",
		"rollout status -n imas-uat deployment/imas-uat-edge --timeout 1m0s",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no call %q in\n%s", want, got)
		}
	}
	if _, err := k.Run(c, nil, "fail"); err == nil || !strings.Contains(err.Error(), "core: kubectl fail: boom") {
		t.Errorf("a failing kubectl: %v", err)
	}
	if _, err := (&Kube{Hub: "x"}).Run(c, nil, "get"); err == nil {
		t.Error("no kubeconfig must be an error")
	}
}

func TestKubePortForward(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "kubectl")
	body := "#!/bin/sh\necho \"$@\" > " + filepath.Join(dir, "args") + "\necho 'Forwarding from 127.0.0.1:43211 -> 5406'\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	k := &Kube{Hub: "dmz", Kubeconfig: "/k", Kubectl: script}
	port, stop, err := k.PortForward(context.Background(), "imas-dmz", "imas-dmz-nats-bus-0", 5406)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	stop()
	if port != 43211 {
		t.Errorf("port %d", port)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if strings.TrimSpace(string(args)) != "--kubeconfig /k port-forward -n imas-dmz pod/imas-dmz-nats-bus-0 --address 127.0.0.1 :5406" {
		t.Errorf("args %q", args)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho 'error: pod not found' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	k.Kubectl = bad
	if _, _, err := k.PortForward(context.Background(), "ns", "p", 1); err == nil || !strings.Contains(err.Error(), "pod not found") {
		t.Errorf("a failed forward must say why: %v", err)
	}
}

func TestBusServerName(t *testing.T) {
	p := Pod{Name: "imas-dmz-nats-bus-0", Env: map[string]map[string]string{LoaderContainer: {"IMAS_LOADER_NATS_SERVER_NAME": "imas-dmz-nats-bus.imas-dmz.svc.cluster.local"}}}
	if n, err := BusServerName(p); err != nil || n != "imas-dmz-nats-bus.imas-dmz.svc.cluster.local" {
		t.Errorf("%q %v", n, err)
	}
	if _, err := BusServerName(Pod{Name: "x"}); err == nil {
		t.Error("a pod without the loader's server name must be an error")
	}
}
