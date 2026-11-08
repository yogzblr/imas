package farmerchart

import (
	"strings"
	"testing"
)

// The OpenBao bootstrap Job on HA OpenBao behind the spread Service (UAT
// HA run 42448281672): it waits for an active node, enables mounts so a
// re-run or a concurrent writer is success, waits out a KV mount's
// upgrade, and keeps a failed run (every pod, every log) until the next
// one replaces it.
func TestOpenBaoBootstrapHA(t *testing.T) {
	job := find(t, mustRender(t, "--set", "natsTrust.kvCopy.enabled=true",
		"--set", "openbaoBootstrap.farmerbus.enabled=true", "--set", "openbaoBootstrap.farmerbus.serviceAccountName=imas-dmz-nats-bus",
		"--set", "bus.namespace=imas-dmz"), "Job", "t-farmer-openbao-bootstrap")

	if _, ok := job["spec"].(obj)["ttlSecondsAfterFinished"]; ok {
		t.Error("ttlSecondsAfterFinished set: a failed run's pods and logs would be deleted")
	}
	ann := get(job, "metadata", "annotations").(obj)
	if ann["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded" ||
		ann["argocd.argoproj.io/hook-delete-policy"] != "BeforeHookCreation,HookSucceeded" {
		t.Errorf("delete policies %v: a failed run must be kept until the next one", ann)
	}

	prep := get(initContainer(t, job, "prepare"), "args", 0).(string)
	for _, want := range []string{
		"until bao_ready; do",
		`[ -n "$(bao read -field=leader_address sys/leader 2>/dev/null)" ]`,
		"\nenable_mount transit transit\n",
		"\nenable_kv secret\n",
		"\nenable_mount pki pki\n",
		"grep -q 'path is already in use'",
		"KV mount $1/ still answers that it is upgrading after ${kv_wait}s",
		"grep -q 'version:2'",
	} {
		if !strings.Contains(prep, want) {
			t.Errorf("prepare lacks %q", want)
		}
	}
	for _, gone := range []string{"has_mount secret || bao secrets enable", "until bao status >/dev/null 2>&1; do"} {
		if strings.Contains(prep, gone) {
			t.Errorf("prepare still has %q", gone)
		}
	}
	main := get(container(t, job, "bootstrap"), "args", 0).(string)
	if !strings.Contains(main, "until bao_ready; do") {
		t.Error("the bootstrap container doesn't wait for an active node")
	}
}
