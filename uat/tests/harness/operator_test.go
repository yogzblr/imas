package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// operator-release.sh post-altered: the arguments it is given, the script
// found next to bind-tenant.sh, the answer parsed whatever its status, and
// a run that prints no answer.
func TestPostAlteredRelease(t *testing.T) {
	f, _ := fakeFleet(t)
	f.Env.Bind = BindConfig{}
	if f.CanReachOperatorAPI() {
		t.Fatal("no bind config and no OperatorExec, but the operator API is reachable")
	}
	if _, err := f.PostAlteredRelease(ctx(t), "v0.1.1-uat.altered"); !errors.Is(err, ErrNoOperatorAPI) {
		t.Fatalf("without a configuration: %v", err)
	}

	// The real path: the script next to bind-tenant.sh, run with the
	// common arguments. Exit 1 with an answer (a refusal) is still an answer.
	dir := t.TempDir()
	script := filepath.Join(dir, OperatorScriptName)
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$(dirname \"$0\")/args\"\necho '[uat/hub/core] noise' >&2\n" +
		"echo '{\"status\":422,\"body\":{\"error\":\"invalid_checksums\"}}'\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	f.Env.Bind = BindConfig{Script: filepath.Join(dir, "bind-tenant.sh"), Kubeconfig: "/k", Endpoints: "/e", StateDir: "/s"}
	ans, err := f.PostAlteredRelease(ctx(t), "v0.1.1-uat.altered")
	if err != nil {
		t.Fatal(err)
	}
	if ans.Status != 422 || !strings.Contains(string(ans.Body), "invalid_checksums") {
		t.Errorf("answer %+v", ans)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if got := strings.Fields(string(args)); strings.Join(got, " ") != "/k /e /s post-altered v0.1.1-uat.altered" {
		t.Errorf("arguments %q", got)
	}

	// OperatorExec: a 201 answer after log lines; no answer is an error.
	f.OperatorExec = func(_ context.Context, args []string) ([]byte, []byte, error) {
		return []byte("note\n{\"status\":201,\"body\":{\"version\":\"" + args[4] + "\",\"created\":1}}\n"), nil, nil
	}
	if ans, err := f.PostAlteredRelease(ctx(t), "v0.2.1-uat.altered"); err != nil || ans.Status != 201 || !strings.Contains(string(ans.Body), "v0.2.1-uat.altered") {
		t.Errorf("OperatorExec answer %+v, %v", ans, err)
	}
	f.OperatorExec = func(context.Context, []string) ([]byte, []byte, error) {
		return []byte("not json\n"), []byte("kubectl port-forward failed"), errors.New("exit status 1")
	}
	if _, err := f.PostAlteredRelease(ctx(t), "v0.2.1-uat.altered"); err == nil || !strings.Contains(err.Error(), "port-forward failed") {
		t.Errorf("no answer: %v", err)
	}
}
