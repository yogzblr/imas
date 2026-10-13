package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OperatorScriptName is uat/hub/core's script for saasapi's operator API
// (POST /v1/operator/fleet-releases through kubectl port-forward, with the
// operator token from the core state directory). It sits next to
// bind-tenant.sh and takes the same first three arguments (BindConfig).
const OperatorScriptName = "operator-release.sh"

// ErrNoOperatorAPI is returned when the harness has no way to reach the
// operator API: operator-release.sh needs what bind-tenant.sh needs.
var ErrNoOperatorAPI = errors.New("no way to reach saasapi's operator API: uat/hub/core/" + OperatorScriptName +
	" needs the core kubeconfig ($IMAS_UAT_CORE_KUBECONFIG), the endpoints file ($IMAS_UAT_ENDPOINTS), the state " +
	"directory and the uat/hub/core directory (harness.json's bind_tenant, or run.sh's defaults)")

// OperatorAnswer is the JSON line operator-release.sh post-altered prints:
// the operator API's HTTP status and its response body.
type OperatorAnswer struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// CanReachOperatorAPI reports whether PostAlteredRelease can run.
func (f *Fleet) CanReachOperatorAPI() bool { return f.OperatorExec != nil || f.Env.Bind.Enabled() }

// PostAlteredRelease registers version through the operator API as the
// release under test with an altered checksums.txt: version rewritten in
// every file name of the packages and of checksums.txt, and the release's
// own checksums.txt.sig, which therefore no longer verifies
// (operator-release.sh post-altered). saasapi never verifies the
// signature (signing design D20), so it accepts the pair; a sprout must
// refuse it (L5). The answer is returned whatever its status; err is set
// only when the script could not run or printed no answer.
func (f *Fleet) PostAlteredRelease(ctx context.Context, version string) (OperatorAnswer, error) {
	if !f.CanReachOperatorAPI() {
		return OperatorAnswer{}, ErrNoOperatorAPI
	}
	b := f.Env.Bind
	args := []string{b.Kubeconfig, b.Endpoints, b.StateDir, "post-altered", version}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var stdout, stderr []byte
	var runErr error
	if f.OperatorExec != nil {
		stdout, stderr, runErr = f.OperatorExec(cctx, args)
	} else {
		var so, se bytes.Buffer
		cmd := exec.CommandContext(cctx, filepath.Join(filepath.Dir(b.Script), OperatorScriptName), args...)
		cmd.Stdout, cmd.Stderr = &so, &se
		cmd.WaitDelay = time.Second
		runErr = cmd.Run()
		stdout, stderr = so.Bytes(), se.Bytes()
	}
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	var ans OperatorAnswer
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[len(lines)-1])), &ans); err != nil || ans.Status == 0 {
		return OperatorAnswer{}, fmt.Errorf("%s post-altered %s printed no answer (%v): %s", OperatorScriptName, version, runErr, tail(stderr, 600))
	}
	return ans, nil
}
