package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// VMDiag collects a VM's side of a failure while it is fresh (W10): the
// end of the sprout's log and the failed jobs' records, through
// IMAS_UAT_DIAG_HOOK vm (uat/scripts/diagnostics.sh), which reads them
// through az vm run-command and never the test channel, so it works when
// the tunnel is what failed. They go into <report>/diagnostics/<vm>/.
// Each VM gets at most Max collections (each costs a minute or two of
// run-command), the first failures being the ones worth reading.
type VMDiag struct {
	// Hook is diagnostics.sh; Dir is <report>/diagnostics.
	Hook, Dir string
	// Max is the collections per VM (IMAS_UAT_VM_DIAG_MAX, default 4).
	Max int
	// Timeout bounds one collection (default 5 minutes).
	Timeout time.Duration
	// Exec, when set, replaces running Hook, for tests.
	Exec func(ctx context.Context, args []string) error

	mu    sync.Mutex
	count map[string]int
}

// Env names VMDiagFromEnv reads.
const (
	EnvDiagHook  = "IMAS_UAT_DIAG_HOOK"
	EnvReportDir = "IMAS_UAT_REPORT_DIR"
	EnvVMDiagMax = "IMAS_UAT_VM_DIAG_MAX"
)

// VMDiagFromEnv returns the run's VMDiag, or nil without a hook or a
// report directory (the local rig, a unit test).
func VMDiagFromEnv() *VMDiag {
	hook, dir := os.Getenv(EnvDiagHook), os.Getenv(EnvReportDir)
	if hook == "" || dir == "" {
		return nil
	}
	max := 4
	if n, err := fmt.Sscanf(os.Getenv(EnvVMDiagMax), "%d", &max); n != 1 || err != nil {
		max = 4
	}
	return &VMDiag{Hook: hook, Dir: filepath.Join(dir, "diagnostics"), Max: max}
}

var vmDiagName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Collect collects vm's side of a failure, with the records of jids (job
// ids of failed cooks; may be none). It returns where they went, or "" when
// nothing was collected (no VMDiag, the VM's quota used up, a bad name).
func (d *VMDiag) Collect(ctx context.Context, vm string, jids ...string) (string, error) {
	if d == nil || !vmDiagName.MatchString(vm) {
		return "", nil
	}
	d.mu.Lock()
	if d.count == nil {
		d.count = map[string]int{}
	}
	if d.Max >= 0 && d.count[vm] >= d.Max {
		d.mu.Unlock()
		return "", nil
	}
	d.count[vm]++
	d.mu.Unlock()
	out := filepath.Join(d.Dir, vm)
	args := []string{"vm", out, vm}
	for _, j := range jids {
		if jidRe.MatchString(j) {
			args = append(args, j)
		}
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if d.Exec != nil {
		return out, d.Exec(ctx, args)
	}
	cmd := exec.CommandContext(ctx, d.Hook, args...)
	cmd.WaitDelay = time.Second
	if b, err := cmd.CombinedOutput(); err != nil {
		return out, fmt.Errorf("%s vm %s: %v: %s", d.Hook, vm, err, tail(b, 400))
	}
	return out, nil
}

// jidRe is the shape of a job id the hook passes on to a VM's shell.
var jidRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
