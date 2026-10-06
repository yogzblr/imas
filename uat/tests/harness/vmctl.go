package harness

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ValuePrefix starts the lines a host script prints for the harness to
// read back: "__IMAS_UAT_<KEY>=<value>". Everything else vmctl.sh prints
// (Azure's run-command headers, stderr) is kept as output but never
// parsed.
const ValuePrefix = "__IMAS_UAT_"

// rcKey is the value the wrapper prints with the script's exit status.
const rcKey = "RC"

// VMCtl runs uat/access/vmctl.sh, the Access interface of the plan's
// Shared contract:
//
//	vmctl.sh <uat.json> restart|stop-sprout|start-sprout|run <vm> [command]
//
// It restarts a VM and waits until it is back, stops or starts the sprout
// service, or runs a command and prints its output and exit code. The
// harness never calls Azure itself, so the local rig (UAT.8) can supply a
// vmctl.sh of its own. Calls to one VM are serialized: Azure's
// run-command refuses a second command on a VM while one is running.
type VMCtl struct {
	// Path is vmctl.sh; UATFile is passed as its first argument.
	Path    string
	UATFile string
	// Timeout bounds one call (default 15 minutes: a Windows restart
	// through the Azure control plane is slow).
	Timeout time.Duration
	// Exec, when set, replaces running Path: it gets vmctl.sh's arguments
	// after the uat.json path and returns what it printed and its exit
	// code. For tests and in-process fakes.
	Exec func(ctx context.Context, args []string) ([]byte, int, error)

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewVMCtl returns a VMCtl.
func NewVMCtl(path, uatFile string) *VMCtl {
	return &VMCtl{Path: path, UATFile: uatFile, Timeout: 15 * time.Minute, locks: map[string]*sync.Mutex{}}
}

func (v *VMCtl) lock(vm string) func() {
	if v == nil {
		return func() {}
	}
	v.mu.Lock()
	if v.locks == nil {
		v.locks = map[string]*sync.Mutex{}
	}
	l, ok := v.locks[vm]
	if !ok {
		l = &sync.Mutex{}
		v.locks[vm] = l
	}
	v.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (v *VMCtl) call(ctx context.Context, args ...string) ([]byte, int, error) {
	if v != nil && v.Exec != nil {
		return v.Exec(ctx, args)
	}
	if v == nil || v.Path == "" {
		return nil, -1, fmt.Errorf("no vmctl.sh: set %s (run.sh defaults it to uat/access/vmctl.sh)", EnvVMCtl)
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.Path, append([]string{v.UATFile}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// On a timeout the script is killed, but a child it started (az,
	// ssh, sleep) can hold the output pipe open; stop waiting for it.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
		err = nil
	case err != nil && ctx.Err() == nil:
		return out.Bytes(), -1, fmt.Errorf("running %s %s: %w", v.Path, args[0], err)
	}
	if ctx.Err() != nil {
		return out.Bytes(), code, fmt.Errorf("vmctl.sh %s %s timed out after %s", args[0], args[1], timeout)
	}
	return out.Bytes(), code, nil
}

func (v *VMCtl) simple(ctx context.Context, verb, vm string) error {
	defer v.lock(vm)()
	out, code, err := v.call(ctx, verb, vm)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("vmctl.sh %s %s exited %d: %s", verb, vm, code, tail(out, 800))
	}
	return nil
}

// Restart restarts a VM and waits until it is back (vmctl.sh restart).
func (v *VMCtl) Restart(ctx context.Context, vm string) error { return v.simple(ctx, "restart", vm) }

// StopSprout stops the sprout service on a VM (vmctl.sh stop-sprout).
func (v *VMCtl) StopSprout(ctx context.Context, vm string) error {
	return v.simple(ctx, "stop-sprout", vm)
}

// StartSprout starts the sprout service on a VM (vmctl.sh start-sprout).
func (v *VMCtl) StartSprout(ctx context.Context, vm string) error {
	return v.simple(ctx, "start-sprout", vm)
}

// RunResult is what a host script printed.
type RunResult struct {
	// ExitCode is the script's own exit status (from the wrapper), not
	// vmctl.sh's.
	ExitCode int
	// Values are the "__IMAS_UAT_<KEY>=<value>" lines, by KEY. A key
	// printed twice keeps its last value.
	Values map[string]string
	// Output is everything vmctl.sh printed, values included.
	Output string
}

// Value returns a printed value and whether it was printed.
func (r *RunResult) Value(key string) (string, bool) {
	v, ok := r.Values[key]
	return v, ok
}

// Run runs a script on a VM through vmctl.sh run, as root on Linux (sh)
// or as SYSTEM on Windows (PowerShell). The script is wrapped so that its
// exit status is printed as a value; the error is set when vmctl.sh
// failed or the wrapper's status line never came back, not when the
// script itself exited non-zero (see ExitCode).
//
// Linux scripts run in a subshell and may exit. Windows scripts must not
// call exit (it would end the wrapper too); they set $global:LASTEXITCODE
// to report a failure.
func (v *VMCtl) Run(ctx context.Context, vm, family, script string) (*RunResult, error) {
	defer v.lock(vm)()
	out, code, err := v.call(ctx, "run", vm, WrapScript(family, script))
	if err != nil {
		return nil, err
	}
	res := ParseRunOutput(out)
	if _, ok := res.Values[rcKey]; !ok {
		return res, fmt.Errorf("vmctl.sh run %s exited %d and printed no exit status line: %s", vm, code, tail(out, 800))
	}
	return res, nil
}

// WrapScript wraps a host script so that its exit status is printed as
// __IMAS_UAT_RC=<n> after it, whatever it prints.
func WrapScript(family, script string) string {
	if family == FamilyWindows {
		return strings.Join([]string{
			"$ErrorActionPreference = 'Continue'",
			"$ProgressPreference = 'SilentlyContinue'",
			"$global:LASTEXITCODE = 0",
			"$__imasRc = 0",
			"try {",
			"  & {",
			script,
			"  }",
			"  if ($global:LASTEXITCODE -ne $null -and $global:LASTEXITCODE -ne 0) { $__imasRc = $global:LASTEXITCODE }",
			"} catch {",
			"  Write-Output ('" + ValuePrefix + "ERROR=' + ($_.Exception.Message -replace '[\\r\\n]+', ' '))",
			"  $__imasRc = 1",
			"}",
			"Write-Output ('" + ValuePrefix + rcKey + "=' + $__imasRc)",
		}, "\n")
	}
	return "(\n" + script + "\n)\necho \"" + ValuePrefix + rcKey + "=$?\"\n"
}

// ParseRunOutput reads the values out of vmctl.sh's output. Lines may
// carry Windows line endings or leading whitespace.
func ParseRunOutput(out []byte) *RunResult {
	res := &RunResult{Values: map[string]string{}, Output: string(out), ExitCode: -1}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		i := strings.Index(line, ValuePrefix)
		if i < 0 {
			continue
		}
		kv := line[i+len(ValuePrefix):]
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := kv[:eq]
		if strings.IndexFunc(key, func(r rune) bool {
			return (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_'
		}) >= 0 {
			continue
		}
		res.Values[key] = kv[eq+1:]
	}
	if rc, ok := res.Values[rcKey]; ok {
		if n, err := strconv.Atoi(rc); err == nil {
			res.ExitCode = n
		}
	}
	return res
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "..." + s[len(s)-n:]
	}
	return s
}
