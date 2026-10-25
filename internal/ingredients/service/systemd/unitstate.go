//go:build linux

package systemd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/taigrr/systemctl"

	"github.com/yogzblr/imas/internal/ingredients"
)

// queryTimeout bounds one systemctl state query, so a query that hangs
// (a stuck D-Bus) fails the step quickly instead of holding it.
var queryTimeout = 30 * time.Second

// runSystemctl runs systemctl with args and returns its stdout, stderr and
// exit code; err is set only when it could not run or was killed (a
// non-zero exit is not an error here: the caller decides what it means).
// Replaceable in tests.
var runSystemctl = func(ctx context.Context, args ...string) (stdout, stderr string, code int, err error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), errb.String(), -1, fmt.Errorf("systemctl %s: %w after %s", strings.Join(args, " "), ctx.Err(), queryTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return out.String(), errb.String(), exitErr.ExitCode(), nil
	}
	if runErr != nil {
		return out.String(), errb.String(), -1, fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), runErr)
	}
	return out.String(), errb.String(), 0, nil
}

// The unit file states `systemctl is-enabled` prints (systemctl(1),
// "is-enabled": the table of states and exit codes, systemd 252 to 256).
// The exit code is 0 for enabled, enabled-runtime, alias, static,
// indirect, generated and transient, and non-zero for linked,
// linked-runtime, masked, masked-runtime, disabled and bad; not-found
// (systemd 246 and later print it) exits 4. A non-zero exit is therefore
// an answer, not a failure: the state is read from stdout whatever the
// exit code. Older systemd prints nothing for a unit with no file and
// says "No such file or directory" on stderr; that is not-found too.
const stateNotFound = "not-found"

var unitFileStates = map[string]bool{
	"enabled": true, "enabled-runtime": true, "linked": true, "linked-runtime": true,
	"alias": true, "masked": true, "masked-runtime": true, "static": true,
	"indirect": true, "disabled": true, "generated": true, "transient": true,
	"bad": true, stateNotFound: true,
}

// unitFileState returns the unit's state as `systemctl is-enabled` prints
// it. It replaces taigrr/systemctl's IsMasked, which ran `systemctl
// list-unit-files --state=masked` and failed on its exit status: that
// command exits 1 when no unit file is masked at all, as on a fresh
// AlmaLinux 9 (systemd 252), while Ubuntu ships masked units and never
// saw it (UAT I.service.masked / unmasked on AlmaLinux, Run 2 on rc.21:
// "step uat service masked: exit status 1" in test mode, before any
// change, and again in the test mode after the unmask).
func unitFileState(ctx context.Context, unit string, opts systemctl.Options) (string, error) {
	mode := "--system"
	if opts.UserMode {
		mode = "--user"
	}
	stdout, stderr, code, err := runSystemctl(ctx, "is-enabled", mode, unit)
	if err != nil {
		return "", err
	}
	state := strings.TrimSpace(stdout)
	if i := strings.IndexByte(state, '\n'); i >= 0 {
		state = strings.TrimSpace(state[:i])
	}
	if unitFileStates[state] {
		return state, nil
	}
	if state == "" && (strings.Contains(stderr, "No such file or directory") || strings.Contains(stderr, "not found")) {
		return stateNotFound, nil
	}
	return "", ingredients.CommandError("systemctl is-enabled "+unit,
		fmt.Errorf("exit status %d with no unit file state", code), []byte(stdout), []byte(stderr))
}

// isMaskedState: masked or masked-runtime. A unit with no file is not
// masked (masking it is still allowed: systemd links its name to
// /dev/null).
func isMaskedState(ctx context.Context, unit string, opts systemctl.Options) (bool, error) {
	state, err := unitFileState(ctx, unit, opts)
	if err != nil {
		return false, err
	}
	return state == "masked" || state == "masked-runtime", nil
}

// isEnabledState keeps taigrr/systemctl's meaning of "enabled" (enabled,
// enabled-runtime, alias, static, indirect, generated and transient), but
// a masked or linked unit is not enabled rather than an error, so
// service.disabled on a masked unit is already done and service.enabled
// gets systemctl's own refusal. A unit with no file is an error: neither
// enabling nor disabling it means anything.
func isEnabledState(ctx context.Context, unit string, opts systemctl.Options, _ ...string) (bool, error) {
	state, err := unitFileState(ctx, unit, opts)
	if err != nil {
		return false, err
	}
	switch state {
	case "enabled", "enabled-runtime", "alias", "static", "indirect", "generated", "transient":
		return true, nil
	case stateNotFound:
		return false, fmt.Errorf("unit %s: %w", unit, systemctl.ErrDoesNotExist)
	default:
		return false, nil
	}
}
