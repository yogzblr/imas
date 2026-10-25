// Package winexec provides the shared exec.Command wrappers backing the
// PowerShell-only (G.8) and CLI-tool-only (G.9) Windows ingredient
// batches described in docs/design/imas-windows-parity-addendum.md.
//
// Both batches shell out rather than bind a Win32/COM API, so this
// package is intentionally thin: it follows the same
// exec.CommandContext + timeout pattern as the cmd ingredient
// (internal/ingredients/cmd/cmdRun.go) instead of introducing a second
// execution path.
package winexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/ingredients"
)

// DefaultTimeout bounds how long a single powershell.exe or CLI-tool
// invocation may run when no explicit timeout is given.
const DefaultTimeout = 60 * time.Second

// ParseTimeout parses a duration string as used by the "timeout"
// property on these ingredients, defaulting to DefaultTimeout for an
// empty string.
func ParseTimeout(s string) (time.Duration, error) {
	if s == "" {
		return DefaultTimeout, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q: %w", s, err)
	}
	return d, nil
}

// RunPowerShell runs script via powershell.exe -Command and returns its
// trimmed stdout. Errors include the process's stderr for diagnosis.
func RunPowerShell(ctx context.Context, script string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	command := exec.CommandContext(tctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		return out, ingredients.CommandError("powershell.exe", timeoutErr(tctx, err), stdout.Bytes(), stderr.Bytes())
	}
	return out, nil
}

// RunPowerShellJSON runs script — expected to end its pipeline with
// `| ConvertTo-Json -Compress` — and unmarshals stdout into v. An empty
// result (PowerShell prints nothing for $null) leaves v untouched.
func RunPowerShellJSON(ctx context.Context, script string, timeout time.Duration, v interface{}) error {
	out, err := RunPowerShell(ctx, script, timeout)
	if err != nil {
		return err
	}
	if out == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		return fmt.Errorf("parsing powershell.exe JSON output: %w (output: %s)", err, out)
	}
	return nil
}

// RunCLI runs a native Windows CLI tool (netsh, auditpol.exe,
// powercfg.exe, certutil.exe, ...) and returns its trimmed stdout.
func RunCLI(ctx context.Context, exe string, args []string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	command := exec.CommandContext(tctx, exe, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		return out, ingredients.CommandError(exe, timeoutErr(tctx, err), stdout.Bytes(), stderr.Bytes())
	}
	return out, nil
}

// timeoutErr hides the exit status of a process killed because tctx
// ended: on Windows the kill leaves exit code 1, which some CLI tools
// also use for "not found" (netsh), so a timed-out existence check must
// not read as one. ExitCode reports no code for the result.
func timeoutErr(tctx context.Context, err error) error {
	if ctxErr := tctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w (%v)", ctxErr, err)
	}
	return err
}

// ExitCode returns the exit code of the process behind err, an error
// from RunCLI or RunPowerShell, and whether there is one. There is none
// for a process that could not start, or that was killed because the
// timeout or the caller's context ended. A Windows exit code above
// 0x7fffffff (an HRESULT, as certutil.exe exits with) comes back as the
// uint32 code converted to int; compare it as uint32.
func ExitCode(err error) (int, bool) {
	if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return 0, false
	}
	var exitErr interface{ ExitCode() int }
	if !errors.As(err, &exitErr) {
		return 0, false
	}
	return exitErr.ExitCode(), true
}

// StringParam extracts a required string property, matching the
// validation shape cmd.Cmd.validate uses for its own "name" property.
func StringParam(params map[string]interface{}, key string) (string, bool) {
	v, ok := params[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// BoolParam extracts an optional bool property, defaulting when absent
// or of the wrong type.
func BoolParam(params map[string]interface{}, key string, def bool) bool {
	v, ok := params[key]
	if !ok {
		return def
	}
	b, ok := v.(bool)
	if !ok {
		return def
	}
	return b
}

// StringSliceParam extracts an optional []string property.
func StringSliceParam(params map[string]interface{}, key string) ([]string, bool) {
	v, ok := params[key]
	if !ok {
		return nil, false
	}
	s, ok := v.([]string)
	return s, ok
}

// StringParamOr extracts an optional string property, returning def when
// absent or of the wrong type.
func StringParamOr(params map[string]interface{}, key, def string) string {
	s, ok := StringParam(params, key)
	if !ok || s == "" {
		return def
	}
	return s
}

// PSQuote quotes s for safe interpolation into a PowerShell
// single-quoted string literal (the only escaping PowerShell single
// quotes need is doubling embedded quotes).
func PSQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// PSBool renders a Go bool as a PowerShell boolean literal.
func PSBool(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}
