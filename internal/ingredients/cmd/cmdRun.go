package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/cook"
)

// needsShell reports whether cmd contains shell metacharacters that require
// interpretation by a shell (pipes, redirects, subshells, quotes, etc.) on
// this platform.
func needsShell(cmd string) bool { return needsShellFor(runtime.GOOS, cmd) }

// needsShellFor is needsShell for a given GOOS. A backslash is a shell
// escape on Unix, but the path separator on Windows, so it doesn't count
// there.
func needsShellFor(goos, cmd string) bool {
	chars := "|><$;`\"'&\\"
	if goos == "windows" {
		chars = "|><$;`\"'&"
	}
	return strings.ContainsAny(cmd, chars) ||
		strings.Contains(cmd, "&&") ||
		strings.Contains(cmd, "||") ||
		strings.Contains(cmd, "\n")
}

// shellCommand is the executable and arguments that run cmd through a shell
// on goos: /bin/sh -c on Unix, and powershell.exe on Windows, which has no
// /bin/sh (the Windows ingredients already use powershell.exe, and it
// parses its command line the way Go quotes it).
func shellCommand(goos, cmd string) (string, []string) {
	if goos == "windows" {
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", cmd}
	}
	return "/bin/sh", []string{"-c", cmd}
}

func (c Cmd) run(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result
	var err error

	cmd, ok := c.params["name"].(string)
	if !ok {
		result.Succeeded = false
		result.Failed = true
		return result, errors.New("invalid command; name must be a string")
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return result, errors.New("invalid command; name must not be empty")
	}

	var executable string
	var args []string

	if needsShell(cmd) {
		executable, args = shellCommand(runtime.GOOS, cmd)
	} else {
		splitCmd := strings.Fields(cmd)
		executable = splitCmd[0]
		args = splitCmd[1:]
	}

	runas := ""
	path := ""
	cwd := ""
	env := []string{}
	timeout := ""
	if runasInter, ok := c.params["runas"]; ok {
		runas, ok = runasInter.(string)
		if !ok {
			return result, fmt.Errorf("invalid runas %v; must be a string", runasInter)
		}
	}
	if pathInter, ok := c.params["path"]; ok {
		path, ok = pathInter.(string)
		if !ok {
			return result, fmt.Errorf("invalid path %v; must be a string", pathInter)
		}
	}
	if cwdInter, ok := c.params["cwd"]; ok {
		cwd, ok = cwdInter.(string)
		if !ok {
			return result, fmt.Errorf("invalid cwd %v; must be a string", cwdInter)
		}
	}
	if envInter, ok := c.params["env"]; ok {
		env, ok = envInter.([]string)
		if !ok {
			return result, fmt.Errorf("invalid env %v; must be a string slice like `k=v`", envInter)
		}
	}
	if timeoutInter, ok := c.params["timeout"]; ok {
		timeout, ok = timeoutInter.(string)
		if !ok {
			return result, fmt.Errorf("invalid timeout %v; must be a string", timeoutInter)
		}
	}
	// sanity check env vars
	envVars := map[string]string{}
	for _, envVar := range env {
		sp := strings.SplitN(envVar, "=", 2)
		if len(sp) != 2 {
			return result, fmt.Errorf("invalid env var %s; vars must be key=value pairs", envVar)
		}
		envVars[sp[0]] = sp[1]
	}
	var command *exec.Cmd
	if timeout != "" {
		ttimeout, parseErr := time.ParseDuration(timeout)
		if parseErr != nil {
			result.Succeeded = false
			result.Failed = true
			result.Changed = false
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("invalid timeout %s; must be a valid duration", timeout)))
			return result, errors.Join(parseErr, fmt.Errorf("invalid timeout %s; must be a valid duration", timeout))
		}
		timeoutCTX, cancel := context.WithTimeout(ctx, ttimeout)
		defer cancel()
		command = exec.CommandContext(timeoutCTX, executable, args...)
	} else {
		command = exec.CommandContext(ctx, executable, args...)
	}
	if err := setRunAs(command, runas); err != nil {
		return result, err
	}
	if path != "" {
		command.Path = path
	}
	if cwd != "" {
		command.Dir = cwd
	}
	if len(envVars) > 0 {
		command.Env = []string{}
		command.Env = append(command.Env, env...)
	}
	if test {
		// A cmd.run step acts on every cook, so test mode succeeds and
		// reports the change it would make. A step that isn't Succeeded is
		// failed by the cook engine, in test mode too.
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote("Command would have been run"))
		return result, nil
	}

	out, err := command.CombinedOutput()
	result.Notes = append(result.Notes,
		cook.SimpleNote(fmt.Sprintf("Command output: %s", string(out))),
	)

	if err != nil {
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("Command failed: %s", err.Error())))
	}
	if command.ProcessState.ExitCode() != 0 {
		result.Succeeded = false
		result.Failed = true
	} else {
		result.Succeeded = true
		result.Failed = false
		// The command ran: that is a change, as Salt's cmd.run reports it.
		result.Changed = true
	}
	return result, nil
}
