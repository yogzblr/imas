package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/log"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/tenantconn"
)

// farmerBus is where FRun (farmer's outbound leg) gets a tenant's NATS
// connection: farmer's tenantconn.Registry, installed by cmd/farmer
// (SetFarmerConnGetter). Every send asks it again, so a tenant whose
// connection the idle sweeper closed is dialled again. Sprout never
// installs one.
var farmerBus tenantconn.Source

// SetFarmerConnGetter installs the getter FRun gets a tenant's connection
// from: cmd/farmer's tenant registry.
func SetFarmerConnGetter(g tenantconn.ConnGetter) {
	farmerBus.Set(g)
}

var envMutex sync.Mutex

// FRun runs a command on target's sprout, over tenantID's dedicated NATS
// connection (see SetFarmerConnGetter) — the sprout's own tenant, not
// necessarily whichever tenant happens to be "current" for the process.
// The request and its reply are sealed (sealed.go).
func FRun(tenantID string, target pki.KeyManager, cmdRun apitypes.CmdRun) (apitypes.CmdRun, error) {
	conn, err := farmerBus.Conn(tenantID)
	if err != nil {
		return apitypes.CmdRun{}, fmt.Errorf("cmd: %w", err)
	}
	return frun(conn, tenantID, target, cmdRun)
}

func SRun(cmd apitypes.CmdRun) (apitypes.CmdRun, error) {
	// A zero (or negative) timeout means "no deadline"; WithTimeout would
	// otherwise produce an already-expired context and kill the command
	// immediately.
	ctx := context.Background()
	cancel := context.CancelFunc(func() {})
	if cmd.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), cmd.Timeout)
	}
	defer cancel()
	envMutex.Lock()
	osPath := os.Getenv("PATH")
	newPath := ""
	if val, ok := cmd.Env["PATH"]; cmd.Path == "" && (!ok || (ok && val == "")) {
		_, err := exec.LookPath(cmd.Command)
		if err != nil {
			envMutex.Unlock()
			cmd.Error = err
			cmd.ErrCode = -1
			return cmd, err
		}
	} else {
		if cmd.Path != "" {
			newPath += cmd.Path + string(os.PathListSeparator)
		}
		if ok && val != "" {
			newPath += val + string(os.PathListSeparator)
		}
	}
	os.Setenv("PATH", newPath+osPath)
	command := exec.CommandContext(ctx, cmd.Command, cmd.Args...)
	os.Setenv("PATH", osPath)
	env := os.Environ()
	envMutex.Unlock()
	for key, val := range cmd.Env {
		env = append(env, key+"="+val)
	}
	command.Env = env

	if cmd.RunAs != "" {
		if err := setRunAs(command, cmd.RunAs); err != nil {
			// The command never ran. Without these two fields the reply
			// would carry exit code 0 and no error, and farmer would
			// report a refused run_as (every run_as on Windows) as a
			// success (UAT scenario C4).
			cmd.Error = err
			cmd.ErrCode = -1
			return cmd, err
		}
	}
	command.Dir = cmd.CWD

	// Output is only collected for the (sealed) reply. StreamTopic is
	// ignored: live streaming published output in plaintext, and FIX.1
	// removed it with the plaintext cmd.run path it was reachable from.
	var stdoutBuf, stderrBuf bytes.Buffer
	command.Stdout = &stdoutBuf
	command.Stderr = &stderrBuf
	timer := time.Now()
	err := command.Run()
	cmd.Duration = time.Since(timer)
	if err != nil {
		// Not err itself: a start error names the command, and the
		// sprout's log is shipped over the bus in plaintext while the
		// command itself travels sealed (sealed.go).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			log.Errorf("cmd.Run() failed with exit code %d", exitErr.ExitCode())
		} else {
			log.Errorf("cmd.Run() failed to start the command")
		}
	}
	cmd.Stdout = stdoutBuf.String()
	cmd.Stderr = stderrBuf.String()
	// ProcessState is nil if the process was never started (e.g. fork/exec
	// failure), so guard against a nil dereference.
	if command.ProcessState != nil {
		cmd.ErrCode = command.ProcessState.ExitCode()
	} else {
		cmd.ErrCode = -1
	}
	return cmd, err
}
