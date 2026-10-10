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

	nats "github.com/nats-io/nats.go"
	"github.com/yogzblr/imas/internal/log"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/pki"
)

// nc is the single connection a sprout process registers via
// RegisterNatsConn. Nothing reads it any more: SRun used it to stream a
// running command's output over the bus in plaintext, which FIX.1
// removed. The registration stays only because its caller
// (cmd/sprout/main.go) was outside FIX.1's scope; remove both together.
var nc *nats.Conn

func RegisterNatsConn(conn *nats.Conn) {
	nc = conn
}

// farmerConns holds farmer's own per-tenant NATS connections — the
// counterpart to nc above, but keyed by tenant since a single farmer
// process now holds one connection per tenant (see
// docs/design/imas-tenant-context-threading.md's Option A). Only FRun
// (farmer's outbound leg) reads this; sprout never calls
// RegisterFarmerNatsConn.
var (
	farmerConnMu sync.RWMutex
	farmerConns  = map[string]*nats.Conn{}
)

// RegisterFarmerNatsConn installs tenantID's NATS connection for FRun to
// dispatch commands through. Called once per tenant connection by
// cmd/farmer/main.go.
func RegisterFarmerNatsConn(tenantID string, conn *nats.Conn) {
	farmerConnMu.Lock()
	defer farmerConnMu.Unlock()
	farmerConns[tenantID] = conn
}

// UnregisterFarmerNatsConn removes tenantID's connection — called when
// that tenant is deprovisioned and its connection closed.
func UnregisterFarmerNatsConn(tenantID string) {
	farmerConnMu.Lock()
	defer farmerConnMu.Unlock()
	delete(farmerConns, tenantID)
}

func farmerConnFor(tenantID string) *nats.Conn {
	farmerConnMu.RLock()
	defer farmerConnMu.RUnlock()
	return farmerConns[tenantID]
}

var envMutex sync.Mutex

// FRun runs a command on target's sprout, over tenantID's dedicated NATS
// connection (see RegisterFarmerNatsConn) — the sprout's own tenant, not
// necessarily whichever tenant happens to be "current" for the process.
// The request and its reply are sealed (sealed.go).
func FRun(tenantID string, target pki.KeyManager, cmdRun apitypes.CmdRun) (apitypes.CmdRun, error) {
	conn := farmerConnFor(tenantID)
	if conn == nil {
		return apitypes.CmdRun{}, fmt.Errorf("cmd: no NATS connection registered for tenant %s", tenantID)
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
