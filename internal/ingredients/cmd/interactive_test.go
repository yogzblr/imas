package cmd

import (
	"testing"
	"time"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/pki"
)

func TestRegisterNatsConn(t *testing.T) {
	// RegisterNatsConn with nil should not panic
	RegisterNatsConn(nil)
	if nc != nil {
		t.Error("expected nc to be nil")
	}
}

func TestSRunSimpleCommand(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"hello_srun"},
		Timeout: 5 * time.Second,
		Env:     apitypes.EnvVar{},
	}
	result, err := SRun(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
	if result.Stdout == "" {
		t.Error("expected non-empty stdout")
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestSRunWithCwd(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "pwd",
		CWD:     "/tmp",
		Timeout: 5 * time.Second,
		Env:     apitypes.EnvVar{},
	}
	result, err := SRun(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
}

func TestSRunWithEnv(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo $IMAS_TEST_SRUN"},
		Timeout: 5 * time.Second,
		Env: apitypes.EnvVar{
			"IMAS_TEST_SRUN": "test_value",
		},
	}
	result, err := SRun(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
}

func TestSRunWithCustomPath(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"path_test"},
		Path:    "/usr/bin",
		Timeout: 5 * time.Second,
		Env:     apitypes.EnvVar{},
	}
	result, err := SRun(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
}

func TestSRunWithEnvPath(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"env_path_test"},
		Timeout: 5 * time.Second,
		Env: apitypes.EnvVar{
			"PATH": "/usr/bin:/bin",
		},
	}
	result, err := SRun(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
}

func TestSRunNonexistentCommand(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "nonexistent_cmd_xyz_999",
		Timeout: 5 * time.Second,
		Env:     apitypes.EnvVar{},
	}
	_, err := SRun(cmd)
	if err == nil {
		t.Error("expected error for nonexistent command")
	}
}

func TestSRunFailingCommand(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "false",
		Timeout: 5 * time.Second,
		Env:     apitypes.EnvVar{},
	}
	result, err := SRun(cmd)
	if err == nil {
		t.Log("'false' command may or may not return error depending on implementation")
	}
	if result.ErrCode == 0 {
		t.Error("expected non-zero exit code for 'false'")
	}
}

func TestSRunNonexistentRunas(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"hello"},
		RunAs:   "nonexistent_user_xyz_9999",
		Timeout: 5 * time.Second,
		Env:     apitypes.EnvVar{},
	}
	_, err := SRun(cmd)
	if err == nil {
		t.Error("expected error for nonexistent runas user")
	}
}

func TestSRunWithStreamTopic(t *testing.T) {
	// Without a NATS connection, stream topic should be ignored gracefully
	cmd := apitypes.CmdRun{
		Command:     "echo",
		Args:        []string{"stream_test"},
		Timeout:     5 * time.Second,
		Env:         apitypes.EnvVar{},
		StreamTopic: "imas.test.output",
	}
	result, err := SRun(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
}

func TestSRunWithEmptyPathInEnv(t *testing.T) {
	cmd := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"empty_path"},
		Timeout: 5 * time.Second,
		Env: apitypes.EnvVar{
			"PATH": "",
		},
	}
	result, err := SRun(cmd)
	// With empty PATH in env but no cmd.Path, the existing PATH should be used
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ErrCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ErrCode)
	}
}

func TestFRunWithoutNATSConnection(t *testing.T) {
	// FRun requires a farmer connection registered for the given tenant —
	// with none registered, it returns an error rather than dereferencing a
	// nil connection.
	cmd := apitypes.CmdRun{
		Command: "echo",
		Args:    []string{"hello"},
		Timeout: 5 * time.Second,
	}

	target := pki.KeyManager{SproutID: "test-sprout"}
	_, err := FRun("t_no_such_tenant", target, cmd)
	if err == nil {
		t.Error("expected error for a tenant with no registered NATS connection")
	}
}
