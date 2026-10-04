package cmd

// Tests for the SSH picker model are in internal/sshpicker/picker_test.go
// to avoid the package init() in root.go which requires TLS setup. The
// sealed session itself is tested end to end in internal/natsapi's
// shell_test.go, through shell.RunClient, which connectSSH wraps.

import (
	"os"
	"testing"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/shell"
)

func TestResolveSSHTarget_BothArgAndCohort(t *testing.T) {
	// Save and restore global flag state.
	old := sshCohort
	defer func() { sshCohort = old }()

	sshCohort = "web-servers"
	_, err := resolveSSHTarget([]string{"sprout-1"})
	if err == nil {
		t.Fatal("expected error when both arg and --cohort are provided")
	}
}

func TestResolveSSHTarget_NeitherArgNorCohort(t *testing.T) {
	old := sshCohort
	defer func() { sshCohort = old }()

	sshCohort = ""
	_, err := resolveSSHTarget(nil)
	if err == nil {
		t.Fatal("expected error when neither arg nor --cohort is provided")
	}
}

func TestResolveSSHTarget_DirectArg(t *testing.T) {
	old := sshCohort
	defer func() { sshCohort = old }()

	sshCohort = ""
	id, err := resolveSSHTarget([]string{"my-sprout"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "my-sprout" {
		t.Errorf("got %q, want %q", id, "my-sprout")
	}
}

func TestSessionEnded(t *testing.T) {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if err := sessionEnded(devnull, &shell.ClientResult{Reason: payloadbox.CloseExit}); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	if err := sessionEnded(devnull, &shell.ClientResult{Reason: payloadbox.CloseExit, ExitCode: 2}); err == nil {
		t.Error("exit 2 reported as success")
	}
	if err := sessionEnded(devnull, &shell.ClientResult{Reason: payloadbox.CloseClientClose}); err != nil {
		t.Errorf("client close: %v", err)
	}
	for _, r := range []string{payloadbox.CloseIntegrity, payloadbox.CloseRevoked, payloadbox.CloseShellDisabled, payloadbox.CloseKeySevered} {
		if err := sessionEnded(devnull, &shell.ClientResult{Reason: r}); err == nil {
			t.Errorf("%s reported as success", r)
		}
		if closeReasonText[r] == "" {
			t.Errorf("no text for %s", r)
		}
	}
}

// connectSSH refuses to start without a pinned tenant: the CLI never
// fetches the tenant key over the bus.
func TestConnectSSHNeedsPinnedTenant(t *testing.T) {
	if err := connectSSH("web-01"); err == nil {
		t.Fatal("connected without tenantid/tenantboxpub")
	}
}
