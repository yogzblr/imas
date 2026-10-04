package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/taigrr/jety"
	"golang.org/x/term"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/shell"
	"github.com/yogzblr/imas/internal/sshpicker"
)

var (
	sshShell       string
	sshCohort      string
	sshIdleTimeout int
)

var sshCmd = &cobra.Command{
	Use:   "ssh [sprout]",
	Short: "Open an interactive shell on a sprout over the bus, sealed end to end",
	Long: `Open a remote interactive shell session on a sprout.

The session is relayed by farmer over the bus, with both legs sealed: no
direct SSH or network access to the sprout is required, and nothing on the
bus can read or change what is typed or printed. The request is sealed with
this CLI's box key to the tenant key it pins (tenantboxpub and tenantid in
the CLI config, copied out of band; see imas auth keygen). Your role must
grant shell on the sprout.

Farmer ends an idle session after its idle timeout (15 minutes unless
configured otherwise, 60 at most) and any session after its maximum
duration (8 hours). --idle-timeout can only make the idle timeout shorter.

Use -C/--cohort to target a cohort. If the cohort resolves to
multiple sprouts, an interactive picker is shown.

Press Ctrl-D or type 'exit' to end the session.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSSH,
}

func init() {
	sshCmd.Flags().StringVar(&sshShell, "shell", "", "absolute path of the shell to run (default: the sprout's, /bin/sh if its allow-list has it)")
	sshCmd.Flags().StringVarP(&sshCohort, "cohort", "C", "", "cohort name — resolve to sprouts and pick one")
	sshCmd.Flags().IntVar(&sshIdleTimeout, "idle-timeout", 0, "idle timeout in seconds, shorter than farmer's (0 = farmer's)")
	rootCmd.AddCommand(sshCmd)
}

func runSSH(cmd *cobra.Command, args []string) error {
	sproutID, err := resolveSSHTarget(args)
	if err != nil {
		return err
	}

	return connectSSH(sproutID)
}

// resolveSSHTarget determines which sprout to connect to based on args and flags.
func resolveSSHTarget(args []string) (string, error) {
	hasDirect := len(args) == 1
	hasCohort := sshCohort != ""

	if hasDirect && hasCohort {
		return "", fmt.Errorf("cannot specify both a sprout argument and --cohort (-C)")
	}
	if !hasDirect && !hasCohort {
		return "", fmt.Errorf("specify a sprout name or use --cohort (-C)")
	}

	if hasDirect {
		return args[0], nil
	}

	// Resolve cohort to sprout list.
	sprouts, err := client.ResolveCohort(sshCohort)
	if err != nil {
		return "", fmt.Errorf("cohort %q: %w", sshCohort, err)
	}

	if len(sprouts) == 1 {
		fmt.Fprintf(os.Stderr, "Cohort %q → %s\n", sshCohort, sprouts[0])
		return sprouts[0], nil
	}

	// Multiple sprouts — interactive picker.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("cohort %q has %d sprouts — interactive picker requires a terminal", sshCohort, len(sprouts))
	}

	return sshpicker.Run(sshCohort, sprouts)
}

// sshOpener sends the sealed c2f.shell.open request on the CLI's bus
// connection. Never plaintext; a reply not sealed to this CLI is an error.
func sshOpener(req shell.OpenRequest) (json.RawMessage, error) {
	return client.SealedRequest(client.NatsConn, payloadbox.PurposeShellOpen, "shell.open", req, client.NatsRequestTimeout)
}

// connectSSH opens a sealed shell session to sproutID and relays the
// terminal until it ends.
func connectSSH(sproutID string) error {
	tenantID := jety.GetString(pki.CLITenantIDKey)
	if tenantID == "" {
		return pki.ErrCLIBoxNotConfigured
	}
	userID, err := auth.GetPubkey()
	if err != nil {
		return err
	}
	stdinFd := int(os.Stdin.Fd())
	cols, rows := 80, 24
	if w, h, err := term.GetSize(stdinFd); err == nil {
		cols, rows = min(max(w, 1), payloadbox.MaxTerminalSize), min(max(h, 1), payloadbox.MaxTerminalSize)
	}

	done := make(chan struct{})
	defer close(done)
	var oldState *term.State
	defer func() {
		if oldState != nil {
			_ = term.Restore(stdinFd, oldState)
		}
	}()

	res, err := shell.RunClient(context.Background(), shell.ClientOptions{
		NC: client.NatsConn, Open: sshOpener, TenantID: tenantID, UserID: userID,
		SproutID: sproutID, Shell: sshShell, IdleTimeoutSec: sshIdleTimeout, Cols: cols, Rows: rows,
		Stdin: os.Stdin, Stdout: os.Stdout, Resize: watchTerminalResize(done),
		OnReady: func(r shell.OpenResult) {
			fmt.Fprintf(os.Stderr, "Connected to %s (session %s, sealed)\n", sproutID, r.SessionID)
			if term.IsTerminal(stdinFd) {
				if st, err := term.MakeRaw(stdinFd); err == nil {
					oldState = st
				}
			}
		},
	})
	if oldState != nil {
		_ = term.Restore(stdinFd, oldState)
		oldState = nil
	}
	if err != nil {
		return fmt.Errorf("shell.open: %w", err)
	}
	return sessionEnded(os.Stderr, res)
}

// closeReasonText explains a close reason to the user.
var closeReasonText = map[string]string{
	payloadbox.CloseClientClose:       "closed",
	payloadbox.CloseIdle:              "idle timeout",
	payloadbox.CloseMaxDuration:       "maximum session duration reached",
	payloadbox.ClosePeerLost:          "connection lost (nothing heard for 45 seconds)",
	payloadbox.CloseIntegrity:         "a frame was missing, out of order or altered on the way; the session was stopped",
	payloadbox.CloseRevoked:           "your shell access to this sprout was revoked",
	payloadbox.CloseKeySevered:        "the tenant key was severed",
	payloadbox.CloseFarmerShutdown:    "farmer is shutting down",
	payloadbox.CloseSproutShutdown:    "the sprout is shutting down",
	payloadbox.CloseSpawnFailed:       "the sprout couldn't start the shell",
	payloadbox.CloseShellDisabled:     "shell is disabled on this sprout (disableshell)",
	payloadbox.CloseShellNotAllowed:   "that shell isn't in the sprout's allow-list",
	payloadbox.CloseTooManySessions:   "the sprout has too many sessions open",
	payloadbox.CloseUnsupported:       "this sprout doesn't support shell (Windows)",
	payloadbox.CloseSproutUnreachable: "the sprout didn't answer",
	payloadbox.CloseSproutRefused:     "the sprout refused the sealed start (re-enroll it if it has no payload-encryption key)",
	payloadbox.CloseSproutNeedsUpdate: "the sprout runs a build without sealed shell; upgrade it",
}

// sessionEnded reports how a session ended: nil for a shell that exited
// with status 0, an error otherwise.
func sessionEnded(w *os.File, res *shell.ClientResult) error {
	if res.Reason == payloadbox.CloseExit {
		fmt.Fprintf(w, "\r\nSession ended (exit status %d).\n", res.ExitCode)
		if res.ExitCode != 0 {
			return fmt.Errorf("remote shell exited with status %d", res.ExitCode)
		}
		return nil
	}
	text, ok := closeReasonText[res.Reason]
	if !ok {
		text = res.Reason
	}
	fmt.Fprintf(w, "\r\nSession ended: %s.\n", text)
	if res.Reason == payloadbox.CloseClientClose {
		return nil
	}
	return errors.New("shell session ended: " + res.Reason)
}
