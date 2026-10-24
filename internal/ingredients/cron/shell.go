package cron

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/yogzblr/imas/internal/ingredients"
)

// execCommandContext is a test-overridable factory for exec.Cmd.
var execCommandContext = exec.CommandContext

// readUserCrontab returns the parsed lines of the given user's crontab.
// An empty user operates on the invoking process's own crontab (no -u
// flag). A user with no crontab yet installed returns an empty (non-error)
// result, matching crontab(1)'s own "no crontab for <user>" exit status.
func readUserCrontab(ctx context.Context, user string) ([]Line, error) {
	args := []string{"-l"}
	if user != "" {
		args = append(args, "-u", user)
	}
	cmd := execCommandContext(ctx, "crontab", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if isNoCrontabErr(stderr.String()) {
			return nil, nil
		}
		return nil, fmt.Errorf("crontab -l failed: %w", ingredients.CommandError("crontab", err, stdout.Bytes(), stderr.Bytes()))
	}
	return ParseCrontab(&stdout)
}

func isNoCrontabErr(stderr string) bool {
	return strings.Contains(strings.ToLower(stderr), "no crontab for")
}

// writeUserCrontab installs lines as the given user's crontab.
func writeUserCrontab(ctx context.Context, user string, lines []Line) error {
	var body bytes.Buffer
	if err := WriteCrontab(&body, lines); err != nil {
		return err
	}

	args := []string{}
	if user != "" {
		args = append(args, "-u", user)
	}
	args = append(args, "-")
	cmd := execCommandContext(ctx, "crontab", args...)
	cmd.Stdin = &body
	var stdout, stderr bytes.Buffer
	if cmd.Stdout == nil { // a test fake may collect it itself
		cmd.Stdout = &stdout
	}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab install failed: %w", ingredients.CommandError("crontab", err, stdout.Bytes(), stderr.Bytes()))
	}
	return nil
}
