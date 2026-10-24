package ingredients

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// maxStreamQuote bounds how much of each output stream an error quotes.
// The tail is kept: tools print the reason they failed last.
const maxStreamQuote = 2048

// CommandError is the error for a shelled-out command that failed. It
// quotes both output streams: tools disagree on which one carries the
// reason (Ubuntu's add-apt-repository prints its refusal on stdout and
// leaves stderr empty), so quoting only one can leave an empty message.
func CommandError(name string, err error, stdout, stderr []byte) error {
	return fmt.Errorf("%s: %w; stderr: %s; stdout: %s",
		name, err, quoteStream(stderr), quoteStream(stdout))
}

func quoteStream(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "(empty)"
	}
	if len(s) > maxStreamQuote {
		s = "..." + s[len(s)-maxStreamQuote:]
	}
	return s
}

// RunCommand runs cmd, capturing both output streams, and returns its
// standard output. On failure the error is a CommandError naming the
// command (cmd.Args[0]). cmd's Stdout and Stderr must be unset.
func RunCommand(cmd *exec.Cmd) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		name := cmd.Path
		if len(cmd.Args) > 0 {
			name = cmd.Args[0]
		}
		return stdout.Bytes(), CommandError(name, err, stdout.Bytes(), stderr.Bytes())
	}
	return stdout.Bytes(), nil
}
