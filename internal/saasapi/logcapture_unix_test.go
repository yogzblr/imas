//go:build !windows

package saasapi

import (
	"bytes"
	"io"
	"os"
	"syscall"
	"testing"
)

// captureStderr redirects the OS-level stderr file descriptor (fd 2) to a
// pipe for the duration of fn and returns everything written to it.
//
// internal/log captures os.Stderr once, at package init, inside a
// charmbracelet/log.Logger (see internal/log/log.go). Reassigning the
// os.Stderr *os.File variable afterward would not affect writes already
// routed through that captured value — it's a copy of the pointer, taken
// once. dup2'ing the underlying file descriptor instead redirects every
// writer targeting fd 2, regardless of which *os.File object it holds.
//
// It names fd 2 itself, not os.Stderr.Fd(): under `go test -json` the
// testing package points the os.Stderr variable at stdout (fd 1) after
// internal/log has taken the original, so os.Stderr.Fd() is not the
// descriptor the logger writes to there.
//
// This is a test-only, self-contained technique: it does not modify
// internal/log or any package outside internal/saasapi, per this task's
// scope.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	const stderrFd = 2
	savedFd, err := syscall.Dup(stderrFd)
	if err != nil {
		t.Fatalf("saving stderr fd: %v", err)
	}
	if err := syscall.Dup2(int(w.Fd()), stderrFd); err != nil {
		t.Fatalf("redirecting stderr fd: %v", err)
	}

	outCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outCh <- buf.String()
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Errorf("closing pipe writer: %v", err)
	}
	if err := syscall.Dup2(savedFd, stderrFd); err != nil {
		t.Errorf("restoring stderr fd: %v", err)
	}
	if err := syscall.Close(savedFd); err != nil {
		t.Errorf("closing saved stderr fd: %v", err)
	}

	return <-outCh
}
