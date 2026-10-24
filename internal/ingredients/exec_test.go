package ingredients

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestCommandErrorQuotesBothStreams(t *testing.T) {
	base := errors.New("exit status 1")
	err := CommandError("add-apt-repository", base, []byte("Unable to handle repository shortcut\n"), nil)
	want := "add-apt-repository: exit status 1; stderr: (empty); stdout: Unable to handle repository shortcut"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err, want)
	}
	if !errors.Is(err, base) {
		t.Error("CommandError should wrap the run error")
	}
}

func TestCommandErrorKeepsTail(t *testing.T) {
	long := strings.Repeat("x", 3*maxStreamQuote) + "E: the reason"
	err := CommandError("apt-get", errors.New("exit status 100"), nil, []byte(long))
	if !strings.Contains(err.Error(), "E: the reason") || len(err.Error()) > maxStreamQuote+200 {
		t.Errorf("long stream not cut to its tail: %d bytes", len(err.Error()))
	}
}

func TestRunCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	out, err := RunCommand(exec.Command("sh", "-c", "echo out"))
	if err != nil || strings.TrimSpace(string(out)) != "out" {
		t.Fatalf("got %q, %v", out, err)
	}
	_, err = RunCommand(exec.Command("sh", "-c", "echo to-stdout; echo to-stderr >&2; exit 3"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, s := range []string{"sh: exit status 3", "stderr: to-stderr", "stdout: to-stdout"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q lacks %q", err, s)
		}
	}
}
