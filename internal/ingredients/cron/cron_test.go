package cron

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// fakeCrontabFactory simulates the `crontab` binary against an in-memory
// per-user store, so present/absent can be exercised without touching a
// real crontab.
type fakeCrontabFactory struct {
	t     *testing.T
	store map[string]string // user (or "" for current user) -> crontab body
	calls [][]string
}

func newFakeCrontab(t *testing.T) *fakeCrontabFactory {
	return &fakeCrontabFactory{t: t, store: map[string]string{}}
}

func (f *fakeCrontabFactory) factory(ctx context.Context, name string, args ...string) *exec.Cmd {
	f.calls = append(f.calls, append([]string{name}, args...))
	user := ""
	listMode := false
	stdinMode := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u":
			i++
			if i < len(args) {
				user = args[i]
			}
		case "-l":
			listMode = true
		case "-":
			stdinMode = true
		}
	}

	switch {
	case listMode:
		body, ok := f.store[user]
		if !ok {
			// No crontab for this user: exit 1, stderr message crontab(1)
			// itself would print.
			return exec.CommandContext(ctx, "sh", "-c", `echo "no crontab for `+shQuote(user)+`" 1>&2; exit 1`)
		}
		return exec.CommandContext(ctx, "printf", "%s", body)
	case stdinMode:
		// writeUserCrontab feeds the new crontab body on Stdin; run `cat`
		// as a stand-in for `crontab -` and capture what it echoes to
		// Stdout back into the in-memory store. Reset first: this call
		// replaces the user's crontab wholesale, it doesn't append to it.
		f.store[user] = ""
		cmd := exec.CommandContext(ctx, "cat")
		cmd.Stdout = &storeWriter{store: f.store, user: user}
		return cmd
	default:
		f.t.Fatalf("unexpected crontab invocation: %v", args)
		return nil
	}
}

func shQuote(s string) string {
	if s == "" {
		return "(current user)"
	}
	return s
}

// storeWriter appends everything written to it into store[user], letting
// exec.Cmd's Stdout plumbing capture a subprocess's output directly into
// the fake crontab store.
type storeWriter struct {
	store map[string]string
	user  string
}

func (w *storeWriter) Write(p []byte) (int, error) {
	w.store[w.user] += string(p)
	return len(p), nil
}

func withMockCrontab(t *testing.T, f *fakeCrontabFactory) {
	t.Helper()
	orig := execCommandContext
	execCommandContext = f.factory
	t.Cleanup(func() { execCommandContext = orig })
}

func TestPresentAppliesNewEntry(t *testing.T) {
	f := newFakeCrontab(t)
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "present", params: map[string]interface{}{
		"name": "backup", "command": "/usr/bin/backup.sh", "hour": "3", "minute": "0",
	}}
	result, err := c.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(f.store[""], "IMAS_CRON_ID:backup") {
		t.Fatalf("expected identifier marker in installed crontab, got: %q", f.store[""])
	}
	if !strings.Contains(f.store[""], "/usr/bin/backup.sh") {
		t.Fatalf("expected command in installed crontab, got: %q", f.store[""])
	}
}

func TestPresentIsIdempotent(t *testing.T) {
	f := newFakeCrontab(t)
	f.store["root"] = "# IMAS_CRON_ID:backup\n0 3 * * * /usr/bin/backup.sh\n"
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "present", params: map[string]interface{}{
		"name": "backup", "command": "/usr/bin/backup.sh", "hour": "3", "minute": "0", "user": "root",
	}}
	result, err := c.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("expected no-op result, got %+v", result)
	}
}

func TestPresentUpdatesChangedSchedule(t *testing.T) {
	f := newFakeCrontab(t)
	f.store["root"] = "# IMAS_CRON_ID:backup\n0 3 * * * /usr/bin/backup.sh\n"
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "present", params: map[string]interface{}{
		"name": "backup", "command": "/usr/bin/backup.sh", "hour": "4", "minute": "30", "user": "root",
	}}
	result, err := c.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected changed=true for updated schedule, got %+v", result)
	}
	if !strings.Contains(f.store["root"], "30 4 * * *") {
		t.Fatalf("expected updated schedule in crontab, got %q", f.store["root"])
	}
}

func TestPresentTestModeDoesNotMutate(t *testing.T) {
	f := newFakeCrontab(t)
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "present", params: map[string]interface{}{
		"name": "backup", "command": "/usr/bin/backup.sh",
	}}
	result, err := c.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected changed=true, got %+v", result)
	}
	if _, ok := f.store[""]; ok {
		t.Fatal("test mode must not install a crontab")
	}
}

func TestPresentMissingCommand(t *testing.T) {
	c := Cron{id: "backup", method: "present", params: map[string]interface{}{"name": "backup"}}
	result, err := c.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for missing command")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestAbsentRemovesByIdentifier(t *testing.T) {
	f := newFakeCrontab(t)
	f.store[""] = "# IMAS_CRON_ID:backup\n0 3 * * * /usr/bin/backup.sh\n0 4 * * * /usr/bin/other.sh\n"
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "absent", params: map[string]interface{}{"name": "backup"}}
	result, err := c.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if strings.Contains(f.store[""], "backup.sh") {
		t.Fatalf("expected backup entry removed, got %q", f.store[""])
	}
	if !strings.Contains(f.store[""], "other.sh") {
		t.Fatalf("expected other entry to survive, got %q", f.store[""])
	}
}

func TestAbsentAlreadyGone(t *testing.T) {
	f := newFakeCrontab(t)
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "absent", params: map[string]interface{}{"name": "backup"}}
	result, err := c.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("expected no-op result, got %+v", result)
	}
}

func TestAbsentTestModeDoesNotMutate(t *testing.T) {
	f := newFakeCrontab(t)
	f.store[""] = "# IMAS_CRON_ID:backup\n0 3 * * * /usr/bin/backup.sh\n"
	withMockCrontab(t, f)

	c := Cron{id: "backup", method: "absent", params: map[string]interface{}{"name": "backup"}}
	result, err := c.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected changed=true, got %+v", result)
	}
	if !strings.Contains(f.store[""], "backup.sh") {
		t.Fatal("test mode must not mutate the crontab")
	}
}

func TestCronParseMissingRequired(t *testing.T) {
	c := Cron{}
	if _, err := c.Parse("t", "present", map[string]interface{}{"name": "backup"}); err == nil {
		t.Fatal("expected error for missing command")
	}
	if _, err := c.Parse("t", "present", map[string]interface{}{"command": "x"}); err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestCronUndefinedMethod(t *testing.T) {
	c := Cron{id: "t", method: "bogus", params: map[string]interface{}{}}
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("expected error for undefined method")
	}
	if _, err := c.Test(context.Background()); err == nil {
		t.Fatal("expected error for undefined method")
	}
}

func TestCronMethodsAndProperties(t *testing.T) {
	c := Cron{id: "t", method: "present", params: map[string]interface{}{"name": "backup", "command": "x"}}
	name, methods := c.Methods()
	if name != "cron" {
		t.Fatalf("expected ingredient name 'cron', got %q", name)
	}
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(methods))
	}
	props, err := c.Properties()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if props["name"] != "backup" {
		t.Fatalf("unexpected properties: %+v", props)
	}
}
