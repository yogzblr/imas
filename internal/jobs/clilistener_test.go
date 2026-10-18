package jobs

import (
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/yogzblr/imas/internal/cook"
)

func startTestNATSServer(t *testing.T) (*server.Server, *nats.Conn) {
	t.Helper()
	opts := &server.Options{
		Host: "127.0.0.1",
		Port: -1,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}

	conn, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		t.Fatalf("connect to test NATS: %v", err)
	}

	t.Cleanup(func() {
		conn.Close()
		ns.Shutdown()
	})

	return ns, conn
}

func TestNewCLIListener(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	listener := NewCLIListener(store, "UPUBKEY_TEST")
	if listener.store != store {
		t.Error("store mismatch")
	}
	if listener.userKey != "UPUBKEY_TEST" {
		t.Errorf("expected userKey UPUBKEY_TEST, got %s", listener.userKey)
	}
}

// Record keeps each forwarded step under its job.
func TestCLIListener_Record(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	listener := NewCLIListener(store, "UKEY1")
	listener.Record("sprout-test", "job-rec", cook.StepCompletion{
		ID: "step-1", CompletionStatus: cook.StepCompleted, Started: time.Now(), Duration: time.Second,
	})
	summary, _, err := store.GetJob("job-rec")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if summary.Total != 1 {
		t.Errorf("expected 1 step, got %d", summary.Total)
	}
}

func TestCLIListener_RecordJobInit(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	listener := NewCLIListener(store, "UKEY3")

	listener.RecordJobInit("init-jid", "web.deploy", []string{"sprout-a", "sprout-b"})

	metaA, err := store.GetJobMeta("init-jid")
	if err != nil {
		t.Fatalf("GetJobMeta for sprout-a: %v", err)
	}
	if metaA.Recipe != "web.deploy" {
		t.Errorf("expected recipe web.deploy, got %s", metaA.Recipe)
	}
	if metaA.UserKey != "UKEY3" {
		t.Errorf("expected user key UKEY3, got %s", metaA.UserKey)
	}
}

func TestCLIListener_RecordsFailedStepWithError(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	listener := NewCLIListener(store, "UKEY3")
	listener.Record("sprout-e", "jid-err", cook.StepCompletion{
		ID: "step-1", CompletionStatus: cook.StepFailed, Started: time.Now(), Error: errors.New("boom"),
	})
	summary, _, err := store.GetJob("jid-err")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if summary.Status != JobFailed || len(summary.Steps) != 1 {
		t.Fatalf("summary = %+v, want one failed step", summary)
	}
	if e := summary.Steps[0].Error; e == nil || e.Error() != "boom" {
		t.Errorf("Error = %v, want boom", e)
	}
}
