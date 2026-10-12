package pki

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	log "github.com/yogzblr/imas/internal/log"
)

// syncBuffer is a bytes.Buffer safe for the logger's writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog sends the terminal log to a buffer for the test, in the JSON
// format the farmer chart ships to the log platform.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	log.SetOutput(buf)
	log.SetFormat(log.FormatJSON)
	t.Cleanup(func() {
		log.SetOutput(nil)
		log.SetFormat(log.FormatText)
	})
	return buf
}

// The publisher's two log fields (deploy/helm/farmer/README.md, "Account
// publisher log fields"), which the log platform alerts on in place of
// metrics: each failure logs its field with the count.
func TestAccountPublisherLogFields(t *testing.T) {
	t.Run("bucket write failed, ordinary update", func(t *testing.T) {
		e := newPubEnv(t)
		e.srv.Deny(func(op, _ string) bool { return op == http.MethodPut })
		buf := captureLog(t)
		pub := newAccount(t)
		if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, false)); err == nil {
			t.Fatal("a failed bucket write returned nil")
		}
		if !strings.Contains(buf.String(), logFieldBucketWriteFailed+"=1") {
			t.Fatalf("no %s=1 in the log:\n%s", logFieldBucketWriteFailed, buf)
		}
	})
	t.Run("bucket write failed, lock-out pushed anyway", func(t *testing.T) {
		e := newPubEnv(t)
		e.srv.Deny(func(op, _ string) bool { return op == http.MethodPut })
		buf := captureLog(t)
		pub := newAccount(t)
		if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, true)); err == nil {
			t.Fatal("a failed bucket write returned nil")
		}
		if !strings.Contains(buf.String(), logFieldBucketWriteFailed+"=1") {
			t.Fatalf("no %s=1 in the log:\n%s", logFieldBucketWriteFailed, buf)
		}
	})
	t.Run("bucket write failed, reconcile", func(t *testing.T) {
		e := newPubEnv(t)
		a, b := newAccount(t), newAccount(t)
		local := []string{e.tr.signAt(t, a, 100, false), e.tr.signAt(t, b, 100, false)}
		e.p.local = func() ([]string, error) { return local, nil }
		e.srv.Deny(func(op, _ string) bool { return op == http.MethodPut })
		buf := captureLog(t)
		err := e.p.ReconcileAll(context.Background())
		if !errors.Is(err, errBucketWrite) {
			t.Fatalf("ReconcileAll returned %v, want the bucket write errors", err)
		}
		if !strings.Contains(buf.String(), logFieldBucketWriteFailed+"=2") {
			t.Fatalf("no %s=2 in the log:\n%s", logFieldBucketWriteFailed, buf)
		}
	})
	t.Run("push missed nodes", func(t *testing.T) {
		e := newPubEnv(t)
		e.p.openBus = func() (accountBus, error) {
			return fakeBus{seq: e.seq, events: &e.events, mu: &e.mu, missing: 2}, nil
		}
		buf := captureLog(t)
		pub := newAccount(t)
		if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, false)); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), logFieldPushMissingNodes+"=2") {
			t.Fatalf("no %s=2 in the log:\n%s", logFieldPushMissingNodes, buf)
		}
		if strings.Contains(buf.String(), logFieldBucketWriteFailed) {
			t.Fatalf("%s logged for a write that succeeded:\n%s", logFieldBucketWriteFailed, buf)
		}
	})
}
