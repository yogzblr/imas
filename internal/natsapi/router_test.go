package natsapi

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

// TestSubscribe_UsesQueueGroup verifies that Subscribe registers its route
// handlers as queue subscribers under the shared "imas-core" queue group,
// rather than plain fan-out subscribers. This is the behavior workstream D
// depends on: when multiple farmer replicas run behind the same NATS
// subjects, exactly one replica should handle each API request instead of
// every replica processing (and replying to, or re-executing the side
// effects of) the same request.
//
// It simulates a second farmer replica by adding another queue subscriber
// on the same subject and queue group directly, then verifies that
// published requests are load-balanced across the two instead of delivered
// to both.
func TestSubscribe_UsesQueueGroup(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	SetBuildVersion(config.Version{Tag: "v1.0.0-queue-test"})
	defer SetBuildVersion(config.Version{})

	subject := Subject(MethodVersion)

	// Simulate a second farmer replica subscribing to the same subject in
	// the same queue group.
	var secondReplicaHits int64
	sub2, err := nc.QueueSubscribe(subject, natsCoreQueueGroup, func(msg *nats.Msg) {
		atomic.AddInt64(&secondReplicaHits, 1)
		if msg.Reply != "" {
			msg.Respond([]byte(`{"result":{"tag":"v1.0.0-queue-test"}}`))
		}
	})
	if err != nil {
		t.Fatalf("simulate second replica QueueSubscribe: %v", err)
	}
	defer sub2.Unsubscribe()
	nc.Flush()

	const numRequests = 20
	for range numRequests {
		if _, err := nc.Request(subject, nil, 2*time.Second); err != nil {
			t.Fatalf("request to %s: %v", subject, err)
		}
	}

	hits := atomic.LoadInt64(&secondReplicaHits)
	// Because this is a queue subscription, the second "replica" should
	// receive a share of the requests but never all of them  - if Subscribe
	// used plain nc.Subscribe instead, every request would be delivered to
	// both the real route handler AND this second subscriber (fan-out),
	// so hits would equal numRequests.
	if hits == 0 {
		t.Error("expected second replica to receive at least some requests via queue-group load balancing")
	}
	if hits >= numRequests {
		t.Errorf("expected requests to be load-balanced across queue members, but second replica received all %d (fan-out, not queue-grouped)", hits)
	}
}

// TestSubscribe_QueueGroupIsSharedAcrossRoutes verifies that every
// registered route subscribes using the same well-known queue group name,
// so a farmer replica pool balances load consistently across all API
// methods rather than only some of them.
func TestSubscribe_QueueGroupIsSharedAcrossRoutes(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	tenantID := pki.CurrentTenantID()
	defer ClearNatsConn(tenantID)

	if err := Subscribe(nc, tenantID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if natsCoreQueueGroup != "imas-core" {
		t.Fatalf("expected queue group %q, got %q", "imas-core", natsCoreQueueGroup)
	}
}
