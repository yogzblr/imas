package facts

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/props"
)

func startTestNATS(t *testing.T) (*nats.Conn, func()) {
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
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		t.Fatalf("connect to test NATS: %v", err)
	}
	return nc, func() {
		nc.Close()
		ns.Shutdown()
	}
}

func TestRegisterFarmerListener_ValidFacts(t *testing.T) {
	nc, cleanup := startTestNATS(t)
	defer cleanup()

	RegisterFarmerListener("t_test", nc)
	nc.Flush()

	sf := SystemFacts{
		OS:          "linux",
		Arch:        "amd64",
		Hostname:    "listener-test-host",
		GoVersion:   "go1.22.0",
		NumCPU:      4,
		IPAddresses: []string{"10.0.0.1"},
		KernelArch:  "amd64",
		SproutID:    "sprout-listener-test",
	}
	data, err := json.Marshal(sf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := nc.Publish("imas.sprouts.sprout-listener-test.facts", data); err != nil {
		t.Fatalf("publish: %v", err)
	}
	nc.Flush()
	time.Sleep(100 * time.Millisecond)

	if got := props.GetStringPropForTenant("t_test", "sprout-listener-test", "os"); got != "linux" {
		t.Errorf("expected os=linux, got %q", got)
	}
	if got := props.GetStringPropForTenant("t_test", "sprout-listener-test", "hostname"); got != "listener-test-host" {
		t.Errorf("expected hostname=listener-test-host, got %q", got)
	}
	if got := props.GetStringPropForTenant("t_test", "sprout-listener-test", "num_cpu"); got != "4" {
		t.Errorf("expected num_cpu=4, got %q", got)
	}
}

func TestRegisterFarmerListener_EmptySproutID(t *testing.T) {
	nc, cleanup := startTestNATS(t)
	defer cleanup()

	RegisterFarmerListener("t_test", nc)
	nc.Flush()

	sf := SystemFacts{
		OS:       "linux",
		Arch:     "amd64",
		Hostname: "empty-id-host",
		SproutID: "",
	}
	data, err := json.Marshal(sf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Should log error and not store — no panic.
	if err := nc.Publish("imas.sprouts.unknown.facts", data); err != nil {
		t.Fatalf("publish: %v", err)
	}
	nc.Flush()
	time.Sleep(100 * time.Millisecond)

	// Props should not have been stored for empty sprout ID.
	if got := props.GetStringPropForTenant("t_test", "", "os"); got != "" {
		t.Errorf("expected empty prop for empty sprout ID, got %q", got)
	}
}

func TestRegisterFarmerListener_InvalidJSON(t *testing.T) {
	nc, cleanup := startTestNATS(t)
	defer cleanup()

	RegisterFarmerListener("t_test", nc)
	nc.Flush()

	// Publish invalid JSON — should not panic.
	if err := nc.Publish("imas.sprouts.bad.facts", []byte("not json")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	nc.Flush()
	time.Sleep(100 * time.Millisecond)
	// No assertion needed — just verifying no panic.
}

// TestRegisterFarmerListener_UsesQueueGroup verifies that
// RegisterFarmerListener subscribes as a queue-group member of
// "imas-core", not a plain fan-out subscriber. This used to be the other
// way around (see the function's own doc comment for why that changed):
// props no longer holds an in-process, in-memory cache — workstream A
// moved it to PXC-backed, read-through storage — so every farmer replica
// reads/writes the same shared row regardless of which one received a
// given event, and fan-out here just means every replica redundantly
// reprocessing (and racing to UPSERT) the same facts event.
//
// It simulates a second farmer replica by adding another queue subscriber
// on the same subject and queue group directly (mirroring
// internal/natsapi/router_test.go's TestSubscribe_UsesQueueGroup), then
// verifies that published events are load-balanced across the two instead
// of delivered to both.
func TestRegisterFarmerListener_UsesQueueGroup(t *testing.T) {
	nc, cleanup := startTestNATS(t)
	defer cleanup()

	RegisterFarmerListener("t_test", nc)
	nc.Flush()

	// Simulate a second farmer replica subscribing to the same subject in
	// the same queue group.
	var secondReplicaHits int64
	sub, err := nc.QueueSubscribe("imas.sprouts.*.facts", natsCoreQueueGroup, func(msg *nats.Msg) {
		atomic.AddInt64(&secondReplicaHits, 1)
	})
	if err != nil {
		t.Fatalf("simulate second replica subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	nc.Flush()

	const numEvents = 20
	for i := range numEvents {
		sf := SystemFacts{
			OS:       "linux",
			Hostname: "queue-group-host",
			SproutID: "sprout-queue-group-test",
			NumCPU:   i,
		}
		data, _ := json.Marshal(sf)
		if err := nc.Publish("imas.sprouts.sprout-queue-group-test.facts", data); err != nil {
			t.Fatal(err)
		}
	}
	nc.Flush()
	time.Sleep(200 * time.Millisecond)

	// Because this is a queue subscription, the second "replica" should
	// receive a share of the events but never all of them — if
	// RegisterFarmerListener used plain Subscribe instead, every event
	// would be delivered to both the real listener AND this second
	// subscriber (fan-out), so hits would equal numEvents; if it were
	// queue-grouped under a different group name than the simulated
	// replica's, hits would be 0.
	hits := atomic.LoadInt64(&secondReplicaHits)
	if hits == 0 {
		t.Error("expected second replica to receive at least some events via queue-group load balancing")
	}
	if hits >= numEvents {
		t.Errorf("expected events to be load-balanced across queue members, but second replica received all %d (fan-out, not queue-grouped)", hits)
	}

	// Between the primary listener and the simulated replica, every event
	// was still handled by exactly one queue member — the primary
	// listener processed its share and stored the props.
	if got := props.GetStringPropForTenant("t_test", "sprout-queue-group-test", "hostname"); got != "queue-group-host" {
		t.Errorf("expected hostname=queue-group-host, got %q", got)
	}
}

func TestRegisterFarmerListener_MultipleSprouts(t *testing.T) {
	nc, cleanup := startTestNATS(t)
	defer cleanup()

	RegisterFarmerListener("t_test", nc)
	nc.Flush()

	for _, sprout := range []struct {
		id       string
		os       string
		hostname string
	}{
		{"sprout-a", "linux", "host-a"},
		{"sprout-b", "darwin", "host-b"},
		{"sprout-c", "freebsd", "host-c"},
	} {
		sf := SystemFacts{
			OS:       sprout.os,
			Hostname: sprout.hostname,
			SproutID: sprout.id,
		}
		data, _ := json.Marshal(sf)
		if err := nc.Publish("imas.sprouts."+sprout.id+".facts", data); err != nil {
			t.Fatalf("publish %s: %v", sprout.id, err)
		}
	}
	nc.Flush()
	time.Sleep(150 * time.Millisecond)

	if got := props.GetStringPropForTenant("t_test", "sprout-a", "os"); got != "linux" {
		t.Errorf("sprout-a os: expected linux, got %q", got)
	}
	if got := props.GetStringPropForTenant("t_test", "sprout-b", "os"); got != "darwin" {
		t.Errorf("sprout-b os: expected darwin, got %q", got)
	}
	if got := props.GetStringPropForTenant("t_test", "sprout-c", "hostname"); got != "host-c" {
		t.Errorf("sprout-c hostname: expected host-c, got %q", got)
	}
}
