package natsapi

import (
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
)

// RegisterTenantProvisioning (and the RegisterSproutAction it calls) must
// not return until the server has every subscription. Otherwise a request
// sent on another connection right after, as the SaaS API does, can reach
// the server first and fail with "no responders" (the race behind
// TestSproutAction_CookThroughRealHandler's intermittent CI failure).
// Checked on the server itself, so this does not depend on timing.
func TestRegisterTenantProvisioning_SubscriptionsReachServerBeforeReturn(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("connect to test NATS: %v", err)
	}
	t.Cleanup(nc.Close)

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}

	acc := ns.GlobalAccount()
	for _, subject := range []string{
		controlplane.SubjectTenantProvision,
		controlplane.SubjectTenantDeprovision,
		controlplane.SubjectSproutAction,
	} {
		if n := acc.Interest(subject); n == 0 {
			t.Errorf("server has no subscription on %s when registration returned", subject)
		}
	}
}
