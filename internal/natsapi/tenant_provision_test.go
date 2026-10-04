package natsapi

// Handler-level coverage for tenant_provision.go: the sealed wire (J.4),
// decode/validation/result behavior and the queue-group discipline, with
// pki's provisioning functions stubbed. The whole chain — SaaS API HTTP
// handler, real pki.ProvisionTenant, the scoped SYS credential, sealing
// both ways, and the saas schema status transition — is covered end to
// end in internal/saasapi/provisioning_e2e_test.go.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

func stubTenantProvisioning(t *testing.T, provision func(string, string) error, deprovision func(string) error) {
	t.Helper()
	origP, origD := provisionTenant, deprovisionTenant
	provisionTenant, deprovisionTenant = provision, deprovision
	t.Cleanup(func() { provisionTenant, deprovisionTenant = origP, origD })
}

// nextResult waits for the next result on sub and opens it the way the
// SaaS API does: sealed, for the job its subject names.
func nextResult(t *testing.T, c *saasClient, sub *nats.Subscription) controlplane.TenantResult {
	t.Helper()
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("waiting for result: %v", err)
	}
	deprovision := strings.HasPrefix(msg.Subject, controlplane.SubjectTenantDeprovisionedPrefix)
	prefix := controlplane.SubjectTenantProvisionedPrefix
	if deprovision {
		prefix = controlplane.SubjectTenantDeprovisionedPrefix
	}
	jobID, ok := controlplane.JobIDFromSubject(msg.Subject, prefix)
	if !ok {
		t.Fatalf("result on unexpected subject %q", msg.Subject)
	}
	res, err := c.openTenantResult(deprovision, jobID, msg)
	if err != nil {
		t.Fatalf("opening result on %s: %v", msg.Subject, err)
	}
	return res
}

// publishSealed publishes params as the SaaS API's sealed request on
// subject and returns the message, for replaying.
func publishSealed(t *testing.T, c *saasClient, nc *nats.Conn, subject string, params any) *nats.Msg {
	t.Helper()
	m, _ := c.sealedMsg(t, subject, params)
	publishMsg(t, nc, m)
	return m
}

func publishMsg(t *testing.T, nc *nats.Conn, m *nats.Msg) {
	t.Helper()
	if err := nc.PublishMsg(m); err != nil {
		t.Fatalf("publish %s: %v", m.Subject, err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// expectNoMsg fails if sub receives anything within a short wait.
func expectNoMsg(t *testing.T, sub *nats.Subscription, what string) {
	t.Helper()
	if msg, err := sub.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("%s: unexpected message on %s: %q", what, msg.Subject, msg.Data)
	}
}

func TestTenantProvision_SuccessPublishesActive(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	var gotID, gotName string
	stubTenantProvisioning(t, func(id, name string) error { gotID, gotName = id, name; return nil }, nil)

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	sub, _ := nc.SubscribeSync(controlplane.ProvisionedSubject("pj_ok"))
	publishSealed(t, saas, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_ok", TenantID: "t_1", Name: "Acme"})

	res := nextResult(t, saas, sub)
	if res.Status != controlplane.StatusActive || res.JobID != "pj_ok" || res.TenantID != "t_1" || res.ErrorCode != "" {
		t.Fatalf("unexpected result %+v", res)
	}
	if gotID != "t_1" || gotName != "Acme" {
		t.Fatalf("ProvisionTenant called with (%q, %q)", gotID, gotName)
	}
}

func TestTenantProvision_FailurePublishesFailedWithError(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	// An error whose text carries internal detail (a filesystem path).
	stubTenantProvisioning(t, func(string, string) error {
		return errors.New("mkdir /etc/imas/pki/nats-auth/tenants: not a directory")
	}, nil)

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	sub, _ := nc.SubscribeSync(controlplane.ProvisionedSubject("pj_bad"))
	publishSealed(t, saas, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_bad", TenantID: "t_1"})

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("waiting for result: %v", err)
	}
	res, err := saas.openTenantResult(false, "pj_bad", msg)
	if err != nil {
		t.Fatalf("opening result: %v", err)
	}
	// Not even inside the box: only a fixed code crosses the boundary.
	body, _ := saas.box.OpenResult(payloadbox.PurposeSaaSTenantProvisioned, "tenant.provisioned", msg.Subject, msg.Data)
	if body != nil && (strings.Contains(string(body.Params), "/etc/imas") || strings.Contains(string(body.Params), "not a directory")) {
		t.Fatalf("raw error text in the result: %s", body.Params)
	}
	if res.Status != controlplane.StatusFailed || res.ErrorCode != controlplane.ErrorInternal {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestTenantDeprovision_SuccessNotFoundAndFailure(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	stubTenantProvisioning(t, nil, func(id string) error {
		switch id {
		case "t_missing":
			return fmt.Errorf("looking up tenant: %w", pki.ErrTenantNotFound)
		case "t_dberr":
			return errors.New("pki: looking up tenant \"t_dberr\": sql: database is closed")
		}
		return nil
	})

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	sub, _ := nc.SubscribeSync(controlplane.SubjectTenantDeprovisionedWildcard)

	publishSealed(t, saas, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_d1", TenantID: "t_1"})
	if res := nextResult(t, saas, sub); res.Status != controlplane.StatusOffboarded || res.JobID != "pj_d1" || res.WarningCode != "" {
		t.Fatalf("unexpected result %+v", res)
	}

	// Never provisioned on farmer: nothing to tear down, so it's a
	// success, qualified by a warning.
	publishSealed(t, saas, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_d2", TenantID: "t_missing"})
	if res := nextResult(t, saas, sub); res.Status != controlplane.StatusOffboarded || res.WarningCode != controlplane.WarningTenantNotProvisioned || res.ErrorCode != "" {
		t.Fatalf("unexpected result %+v", res)
	}

	// Any other error — a DB failure included — must still fail: it could
	// mean the tenant's Account is still live.
	publishSealed(t, saas, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_d3", TenantID: "t_dberr"})
	if res := nextResult(t, saas, sub); res.Status != controlplane.StatusFailed || res.ErrorCode != controlplane.ErrorInternal || res.WarningCode != "" {
		t.Fatalf("unexpected result %+v", res)
	}
}

// TestTenantProvision_DropsInvalidJobIDAndMalformedJSON: neither case has
// a safe subject to reply on, so nothing is published and pki is never
// called — in particular a job_id with an extra token must not steer the
// result onto some other subject. The requests are genuinely sealed: the
// checks inside still apply.
func TestTenantProvision_DropsInvalidJobIDAndMalformedJSON(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	var calls atomic.Int32
	stubTenantProvisioning(t, func(string, string) error { calls.Add(1); return nil }, func(string) error { calls.Add(1); return nil })

	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatalf("RegisterTenantProvisioning: %v", err)
	}
	all, _ := nc.SubscribeSync("internal.tenant.>")
	_ = nc.Flush()

	publishSealed(t, saas, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_x.evil", TenantID: "t_1"})
	publishSealed(t, saas, nc, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "", TenantID: "t_1"})
	publishSealed(t, saas, nc, controlplane.SubjectTenantProvision, "{not json")

	// Drain the three requests themselves; anything after them is a reply.
	for i := 0; i < 3; i++ {
		if _, err := all.NextMsg(time.Second); err != nil {
			t.Fatalf("expected request %d to be observed: %v", i, err)
		}
	}
	expectNoMsg(t, all, "a dropped request")
	if calls.Load() != 0 {
		t.Fatalf("expected pki not to be called, got %d calls", calls.Load())
	}
}

// TestTenantProvision_QueueGroupDeliversOnce registers the handlers on two
// connections (two farmer replicas) and checks a single request is
// processed exactly once.
func TestTenantProvision_QueueGroupDeliversOnce(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	replica, err := nats.Connect(nc.ConnectedUrl())
	if err != nil {
		t.Fatalf("connect second replica: %v", err)
	}
	defer replica.Close()

	var calls atomic.Int32
	stubTenantProvisioning(t, func(string, string) error { calls.Add(1); return nil }, nil)
	if err := registerSaaSAPIHandlers(nc, newSealedAPI()); err != nil {
		t.Fatalf("RegisterTenantProvisioning (replica 1): %v", err)
	}
	if err := registerSaaSAPIHandlers(replica, newSealedAPI()); err != nil {
		t.Fatalf("RegisterTenantProvisioning (replica 2): %v", err)
	}
	_ = replica.Flush()
	sub, _ := nc.SubscribeSync(controlplane.SubjectTenantProvisionedWildcard)

	publishSealed(t, saas, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_once", TenantID: "t_1"})
	nextResult(t, saas, sub)
	expectNoMsg(t, sub, "a second result for one request across two replicas")
	if calls.Load() != 1 {
		t.Fatalf("ProvisionTenant called %d times, want 1", calls.Load())
	}
}

// impostorSaaSAPI is a bus that made its own box key and pinned the
// genuine platform key: everything it seals looks right except the key.
func impostorSaaSAPI(t *testing.T, c *saasClient) *pki.SaaSAPIBox {
	t.Helper()
	_, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	platformPub := c.env.bao.Versions(tenantboxtest.BasePath + "/controlplane-pub")[0].Data["platform_pub"]
	b, err := pki.NewSaaSAPIBox(priv, platformPub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTenantProvisioning_RefusesForgedAndReplayed is J.4's point for the
// provisioning subjects: a compromised bus can't provision or deprovision
// a tenant. Plaintext, a request sealed with a key that isn't the SaaS
// API's, a genuine request with its principal header changed or moved to
// the other subject, and a genuine request replayed to the same replica
// or to another one: none reaches pki, and no result is published for
// any of them. Only the genuine request, once, runs.
func TestTenantProvisioning_RefusesForgedAndReplayed(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	replicaB, err := nats.Connect(nc.ConnectedUrl())
	if err != nil {
		t.Fatal(err)
	}
	defer replicaB.Close()
	var provisions, deprovisions atomic.Int32
	stubTenantProvisioning(t,
		func(string, string) error { provisions.Add(1); return nil },
		func(string) error { deprovisions.Add(1); return nil })
	// Two replicas, each with its own replay guard, sharing Valkey.
	if err := registerSaaSAPIHandlers(nc, newSealedAPI()); err != nil {
		t.Fatal(err)
	}
	if err := registerSaaSAPIHandlers(replicaB, newSealedAPI()); err != nil {
		t.Fatal(err)
	}
	_ = replicaB.Flush()
	results, _ := nc.SubscribeSync("internal.tenant.*.*")
	_ = nc.Flush()

	deprov := controlplane.TenantDeprovisionRequest{JobID: "pj_victim", TenantID: "t_1"}

	// Plaintext, as before J.4.
	plain := nats.NewMsg(controlplane.SubjectTenantDeprovision)
	plain.Data = mustJSON(t, deprov)
	publishMsg(t, nc, plain)
	// Plaintext with the sealed headers claimed.
	claimed := nats.NewMsg(controlplane.SubjectTenantDeprovision)
	claimed.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	claimed.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	claimed.Data = mustJSON(t, deprov)
	publishMsg(t, nc, claimed)
	// Sealed by a bus that made its own key.
	forged, _, err := sealedSaaSAPIMsg(impostorSaaSAPI(t, saas), controlplane.SubjectTenantDeprovision, deprov)
	if err != nil {
		t.Fatal(err)
	}
	publishMsg(t, nc, forged)
	// A genuine provision request, its principal header changed.
	asUser, _ := saas.sealedMsg(t, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_p", TenantID: "t_1"})
	asUser.Header.Set(payloadbox.PrincipalHeader, "AUSER")
	publishMsg(t, nc, asUser)
	// A genuine provision request moved onto the deprovision subject.
	moved, _ := saas.sealedMsg(t, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_victim", TenantID: "t_1"})
	moved.Subject = controlplane.SubjectTenantDeprovision
	publishMsg(t, nc, moved)
	expectNoMsg(t, results, "a forged request")
	if provisions.Load() != 0 || deprovisions.Load() != 0 {
		t.Fatalf("a forged request ran: %d provisions, %d deprovisions", provisions.Load(), deprovisions.Load())
	}

	// The genuine deprovision runs once...
	genuine := publishSealed(t, saas, nc, controlplane.SubjectTenantDeprovision, deprov)
	if res := nextResult(t, saas, results); res.JobID != "pj_victim" || res.Status != controlplane.StatusOffboarded {
		t.Fatalf("genuine result %+v", res)
	}
	// ...and replayed, to whichever replica the queue group picks, and
	// to each replica directly, it doesn't run again.
	for i := 0; i < 4; i++ {
		publishMsg(t, nc, genuine)
	}
	for _, s := range []*sealedAPI{newSealedAPI(), newSealedAPI()} {
		if req := s.openSaaSAPIRequestOrRefuse(genuine, false); req != nil {
			t.Fatal("a replayed request opened on a fresh replica")
		}
	}
	expectNoMsg(t, results, "a replayed request")
	if deprovisions.Load() != 1 {
		t.Fatalf("DeprovisionTenant ran %d times, want 1", deprovisions.Load())
	}
}

// staleSaaSAPIMsg is a request the SaaS API genuinely sealed, with its
// real key, age ago: what a bus that held one back would have.
func staleSaaSAPIMsg(t *testing.T, c *saasClient, subject string, params any, age time.Duration) *nats.Msg {
	t.Helper()
	decode := func(path, field string) *[32]byte {
		raw, err := base64.StdEncoding.DecodeString(c.env.bao.Versions(tenantboxtest.BasePath + path)[0].Data[field])
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s %s: %v", path, field, err)
		}
		var k [32]byte
		copy(k[:], raw)
		return &k
	}
	w, _ := pki.SaaSAPIRequestWire(subject)
	msg, err := payloadbox.NewMessage(w.Purpose, payloadbox.PlatformTenantID, payloadbox.PrincipalSaaSAPI, "",
		payloadbox.CallBody{Method: w.Method, Subject: w.Subject, Params: mustJSON(t, params)})
	if err != nil {
		t.Fatal(err)
	}
	msg.IssuedAt = time.Now().Add(-age).Unix()
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: decode("/controlplane-pub", "platform_pub"), Priv: decode("/saasapi-box", "priv")}})
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	m.Data = data
	return m
}

// A request sealed by the SaaS API more than the freshness window ago is
// refused, though it opens: a bus held it back to use later. Neither
// subject runs it.
func TestSaaSAPIRequests_RefuseStale(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	var calls atomic.Int32
	stubTenantProvisioning(t, func(string, string) error { calls.Add(1); return nil }, func(string) error { calls.Add(1); return nil })
	rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatal(err)
	}
	results, _ := nc.SubscribeSync("internal.tenant.*.*")
	_ = nc.Flush()
	age := payloadbox.DefaultMaxSkew + time.Minute

	publishMsg(t, nc, staleSaaSAPIMsg(t, saas, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: "pj_s", TenantID: "t_1"}, age))
	expectNoMsg(t, results, "a stale deprovision")
	if calls.Load() != 0 {
		t.Fatal("a stale provisioning request ran")
	}

	m := staleSaaSAPIMsg(t, saas, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"), age)
	reply, err := saas.nc.RequestMsg(m, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Fatalf("stale sprout action answered %q (%v), want open-failed", code, reply.Header)
	}
	if len(rec.all()) != 0 {
		t.Fatal("a stale sprout action was dispatched")
	}
	// The same request, fresh, opens: it was only its age.
	if _, err := newSealedAPI().openSaaSAPIRequest(t.Context(), staleSaaSAPIMsg(t, saas, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"), 0)); err != nil {
		t.Fatalf("a fresh hand-sealed request: %v", err)
	}
}

// Results are sealed: a watcher on the bus sees ciphertext, not the
// tenant, the job's status or its error code.
func TestTenantProvisioning_ResultsAreSealed(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	saas := dialSaaSAPI(t, nc)
	stubTenantProvisioning(t, func(string, string) error { return nil }, nil)
	if err := RegisterTenantProvisioning(nc); err != nil {
		t.Fatal(err)
	}
	sub, _ := nc.SubscribeSync(controlplane.ProvisionedSubject("pj_seal"))
	publishSealed(t, saas, nc, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: "pj_seal", TenantID: "t_secret_tenant", Name: "Secret Co"})
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"t_secret_tenant", controlplane.StatusActive, "Secret Co"} {
		if strings.Contains(string(msg.Data), s) || strings.Contains(string(msg.Data), base64.StdEncoding.EncodeToString([]byte(s))) {
			t.Fatalf("result shows %q on the bus: %s", s, msg.Data)
		}
	}
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Fatalf("result headers %v", msg.Header)
	}
	// It opens only on its own job's subject.
	if _, err := saas.box.OpenTenantResult(false, "pj_other", controlplane.ProvisionedSubject("pj_other"), msg.Data); err == nil {
		t.Fatal("a result opened as another job's")
	}
	if _, err := saas.openTenantResult(false, "pj_seal", msg); err != nil {
		t.Fatal(err)
	}
}

func TestTenantErrorCode(t *testing.T) {
	cases := []struct {
		err  error
		want controlplane.ErrorCode
	}{
		{pki.ErrTenantIDInvalid, controlplane.ErrorInvalidTenantID},
		{fmt.Errorf("wrapped: %w", pki.ErrTenantIDInvalid), controlplane.ErrorInvalidTenantID},
		{pki.ErrTenantNotFound, controlplane.ErrorTenantNotFound},
		{errors.New("open /var/lib/imas/pki/nats-auth/sys-account.nk: permission denied"), controlplane.ErrorInternal},
	}
	for _, c := range cases {
		if got := tenantErrorCode(c.err); got != c.want {
			t.Errorf("tenantErrorCode(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
