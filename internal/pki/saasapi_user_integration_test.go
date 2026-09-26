package pki

// Live-bus proof of the SaaS API credential's scoping (FLAG FOR SECURITY
// REVIEW — see docs/design/imas-internal-api-account.md). Asserting on the
// JWT's fields alone (saasapi_user_test.go) wouldn't prove that a User in
// the SYS Account really gets no $SYS reach beyond its own allow-lists;
// this does, against a real embedded nats-server.

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/controlplane"
)

// permissionErrors collects the asynchronous -ERR 'Permissions Violation'
// notices the server sends for a denied publish or subscribe.
type permissionErrors struct {
	mu   sync.Mutex
	errs []string
}

func (p *permissionErrors) handler(_ *nats.Conn, _ *nats.Subscription, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errs = append(p.errs, err.Error())
}

// waitFor reports whether a permission violation naming subject arrives
// within a short window.
func (p *permissionErrors) waitFor(subject string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		for _, e := range p.errs {
			if strings.Contains(e, "Permissions Violation") && strings.Contains(e, `"`+subject+`"`) {
				p.mu.Unlock()
				return true
			}
		}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// waitForOp is waitFor narrowed to one direction — op is "Publish" or
// "Subscription", as the server words it — for tests that check the same
// subject both ways, where a publish denial would otherwise satisfy the
// subscribe check.
func (p *permissionErrors) waitForOp(op, subject string) bool {
	want := "Permissions Violation for " + op + ` to "` + subject + `"`
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		for _, e := range p.errs {
			if strings.Contains(e, want) {
				p.mu.Unlock()
				return true
			}
		}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (p *permissionErrors) any() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.errs...)
}

func dialWithCreds(t *testing.T, userJWT string, seed []byte, opts ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	rootPEM, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("reading root CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatal("failed to parse root CA")
	}
	return nats.Connect(config.FarmerBusURL, append([]nats.Option{
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWTAndSeed(userJWT, string(seed)),
		nats.Timeout(5 * time.Second),
		nats.RetryOnFailedConnect(false),
		nats.NoReconnect(),
	}, opts...)...)
}

func TestSaaSAPICredential_ScopedOnLiveBus(t *testing.T) {
	setupTestPKI(t)
	defer startTestBus(t)()

	userJWT, seed, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}

	// Farmer's side: its SYS connection, the one internal/natsapi's
	// provisioning handlers are registered on.
	farmer, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	defer farmer.Close()
	requests, _ := farmer.SubscribeSync("internal.tenant.provision")
	forged, _ := farmer.SubscribeSync("internal.tenant.provisioned.pj_forged")
	imasAPI, _ := farmer.SubscribeSync("imas.api.>")
	if err := farmer.Flush(); err != nil {
		t.Fatalf("farmer flush: %v", err)
	}

	var perrs permissionErrors
	saas, err := dialWithCreds(t, userJWT, seed, nats.ErrorHandler(perrs.handler))
	if err != nil {
		t.Fatalf("expected the SaaS API credential to connect: %v", err)
	}
	defer saas.Close()

	// Allowed: subscribe to results, publish a request that farmer receives.
	results, err := saas.SubscribeSync("internal.tenant.provisioned.*")
	if err != nil {
		t.Fatalf("subscribe to results: %v", err)
	}
	if err := saas.Publish("internal.tenant.provision", []byte(`{}`)); err != nil {
		t.Fatalf("publish request: %v", err)
	}
	if err := saas.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, err := requests.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected farmer's SYS connection to receive the SaaS API's request: %v", err)
	}
	if err := farmer.Publish("internal.tenant.provisioned.pj_1", []byte(`{}`)); err != nil {
		t.Fatalf("farmer publish result: %v", err)
	}
	if _, err := results.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected the SaaS API to receive farmer's result: %v", err)
	}
	if got := perrs.any(); len(got) != 0 {
		t.Fatalf("unexpected permission errors on allowed operations: %v", got)
	}

	// Denied publishes: $SYS administration, a tenant API subject, and a
	// forged result (only farmer may publish those).
	for _, subj := range []string{
		"$SYS.REQ.SERVER.PING",
		"$SYS.REQ.ACCOUNT.PING.CONNZ",
		"$SYS.REQ.CLAIMS.UPDATE",
		"imas.api.health",
		"imas.sprouts.web-01.cmd.run",
		"internal.tenant.provisioned.pj_forged",
	} {
		_ = saas.Publish(subj, []byte(`{}`))
		_ = saas.Flush()
		if !perrs.waitFor(subj) {
			t.Errorf("expected publish to %q to be denied", subj)
		}
	}
	if _, err := forged.NextMsg(200 * time.Millisecond); err == nil {
		t.Error("a forged result from the SaaS API credential reached farmer's subscriber")
	}
	if _, err := imasAPI.NextMsg(200 * time.Millisecond); err == nil {
		t.Error("a imas.api publish from the SaaS API credential was delivered")
	}

	// Denied subscribes: farmer's own request subject, cross-tenant
	// connection events, $SYS generally, and any tenant's traffic.
	for _, subj := range []string{
		"internal.tenant.provision",
		"$SYS.ACCOUNT.*.CONNECT",
		"$SYS.>",
		"imas.>",
		"_INBOX.>",
		">",
	} {
		if _, err := saas.SubscribeSync(subj); err != nil {
			t.Fatalf("SubscribeSync(%q) returned a local error: %v", subj, err)
		}
		_ = saas.Flush()
		if !perrs.waitFor(subj) {
			t.Errorf("expected subscribe to %q to be denied", subj)
		}
	}
}

// TestSaaSAPICredential_SproutActionScopedOnLiveBus proves the
// internal.sprout.action grant (FLAG FOR SECURITY REVIEW): the credential
// can make the request-reply round trip through farmer's SYS connection,
// but only with replies on its own _INBOX.saasapi.> inboxes — it still
// can't reach imas.api.* or imas.sprouts.*, can't receive farmer's
// requests, and can't subscribe to (or publish into) any other SYS user's
// reply inbox.
func TestSaaSAPICredential_SproutActionScopedOnLiveBus(t *testing.T) {
	setupTestPKI(t)
	defer startTestBus(t)()

	userJWT, seed, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}

	// Farmer's side: its SYS connection answers internal.sprout.action the
	// way natsapi.RegisterSproutAction does, from its own unrestricted SYS
	// user, in the same queue group.
	farmer, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	defer farmer.Close()
	var replyTo []string
	var replyMu sync.Mutex
	if _, err := farmer.QueueSubscribe(controlplane.SubjectSproutAction, "imas-core", func(msg *nats.Msg) {
		replyMu.Lock()
		replyTo = append(replyTo, msg.Reply)
		replyMu.Unlock()
		_ = msg.Respond([]byte(`{"status":"completed"}`))
	}); err != nil {
		t.Fatalf("farmer subscribe: %v", err)
	}
	// Another SYS user's live reply inbox, and the tenant/sprout subjects
	// the credential must never reach.
	farmerInbox := farmer.NewInbox()
	farmerReplies, _ := farmer.SubscribeSync(farmerInbox)
	imasAPI, _ := farmer.SubscribeSync("imas.api.>")
	imasSprouts, _ := farmer.SubscribeSync("imas.sprouts.>")
	if err := farmer.Flush(); err != nil {
		t.Fatalf("farmer flush: %v", err)
	}
	if strings.HasPrefix(farmerInbox, controlplane.SaaSAPIInboxPrefix+".") {
		t.Fatalf("farmer's own inbox %q falls under the SaaS API's inbox prefix", farmerInbox)
	}

	var perrs permissionErrors
	saas, err := dialWithCreds(t, userJWT, seed,
		nats.ErrorHandler(perrs.handler),
		nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix))
	if err != nil {
		t.Fatalf("expected the SaaS API credential to connect: %v", err)
	}
	defer saas.Close()

	// Allowed: the full request-reply round trip, reply on a scoped inbox.
	msg, err := saas.Request(controlplane.SubjectSproutAction, []byte(`{}`), 2*time.Second)
	if err != nil {
		t.Fatalf("expected internal.sprout.action to round-trip through farmer: %v", err)
	}
	if string(msg.Data) != `{"status":"completed"}` {
		t.Fatalf("unexpected reply %q", msg.Data)
	}
	replyMu.Lock()
	gotReply := append([]string(nil), replyTo...)
	replyMu.Unlock()
	if len(gotReply) != 1 || !controlplane.ValidSaaSAPIReplySubject(gotReply[0]) {
		t.Fatalf("farmer saw reply subjects %v, want one scoped SaaS API inbox", gotReply)
	}
	if got := perrs.any(); len(got) != 0 {
		t.Fatalf("unexpected permission errors on allowed operations: %v", got)
	}

	// Denied publishes: tenant API and sprout subjects, the not-yet-built
	// internal.sprout* subjects, and any reply inbox — its own included
	// (replies come from farmer) and, above all, farmer's, where a publish
	// would forge a reply to one of farmer's own requests.
	for _, subj := range []string{
		"imas.api.cmd.run",
		"imas.api.cook",
		"imas.sprouts.web-01.cmd.run",
		"imas.sprouts.web-01.cook",
		"internal.sprout.mint",
		"internal.sprout.revoke",
		"internal.sprouts.list",
		farmerInbox,
		controlplane.SaaSAPIInboxPrefix + ".forged",
	} {
		_ = saas.Publish(subj, []byte(`{}`))
		_ = saas.Flush()
		if !perrs.waitForOp("Publish", subj) {
			t.Errorf("expected publish to %q to be denied", subj)
		}
	}
	for name, sub := range map[string]*nats.Subscription{"imas.api": imasAPI, "imas.sprouts": imasSprouts, "farmer inbox": farmerReplies} {
		if _, err := sub.NextMsg(200 * time.Millisecond); err == nil {
			t.Errorf("a %s publish from the SaaS API credential was delivered", name)
		}
	}

	// Denied subscribes: farmer's request subject (only farmer receives
	// requests), every other SYS user's inboxes, and tenant traffic.
	for _, subj := range []string{
		controlplane.SubjectSproutAction,
		"internal.sprout.>",
		"internal.>",
		farmerInbox,
		farmerInbox + ".*",
		"_INBOX.*",
		"_INBOX.*.>",
		"_INBOX.>",
		"_INBOX.saasapix.>",
		"imas.api.>",
		"imas.sprouts.>",
		"imas.sprouts.*.cmd.run",
	} {
		if _, err := saas.SubscribeSync(subj); err != nil {
			t.Fatalf("SubscribeSync(%q) returned a local error: %v", subj, err)
		}
		_ = saas.Flush()
		if !perrs.waitForOp("Subscription", subj) {
			t.Errorf("expected subscribe to %q to be denied", subj)
		}
	}

	// Without the scoped prefix the same credential gets no replies at
	// all: nats.go's default response inbox (_INBOX.<nuid>.*) is refused.
	var bareErrs permissionErrors
	bare, err := dialWithCreds(t, userJWT, seed, nats.ErrorHandler(bareErrs.handler))
	if err != nil {
		t.Fatalf("connect without the inbox prefix: %v", err)
	}
	defer bare.Close()
	if _, err := bare.Request(controlplane.SubjectSproutAction, []byte(`{}`), 500*time.Millisecond); err == nil {
		t.Fatal("expected a request with a bare _INBOX reply to get no reply")
	}
	denied := false
	for _, e := range bareErrs.any() {
		if strings.Contains(e, `Permissions Violation for Subscription to "_INBOX.`) {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("expected the default _INBOX response subscription to be denied, got %v", bareErrs.any())
	}
}

// TestSaaSAPICredential_RotationRevokesPreviousKeyOnLiveBus proves that
// rotating the SaaS API's seed (a new IMAS_NATS_SAASAPI_USER_SEED from
// OpenBao) actually cuts off the old credential at the bus, via a
// revocation pushed on the SYS Account JWT — not just that a new JWT gets
// written locally.
func TestSaaSAPICredential_RotationRevokesPreviousKeyOnLiveBus(t *testing.T) {
	setupTestPKI(t)
	defer startTestBus(t)()

	oldKP, _ := nkeys.CreateUser()
	oldSeed, _ := oldKP.Seed()
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", string(oldSeed))
	oldJWT, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential (old key): %v", err)
	}
	nc, err := dialWithCreds(t, oldJWT, oldSeed)
	if err != nil {
		t.Fatalf("expected the original credential to connect: %v", err)
	}
	nc.Close()

	newKP, _ := nkeys.CreateUser()
	newSeed, _ := newKP.Seed()
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", string(newSeed))
	newJWT, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential (rotated key): %v", err)
	}
	if newJWT == oldJWT {
		t.Fatal("expected a new JWT for the rotated key")
	}

	if nc, err := dialWithCreds(t, oldJWT, oldSeed); err == nil {
		nc.Close()
		t.Fatal("expected the rotated-out credential to be rejected by the bus")
	}
	nc, err = dialWithCreds(t, newJWT, newSeed)
	if err != nil {
		t.Fatalf("expected the rotated-in credential to connect: %v", err)
	}
	nc.Close()

	// Farmer's own SYS push user must be unaffected by the revocation.
	sys, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("expected farmer's SYS user to still connect after the SYS Account was re-signed: %v", err)
	}
	sys.Close()

	// A later boot with the same (new) key is a no-op mint but still
	// re-pushes the SYS Account JWT, since it carries a revocation.
	again, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential (idempotent re-run): %v", err)
	}
	if again != newJWT {
		t.Fatal("expected the re-run to reuse the rotated-in JWT")
	}
}
