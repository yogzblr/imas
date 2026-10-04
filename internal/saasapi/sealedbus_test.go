package saasapi

// J.4 (FLAG FOR SECURITY REVIEW): the SaaS API seals every internal.*
// request, re-sends as new sealed messages, and believes only farmer's
// sealed answers. Farmer's side (forged and replayed requests refused) is
// internal/natsapi's tenant_provision_test.go and
// sprout_action_sealed_test.go; both together, with the real keygen Job
// and real handlers, are provisioning_e2e_test.go.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// ---- requests --------------------------------------------------------------

// A provisioning request is sealed on the wire: ciphertext, with the
// sealed-payload and principal headers, bound to its subject. Nothing of
// the tenant or its name is readable, and the request doesn't open as a
// request for any other subject.
func TestSealedBus_RequestsAreSealed(t *testing.T) {
	gdb := newTestDB(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	sub, _ := nc.SubscribeSync("internal.tenant.>")
	_ = nc.Flush()

	tenant, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	dispatchProvisioning(t.Context(), &job, "Very Secret Name Co")
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != controlplane.SubjectTenantProvision || msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 ||
		msg.Header.Get(payloadbox.PrincipalHeader) != payloadbox.PrincipalSaaSAPI {
		t.Fatalf("request %s with headers %v", msg.Subject, msg.Header)
	}
	for _, s := range []string{tenant.ID, job.ID, "Very Secret Name Co"} {
		if strings.Contains(string(msg.Data), s) || strings.Contains(string(msg.Data), base64.StdEncoding.EncodeToString([]byte(s))) {
			t.Fatalf("the request shows %q on the bus", s)
		}
	}
	var req controlplane.TenantProvisionRequest
	if _, err := farmerOpenRequest(msg, &req); err != nil || req.TenantID != tenant.ID || req.JobID != job.ID || req.Name != "Very Secret Name Co" {
		t.Fatalf("opened as farmer: %+v, %v", req, err)
	}
	for _, other := range []string{controlplane.SubjectTenantDeprovision, controlplane.SubjectSproutAction} {
		moved := nats.NewMsg(other)
		moved.Header, moved.Data = msg.Header, msg.Data
		if _, err := farmerOpenRequest(moved, nil); err == nil {
			t.Errorf("a provision request opened on %s", other)
		}
	}
}

// Without a box key nothing is sent at all: no plaintext fallback.
func TestSealedBus_NoBoxNothingSent(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	useControlBox(t, nil)
	watch, _ := nc.SubscribeSync("internal.>")
	_ = nc.Flush()

	_, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	dispatchProvisioning(t.Context(), &job, "Acme")

	tid := mustCreateActiveTenant(t, gdb)
	mustInsertFarmerSprout(t, gdb, tid, "web-01", "accepted")
	mustLinkAsset(t, tid, "web-01", "a1")
	_, resp := postActions(t, tid, map[string]any{"asset_ids": []string{"a1"}, "action": cmdAction("ls")})
	actionDispatches.Wait()

	if msg, err := watch.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("sent without a box key: %s %q", msg.Subject, msg.Data)
	}
	var it AssetActionItem
	gdb.Where("batch_id = ?", resp["batch_id"]).First(&it)
	if it.Status != ActionItemQueued || it.Attempts != 0 {
		t.Fatalf("item without a box key = %s/%d, want queued, never claimed", it.Status, it.Attempts)
	}
}

// waitNextSecond sleeps until the wall clock's Unix second changes, so
// two messages sealed either side of it have different iat.
func waitNextSecond() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second + 10*time.Millisecond).Sub(now))
}

// The outbox sweeper's re-publish of a provisioning job is a new sealed
// message: a new ID and a later iat, for the same job. Farmer's replay
// guard accepts it, where it refuses the first message sent again.
// Idempotency stays on the job ID, as CL.3 built it.
func TestSealedBus_SweeperResendIsAFreshMessage(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startProvisioningFarmer(t, nc)
	_, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)

	dispatchProvisioning(t.Context(), &job, "Acme")
	farmer.received(t, 1)
	waitNextSecond()
	sw := testSweeper(gdb, nc)
	clock.Advance(defaultProvisioningStaleAfter + time.Second)
	sw.sweep()
	if got := farmer.received(t, 2); got[job.ID] != 2 {
		t.Fatalf("farmer got %v, want the job twice", got)
	}
	sent := farmer.sent()
	if len(sent) != 2 {
		t.Fatalf("%d messages", len(sent))
	}
	first, resend := sent[0], sent[1]
	if first.ID == resend.ID || resend.IssuedAt <= first.IssuedAt {
		t.Fatalf("re-send reused the message: id %s/%s iat %d/%d", first.ID, resend.ID, first.IssuedAt, resend.IssuedAt)
	}
	guard := payloadbox.NewReplayGuard()
	if err := guard.Accept(first); err != nil {
		t.Fatal(err)
	}
	if err := guard.Accept(resend); err != nil {
		t.Fatalf("farmer's guard refused the re-send: %v", err)
	}
	if err := guard.Accept(first); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Fatalf("the first message again: %v, want ErrReplayed", err)
	}
}

// The same for a §1.5 action item farmer refused unrun (farmer_busy,
// sealed): the sweeper's re-dispatch is a new sealed message, which a
// farmer that remembers the first one accepts and runs.
func TestSealedBus_ActionRedispatchIsAFreshMessage(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 1)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	var calls int
	var mu sync.Mutex
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
				Status: controlplane.StatusFailed, ErrorCode: farmerCodeBusy}
		}
		return completingFarmer(req)
	})

	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	batchID := resp["batch_id"].(string)
	if it := batchItems(t, gdb, batchID)[0]; it.Status != ActionItemQueued || it.Attempts != 1 {
		t.Fatalf("after farmer_busy: %+v", it)
	}
	waitNextSecond()
	clock.Advance(defaultOutboxLeaseTTL + defaultActionStaleAfter + time.Minute)
	testSweeper(gdb, nc).sweep()
	actionDispatches.Wait()
	if it := batchItems(t, gdb, batchID)[0]; it.Status != ActionItemSucceeded || it.Attempts != 2 {
		t.Fatalf("after the re-dispatch: %+v", it)
	}
	farmer.mu.Lock()
	ids := append([]string(nil), farmer.ids...)
	farmer.mu.Unlock()
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("message ids %v, want two different", ids)
	}
}

// ---- provisioning results ----------------------------------------------------

// impostorKeys is a bus that made its own "platform" key and seals to the
// SaaS API's genuine public key: everything right except the key.
func impostorKeys(t *testing.T) controlKeys {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return controlKeys{platformPub: pub, platformPriv: priv, saasPub: testKeys.saasPub}
}

// Results the bus could forge are never applied: plaintext (as before
// J.4), sealed under a key that isn't the platform key, a SaaS API
// request reflected onto the result subject, a genuine result for another
// job moved onto this one's subject, and a stale one. The genuine result,
// through the real listener, is applied once; replayed, it is refused.
func TestSealedBus_ForgedResultsRefused(t *testing.T) {
	gdb := newTestDB(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	if err := StartProvisioningResultListener(nc); err != nil {
		t.Fatal(err)
	}
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	other, otherJob := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	active := controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusActive}
	subject := controlplane.ProvisionedSubject(job.ID)

	publish := func(m *nats.Msg) {
		t.Helper()
		if err := nc.PublishMsg(m); err != nil {
			t.Fatal(err)
		}
		_ = nc.Flush()
	}
	unchanged := func(what string) {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		if gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID); gotTenant.Status != TenantStatusPending || gotJob.Status != ProvisioningJobPending {
			t.Fatalf("%s was applied: tenant %s, job %s", what, gotTenant.Status, gotJob.Status)
		}
	}

	plain := nats.NewMsg(subject)
	plain.Data, _ = json.Marshal(active)
	publish(plain)
	unchanged("a plaintext result")

	claimed := nats.NewMsg(subject)
	claimed.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	claimed.Data, _ = json.Marshal(active)
	publish(claimed)
	unchanged("a plaintext result claiming to be sealed")

	publish(impostorKeys(t).sealedResultMsg(ProvisioningJobProvision, active))
	unchanged("a result sealed under an impostor platform key")

	reflected, _, err := sealedRequestMsg(controlplane.SubjectTenantProvision, active)
	if err != nil {
		t.Fatal(err)
	}
	reflected.Subject = subject
	publish(reflected)
	unchanged("a SaaS API request reflected as a result")

	moved := testKeys.sealedResultMsg(ProvisioningJobProvision, controlplane.TenantResult{JobID: otherJob.ID, TenantID: other.ID, Status: controlplane.StatusActive})
	moved.Subject = subject
	publish(moved)
	unchanged("another job's result moved onto this job's subject")

	deprov := testKeys.sealedResultMsg(ProvisioningJobDeprovision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusOffboarded})
	deprov.Subject = subject
	publish(deprov)
	unchanged("a deprovision result moved onto the provision subject")

	// The genuine result is applied.
	genuine := testKeys.sealedResultMsg(ProvisioningJobProvision, active)
	publish(genuine)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if gotTenant, gotJob := reload(t, gdb, tenant.ID, job.ID); gotTenant.Status == TenantStatusActive && gotJob.Status == ProvisioningJobSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the genuine result was not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Replayed: refused by the guard (and harmless under the state machine
	// anyway).
	if _, err := openTenantResult(ProvisioningJobProvision, job.ID, genuine); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Fatalf("a replayed result: %v, want ErrReplayed", err)
	}
	// The other tenant was never touched.
	if gotTenant, _ := reload(t, gdb, other.ID, otherJob.ID); gotTenant.Status != TenantStatusPending {
		t.Fatalf("other tenant moved to %s", gotTenant.Status)
	}
}

// ---- internal.sprout.action replies ----------------------------------------

// Replies the bus could forge are never believed, and never make an item
// re-sendable: plaintext (as before J.4), sealed under an impostor
// platform key, a genuine reply to an earlier request replayed, and an
// Imas-Payload-Error code all fail the item with dispatch_outcome_unknown.
// Only farmer's sealed refusal-unrun sends it back to queued.
func TestSealedBus_ForgedActionRepliesRefused(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	behaviours := []string{"plaintext", "impostor", "replayed", "refusal-code", "refused-unrun", "genuine"}
	for _, s := range behaviours {
		mustInsertFarmerSprout(t, gdb, tid, s, "accepted")
		mustLinkAsset(t, tid, s, "asset-"+s)
	}
	var mu sync.Mutex
	var earlierReply []byte // a genuine sealed reply to some other request
	fnc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fnc.Close)
	if _, err := fnc.Subscribe(controlplane.SubjectSproutAction, func(msg *nats.Msg) {
		var req controlplane.SproutActionRequest
		sealed, err := farmerOpenRequest(msg, &req)
		if err != nil {
			t.Errorf("request didn't open: %v", err)
			return
		}
		ok := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}}
		resp := nats.NewMsg(msg.Reply)
		resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		switch req.SproutID {
		case "plaintext":
			resp.Header = nats.Header{}
			resp.Data, _ = json.Marshal(ok)
		case "impostor":
			resp.Data = impostorKeys(t).sealFarmerReply(sealed.ID, ok, "")
		case "replayed":
			mu.Lock()
			resp.Data = earlierReply
			mu.Unlock()
		case "refusal-code":
			resp.Header = nats.Header{}
			resp.Header.Set(payloadbox.ErrorHeader, payloadbox.ErrorCodeOpenFailed)
		case "refused-unrun":
			resp.Data = testKeys.sealFarmerReply(sealed.ID, nil, "the replay store is unavailable")
		default:
			resp.Data = testKeys.sealFarmerReply(sealed.ID, ok, "")
		}
		_ = msg.RespondMsg(resp)
	}); err != nil {
		t.Fatal(err)
	}
	_ = fnc.Flush()
	other, _ := payloadbox.NewID()
	earlierReply = testKeys.sealFarmerReply(other, controlplane.SproutActionReply{TenantID: tid, SproutID: "replayed",
		Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}}, "")

	assets := make([]string, len(behaviours))
	for i, s := range behaviours {
		assets[i] = "asset-" + s
	}
	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("ls")})
	actionDispatches.Wait()
	var items []AssetActionItem
	gdb.Where("batch_id = ?", resp["batch_id"]).Find(&items)
	for _, it := range items {
		switch it.SproutID {
		case "genuine":
			if it.Status != ActionItemSucceeded {
				t.Errorf("genuine: %s/%s", it.Status, it.ErrorCode)
			}
		case "refused-unrun":
			if it.Status != ActionItemQueued || it.DispatchedAt != nil {
				t.Errorf("refused-unrun: %s/%s, want queued", it.Status, it.ErrorCode)
			}
		default:
			if it.Status != ActionItemFailed || it.ErrorCode != errCodeDispatchOutcomeUnknown {
				t.Errorf("%s: %s/%s, want failed/%s", it.SproutID, it.Status, it.ErrorCode, errCodeDispatchOutcomeUnknown)
			}
		}
	}
	if len(items) != len(behaviours) {
		t.Fatalf("%d items", len(items))
	}
}

// ---- configuration ---------------------------------------------------------

// ConnectBus refuses to start without the box key and the platform pin,
// or with a pin that is the SaaS API's own key, before dialing anything.
func TestConnectBus_RequiresTheBoxKey(t *testing.T) {
	dir := t.TempDir()
	writeE2ECerts(t, dir)
	user, _ := newUserCredential(t)
	cfg := Config{NATSURL: "nats://127.0.0.1:1", NATSCAFile: filepath.Join(dir, "rootca.pem"),
		NATSNKeySeedFile: user.seedFile, NATSUserJWT: user.jwt}
	if _, err := ConnectBus(cfg); !errors.Is(err, ErrBusNotConfigured) || !strings.Contains(err.Error(), "SAASAPI_BOX_PRIV_FILE") {
		t.Fatalf("no box key: %v", err)
	}
	privFile := filepath.Join(dir, "box.key")
	if err := os.WriteFile(privFile, []byte(base64.StdEncoding.EncodeToString(testKeys.saasPriv[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.BoxPrivFile = privFile
	if _, err := ConnectBus(cfg); !errors.Is(err, ErrBusNotConfigured) {
		t.Fatalf("no platform pin: %v", err)
	}
	cfg.PlatformBoxPubs = []string{base64.StdEncoding.EncodeToString(testKeys.saasPub[:])}
	if _, err := ConnectBus(cfg); err == nil || !strings.Contains(err.Error(), "own key") {
		t.Fatalf("pinned to its own key: %v", err)
	}
	cfg.PlatformBoxPubs = []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}
	if _, err := ConnectBus(cfg); err == nil || !strings.Contains(err.Error(), "low-order") {
		t.Fatalf("pinned to a weak key: %v", err)
	}
	// With good keys it gets as far as dialing (nothing listens there).
	cfg.PlatformBoxPubs = []string{base64.StdEncoding.EncodeToString(testKeys.platformPub[:])}
	if _, err := ConnectBus(cfg); err == nil || !strings.Contains(err.Error(), "connecting to NATS bus") {
		t.Fatalf("good keys: %v", err)
	}
}

func TestLoadConfig_BoxKeySettings(t *testing.T) {
	t.Setenv("SAASAPI_BOX_PRIV_FILE", "/run/secrets/saasapi-box/priv")
	t.Setenv("SAASAPI_PLATFORM_BOX_PUB", " AAAA , BBBB ,")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BoxPrivFile != "/run/secrets/saasapi-box/priv" || len(cfg.PlatformBoxPubs) != 2 || cfg.PlatformBoxPubs[0] != "AAAA" || cfg.PlatformBoxPubs[1] != "BBBB" {
		t.Fatalf("config %q %q", cfg.BoxPrivFile, cfg.PlatformBoxPubs)
	}
}

// userCredential is a matching NATS User seed file and JWT.
type userCredential struct{ seedFile, jwt string }

func newUserCredential(t *testing.T) (userCredential, error) {
	t.Helper()
	user, _ := nkeys.CreateUser()
	seed, _ := user.Seed()
	pub, _ := user.PublicKey()
	acct, _ := nkeys.CreateAccount()
	userJWT, err := jwt.NewUserClaims(pub).Encode(acct)
	if err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(t.TempDir(), "nkey.seed")
	if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return userCredential{seedFile: seedFile, jwt: userJWT}, nil
}
