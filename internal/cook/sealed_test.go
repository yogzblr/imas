package cook

// End-to-end tests for sealed cook dispatches and nudges (sealed.go): a
// real embedded NATS server, farmer's real sendEnvelope / NudgeSprout on
// one connection and the sprout's real RespondCook / RespondNudge on
// another, keys from a mock OpenBao (tenant) and the sprout's own files,
// and a "bus" subscriber standing in for a compromised bus that sees
// everything routed through it. Mirrors internal/ingredients/cmd's
// sealed_test.go.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

type sealedCookEnv struct {
	tenant, sproutID string
	farmer, sprout   *nats.Conn
	kv               *tenantboxtest.Server
	dir              string

	mu       sync.Mutex
	cooked   []RecipeEnvelope // envelopes RespondCook accepted
	nudged   int              // nudges RespondNudge accepted
	recorded []string         // job IDs the DispatchRecorder saw
}

// setupSealedCook wires farmer and one enrolled sprout (web-01) of tenant
// together: the sprout's box key on record farmer-side, the tenant's
// public key pinned sprout-side, and the sprout answering cook and nudge
// with RespondCook and RespondNudge. The pki store is TestMain's.
func setupSealedCook(t *testing.T, tenant string) *sealedCookEnv {
	t.Helper()
	e := &sealedCookEnv{tenant: tenant, sproutID: "web-01", dir: t.TempDir()}
	e.kv = tenantboxtest.Start(t)
	pki.InvalidateTenantBoxKeys(tenant)
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	origGrace, origPriv, origPin, origHandled := config.BoxKeyGraceDuration, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile, config.SproutHandledJobsFile
	t.Cleanup(func() {
		config.BoxKeyGraceDuration, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile, config.SproutHandledJobsFile = origGrace, origPriv, origPin, origHandled
	})
	config.BoxKeyGraceDuration = time.Hour
	config.SproutBoxPrivFile = filepath.Join(e.dir, "box.key")
	config.SproutTenantX25519PubFile = filepath.Join(e.dir, "tenant-x25519.pub")
	config.SproutHandledJobsFile = filepath.Join(e.dir, "handled-jobs")

	// The sprout's own keypair, and farmer's record of its public half.
	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenant, e.sproutID, sproutPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	// The tenant key the sprout pinned at enrollment.
	tenantPub, err := pki.GetTenantX25519PublicKey(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(tenantPub), 0o644); err != nil {
		t.Fatal(err)
	}
	// And the tenant it pinned with it.
	if err := os.WriteFile(pki.SproutTenantIDFile(), []byte(tenant), 0o644); err != nil {
		t.Fatal(err)
	}

	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(ns.Shutdown)
	e.farmer, e.sprout = connectCookTest(t, ns.ClientURL()), connectCookTest(t, ns.ClientURL())
	RegisterFarmerNatsConn(tenant, e.farmer)
	t.Cleanup(func() { UnregisterFarmerNatsConn(tenant) })
	SetDispatchRecorder(func(_, _ string, env RecipeEnvelope) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.recorded = append(e.recorded, env.JobID)
	})
	t.Cleanup(func() { SetDispatchRecorder(nil) })
	e.serve(t, e.sproutID)
	return e
}

func connectCookTest(t *testing.T, url string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// serve answers cook and nudge for sproutID on e.sprout, as
// cmd/sprout/nats.go does, recording what was accepted instead of acting
// on it.
func (e *sealedCookEnv) serve(t *testing.T, sproutID string) {
	t.Helper()
	if _, err := e.sprout.Subscribe(CookSubject(sproutID), func(m *nats.Msg) {
		reply, env := RespondCook(sproutID, m)
		if env != nil {
			e.mu.Lock()
			e.cooked = append(e.cooked, *env)
			e.mu.Unlock()
		}
		m.RespondMsg(reply)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sprout.Subscribe(NudgeSubject(sproutID), func(m *nats.Msg) {
		reply, ok := RespondNudge(sproutID, m)
		if ok {
			e.mu.Lock()
			e.nudged++
			e.mu.Unlock()
		}
		m.RespondMsg(reply)
	}); err != nil {
		t.Fatal(err)
	}
	e.sprout.Flush()
}

func (e *sealedCookEnv) cookedJobs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ids []string
	for _, env := range e.cooked {
		ids = append(ids, env.JobID)
	}
	return ids
}

func (e *sealedCookEnv) nudges() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nudged
}

func (e *sealedCookEnv) recordedJobs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.recorded)
}

// hostile replaces the real sprout with one answering cook with respond.
func (e *sealedCookEnv) hostile(t *testing.T, respond func(m *nats.Msg) *nats.Msg) {
	t.Helper()
	e.sprout.Close()
	h := connectCookTest(t, e.farmer.ConnectedUrl())
	if _, err := h.Subscribe(CookSubject(e.sproutID), func(m *nats.Msg) { m.RespondMsg(respond(m)) }); err != nil {
		t.Fatal(err)
	}
	h.Flush()
}

// cookBusSpy records every payload routed on the given subjects and every
// reply inbox, as a compromised bus would see them.
type cookBusSpy struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func spyOnCookBus(t *testing.T, e *sealedCookEnv, subjects ...string) *cookBusSpy {
	t.Helper()
	spy := &cookBusSpy{}
	nc := connectCookTest(t, e.farmer.ConnectedUrl())
	for _, subj := range append(subjects, "_INBOX.>") {
		if _, err := nc.Subscribe(subj, func(m *nats.Msg) {
			spy.mu.Lock()
			spy.msgs = append(spy.msgs, m)
			spy.mu.Unlock()
		}); err != nil {
			t.Fatal(err)
		}
	}
	nc.Flush()
	return spy
}

func (s *cookBusSpy) waitFor(t *testing.T, n int) []*nats.Msg {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		msgs := slices.Clone(s.msgs)
		s.mu.Unlock()
		if len(msgs) >= n {
			return msgs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bus saw fewer than %d messages", n)
	return nil
}

func secretSteps() []Step {
	return []Step{{
		ID: "write-secret-7c1d", Ingredient: "file", Method: "content",
		Properties: map[string]interface{}{"name": "/etc/app.conf", "text": "db_password=secret-recipe-3a9f"},
	}}
}

// sealedRequest is what farmer would send on sproutID's cook subject
// under purpose, carrying body.
func sealedRequest(t *testing.T, tenant, sproutID, subject, purpose string, body any) *nats.Msg {
	t.Helper()
	data, _, err := pki.SealToSprout(tenant, sproutID, purpose, "", body)
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m
}

func TestSealedCook_RoundTripHidesRecipeFromTheBus(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_rt")
	spy := spyOnCookBus(t, e, CookSubject(e.sproutID))

	if err := SendStepsEvent(e.tenant, e.sproutID, "job-rt", secretSteps()); err != nil {
		t.Fatalf("SendStepsEvent: %v", err)
	}
	if got := e.cookedJobs(); !slices.Equal(got, []string{"job-rt"}) {
		t.Fatalf("sprout accepted %v, want [job-rt]", got)
	}
	e.mu.Lock()
	props := e.cooked[0].Steps[0].Properties
	e.mu.Unlock()
	if props["text"] != "db_password=secret-recipe-3a9f" {
		t.Errorf("sprout opened the wrong steps: %v", props)
	}
	if got := e.recordedJobs(); !slices.Equal(got, []string{"job-rt"}) {
		t.Errorf("dispatch recorder saw %v, want [job-rt]", got)
	}

	for _, m := range spy.waitFor(t, 2) { // the dispatch and its Ack
		for _, secret := range []string{"secret-recipe", "write-secret", "app.conf", "job-rt"} {
			if bytes.Contains(m.Data, []byte(secret)) {
				t.Errorf("the bus saw %q in plaintext on %s: %s", secret, m.Subject, m.Data)
			}
		}
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Errorf("message on %s isn't marked sealed", m.Subject)
		}
	}
}

func TestSealedCook_NudgeRoundTrip(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_nudge")
	spy := spyOnCookBus(t, e, NudgeSubject(e.sproutID))
	if err := NudgeSprout(e.tenant, e.sproutID); err != nil {
		t.Fatalf("NudgeSprout: %v", err)
	}
	if e.nudges() != 1 {
		t.Fatalf("sprout accepted %d nudges, want 1", e.nudges())
	}
	for _, m := range spy.waitFor(t, 2) {
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Errorf("message on %s isn't marked sealed", m.Subject)
		}
	}
}

// What a compromised bus would inject: an unsealed dispatch or nudge. A
// sprout with keys refuses both without acting on them.
func TestSealedCook_SproutRefusesPlaintext(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_plain")
	env, _ := json.Marshal(RecipeEnvelope{JobID: "injected", Steps: secretSteps()})
	for subject, body := range map[string][]byte{CookSubject(e.sproutID): env, NudgeSubject(e.sproutID): nil} {
		reply, err := e.farmer.Request(subject, body, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeEncryptionRequired {
			t.Errorf("%s: refusal code %q, want %q", subject, code, payloadbox.ErrorCodeEncryptionRequired)
		}
	}
	if got := e.cookedJobs(); len(got) != 0 {
		t.Errorf("the sprout accepted a plaintext dispatch: %v", got)
	}
	if e.nudges() != 0 {
		t.Error("the sprout accepted a plaintext nudge")
	}
	// Not recorded as handled either, so it can't shadow a real job.
	if handled, _ := os.ReadFile(config.SproutHandledJobsFile); bytes.Contains(handled, []byte("injected")) {
		t.Error("a refused dispatch was recorded as handled")
	}
}

func TestSealedCook_ReplayIsRefused(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_replay")
	spy := spyOnCookBus(t, e, CookSubject(e.sproutID))
	if err := SendStepsEvent(e.tenant, e.sproutID, "job-once", secretSteps()); err != nil {
		t.Fatal(err)
	}
	var captured *nats.Msg
	for _, m := range spy.waitFor(t, 1) {
		if m.Subject == CookSubject(e.sproutID) {
			captured = m
		}
	}
	// The bus re-sends the captured sealed dispatch.
	replay := nats.NewMsg(captured.Subject)
	replay.Header = captured.Header
	replay.Data = captured.Data
	reply, err := e.farmer.RequestMsg(replay, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if got := e.cookedJobs(); !slices.Equal(got, []string{"job-once"}) {
		t.Errorf("sprout accepted %v, want the job once", got)
	}
}

// A message sealed for another boundary opens under the same keys but is
// refused for its purpose: a cmd.run request or a nudge is never a cook
// dispatch, and a dispatch is never a nudge.
func TestSealedCook_WrongPurposeIsRefused(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_purpose")
	env := RecipeEnvelope{JobID: "wrong-purpose", Steps: secretSteps()}
	cases := map[string]*nats.Msg{
		"cmd.run on cook": sealedRequest(t, e.tenant, e.sproutID, CookSubject(e.sproutID), payloadbox.PurposeCmdRunRequest, env),
		"nudge on cook":   sealedRequest(t, e.tenant, e.sproutID, CookSubject(e.sproutID), payloadbox.PurposeCookNudgeRequest, env),
		"cook reply":      sealedRequest(t, e.tenant, e.sproutID, CookSubject(e.sproutID), payloadbox.PurposeCookResponse, env),
		"cook on nudge":   sealedRequest(t, e.tenant, e.sproutID, NudgeSubject(e.sproutID), payloadbox.PurposeCookRequest, env),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			reply, err := e.farmer.RequestMsg(req, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
				t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
			}
		})
	}
	if got := e.cookedJobs(); len(got) != 0 {
		t.Errorf("sprout accepted %v", got)
	}
	if e.nudges() != 0 {
		t.Error("sprout accepted a dispatch as a nudge")
	}
}

// A dispatch sealed for web-01 names web-01: a sprout enrolled as web-02
// refuses it even though, here, it holds the same keys.
func TestSealedCook_SealedForAnotherSproutIsRefused(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_other_sprout")
	e.serve(t, "web-02")
	req := sealedRequest(t, e.tenant, e.sproutID, CookSubject("web-02"), payloadbox.PurposeCookRequest,
		RecipeEnvelope{JobID: "for-web-01", Steps: secretSteps()})
	reply, err := e.farmer.RequestMsg(req, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if got := e.cookedJobs(); len(got) != 0 {
		t.Errorf("web-02 accepted %v", got)
	}
}

// Another tenant's web-01 has its own box key; a dispatch sealed for it
// doesn't open on this tenant's web-01.
func TestSealedCook_OtherTenantsSproutCannotOpen(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_a")
	otherPub, _, _ := box.GenerateKey(rand.Reader)
	if err := pki.RotateSproutBoxKey("t_cook_sealed_b", e.sproutID, base64.StdEncoding.EncodeToString(otherPub[:]), time.Hour); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys("t_cook_sealed_b") })
	req := sealedRequest(t, "t_cook_sealed_b", e.sproutID, CookSubject(e.sproutID), payloadbox.PurposeCookRequest,
		RecipeEnvelope{JobID: "for-b", Steps: secretSteps()})
	reply, err := e.farmer.RequestMsg(req, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if got := e.cookedJobs(); len(got) != 0 {
		t.Errorf("t_cook_sealed_a's sprout accepted %v", got)
	}
}

// Farmer must not accept anything but a sealed Ack to its own dispatch:
// not plaintext (a downgrade), not its own request reflected back, and
// not a refusal.
func TestSealedCook_FarmerRejectsBadAcks(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_acks")
	var respond func(m *nats.Msg) *nats.Msg
	e.hostile(t, func(m *nats.Msg) *nats.Msg { return respond(m) })

	cases := map[string]struct {
		respond func(m *nats.Msg) *nats.Msg
		want    error
	}{
		"plaintext": {func(m *nats.Msg) *nats.Msg {
			return plainAck(Ack{Acknowledged: true, JobID: "job-bad"})
		}, ErrReplyNotSealed},
		"reflected request": {func(m *nats.Msg) *nats.Msg {
			r := nats.NewMsg("")
			r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			r.Data = m.Data
			return r
		}, payloadbox.ErrOpen},
		"refusal": {func(*nats.Msg) *nats.Msg { return refusal(payloadbox.ErrorCodeOpenFailed) }, ErrSproutRefusedPayload},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			respond = c.respond
			if err := SendStepsEvent(e.tenant, e.sproutID, "job-bad", secretSteps()); !errors.Is(err, c.want) {
				t.Errorf("SendStepsEvent error %v, want %v", err, c.want)
			}
		})
	}
}

// An Ack the sprout sealed for an earlier dispatch is refused, even
// though it opens and names the right job: it doesn't answer this one.
func TestSealedCook_FarmerRejectsAnAckToAnotherRequest(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_stale_ack")
	stale, err := pki.SproutSealForFarmer(e.sproutID, payloadbox.PurposeCookResponse, "some-earlier-request",
		Ack{Acknowledged: true, JobID: "job-stale"})
	if err != nil {
		t.Fatal(err)
	}
	e.hostile(t, func(*nats.Msg) *nats.Msg {
		r := nats.NewMsg("")
		r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		r.Data = stale
		return r
	})
	if err := SendStepsEvent(e.tenant, e.sproutID, "job-stale", secretSteps()); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("SendStepsEvent error %v, want ErrOpen", err)
	}
}

// A nudge Ack must answer this nudge too, and a cook Ack is not a nudge
// Ack.
func TestSealedCook_FarmerRejectsBadNudgeAcks(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_nudge_acks")
	e.sprout.Close()
	h := connectCookTest(t, e.farmer.ConnectedUrl())
	var respond func(m *nats.Msg) *nats.Msg
	h.Subscribe(NudgeSubject(e.sproutID), func(m *nats.Msg) { m.RespondMsg(respond(m)) })
	h.Flush()

	cases := map[string]struct {
		respond func(m *nats.Msg) *nats.Msg
		want    error
	}{
		"plaintext": {func(*nats.Msg) *nats.Msg { return plainAck(Ack{Acknowledged: true}) }, ErrReplyNotSealed},
		"cook ack for this request": {func(m *nats.Msg) *nats.Msg {
			// Seal an Ack under the cook purpose, naming this nudge.
			opened, err := pki.SproutOpenFromFarmer(e.sproutID, payloadbox.PurposeCookNudgeRequest, m.Data)
			if err != nil {
				t.Errorf("opening nudge: %v", err)
				return refusal(payloadbox.ErrorCodeInternal)
			}
			return cookBoundary.reply(e.sproutID, opened, Ack{Acknowledged: true})
		}, payloadbox.ErrOpen},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			respond = c.respond
			if err := NudgeSprout(e.tenant, e.sproutID); !errors.Is(err, c.want) {
				t.Errorf("NudgeSprout error %v, want %v", err, c.want)
			}
		})
	}
}

// Any failure to seal other than "no box key on record" fails the
// dispatch: nothing is sent, in plaintext or otherwise, and nothing is
// recorded.
func TestSealedCook_SealFailureFailsTheDispatch(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_fail")
	spy := spyOnCookBus(t, e, CookSubject(e.sproutID), NudgeSubject(e.sproutID))
	// Tenant keys unavailable: OpenBao is down and nothing is cached.
	e.kv.Close()
	pki.InvalidateTenantBoxKeys(e.tenant)

	if err := SendStepsEvent(e.tenant, e.sproutID, "job-unsealable", secretSteps()); err == nil {
		t.Fatal("SendStepsEvent succeeded without tenant keys")
	}
	if err := NudgeSprout(e.tenant, e.sproutID); err == nil {
		t.Fatal("NudgeSprout succeeded without tenant keys")
	}
	time.Sleep(100 * time.Millisecond) // anything published would have landed
	spy.mu.Lock()
	n := len(spy.msgs)
	spy.mu.Unlock()
	if n != 0 {
		t.Errorf("the bus saw %d messages from a dispatch that couldn't be sealed", n)
	}
	if got := e.recordedJobs(); len(got) != 0 {
		t.Errorf("dispatch recorder saw %v for a dispatch that was never sent", got)
	}
}

// A sprout enrolled before workstream J has no box key on record and no
// keys of its own: cook and nudge stay plaintext for it, as before.
func TestSealedCook_LegacySproutStaysPlaintext(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_legacy")
	const legacy = "legacy-01"
	os.Remove(config.SproutTenantX25519PubFile) // this process now plays a keyless sprout
	e.serve(t, legacy)
	spy := spyOnCookBus(t, e, CookSubject(legacy))

	if err := SendStepsEvent(e.tenant, legacy, "job-legacy", secretSteps()); err != nil {
		t.Fatalf("SendStepsEvent to a legacy sprout: %v", err)
	}
	if err := NudgeSprout(e.tenant, legacy); err != nil {
		t.Fatalf("NudgeSprout to a legacy sprout: %v", err)
	}
	if got := e.cookedJobs(); !slices.Equal(got, []string{"job-legacy"}) {
		t.Errorf("legacy sprout accepted %v, want [job-legacy]", got)
	}
	if e.nudges() != 1 {
		t.Errorf("legacy sprout accepted %d nudges, want 1", e.nudges())
	}
	for _, m := range spy.waitFor(t, 2) {
		if m.Header.Get(payloadbox.Header) != "" {
			t.Errorf("message on %s to a legacy sprout is marked sealed", m.Subject)
		}
	}
}

// The other half of the carve-out: a keyless sprout can't open a sealed
// dispatch (farmer has a box key on record for it, but the sprout lost
// its keys), and says so instead of acting on it.
func TestSealedCook_KeylessSproutRefusesSealed(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_keyless")
	os.Remove(config.SproutTenantX25519PubFile)
	err := SendStepsEvent(e.tenant, e.sproutID, "job-keyless", secretSteps())
	if !errors.Is(err, ErrSproutRefusedPayload) {
		t.Fatalf("SendStepsEvent error %v, want ErrSproutRefusedPayload", err)
	}
	if err := NudgeSprout(e.tenant, e.sproutID); !errors.Is(err, ErrSproutRefusedPayload) {
		t.Fatalf("NudgeSprout error %v, want ErrSproutRefusedPayload", err)
	}
	if got := e.cookedJobs(); len(got) != 0 {
		t.Errorf("keyless sprout accepted %v", got)
	}
}

// Across a tenant key rotation, dispatch keeps working for a sprout still
// pinned to the old key (inside the grace window).
func TestSealedCook_AcrossTenantKeyRotation(t *testing.T) {
	e := setupSealedCook(t, "t_cook_sealed_rotate")
	if _, err := pki.RotateTenantX25519Keypair(e.tenant, false); err != nil {
		t.Fatal(err)
	}
	if err := SendStepsEvent(e.tenant, e.sproutID, "job-rotated", secretSteps()); err != nil {
		t.Fatalf("SendStepsEvent after rotation: %v", err)
	}
	if got := e.cookedJobs(); !slices.Equal(got, []string{"job-rotated"}) {
		t.Errorf("sprout accepted %v, want [job-rotated]", got)
	}
}
