package cook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// newStageTestStore gives t its own recipe store on a fake S3 server it
// can inject failures into, with two recipes under config.RecipeDir.
func newStageTestStore(t *testing.T) *objectstoretest.Server {
	t.Helper()
	srv := objectstoretest.NewServer(t)
	s, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatalf("opening fake store: %v", err)
	}
	useRecipeStore(t, s)
	const prefix = "recipes"
	orig := config.RecipeDir
	config.RecipeDir = prefix
	t.Cleanup(func() { config.RecipeDir = orig })
	t.Setenv(RecipeDirEnvVar, "")

	writeRecipe(t, filepath.Join(prefix, "first.imas"), `steps:
  first step:
    cmd.run:
      - name: echo first
`)
	writeRecipe(t, filepath.Join(prefix, "second.imas"), `steps:
  second step:
    cmd.run:
      - name: echo second
`)
	return srv
}

// stageSprout is a stub sprout with a box keypair farmer has on record,
// so dispatches to it are sealed and staged (stage.go), and the tenant
// key it pinned. Tests that start one start the mock OpenBao first
// (useStageKeys).
type stageSprout struct {
	tenant, id string
	priv       *[32]byte
	tenantPub  *[32]byte
}

// useStageKeys starts a mock OpenBao for tenant keypairs for the rest of
// t, with tenants' cached keys dropped before and after.
func useStageKeys(t *testing.T, tenants ...string) {
	t.Helper()
	tenantboxtest.Start(t)
	for _, tenant := range tenants {
		pki.InvalidateTenantBoxKeys(tenant)
		t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	}
}

// newStageSprout records a fresh box key for tenant's sproutID, as
// enrollment would.
func newStageSprout(t *testing.T, tenant, sproutID string) stageSprout {
	t.Helper()
	pub, priv := genBoxKey(t)
	if err := pki.RotateSproutBoxKey(tenant, sproutID, encodeBoxKey(pub), time.Hour); err != nil {
		t.Fatal(err)
	}
	tenantPubB64, err := pki.GetTenantX25519PublicKey(tenant)
	if err != nil {
		t.Fatal(err)
	}
	tenantPub, err := pki.DecodeBoxPubKey(tenantPubB64)
	if err != nil {
		t.Fatal(err)
	}
	return stageSprout{tenant: tenant, id: sproutID, priv: priv, tenantPub: tenantPub}
}

func (s stageSprout) open(data []byte, purpose string) (*payloadbox.Message, error) {
	return payloadbox.Open(data, []payloadbox.KeyPair{{PeerPub: s.tenantPub, Priv: s.priv}},
		payloadbox.Expect{Purpose: purpose, TenantID: s.tenant, SproutID: s.id})
}

// sealedReply is sp's reply to request ID replyTo, body sealed under
// purpose, as the real sprout would send it.
func (s stageSprout) sealedReply(t *testing.T, purpose, replyTo string, body any) *nats.Msg {
	t.Helper()
	reply, err := payloadbox.NewMessage(purpose, s.tenant, s.id, replyTo, body)
	if err != nil {
		t.Error(err)
		return nil
	}
	r := nats.NewMsg("")
	r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	if r.Data, err = payloadbox.Seal(reply, []payloadbox.KeyPair{{PeerPub: s.tenantPub, Priv: s.priv}}); err != nil {
		t.Error(err)
		return nil
	}
	return r
}

// ackCooks answers every sealed cook request for sp, acknowledging it if
// ack is true, and passes each pushed envelope, opened, to pushed.
func ackCooks(t *testing.T, nc *nats.Conn, sp stageSprout, ack bool) <-chan RecipeEnvelope {
	t.Helper()
	return answerCooks(t, nc, sp, func(env RecipeEnvelope) Ack { return Ack{Acknowledged: ack, JobID: env.JobID} })
}

// answerCooks answers every sealed cook request for sp with a sealed
// answer(envelope), and passes each pushed envelope, opened, to pushed.
// A request that doesn't open as a sealed dispatch for sp fails t.
func answerCooks(t *testing.T, nc *nats.Conn, sp stageSprout, answer func(RecipeEnvelope) Ack) <-chan RecipeEnvelope {
	t.Helper()
	pushed := make(chan RecipeEnvelope, 8)
	sub, err := nc.Subscribe(CookSubject(sp.id), func(msg *nats.Msg) {
		m, err := sp.open(msg.Data, payloadbox.PurposeCookRequest)
		if err != nil {
			t.Errorf("opening pushed envelope: %v", err)
			return
		}
		var env RecipeEnvelope
		if err := json.Unmarshal(m.Body, &env); err != nil {
			t.Errorf("unmarshal envelope: %v", err)
			return
		}
		pushed <- env
		if r := sp.sealedReply(t, payloadbox.PurposeCookResponse, m.ID, answer(env)); r != nil {
			msg.RespondMsg(r)
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
	return pushed
}

// ackNudges acknowledges every sealed recipe nudge for sp, sealed.
func ackNudges(t *testing.T, nc *nats.Conn, sp stageSprout) {
	t.Helper()
	sub, err := nc.Subscribe(NudgeSubject(sp.id), func(msg *nats.Msg) {
		m, err := sp.open(msg.Data, payloadbox.PurposeCookNudgeRequest)
		if err != nil {
			t.Errorf("opening nudge: %v", err)
			return
		}
		if r := sp.sealedReply(t, payloadbox.PurposeCookNudgeResponse, m.ID, Ack{Acknowledged: true}); r != nil {
			msg.RespondMsg(r)
		}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
}

func mustStagedKey(t *testing.T, tenantID, sproutID string) string {
	t.Helper()
	key, err := StagedRecipeKey(tenantID, sproutID)
	if err != nil {
		t.Fatalf("StagedRecipeKey(%q, %q): %v", tenantID, sproutID, err)
	}
	return key
}

// readStaged opens sp's staged recipe as sp would.
func readStaged(t *testing.T, sp stageSprout) RecipeEnvelope {
	t.Helper()
	data, err := store.Get(context.Background(), mustStagedKey(t, sp.tenant, sp.id))
	if err != nil {
		t.Fatalf("reading staged recipe for %s/%s: %v", sp.tenant, sp.id, err)
	}
	m, err := sp.open(data, payloadbox.PurposeStagedRecipe)
	if err != nil {
		t.Fatalf("opening staged recipe for %s/%s: %v", sp.tenant, sp.id, err)
	}
	var env RecipeEnvelope
	if err := json.Unmarshal(m.Body, &env); err != nil {
		t.Fatalf("decoding staged recipe: %v", err)
	}
	return env
}

func TestStagedRecipeKey(t *testing.T) {
	if got := mustStagedKey(t, "t_acme", "web-01"); got != "sprouts/t_acme/web-01/recipe.json" {
		t.Errorf("got %q", got)
	}
	// Keyed on the pair: the same sprout_id in two tenants gets two keys.
	if mustStagedKey(t, "t_acme", "web-01") == mustStagedKey(t, "t_other", "web-01") {
		t.Error("same sprout_id in two tenants mapped to one key")
	}
	for _, ids := range [][2]string{
		{"", "web-01"},
		{"t_acme", ""},
		{"t_acme/web-02", "x"}, // would land under web-02's prefix
		{"t_acme", "web-01/../web-02"},
		{"..", "web-01"},
		{"t_acme", "."},
		{"t_acme", `web\01`},
		{"t_acme", "web\x0001"},
	} {
		if key, err := StagedRecipeKey(ids[0], ids[1]); err == nil {
			t.Errorf("StagedRecipeKey(%q, %q) = %q, want an error", ids[0], ids[1], key)
		}
	}
}

// TestSendCookEvent_StagesPushedEnvelope: the staged copy, sealed for
// the sprout under its own purpose, opens to the envelope pushed over
// NATS, at the sprout's own key, and carries none of it in plaintext.
func TestSendCookEvent_StagesPushedEnvelope(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sp := newStageSprout(t, testTenantID, "stage-sprout")
	pushed := ackCooks(t, nc, sp, true)

	jid := GenerateJobID()
	if err := SendCookEvent(testTenantID, sp.id, "first", jid, false, WithInvoker("UINVOKER")); err != nil {
		t.Fatalf("SendCookEvent: %v", err)
	}
	env := readStaged(t, sp)
	if got := <-pushed; !reflect.DeepEqual(got, env) {
		t.Errorf("staged copy differs from pushed envelope:\nstaged: %+v\npushed: %+v", env, got)
	}
	if env.JobID != jid || env.InvokedBy != "UINVOKER" || len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo first" {
		t.Errorf("unexpected staged envelope: %+v", env)
	}
	raw, _ := store.Get(context.Background(), mustStagedKey(t, testTenantID, sp.id))
	for _, plain := range []string{jid, "echo first", "UINVOKER"} {
		if strings.Contains(string(raw), plain) {
			t.Errorf("staged object carries %q in plaintext", plain)
		}
	}
}

// TestSendCookEvent_RestageReplacesPrevious: a second dispatch to the same
// sprout replaces the first one's staged copy, leaving exactly one
// object under the sprout's prefix.
func TestSendCookEvent_RestageReplacesPrevious(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sp := newStageSprout(t, testTenantID, "restage-sprout")
	ackCooks(t, nc, sp, true)

	if err := SendCookEvent(testTenantID, sp.id, "first", GenerateJobID(), false); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	secondJID := GenerateJobID()
	if err := SendCookEvent(testTenantID, sp.id, "second", secondJID, false); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}

	env := readStaged(t, sp)
	if env.JobID != secondJID || len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo second" {
		t.Errorf("staged copy is not the latest dispatch: %+v", env)
	}
	keys, err := store.List(context.Background(), "sprouts/"+testTenantID+"/"+sp.id+"/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("want exactly one staged object, got %v", keys)
	}
}

// TestSendCookEvent_StagesPrunedSteps: with a target step, what's staged
// is the pruned step list actually pushed, not the whole recipe.
func TestSendCookEvent_StagesPrunedSteps(t *testing.T) {
	newStageTestStore(t)
	writeRecipe(t, filepath.Join("recipes", "two.imas"), `steps:
  step a:
    cmd.run:
      - name: echo a
  step b:
    cmd.run:
      - name: echo b
`)
	useStageKeys(t, testTenantID)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sp := newStageSprout(t, testTenantID, "pruned-sprout")
	ackCooks(t, nc, sp, true)

	if err := SendCookEvent(testTenantID, sp.id, "two", GenerateJobID(), false, WithTargetStep("step b")); err != nil {
		t.Fatalf("SendCookEvent: %v", err)
	}
	env := readStaged(t, sp)
	if len(env.Steps) != 1 || env.Steps[0].ID != "step b" {
		t.Errorf("staged steps: got %+v, want only step b", env.Steps)
	}
}

// TestSendCookEvent_StagedCopyKeptWhenPushFails: the staged copy records
// the recipe farmer last assigned, whether or not the sprout acked it.
func TestSendCookEvent_StagedCopyKeptWhenPushFails(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sp := newStageSprout(t, testTenantID, "nack-sprout")
	ackCooks(t, nc, sp, false)

	jid := GenerateJobID()
	if err := SendCookEvent(testTenantID, sp.id, "first", jid, false); err == nil {
		t.Fatal("expected an error for an unacknowledged cook")
	}
	if env := readStaged(t, sp); env.JobID != jid {
		t.Errorf("staged JobID: got %q, want %q", env.JobID, jid)
	}
}

// TestSendCookEvent_TenantsStagedSeparately: the same sprout_id in two
// tenants gets two independent staged copies, each sealed for its own
// tenant's sprout only.
func TestSendCookEvent_TenantsStagedSeparately(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID, "t_other")
	const sproutID = "shared-name"
	other := newStageSprout(t, "t_other", sproutID)
	if err := stageRecipe(context.Background(), "t_other", sproutID, RecipeEnvelope{JobID: "other-tenant-job"}); err != nil {
		t.Fatal(err)
	}
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sp := newStageSprout(t, testTenantID, sproutID)
	ackCooks(t, nc, sp, true)
	jid := GenerateJobID()
	if err := SendCookEvent(testTenantID, sproutID, "first", jid, false); err != nil {
		t.Fatalf("SendCookEvent: %v", err)
	}
	if env := readStaged(t, sp); env.JobID != jid {
		t.Errorf("%s: got JobID %q, want %q", testTenantID, env.JobID, jid)
	}
	if env := readStaged(t, other); env.JobID != "other-tenant-job" {
		t.Errorf("t_other's staged copy was touched: %+v", env)
	}
	data, _ := store.Get(context.Background(), mustStagedKey(t, "t_other", sproutID))
	if _, err := sp.open(data, payloadbox.PurposeStagedRecipe); err == nil {
		t.Error("t_other's staged copy opens for the same sprout_id in another tenant")
	}
}

// TestStageRecipe_FailedWriteRemovesStaleCopy: if the overwrite fails,
// the previous copy is deleted rather than left readable.
func TestStageRecipe_FailedWriteRemovesStaleCopy(t *testing.T) {
	srv := newStageTestStore(t)
	useStageKeys(t, testTenantID)
	newStageSprout(t, testTenantID, "w")
	ctx := context.Background()
	if err := stageRecipe(ctx, testTenantID, "w", RecipeEnvelope{JobID: "old"}); err != nil {
		t.Fatal(err)
	}

	srv.FailNext(1, http.StatusForbidden, "AccessDenied") // the Put
	if err := stageRecipe(ctx, testTenantID, "w", RecipeEnvelope{JobID: "new"}); err != nil {
		t.Fatalf("stageRecipe: got %v, want nil once the stale copy is removed", err)
	}
	if ok, err := store.Exists(ctx, mustStagedKey(t, testTenantID, "w")); err != nil || ok {
		t.Errorf("stale staged copy still present (exists=%v, err=%v)", ok, err)
	}
}

// TestStageRecipe_FailedWriteAndDeleteRefusesDispatch: if the stale copy
// can't be removed either, staging fails, and so does the dispatch.
func TestStageRecipe_FailedWriteAndDeleteRefusesDispatch(t *testing.T) {
	srv := newStageTestStore(t)
	useStageKeys(t, testTenantID)
	newStageSprout(t, testTenantID, "w")
	ctx := context.Background()
	if err := stageRecipe(ctx, testTenantID, "w", RecipeEnvelope{JobID: "old"}); err != nil {
		t.Fatal(err)
	}

	srv.FailNext(2, http.StatusForbidden, "AccessDenied") // the Put, then the Delete
	if err := stageRecipe(ctx, testTenantID, "w", RecipeEnvelope{JobID: "new"}); err == nil {
		t.Fatal("stageRecipe: expected an error when neither write nor delete succeeds")
	}
}

// TestStageRecipe_SealFailureRefusesDispatch: a sprout with a box key on
// record whose payload can't be sealed (here, no tenant key store) gets
// no staged copy and no dispatch: never a plaintext fallback.
func TestStageRecipe_SealFailureRefusesDispatch(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	newStageSprout(t, testTenantID, "w")
	pki.InvalidateTenantBoxKeys(testTenantID)
	t.Setenv("IMAS_TENANTBOX_OPENBAO_ADDR", "")
	if err := stageRecipe(context.Background(), testTenantID, "w", RecipeEnvelope{JobID: "j"}); err == nil {
		t.Fatal("stageRecipe: expected an error when sealing fails")
	}
	if ok, _ := store.Exists(context.Background(), mustStagedKey(t, testTenantID, "w")); ok {
		t.Error("something was staged although sealing failed")
	}
}

func TestUnstageRecipe(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	newStageSprout(t, testTenantID, "gone")
	ctx := context.Background()
	if err := stageRecipe(ctx, testTenantID, "gone", RecipeEnvelope{JobID: "j"}); err != nil {
		t.Fatal(err)
	}
	if err := UnstageRecipe(ctx, testTenantID, "gone"); err != nil {
		t.Fatalf("UnstageRecipe: %v", err)
	}
	if ok, _ := store.Exists(ctx, mustStagedKey(t, testTenantID, "gone")); ok {
		t.Error("staged copy still present after UnstageRecipe")
	}
	// Removing a sprout with nothing staged is not an error.
	if err := UnstageRecipe(ctx, testTenantID, "never-staged"); err != nil {
		t.Errorf("UnstageRecipe with nothing staged: %v", err)
	}
}

func TestStageRecipe_NoStore(t *testing.T) {
	useRecipeStore(t, nil)
	if err := stageRecipe(context.Background(), testTenantID, "w", RecipeEnvelope{}); err != ErrRecipeStoreNotConfigured {
		t.Errorf("stageRecipe: got %v, want ErrRecipeStoreNotConfigured", err)
	}
	if err := UnstageRecipe(context.Background(), testTenantID, "w"); err != ErrRecipeStoreNotConfigured {
		t.Errorf("UnstageRecipe: got %v, want ErrRecipeStoreNotConfigured", err)
	}
}

// TestSendCookEvent_StageGuardFailure: when the stage guard fails, the
// just-staged copy is removed and nothing is pushed.
func TestSendCookEvent_StageGuardFailure(t *testing.T) {
	newStageTestStore(t)
	useStageKeys(t, testTenantID)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sproutID := "guarded-sprout"
	pushed := ackCooks(t, nc, newStageSprout(t, testTenantID, sproutID), true)

	guardErr := errors.New("sprout replaced")
	err := SendCookEvent(testTenantID, sproutID, "first", GenerateJobID(), false,
		WithStageGuard(func() error {
			// The copy is in place when the guard runs.
			if ok, _ := store.Exists(context.Background(), mustStagedKey(t, testTenantID, sproutID)); !ok {
				t.Error("guard ran before the recipe was staged")
			}
			return guardErr
		}))
	if !errors.Is(err, guardErr) {
		t.Fatalf("SendCookEvent: got %v, want the guard's error", err)
	}
	if ok, _ := store.Exists(context.Background(), mustStagedKey(t, testTenantID, sproutID)); ok {
		t.Error("staged copy left in place after the guard failed")
	}
	select {
	case <-pushed:
		t.Error("recipe was pushed although the guard failed")
	default:
	}
}
