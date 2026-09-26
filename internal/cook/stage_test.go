package cook

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
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

// ackCooks answers every cook request for sproutID, acknowledging it if
// ack is true, and passes each pushed envelope's raw bytes to pushed.
func ackCooks(t *testing.T, nc *nats.Conn, sproutID string, ack bool) <-chan []byte {
	t.Helper()
	pushed := make(chan []byte, 8)
	sub, err := nc.Subscribe("imas.sprouts."+sproutID+".cook", func(msg *nats.Msg) {
		var env RecipeEnvelope
		if err := json.Unmarshal(msg.Data, &env); err != nil {
			t.Errorf("unmarshal envelope: %v", err)
			return
		}
		pushed <- msg.Data
		data, _ := json.Marshal(Ack{Acknowledged: ack, JobID: env.JobID})
		msg.Respond(data)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
	return pushed
}

func mustStagedKey(t *testing.T, tenantID, sproutID string) string {
	t.Helper()
	key, err := StagedRecipeKey(tenantID, sproutID)
	if err != nil {
		t.Fatalf("StagedRecipeKey(%q, %q): %v", tenantID, sproutID, err)
	}
	return key
}

func readStaged(t *testing.T, tenantID, sproutID string) RecipeEnvelope {
	t.Helper()
	data, err := store.Get(context.Background(), mustStagedKey(t, tenantID, sproutID))
	if err != nil {
		t.Fatalf("reading staged recipe for %s/%s: %v", tenantID, sproutID, err)
	}
	var env RecipeEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
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

// TestSendCookEvent_StagesPushedEnvelope: the staged copy is byte-for-byte
// the envelope pushed over NATS, at the sprout's own key.
func TestSendCookEvent_StagesPushedEnvelope(t *testing.T) {
	newStageTestStore(t)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sproutID := "stage-sprout"
	pushed := ackCooks(t, nc, sproutID, true)

	jid := GenerateJobID()
	if err := SendCookEvent(testTenantID, sproutID, "first", jid, false, WithInvoker("UINVOKER")); err != nil {
		t.Fatalf("SendCookEvent: %v", err)
	}
	staged, err := store.Get(context.Background(), mustStagedKey(t, testTenantID, sproutID))
	if err != nil {
		t.Fatalf("reading staged recipe: %v", err)
	}
	if got := string(<-pushed); got != string(staged) {
		t.Errorf("staged copy differs from pushed envelope:\nstaged: %s\npushed: %s", staged, got)
	}
	env := readStaged(t, testTenantID, sproutID)
	if env.JobID != jid || env.InvokedBy != "UINVOKER" || len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo first" {
		t.Errorf("unexpected staged envelope: %+v", env)
	}
}

// TestSendCookEvent_RestageReplacesPrevious: a second dispatch to the same
// sprout replaces the first one's staged copy, leaving exactly one
// object under the sprout's prefix.
func TestSendCookEvent_RestageReplacesPrevious(t *testing.T) {
	newStageTestStore(t)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sproutID := "restage-sprout"
	ackCooks(t, nc, sproutID, true)

	if err := SendCookEvent(testTenantID, sproutID, "first", GenerateJobID(), false); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	secondJID := GenerateJobID()
	if err := SendCookEvent(testTenantID, sproutID, "second", secondJID, false); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}

	env := readStaged(t, testTenantID, sproutID)
	if env.JobID != secondJID || len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo second" {
		t.Errorf("staged copy is not the latest dispatch: %+v", env)
	}
	keys, err := store.List(context.Background(), "sprouts/"+testTenantID+"/"+sproutID+"/")
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
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sproutID := "pruned-sprout"
	ackCooks(t, nc, sproutID, true)

	if err := SendCookEvent(testTenantID, sproutID, "two", GenerateJobID(), false, WithTargetStep("step b")); err != nil {
		t.Fatalf("SendCookEvent: %v", err)
	}
	env := readStaged(t, testTenantID, sproutID)
	if len(env.Steps) != 1 || env.Steps[0].ID != "step b" {
		t.Errorf("staged steps: got %+v, want only step b", env.Steps)
	}
}

// TestSendCookEvent_StagedCopyKeptWhenPushFails: the staged copy records
// the recipe farmer last assigned, whether or not the sprout acked it.
func TestSendCookEvent_StagedCopyKeptWhenPushFails(t *testing.T) {
	newStageTestStore(t)
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	sproutID := "nack-sprout"
	ackCooks(t, nc, sproutID, false)

	jid := GenerateJobID()
	if err := SendCookEvent(testTenantID, sproutID, "first", jid, false); err == nil {
		t.Fatal("expected an error for an unacknowledged cook")
	}
	if env := readStaged(t, testTenantID, sproutID); env.JobID != jid {
		t.Errorf("staged JobID: got %q, want %q", env.JobID, jid)
	}
}

// TestSendCookEvent_TenantsStagedSeparately: the same sprout_id in two
// tenants gets two independent staged copies.
func TestSendCookEvent_TenantsStagedSeparately(t *testing.T) {
	newStageTestStore(t)
	const sproutID = "shared-name"
	if err := stageRecipe(context.Background(), "t_other", sproutID, RecipeEnvelope{JobID: "other-tenant-job"}); err != nil {
		t.Fatal(err)
	}
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()
	ackCooks(t, nc, sproutID, true)
	jid := GenerateJobID()
	if err := SendCookEvent(testTenantID, sproutID, "first", jid, false); err != nil {
		t.Fatalf("SendCookEvent: %v", err)
	}
	if env := readStaged(t, testTenantID, sproutID); env.JobID != jid {
		t.Errorf("%s: got JobID %q, want %q", testTenantID, env.JobID, jid)
	}
	if env := readStaged(t, "t_other", sproutID); env.JobID != "other-tenant-job" {
		t.Errorf("t_other's staged copy was touched: %+v", env)
	}
}

// TestStageRecipe_FailedWriteRemovesStaleCopy: if the overwrite fails,
// the previous copy is deleted rather than left readable.
func TestStageRecipe_FailedWriteRemovesStaleCopy(t *testing.T) {
	srv := newStageTestStore(t)
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
	ctx := context.Background()
	if err := stageRecipe(ctx, testTenantID, "w", RecipeEnvelope{JobID: "old"}); err != nil {
		t.Fatal(err)
	}

	srv.FailNext(2, http.StatusForbidden, "AccessDenied") // the Put, then the Delete
	if err := stageRecipe(ctx, testTenantID, "w", RecipeEnvelope{JobID: "new"}); err == nil {
		t.Fatal("stageRecipe: expected an error when neither write nor delete succeeds")
	}
}

func TestUnstageRecipe(t *testing.T) {
	newStageTestStore(t)
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
