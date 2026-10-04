package natsapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/api/client"
	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// testRecipeStore is the binary-wide recipe store TestMain installs in
// internal/cook, restored after tests that swap in their own.
var testRecipeStore *objectstore.Store

// useStageStore installs a fresh recipe store on a fake S3 server t can
// inject failures into, as internal/cook's store for the rest of t.
func useStageStore(t *testing.T) (*objectstoretest.Server, *objectstore.Store) {
	t.Helper()
	srv := objectstoretest.NewServer(t)
	s, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	cook.SetStore(s)
	t.Cleanup(func() { cook.SetStore(testRecipeStore) })
	return srv, s
}

// seedStaged puts a staged recipe for sproutID in the current tenant and
// returns its key.
func seedStaged(t *testing.T, s *objectstore.Store, sproutID string) string {
	t.Helper()
	key, err := cook.StagedRecipeKey(pki.CurrentTenantID(), sproutID)
	if err != nil {
		t.Fatal(err)
	}
	objectstoretest.Seed(t, s, map[string]string{key: `{"JobID":"old-host-job"}`})
	return key
}

func staged(t *testing.T, s *objectstore.Store, key string) bool {
	t.Helper()
	ok, err := s.Exists(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func sproutRegistered(sproutID string) bool {
	registered, _ := pki.NKeyExists(pki.CurrentTenantID(), sproutID, "")
	return registered
}

func TestHandlePKIDelete_UnstagesRecipe(t *testing.T) {
	setupNatsAPIPKI(t)
	_, s := useStageStore(t)
	writeNKey(t, "", "accepted", "web-01", "UKEY_OLD")
	key := seedStaged(t, s, "web-01")
	other := seedStaged(t, s, "web-02")

	if _, err := handlePKIDelete(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01"}`)); err != nil {
		t.Fatalf("handlePKIDelete: %v", err)
	}
	if staged(t, s, key) {
		t.Error("deleted sprout's staged recipe is still readable")
	}
	if !staged(t, s, other) {
		t.Error("another sprout's staged recipe was removed")
	}
}

// TestHandlePKIDelete_RefusedWhenUnstageFails: if the staged recipe can't
// be removed, the sprout isn't deleted either, so the operator can retry.
func TestHandlePKIDelete_RefusedWhenUnstageFails(t *testing.T) {
	setupNatsAPIPKI(t)
	srv, s := useStageStore(t)
	writeNKey(t, "", "accepted", "web-01", "UKEY_OLD")
	key := seedStaged(t, s, "web-01")

	srv.FailNext(1, http.StatusForbidden, "AccessDenied")
	if _, err := handlePKIDelete(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01"}`)); err == nil {
		t.Fatal("handlePKIDelete: expected an error when the staged recipe can't be removed")
	}
	if !sproutRegistered("web-01") {
		t.Error("sprout was deleted although its staged recipe is still there")
	}
	if !staged(t, s, key) {
		t.Fatal("test setup: staged recipe unexpectedly gone")
	}

	// A retry once the store recovers deletes both.
	if _, err := handlePKIDelete(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01"}`)); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if sproutRegistered("web-01") || staged(t, s, key) {
		t.Error("retry left the sprout or its staged recipe behind")
	}
}

// TestHandlePKIAccept_ReplacingBaseUnstagesIt: accepting "web-01_1" hands
// the sprout ID "web-01" to a new host, which must not be able to read
// the old web-01's staged recipe.
func TestHandlePKIAccept_ReplacingBaseUnstagesIt(t *testing.T) {
	setupNatsAPIPKI(t)
	_, s := useStageStore(t)
	writeNKey(t, "", "accepted", "web-01", "UKEY_OLD")
	writeNKey(t, "", "unaccepted", "web-01_1", "UKEY_NEW")
	key := seedStaged(t, s, "web-01")

	if _, err := handlePKIAccept(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01_1"}`)); err != nil {
		t.Fatalf("handlePKIAccept: %v", err)
	}
	if nkey, _ := pki.GetNKey(pki.CurrentTenantID(), "web-01"); nkey != "UKEY_NEW" {
		t.Fatalf("test setup: web-01's nkey is %q, want the new host's", nkey)
	}
	if staged(t, s, key) {
		t.Error("old web-01's staged recipe is readable by the host that replaced it")
	}
}

func TestHandlePKIAccept_ReplacingBaseRefusedWhenUnstageFails(t *testing.T) {
	setupNatsAPIPKI(t)
	srv, s := useStageStore(t)
	writeNKey(t, "", "accepted", "web-01", "UKEY_OLD")
	writeNKey(t, "", "unaccepted", "web-01_1", "UKEY_NEW")
	seedStaged(t, s, "web-01")

	srv.FailNext(1, http.StatusForbidden, "AccessDenied")
	if _, err := handlePKIAccept(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01_1"}`)); err == nil {
		t.Fatal("handlePKIAccept: expected an error when the staged recipe can't be removed")
	}
	if nkey, _ := pki.GetNKey(pki.CurrentTenantID(), "web-01"); nkey != "UKEY_OLD" {
		t.Errorf("web-01 was handed to the new host (nkey %q) although its staged recipe is still there", nkey)
	}
}

// TestHandlePKIAccept_PlainAcceptLeavesStagedRecipe: accepting a sprout
// that replaces no one doesn't touch any staged recipe.
func TestHandlePKIAccept_PlainAcceptLeavesStagedRecipe(t *testing.T) {
	setupNatsAPIPKI(t)
	_, s := useStageStore(t)
	writeNKey(t, "", "unaccepted", "web-01", "UKEY")
	key := seedStaged(t, s, "web-01")

	if _, err := handlePKIAccept(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01"}`)); err != nil {
		t.Fatalf("handlePKIAccept: %v", err)
	}
	if !staged(t, s, key) {
		t.Error("plain accept removed the sprout's staged recipe")
	}
}

func TestHandlePKIDelete_NoRecipeStore(t *testing.T) {
	setupNatsAPIPKI(t)
	cook.SetStore(nil)
	t.Cleanup(func() { cook.SetStore(testRecipeStore) })
	writeNKey(t, "", "accepted", "web-01", "UKEY")

	if _, err := handlePKIDelete(pki.CurrentTenantID(), json.RawMessage(`{"id":"web-01"}`)); err != nil {
		t.Fatalf("handlePKIDelete with no recipe store: %v", err)
	}
}

func TestSproutIdentityGuard(t *testing.T) {
	setupNatsAPIPKI(t)
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_OLD")
	guard := sproutIdentityGuard(tenant, "web-01", "UKEY_OLD")

	if err := guard(); err != nil {
		t.Fatalf("unchanged sprout: %v", err)
	}

	// Replaced by a new host under the same sprout ID.
	writeNKey(t, "", "unaccepted", "web-01_1", "UKEY_NEW")
	if err := pki.AcceptNKey(tenant, "web-01_1"); err != nil {
		t.Fatal(err)
	}
	if err := guard(); err == nil {
		t.Error("guard passed after web-01 was handed to a new host")
	}

	// Deleted.
	if err := pki.DeleteNKey(tenant, "web-01"); err != nil {
		t.Fatal(err)
	}
	if err := sproutIdentityGuard(tenant, "web-01", "UKEY_NEW")(); err == nil {
		t.Error("guard passed after web-01 was deleted")
	}
}

// TestHandleCook_SproutReplacedMidDispatch: a cook targets web-01, then
// web-01 is handed to a new host before the dispatch runs. The dispatch
// must neither leave its staged recipe readable under web-01 nor push it
// to the new host. web-02, unchanged, is dispatched normally.
func TestHandleCook_SproutReplacedMidDispatch(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	_, s := useStageStore(t)
	origDir := config.RecipeDir
	config.RecipeDir = "recipes"
	t.Cleanup(func() { config.RecipeDir = origDir })
	t.Setenv(cook.RecipeDirEnvVar, "")
	objectstoretest.Seed(t, s, map[string]string{
		"recipes/webserver.imas": "steps:\n  install nginx:\n    cmd.run:\n      - name: echo hi\n",
	})

	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_OLD")
	writeNKey(t, "", "accepted", "web-02", "UKEY_WEB02")
	writeNKey(t, "", "unaccepted", "web-01_1", "UKEY_NEW")
	SetNatsConn(tenant, nc)
	defer ClearNatsConn(tenant)
	cook.RegisterFarmerNatsConn(tenant, nc)
	defer cook.UnregisterFarmerNatsConn(tenant)

	setupSealedEnv(t)
	// web-02 has a box key on record, so its staged copy and push are
	// sealed (security review 2026-10-b, B1: nothing is staged for a
	// sprout without one); its stub opens the push and acks it sealed.
	web02Box := newSproutKeypair(t)
	enrollSprout(t, tenant, "web-02", web02Box)
	tenantPub := pinnedTenantPub(t, tenant)

	pushed := make(chan string, 4)
	sub, err := nc.Subscribe("imas.sprouts.*.cook", func(msg *nats.Msg) {
		pushed <- msg.Subject
		var env cook.RecipeEnvelope
		if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			_ = json.Unmarshal(msg.Data, &env)
			ack, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: env.JobID})
			_ = msg.Respond(ack)
			return
		}
		m, err := openAsSprout(web02Box, tenant, tenantPub, "web-02", payloadbox.PurposeCookRequest, msg.Data)
		if err != nil {
			return
		}
		_ = json.Unmarshal(m.Body, &env)
		reply, _ := payloadbox.NewMessage(payloadbox.PurposeCookResponse, tenant, "web-02", m.ID, cook.Ack{Acknowledged: true, JobID: env.JobID})
		r := nats.NewMsg("")
		r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		r.Data, _ = payloadbox.Seal(reply, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: web02Box.priv}})
		_ = msg.RespondMsg(r)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()

	params, _ := json.Marshal(map[string]any{
		"target": []map[string]string{{"id": "web-01"}, {"id": "web-02"}},
		"action": map[string]string{"recipe": "webserver"},
	})
	u := newSealedCLIUserIn(t, tenant)
	result, err := handleCook(apiCaller{TenantID: tenant, UserID: u.id}, params)
	if err != nil {
		t.Fatalf("handleCook: %v", err)
	}
	jid := result.(apitypes.CmdCook).JID

	// Replace web-01 between handleCook and its dispatch. pki.AcceptNKey
	// directly, not handlePKIAccept, so nothing else removes the copy.
	if err := pki.AcceptNKey(tenant, "web-01_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.TriggerCook(nc, jid); err != nil {
		t.Fatalf("triggering cook: %v", err)
	}

	select {
	case subj := <-pushed:
		if subj != "imas.sprouts.web-02.cook" {
			t.Fatalf("pushed to %s, want only web-02", subj)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("web-02 never received its cook")
	}
	// Give web-01's dispatch time to finish too.
	select {
	case subj := <-pushed:
		t.Fatalf("pushed to %s after web-01 was replaced", subj)
	case <-time.After(time.Second):
	}
	web01, _ := cook.StagedRecipeKey(tenant, "web-01")
	web02, _ := cook.StagedRecipeKey(tenant, "web-02")
	if staged(t, s, web01) {
		t.Error("recipe rendered for the old web-01 is staged where the new host can read it")
	}
	if !staged(t, s, web02) {
		t.Error("web-02's recipe was not staged")
	}
}
