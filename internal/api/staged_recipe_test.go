package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// TestStagedRecipeKey_UnderGatewayPrefix: the key cook stages a sprout's
// recipe at is inside the prefix Auth grants that sprout's gateway JWT.
// The two are defined in separate packages (handlers imports cook), so
// this is what keeps them from drifting apart.
func TestStagedRecipeKey_UnderGatewayPrefix(t *testing.T) {
	key, err := cook.StagedRecipeKey("t_acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	rest, ok := strings.CutPrefix(key, handlers.SproutFilePrefix("t_acme", "web-01"))
	if !ok || !isCleanRelKey(rest) {
		t.Errorf("staged key %q is not a clean key under %q", key, handlers.SproutFilePrefix("t_acme", "web-01"))
	}
}

// newStagingTestServer wires one fake S3 bucket in as both cook's recipe
// store (the staging write side) and GetFile's (the read side), the way
// cmd/farmer does, seeds one recipe, and registers an embedded NATS
// server as farmer's connection for each of tenants. Every sprout on it
// acks every cook.
func newStagingTestServer(t *testing.T, tenants ...string) *httptest.Server {
	t.Helper()
	store := objectstoretest.NewStore(t)
	objectstoretest.Seed(t, store, map[string]string{
		"recipes/webserver.imas": "steps:\n  install nginx:\n    cmd.run:\n      - name: echo {{ sproutID }}\n",
	})
	cook.SetStore(store)
	t.Cleanup(func() { cook.SetStore(nil) })
	handlers.SetRecipeStore(store)
	t.Cleanup(func() { handlers.SetRecipeStore(nil) })
	origDir := config.RecipeDir
	config.RecipeDir = "recipes"
	t.Cleanup(func() { config.RecipeDir = origDir })
	t.Setenv(cook.RecipeDirEnvVar, "")

	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	sub, err := nc.Subscribe("imas.sprouts.*.cook", func(msg *nats.Msg) {
		var env cook.RecipeEnvelope
		json.Unmarshal(msg.Data, &env)
		data, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: env.JobID})
		msg.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
	for _, tenant := range tenants {
		cook.RegisterFarmerNatsConn(tenant, nc)
		t.Cleanup(func() { cook.UnregisterFarmerNatsConn(tenant) })
	}

	srv := httptest.NewServer(NewRouter(""))
	t.Cleanup(srv.Close)
	return srv
}

func dispatch(t *testing.T, tenantID, sproutID string) string {
	t.Helper()
	jid := cook.GenerateJobID()
	if err := cook.SendCookEventContext(context.Background(), tenantID, sproutID, "webserver", jid, false); err != nil {
		t.Fatalf("dispatching to %s/%s: %v", tenantID, sproutID, err)
	}
	return jid
}

// TestStagedRecipe_OnlyOwnSproutCanRead stages a recipe for one sprout
// through farmer's real dispatch path, then checks GET /files/ serves it
// to that sprout's gateway JWT and refuses every other correctly signed,
// valid gateway JWT.
func TestStagedRecipe_OnlyOwnSproutCanRead(t *testing.T) {
	key := installGatewayKey(t)
	srv := newStagingTestServer(t, "t_acme")

	jid := dispatch(t, "t_acme", "web-01")
	stagedKey, err := cook.StagedRecipeKey("t_acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/files/" + stagedKey
	exp := time.Now().Add(time.Hour)

	code, body := get(t, url, "Bearer "+mint(t, key.priv, "t_acme", "web-01", exp))
	if code != http.StatusOK {
		t.Fatalf("own sprout: got %d, want 200", code)
	}
	var env cook.RecipeEnvelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decoding served recipe: %v", err)
	}
	if env.JobID != jid || len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo web-01" {
		t.Errorf("served recipe is not web-01's rendered dispatch: %+v", env)
	}

	for name, claims := range map[string][2]string{
		"another sprout, same tenant":    {"t_acme", "web-02"},
		"same sprout_id, another tenant": {"t_other", "web-01"},
		"sprout_id that shares a prefix": {"t_acme", "web-0"},
	} {
		t.Run(name, func(t *testing.T) {
			token := mint(t, key.priv, claims[0], claims[1], exp)
			if code, _ := get(t, url, "Bearer "+token); code != http.StatusForbidden {
				t.Errorf("%s/%s reading web-01's staged recipe: got %d, want 403", claims[0], claims[1], code)
			}
		})
	}
}

// TestStagedRecipe_SameSproutIDInTwoTenants: two tenants' sprouts with
// the same sprout_id each read only their own tenant's rendered recipe.
func TestStagedRecipe_SameSproutIDInTwoTenants(t *testing.T) {
	key := installGatewayKey(t)
	srv := newStagingTestServer(t, "t_acme", "t_other")
	acmeJID := dispatch(t, "t_acme", "web-01")
	otherJID := dispatch(t, "t_other", "web-01")
	exp := time.Now().Add(time.Hour)

	for tenant, wantJID := range map[string]string{"t_acme": acmeJID, "t_other": otherJID} {
		stagedKey, _ := cook.StagedRecipeKey(tenant, "web-01")
		code, body := get(t, srv.URL+"/files/"+stagedKey, "Bearer "+mint(t, key.priv, tenant, "web-01", exp))
		if code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", tenant, code)
		}
		var env cook.RecipeEnvelope
		json.Unmarshal([]byte(body), &env)
		if env.JobID != wantJID {
			t.Errorf("%s/web-01 got JobID %q, want %q", tenant, env.JobID, wantJID)
		}
	}
}

// TestStagedRecipe_ServesOnlyLatestDispatch: after a second dispatch, the
// sprout reads the second job's recipe, never the first.
func TestStagedRecipe_ServesOnlyLatestDispatch(t *testing.T) {
	key := installGatewayKey(t)
	srv := newStagingTestServer(t, "t_acme")
	dispatch(t, "t_acme", "web-01")
	second := dispatch(t, "t_acme", "web-01")

	stagedKey, _ := cook.StagedRecipeKey("t_acme", "web-01")
	code, body := get(t, srv.URL+"/files/"+stagedKey, "Bearer "+mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour)))
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
	var env cook.RecipeEnvelope
	json.Unmarshal([]byte(body), &env)
	if env.JobID != second {
		t.Errorf("served JobID %q, want the latest dispatch %q", env.JobID, second)
	}
}
