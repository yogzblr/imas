package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
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

// stagingSprouts is the box private key of every stub sprout the current
// test's farmer has on record, by (tenant_id, sprout_id): the keys the
// staged copy and the push are sealed to (internal/cook's stage.go and
// sealed.go). Reset by newStagingTestServer; read by the stub sprouts'
// NATS handlers, so guarded by stagingSproutsMu.
var (
	stagingSproutsMu sync.Mutex
	stagingSprouts   map[[2]string]*[32]byte
)

// stagingSproutKeys returns a snapshot of stagingSprouts.
func stagingSproutKeys() map[[2]string]*[32]byte {
	stagingSproutsMu.Lock()
	defer stagingSproutsMu.Unlock()
	return maps.Clone(stagingSprouts)
}

// newStagingTestServer wires one fake S3 bucket in as both cook's recipe
// store (the staging write side) and GetFile's (the read side), the way
// cmd/farmer does, seeds one recipe, starts a mock OpenBao for the
// tenants' keypairs, and registers an embedded NATS server as farmer's
// connection for each of tenants. Every sprout on it acks every cook.
// Farmer stages a sealed copy only for a sprout with a box key on record
// (security review 2026-10-b, B1): dispatch gives each sprout one first
// (recordStagingSprout), and the stub sprouts open the sealed pushes with
// it and answer sealed Acks.
func newStagingTestServer(t *testing.T, tenants ...string) *httptest.Server {
	t.Helper()
	return newStagingTestServerWithRecipes(t, nil, tenants...)
}

// newStagingTestServerWithRecipes is newStagingTestServer with extra
// objects seeded into the bucket alongside recipes/webserver.imas.
func newStagingTestServerWithRecipes(t *testing.T, extra map[string]string, tenants ...string) *httptest.Server {
	t.Helper()
	tenantboxtest.Start(t)
	for _, tenant := range append([]string{"t_acme", "t_other"}, tenants...) {
		pki.InvalidateTenantBoxKeys(tenant)
		t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	}
	stagingSproutsMu.Lock()
	stagingSprouts = map[[2]string]*[32]byte{}
	stagingSproutsMu.Unlock()
	gdb, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"_pki?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })
	store := objectstoretest.NewStore(t)
	objectstoretest.Seed(t, store, map[string]string{
		"recipes/webserver.imas": "steps:\n  install nginx:\n    cmd.run:\n      - name: echo {{ sproutID }}\n",
	})
	if extra != nil {
		objectstoretest.Seed(t, store, extra)
	}
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
	sub, err := nc.Subscribe("imas.sprouts.*.cook", answerStagingCook)
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

// answerStagingCook is every stub sprout's cook handler: a sealed push
// is opened with whichever recorded sprout key opens it (the same
// sprout_id can be on record in two tenants) and acked sealed; a
// plaintext one, to a sprout with no key on record, is acked in
// plaintext.
func answerStagingCook(msg *nats.Msg) {
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		var env cook.RecipeEnvelope
		json.Unmarshal(msg.Data, &env)
		data, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: env.JobID})
		msg.Respond(data)
		return
	}
	sproutID := strings.TrimSuffix(strings.TrimPrefix(msg.Subject, "imas.sprouts."), ".cook")
	for id, priv := range stagingSproutKeys() {
		if id[1] != sproutID {
			continue
		}
		tenantPub, err := stagingTenantPub(id[0])
		if err != nil {
			continue
		}
		pair := []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: priv}}
		m, err := payloadbox.Open(msg.Data, pair, payloadbox.Expect{Purpose: payloadbox.PurposeCookRequest, TenantID: id[0], SproutID: id[1]})
		if err != nil {
			continue
		}
		var env cook.RecipeEnvelope
		json.Unmarshal(m.Body, &env)
		reply, _ := payloadbox.NewMessage(payloadbox.PurposeCookResponse, id[0], id[1], m.ID, cook.Ack{Acknowledged: true, JobID: env.JobID})
		r := nats.NewMsg("")
		r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		r.Data, _ = payloadbox.Seal(reply, pair)
		msg.RespondMsg(r)
		return
	}
}

func stagingTenantPub(tenantID string) (*[32]byte, error) {
	pub, err := pki.GetTenantX25519PublicKey(tenantID)
	if err != nil {
		return nil, err
	}
	return pki.DecodeBoxPubKey(pub)
}

// recordStagingSprout gives tenantID's sproutID a fresh box key on
// record farmer-side, as enrollment would, unless it already has one.
func recordStagingSprout(t *testing.T, tenantID, sproutID string) {
	t.Helper()
	if _, _, err := pki.ValidSproutBoxKeys(tenantID, sproutID); err == nil {
		return
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenantID, sproutID, base64.StdEncoding.EncodeToString(pub[:]), time.Hour); err != nil {
		t.Fatal(err)
	}
	stagingSproutsMu.Lock()
	stagingSprouts[[2]string{tenantID, sproutID}] = priv
	stagingSproutsMu.Unlock()
}

// openStaged opens body, a staged recipe as GET /files/ served it, as
// tenantID's sproutID would, and fails t if it doesn't open.
func openStaged(t *testing.T, tenantID, sproutID, body string) cook.RecipeEnvelope {
	t.Helper()
	priv := stagingSproutKeys()[[2]string{tenantID, sproutID}]
	tenantPub, err := stagingTenantPub(tenantID)
	if priv == nil || err != nil {
		t.Fatalf("no keys for %s/%s: %v", tenantID, sproutID, err)
	}
	m, err := payloadbox.Open([]byte(body), []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: priv}},
		payloadbox.Expect{Purpose: payloadbox.PurposeStagedRecipe, TenantID: tenantID, SproutID: sproutID})
	if err != nil {
		t.Fatalf("staged recipe for %s/%s does not open for it: %v", tenantID, sproutID, err)
	}
	var env cook.RecipeEnvelope
	if err := json.Unmarshal(m.Body, &env); err != nil {
		t.Fatalf("decoding staged recipe: %v", err)
	}
	return env
}

// dispatch cooks webserver on tenantID's sproutID through farmer's real
// dispatch path, recording a box key for the sprout first if it has none.
func dispatch(t *testing.T, tenantID, sproutID string) string {
	t.Helper()
	recordStagingSprout(t, tenantID, sproutID)
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
	if strings.Contains(body, jid) || strings.Contains(body, "echo web-01") {
		t.Errorf("served staged recipe is readable in plaintext: %s", body)
	}
	env := openStaged(t, "t_acme", "web-01", body)
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
		if env := openStaged(t, tenant, "web-01", body); env.JobID != wantJID {
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
	if env := openStaged(t, "t_acme", "web-01", body); env.JobID != second {
		t.Errorf("served JobID %q, want the latest dispatch %q", env.JobID, second)
	}
}
