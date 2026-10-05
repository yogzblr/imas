package saasapi

// REC.1 end to end: a recipe uploaded through the SaaS API is what farmer
// cooks on the next dispatch to a sprout of the same tenant, with no
// restart and no cache to clear, and is invisible to a sprout of another
// tenant. Nothing between the upload and the sprout is mocked except the
// bucket (the in-process fake S3) and the per-tenant NATS accounts (one
// embedded server per tenant):
//
//	PUT /v1/tenants/{A}/recipes/web.hello  (real router, Auth, roles)
//	  -> saasapi writes tenants/A/recipes/web/hello.imas with its own client
//	farmer: cook.SendCookEventContext (real resolution, render, staging)
//	  -> reads the bucket with a separate client, as farmer does
//	  -> pushes on A's connection (nothing staged: these sprouts have no
//	     box key, and a staged copy is only ever sealed)
//	sprout: cook.RespondCook on imas.sprouts.web-01.cook accepts it

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/pki"
)

// cookSprout is one tenant's sprout "web-01" on its own bus, recording the
// envelopes it accepted.
type cookSprout struct {
	mu       sync.Mutex
	accepted []cook.RecipeEnvelope
}

func (s *cookSprout) last(t *testing.T) cook.RecipeEnvelope {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.accepted) == 0 {
		t.Fatal("the sprout accepted no recipe")
	}
	return s.accepted[len(s.accepted)-1]
}

func (s *cookSprout) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.accepted)
}

// startTenantBus starts an embedded NATS server standing in for tenant's
// Account, registers farmer's connection for tenant on it, and answers
// cook for sprout web-01 there with the sprout's real RespondCook.
func startTenantBus(t *testing.T, tenant string) *cookSprout {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(ns.Shutdown)
	connect := func() *nats.Conn {
		nc, err := nats.Connect(ns.ClientURL())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(nc.Close)
		return nc
	}
	farmer, sproutConn := connect(), connect()
	cook.RegisterFarmerNatsConn(tenant, farmer)
	t.Cleanup(func() { cook.UnregisterFarmerNatsConn(tenant) })

	s := &cookSprout{}
	if _, err := sproutConn.Subscribe(cook.CookSubject("web-01"), func(m *nats.Msg) {
		reply, env := cook.RespondCook("web-01", m)
		if env != nil {
			s.mu.Lock()
			s.accepted = append(s.accepted, *env)
			s.mu.Unlock()
		}
		_ = m.RespondMsg(reply)
	}); err != nil {
		t.Fatal(err)
	}
	if err := sproutConn.Flush(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRecipeUploadCooksOnSameTenantOnly(t *testing.T) {
	e := newRecipeEnv(t, nil)
	ctx := context.Background()

	// Farmer's side: its own client on the same bucket, the platform
	// prefix "platform", a pki store with no box keys (plaintext
	// dispatch), and the sprout's handled-jobs file in a temp dir.
	farmerStore, err := objectstore.Open(e.srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	cook.SetStore(farmerStore)
	t.Cleanup(func() { cook.SetStore(nil) })
	t.Setenv(cook.RecipeDirEnvVar, "platform")
	pkiDB, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:rec1_pki_%d?mode=memory&cache=shared", time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := pkiDB.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(pkiDB)
	t.Cleanup(func() { pki.SetDB(nil) })
	origHandled, origPriv, origPin := config.SproutHandledJobsFile, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	t.Cleanup(func() {
		config.SproutHandledJobsFile, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = origHandled, origPriv, origPin
	})
	config.SproutHandledJobsFile = filepath.Join(t.TempDir(), "handled-jobs")
	config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = "", ""

	sproutA, sproutB := startTenantBus(t, e.tA), startTenantBus(t, e.tB)

	// The platform's own web.hello, which tenant A will shadow.
	if err := farmerStore.Put(ctx, "platform/web/hello.imas", []byte("steps:\n  hello:\n    cmd.run:\n      - name: echo platform-version\n")); err != nil {
		t.Fatal(err)
	}
	stepsOf := func(env cook.RecipeEnvelope) string {
		b, _ := json.Marshal(env.Steps)
		return string(b)
	}
	jobs := 0
	cookOn := func(tenant string) error {
		jobs++
		return cook.SendCookEventContext(ctx, tenant, "web-01", "web.hello", fmt.Sprintf("job-%d", jobs), false)
	}
	staged := func(tenant string) string {
		key, err := cook.StagedRecipeKey(tenant, "web-01")
		if err != nil {
			t.Fatal(err)
		}
		v, _ := e.srv.Object(key)
		return v
	}

	// 1. Before any upload, A cooks the platform recipe.
	if err := cookOn(e.tA); err != nil {
		t.Fatal(err)
	}
	if got := stepsOf(sproutA.last(t)); !strings.Contains(got, "platform-version") {
		t.Fatalf("before upload A cooked %s", got)
	}

	// 2. A uploads web.hello; the next cook uses it, no restart.
	v1 := "steps:\n  hello:\n    cmd.run:\n      - name: echo tenant-a-v1\n"
	w := e.put(e.tA, "web.hello", v1, "")
	wantStatus(t, w, http.StatusCreated, "")
	if err := cookOn(e.tA); err != nil {
		t.Fatal(err)
	}
	if got := stepsOf(sproutA.last(t)); !strings.Contains(got, "tenant-a-v1") {
		t.Fatalf("after upload A cooked %s", got)
	}
	// These sprouts have no box key on record (plaintext dispatch), so
	// farmer stages no copy for them (security review 2026-10-b, B1): a
	// staged copy is sealed to the sprout or not written. Sealed staging
	// per tenant is covered by internal/api's
	// TestTenantRecipes_CrossTenantRefusedAtEveryLayer.
	if got := staged(e.tA); got != "" {
		t.Fatalf("A's keyless sprout was staged a copy: %s", got)
	}

	// 3. B's sprout of the same name still gets the platform recipe,
	// never A's, and a name only A has is not found for B.
	if err := cookOn(e.tB); err != nil {
		t.Fatal(err)
	}
	if got := stepsOf(sproutB.last(t)); strings.Contains(got, "tenant-a") || !strings.Contains(got, "platform-version") {
		t.Fatalf("B cooked %s", got)
	}
	wantStatus(t, e.put(e.tA, "only.a", "steps:\n  x:\n    cmd.run:\n      - name: echo tenant-a-only\n", ""), http.StatusCreated, "")
	before := sproutB.count()
	if err := cook.SendCookEventContext(ctx, e.tB, "web-01", "only.a", "job-b-only", false); !errors.Is(err, cook.ErrNoRecipe) {
		t.Fatalf("B cooking A's only.a: %v, want ErrNoRecipe", err)
	}
	if sproutB.count() != before || strings.Contains(staged(e.tB), "tenant-a") {
		t.Fatal("B's sprout received or was staged A's recipe")
	}

	// 4. A replaces it; the very next cook uses the new version.
	v2 := "steps:\n  hello:\n    cmd.run:\n      - name: echo tenant-a-v2\n"
	wantStatus(t, e.put(e.tA, "web.hello", v2, sha256Hex([]byte(v1))), http.StatusOK, "")
	if err := cookOn(e.tA); err != nil {
		t.Fatal(err)
	}
	if got := stepsOf(sproutA.last(t)); !strings.Contains(got, "tenant-a-v2") || strings.Contains(got, "tenant-a-v1") {
		t.Fatalf("after replace A cooked %s", got)
	}

	// 5. A deletes it; the next cook falls back to the platform recipe.
	w = e.do(http.MethodDelete, e.path(e.tA, "web.hello"), e.token(e.tA, recipeWriteRole), "", nil)
	wantStatus(t, w, http.StatusNoContent, "")
	if err := cookOn(e.tA); err != nil {
		t.Fatal(err)
	}
	if got := stepsOf(sproutA.last(t)); !strings.Contains(got, "platform-version") {
		t.Fatalf("after delete A cooked %s", got)
	}
}
