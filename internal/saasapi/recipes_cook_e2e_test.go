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
//	  -> stages a copy sealed to A's sprout, and pushes the dispatch,
//	     sealed to it, on A's connection
//	sprout: a stub with its own box key (internal/cook/cooktest) opens
//	     the sealed dispatch on imas.sprouts.web-01.cook and acknowledges
//	     it. Since FIX.1 farmer sends nothing to a sprout with no box key,
//	     so each tenant's web-01 is enrolled with one; the stub stands in
//	     for cook.RespondCook because one process can only hold one
//	     sprout's keys, and this test runs a web-01 in each of two tenants.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/cook/cooktest"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// cookSprout is one tenant's sprout "web-01" on its own bus, recording the
// envelopes it accepted.
type cookSprout struct {
	*cooktest.Sprout
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
// cook for sprout web-01 there with a stub sprout enrolled with its own
// box key (cooktest), acknowledging every sealed dispatch it opens.
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

	s := &cookSprout{Sprout: cooktest.NewSprout(t, tenant, "web-01")}
	s.AnswerCooks(t, sproutConn, func(env cook.RecipeEnvelope) cook.Ack {
		s.mu.Lock()
		s.accepted = append(s.accepted, env)
		s.mu.Unlock()
		return cooktest.Acknowledge(env)
	})
	return s
}

func TestRecipeUploadCooksOnSameTenantOnly(t *testing.T) {
	e := newRecipeEnv(t, nil)
	ctx := context.Background()

	// Farmer's side: its own client on the same bucket, the platform
	// prefix "platform", a pki store holding each sprout's box key, and
	// a mock OpenBao for the tenant keypairs it seals with.
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
	tenantboxtest.Start(t)
	for _, tenant := range []string{e.tA, e.tB} {
		pki.InvalidateTenantBoxKeys(tenant)
		t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	}

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
	// The staged copy is sealed to A's sprout (security review 2026-10-b,
	// B1): unreadable in the bucket, and it opens for that sprout to the
	// recipe just cooked. Cross-tenant staging is also covered by
	// internal/api's TestTenantRecipes_CrossTenantRefusedAtEveryLayer.
	stagedA := staged(e.tA)
	if stagedA == "" || strings.Contains(stagedA, "tenant-a-v1") {
		t.Fatalf("A's staged copy is missing or readable in the bucket: %q", stagedA)
	}
	if env, err := sproutA.OpenStaged([]byte(stagedA)); err != nil || !strings.Contains(stepsOf(env), "tenant-a-v1") {
		t.Fatalf("A's staged copy: %v, %s", err, stepsOf(env))
	}
	if _, err := sproutB.OpenStaged([]byte(stagedA)); err == nil {
		t.Fatal("B's sprout opened A's staged copy")
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
	if sproutB.count() != before {
		t.Fatal("B's sprout received A's recipe")
	}
	if env, err := sproutB.OpenStaged([]byte(staged(e.tB))); err != nil || strings.Contains(stepsOf(env), "tenant-a") || !strings.Contains(stepsOf(env), "platform-version") {
		t.Fatalf("B's staged copy: %v, %s", err, stepsOf(env))
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
