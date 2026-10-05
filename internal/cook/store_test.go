package cook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/props"
)

// --- no store configured ---
//
// There is deliberately no local-disk fallback: a replica with no object
// store must fail with ErrRecipeStoreNotConfigured, and must not look like
// it merely couldn't find the recipe (ErrNoRecipe).

func TestNoStore_FailsClearly(t *testing.T) {
	useRecipeStore(t, nil)
	ctx := context.Background()

	checks := map[string]func() error{
		"readRecipe": func() error {
			_, err := readRecipe(ctx, filepath.Join(getBasePath(), "dev.imas"))
			return err
		},
		"ResolveRecipeFilePath": func() error {
			_, err := ResolveRecipeFilePath(ctx, testPropsTenantID, getBasePath(), "dev")
			return err
		},
		"collectAllIncludes": func() error {
			_, err := collectAllIncludes(ctx, testPropsTenantID, "no-store-sprout", getBasePath(), "dev")
			return err
		},
		"resolveRecipeSteps": func() error {
			_, err := resolveRecipeSteps(ctx, testPropsTenantID, "no-store-sprout", "independent")
			return err
		},
		"SendCookEvent": func() error {
			return SendCookEvent(testTenantID, "no-store-sprout", "independent", GenerateJobID(), false)
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			err := check()
			if !errors.Is(err, ErrRecipeStoreNotConfigured) {
				t.Fatalf("expected ErrRecipeStoreNotConfigured, got %v", err)
			}
			if errors.Is(err, ErrNoRecipe) {
				t.Errorf("not-configured must not also read as ErrNoRecipe: %v", err)
			}
		})
	}
}

func TestReadRecipe_MissingKeyIsErrNoRecipe(t *testing.T) {
	recipeDir := newRecipeTestStore(t)

	_, err := readRecipe(context.Background(), filepath.Join(recipeDir, "absent.imas"))
	if !errors.Is(err, ErrNoRecipe) {
		t.Fatalf("expected ErrNoRecipe for a missing key, got %v", err)
	}
}

// TestSendCookEvent_ReadsFromStore proves the dispatch path reads recipe
// content from the object store: a recipe that exists only in the store
// (the testing/recipes fixtures on disk have no such file) is what reaches
// the sprout.
func TestSendCookEvent_ReadsFromStore(t *testing.T) {
	recipeDir := newRecipeTestStore(t)
	writeRecipe(t, filepath.Join(recipeDir, "storeonly.imas"), `steps:
  only in the bucket:
    cmd.run:
      - name: echo from-object-store
`)

	sproutID := "store-only-sprout"
	got := sendCookStub(t, sproutID, acknowledge)

	if err := SendCookEventContext(context.Background(), testTenantID, sproutID, "storeonly", GenerateJobID(), false); err != nil {
		t.Fatalf("SendCookEventContext: %v", err)
	}
	env := <-got
	if len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo from-object-store" {
		t.Fatalf("unexpected dispatched steps: %+v", env.Steps)
	}
}

func TestResolveRecipeSteps_HonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolveRecipeSteps(ctx, testPropsTenantID, "ctx-sprout", "independent")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from a cancelled ctx, got %v", err)
	}
}

// --- replicas ---

// replicaRecipes is a small recipe tree exercising the parts of resolution
// that read the store more than once: an init.imas, an include and a
// props-templated value, so each replica does several independent
// Get/Exists round trips.
var replicaRecipes = map[string]string{
	"web/init.imas": `include:
  - web.common
steps:
  install nginx:
    cmd.run:
      - name: "install nginx --port={{ props "http_port" }}"
      - requisites:
        - require: base packages
`,
	"web/common.imas": `steps:
  base packages:
    cmd.run:
      - name: install base
`,
}

// dispatchSteps resolves recipeID for sproutID through whichever store is
// currently installed and returns the steps in a canonical, comparable
// form (resolution walks maps, so raw step order isn't stable).
func dispatchSteps(t *testing.T, sproutID string, recipeID RecipeName) []byte {
	t.Helper()
	steps, err := resolveRecipeSteps(context.Background(), testPropsTenantID, sproutID, recipeID)
	if err != nil {
		t.Fatalf("resolveRecipeSteps(%q): %v", recipeID, err)
	}
	sort.Slice(steps, func(i, j int) bool { return steps[i].ID < steps[j].ID })
	b, err := json.Marshal(steps)
	if err != nil {
		t.Fatalf("marshal steps: %v", err)
	}
	return b
}

// TestReplicasResolveIdentically is the property object storage exists to
// provide: two farmer replicas — two separately opened cook stores, pointed
// at the same bucket rather than at two local recipe trees — resolve the
// same recipe to byte-identical dispatch steps, including after the recipe
// changes.
func TestReplicasResolveIdentically(t *testing.T) {
	recipeDir := newRecipeTestStore(t)
	stores := objectstoretest.NewSharedStores(t, 2)
	replicaA, replicaB := stores[0], stores[1]

	const sproutID = "replica-sprout"
	if err := props.SetProp(sproutID, "http_port", "8080"); err != nil {
		t.Fatalf("set prop: %v", err)
	}

	// Seed through replica A only: nothing is ever copied to replica B.
	seed := map[string]string{}
	for rel, content := range replicaRecipes {
		seed[filepath.Join(recipeDir, rel)] = content
	}
	objectstoretest.Seed(t, replicaA, seed)

	SetStore(replicaA)
	fromA := dispatchSteps(t, sproutID, "web")
	SetStore(replicaB)
	fromB := dispatchSteps(t, sproutID, "web")

	if string(fromA) != string(fromB) {
		t.Fatalf("replicas resolved differently:\nA: %s\nB: %s", fromA, fromB)
	}
	var steps []Step
	if err := json.Unmarshal(fromA, &steps); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(steps) != 2 || steps[1].Properties["name"] != "install nginx --port=8080" {
		t.Fatalf("unexpected resolved steps: %s", fromA)
	}

	// A recipe update written through replica B is what replica A serves
	// next — there's no per-replica copy to drift out of sync.
	objectstoretest.Seed(t, replicaB, map[string]string{
		filepath.Join(recipeDir, "web/common.imas"): `steps:
  base packages:
    cmd.run:
      - name: install base v2
`,
	})
	SetStore(replicaA)
	updatedA := dispatchSteps(t, sproutID, "web")
	SetStore(replicaB)
	updatedB := dispatchSteps(t, sproutID, "web")
	if string(updatedA) != string(updatedB) {
		t.Fatalf("replicas diverged after update:\nA: %s\nB: %s", updatedA, updatedB)
	}
	if string(updatedA) == string(fromA) {
		t.Fatalf("update through replica B not visible to replica A: %s", updatedA)
	}

	// Control: a store on a different bucket (the analogue of a replica
	// with its own local recipe tree) doesn't see any of it, so the
	// equality above really comes from the shared bucket.
	SetStore(objectstoretest.NewStore(t))
	if _, err := resolveRecipeSteps(context.Background(), testPropsTenantID, sproutID, "web"); !errors.Is(err, ErrNoRecipe) {
		t.Fatalf("expected ErrNoRecipe from an unshared store, got %v", err)
	}
}

// TestUnreachableStoreFailsTheRequest: with the store installed but its
// endpoint down, a cook fails that one request, reported as neither
// "no recipe" nor "not configured", instead of anything process-wide.
func TestUnreachableStoreFailsTheRequest(t *testing.T) {
	dead := httptest.NewServer(nil)
	endpoint := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()
	s, err := objectstore.Open(objectstore.Config{Endpoint: endpoint, AccessKeyID: "x", SecretAccessKey: "x", Bucket: "recipes"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	useRecipeStore(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = resolveRecipeSteps(ctx, testPropsTenantID, "unreachable-sprout", "independent")
	if err == nil {
		t.Fatal("expected the request to fail against an unreachable store")
	}
	if errors.Is(err, ErrNoRecipe) || errors.Is(err, ErrRecipeStoreNotConfigured) {
		t.Errorf("unreachable store misreported as %v", err)
	}
	t.Logf("failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
}
