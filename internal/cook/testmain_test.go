package cook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
)

// testPropsTenantID is the tenant used by this package's existing
// props/template tests that aren't specifically about tenant isolation
// (see TestRenderRecipeTemplate_TenantIsolation in template_props_test.go
// for that one) — it matches props' bare, legacy-tenant-scoped functions'
// implicit tenant (tenantID() in internal/props/store.go, "default" here
// since config.FarmerOrganization is never set in this package's tests),
// so prop fixtures written via the existing bare props.SetProp calls stay
// visible once tenantID is threaded through the render chain. Distinct
// from cook_coverage_test.go's own testTenantID ("t_test"), which scopes
// SendCookEvent's farmerConnFor NATS connection lookup instead — an
// unrelated concern that predates this constant.
const testPropsTenantID = "default"

func TestMain(m *testing.M) {
	// Set RecipeDir to the test fixtures directory
	_, filename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	config.RecipeDir = filepath.Join(projectRoot, "testing", "recipes")

	// This package's props.* templating tests need props' PXC-backed store
	// wired up (see internal/props/store.go) — a single shared in-memory
	// db for the whole binary run is fine since every test below uses its
	// own distinct sprout ID.
	gdb, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		fmt.Println("opening props test db:", err)
		os.Exit(1)
	}
	if err := gdb.AutoMigrate(props.Models()...); err != nil {
		fmt.Println("migrating props test db:", err)
		os.Exit(1)
	}
	props.SetDB(gdb)
	// Dispatch seals to the sprout's box key (sealed.go), so it looks one
	// up in pki's store. Nothing enrolls a box key here: a test that
	// dispatches records one for its stub sprout (stage_test.go's
	// newStageSprout, sealed_test.go's setupSealedCook). A sprout without
	// one is sent nothing (FIX.1).
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		fmt.Println("migrating pki test db:", err)
		os.Exit(1)
	}
	pki.SetDB(gdb)

	// Recipes now read through internal/objectstore (see store.go) instead
	// of local disk — seed a fake S3 backend with the same testing/recipes
	// fixture tree the old local-disk store read directly, keyed exactly
	// the way ResolveRecipeFilePath computes them (config.RecipeDir joined
	// with each fixture's path relative to it), so every existing test's
	// recipe names resolve identically.
	store, closeStore, err := objectstoretest.NewStoreForBinary()
	if err != nil {
		fmt.Println("opening recipe test store:", err)
		os.Exit(1)
	}
	if err := seedRecipeFixtures(store, config.RecipeDir); err != nil {
		fmt.Println("seeding recipe test store:", err)
		os.Exit(1)
	}
	SetStore(store)

	// os.Exit below skips defers, so close the fake store's HTTP server
	// explicitly rather than deferring it.
	code := m.Run()
	closeStore()
	os.Exit(code)
}

func seedRecipeFixtures(store *objectstore.Store, dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		return store.Put(context.Background(), path, data)
	})
}

// useRecipeStore installs s as this package's recipe store for the rest of
// t, restoring the binary-wide fixture store (see TestMain) afterwards —
// the same swap-and-restore pattern internal/api/handlers/recipes_test.go
// uses for its recipeStore.
func useRecipeStore(t *testing.T, s *objectstore.Store) {
	t.Helper()
	orig := store
	SetStore(s)
	t.Cleanup(func() { SetStore(orig) })
}

// newRecipeTestStore gives t its own empty objectstoretest-backed recipe
// store, with config.RecipeDir (the recipe key prefix, see getBasePath)
// pointed at a fixed prefix within it, and returns that prefix. Tests write
// recipes with writeRecipe and read them back with mustReadRecipe — both
// go through the store, never local disk.
func newRecipeTestStore(t *testing.T) string {
	t.Helper()
	useRecipeStore(t, objectstoretest.NewStore(t))
	const prefix = "recipes"
	orig := config.RecipeDir
	config.RecipeDir = prefix
	t.Cleanup(func() { config.RecipeDir = orig })
	t.Setenv(RecipeDirEnvVar, "")
	return prefix
}

// writeRecipe puts content at key in the current recipe store.
func writeRecipe(t *testing.T, key, content string) {
	t.Helper()
	objectstoretest.Seed(t, store, map[string]string{key: content})
}

// mustReadRecipe reads key back through readRecipe — the same read path
// recipe resolution itself uses.
func mustReadRecipe(t *testing.T, key string) []byte {
	t.Helper()
	data, err := readRecipe(context.Background(), key)
	if err != nil {
		t.Fatalf("read recipe %s: %v", key, err)
	}
	return data
}
