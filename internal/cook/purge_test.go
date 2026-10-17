package cook

import (
	"context"
	"testing"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// PurgeTenantObjects deletes the tenant's recipes, recipe audit and staged
// recipes, and nothing of another tenant's or the platform's.
func TestPurgeTenantObjects(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	s, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	useRecipeStore(t, s)
	ctx := context.Background()
	keep := []string{"recipes/platform.imas", "tenants/t_b/recipes/web.imas", "tenants/t_ab/recipes/web.imas", "sprouts/t_b/web-01/recipe.json"}
	for _, k := range append([]string{"tenants/t_a/recipes/web.imas", "tenants/t_a/recipe-audit/2026-10-17/a.json", "sprouts/t_a/web-01/recipe.json"}, keep...) {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := PurgeTenantObjects(ctx, "t_a", 1)
	if err != nil || counts["objects.recipes"] != 2 || counts["objects.staged_recipes"] != 1 {
		t.Fatalf("PurgeTenantObjects = %v, %v", counts, err)
	}
	if keys := srv.Keys(); len(keys) != len(keep) {
		t.Fatalf("keys left %v, want %v", keys, keep)
	}
	if counts, err := PurgeTenantObjects(ctx, "t_a", 1); err != nil || counts["objects.recipes"]+counts["objects.staged_recipes"] != 0 {
		t.Errorf("second PurgeTenantObjects = %v, %v", counts, err)
	}
	useRecipeStore(t, nil)
	if _, err := PurgeTenantObjects(ctx, "t_a", 1); err == nil {
		t.Error("no store: want an error")
	}
}
