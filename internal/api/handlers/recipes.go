// Recipe file serving. This used to be http.FileServer over farmer's
// local-disk basepath (config.RecipeDir) — see
// docs/design/imas-master-plan.md Phase 1: that doesn't survive
// horizontal scaling, since any core replica needs to be able to serve
// any recipe, so reads now go through object storage instead. Git
// remains the source of truth; syncing a merged commit into the bucket
// this reads from is a deploy-time concern (see
// internal/objectstore's package doc), not something this handler does.
//
// GetFile is the raw-bytes-by-exact-key download path sprouts use for the
// farmer:// scheme. Recipe browsing is not served here: the imas CLI and
// imas serve list and read recipes over sealed imas.api.recipes.list and
// imas.api.recipes.get (internal/natsapi/recipes.go).
package handlers

import (
	"net/http"
	"strings"

	"github.com/yogzblr/imas/internal/objectstore"
)

// recipeStore is the object-storage backend GetFile reads from. Set once
// at startup via SetRecipeStore.
var recipeStore *objectstore.Store

// SetRecipeStore installs the object-storage backend GetFile reads from.
func SetRecipeStore(s *objectstore.Store) { recipeStore = s }

// GetFile serves a single recipe file's content, reusing the
// authenticated-download shape of internal/ingredients/file/http's
// client-side provider — a bearer token in the Authorization header (see
// Auth in middleware.go), a GET request, and the raw bytes back — for the
// route sprouts already know as the farmer:// scheme's read path.
//
// A sprout authenticating with its gateway JWT may only read keys under
// SproutFilePrefix for its own (tenant_id, sprout_id) — enforced by Auth
// before this handler runs. That is the
// only route a sprout can read the bucket through, and it never reaches a
// tenant's source recipes (tenants/<tenant_id>/recipes/, see "Recipe key
// layout" in internal/cook/store.go) or the platform tree: farmer renders
// those itself and stages only the result, under the sprout's own prefix.
func GetFile(w http.ResponseWriter, r *http.Request) {
	key := FileKey(r)
	if key == "" || strings.HasSuffix(r.URL.Path, "/") {
		http.NotFound(w, r)
		return
	}
	if recipeStore == nil {
		http.Error(w, "recipe store not configured", http.StatusServiceUnavailable)
		return
	}

	data, err := recipeStore.Get(r.Context(), key)
	if err != nil {
		if objectstore.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to read recipe", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// FileKey returns the object key a GET /files/<key> request names. Auth
// and GetFile both derive the key through this, so the key Auth
// authorizes is exactly the key GetFile reads.
func FileKey(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/files/")
}

// sproutFileRoot is the top-level key prefix under which each sprout's
// own files live, one subtree per (tenant_id, sprout_id).
const sproutFileRoot = "sprouts/"

// SproutFilePrefix returns the key prefix a sprout's gateway JWT
// grants read access to: sprouts/<tenant_id>/<sprout_id>/. Keyed on the
// (tenant_id, sprout_id) pair, never sprout_id alone, since a sprout_id
// is only unique within its tenant. The trailing slash keeps "web-01"
// from also matching "web-010".
func SproutFilePrefix(tenantID, sproutID string) string {
	return sproutFileRoot + tenantID + "/" + sproutID + "/"
}
