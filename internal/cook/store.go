package cook

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
)

// store is the object-storage backend recipes are read from — see
// docs/design/imas-master-plan.md Phase 1: farmer's local-disk recipe
// tree (config.RecipeDir/IMAS_RECIPE_DIR) doesn't survive horizontal
// scaling, since any replica needs to be able to serve any recipe. Git
// remains the source of truth; this package only reads what's already
// been synced into the bucket.
var store *objectstore.Store

// SetStore installs the object-storage backend this package reads
// recipes from. Call once at startup, mirroring RegisterNatsConn's
// injection pattern.
func SetStore(s *objectstore.Store) { store = s }

// readRecipe returns the content of the recipe object at key. It mirrors
// internal/api/handlers/recipes.go's GetFile: no store is a distinct,
// explicit error (never a silent local-disk fallback — that would hide
// exactly the cross-replica inconsistency object storage exists to
// close), and a missing key maps to ErrNoRecipe via objectstore.IsNotExist.
// A recipe over MaxRecipeSourceBytes is ErrRecipeTooLarge, and is never
// read whole.
func readRecipe(ctx context.Context, key string) ([]byte, error) {
	if store == nil {
		return nil, ErrRecipeStoreNotConfigured
	}
	data, err := store.GetLimited(ctx, key, int64(MaxRecipeSourceBytes))
	if err != nil {
		if objectstore.IsNotExist(err) {
			return nil, errors.Join(ErrNoRecipe, err)
		}
		if errors.Is(err, objectstore.ErrObjectTooLarge) {
			return nil, errors.Join(ErrRecipeTooLarge, err)
		}
		return nil, err
	}
	return data, nil
}

// recipeExists reports whether key is present in the recipe store, with
// the same not-configured handling as readRecipe.
func recipeExists(ctx context.Context, key string) (bool, error) {
	if store == nil {
		return false, ErrRecipeStoreNotConfigured
	}
	return store.Exists(ctx, key)
}

// Recipe key layout. FLAG FOR SECURITY REVIEW (SEC.4).
//
// A recipe name resolves under two prefixes, in order, and nowhere else:
//
//	tenants/<tenant_id>/recipes/<path>   the cooking sprout's tenant's own recipes
//	<recipe dir>/<path>                  the platform-wide tree (config.RecipeDir,
//	                                     or IMAS_RECIPE_DIR; see getBasePath)
//
// <path> is the dot-notation name with dots turned into slashes:
// "webserver.nginx" is "webserver/nginx/init.imas" or else
// "webserver/nginx.imas", and an explicit ".imas" suffix names the file
// only. A tenant's recipe shadows a platform recipe of the same name, for
// that tenant's sprouts only, includes included.
//
// The tenant is always the cooking sprout's own (the tenant of the
// connection the cook arrived on). There is no name that reaches another
// tenant's prefix: ParseRecipeName allows only letters, digits, '_' and
// '-' in each segment, so a name can never hold "..", an empty segment or
// a leading slash, and resolveRecipeKey also checks every key it builds
// against the prefix it was built under. The platform prefix may not be
// empty or lie under tenants/, sprouts/ (staged recipes, stage.go) or
// jobs/ (internal/jobs), since a name like "tenants.t_b.recipes.web" would
// otherwise reach into them from an empty prefix.
//
// The platform tree is read-only to tenants: farmer only ever reads it,
// and the SaaS API's recipe upload (design doc §1.6) writes only under
// tenants/<tenant_id>/recipes/.

// tenantRecipeRoot is the top-level prefix of every tenant's own recipes.
const tenantRecipeRoot = "tenants/"

// reservedRecipeRoots are top-level key prefixes the platform recipe tree
// may not sit under.
var reservedRecipeRoots = []string{"tenants", "sprouts", "jobs"}

// Recipe name limits.
const (
	maxRecipeNameLen      = 512
	maxRecipeNameSegments = 32
	maxRecipeSegmentLen   = 128
)

// ErrInvalidRecipeName is returned (joined with ErrNoRecipe) for a recipe
// name ParseRecipeName refuses.
var ErrInvalidRecipeName = errors.New("invalid recipe name")

// ErrRecipePrefixInvalid is returned when the platform recipe prefix is
// empty or under a reserved root, or a tenant ID can't be a key segment.
var ErrRecipePrefixInvalid = errors.New("recipe key prefix is not usable")

// ParseRecipeName splits a recipe name into its path segments and reports
// whether it named the .imas file explicitly. Segments are separated by
// '.' (or '/', which older callers used) and are 1 to 128 of ASCII
// letters, digits, '_' and '-'. The error wraps ErrInvalidRecipeName and
// ErrNoRecipe.
func ParseRecipeName(name string) (segments []string, explicitFile bool, err error) {
	invalid := func(why string) error {
		return errors.Join(ErrNoRecipe, fmt.Errorf("%w: %s", ErrInvalidRecipeName, why))
	}
	if name == "" {
		return nil, false, invalid("empty")
	}
	if len(name) > maxRecipeNameLen {
		return nil, false, invalid("too long")
	}
	ext := "." + config.ImasExt
	if trimmed, ok := strings.CutSuffix(name, ext); ok {
		name, explicitFile = trimmed, true
	}
	segments = strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '/' })
	// FieldsFunc drops empty fields; count separators to catch them.
	if len(segments) == 0 || len(segments) != strings.Count(name, ".")+strings.Count(name, "/")+1 {
		return nil, false, invalid("empty segment")
	}
	if len(segments) > maxRecipeNameSegments {
		return nil, false, invalid("too many segments")
	}
	for _, seg := range segments {
		if !isRecipeNameSegment(seg) {
			return nil, false, invalid("segment must be ASCII letters, digits, '_' or '-'")
		}
	}
	return segments, explicitFile, nil
}

// ValidateRecipeName reports whether name is a recipe name ParseRecipeName
// accepts.
func ValidateRecipeName(name string) error {
	_, _, err := ParseRecipeName(name)
	return err
}

func isRecipeNameSegment(s string) bool {
	if s == "" || len(s) > maxRecipeSegmentLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// TenantRecipePrefix returns tenants/<tenant_id>/recipes/, the prefix
// tenantID's own recipes live under.
func TenantRecipePrefix(tenantID string) (string, error) {
	if !isStageKeySegment(tenantID) {
		return "", fmt.Errorf("%w: tenant %q", ErrRecipePrefixInvalid, tenantID)
	}
	return tenantRecipeRoot + tenantID + "/recipes/", nil
}

// PlatformRecipePrefix returns basepath, cleaned, with a trailing slash,
// or an error if it is empty or under a reserved root (see the key layout
// above).
func PlatformRecipePrefix(basepath string) (string, error) {
	cleaned := path.Clean(filepath.ToSlash(basepath))
	rel := strings.TrimLeft(cleaned, "/")
	if basepath == "" || rel == "" || rel == "." {
		return "", fmt.Errorf("%w: platform recipe prefix %q is empty", ErrRecipePrefixInvalid, basepath)
	}
	first, _, _ := strings.Cut(rel, "/")
	if slices.Contains(reservedRecipeRoots, first) {
		return "", fmt.Errorf("%w: platform recipe prefix %q is under reserved %s/", ErrRecipePrefixInvalid, basepath, first)
	}
	return cleaned + "/", nil
}

// recipeKeyCandidates returns the keys a parsed name may live at under
// prefix, in lookup order, each checked to sit cleanly under prefix.
func recipeKeyCandidates(prefix string, segments []string, explicitFile bool) ([]string, error) {
	rel := strings.Join(segments, "/")
	ext := "." + config.ImasExt
	var keys []string
	if explicitFile {
		keys = []string{prefix + rel + ext}
	} else {
		keys = []string{prefix + rel + "/init" + ext, prefix + rel + ext}
	}
	for _, k := range keys {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok || rest == "" || path.Clean("/"+rest) != "/"+rest {
			return nil, fmt.Errorf("%w: key %q escapes %q", ErrInvalidRecipeName, k, prefix)
		}
	}
	return keys, nil
}

// resolveRecipeKey returns the key name resolves to for tenantID: the
// first existing candidate under tenantID's prefix, then under the
// platform prefix (basepath). See the key layout above.
func resolveRecipeKey(ctx context.Context, tenantID, basepath string, name RecipeName) (string, error) {
	if store == nil {
		return "", ErrRecipeStoreNotConfigured
	}
	segments, explicitFile, err := ParseRecipeName(string(name))
	if err != nil {
		return "", err
	}
	tenantPrefix, err := TenantRecipePrefix(tenantID)
	if err != nil {
		return "", err
	}
	platformPrefix, err := PlatformRecipePrefix(basepath)
	if err != nil {
		return "", err
	}
	for _, prefix := range []string{tenantPrefix, platformPrefix} {
		keys, err := recipeKeyCandidates(prefix, segments, explicitFile)
		if err != nil {
			return "", errors.Join(ErrNoRecipe, err)
		}
		for _, key := range keys {
			ok, err := recipeExists(ctx, key)
			if err != nil {
				return "", err
			}
			if ok {
				return key, nil
			}
		}
	}
	return "", ErrNoRecipe
}
