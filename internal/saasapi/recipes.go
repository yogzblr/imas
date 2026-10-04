package saasapi

// Tenant recipes: upload, list, read and delete (design doc §1.6, REC.1).
// FLAG FOR SECURITY REVIEW: a tenant's recipe is code that runs as root
// on every sprout of that tenant that cooks it, and its template is
// untrusted input that farmer renders.
//
//	GET    /v1/tenants/{tenant_id}/recipes          list, paged      read role
//	GET    /v1/tenants/{tenant_id}/recipes/{name}   content + sha256 read role
//	PUT    /v1/tenants/{tenant_id}/recipes/{name}   create/replace   write role, rate-limited
//	DELETE /v1/tenants/{tenant_id}/recipes/{name}   delete           write role, rate-limited
//
// Every route sits behind Auth, so {tenant_id} is the caller's own
// organization. The tenant's recipes live at the key layout SEC.4 settled
// (internal/cook/store.go, "Recipe key layout"):
//
//	tenants/<tenant_id>/recipes/<name with dots as slashes>.imas
//
// recipeObjectKey is the one function that maps a name to a key; every
// route uses it, and none takes a key, a prefix or a tenant from the
// body or the query. Names are stricter than cook.ParseRecipeName (see
// validateUploadRecipeName), so each name has exactly one key, and every
// name accepted here is one farmer resolves to that same key for a sprout
// of this tenant.
//
// saasapi writes the bucket directly, with its own credential limited to
// tenants/ (recipes_config.go). Farmer reads recipes from the bucket on
// every cook with no cache, so an upload is used by the next cook.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// Upload name limits. They sit inside cook.ParseRecipeName's (512 bytes,
// 32 segments of 128), so farmer accepts every name accepted here.
const (
	maxUploadRecipeNameLen    = 200
	maxUploadRecipeSegments   = 16
	maxUploadRecipeSegmentLen = 64
)

// reservedRecipeFirstSegments may not start an uploaded name: they are the
// bucket's reserved roots (tenants/, sprouts/ staged recipes, jobs/). A
// name is always placed under the tenant's own prefix, so this is defence
// in depth against a resolver that ever falls back to the bucket root,
// and keeps names from reading like keys.
var reservedRecipeFirstSegments = []string{"tenants", "sprouts", "jobs"}

// reservedRecipeLastSegments may not end an uploaded name. "x.imas" is
// what cook reads as "the file x.imas", and "x.init" is stored at
// x/init.imas, which cook resolves for the name "x" ahead of x.imas: both
// would make one upload answer to two names.
var reservedRecipeLastSegments = []string{"imas", "init"}

// recipeObjectExt is the recipe file suffix (config.ImasExt).
const recipeObjectExt = ".imas"

// recipeObjectContentType is the Content-Type uploaded recipes are stored with.
const recipeObjectContentType = "text/yaml; charset=utf-8"

// List paging.
const (
	defaultRecipePageSize = 100
	maxRecipePageSize     = 500
	maxRecipePageTokenLen = 1024
)

// errInvalidRecipeName is wrapped by validateUploadRecipeName's errors;
// the rest of each message names the rule broken, never the name.
var errInvalidRecipeName = errors.New("invalid recipe name")

// validateUploadRecipeName checks a recipe name for upload: 1 to 200
// bytes; 1 to 16 segments separated by '.'; each segment 1 to 64 of
// lowercase ASCII letters, digits, '-' and '_', starting with a letter or
// digit (so no empty or dot-only segment, no slash, no traversal, nothing
// encoded); not starting with a reserved root (tenants, sprouts, jobs) and
// not ending in imas or init. It also requires cook.ParseRecipeName to
// accept it as a plain (not explicit-file) name.
func validateUploadRecipeName(name string) error {
	invalid := func(why string) error { return fmt.Errorf("%w: %s", errInvalidRecipeName, why) }
	if name == "" {
		return invalid("the name is empty")
	}
	if len(name) > maxUploadRecipeNameLen {
		return invalid(fmt.Sprintf("the name is longer than %d bytes", maxUploadRecipeNameLen))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return invalid("the name may hold only lowercase letters, digits, '.', '-' and '_'")
		}
	}
	segments := strings.Split(name, ".")
	if len(segments) > maxUploadRecipeSegments {
		return invalid(fmt.Sprintf("the name has more than %d dot-separated segments", maxUploadRecipeSegments))
	}
	for _, seg := range segments {
		if seg == "" {
			return invalid("the name has an empty segment (a leading, trailing or doubled '.')")
		}
		if len(seg) > maxUploadRecipeSegmentLen {
			return invalid(fmt.Sprintf("a segment is longer than %d bytes", maxUploadRecipeSegmentLen))
		}
		if c := seg[0]; c == '-' || c == '_' {
			return invalid("each segment must start with a letter or digit")
		}
	}
	if slices.Contains(reservedRecipeFirstSegments, segments[0]) {
		return invalid("the name may not start with a reserved prefix (tenants, sprouts, jobs)")
	}
	if slices.Contains(reservedRecipeLastSegments, segments[len(segments)-1]) {
		return invalid("the name may not end in .imas or .init")
	}
	if _, explicitFile, err := cook.ParseRecipeName(name); err != nil || explicitFile {
		return invalid("farmer would not resolve this name")
	}
	return nil
}

// recipeObjectKey returns the object key of tenantID's recipe name:
// tenants/<tenant_id>/recipes/<name, dots as slashes>.imas. It is the only
// name-to-key mapping the recipe routes use. It validates both inputs and
// checks the key sits cleanly under the tenant's prefix.
func recipeObjectKey(tenantID, name string) (string, error) {
	if err := validateUploadRecipeName(name); err != nil {
		return "", err
	}
	prefix, err := cook.TenantRecipePrefix(tenantID)
	if err != nil {
		return "", err
	}
	rel := strings.ReplaceAll(name, ".", "/") + recipeObjectExt
	key := prefix + rel
	if !strings.HasPrefix(key, prefix) || strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("%w: key escapes the tenant prefix", errInvalidRecipeName)
	}
	return key, nil
}

// recipeNameFromKey is recipeObjectKey's inverse for a key listed under
// prefix (the tenant's recipe prefix): the name, if the key is exactly
// what recipeObjectKey makes of it, else ok is false.
func recipeNameFromKey(tenantID, prefix, key string) (string, bool) {
	rel, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return "", false
	}
	rel, ok = strings.CutSuffix(rel, recipeObjectExt)
	if !ok || strings.Contains(rel, ".") {
		return "", false
	}
	name := strings.ReplaceAll(rel, "/", ".")
	if k, err := recipeObjectKey(tenantID, name); err != nil || k != key {
		return "", false
	}
	return name, true
}

// isRecipeKeySegment reports whether tenantID can stand as a key segment.
func isRecipeKeySegment(tenantID string) bool {
	_, err := cook.TenantRecipePrefix(tenantID)
	return err == nil
}

// recipePathEncoded reports whether the request path was sent with any
// percent-encoding. Recipe names never need it, so an encoded name (an
// encoded '/', '.' or anything else) is refused before it is decoded into
// something else.
func recipePathEncoded(r *http.Request) bool {
	p := r.RequestURI
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return strings.Contains(p, "%") || strings.Contains(r.URL.EscapedPath(), "%")
}

// recipeProblem is a refusal: status, code and a message that names the
// rule broken. It never carries any of the request body.
type recipeProblem struct {
	status  int
	code    string
	message string
	details map[string]any
}

func (p *recipeProblem) write(w http.ResponseWriter) {
	writeErrorDetails(w, p.status, p.code, p.message, p.details)
}

// recipeRecord is what the routes report about one stored recipe.
type recipeRecord struct {
	Name      string    `json:"name"`
	SHA256    string    `json:"sha256,omitempty"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
	// Content is set by GET .../recipes/{name} only.
	Content *string `json:"content,omitempty"`
}

type recipeListResponse struct {
	Recipes       []recipeRecord `json:"recipes"`
	NextPageToken string         `json:"next_page_token,omitempty"`
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func setRecipeETag(w http.ResponseWriter, sha string) {
	w.Header().Set("ETag", `"`+sha+`"`)
}

// currentRecipe is the stored object at a recipe key, if any.
type currentRecipe struct {
	exists bool
	data   []byte
	sha    string // empty if the object is over the size limit (unreadable)
	info   objectstore.ObjectInfo
}

// readCurrent reads the object at key, at most the source size limit. An
// object over the limit (written some other way) exists with an unknown
// sha256.
func (svc *recipeService) readCurrent(ctx context.Context, key string) (currentRecipe, error) {
	data, info, err := svc.store.GetLimitedWithInfo(ctx, key, int64(cook.CurrentRenderLimits().MaxSourceBytes))
	switch {
	case err == nil:
		return currentRecipe{exists: true, data: data, sha: sha256Hex(data), info: info}, nil
	case objectstore.IsNotExist(err):
		return currentRecipe{}, nil
	case errors.Is(err, objectstore.ErrObjectTooLarge):
		return currentRecipe{exists: true, info: info}, nil
	default:
		return currentRecipe{}, err
	}
}

// recipeTarget is the validated (tenant, name, key) a per-recipe request
// names.
type recipeTarget struct {
	tenantID string
	name     string
	key      string
}

// target validates the request's {name}: refused if percent-encoded or
// invalid, before anything else reads it.
func recipeTargetFrom(r *http.Request) (recipeTarget, *recipeProblem) {
	tenantID := r.PathValue("tenant_id")
	if recipePathEncoded(r) {
		return recipeTarget{}, &recipeProblem{status: http.StatusBadRequest, code: "invalid_recipe_name",
			message: "invalid recipe name: the path may not be percent-encoded"}
	}
	name := r.PathValue("name")
	key, err := recipeObjectKey(tenantID, name)
	if err != nil {
		msg := "invalid recipe name"
		if errors.Is(err, errInvalidRecipeName) {
			msg = err.Error()
		}
		return recipeTarget{}, &recipeProblem{status: http.StatusBadRequest, code: "invalid_recipe_name", message: msg}
	}
	return recipeTarget{tenantID: tenantID, name: name, key: key}, nil
}

// configured answers 503 when recipe upload is off.
func (svc *recipeService) configured(w http.ResponseWriter) bool {
	if svc.store == nil {
		writeError(w, http.StatusServiceUnavailable, "recipes_not_configured", "recipe storage is not configured on this deployment")
		return false
	}
	return true
}

// ListRecipes handles GET /v1/tenants/{tenant_id}/recipes?limit=&page_token=.
func (svc *recipeService) ListRecipes(w http.ResponseWriter, r *http.Request) {
	if !svc.configured(w) {
		return
	}
	tenantID := r.PathValue("tenant_id")
	prefix, err := cook.TenantRecipePrefix(tenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant id")
		return
	}
	limit := defaultRecipePageSize
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxRecipePageSize {
			writeErrorDetails(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be a whole number from 1 to %d", maxRecipePageSize), map[string]any{"max": maxRecipePageSize})
			return
		}
		limit = n
	}
	startAfter := ""
	if tok := r.URL.Query().Get("page_token"); tok != "" {
		rel, ok := decodeRecipePageToken(tok)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_page_token", "page_token is not one this API returned")
			return
		}
		startAfter = prefix + rel
	}
	if !tenantExists(w, tenantID) {
		return
	}
	objs, more, err := svc.store.ListPage(r.Context(), prefix, startAfter, limit)
	if err != nil {
		log.Errorf("saasapi: listing recipes of tenant %s: %v", tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be read")
		return
	}
	resp := recipeListResponse{Recipes: []recipeRecord{}}
	for _, o := range objs {
		// Keys that are not exactly an uploadable name's key (written some
		// other way) are skipped, but still advance the cursor.
		if name, ok := recipeNameFromKey(tenantID, prefix, o.Key); ok {
			resp.Recipes = append(resp.Recipes, recipeRecord{Name: name, Size: o.Size, UpdatedAt: o.LastModified.UTC()})
		}
	}
	if more && len(objs) > 0 {
		resp.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(strings.TrimPrefix(objs[len(objs)-1].Key, prefix)))
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeRecipePageToken decodes a page token to the key (relative to the
// tenant's prefix) the listing continues after. Any key is harmless (the
// listing is bounded by the prefix), but only key-shaped text is accepted.
func decodeRecipePageToken(tok string) (string, bool) {
	if len(tok) > maxRecipePageTokenLen*2 {
		return "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) == 0 || len(b) > maxRecipePageTokenLen {
		return "", false
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '/') {
			return "", false
		}
	}
	return string(b), true
}

// GetRecipe handles GET /v1/tenants/{tenant_id}/recipes/{name}: the
// content, sha256, size and modification time, with the sha256 as the
// ETag (for If-Match on a later PUT).
func (svc *recipeService) GetRecipe(w http.ResponseWriter, r *http.Request) {
	if !svc.configured(w) {
		return
	}
	t, p := recipeTargetFrom(r)
	if p != nil {
		p.write(w)
		return
	}
	if !tenantExists(w, t.tenantID) {
		return
	}
	cur, err := svc.readCurrent(r.Context(), t.key)
	if err != nil {
		log.Errorf("saasapi: reading recipe %s of tenant %s: %v", t.name, t.tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be read")
		return
	}
	if !cur.exists {
		writeError(w, http.StatusNotFound, "recipe_not_found", "no recipe with this name")
		return
	}
	if cur.sha == "" {
		writeError(w, http.StatusUnprocessableEntity, "recipe_unreadable", "the stored recipe is over the size limit and cannot be read or cooked")
		return
	}
	content := string(cur.data)
	setRecipeETag(w, cur.sha)
	writeJSON(w, http.StatusOK, recipeRecord{Name: t.name, SHA256: cur.sha, Size: int64(len(cur.data)), UpdatedAt: cur.info.LastModified.UTC(), Content: &content})
}

// recipePrecondition is a write's parsed If-Match / If-None-Match.
type recipePrecondition struct {
	ifMatchSHA  string // a specific sha256
	ifMatchAny  bool   // If-Match: *
	ifNoneMatch bool   // If-None-Match: *
}

func (c recipePrecondition) set() bool { return c.ifMatchSHA != "" || c.ifMatchAny || c.ifNoneMatch }

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// parseRecipePrecondition reads If-Match (one strong tag: the sha256 in
// hex, quoted or not, or *) and If-None-Match (* only). allowNoneMatch is
// false for DELETE.
func parseRecipePrecondition(r *http.Request, allowNoneMatch bool) (recipePrecondition, *recipeProblem) {
	bad := func(msg string) *recipeProblem {
		return &recipeProblem{status: http.StatusBadRequest, code: "invalid_precondition", message: msg}
	}
	var c recipePrecondition
	if vals := r.Header.Values("If-None-Match"); len(vals) > 0 {
		if !allowNoneMatch {
			return c, bad("If-None-Match is not supported on this route")
		}
		if len(vals) != 1 || strings.TrimSpace(vals[0]) != "*" {
			return c, bad(`If-None-Match must be "*" (create only)`)
		}
		c.ifNoneMatch = true
	}
	if vals := r.Header.Values("If-Match"); len(vals) > 0 {
		v := strings.TrimSpace(vals[0])
		if len(vals) != 1 || strings.Contains(v, ",") {
			return c, bad("If-Match must name exactly one sha256")
		}
		switch {
		case v == "*":
			c.ifMatchAny = true
		case strings.HasPrefix(v, "W/"):
			return c, bad("If-Match must be a strong tag: the recipe's sha256")
		default:
			v = strings.ToLower(strings.Trim(v, `"`))
			if !sha256HexRe.MatchString(v) {
				return c, bad("If-Match must be the recipe's sha256, 64 hex digits, or *")
			}
			c.ifMatchSHA = v
		}
	}
	if c.ifNoneMatch && (c.ifMatchAny || c.ifMatchSHA != "") {
		return c, bad("send If-Match or If-None-Match, not both")
	}
	return c, nil
}

// check evaluates c against the stored object.
func (c recipePrecondition) check(cur currentRecipe) *recipeProblem {
	fail := func(msg string) *recipeProblem {
		p := &recipeProblem{status: http.StatusPreconditionFailed, code: "precondition_failed", message: msg}
		if cur.exists && cur.sha != "" {
			p.details = map[string]any{"current_sha256": cur.sha}
		}
		return p
	}
	switch {
	case c.ifNoneMatch && cur.exists:
		return fail("a recipe with this name already exists")
	case (c.ifMatchAny || c.ifMatchSHA != "") && !cur.exists:
		return fail("no recipe with this name exists")
	case c.ifMatchSHA != "" && cur.sha != c.ifMatchSHA:
		return fail("the recipe has changed since it was read: get it again and resend with its current sha256")
	}
	return nil
}

// allowedRecipeContentTypes are the media types a PUT body may declare.
// No Content-Type at all is accepted too.
var allowedRecipeContentTypes = []string{"application/yaml", "application/x-yaml", "text/yaml", "text/x-yaml", "text/plain"}

func checkRecipeContentType(r *http.Request) *recipeProblem {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return nil
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err == nil && slices.Contains(allowedRecipeContentTypes, mt) {
		if cs, ok := params["charset"]; !ok || strings.EqualFold(cs, "utf-8") {
			return nil
		}
	}
	return &recipeProblem{status: http.StatusUnsupportedMediaType, code: "unsupported_media_type",
		message: "send the recipe as application/yaml (or text/yaml, text/plain), UTF-8"}
}

// recipeValidationSlots bounds how many uploads are rendered at once
// across all tenants: each render may use a CPU for the render timeout.
var recipeValidationSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

var (
	templateLineRe = regexp.MustCompile(`^template: [^:]*:(\d+)`)
	yamlLineRe     = regexp.MustCompile(`^yaml: line (\d+)`)
)

// validateRecipeBody checks an upload before anything is stored: not
// empty, UTF-8 text without control characters (other than tab, LF and
// CR), and a template that parses and executes under farmer's restricted
// function map and render limits against placeholder props, to YAML that
// parses (cook.ValidateRecipeSource). Includes are not resolved. A
// refusal names the rule broken and, at most, a line number; never any of
// the body.
func validateRecipeBody(ctx context.Context, body []byte) *recipeProblem {
	invalid := func(code, msg string, details map[string]any) *recipeProblem {
		return &recipeProblem{status: http.StatusUnprocessableEntity, code: code, message: msg, details: details}
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return invalid("recipe_empty", "the recipe is empty", nil)
	}
	if !utf8.Valid(body) {
		return invalid("recipe_not_utf8", "the recipe must be UTF-8 text", nil)
	}
	for _, c := range body {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return invalid("recipe_not_text", "the recipe may not contain control characters other than tab and line breaks", nil)
		}
	}
	select {
	case recipeValidationSlots <- struct{}{}:
		defer func() { <-recipeValidationSlots }()
	case <-ctx.Done():
		return &recipeProblem{status: http.StatusServiceUnavailable, code: "recipe_validation_busy", message: "too many recipes are being validated; retry"}
	}
	err := cook.ValidateRecipeSource("recipe", body)
	if err == nil {
		return nil
	}
	return classifyRecipeError(err)
}

// classifyRecipeError maps a cook.ValidateRecipeSource error to a 422
// without its text, which can quote the template.
func classifyRecipeError(err error) *recipeProblem {
	p := &recipeProblem{status: http.StatusUnprocessableEntity}
	limit := func(which string) {
		p.code, p.message = "recipe_template_limit", "the template exceeded a render limit: "+which
		p.details = map[string]any{"limit": which}
	}
	switch {
	case errors.Is(err, cook.ErrRecipeTooLarge):
		p.status, p.code, p.message = http.StatusRequestEntityTooLarge, "recipe_too_large", "the recipe is over the size limit"
	case errors.Is(err, cook.ErrTemplateFuncRemoved):
		p.code, p.message = "recipe_template_forbidden", "the template calls a function recipes may not use (env, call, html, js)"
	case errors.Is(err, cook.ErrTemplateConstruct):
		p.code, p.message = "recipe_template_forbidden", "the template uses a construct recipes may not use (template, define, block, or range over something other than a list or map)"
	case errors.Is(err, cook.ErrTemplateTimeout):
		limit("render_timeout")
	case errors.Is(err, cook.ErrTemplateOutputTooBig):
		limit("rendered_bytes")
	case errors.Is(err, cook.ErrTemplateValueTooBig):
		limit("value_bytes")
	case errors.Is(err, cook.ErrTemplateRangeTooLong):
		limit("range_iterations")
	case errors.Is(err, cook.ErrTemplateArgument), errors.Is(err, cook.ErrTemplateValueEncoding):
		p.code, p.message = "recipe_template_failed", "the template passed an invalid argument to a function"
	default:
		var execErr template.ExecError
		msg := err.Error()
		switch {
		case errors.As(err, &execErr):
			p.code, p.message = "recipe_template_failed", "the template failed to execute against placeholder props"
			if m := templateLineRe.FindStringSubmatch(execErr.Error()); m != nil {
				p.details = map[string]any{"line": atoiOr0(m[1])}
			}
		case strings.HasPrefix(msg, "template: "):
			p.code, p.message = "recipe_template_invalid", "the template does not parse"
			if m := templateLineRe.FindStringSubmatch(msg); m != nil {
				p.details = map[string]any{"line": atoiOr0(m[1])}
			}
		case strings.HasPrefix(msg, "yaml: "):
			p.code, p.message = "recipe_yaml_invalid", "the rendered recipe is not valid YAML (or not a mapping)"
			if m := yamlLineRe.FindStringSubmatch(msg); m != nil {
				p.details = map[string]any{"line": atoiOr0(m[1])}
			}
		default:
			p.code, p.message = "recipe_invalid", "the recipe is not valid"
		}
	}
	return p
}

func atoiOr0(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// recipeTenantLocks serialises PUT and DELETE per tenant within this
// process, so the quota check and the write of one request don't
// interleave with another's. Across replicas the conditional write still
// prevents a lost update; the caps can be exceeded by at most one recipe
// per replica writing at the same moment.
var recipeTenantLocks sync.Map // tenant_id -> *sync.Mutex

func lockRecipeTenant(tenantID string) func() {
	mu, _ := recipeTenantLocks.LoadOrStore(tenantID, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

// checkQuota refuses a write that would take the tenant over its recipe
// count or total size cap, counting every object under its recipe prefix.
func (svc *recipeService) checkQuota(ctx context.Context, tenantID string, cur currentRecipe, newSize int64) (*recipeProblem, error) {
	prefix, err := cook.TenantRecipePrefix(tenantID)
	if err != nil {
		return nil, err
	}
	s := svc.settings
	var count, total int64
	startAfter := ""
	for {
		objs, more, err := svc.store.ListPage(ctx, prefix, startAfter, objectstore.MaxListPage)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			count++
			total += o.Size
		}
		if !more || count > int64(s.MaxCount) {
			break
		}
		startAfter = objs[len(objs)-1].Key
	}
	if !cur.exists {
		count++
	}
	total += newSize - cur.info.Size
	switch {
	case count > int64(s.MaxCount):
		return &recipeProblem{status: http.StatusConflict, code: "recipe_quota_exceeded",
			message: fmt.Sprintf("the tenant may hold at most %d recipes", s.MaxCount),
			details: map[string]any{"quota": "count", "limit": s.MaxCount}}, nil
	case total > s.MaxTotalBytes:
		return &recipeProblem{status: http.StatusConflict, code: "recipe_quota_exceeded",
			message: fmt.Sprintf("the tenant's recipes may total at most %d bytes", s.MaxTotalBytes),
			details: map[string]any{"quota": "total_bytes", "limit": s.MaxTotalBytes}}, nil
	}
	return nil, nil
}

// PutRecipe handles PUT /v1/tenants/{tenant_id}/recipes/{name}: create or
// replace. The body is the recipe source. A precondition is required:
// If-None-Match: * to create, If-Match: "<sha256>" (or *) to replace;
// none is 428. Everything is checked before anything is stored, and the
// response carries the new sha256 (also as the ETag).
func (svc *recipeService) PutRecipe(w http.ResponseWriter, r *http.Request) {
	if !svc.configured(w) {
		return
	}
	t, p := recipeTargetFrom(r)
	if p != nil {
		p.write(w)
		return
	}
	caller, _ := CallerFromContext(r.Context())
	rec := RecipeAuditRecord{TenantID: t.tenantID, Caller: caller.Subject, Action: recipeAuditPut, Name: t.name}
	reject := func(p *recipeProblem) {
		rec.Outcome, rec.Code = recipeOutcomeRejected, p.code
		_ = svc.auditRecipe(r.Context(), rec)
		p.write(w)
	}

	cond, p := parseRecipePrecondition(r, true)
	if p != nil {
		reject(p)
		return
	}
	if !cond.set() {
		reject(&recipeProblem{status: http.StatusPreconditionRequired, code: "precondition_required",
			message: `send If-None-Match: * to create the recipe, or If-Match: "<sha256>" to replace it`})
		return
	}
	if p := checkRecipeContentType(r); p != nil {
		reject(p)
		return
	}
	maxBytes := int64(cook.CurrentRenderLimits().MaxSourceBytes)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			reject(&recipeProblem{status: http.StatusRequestEntityTooLarge, code: "recipe_too_large",
				message: fmt.Sprintf("the recipe is over %d bytes", maxBytes), details: map[string]any{"max": maxBytes}})
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read the request body")
		return
	}
	rec.SHA256After, rec.SizeAfter = sha256Hex(body), int64(len(body))
	if p := validateRecipeBody(r.Context(), body); p != nil {
		reject(p)
		return
	}
	if !tenantActive(w, t.tenantID) {
		return
	}

	unlock := lockRecipeTenant(t.tenantID)
	defer unlock()
	cur, err := svc.readCurrent(r.Context(), t.key)
	if err != nil {
		log.Errorf("saasapi: reading recipe %s of tenant %s before a write: %v", t.name, t.tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be read")
		return
	}
	if cur.exists {
		rec.SHA256Before, rec.SizeBefore = cur.sha, cur.info.Size
	}
	if p := cond.check(cur); p != nil {
		reject(p)
		return
	}
	quota, err := svc.checkQuota(r.Context(), t.tenantID, cur, int64(len(body)))
	if err != nil {
		log.Errorf("saasapi: checking recipe quota of tenant %s: %v", t.tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be read")
		return
	}
	if quota != nil {
		reject(quota)
		return
	}

	// Fail closed: no change without its audit record.
	attempt := rec
	attempt.Outcome = recipeOutcomeAttempted
	if err := svc.auditRecipe(r.Context(), attempt); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the change could not be audited, so it was not made; retry")
		return
	}

	// The compare-and-swap: on the ETag just read, or create-only.
	putCond := objectstore.PutCondition{IfNoneMatch: true}
	if cur.exists {
		putCond = objectstore.PutCondition{IfMatchETag: cur.info.ETag}
	}
	info, err := svc.store.PutConditional(r.Context(), t.key, body, recipeObjectContentType, putCond)
	if err != nil {
		rec.Outcome = recipeOutcomeFailed
		if errors.Is(err, objectstore.ErrPreconditionFailed) {
			rec.Code = "precondition_failed"
			_ = svc.auditRecipe(r.Context(), rec)
			writeError(w, http.StatusPreconditionFailed, "precondition_failed", "the recipe was changed by another request at the same time: get it again and resend")
			return
		}
		rec.Code = "recipe_store_unavailable"
		_ = svc.auditRecipe(r.Context(), rec)
		log.Errorf("saasapi: writing recipe %s of tenant %s: %v", t.name, t.tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be written")
		return
	}
	status := http.StatusCreated
	rec.Outcome = recipeOutcomeCreated
	if cur.exists {
		status, rec.Outcome = http.StatusOK, recipeOutcomeReplaced
	}
	_ = svc.auditRecipe(r.Context(), rec)
	setRecipeETag(w, rec.SHA256After)
	writeJSON(w, status, recipeRecord{Name: t.name, SHA256: rec.SHA256After, Size: rec.SizeAfter, UpdatedAt: info.LastModified.UTC()})
}

// DeleteRecipe handles DELETE /v1/tenants/{tenant_id}/recipes/{name}.
// If-Match: "<sha256>" is optional: with it, the recipe is deleted only if
// it is still that version. 204 on success, 404 if there is no such
// recipe.
func (svc *recipeService) DeleteRecipe(w http.ResponseWriter, r *http.Request) {
	if !svc.configured(w) {
		return
	}
	t, p := recipeTargetFrom(r)
	if p != nil {
		p.write(w)
		return
	}
	caller, _ := CallerFromContext(r.Context())
	rec := RecipeAuditRecord{TenantID: t.tenantID, Caller: caller.Subject, Action: recipeAuditDelete, Name: t.name}
	reject := func(p *recipeProblem) {
		rec.Outcome, rec.Code = recipeOutcomeRejected, p.code
		_ = svc.auditRecipe(r.Context(), rec)
		p.write(w)
	}
	cond, p := parseRecipePrecondition(r, false)
	if p != nil {
		reject(p)
		return
	}
	if !tenantExists(w, t.tenantID) {
		return
	}

	unlock := lockRecipeTenant(t.tenantID)
	defer unlock()
	cur, err := svc.readCurrent(r.Context(), t.key)
	if err != nil {
		log.Errorf("saasapi: reading recipe %s of tenant %s before a delete: %v", t.name, t.tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be read")
		return
	}
	if !cur.exists {
		reject(&recipeProblem{status: http.StatusNotFound, code: "recipe_not_found", message: "no recipe with this name"})
		return
	}
	rec.SHA256Before, rec.SizeBefore = cur.sha, cur.info.Size
	if p := cond.check(cur); p != nil {
		reject(p)
		return
	}

	attempt := rec
	attempt.Outcome = recipeOutcomeAttempted
	if err := svc.auditRecipe(r.Context(), attempt); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the change could not be audited, so it was not made; retry")
		return
	}
	if err := svc.store.Delete(r.Context(), t.key); err != nil {
		rec.Outcome, rec.Code = recipeOutcomeFailed, "recipe_store_unavailable"
		_ = svc.auditRecipe(r.Context(), rec)
		log.Errorf("saasapi: deleting recipe %s of tenant %s: %v", t.name, t.tenantID, err)
		writeError(w, http.StatusBadGateway, "recipe_store_unavailable", "the recipe store could not be written")
		return
	}
	rec.Outcome = recipeOutcomeDeleted
	_ = svc.auditRecipe(r.Context(), rec)
	w.WriteHeader(http.StatusNoContent)
}
