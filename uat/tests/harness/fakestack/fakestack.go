// Package fakestack is an in-memory stand-in for the deployed UAT stack:
// saasapi's tenant routes, Keycloak's token and admin endpoints, Envoy's
// /v1/enroll, and the sprout hosts behind vmctl.sh. It implements the
// documented behaviour the harness and the smoke tier rely on
// (docs/api/saasapi.md), not the whole product, so the harness can be unit
// tested and uat/tests/run.sh can be exercised end to end without a
// deployment (go run ./uat/tests/fakestack). Passing against it proves the
// suite's plumbing, never the product.
package fakestack

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

// Realm and client names the stack serves.
const (
	Realm           = "imas-uat"
	ClientID        = "uat-tests"
	Audience        = "imas-saasapi"
	TenantAttribute = "tenant_id"
	InternalSecret  = "fake-internal-secret"
	AdminUser       = "kcadmin"
	AdminPassword   = "kcadmin-password"
	ReadRole        = "imas-recipes-read"
	WriteRole       = "imas-recipes-write"
)

// Host is a simulated sprout machine.
type Host struct {
	VM       string
	Tenant   int
	OS       string
	SproutID string
	Version  string
	Stopped  bool
	Files    map[string]string
	MTimes   map[string]int64
	Owners   map[string]string
}

type user struct {
	id, password, tenantID string
	roles                  []string
}

type key struct {
	tenantID, secret string
	expires          time.Time
	maxUses, used    int
	revoked          bool
	created          time.Time
}

type sprout struct {
	nkey      string
	hasBoxKey bool
	vm        string
}

type item struct {
	AssetID  string `json:"asset_id"`
	SproutID string `json:"sprout_id,omitempty"`
	Status   string `json:"status"`
	JID      string `json:"jid,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
}

type batch struct {
	tenantID, actionType string
	created              time.Time
	items                []item
}

// Stack is the fake. Its zero value is not usable; call New.
type Stack struct {
	Server *httptest.Server

	mu          sync.Mutex
	signKey     []byte
	tenants     map[string]*tenantRec
	users       map[string]*user // by username
	keys        map[string]*key
	sprouts     map[string]*sprout // by tenantID + "/" + sproutID
	links       map[string]string  // asset -> tenantID/sproutID
	batches     map[string]*batch
	hosts       map[string]*Host
	recipeStore map[string]recipe // tenantID/name
	limiter     map[string]*bucket
	tokenTTL    time.Duration
}

type tenantRec struct {
	name, status string
	polls        int
}

// New starts a stack on a TLS httptest server. Tenants 1 and 2 exist and
// are active; each has an admin user (both recipe roles) and a read only
// user, "t<n>-admin" and "t<n>-reader" (UAT.3b's names), with password "pw".
func New() *Stack {
	s := &Stack{
		signKey: random(32), tenants: map[string]*tenantRec{}, users: map[string]*user{},
		keys: map[string]*key{}, sprouts: map[string]*sprout{}, links: map[string]string{},
		batches: map[string]*batch{}, hosts: map[string]*Host{}, recipeStore: map[string]recipe{},
		limiter: map[string]*bucket{}, tokenTTL: 90 * time.Second,
	}
	for n := 1; n <= 2; n++ {
		id := TenantID(n)
		s.tenants[id] = &tenantRec{name: fmt.Sprintf("uat-%d", n), status: "active"}
		s.users[fmt.Sprintf("t%d-admin", n)] = &user{id: newID("u"), password: "pw", tenantID: id, roles: []string{ReadRole, WriteRole}}
		s.users[fmt.Sprintf("t%d-reader", n)] = &user{id: newID("u"), password: "pw", tenantID: id, roles: []string{ReadRole}}
	}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the server.
func (s *Stack) Close() { s.Server.Close() }

// TenantID is the fixed saasapi ID of tenant 1 or 2.
func TenantID(n int) string { return "t_" + strings.Repeat(string(rune('a'+n-1)), 16) }

// Issuer is the realm URL.
func (s *Stack) Issuer() string { return s.Server.URL + "/realms/" + Realm }

// AddHost adds an enrolled, connected sprout host.
func (s *Stack) AddHost(vm string, tenant int, osName, sproutID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tid := TenantID(tenant)
	s.hosts[vm] = &Host{VM: vm, Tenant: tenant, OS: osName, SproutID: sproutID, Version: "0.1.0~rc.4+git",
		Files: map[string]string{}, MTimes: map[string]int64{}, Owners: map[string]string{}}
	s.sprouts[tid+"/"+sproutID] = &sprout{nkey: "U" + strings.ToUpper(hex.EncodeToString(random(27))), hasBoxKey: true, vm: vm}
}

// Host returns a copy of a host's state.
func (s *Stack) Host(vm string) (Host, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[vm]
	if !ok {
		return Host{}, false
	}
	c := *h
	return c, true
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newID(prefix string) string {
	return prefix + base32ish(16)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func (s *Stack) serve(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case strings.HasSuffix(p, "/protocol/openid-connect/token"):
		s.token(w, r)
	case strings.HasPrefix(p, "/admin/realms/"+Realm+"/"):
		s.kcAdmin(w, r)
	case p == "/v1/enroll":
		s.enroll(w, r)
	case p == "/_vmctl":
		s.vmctl(w, r)
	case p == "/v1/refresh":
		writeJSON(w, 401, map[string]string{"error": "enrollment_failed"})
	case strings.HasPrefix(p, "/v1/") && !strings.HasPrefix(p, "/v1/sprout/"):
		s.saas(w, r)
	default:
		// Envoy's jwt_authn: every other route needs a gateway JWT, and
		// the fake trusts none.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(401)
		_, _ = io.WriteString(w, "Jwt is missing")
	}
}

// --- Keycloak ---------------------------------------------------------------

func (s *Stack) mint(sub, tenantID string, roles []string, aud string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]any{
		"iss": s.Issuer(), "aud": aud, "sub": sub, "exp": time.Now().Add(s.tokenTTL).Unix(),
		"realm_access": map[string]any{"roles": roles},
	}
	if tenantID != "" {
		claims["organization"] = map[string]any{"id": tenantID, "name": tenantID}
	}
	b, _ := json.Marshal(claims)
	in := h + "." + base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.signKey)
	m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Stack) verify(tok string) (map[string]any, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	m := hmac.New(sha256.New, s.signKey)
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c map[string]any
	if json.Unmarshal(b, &c) != nil {
		return nil, false
	}
	exp, _ := c["exp"].(float64)
	if c["iss"] != s.Issuer() || c["aud"] != Audience || time.Now().Unix() >= int64(exp) {
		return nil, false
	}
	return c, true
}

func (s *Stack) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := r.PostForm
	if strings.Contains(r.URL.Path, "/realms/master/") {
		if f.Get("username") != AdminUser || f.Get("password") != AdminPassword {
			writeJSON(w, 401, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": s.mint("admin", "", nil, "master-realm"), "expires_in": 300})
		return
	}
	u, ok := s.users[f.Get("username")]
	if f.Get("grant_type") != "password" || !ok || u.password != f.Get("password") {
		writeJSON(w, 401, map[string]string{"error": "invalid_grant"})
		return
	}
	aud := Audience
	if f.Get("client_id") != ClientID {
		aud = "account"
	}
	writeJSON(w, 200, map[string]any{"access_token": s.mint(u.id, u.tenantID, u.roles, aud), "expires_in": int(s.tokenTTL.Seconds())})
}

func (s *Stack) kcAdmin(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(401)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rest := strings.TrimPrefix(r.URL.Path, "/admin/realms/"+Realm)
	switch {
	case r.Method == http.MethodPost && rest == "/users":
		var body struct {
			Username    string              `json:"username"`
			Attributes  map[string][]string `json:"attributes"`
			Credentials []struct {
				Value string `json:"value"`
			} `json:"credentials"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Username == "" || len(body.Credentials) == 0 {
			w.WriteHeader(400)
			return
		}
		tid := ""
		if v := body.Attributes[TenantAttribute]; len(v) > 0 {
			tid = v[0]
		}
		u := &user{id: newID("u"), password: body.Credentials[0].Value, tenantID: tid}
		s.users[body.Username] = u
		w.Header().Set("Location", s.Server.URL+"/admin/realms/"+Realm+"/users/"+u.id)
		w.WriteHeader(201)
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "/users/"):
		id := strings.TrimPrefix(rest, "/users/")
		for name, u := range s.users {
			if u.id == id {
				delete(s.users, name)
				w.WriteHeader(204)
				return
			}
		}
		w.WriteHeader(404)
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/roles/"):
		writeJSON(w, 200, map[string]string{"name": strings.TrimPrefix(rest, "/roles/")})
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/role-mappings/realm"):
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

// --- Envoy /v1/enroll ---------------------------------------------------------

func (s *Stack) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JoinToken string `json:"join_token"`
		NKeyPub   string `json:"nkey_pub"`
		Hostname  string `json:"hostname"`
		SproutPub string `json:"sprout_pub"`
		Timestamp int64  `json:"timestamp"`
		NKeySig   string `json:"nkey_sig"`
	}
	fail := func() { writeJSON(w, 401, map[string]string{"error": "enrollment_failed"}) }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail()
		return
	}
	kp, err := nkeys.FromPublicKey(req.NKeyPub)
	sig, err2 := base64.RawURLEncoding.DecodeString(req.NKeySig)
	if err != nil || err2 != nil || kp.Verify(pki.EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken), sig) != nil {
		fail()
		return
	}
	if d := time.Since(time.Unix(req.Timestamp, 0)); d > 5*time.Minute || d < -5*time.Minute {
		fail()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keyID, secret, _ := strings.Cut(req.JoinToken, ".")
	k, ok := s.keys[keyID]
	if !ok || k.secret != secret || k.revoked || time.Now().After(k.expires) || k.used >= k.maxUses ||
		s.tenants[k.tenantID] == nil || s.tenants[k.tenantID].status != "active" {
		fail()
		return
	}
	k.used++
	id := strings.ReplaceAll(req.Hostname, ".", "-")
	s.sprouts[k.tenantID+"/"+id] = &sprout{nkey: req.NKeyPub}
	writeJSON(w, 200, map[string]any{"sprout_id": id, "tenant_id": k.tenantID, "jwt": "fake-user-jwt", "nkey_identity": req.NKeyPub,
		"tenant_x25519_pub": base64.StdEncoding.EncodeToString(random(32)), "enroll_binding": map[string]any{"v": 2}})
}

// --- saasapi ------------------------------------------------------------------

func (s *Stack) saas(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Internal-Auth") != InternalSecret {
		writeErr(w, 401, "unauthorized", "unauthorized")
		return
	}
	claims, ok := s.verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !ok {
		writeErr(w, 401, "unauthorized", "unauthorized")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 2 && parts[1] == "versions" {
		writeJSON(w, 200, []any{})
		return
	}
	if len(parts) == 2 && parts[1] == "tenants" && r.Method == http.MethodPost {
		s.createTenant(w, r)
		return
	}
	if len(parts) < 3 || parts[1] != "tenants" {
		http.NotFound(w, r)
		return
	}
	tid := parts[2]
	org, _ := claims["organization"].(map[string]any)
	if org == nil || org["id"] != tid {
		writeErr(w, 403, "forbidden", "forbidden")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tid]
	if !ok {
		writeErr(w, 404, "tenant_not_found", "no such tenant")
		return
	}
	rest := parts[3:]
	switch {
	case len(rest) == 0 && r.Method == http.MethodDelete:
		switch t.status {
		case "pending":
			writeErr(w, 409, "provisioning_in_progress", "provisioning")
		case "offboarding", "offboarded":
			writeErr(w, 409, "offboarding_in_progress", "offboarding")
		default:
			t.status, t.polls = "offboarding", 0
			writeJSON(w, 202, map[string]string{"tenant_id": tid, "status": t.status})
		}
	case len(rest) >= 1 && rest[0] == "recipes":
		s.recipesRoute(w, r, claims, tid, rest)
	case len(rest) == 1 && rest[0] == "status" && r.Method == http.MethodGet:
		t.polls++
		if t.polls >= 2 && t.status == "pending" {
			t.status = "active"
		}
		if t.polls >= 2 && t.status == "offboarding" {
			t.status = "offboarded"
		}
		writeJSON(w, 200, map[string]string{"tenant_id": tid, "status": t.status})
	case len(rest) == 1 && rest[0] == "enrollment-keys" && r.Method == http.MethodPost:
		s.createKey(w, r, tid)
	case len(rest) == 1 && rest[0] == "enrollment-keys" && r.Method == http.MethodGet:
		s.listKeys(w, tid)
	case len(rest) == 2 && rest[0] == "enrollment-keys" && r.Method == http.MethodDelete:
		k, ok := s.keys[rest[1]]
		if !ok || k.tenantID != tid {
			writeErr(w, 404, "enrollment_key_not_found", "no such enrollment key")
			return
		}
		k.revoked = true
		writeJSON(w, 200, map[string]any{"key_id": rest[1], "revoked": true})
	case len(rest) == 3 && rest[0] == "sprouts" && rest[2] == "asset-link":
		s.assetLink(w, r, tid, rest[1])
	case len(rest) == 1 && rest[0] == "sprouts" && r.Method == http.MethodGet:
		s.lookup(w, r, tid)
	case len(rest) == 2 && rest[0] == "sprouts" && rest[1] == "actions" && r.Method == http.MethodPost:
		s.postBatch(w, r, tid, t)
	case len(rest) == 3 && rest[0] == "sprouts" && rest[1] == "actions" && r.Method == http.MethodGet:
		b, ok := s.batches[rest[2]]
		if !ok || b.tenantID != tid {
			writeErr(w, 404, "batch_not_found", "no such action batch")
			return
		}
		writeJSON(w, 200, map[string]any{"batch_id": rest[2], "status": "completed", "action_type": b.actionType, "created_at": b.created, "items": b.items})
	default:
		writeErr(w, 404, "not_found", "the fake stack doesn't serve this route")
	}
}

func (s *Stack) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Name) == "" {
		writeErr(w, 400, "invalid_request", "name is required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := "t_" + strings.ToLower(base32ish(16))
	s.tenants[id] = &tenantRec{name: body.Name, status: "pending"}
	writeJSON(w, 202, map[string]string{"tenant_id": id, "status": "pending"})
}

func base32ish(n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz234567"
	b := random(n)
	for i := range b {
		b[i] = alpha[int(b[i])%32]
	}
	return string(b)
}

type bucket struct {
	tokens float64
	last   time.Time
}

// limited is a token bucket refilling 1 per second up to burst, like
// saasapi's limiters. s.mu is held.
func (s *Stack) limited(name string, burst int) bool {
	now := time.Now()
	b, ok := s.limiter[name]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now}
		s.limiter[name] = b
	}
	b.tokens = min(float64(burst), b.tokens+now.Sub(b.last).Seconds())
	b.last = now
	if b.tokens < 1 {
		return true
	}
	b.tokens--
	return false
}

func (s *Stack) createKey(w http.ResponseWriter, r *http.Request, tid string) {
	var body struct {
		Hours   int `json:"expires_in_hours"`
		MaxUses int `json:"max_uses"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, 400, "invalid_request", "bad JSON")
		return
	}
	if body.Hours < 1 || body.Hours > 720 {
		writeErr(w, 400, "invalid_request", "expires_in_hours out of range")
		return
	}
	if body.MaxUses < 1 || body.MaxUses > 10000 {
		writeErr(w, 400, "invalid_request", "max_uses out of range")
		return
	}
	if s.limited("keys/"+tid, 5) {
		writeErr(w, 429, "rate_limited", "rate limited")
		return
	}
	id := "ek_" + strings.ToLower(base32ish(16))
	k := &key{tenantID: tid, secret: hex.EncodeToString(random(16)), expires: time.Now().Add(time.Duration(body.Hours) * time.Hour), maxUses: body.MaxUses, created: time.Now()}
	s.keys[id] = k
	writeJSON(w, 200, map[string]any{"key_id": id, "registration_key": id + "." + k.secret, "expires_at": k.expires.UTC().Format(time.RFC3339), "max_uses": k.maxUses})
}

func (s *Stack) listKeys(w http.ResponseWriter, tid string) {
	type entry struct {
		KeyID     string    `json:"key_id"`
		State     string    `json:"state"`
		ExpiresAt time.Time `json:"expires_at"`
		MaxUses   int       `json:"max_uses"`
		UsedCount int       `json:"used_count"`
		CreatedAt time.Time `json:"created_at"`
	}
	var out []entry
	for id, k := range s.keys {
		if k.tenantID != tid {
			continue
		}
		state := "active"
		switch {
		case k.revoked:
			state = "revoked"
		case time.Now().After(k.expires):
			state = "expired"
		case k.used >= k.maxUses:
			state = "exhausted"
		}
		out = append(out, entry{KeyID: id, State: state, ExpiresAt: k.expires, MaxUses: k.maxUses, UsedCount: k.used, CreatedAt: k.created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSON(w, 200, map[string]any{"enrollment_keys": out})
}

func (s *Stack) assetLink(w http.ResponseWriter, r *http.Request, tid, sproutID string) {
	if _, ok := s.sprouts[tid+"/"+sproutID]; !ok && r.Method == http.MethodPost {
		writeErr(w, 404, "sprout_not_found", "no such sprout")
		return
	}
	owner := tid + "/" + sproutID
	if r.Method == http.MethodDelete {
		for a, o := range s.links {
			if o == owner {
				delete(s.links, a)
				writeJSON(w, 200, map[string]any{"sprout_id": sproutID, "unlinked": true})
				return
			}
		}
		writeErr(w, 404, "asset_link_not_found", "no asset link for this sprout")
		return
	}
	var body struct {
		AssetID string `json:"asset_id"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.AssetID == "" {
		writeErr(w, 400, "invalid_request", "asset_id is required")
		return
	}
	if o, ok := s.links[body.AssetID]; ok {
		if o == owner {
			writeJSON(w, 200, map[string]string{"sprout_id": sproutID, "asset_id": body.AssetID})
			return
		}
		writeErr(w, 409, "asset_link_conflict", "conflict")
		return
	}
	for _, o := range s.links {
		if o == owner {
			writeErr(w, 409, "asset_link_conflict", "conflict")
			return
		}
	}
	s.links[body.AssetID] = owner
	writeJSON(w, 201, map[string]string{"sprout_id": sproutID, "asset_id": body.AssetID})
}

func (s *Stack) resolve(tid, asset string) (string, *sprout, bool) {
	o, ok := s.links[asset]
	if !ok || !strings.HasPrefix(o, tid+"/") {
		return "", nil, false
	}
	sp := s.sprouts[o]
	return strings.TrimPrefix(o, tid+"/"), sp, sp != nil
}

func (s *Stack) lookup(w http.ResponseWriter, r *http.Request, tid string) {
	raw := r.URL.Query().Get("asset_ids")
	if raw == "" {
		writeErr(w, 400, "invalid_request", "asset_ids is required")
		return
	}
	ids := strings.Split(raw, ",")
	if len(ids) > 100 {
		writeJSON(w, 400, map[string]any{"error": "too_many_asset_ids", "message": "too many", "details": map[string]int{"max": 100}})
		return
	}
	results := []map[string]any{}
	unresolved := []string{}
	for _, a := range ids {
		id, sp, ok := s.resolve(tid, a)
		if !ok {
			unresolved = append(unresolved, a)
			continue
		}
		connected := false
		if h, ok := s.hosts[sp.vm]; ok && !h.Stopped {
			connected = true
		}
		results = append(results, map[string]any{"sprout_id": id, "asset_id": a, "key_state": "accepted", "connected": connected})
	}
	writeJSON(w, 200, map[string]any{"results": results, "unresolved": unresolved})
}

func (s *Stack) postBatch(w http.ResponseWriter, r *http.Request, tid string, t *tenantRec) {
	if t.status != "active" {
		writeErr(w, 409, "tenant_not_active", "tenant not active")
		return
	}
	var body struct {
		AssetIDs []string `json:"asset_ids"`
		Action   struct {
			Type   string          `json:"type"`
			Params json.RawMessage `json:"params"`
		} `json:"action"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.AssetIDs) == 0 {
		writeErr(w, 400, "invalid_request", "bad request")
		return
	}
	var cmd struct {
		Cmd     string   `json:"cmd"`
		Args    []string `json:"args"`
		CWD     string   `json:"cwd"`
		RunAs   string   `json:"run_as"`
		Timeout int      `json:"timeout_seconds"`
	}
	var cookP struct {
		Recipe string `json:"recipe"`
		Test   bool   `json:"test"`
	}
	switch body.Action.Type {
	case "cmd.run":
		if json.Unmarshal(body.Action.Params, &cmd) != nil || cmd.Cmd == "" {
			writeErr(w, 400, "invalid_request", "cmd.run requires cmd")
			return
		}
		if cmd.Args == nil && strings.ContainsAny(cmd.Cmd, "\"'\\`$|&;<>(){}*?[]~") {
			writeErr(w, 400, "invalid_request", "cmd is not run through a shell")
			return
		}
	case "cook":
		if json.Unmarshal(body.Action.Params, &cookP) != nil || cookP.Recipe == "" {
			writeErr(w, 400, "invalid_request", "cook requires recipe")
			return
		}
	default:
		writeErr(w, 400, "unsupported_action", "action.type must be cmd.run or cook")
		return
	}
	if s.limited("actions/"+tid, 5) {
		writeErr(w, 429, "rate_limited", "rate limited")
		return
	}
	b := &batch{tenantID: tid, actionType: body.Action.Type, created: time.Now()}
	seen := map[string]bool{}
	for _, a := range body.AssetIDs {
		if seen[a] {
			continue
		}
		seen[a] = true
		id, sp, ok := s.resolve(tid, a)
		it := item{AssetID: a, SproutID: id}
		switch {
		case !ok:
			it = item{AssetID: a, Status: "unresolved"}
		case !sp.hasBoxKey:
			it.Status, it.Error, it.Message = "failed", "sprout_reenroll_required", "re-enroll the sprout"
		case s.hosts[sp.vm] == nil || s.hosts[sp.vm].Stopped:
			it.Status, it.Error, it.Message = "failed", "sprout_unreachable", "unreachable"
		case body.Action.Type == "cmd.run":
			status, code, errCode := s.runCmd(s.hosts[sp.vm], cmd.Cmd, cmd.CWD, cmd.RunAs, cmd.Args, cmd.Timeout)
			it.Status, it.ExitCode, it.Error = status, &code, errCode
			if errCode != "" {
				it.Message = "the command failed"
			}
		default:
			if code := s.cook(tid, cookP.Recipe, s.hosts[sp.vm], cookP.Test); code != "" {
				it.Status, it.Error, it.Message = "failed", code, "the job failed"
			} else {
				it.Status, it.JID = "succeeded", newID("j")
			}
		}
		b.items = append(b.items, it)
	}
	id := "b_" + strings.ToLower(base32ish(16))
	s.batches[id] = b
	writeJSON(w, 202, map[string]string{"batch_id": id})
}

// exitCode understands the harness's ExitCmd; everything else exits 0.
func exitCode(cmd string, args []string) int {
	if len(args) >= 2 && (cmd == "sh" && args[0] == "-c" || cmd == "cmd.exe") {
		f := strings.Fields(strings.Join(args, " "))
		if n, err := strconv.Atoi(f[len(f)-1]); err == nil && strings.Contains(strings.Join(args, " "), "exit") {
			return n
		}
	}
	return 0
}

// --- hosts behind vmctl.sh ------------------------------------------------------

// vmctl answers POST /_vmctl?verb=...&vm=... with the script as the body,
// the way vmctl.sh would: it recognises the harness's host scripts by the
// values they print and answers for the simulated host.
func (s *Stack) vmctl(w http.ResponseWriter, r *http.Request) {
	verb, vm := r.URL.Query().Get("verb"), r.URL.Query().Get("vm")
	body := new(strings.Builder)
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	code, out := s.Vmctl(verb, vm, body.String())
	// Plain text, never sniffed as HTML: the answer is what vmctl.sh
	// prints on a terminal, and Vmctl never echoes the request's verb or
	// VM name back.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Exit-Code", strconv.Itoa(code))
	_, _ = io.WriteString(w, out)
}

// Vmctl is what vmctl.sh <verb> <vm> [script] prints, and its exit code.
func (s *Stack) Vmctl(verb, vm, script string) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (vm == "uat-core" || vm == "uat-dmz") && verb == "run" {
		// The hubs: a workload restart (kubectl rollout) always works.
		if strings.Contains(script, "rollout restart") {
			return 0, "deployment restarted\n__IMAS_UAT_RC=0\n"
		}
		return 0, "__IMAS_UAT_RC=1\n"
	}
	h, ok := s.hosts[vm]
	if !ok {
		return 2, "vmctl: no such VM in the fake stack\n"
	}
	switch verb {
	case "restart":
		h.Stopped = false
		return 0, ""
	case "stop-sprout":
		h.Stopped = true
		return 0, ""
	case "start-sprout":
		h.Stopped = false
		return 0, ""
	case "run":
	default:
		return 2, "vmctl: unknown verb (want restart, stop-sprout, start-sprout or run)\n"
	}
	return 0, "Enable succeeded:\n[stdout]\n" + s.hostScript(h, script) + "__IMAS_UAT_RC=0\n[stderr]\n"
}
