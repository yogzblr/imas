package saasapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	log "github.com/yogzblr/imas/internal/log"
)

// secretShapedToken/hashShapedToken detect log output that merely *looks*
// like a leaked enrollment secret or key_hash, without the test needing
// to know the literal value in advance (useful on the forced-failure
// path below, where the secret is never returned to the test). Their
// shapes come directly from idgen.go: newEnrollmentSecret returns
// base64.RawURLEncoding of 32 bytes (43 chars, alphabet
// [A-Za-z0-9_-]), and hashSecret returns hex.EncodeToString of a
// SHA-256 sum (64 lowercase hex chars). Generated IDs (tenant_id,
// key_id, provisioning job id) are all shorter than 43 chars, so they
// don't false-positive against secretShapedToken.
var (
	secretShapedToken = regexp.MustCompile(`[A-Za-z0-9_-]{43}`)
	hashShapedToken   = regexp.MustCompile(`[a-f0-9]{64}`)
)

func assertNoSecretShapedTokens(t *testing.T, output string) {
	t.Helper()
	if m := secretShapedToken.FindString(output); m != "" {
		t.Fatalf("log output contains a token shaped like a raw enrollment secret (%q):\n%s", m, output)
	}
	if m := hashShapedToken.FindString(output); m != "" {
		t.Fatalf("log output contains a token shaped like a hex-encoded key hash (%q):\n%s", m, output)
	}
}

// withVerboseLogging temporarily lowers internal/log's terminal level to
// LTrace, so Trace/Debug lines (normally filtered out at the package's
// default level) are captured too — the task brief asks this test to
// cover "not in Trace, not in Debug", which requires them to actually be
// emitted during the call.
func withVerboseLogging(t *testing.T) {
	t.Helper()
	log.SetLogLevel(log.LTrace)
	t.Cleanup(func() { log.SetLogLevel(log.LDebug) }) // internal/log's own init() default
}

func TestCreateEnrollmentKeyUnknownTenant(t *testing.T) {
	newTestDB(t)
	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/nope/enrollment-keys",
		map[string]string{"tenant_id": "nope"}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404, body=%s", w.Code, w.Body.String())
	}
}

func TestCreateEnrollmentKeyValidation(t *testing.T) {
	newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	cases := []createEnrollmentKeyRequest{
		{ExpiresInHours: 0, MaxUses: 50},
		{ExpiresInHours: maxExpiresInHours + 1, MaxUses: 50},
		{ExpiresInHours: 24, MaxUses: 0},
		{ExpiresInHours: 24, MaxUses: maxMaxUses + 1},
	}
	for _, c := range cases {
		w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
			map[string]string{"tenant_id": tenantID}, c)
		if w.Code != 400 {
			t.Fatalf("case %+v: status = %d, want 400, body=%s", c, w.Code, w.Body.String())
		}
	}
}

// TestCreateEnrollmentKeyNeverPersistsRawSecret is the security-critical
// assertion for this task: the stored row's key_hash must be the SHA-256
// of the issued secret, the raw secret itself must never be persisted,
// and the two halves of the returned registration_key must match key_id
// and the format from design doc §3.1 ("{key_id}.{secret}").
func TestCreateEnrollmentKeyNeverPersistsRawSecret(t *testing.T) {
	gdb := newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp createEnrollmentKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	parts := strings.SplitN(resp.RegistrationKey, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("registration_key %q is not in key_id.secret form", resp.RegistrationKey)
	}
	keyID, secret := parts[0], parts[1]
	if keyID != resp.KeyID {
		t.Fatalf("registration_key's key_id half = %q, want %q", keyID, resp.KeyID)
	}
	if secret == "" {
		t.Fatalf("expected a non-empty secret half")
	}

	var stored EnrollmentKey
	if err := gdb.First(&stored, "key_id = ?", resp.KeyID).Error; err != nil {
		t.Fatalf("loading stored key: %v", err)
	}
	if stored.KeyHash == secret {
		t.Fatalf("raw secret must never be stored as-is")
	}
	if stored.KeyHash != hashSecret(secret) {
		t.Fatalf("key_hash = %q, want sha256(secret) = %q", stored.KeyHash, hashSecret(secret))
	}

	// The raw response body (as sent over the wire) must not leak
	// key_hash under any field name.
	if strings.Contains(w.Body.String(), stored.KeyHash) {
		t.Fatalf("response body leaked the stored key_hash: %s", w.Body.String())
	}
}

func TestListEnrollmentKeysExcludesHashAndShowsState(t *testing.T) {
	newTestDB(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	var created createEnrollmentKeyResponse
	json.Unmarshal(w.Body.Bytes(), &created)

	lw := doRequest(t, ListEnrollmentKeys, "GET", "/v1/tenants/"+tenantID+"/enrollment-keys",
		map[string]string{"tenant_id": tenantID}, nil)
	if lw.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", lw.Code, lw.Body.String())
	}
	if strings.Contains(lw.Body.String(), "key_hash") {
		t.Fatalf("list response must never include key_hash: %s", lw.Body.String())
	}

	var listResp struct {
		EnrollmentKeys []enrollmentKeyListItem `json:"enrollment_keys"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	if len(listResp.EnrollmentKeys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listResp.EnrollmentKeys))
	}
	if listResp.EnrollmentKeys[0].KeyID != created.KeyID {
		t.Fatalf("key_id = %q, want %q", listResp.EnrollmentKeys[0].KeyID, created.KeyID)
	}
	if listResp.EnrollmentKeys[0].State != "active" {
		t.Fatalf("state = %q, want active", listResp.EnrollmentKeys[0].State)
	}
}

func TestDeleteEnrollmentKeyRevokesAndIsTenantScoped(t *testing.T) {
	newTestDB(t)
	tenantA := mustCreateTenant(t, "Acme Bank")
	tenantB := mustCreateTenant(t, "Other Tenant")

	w := doRequest(t, CreateEnrollmentKey, "POST", "/v1/tenants/"+tenantA+"/enrollment-keys",
		map[string]string{"tenant_id": tenantA}, createEnrollmentKeyRequest{ExpiresInHours: 24, MaxUses: 50})
	var created createEnrollmentKeyResponse
	json.Unmarshal(w.Body.Bytes(), &created)

	// A different tenant may not revoke this key — it must resolve to
	// not-found, per design doc §4's tenant-safety convention.
	wrong := doRequest(t, DeleteEnrollmentKey, "DELETE", "/v1/tenants/"+tenantB+"/enrollment-keys/"+created.KeyID,
		map[string]string{"tenant_id": tenantB, "key_id": created.KeyID}, nil)
	if wrong.Code != 404 {
		t.Fatalf("cross-tenant delete status = %d, want 404, body=%s", wrong.Code, wrong.Body.String())
	}

	ok := doRequest(t, DeleteEnrollmentKey, "DELETE", "/v1/tenants/"+tenantA+"/enrollment-keys/"+created.KeyID,
		map[string]string{"tenant_id": tenantA, "key_id": created.KeyID}, nil)
	if ok.Code != 200 {
		t.Fatalf("delete status = %d, want 200, body=%s", ok.Code, ok.Body.String())
	}

	lw := doRequest(t, ListEnrollmentKeys, "GET", "/v1/tenants/"+tenantA+"/enrollment-keys",
		map[string]string{"tenant_id": tenantA}, nil)
	var listResp struct {
		EnrollmentKeys []enrollmentKeyListItem `json:"enrollment_keys"`
	}
	json.Unmarshal(lw.Body.Bytes(), &listResp)
	if len(listResp.EnrollmentKeys) != 1 || listResp.EnrollmentKeys[0].State != "revoked" {
		t.Fatalf("expected the key to show state=revoked, got %+v", listResp.EnrollmentKeys)
	}
}

// TestCreateEnrollmentKeyNeverLogsSecret is the logging-safety guarantee
// for the happy path: nothing CreateEnrollmentKey does — directly or via
// the Logger middleware it runs behind — may ever write the raw secret
// (or the full registration_key that embeds it) to the log. Routed
// through the real router/middleware stack so Logger's own behavior
// (method/URI/name/duration only, never the body) is exercised for real,
// not just asserted by reading the code.
func TestCreateEnrollmentKeyNeverLogsSecret(t *testing.T) {
	newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	withVerboseLogging(t)

	mux := NewRouter()

	var resp createEnrollmentKeyResponse
	output := captureStderr(t, func() {
		body := `{"expires_in_hours":24,"max_uses":50}`
		r := httptest.NewRequest("POST", "/v1/tenants/"+tenantID+"/enrollment-keys", strings.NewReader(body))
		auth.setAuthHeaders(r, tenantID)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding response: %v", err)
		}
	})

	// Sanity check: the capture mechanism actually captured something
	// (Logger's request trace line at minimum), so an empty-output bug
	// in captureStderr itself can't make this test pass vacuously.
	if !strings.Contains(output, "CreateEnrollmentKey") {
		t.Fatalf("expected captured log output to include the route name, got:\n%s", output)
	}

	parts := strings.SplitN(resp.RegistrationKey, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("registration_key %q is not in key_id.secret form", resp.RegistrationKey)
	}
	secret := parts[1]

	if strings.Contains(output, secret) {
		t.Fatalf("log output leaked the raw enrollment secret:\n%s", output)
	}
	if strings.Contains(output, resp.RegistrationKey) {
		t.Fatalf("log output leaked the full registration_key:\n%s", output)
	}
	assertNoSecretShapedTokens(t, output)
}

// TestCreateEnrollmentKeyNeverLogsSecretOnDBFailure forces the failure
// path — db.Create(&key) failing — and re-checks the same guarantee
// there. This is precisely the kubeadm CVE-2023-2287 class of bug: a
// secret that's safe on the happy path but gets logged only when
// something goes wrong on a path nobody thought to check.
//
// The secret is generated (in CreateEnrollmentKey's local `secret`
// variable) before the failing write, so it exists in memory at the
// moment of failure — but the failed response never returns it to this
// test, by design. So instead of comparing against a known literal, this
// asserts the log output contains nothing *shaped* like the secret or
// its hash (see secretShapedToken/hashShapedToken above).
func TestCreateEnrollmentKeyNeverLogsSecretOnDBFailure(t *testing.T) {
	gdb := newTestDB(t)
	auth := newTestAuthEnv(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	withVerboseLogging(t)

	// Force db.Create(&key) to fail without touching production code:
	// drop enrollment_keys out from under it. tenantExists' query against
	// `tenants` still succeeds, so the failure happens exactly at the
	// write step, after the secret already exists in memory.
	if err := gdb.Migrator().DropTable(&EnrollmentKey{}); err != nil {
		t.Fatalf("dropping enrollment_keys table: %v", err)
	}

	mux := NewRouter()

	var status int
	var body string
	output := captureStderr(t, func() {
		reqBody := `{"expires_in_hours":24,"max_uses":50}`
		r := httptest.NewRequest("POST", "/v1/tenants/"+tenantID+"/enrollment-keys", strings.NewReader(reqBody))
		auth.setAuthHeaders(r, tenantID)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		status = w.Code
		body = w.Body.String()
	})

	if status != http.StatusInternalServerError {
		t.Fatalf("expected the forced DB failure to surface as 500, got %d body=%s", status, body)
	}
	if strings.Contains(body, "registration_key") {
		t.Fatalf("a failed issuance must not return a registration_key: %s", body)
	}
	if !strings.Contains(output, "CreateEnrollmentKey") {
		t.Fatalf("expected captured log output to include the route name, got:\n%s", output)
	}
	assertNoSecretShapedTokens(t, output)
}
