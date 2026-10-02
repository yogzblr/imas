package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/fleetsign"
)

const (
	testChecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	// testCallerToken is what saasapi presents; testPreviousToken is the
	// one it presented before the last rotation.
	testCallerToken   = "saasapi-caller-token-0123456789abcdef"
	testPreviousToken = "saasapi-previous-token-0123456789abcdef"
	testFloor         = "v2.0.0"
)

func testManifest() fleetsign.Manifest {
	return fleetsign.Manifest{
		Version:          "v2.4.1",
		OS:               "linux",
		Arch:             "amd64",
		FileName:         "imas-sprout_2.4.1_amd64.deb",
		ChecksumSHA256:   testChecksum,
		MinSproutVersion: "v2.0.0",
	}
}

// signBody is the POST /v1/sign body saasapi sends for m.
func signBody(m fleetsign.Manifest) string {
	b, _ := json.Marshal(map[string]string{
		"version": m.Version, "os": m.OS, "arch": m.Arch, "file_name": m.FileName,
		"checksum_sha256": m.ChecksumSHA256, "min_sprout_version": m.MinSproutVersion,
	})
	return string(b)
}

// mockTransit implements Transit's sign/<key> and keys/<key> for one
// Ed25519 key, in the same request/response shapes as the real API (see
// internal/gatewayjwt's mockTransitServer). Only signToken may sign;
// readTokens may read keys. Any other token, or path, is a 403/404.
type mockTransit struct {
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	version    int
	signToken  string
	readTokens map[string]bool
	// tamper, when set, makes sign return a signature over different
	// bytes than it was given.
	tamper bool
	signs  int
	// older are earlier key versions Transit still holds but no longer
	// signs with (below version). minDecryption is the key's verify floor
	// as Transit reports it.
	older         map[int]ed25519.PublicKey
	minDecryption int
}

func newMockTransit(t *testing.T) *mockTransit {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &mockTransit{priv: priv, pub: pub, version: 1, signToken: "signer",
		readTokens: map[string]bool{"signer": true, "farmer-ro": true, "saasapi-ro": true}}
}

func (m *mockTransit) serve(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		deny := func() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"1 error occurred:\n\t* permission denied\n\n"}})
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/"+fleetsign.DefaultTransitKeyName:
			if tok != m.signToken {
				deny()
				return
			}
			var req struct{ Input string }
			json.NewDecoder(r.Body).Decode(&req)
			input, _ := base64.StdEncoding.DecodeString(req.Input)
			if m.tamper {
				input = append(input, 'x')
			}
			m.signs++
			sig := ed25519.Sign(m.priv, input)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"signature":   "vault:v" + strconv.Itoa(m.version) + ":" + base64.StdEncoding.EncodeToString(sig),
				"key_version": m.version,
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/"+fleetsign.DefaultTransitKeyName:
			if !m.readTokens[tok] {
				deny()
				return
			}
			keys := map[string]any{}
			add := func(v int, pub ed25519.PublicKey) {
				der, _ := x509.MarshalPKIXPublicKey(pub)
				keys[strconv.Itoa(v)] = map[string]any{
					"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
				}
			}
			add(m.version, m.pub)
			for v, pub := range m.older {
				add(v, pub)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type":                   "ed25519",
				"keys":                   keys,
				"min_decryption_version": m.minDecryption,
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func setSignerEnv(t *testing.T, addr, token string) {
	t.Helper()
	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoTransitMount, "")
	t.Setenv(EnvOpenBaoAuthMethod, "")
	t.Setenv(EnvOpenBaoToken, token)
	t.Setenv(EnvTransitKeyName, "")
}

func newSigner(t *testing.T, m *mockTransit, token string) *obTransitClient {
	t.Helper()
	setSignerEnv(t, m.serve(t), token)
	c, err := newTransitClientFromEnv()
	if err != nil {
		t.Fatalf("newTransitClientFromEnv: %v", err)
	}
	return c
}

// newTestService is the signing service over m, accepting the current and
// previous caller tokens, with floor testFloor.
func newTestService(t *testing.T, m *mockTransit, openBaoToken string) http.Handler {
	t.Helper()
	svc := &signService{
		signer: newSigner(t, m, openBaoToken),
		tokens: [][]byte{[]byte(testCallerToken), []byte(testPreviousToken)},
		floor:  testFloor,
	}
	return svc.handler()
}

// postSign sends body to POST /v1/sign with authz as the Authorization
// header (none if empty) and returns the status and decoded body.
func postSign(t *testing.T, h http.Handler, authz, body string) (int, map[string]string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/sign", strings.NewReader(body))
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	out := map[string]string{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func bearer(tok string) string { return "Bearer " + tok }

func TestSign_ReturnsSignatureOverManifestMessage(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")

	code, out := postSign(t, h, bearer(testCallerToken), signBody(testManifest()))
	if code != http.StatusOK || out["signature"] == "" {
		t.Fatalf("POST /v1/sign = %d %v", code, out)
	}
	// It verifies with nothing but the public key, as farmer, saasapi and
	// the sprout each check it.
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: m.pub}})
	signed := testManifest()
	signed.Signature = out["signature"]
	if err := ks.Verify(signed); err != nil {
		t.Fatalf("returned signature does not verify: %v", err)
	}
	// And it is over the canonical message, byte for byte, with no URL.
	_, sig, err := fleetsign.DecodeSignature(out["signature"])
	if err != nil {
		t.Fatal(err)
	}
	want := "imas-fleet-manifest-v1|v2.4.1|linux|amd64|imas-sprout_2.4.1_amd64.deb|" + testChecksum + "|v2.0.0"
	if !ed25519.Verify(m.pub, []byte(want), sig) {
		t.Fatalf("signature is not over %q", want)
	}
	// The response carries the signature and nothing else.
	if len(out) != 1 {
		t.Fatalf("response has extra fields: %v", out)
	}
}

// Stateless: signing the same entry twice signs twice (Ed25519 is
// deterministic, so the signature is the same). Deduplication is saasapi's
// job, against saas.fleet_versions.
func TestSign_Stateless(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")
	_, a := postSign(t, h, bearer(testCallerToken), signBody(testManifest()))
	_, b := postSign(t, h, bearer(testCallerToken), signBody(testManifest()))
	if a["signature"] == "" || a["signature"] != b["signature"] || m.signs != 2 {
		t.Fatalf("signatures %q, %q after %d Transit signs", a["signature"], b["signature"], m.signs)
	}
}

func TestSign_RefusesCallerWithoutToken(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")
	body := signBody(testManifest())
	for name, authz := range map[string]string{
		"no header":                "",
		"empty bearer":             "Bearer ",
		"wrong token":              bearer("not-the-caller-token-0123456789abcdef"),
		"token prefix":             bearer(testCallerToken[:len(testCallerToken)-1]),
		"token plus suffix":        bearer(testCallerToken + "x"),
		"basic scheme":             "Basic " + base64.StdEncoding.EncodeToString([]byte("saasapi:"+testCallerToken)),
		"lowercase scheme":         "bearer " + testCallerToken,
		"token without scheme":     testCallerToken,
		"openbao token, not ours":  bearer("signer"),
		"bff shared secret header": "",
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/sign", strings.NewReader(body))
			if authz != "" {
				r.Header.Set("Authorization", authz)
			}
			if name == "bff shared secret header" {
				r.Header.Set("X-Internal-Auth", testCallerToken)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "signature\"") {
				t.Fatalf("status %d, body %s; want a bare 401", w.Code, w.Body.String())
			}
		})
	}
	if m.signs != 0 {
		t.Fatalf("Transit was asked to sign %d time(s) for unauthenticated callers", m.signs)
	}
	// The previous token is accepted during a rotation.
	if code, out := postSign(t, h, bearer(testPreviousToken), body); code != http.StatusOK || out["signature"] == "" {
		t.Fatalf("previous token: %d %v", code, out)
	}
}

func TestSign_RefusesVersionAtOrBelowFloor(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")
	for _, v := range []string{testFloor, "v1.9.9", "v2.0.0-rc.1"} {
		e := testManifest()
		e.Version, e.MinSproutVersion = v, "v1.0.0"
		code, out := postSign(t, h, bearer(testCallerToken), signBody(e))
		if code != http.StatusUnprocessableEntity || out["error"] != "version_not_above_floor" {
			t.Errorf("%s: %d %v, want 422 version_not_above_floor", v, code, out)
		}
	}
	if m.signs != 0 {
		t.Fatalf("Transit was asked to sign %d version(s) at or below the floor", m.signs)
	}
	e := testManifest()
	e.Version = "v2.0.1"
	if code, out := postSign(t, h, bearer(testCallerToken), signBody(e)); code != http.StatusOK {
		t.Fatalf("v2.0.1 above floor %s: %d %v", testFloor, code, out)
	}
}

// fleetsign's rules, applied before anything reaches Transit, and never by
// rewriting a value.
func TestSign_RejectsInvalidManifest(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")
	for name, mutate := range map[string]func(*fleetsign.Manifest){
		"uppercase checksum":     func(e *fleetsign.Manifest) { e.ChecksumSHA256 = strings.ToUpper(testChecksum) },
		"path in file_name":      func(e *fleetsign.Manifest) { e.FileName = "../imas-sprout.deb" },
		"min above version":      func(e *fleetsign.Manifest) { e.MinSproutVersion = "v9.0.0" },
		"non-canonical version":  func(e *fleetsign.Manifest) { e.Version = "v2.4" },
		"separator in os":        func(e *fleetsign.Manifest) { e.OS = "linux|amd64" },
		"empty arch":             func(e *fleetsign.Manifest) { e.Arch = "" },
		"uppercase os":           func(e *fleetsign.Manifest) { e.OS = "Linux" },
		"whitespace in checksum": func(e *fleetsign.Manifest) { e.ChecksumSHA256 = " " + testChecksum },
	} {
		e := testManifest()
		mutate(&e)
		if code, out := postSign(t, h, bearer(testCallerToken), signBody(e)); code != http.StatusBadRequest || out["error"] != "invalid_manifest" {
			t.Errorf("%s: %d %v, want 400 invalid_manifest", name, code, out)
		}
	}
	if m.signs != 0 {
		t.Fatalf("Transit was asked to sign %d invalid entr(ies)", m.signs)
	}
}

func TestDecodeSignRequest(t *testing.T) {
	valid := signBody(testManifest())
	if m, err := decodeSignRequest(strings.NewReader(valid)); err != nil || m != testManifest() {
		t.Fatalf("valid body: %+v, %v", m, err)
	}
	without := func(key string) string {
		var obj map[string]string
		json.Unmarshal([]byte(valid), &obj)
		delete(obj, key)
		b, _ := json.Marshal(obj)
		return string(b)
	}
	for name, body := range map[string]string{
		"empty":               "",
		"array":               "[" + valid + "]",
		"missing field":       without("min_sprout_version"),
		"unknown field":       strings.Replace(valid, "{", `{"artifact_url":"https://evil.example.com/x",`, 1),
		"signature supplied":  strings.Replace(valid, "{", `{"signature":"v1:AAAA",`, 1),
		"duplicate field":     strings.Replace(valid, "{", `{"version":"v9.9.9",`, 1),
		"case-folded key":     strings.Replace(valid, `"version"`, `"Version"`, 1),
		"number value":        strings.Replace(valid, `"os":"linux"`, `"os":1`, 1),
		"null value":          strings.Replace(valid, `"os":"linux"`, `"os":null`, 1),
		"trailing object":     valid + "{}",
		"trailing garbage":    valid + "x",
		"truncated":           valid[:len(valid)-1],
		"nested object value": strings.Replace(valid, `"os":"linux"`, `"os":{"a":"b"}`, 1),
	} {
		if _, err := decodeSignRequest(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted %s", name, body)
		}
	}
}

func TestSign_OversizedBody(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")
	e := testManifest()
	body := strings.Replace(signBody(e), "{", `{"pad":"`+strings.Repeat("a", maxSignRequestBytes)+`",`, 1)
	if code, _ := postSign(t, h, bearer(testCallerToken), body); code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", code)
	}
}

// If what Transit hands back doesn't verify over the canonical message,
// no signature is returned.
func TestSign_SelfVerifiesBeforeReturning(t *testing.T) {
	m := newMockTransit(t)
	m.tamper = true
	h := newTestService(t, m, "signer")
	code, out := postSign(t, h, bearer(testCallerToken), signBody(testManifest()))
	if code != http.StatusBadGateway || out["signature"] != "" {
		t.Fatalf("POST /v1/sign with a bad Transit signature = %d %v", code, out)
	}
}

// A read-only OpenBao token (what farmer and saasapi hold) gets a 403 from
// sign, so no signature comes back. This is the mock's policy, not
// OpenBao's; see TestOpenBaoEnforcesReadOnlyFleetKey for the real one.
func TestSign_ReadOnlyOpenBaoTokenCannotSign(t *testing.T) {
	m := newMockTransit(t)
	signer := newSigner(t, m, "saasapi-ro")
	if _, _, err := signAndVerify(t.Context(), signer, testManifest()); !errors.Is(err, errSignFailed) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("signAndVerify with a read-only token = %v, want errSignFailed/403", err)
	}
	h := (&signService{signer: signer, tokens: [][]byte{[]byte(testCallerToken)}, floor: testFloor}).handler()
	if code, out := postSign(t, h, bearer(testCallerToken), signBody(testManifest())); code != http.StatusBadGateway || out["signature"] != "" {
		t.Fatalf("POST /v1/sign = %d %v", code, out)
	}
}

// After a rotation, new signatures use the newest key version while older
// versions Transit still verifies stay in the key set the self-verify
// reads.
func TestSign_AfterRotationSignsWithNewestVersion(t *testing.T) {
	m := newMockTransit(t)
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	m.version, m.older, m.minDecryption = 2, map[int]ed25519.PublicKey{1: oldPub}, 1
	h := newTestService(t, m, "signer")
	code, out := postSign(t, h, bearer(testCallerToken), signBody(testManifest()))
	if code != http.StatusOK || !strings.HasPrefix(out["signature"], "v2:") {
		t.Fatalf("POST /v1/sign after rotation = %d %v, want a v2 signature", code, out)
	}
}

func TestRoutes(t *testing.T) {
	m := newMockTransit(t)
	h := newTestService(t, m, "signer")
	for _, tc := range []struct {
		method, path string
		authz        string
		want         int
	}{
		{http.MethodGet, "/healthz", "", http.StatusOK},
		{http.MethodGet, "/v1/sign", bearer(testCallerToken), http.StatusMethodNotAllowed},
		{http.MethodPut, "/v1/sign", bearer(testCallerToken), http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/verify", bearer(testCallerToken), http.StatusNotFound},
		{http.MethodGet, "/", "", http.StatusNotFound},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.authz != "" {
			r.Header.Set("Authorization", tc.authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig(t *testing.T) {
	tokenFile := writeFile(t, testCallerToken+"\n")
	prevFile := writeFile(t, testPreviousToken)
	base := map[string]string{
		EnvTLSCertFile:     "/tls/tls.crt",
		EnvTLSKeyFile:      "/tls/tls.key",
		EnvCallerTokenFile: tokenFile,
		EnvVersionFloor:    "v2.4.0",
	}
	env := func(over map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return base[k]
		}
	}

	cfg, err := loadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listenAddr != defaultListenAddr || cfg.floor != "v2.4.0" || len(cfg.tokens) != 1 || string(cfg.tokens[0]) != testCallerToken {
		t.Fatalf("config = %+v", cfg)
	}
	cfg, err = loadConfig(env(map[string]string{EnvCallerTokenPreviousFile: prevFile, EnvListenAddr: ":9443"}))
	if err != nil || len(cfg.tokens) != 2 || cfg.listenAddr != ":9443" {
		t.Fatalf("with previous token: %+v, %v", cfg, err)
	}

	for name, over := range map[string]map[string]string{
		"no cert":                  {EnvTLSCertFile: ""},
		"no key":                   {EnvTLSKeyFile: ""},
		"no floor":                 {EnvVersionFloor: ""},
		"floor without v":          {EnvVersionFloor: "2.4.0"},
		"floor not canonical":      {EnvVersionFloor: "v2.4"},
		"floor with build":         {EnvVersionFloor: "v2.4.0+b1"},
		"no token file":            {EnvCallerTokenFile: ""},
		"missing token file":       {EnvCallerTokenFile: filepath.Join(t.TempDir(), "missing")},
		"short token":              {EnvCallerTokenFile: writeFile(t, "short")},
		"empty token":              {EnvCallerTokenFile: writeFile(t, "\n")},
		"token with inner space":   {EnvCallerTokenFile: writeFile(t, "saasapi caller token 0123456789abcdef")},
		"oversized token file":     {EnvCallerTokenFile: writeFile(t, strings.Repeat("a", maxCallerTokenFile+1))},
		"weak previous token":      {EnvCallerTokenPreviousFile: writeFile(t, "short")},
		"missing previous token":   {EnvCallerTokenPreviousFile: filepath.Join(t.TempDir(), "missing")},
		"token with control chars": {EnvCallerTokenFile: writeFile(t, "saasapi-caller-token\x00-0123456789abcdef")},
	} {
		if _, err := loadConfig(env(over)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// run refuses to start without its configuration (exit 2), before any
// listener or OpenBao call.
func TestRun_ConfigErrors(t *testing.T) {
	if code := run(func(string) string { return "" }); code != 2 {
		t.Fatalf("empty environment: exit %d, want 2", code)
	}
	tokenFile := writeFile(t, testCallerToken)
	t.Setenv(EnvOpenBaoAddr, "")
	env := map[string]string{EnvTLSCertFile: "/x", EnvTLSKeyFile: "/y", EnvCallerTokenFile: tokenFile, EnvVersionFloor: "v1.0.0"}
	if code := run(func(k string) string { return env[k] }); code != 2 {
		t.Fatalf("no OpenBao configuration: exit %d, want 2", code)
	}
	// OpenBao configured, but the certificate files don't exist.
	setSignerEnv(t, "http://127.0.0.1:1", "x")
	if code := run(func(k string) string { return env[k] }); code != 2 {
		t.Fatalf("unreadable certificate: exit %d, want 2", code)
	}
}

// TestNoDatabaseAccess: fleetreleaser holds the only Transit sign
// capability, so it must not also be able to write what it signs. Its
// binary links no database client, ORM or driver and none of the
// packages that own a schema, and its configuration has no DSN.
func TestNoDatabaseAccess(t *testing.T) {
	// go test puts $GOROOT/bin first on the test's PATH.
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("finding the go command: %v", err)
	}
	out, err := exec.Command(goTool, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	if !slices.Contains(deps, "github.com/yogzblr/imas/internal/fleetsign") {
		t.Fatalf("go list -deps output looks wrong: %v", deps)
	}
	// database/sql/driver is allowed: it is only the Valuer/Scanner
	// interfaces, which a UUID type pulls in, not a database client.
	forbiddenExact := []string{"database/sql"}
	forbiddenTrees := []string{
		"gorm.io",
		"github.com/go-sql-driver",
		"github.com/glebarez",
		"modernc.org/sqlite",
		"github.com/pressly/goose",
		"github.com/yogzblr/imas/internal/saasapi",
		"github.com/yogzblr/imas/internal/pxc",
		"github.com/yogzblr/imas/internal/migrations",
	}
	for _, d := range deps {
		if slices.Contains(forbiddenExact, d) {
			t.Errorf("fleetreleaser links %s", d)
		}
		for _, f := range forbiddenTrees {
			if d == f || strings.HasPrefix(d, f+"/") {
				t.Errorf("fleetreleaser links %s", d)
			}
		}
	}

	// No configuration reads a database location.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"DSN", "IMAS_FLEETRELEASER_DB"} {
		if bytes.Contains(src, []byte(s)) {
			t.Errorf("main.go mentions %q", s)
		}
	}
}
