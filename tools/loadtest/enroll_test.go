package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/curve25519"

	"github.com/yogzblr/imas/internal/pki"
)

const (
	testTenantID = "t_loadtest1"
	testSecret   = "internal-secret"
	testToken    = "user-token"
)

// fakeSaaSAPI answers the SaaS API routes the harness calls, as
// internal/saasapi does, checking both credentials.
type fakeSaaSAPI struct {
	mu       sync.Mutex
	status   string
	limited  int // POSTs still to answer 429
	keys     map[string]*fakeKey
	nextID   int
	requests []string
}

type fakeKey struct {
	secret  string
	maxUses int
	used    int
	revoked bool
}

func newFakeSaaSAPI() *fakeSaaSAPI {
	return &fakeSaaSAPI{status: "active", keys: map[string]*fakeKey{}}
}

func (f *fakeSaaSAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-Internal-Auth") != testSecret || r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	base := "/v1/tenants/" + testTenantID
	switch {
	case r.Method == http.MethodGet && r.URL.Path == base+"/status":
		_ = json.NewEncoder(w).Encode(map[string]string{"tenant_id": testTenantID, "status": f.status})
	case r.Method == http.MethodPost && r.URL.Path == base+"/enrollment-keys":
		if f.limited > 0 {
			f.limited--
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		var body struct {
			Hours int `json:"expires_in_hours"`
			Uses  int `json:"max_uses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Hours < 1 || body.Uses < 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.nextID++
		id := fmt.Sprintf("ek_%d", f.nextID)
		k := &fakeKey{secret: id + ".s" + randomHex(4), maxUses: body.Uses}
		f.keys[id] = k
		_ = json.NewEncoder(w).Encode(map[string]any{"key_id": id, "registration_key": k.secret, "max_uses": body.Uses})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/enrollment-keys/"):
		k, ok := f.keys[strings.TrimPrefix(r.URL.Path, base+"/enrollment-keys/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		k.revoked = true
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// redeem spends one use of the key whose secret is token, as farmer's
// redemption does; false if there is none left.
func (f *fakeSaaSAPI) redeem(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k.secret == token && !k.revoked && k.used < k.maxUses {
			k.used++
			return true
		}
	}
	return false
}

// fakeFarmer answers POST /v1/enroll the way farmer's handler does for
// the harness's purposes: it checks the NKey signature over
// pki.EnrollSigningPayload and the join token, issues a User JWT in the
// test tenant's Account for the request's NKey on the first request, and
// a gateway JWT only on the second, which must carry a box key proof and
// the binding. Its first busy answers are 503s with Retry-After 1.
type fakeFarmer struct {
	api       *fakeSaaSAPI
	tf        *tenantFixture
	tenantPub string
	natsURL   string
	gwKey     ed25519.PrivateKey

	mu       sync.Mutex
	busy     int
	enrolled map[string]string // NKey -> sprout ID
	requests int
}

type fakeEnrollRequest struct {
	JoinToken      string          `json:"join_token"`
	NKeyPub        string          `json:"nkey_pub"`
	Hostname       string          `json:"hostname"`
	SproutPub      string          `json:"sprout_pub"`
	Timestamp      int64           `json:"timestamp"`
	NKeySig        string          `json:"nkey_sig"`
	SproutPubProof json.RawMessage `json:"sprout_pub_proof"`
	EnrollBinding  json.RawMessage `json:"enroll_binding"`
}

func (f *fakeFarmer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/enroll" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.mu.Lock()
	f.requests++
	busy := f.busy > 0
	if busy {
		f.busy--
	}
	f.mu.Unlock()
	fail := func() {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
	}
	if busy {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
		return
	}
	var req fakeEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail()
		return
	}
	pub, err := nkeys.FromPublicKey(req.NKeyPub)
	sig, err2 := base64.RawURLEncoding.DecodeString(req.NKeySig)
	if err != nil || err2 != nil || pub.Verify(pki.EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken), sig) != nil {
		fail()
		return
	}
	f.mu.Lock()
	id, known := f.enrolled[req.NKeyPub]
	f.mu.Unlock()
	proven := len(req.SproutPubProof) > 0
	switch {
	case !known && proven, !known && !f.api.redeem(req.JoinToken):
		fail()
		return
	case known && proven && string(req.EnrollBinding) != `{"b":"`+req.NKeyPub+`"}`:
		fail()
		return
	case !known:
		id = req.Hostname
		f.mu.Lock()
		f.enrolled[req.NKeyPub] = id
		f.mu.Unlock()
	}
	uc := jwt.NewUserClaims(req.NKeyPub)
	uc.Name = id
	uc.IssuerAccount = f.tf.accountPub
	uc.Permissions = pki.SproutPermissions(id)
	userJWT, err := uc.Encode(f.tf.signing)
	if err != nil {
		fail()
		return
	}
	out := map[string]any{
		"sprout_id": id, "tenant_id": testTenantID, "jwt": userJWT, "nkey_identity": req.NKeyPub,
		"tenant_x25519_pub": f.tenantPub, "nats_urls": []string{f.natsURL},
	}
	if proven {
		tok, _ := jwxjwt.NewBuilder().Subject(req.NKeyPub).IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).Build()
		gw, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.EdDSA, f.gwKey))
		if err != nil {
			fail()
			return
		}
		out["gateway_jwt"] = string(gw)
	} else {
		out["enroll_binding"] = json.RawMessage(`{"b":"` + req.NKeyPub + `"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// writeServerCA writes ts's certificate as a PEM file and returns its
// path: the CA a client of ts pins.
func writeServerCA(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeLine(t *testing.T, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTenantBoxPub(t *testing.T) string {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// TestRunExternalEndToEnd runs the harness the way it runs against a
// deployed bus, holding no trust key: keys from a SaaS API, every sprout
// enrolled through POST /v1/enroll (with a busy answer on the way),
// connected with the JWT it was issued, measured, and the keys revoked.
func TestRunExternalEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process")
	}
	bus, _, _, tf := startTestBus(t)
	api := newFakeSaaSAPI()
	api.limited = 1
	apiSrv := httptest.NewTLSServer(api)
	t.Cleanup(apiSrv.Close)
	_, gwKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	farmer := &fakeFarmer{api: api, tf: tf, tenantPub: newTenantBoxPub(t), natsURL: bus.URL(), gwKey: gwKey,
		enrolled: map[string]string{}, busy: 1}
	farmerSrv := httptest.NewTLSServer(farmer)
	t.Cleanup(farmerSrv.Close)

	const sprouts = 12
	o, err := parseOptions([]string{
		"-servers", bus.URL(), "-ca", filepath.Join(bus.dir, "ca.pem"), "-tenant", testTenantID,
		"-saasapi-url", apiSrv.URL, "-saasapi-ca", writeServerCA(t, apiSrv),
		"-internal-auth-file", writeLine(t, testSecret), "-token-file", writeLine(t, testToken),
		"-farmer-url", farmerSrv.URL, "-farmer-ca", writeServerCA(t, farmerSrv),
		"-enroll-key-uses", "5", "-enroll-workers", "4",
		"-sprouts", fmt.Sprint(sprouts), "-hold", "1s", "-ping-rate", "40", "-after", "0",
		"-sample-interval", "300ms", "-max-p99", "2s", "-max-ping-fail-ratio", "0.05",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := run(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	res.writeText(&sb)
	if !res.passed() {
		t.Fatalf("checks failed:\n%s", sb.String())
	}
	if res.Mode != "external" || res.Enroll == nil || res.Enroll.Enrolled != sprouts || res.Enroll.Keys != 3 {
		t.Fatalf("enrolment: %+v\n%s", res.Enroll, sb.String())
	}
	if res.Connect.Connected != sprouts || res.Probe != probeBusRTT || res.Hold.OK == 0 {
		t.Fatalf("unexpected result:\n%s", sb.String())
	}
	if len(res.Bus) != 0 || !strings.Contains(sb.String(), "NATS PING") || !strings.Contains(sb.String(), "(a0) enrolment") {
		t.Errorf("report:\n%s", sb.String())
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.keys) != 3 {
		t.Errorf("%d keys minted, want 3 (12 sprouts, 5 uses each)", len(api.keys))
	}
	for id, k := range api.keys {
		if !k.revoked {
			t.Errorf("key %s not revoked at the end of the run", id)
		}
	}
	farmer.mu.Lock()
	defer farmer.mu.Unlock()
	if len(farmer.enrolled) != sprouts || farmer.requests != 2*sprouts+1 {
		t.Errorf("farmer enrolled %d NKeys over %d requests, want %d over %d (two each, one busy answer retried)",
			len(farmer.enrolled), farmer.requests, sprouts, 2*sprouts+1)
	}
}

// A sprout that can't enroll counts as never connected, under its
// enrolment reason, and fails the run.
func TestRunExternalEnrolmentFailureFailsTheRun(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process")
	}
	bus, _, _, tf := startTestBus(t)
	api := newFakeSaaSAPI()
	apiSrv := httptest.NewTLSServer(api)
	t.Cleanup(apiSrv.Close)
	_, gwKey, _ := ed25519.GenerateKey(rand.Reader)
	// Farmer redeems against a key store that holds none of the keys the
	// SaaS API mints, so it refuses every one.
	farmer := &fakeFarmer{api: newFakeSaaSAPI(), tf: tf, tenantPub: newTenantBoxPub(t), natsURL: bus.URL(), gwKey: gwKey, enrolled: map[string]string{}}
	farmerSrv := httptest.NewTLSServer(farmer)
	t.Cleanup(farmerSrv.Close)
	o, err := parseOptions([]string{
		"-servers", bus.URL(), "-ca", filepath.Join(bus.dir, "ca.pem"), "-tenant", testTenantID,
		"-saasapi-url", apiSrv.URL, "-saasapi-ca", writeServerCA(t, apiSrv),
		"-internal-auth-file", writeLine(t, testSecret), "-token-file", writeLine(t, testToken),
		"-farmer-url", farmerSrv.URL, "-farmer-ca", writeServerCA(t, farmerSrv),
		"-enroll-retries", "0", "-sprouts", "3", "-hold", "300ms", "-ping-rate", "20", "-after", "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := run(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.passed() || res.Enroll.Failed != 3 || res.Connect.NotConnected != 3 || res.Connect.Reasons["not enrolled: HTTP 401"] != 3 {
		var sb strings.Builder
		res.writeText(&sb)
		t.Fatalf("want a failed run with 3 sprouts not enrolled (HTTP 401):\n%s", sb.String())
	}
}

func TestExternalRefusesAnInactiveTenant(t *testing.T) {
	api := newFakeSaaSAPI()
	api.status = "offboarded"
	apiSrv := httptest.NewTLSServer(api)
	t.Cleanup(apiSrv.Close)
	o, err := parseOptions(append(externalArgs[:len(externalArgs):len(externalArgs)],
		"-saasapi-url", apiSrv.URL, "-saasapi-ca", writeServerCA(t, apiSrv),
		"-internal-auth-file", writeLine(t, testSecret), "-token-file", writeLine(t, testToken)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := enrollFleet(t.Context(), o); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("enrollFleet for an offboarded tenant: %v", err)
	}
}

func TestSaaSClientCredentialsAndRateLimit(t *testing.T) {
	api := newFakeSaaSAPI()
	api.limited = 3
	apiSrv := httptest.NewTLSServer(api)
	t.Cleanup(apiSrv.Close)
	tokenFile := writeLine(t, testToken)
	c := &saasClient{http: apiSrv.Client(), base: apiSrv.URL, tenant: testTenantID,
		secretFile: writeLine(t, testSecret), tokenFile: tokenFile, minBackoff: time.Millisecond}
	k, err := c.createKey(t.Context(), 1, 1)
	if err != nil || k.ID != "ek_1" || !strings.HasPrefix(k.Secret, "ek_1.") {
		t.Fatalf("createKey after 429s = %+v, %v", k, err)
	}
	// The token is re-read for every request.
	if err := os.WriteFile(tokenFile, []byte("other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.revokeKey(t.Context(), k.ID); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("revokeKey with a wrong token: %v, want a 401", err)
	}
	if err := os.WriteFile(tokenFile, []byte("two\nlines\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.do(t.Context(), http.MethodGet, c.tenantPath("status"), nil, nil); err == nil {
		t.Error("a two-line token file was accepted")
	}
}

func TestKeyPoolMintsPerUses(t *testing.T) {
	api := newFakeSaaSAPI()
	apiSrv := httptest.NewTLSServer(api)
	t.Cleanup(apiSrv.Close)
	c := &saasClient{http: apiSrv.Client(), base: apiSrv.URL, tenant: testTenantID,
		secretFile: writeLine(t, testSecret), tokenFile: writeLine(t, testToken), minBackoff: time.Millisecond}
	p := &keyPool{api: c, uses: 2, hours: 1}
	seen := map[string]int{}
	for range 5 {
		tok, err := p.take(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		seen[tok]++
	}
	if len(seen) != 3 || len(p.minted) != 3 {
		t.Fatalf("5 tokens from keys of 2 uses: %d distinct, %d minted; want 3", len(seen), len(p.minted))
	}
	if n, err := p.revokeAll(t.Context()); n != 3 || err != nil {
		t.Fatalf("revokeAll = %d, %v", n, err)
	}
	for id, k := range api.keys {
		if !k.revoked {
			t.Errorf("%s not revoked", id)
		}
	}
}

func TestEnrollReason(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("x: %w", pki.ErrFarmerBusy): "farmer busy (lease held) at every try",
		context.Canceled:                       "run cut short",
		errors.New("pki: /v1/enroll rejected: HTTP 401 (see farmer's log)"):   "HTTP 401",
		errors.New("pki: /v1/enroll rejected: HTTP 429 (see farmer's log)"):   "HTTP 429 (Envoy's /v1/enroll rate limit: 20 a minute per Envoy)",
		errors.New("minting an enrolment key: POST ...: HTTP 403 forbidden"):  "HTTP 403",
		errors.New("minting an enrolment key: dial tcp: connection refused"):  "minting an enrolment key failed",
		errors.New("pki: /v1/enroll request: dial tcp 10.0.0.1: i/o timeout"): "pki: /v1/enroll request: dial tcp 10.0.0.1: i/o timeout",
	} {
		if got := enrollReason(err); got != want {
			t.Errorf("enrollReason(%v) = %q, want %q", err, got, want)
		}
	}
}
