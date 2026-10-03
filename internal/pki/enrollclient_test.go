package pki

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
)

// setupSproutFiles points every sprout-side path this client reads or
// writes at a fresh temp dir and gives the sprout an NKey, as
// certs.GenNKey would. Returns the NKey pair.
func setupSproutFiles(t *testing.T) nkeys.KeyPair {
	t.Helper()
	dir := t.TempDir()
	saved := []*string{
		&config.NKeySproutPrivFile, &config.SproutUserJWTFile, &config.SproutGatewayJWTFile,
		&config.SproutTenantX25519PubFile, &config.SproutBoxPrivFile, &config.SproutBoxPubFile,
		&config.FarmerURL, &config.SproutBusURLsFile,
		&config.SproutRootCA,
	}
	old := make([]string, len(saved))
	for i, p := range saved {
		old[i] = *p
	}
	oldBusURLs := config.BusURLs
	t.Cleanup(func() {
		for i, p := range saved {
			*p = old[i]
		}
		config.BusURLs = oldBusURLs
	})
	config.BusURLs = nil
	config.SproutBusURLsFile = filepath.Join(dir, "bus-urls.json")
	config.NKeySproutPrivFile = filepath.Join(dir, "sprout.nkey")
	config.SproutUserJWTFile = filepath.Join(dir, "sprout.jwt")
	config.SproutGatewayJWTFile = filepath.Join(dir, "gateway.jwt")
	config.SproutTenantX25519PubFile = filepath.Join(dir, "tenant-x25519.pub")
	config.SproutBoxPrivFile = filepath.Join(dir, "sprout-x25519.key")
	config.SproutBoxPubFile = filepath.Join(dir, "sprout-x25519.pub")

	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	if err := os.WriteFile(config.NKeySproutPrivFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	setCurrentGatewayJWT("")
	return kp
}

// jwsGatewayMinter mints real alg:EdDSA gateway JWTs with a local key, so
// the client's parsing of sub/iat/exp runs against the same token shape
// internal/gatewayjwt produces.
type jwsGatewayMinter struct {
	mu    sync.Mutex
	key   ed25519.PrivateKey
	calls int
}

func newJWSGatewayMinter(t *testing.T) *jwsGatewayMinter {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &jwsGatewayMinter{key: priv}
	orig := gatewayMinter
	gatewayMinter = m
	t.Cleanup(func() { gatewayMinter = orig })
	return m
}

func (m *jwsGatewayMinter) MintGatewayJWT(_ context.Context, c gatewayjwt.GatewayClaims) (string, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return signTestGatewayJWT(m.key, c.Subject, time.Now(), c.Expiry)
}

func signTestGatewayJWT(key ed25519.PrivateKey, sub string, iat, exp time.Time) (string, error) {
	tok, err := jwxjwt.NewBuilder().Subject(sub).Issuer(gatewayjwt.GatewayIssuer).IssuedAt(iat).Expiration(exp).Build()
	if err != nil {
		return "", err
	}
	b, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.EdDSA, key))
	return string(b), err
}

// enrollServer is a TLS farmer stand-in that answers POST /v1/enroll by
// calling the real Enroll, and records every request it receives.
type enrollServer struct {
	mu       sync.Mutex
	requests []enrollWireRequest
	// refreshBodies holds each POST /v1/refresh body verbatim, so tests
	// can check which fields the client actually sent.
	refreshBodies []map[string]any
	// natsURLs is what POST /v1/enroll returns as nats_urls.
	natsURLs []string
}

// setNatsURLs changes what later POST /v1/enroll responses carry as
// nats_urls.
func (s *enrollServer) setNatsURLs(urls ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.natsURLs = urls
}

func (s *enrollServer) refreshCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.refreshBodies)
}

func (s *enrollServer) lastRefreshBody() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshBodies[len(s.refreshBodies)-1]
}

func (s *enrollServer) lastRequest() enrollWireRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[len(s.requests)-1]
}

func startEnrollServer(t *testing.T) *enrollServer {
	t.Helper()
	s := &enrollServer{natsURLs: []string{"wss://127.0.0.1:5407"}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req enrollWireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, req)
		natsURLs := s.natsURLs
		s.mu.Unlock()
		res, err := Enroll(r.Context(), EnrollRequest(req))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(EnrollResponse{
			SproutID: res.SproutID, JWT: res.JWT, GatewayJWT: res.GatewayJWT,
			NKeyIdentity: req.NKeyPub, TenantX25519Pub: res.TenantX25519Pub,
			NatsURLs:               natsURLs,
			TenantX25519Continuity: res.TenantX25519Continuity,
		})
	})
	mux.HandleFunc("POST /v1/refresh", func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.refreshBodies = append(s.refreshBodies, raw)
		s.mu.Unlock()
		b, _ := json.Marshal(raw)
		var req refreshWireRequest
		_ = json.Unmarshal(b, &req)
		res, err := RefreshSprout(r.Context(), RefreshRequest(req))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(RefreshResponse{
			SproutID: res.SproutID, JWT: res.JWT, GatewayJWT: res.GatewayJWT,
			NKeyIdentity: req.NKeyPub, TenantX25519Pub: res.TenantX25519Pub,
			TenantX25519Continuity: res.TenantX25519Continuity,
		})
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	config.FarmerURL = ts.URL
	nkeyClientMu.Lock()
	orig := nkeyClient
	nkeyClient = ts.Client()
	nkeyClientMu.Unlock()
	t.Cleanup(func() {
		nkeyClientMu.Lock()
		nkeyClient = orig
		nkeyClientMu.Unlock()
	})
	return s
}

func TestEnsureSproutBoxKey(t *testing.T) {
	setupSproutFiles(t)

	pub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatalf("EnsureSproutBoxKey: %v", err)
	}
	if _, err := DecodeBoxPubKey(pub); err != nil {
		t.Fatalf("returned public key doesn't decode: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(config.SproutBoxPrivFile)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("private key mode = %o, want 600", perm)
		}
	}
	onDisk, _ := os.ReadFile(config.SproutBoxPubFile)
	if string(onDisk) != pub {
		t.Errorf("public key file = %q, want %q", onDisk, pub)
	}

	// Idempotent: the keypair is generated once and never replaced.
	privBefore, _ := os.ReadFile(config.SproutBoxPrivFile)
	again, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	privAfter, _ := os.ReadFile(config.SproutBoxPrivFile)
	if again != pub || string(privBefore) != string(privAfter) {
		t.Error("second call changed the sprout's X25519 keypair")
	}

	// The returned public key is the private key's real X25519 partner:
	// a box sealed to it opens with the stored private key.
	privRaw, _ := base64.StdEncoding.DecodeString(string(privAfter))
	var priv [32]byte
	copy(priv[:], privRaw)
	sproutPub, _ := DecodeBoxPubKey(pub)
	peerPub, peerPriv, _ := box.GenerateKey(rand.Reader)
	var nonce [24]byte
	sealed := box.Seal(nil, []byte("hello"), &nonce, sproutPub, peerPriv)
	if opened, ok := box.Open(nil, sealed, &nonce, peerPub, &priv); !ok || string(opened) != "hello" {
		t.Error("box sealed to the returned public key doesn't open with the stored private key")
	}
}

func TestEnsureSproutBoxKey_RejectsCorruptKey(t *testing.T) {
	setupSproutFiles(t)
	if err := os.WriteFile(config.SproutBoxPrivFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureSproutBoxKey(); err == nil {
		t.Fatal("expected an error for a corrupt private key file")
	}
	if b, _ := os.ReadFile(config.SproutBoxPrivFile); string(b) != "not a key" {
		t.Error("a corrupt private key file must be left for an operator, not replaced")
	}
}

func TestEnrollSprout_EnrollPersistAndRefresh(t *testing.T) {
	store, _ := setupEnrollTest(t)
	minter := newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 1,
	}
	kp := setupSproutFiles(t)
	nkeyPub, _ := kp.PublicKey()
	srv := startEnrollServer(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := EnrollSprout(t.Context(), "ek_1.supersecret", "web-01", sproutPub)
	if err != nil {
		t.Fatalf("EnrollSprout: %v", err)
	}
	sent := srv.lastRequest()
	if sent.NKeyPub != nkeyPub || sent.SproutPub != sproutPub || sent.Hostname != "web-01" {
		t.Errorf("request carried the wrong identity: %+v", sent)
	}
	if resp.SproutID != "web-01" {
		t.Errorf("sprout_id = %q, want web-01", resp.SproutID)
	}
	if SproutEnrolled() {
		t.Fatal("EnrollSprout must not persist anything by itself")
	}

	if err := PersistEnrollment(resp); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}
	if !SproutEnrolled() {
		t.Fatal("expected the sprout to be enrolled after PersistEnrollment")
	}
	userJWT, err := LoadSproutUserJWT()
	if err != nil || userJWT != resp.JWT {
		t.Fatalf("LoadSproutUserJWT = %q, %v", userJWT, err)
	}
	uc, err := natsjwt.DecodeUserClaims(userJWT)
	if err != nil || uc.Subject != nkeyPub {
		t.Fatalf("persisted User JWT isn't for this sprout: %v", err)
	}
	if urls, src, err := ResolveSproutBusURLs(); err != nil || src != BusURLsFromEnrollment || len(urls) != 1 || urls[0] != "wss://127.0.0.1:5407" {
		t.Errorf("persisted nats_urls: %q from %q (%v)", urls, src, err)
	}
	if gw, err := LoadGatewayJWT(); err != nil || gw != resp.GatewayJWT {
		t.Fatalf("LoadGatewayJWT = %q, %v", gw, err)
	}
	if b, _ := os.ReadFile(config.SproutTenantX25519PubFile); string(b) != resp.TenantX25519Pub {
		t.Errorf("tenant X25519 pub on disk = %q, want %q", b, resp.TenantX25519Pub)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{config.SproutUserJWTFile, config.SproutGatewayJWTFile} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s mode = %o, want 600", filepath.Base(p), perm)
			}
		}
	}

	// Refresh: its own contract on POST /v1/refresh, carrying nkey_pub
	// and a proof of possession only, and spending no token use.
	firstGateway := resp.GatewayJWT
	time.Sleep(1100 * time.Millisecond) // a new iat second, so the token differs
	id, err := RefreshGatewayJWT(t.Context())
	if err != nil {
		t.Fatalf("RefreshGatewayJWT: %v", err)
	}
	if id != "web-01" {
		t.Errorf("refresh re-issued sprout_id %q, want web-01", id)
	}
	body := srv.lastRefreshBody()
	if len(body) != 3 || body["nkey_pub"] != nkeyPub || body["timestamp"] == nil || body["nkey_sig"] == nil {
		t.Errorf("refresh body = %v, want exactly nkey_pub, timestamp and nkey_sig", body)
	}
	if _, ok := body["join_token"]; ok {
		t.Error("refresh must not send a join_token")
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("used_count = %d after refresh, want 1", store.rows["ek_1"].UsedCount)
	}
	if minter.calls != 2 {
		t.Errorf("gateway JWT mints = %d, want 2", minter.calls)
	}
	gw, _ := LoadGatewayJWT()
	if gw == firstGateway || gw != CurrentGatewayJWT() {
		t.Error("refresh did not persist and install a new gateway JWT")
	}
	hdr, err := GatewayJWTHeaders()
	if err != nil || hdr.Get("Authorization") != "Bearer "+gw {
		t.Errorf("GatewayJWTHeaders = %v, %v", hdr, err)
	}
}

// A sprout deleted on farmer must not come back through its refresh
// loop, even while its join token is still valid and unspent.
func TestRefreshGatewayJWT_DeletedSproutCannotReenroll(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 5,
	}
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()
	resp, err := EnrollSprout(t.Context(), "ek_1.supersecret", "web-01", sproutPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatal(err)
	}
	if err := DeleteNKey("t_1", "web-01"); err != nil {
		t.Fatalf("DeleteNKey: %v", err)
	}

	if _, err := RefreshGatewayJWT(t.Context()); err == nil {
		t.Fatal("expected refresh to fail for a deleted sprout")
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("used_count = %d, want 1: refresh must never redeem the join token", store.rows["ek_1"].UsedCount)
	}
}

func TestEnrollSprout_Rejected(t *testing.T) {
	setupEnrollTest(t)
	newJWSGatewayMinter(t)
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()

	if _, err := EnrollSprout(t.Context(), "ek_unknown.secret", "web-01", sproutPub); err == nil {
		t.Fatal("expected an error for an unknown join token")
	}
	if SproutEnrolled() {
		t.Error("a rejected enrollment must not mark the sprout enrolled")
	}
}

func TestEnrollSprout_NoJoinToken(t *testing.T) {
	setupSproutFiles(t)
	if _, err := EnrollSprout(t.Context(), "", "web-01", "unused"); err == nil {
		t.Fatal("expected an error with no join token")
	}
}

func TestEnrollSprout_ClockSkewRejected(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()

	orig := enrollClock
	enrollClock = func() time.Time { return time.Now().Add(-EnrollSigMaxSkew - time.Minute) }
	t.Cleanup(func() { enrollClock = orig })
	if _, err := EnrollSprout(t.Context(), "ek_1.s", "web-01", sproutPub); err == nil {
		t.Fatal("expected a request signed outside the skew window to be rejected")
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Error("a rejected request must not spend the join token")
	}
}

func TestValidateEnrollResponse(t *testing.T) {
	kp := setupSproutFiles(t)
	nkeyPub, _ := kp.PublicKey()
	other, _ := nkeys.CreateUser()
	otherPub, _ := other.PublicKey()

	accountKP, _ := nkeys.CreateAccount()
	userJWTFor := func(sub string) string {
		uc := natsjwt.NewUserClaims(sub)
		s, err := uc.Encode(accountKP)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	_, gwKey, _ := ed25519.GenerateKey(rand.Reader)
	gatewayFor := func(sub string, exp time.Time) string {
		s, err := signTestGatewayJWT(gwKey, sub, time.Now(), exp)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	tenantPub, _, _ := box.GenerateKey(rand.Reader)
	good := func() *EnrollResponse {
		return &EnrollResponse{
			SproutID:        "web-01",
			JWT:             userJWTFor(nkeyPub),
			GatewayJWT:      gatewayFor(nkeyPub, time.Now().Add(time.Hour)),
			NKeyIdentity:    nkeyPub,
			TenantX25519Pub: base64.StdEncoding.EncodeToString(tenantPub[:]),
		}
	}
	if err := validateEnrollResponse(good(), nkeyPub); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	cases := map[string]func(r *EnrollResponse){
		"invalid sprout_id":        func(r *EnrollResponse) { r.SproutID = "../etc" },
		"other nkey_identity":      func(r *EnrollResponse) { r.NKeyIdentity = otherPub },
		"jwt for another nkey":     func(r *EnrollResponse) { r.JWT = userJWTFor(otherPub) },
		"jwt not a NATS JWT":       func(r *EnrollResponse) { r.JWT = "garbage" },
		"gateway for another nkey": func(r *EnrollResponse) { r.GatewayJWT = gatewayFor(otherPub, time.Now().Add(time.Hour)) },
		"gateway already expired":  func(r *EnrollResponse) { r.GatewayJWT = gatewayFor(nkeyPub, time.Now().Add(-time.Minute)) },
		"gateway not a JWT":        func(r *EnrollResponse) { r.GatewayJWT = "garbage" },
		"bad tenant_x25519_pub":    func(r *EnrollResponse) { r.TenantX25519Pub = "AAAA" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := good()
			mutate(r)
			if err := validateEnrollResponse(r, nkeyPub); err == nil {
				t.Error("expected the response to be rejected")
			}
		})
	}
}

// A farmer built before CL.1 still sends fleet_signing_jwks. The sprout
// ignores it (it verifies releases against its shipped keyring), so a
// sprout upgraded first keeps enrolling against an older farmer.
func TestEnrollResponse_IgnoresLegacyFleetSigningJWKS(t *testing.T) {
	var resp EnrollResponse
	body := `{"sprout_id":"web-01","jwt":"j","gateway_jwt":"g","nkey_identity":"n","tenant_x25519_pub":"t","fleet_signing_jwks":{"keys":[]},"nats_urls":["wss://farmer:5407"]}`
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decoding a response with fleet_signing_jwks: %v", err)
	}
	if resp.SproutID != "web-01" || len(resp.NatsURLs) != 1 {
		t.Errorf("decoded %+v", resp)
	}
}

func TestGatewayRefreshDelay(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	tok := func(iat, exp time.Time) string {
		s, err := signTestGatewayJWT(key, "UABC", iat, exp)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	noJitter := func(int64) int64 { return 0 }
	maxJitter := func(n int64) int64 { return n - 1 }

	origTTL := config.GatewayJWTTTL
	t.Cleanup(func() { config.GatewayJWTTTL = origTTL })
	config.GatewayJWTTTL = 24 * time.Hour

	cases := []struct {
		name   string
		token  string
		jitter func(int64) int64
		want   time.Duration
	}{
		{"missing token refreshes now", "", noJitter, 0},
		{"unparseable token refreshes now", "garbage", noJitter, 0},
		{"fresh 24h token refreshes at 16h", tok(now, now.Add(24*time.Hour)), noJitter, 16 * time.Hour},
		{"jitter pulls the refresh earlier", tok(now, now.Add(24*time.Hour)), maxJitter, 16*time.Hour - 144*time.Minute + time.Nanosecond},
		{"past the refresh point refreshes now", tok(now.Add(-20*time.Hour), now.Add(4*time.Hour)), noJitter, 0},
		{"expired token refreshes now", tok(now.Add(-48*time.Hour), now.Add(-24*time.Hour)), noJitter, 0},
		{"very short lifetime is floored", tok(now, now.Add(30*time.Second)), noJitter, gatewayRefreshMinDelay},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := gatewayRefreshDelay(c.token, now, c.jitter); got != c.want {
				t.Errorf("gatewayRefreshDelay = %s, want %s", got, c.want)
			}
		})
	}
}

func TestGatewayJWTHeaders_NoToken(t *testing.T) {
	setCurrentGatewayJWT("")
	if _, err := GatewayJWTHeaders(); err == nil {
		t.Error("expected an error with no gateway JWT loaded")
	}
}

func TestLoadSproutUserJWT_NotEnrolled(t *testing.T) {
	setupSproutFiles(t)
	if _, err := LoadSproutUserJWT(); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("LoadSproutUserJWT = %v, want ErrNotEnrolled", err)
	}
}

func TestRunGatewayJWTRefresher_RefreshesExpiredTokenAndStops(t *testing.T) {
	store, _ := setupEnrollTest(t)
	minter := newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()
	resp, err := EnrollSprout(t.Context(), "ek_1.s", "web-01", sproutPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatal(err)
	}
	// Simulate a sprout that was off past its token's expiry.
	setCurrentGatewayJWT("")

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		if err := RunGatewayJWTRefresher(ctx, "web-01", 10*time.Millisecond); err != nil {
			t.Errorf("RunGatewayJWTRefresher: %v", err)
		}
		close(stopped)
	}()
	deadline := time.After(10 * time.Second)
	for CurrentGatewayJWT() == "" {
		select {
		case <-deadline:
			t.Fatal("refresher did not replace the missing gateway JWT")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("refresher did not stop when its context was cancelled")
	}
	minter.mu.Lock()
	calls := minter.calls
	minter.mu.Unlock()
	if calls != 2 {
		t.Errorf("gateway JWT mints = %d, want 2 (enroll + one refresh, then sleep until due)", calls)
	}
	if strings.TrimSpace(CurrentGatewayJWT()) == "" {
		t.Error("expected a gateway JWT in memory")
	}
}

func TestEnsureEnrolled_AlreadyEnrolledSendsNothing(t *testing.T) {
	setupSproutFiles(t)
	if err := os.WriteFile(config.SproutUserJWTFile, []byte("jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No server and no join token: an enrolled sprout must not need either.
	id, err := EnsureEnrolled(t.Context(), "", "web-01", "unused", time.Millisecond)
	if err != nil || id != "web-01" {
		t.Fatalf("EnsureEnrolled = %q, %v", id, err)
	}
}

func TestEnsureEnrolled_NoJoinToken(t *testing.T) {
	setupSproutFiles(t)
	if _, err := EnsureEnrolled(t.Context(), "", "web-01", "unused", time.Millisecond); !errors.Is(err, ErrNoJoinToken) {
		t.Fatalf("EnsureEnrolled = %v, want ErrNoJoinToken", err)
	}
}

// Farmer resolves a hostname collision within the tenant by suffixing the
// ID; the sprout must run as the ID its User JWT's permissions name.
func TestEnsureEnrolled_AdoptsFarmerAssignedID(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	other, _ := nkeys.CreateUser()
	otherPub, _ := other.PublicKey()
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_1", SproutID: "web-01", NKey: otherPub, State: stateAccepted}); err != nil {
		t.Fatal(err)
	}
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()

	id, err := EnsureEnrolled(t.Context(), "ek_1.s", "web-01", sproutPub, time.Millisecond)
	if err != nil {
		t.Fatalf("EnsureEnrolled: %v", err)
	}
	if id != "web-01_1" {
		t.Errorf("EnsureEnrolled returned %q, want farmer's web-01_1", id)
	}
	if !SproutEnrolled() {
		t.Error("expected the enrollment to be persisted")
	}
}

func TestEnsureEnrolled_RetriesUntilCancelled(t *testing.T) {
	setupEnrollTest(t)
	newJWSGatewayMinter(t)
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := EnsureEnrolled(ctx, "ek_unknown.s", "web-01", sproutPub, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("EnsureEnrolled = %v, want the context's error", err)
	}
	srv.mu.Lock()
	attempts := len(srv.requests)
	srv.mu.Unlock()
	if attempts < 2 {
		t.Errorf("attempts = %d, want the failure retried", attempts)
	}
	if SproutEnrolled() {
		t.Error("a failed enrollment must not be persisted")
	}
}

// enrollForTest enrolls a sprout "web-01" in tenant t_1 through the
// client and persists it, returning the enroll server and minter.
func enrollForTest(t *testing.T) (*enrollServer, *jwsGatewayMinter, *fakeEnrollmentKeyStore) {
	t.Helper()
	store, _ := setupEnrollTest(t)
	minter := newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := EnrollSprout(t.Context(), "ek_1.s", "web-01", sproutPub)
	if err != nil {
		t.Fatalf("EnrollSprout: %v", err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}
	return srv, minter, store
}

func otherBoxPub(t *testing.T) string {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

// A refresh whose tenant X25519 key differs from the pinned one is
// refused whole: the pin, the gateway JWT and the User JWT are untouched.
func TestRefreshGatewayJWT_TenantKeyMismatchRefused(t *testing.T) {
	enrollForTest(t)
	pinned := otherBoxPub(t)
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(pinned), 0o644); err != nil {
		t.Fatal(err)
	}
	gwBefore, _ := os.ReadFile(config.SproutGatewayJWTFile)
	userBefore, _ := os.ReadFile(config.SproutUserJWTFile)
	memBefore := CurrentGatewayJWT()

	if _, err := RefreshGatewayJWT(t.Context()); !errors.Is(err, ErrTenantKeyMismatch) {
		t.Fatalf("RefreshGatewayJWT = %v, want ErrTenantKeyMismatch", err)
	}
	if b, _ := os.ReadFile(config.SproutTenantX25519PubFile); string(b) != pinned {
		t.Error("the pinned tenant X25519 key was replaced")
	}
	if b, _ := os.ReadFile(config.SproutGatewayJWTFile); string(b) != string(gwBefore) {
		t.Error("a refused refresh persisted its gateway JWT")
	}
	if b, _ := os.ReadFile(config.SproutUserJWTFile); string(b) != string(userBefore) {
		t.Error("a refused refresh persisted its User JWT")
	}
	if CurrentGatewayJWT() != memBefore {
		t.Error("a refused refresh installed its gateway JWT in memory")
	}
}

// The refresher gives up at once on a tenant key mismatch, since a retry
// would get the same answer, and returns the error for the caller to
// treat as fatal.
func TestRunGatewayJWTRefresher_TenantKeyMismatchIsFatal(t *testing.T) {
	srv, _, _ := enrollForTest(t)
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(otherBoxPub(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	setCurrentGatewayJWT("") // due now

	done := make(chan error, 1)
	go func() { done <- RunGatewayJWTRefresher(t.Context(), "web-01", time.Millisecond) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTenantKeyMismatch) {
			t.Fatalf("RunGatewayJWTRefresher = %v, want ErrTenantKeyMismatch", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("refresher kept running after a tenant key mismatch")
	}
	if n := srv.refreshCount(); n != 1 {
		t.Errorf("refresh attempts = %d, want 1 (no retries on a mismatch)", n)
	}
}

// An enrollment (e.g. a replay after a crash mid-persist) whose tenant
// key differs from an already-pinned one fails before writing anything.
func TestPersistEnrollment_TenantKeyMismatchRefused(t *testing.T) {
	setupSproutFiles(t)
	pinned := otherBoxPub(t)
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(pinned), 0o644); err != nil {
		t.Fatal(err)
	}
	resp := &EnrollResponse{JWT: "user-jwt", GatewayJWT: "gw-jwt", TenantX25519Pub: otherBoxPub(t)}
	if err := PersistEnrollment(resp); !errors.Is(err, ErrTenantKeyMismatch) {
		t.Fatalf("PersistEnrollment = %v, want ErrTenantKeyMismatch", err)
	}
	if SproutEnrolled() {
		t.Error("a refused enrollment must not mark the sprout enrolled")
	}
	if _, err := os.Stat(config.SproutGatewayJWTFile); !os.IsNotExist(err) {
		t.Error("a refused enrollment wrote the gateway JWT")
	}
	if b, _ := os.ReadFile(config.SproutTenantX25519PubFile); string(b) != pinned {
		t.Error("the pinned tenant X25519 key was replaced")
	}
}

// The same key again (a replay after a crash mid-persist) is fine.
func TestPersistEnrollment_SameTenantKeyAccepted(t *testing.T) {
	setupSproutFiles(t)
	pub := otherBoxPub(t)
	resp := &EnrollResponse{JWT: "user-jwt", GatewayJWT: "gw-jwt", TenantX25519Pub: pub}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatal(err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatalf("persisting the same tenant key again: %v", err)
	}
}

// An enrolled sprout whose tenant key pin has gone missing refuses to
// accept (and re-pin) whatever key the next refresh carries.
func TestRefreshGatewayJWT_MissingTenantKeyPinRefused(t *testing.T) {
	enrollForTest(t)
	if err := os.Remove(config.SproutTenantX25519PubFile); err != nil {
		t.Fatal(err)
	}
	gwBefore, _ := os.ReadFile(config.SproutGatewayJWTFile)
	if _, err := RefreshGatewayJWT(t.Context()); !errors.Is(err, ErrTenantKeyNotPinned) {
		t.Fatalf("RefreshGatewayJWT = %v, want ErrTenantKeyNotPinned", err)
	}
	if _, err := os.Stat(config.SproutTenantX25519PubFile); !os.IsNotExist(err) {
		t.Error("a refresh re-pinned the tenant key")
	}
	if b, _ := os.ReadFile(config.SproutGatewayJWTFile); string(b) != string(gwBefore) {
		t.Error("a refused refresh persisted its gateway JWT")
	}
}
