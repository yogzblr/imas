package pki

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// mockKVv2Server serves the subset of OpenBao/Vault KV v2's HTTP API
// tenantbox.go's obKVClient uses: GET/PUT <mount>/data/<path>, including
// PUT's check-and-set semantics (cas: 0 means "only create, fail if a
// version already exists") — mirroring the real API as documented, not
// this package's own encoding of it, so obKVClient's HTTP client code is
// exercised for real. See internal/gatewayjwt/mint_test.go's
// mockTransitServer for the same pattern applied to Transit.
type mockKVv2Server struct {
	t       *testing.T
	mount   string
	path    string
	token   string
	writeMu sync.Mutex

	data    map[string]string // nil until first successful write
	version int
	casHits int // number of PUTs rejected by the cas guard
}

func newMockKVv2Server(t *testing.T) *mockKVv2Server {
	t.Helper()
	return &mockKVv2Server{t: t, mount: "secret", path: "imas/tenant-x25519", token: "test-token"}
}

func (m *mockKVv2Server) start() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+m.mount+"/data/"+m.path, m.handleData)
	return httptest.NewServer(mux)
}

func (m *mockKVv2Server) handleData(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != m.token {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		m.handleGet(w)
	case http.MethodPut:
		m.handlePut(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockKVv2Server) handleGet(w http.ResponseWriter) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if m.data == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
		return
	}
	resp := map[string]any{
		"data": map[string]any{
			"data": m.data,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockKVv2Server) handlePut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Options struct {
			Cas *int `json:"cas"`
		} `json:"options"`
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	if req.Options.Cas != nil && *req.Options.Cas == 0 && m.data != nil {
		m.casHits++
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
		return
	}
	m.data = req.Data
	m.version++
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": m.version}})
}

// setupTenantBoxOpenBao points the package at a mock OpenBao KV v2 server
// for the duration of the test, and clears the in-process keypair cache
// both before and after (so cache state never leaks between tests).
func setupTenantBoxOpenBao(t *testing.T, srv *mockKVv2Server) *httptest.Server {
	t.Helper()
	ts := srv.start()
	t.Cleanup(ts.Close)
	t.Setenv(EnvTenantBoxOpenBaoAddr, ts.URL)
	t.Setenv(EnvTenantBoxOpenBaoKVMount, srv.mount)
	t.Setenv(EnvTenantBoxOpenBaoKVPath, srv.path)
	t.Setenv(EnvTenantBoxOpenBaoAuthMethod, TenantBoxAuthMethodToken)
	t.Setenv(EnvTenantBoxOpenBaoToken, srv.token)
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)
	return ts
}

func TestGetTenantX25519PublicKey_NotConfigured(t *testing.T) {
	t.Setenv(EnvTenantBoxOpenBaoAddr, "")
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)

	if _, err := GetTenantX25519PublicKey(); err == nil {
		t.Fatal("expected an error when OpenBao is not configured")
	}
}

func TestGetTenantX25519PublicKey_GeneratesAndPersists(t *testing.T) {
	srv := newMockKVv2Server(t)
	setupTenantBoxOpenBao(t, srv)

	pub1, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey: %v", err)
	}
	if pub1 == "" {
		t.Fatal("expected non-empty public key")
	}
	if srv.data == nil {
		t.Fatal("expected the keypair to be persisted to OpenBao")
	}

	// A second call, with the cache cleared, must load the same keypair
	// back from OpenBao rather than generating a new one.
	resetTenantX25519KeypairCache()
	pub2, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey (reload): %v", err)
	}
	if pub1 != pub2 {
		t.Errorf("expected stable public key across reload, got %q then %q", pub1, pub2)
	}
}

func TestGetTenantX25519PublicKey_CachedWithoutOpenBaoRoundtrip(t *testing.T) {
	srv := newMockKVv2Server(t)
	ts := setupTenantBoxOpenBao(t, srv)

	pub1, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey: %v", err)
	}

	// Close the server without clearing the in-process cache: a cached
	// call must still succeed and return the same key.
	ts.Close()

	pub2, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey (cached): %v", err)
	}
	if pub1 != pub2 {
		t.Errorf("expected cached call to return the same key, got %q then %q", pub1, pub2)
	}
}

func TestGetTenantX25519PublicKey_ConcurrentBootstrapAgreesOnOneKey(t *testing.T) {
	srv := newMockKVv2Server(t)
	setupTenantBoxOpenBao(t, srv)

	const n = 8
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			resetKeypairCacheRacy() // simulate n separate processes: no shared in-process cache
			results[i], errs[i] = GetTenantX25519PublicKey()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Errorf("expected every concurrent bootstrap to agree on one key, got %q and %q", results[0], results[i])
		}
	}
}

// resetKeypairCacheRacy clears the cache without the mutex a real
// concurrent-process scenario wouldn't share either — used only to force
// TestGetTenantX25519PublicKey_ConcurrentBootstrapAgreesOnOneKey's
// goroutines through the OpenBao create-race path instead of just hitting
// the in-process cache after the first winner populates it.
func resetKeypairCacheRacy() {
	tenantBoxMu.Lock()
	tenantBoxPub, tenantBoxPriv = nil, nil
	tenantBoxMu.Unlock()
}

func TestGetTenantX25519PublicKey_CorruptStoredDataErrors(t *testing.T) {
	srv := newMockKVv2Server(t)
	setupTenantBoxOpenBao(t, srv)
	srv.data = map[string]string{"pub": "not-valid-base64!!", "priv": "also-not-valid!!"}
	srv.version = 1

	if _, err := GetTenantX25519PublicKey(); err == nil {
		t.Fatal("expected an error for corrupt stored key material")
	}
}

func TestGetTenantX25519PublicKey_MissingFieldsErrors(t *testing.T) {
	srv := newMockKVv2Server(t)
	setupTenantBoxOpenBao(t, srv)
	srv.data = map[string]string{"pub": "onlyPubHere"}
	srv.version = 1

	if _, err := GetTenantX25519PublicKey(); err == nil {
		t.Fatal("expected an error when the stored secret is missing priv")
	}
}

// TestObKVClient_WriteKeypairIfAbsent_CASGuardRejectsSecondCreate exercises
// the check-and-set race-safety obKVClient.writeKeypairIfAbsent relies on
// directly, deterministically rather than via goroutine timing: a second
// cas:0 write against a path that already has data must be rejected
// (created=false, no error), and a subsequent read must return the first
// write's keypair, not the second's.
func TestObKVClient_WriteKeypairIfAbsent_CASGuardRejectsSecondCreate(t *testing.T) {
	srv := newMockKVv2Server(t)
	ts := srv.start()
	t.Cleanup(ts.Close)
	t.Setenv(EnvTenantBoxOpenBaoAddr, ts.URL)
	t.Setenv(EnvTenantBoxOpenBaoKVMount, srv.mount)
	t.Setenv(EnvTenantBoxOpenBaoKVPath, srv.path)
	t.Setenv(EnvTenantBoxOpenBaoAuthMethod, TenantBoxAuthMethodToken)
	t.Setenv(EnvTenantBoxOpenBaoToken, srv.token)

	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		t.Fatalf("newTenantBoxClientFromEnv: %v", err)
	}
	ctx := t.Context()

	var pub1, priv1, pub2, priv2 [32]byte
	pub1[0], priv1[0] = 1, 1
	pub2[0], priv2[0] = 2, 2

	created, err := client.writeKeypairIfAbsent(ctx, &pub1, &priv1)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if !created {
		t.Fatal("expected the first write to succeed")
	}

	created, err = client.writeKeypairIfAbsent(ctx, &pub2, &priv2)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if created {
		t.Fatal("expected the second cas:0 write to be rejected")
	}
	if srv.casHits != 1 {
		t.Errorf("expected exactly 1 cas rejection, got %d", srv.casHits)
	}

	gotPub, gotPriv, found, err := client.readKeypair(ctx)
	if err != nil {
		t.Fatalf("readKeypair: %v", err)
	}
	if !found {
		t.Fatal("expected a keypair to be found")
	}
	if *gotPub != pub1 || *gotPriv != priv1 {
		t.Error("expected the read-back keypair to be the first write's, not the second's")
	}
}

func TestGetTenantX25519KeyPair_MatchesPublicKey(t *testing.T) {
	srv := newMockKVv2Server(t)
	setupTenantBoxOpenBao(t, srv)

	pubB64, err := GetTenantX25519PublicKey()
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey: %v", err)
	}
	pub, priv, err := GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}
	if priv == nil {
		t.Fatal("expected a non-nil private key")
	}
	if got := base64.StdEncoding.EncodeToString(pub[:]); got != pubB64 {
		t.Errorf("expected GetTenantX25519KeyPair's pub to match GetTenantX25519PublicKey, got %q vs %q", got, pubB64)
	}
}
