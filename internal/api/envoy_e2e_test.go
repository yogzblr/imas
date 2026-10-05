package api

// TestSproutDownloadsStagedRecipe (sprout_recipe_download_test.go) with a
// real Envoy running the shipped deploy/envoy/envoy.yaml between the
// sprout and farmer (internal/envoytest; skipped unless
// IMAS_TEST_ENVOY_BIN is set). The sprout pins Envoy's certificate and
// only ever talks to Envoy; Envoy's jwt_authn fetches the JWKS from this
// package's real router.
//
// Unlike the in-process tests, Auth here keeps its production key
// source, handlers.GatewayKeySource: the same Transit-backed signer
// (internal/gatewayjwt/transittest) the router's JWKS endpoint serves,
// so Envoy and farmer verify the one token against the same key set, as
// deployed. Envoy checks the token; farmer checks it again and scopes it
// to the sprout's own prefix. Both have to agree for a download to work.

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/envoytest"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/gatewayjwt/transittest"
	"github.com/yogzblr/imas/internal/pki"
)

func TestSproutDownloadsStagedRecipe_ThroughRealEnvoy(t *testing.T) {
	if os.Getenv(envoytest.EnvBin) == "" {
		t.Skipf("%s not set; skipping real-Envoy test", envoytest.EnvBin)
	}
	const tenantID, sproutID = "t_acme", "web-01"
	stagedPath := "/files/sprouts/" + tenantID + "/" + sproutID + "/recipe.json"

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := testGatewayKey{pub: priv.Public().(ed25519.PublicKey), priv: priv}
	handlers.SetGatewaySigner(transittest.NewSigner(t, priv))
	t.Cleanup(func() { handlers.SetGatewaySigner(nil) })

	newStagingTestServer(t, tenantID)
	s := newTestSprout(t, tenantID, sproutID)
	jid := dispatch(t, tenantID, sproutID)
	farmer := startSproutFarmer(t, key, s)
	farmerURL, err := url.Parse(config.FarmerURL)
	if err != nil {
		t.Fatal(err)
	}
	env := envoytest.Start(t, envoytest.Upstreams{
		FarmerAPI: farmerURL.Host,
		// Not used here; nothing listens on it.
		NATSWebsocket: "127.0.0.1:" + strconv.Itoa(envoytest.FreePort(t)),
	})
	// From here on the sprout only ever talks to Envoy, pinned as its
	// root CA. (startSproutFarmer's cleanup restores config.FarmerURL.)
	config.FarmerURL = env.URL
	if err := os.WriteFile(config.SproutRootCA, env.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pki.LoadRootCA("sprout"); err != nil {
		t.Fatalf("LoadRootCA: %v", err)
	}

	// get sends one GET through Envoy and reports the status and body.
	get := func(t *testing.T, path, authz string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, env.URL+path, nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := env.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body))
	}

	t.Run("fresh gateway JWT: Envoy and farmer both accept it", func(t *testing.T) {
		before, refreshesBefore := farmer.snapshot()
		tok := s.mintFor(t, key, time.Now(), time.Now().Add(time.Hour))
		s.setGatewayJWT(t, tok)

		got, err := cook.FetchStagedRecipe(t.Context())
		if err != nil {
			t.Fatalf("FetchStagedRecipe through Envoy: %v", err)
		}
		checkEnvelope(t, got, jid, sproutID)
		after, refreshes := farmer.snapshot()
		if newDl := after[len(before):]; len(newDl) != 1 || newDl[0] != (recordedDownload{stagedPath, "Bearer " + tok}) {
			t.Errorf("GET /files/ reaching farmer = %+v, want one for %s carrying the gateway JWT", newDl, stagedPath)
		}
		if refreshes != refreshesBefore {
			t.Errorf("refreshes = %d, want none", refreshes-refreshesBefore)
		}
	})

	// A token signed by a key the JWKS no longer serves: Envoy itself
	// turns it away (so farmer never sees it), the sprout refreshes
	// through Envoy's ungated /v1/refresh route and retries.
	t.Run("rejected by Envoy, refreshed through Envoy, retried", func(t *testing.T) {
		before, refreshesBefore := farmer.snapshot()
		_, retiredPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s.setGatewayJWT(t, s.mintFor(t, testGatewayKey{priv: retiredPriv}, time.Now(), time.Now().Add(time.Hour)))

		got, err := cook.FetchStagedRecipe(t.Context())
		if err != nil {
			t.Fatalf("FetchStagedRecipe through Envoy: %v", err)
		}
		checkEnvelope(t, got, jid, sproutID)
		after, refreshes := farmer.snapshot()
		if refreshes-refreshesBefore != 1 {
			t.Errorf("refreshes = %d, want 1", refreshes-refreshesBefore)
		}
		if newDl := after[len(before):]; len(newDl) != 1 || newDl[0].authz != "Bearer "+pki.CurrentGatewayJWT() {
			t.Errorf("GET /files/ reaching farmer = %+v, want only the retry with the refreshed token", newDl)
		}
	})

	t.Run("no or bad token: Envoy answers 401 and farmer never sees it", func(t *testing.T) {
		before, _ := farmer.snapshot()
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		for name, authz := range map[string]string{
			"missing": "",
			"expired": "Bearer " + s.mintFor(t, key, time.Now().Add(-2*time.Hour), time.Now().Add(-10*time.Minute)),
			"forged":  "Bearer " + s.mintFor(t, testGatewayKey{priv: otherPriv}, time.Now(), time.Now().Add(time.Hour)),
		} {
			if code, body := get(t, stagedPath, authz); code != http.StatusUnauthorized {
				t.Errorf("%s token: %d %q, want 401 from jwt_authn", name, code, body)
			}
		}
		if after, _ := farmer.snapshot(); len(after) != len(before) {
			t.Errorf("%d requests reached farmer, want none", len(after)-len(before))
		}
	})

	// Envoy only checks the signature, issuer and expiry; scoping a token
	// to its own sprout's files is farmer's job, and has to survive the
	// hop through Envoy.
	t.Run("validly signed token for another sprout: Envoy passes it, farmer refuses", func(t *testing.T) {
		before, _ := farmer.snapshot()
		for name, tok := range map[string]string{
			"other sprout, same tenant":    mint(t, priv, tenantID, "web-02", time.Now().Add(time.Hour)),
			"same sprout_id, other tenant": mint(t, priv, "t_other", sproutID, time.Now().Add(time.Hour)),
		} {
			if code, body := get(t, stagedPath, "Bearer "+tok); code != http.StatusForbidden {
				t.Errorf("%s: %d %q, want 403 from farmer's Auth", name, code, body)
			}
		}
		if after, _ := farmer.snapshot(); len(after)-len(before) != 2 {
			t.Errorf("%d requests reached farmer, want both (Envoy should pass validly signed tokens)", len(after)-len(before))
		}
	})
}

// GET /v1/sprout/update-manifest through the shipped envoy.yaml: Envoy
// must route it to farmer (recipe_service), not let it fall through to
// the NATS websocket catch-all, and gate it on the gateway JWT exactly
// like /files/. Farmer runs its real router with Auth on its production
// key source, the production manifest SQL over an attached SQLite saas
// schema, and a fleet key set that verifies the stored row.
func TestSproutUpdateManifest_ThroughRealEnvoy(t *testing.T) {
	if os.Getenv(envoytest.EnvBin) == "" {
		t.Skipf("%s not set; skipping real-Envoy test", envoytest.EnvBin)
	}
	const tenantID, sproutID = "t_acme", "web-01"
	const manifestPath = "/v1/sprout/update-manifest"
	const query = "?os=linux&arch=amd64&package_type=deb&version=v2.4.1"

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handlers.SetGatewaySigner(transittest.NewSigner(t, priv))
	t.Cleanup(func() { handlers.SetGatewaySigner(nil) })

	fleetPub, fleetPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: fleetPub}})
	if err != nil {
		t.Fatal(err)
	}
	handlers.SetFleetKeySource(fleetKeys(ks))
	t.Cleanup(func() { handlers.SetFleetKeySource(nil) })

	want := fleetsign.Manifest{
		Version:          "v2.4.1",
		OS:               "linux",
		Arch:             "amd64",
		FileName:         "imas-sprout_2.4.1_linux_amd64.deb",
		ChecksumSHA256:   strings.Repeat("0123456789abcdef", 4),
		MinSproutVersion: "v1.0.0",
	}
	msg, err := want.Message()
	if err != nil {
		t.Fatal(err)
	}
	want.Signature = fleetsign.EncodeSignature(1, ed25519.Sign(fleetPriv, msg))
	db := newSaasTestDB(t)
	exec(t, db, `INSERT INTO saas.fleet_versions
		(id, version, os, arch, package_type, file_name, checksum_sha256, min_sprout_version, signature, revoked, released_at)
		VALUES ('r1', ?, ?, ?, 'deb', ?, ?, ?, ?, 0, ?)`,
		want.Version, want.OS, want.Arch, want.FileName, want.ChecksumSHA256, want.MinSproutVersion, want.Signature, time.Now())
	exec(t, db, `INSERT INTO saas.tenant_update_policy (tenant_id, approved_version, auto_update) VALUES (?, 'v2.4.1', 0)`, tenantID)
	handlers.SetReadinessDB(db)
	t.Cleanup(func() { handlers.SetReadinessDB(nil) })

	// farmer records every manifest request that reaches it; natsWS
	// stands in for nats-server's websocket listener behind the
	// catch-all route and records anything that lands there.
	var mu sync.Mutex
	var reached []recordedDownload
	var fellThrough []string
	router := NewRouter("")
	farmer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == manifestPath {
			mu.Lock()
			reached = append(reached, recordedDownload{r.URL.RequestURI(), r.Header.Get("Authorization")})
			mu.Unlock()
		}
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(farmer.Close)
	natsWS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fellThrough = append(fellThrough, r.URL.RequestURI())
		mu.Unlock()
		http.Error(w, "nats websocket listener", http.StatusTeapot)
	}))
	t.Cleanup(natsWS.Close)
	snapshot := func() ([]recordedDownload, []string) {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedDownload(nil), reached...), append([]string(nil), fellThrough...)
	}

	env := envoytest.Start(t, envoytest.Upstreams{
		FarmerAPI:     strings.TrimPrefix(farmer.URL, "https://"),
		NATSWebsocket: strings.TrimPrefix(natsWS.URL, "https://"),
	})
	get := func(t *testing.T, authz string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, env.URL+manifestPath+query, nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := env.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body))
	}

	t.Run("valid gateway JWT: routed to farmer, signed manifest served", func(t *testing.T) {
		before, wsBefore := snapshot()
		tok := mint(t, priv, tenantID, sproutID, time.Now().Add(time.Hour))
		code, body := get(t, "Bearer "+tok)
		if code != http.StatusOK {
			t.Fatalf("GET %s through Envoy: %d %q, want 200 from farmer", manifestPath, code, body)
		}
		got, err := fleetsign.ParseManifest([]byte(body))
		if err != nil {
			t.Fatalf("ParseManifest(%q): %v", body, err)
		}
		if got != want {
			t.Errorf("manifest = %+v, want %+v", got, want)
		}
		after, wsAfter := snapshot()
		if newReqs := after[len(before):]; len(newReqs) != 1 || newReqs[0] != (recordedDownload{manifestPath + query, "Bearer " + tok}) {
			t.Errorf("requests reaching farmer = %+v, want one for %s carrying the gateway JWT", newReqs, manifestPath+query)
		}
		if len(wsAfter) != len(wsBefore) {
			t.Errorf("requests reaching the NATS websocket upstream = %v, want none", wsAfter[len(wsBefore):])
		}
	})

	t.Run("no or bad token: Envoy answers 401 and farmer never sees it", func(t *testing.T) {
		before, wsBefore := snapshot()
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		for name, authz := range map[string]string{
			"missing": "",
			"expired": "Bearer " + mint(t, priv, tenantID, sproutID, time.Now().Add(-10*time.Minute)),
			"forged":  "Bearer " + mint(t, otherPriv, tenantID, sproutID, time.Now().Add(time.Hour)),
		} {
			if code, body := get(t, authz); code != http.StatusUnauthorized {
				t.Errorf("%s token: %d %q, want 401 from jwt_authn", name, code, body)
			}
		}
		after, wsAfter := snapshot()
		if len(after) != len(before) {
			t.Errorf("%d requests reached farmer, want none", len(after)-len(before))
		}
		if len(wsAfter) != len(wsBefore) {
			t.Errorf("requests reaching the NATS websocket upstream = %v, want none", wsAfter[len(wsBefore):])
		}
	})

	// Envoy only checks the signature, issuer and expiry; which tenant's
	// approved version is served is farmer's job, from the token's own
	// tenant_id, and has to survive the hop through Envoy.
	t.Run("validly signed token for another tenant: Envoy passes it, farmer serves nothing", func(t *testing.T) {
		before, _ := snapshot()
		tok := mint(t, priv, "t_other", sproutID, time.Now().Add(time.Hour))
		if code, body := get(t, "Bearer "+tok); code != http.StatusNotFound || body != `{"error":"not_found"}` {
			t.Errorf("t_other's token: %d %q, want farmer's generic 404", code, body)
		}
		if after, _ := snapshot(); len(after)-len(before) != 1 {
			t.Errorf("%d requests reached farmer, want 1 (Envoy should pass a validly signed token)", len(after)-len(before))
		}
	})
}
