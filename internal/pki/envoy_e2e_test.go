package pki

// A sprout's whole life through a real Envoy running the shipped
// deploy/envoy/envoy.yaml (internal/envoytest; skipped unless
// IMAS_TEST_ENVOY_BIN is set). The in-process tests elsewhere in this
// package talk to farmer and the bus directly, so none of them can catch
// a DMZ config that turns a correct sprout away.
//
// Real: Envoy and its jwt_authn/local_ratelimit config; this package's
// enrollment client and server side (EnrollSprout -> Enroll,
// RefreshGatewayJWT -> RefreshSprout, both with NKey proof of
// possession); gateway JWTs minted and served as a JWKS by
// internal/gatewayjwt's production code; the operator-mode bus
// (ConfigureNats) with its websocket listener; ConnectSprout's auth
// options (UserJWTAndSeed + GatewayJWTHeaders); FetchFarmerFile. Stubbed:
// OpenBao Transit (internal/gatewayjwt/transittest), and
// farmer's GET /files/ handler, which here only records what Envoy
// forwarded; internal/api's envoy_e2e_test.go runs the real one.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/envoytest"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/gatewayjwt/transittest"
)

func TestSproutLifecycle_ThroughRealEnvoy(t *testing.T) {
	if os.Getenv(envoytest.EnvBin) == "" {
		t.Skipf("%s not set; skipping real-Envoy test", envoytest.EnvBin)
	}
	store, _ := setupEnrollTest(t)
	useRealFarmerKey(t)
	signer := newTransitGatewaySigner(t)
	forger := newTransitGatewaySigner(t) // same kid, different key
	origMinter := gatewayMinter
	SetGatewaySigner(signer)
	t.Cleanup(func() { gatewayMinter = origMinter })
	config.GatewayJWTTTL = time.Hour

	origWS := config.FarmerWSPort
	wsPort := envoytest.FreePort(t)
	config.FarmerWSPort = strconv.Itoa(wsPort)
	t.Cleanup(func() { config.FarmerWSPort = origWS })
	defer startTestBus(t)()

	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 1,
	}
	sproutKP := setupSproutFiles(t)
	sproutNKey, _ := sproutKP.PublicKey()
	startEnrollServer(t)

	// farmer as Envoy sees it: one TLS upstream for farmer_api and
	// recipe_service. JWKS and /files/ here; /v1/enroll and /v1/refresh
	// go on to startEnrollServer's real Enroll/RefreshSprout.
	enrollURL, _ := url.Parse(config.FarmerURL)
	nkeyClientMu.RLock()
	enrollTransport := nkeyClient.Transport
	nkeyClientMu.RUnlock()
	proxy := httputil.NewSingleHostReverseProxy(enrollURL)
	proxy.Transport = enrollTransport

	const recipe = `{"steps":[]}`
	var filesMu sync.Mutex
	var filesAuthz, filesNKey, filesPath string
	mux := http.NewServeMux()
	mux.Handle("GET /v1/.well-known/jwks.json", gatewayjwt.JWKSHandler(signer))
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		filesMu.Lock()
		filesAuthz, filesNKey, filesPath = r.Header.Get("Authorization"), r.Header.Get("x-imas-sprout-nkey"), r.URL.Path
		filesMu.Unlock()
		io.WriteString(w, recipe)
	})
	mux.Handle("/", proxy)
	farmer := httptest.NewTLSServer(mux)
	t.Cleanup(farmer.Close)

	env := envoytest.Start(t, envoytest.Upstreams{
		FarmerAPI:     farmer.Listener.Addr().String(),
		NATSWebsocket: "127.0.0.1:" + strconv.Itoa(wsPort),
	})
	// From here on the sprout only ever talks to Envoy.
	config.FarmerURL = env.URL
	nkeyClientMu.Lock()
	nkeyClient = env.HTTPClient()
	nkeyClientMu.Unlock()

	// Enroll: POST /v1/enroll through Envoy's ungated, rate-limited route.
	boxPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := EnrollSprout(t.Context(), "ek_1.supersecret", "web-01", boxPub)
	if err != nil {
		t.Fatalf("EnrollSprout through Envoy: %v", err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}
	sproutID := resp.SproutID

	connect := func() (*nats.Conn, error) {
		userJWT, err := LoadSproutUserJWT()
		if err != nil {
			t.Fatal(err)
		}
		seed, err := os.ReadFile(config.NKeySproutPrivFile)
		if err != nil {
			t.Fatal(err)
		}
		// ConnectSprout's auth options, minus its reconnect tuning.
		return nats.Connect(env.BusURL, nats.Secure(env.TLSConfig()),
			nats.UserJWTAndSeed(userJWT, strings.TrimSpace(string(seed))),
			nats.WebSocketConnectionHeadersHandler(GatewayJWTHeaders),
			nats.NoReconnect(), nats.Timeout(5*time.Second))
	}
	roundTrip := func(t *testing.T) {
		t.Helper()
		nc, err := connect()
		if err != nil {
			t.Fatalf("wss:// connect through Envoy: %v", err)
		}
		defer nc.Close()
		subj := "imas.sprouts." + sproutID + ".facts"
		sub, err := nc.SubscribeSync(subj)
		if err != nil {
			t.Fatal(err)
		}
		if err := nc.Publish(subj, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		if msg, err := sub.NextMsg(5 * time.Second); err != nil || string(msg.Data) != "hello" {
			t.Fatalf("round trip through Envoy: msg=%v err=%v", msg, err)
		}
	}
	// upgradeStatus is Envoy's answer to a websocket upgrade carrying
	// authz (none if empty), which nats.go doesn't surface itself.
	upgradeStatus := func(t *testing.T, authz string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, env.URL+"/", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
		r, err := env.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusSwitchingProtocols {
			t.Logf("websocket upgrade: %d %s", r.StatusCode, strings.TrimSpace(string(body)))
		}
		return r.StatusCode
	}
	mint := func(t *testing.T, s *gatewayjwt.GatewaySigner, exp time.Time) string {
		t.Helper()
		tok, err := gatewayjwt.MintGatewayJWT(t.Context(), s, gatewayjwt.GatewayClaims{
			Subject: sproutNKey, TenantID: "t_1", SproutID: sproutID, Expiry: exp,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	t.Run("enrolled sprout connects over wss and the bus works", roundTrip)

	t.Run("Envoy refuses the upgrade without a valid gateway JWT", func(t *testing.T) {
		// Expiry well past jwt_authn's default 60s clock_skew_seconds.
		cases := map[string]string{
			"missing": "",
			"expired": "Bearer " + mint(t, signer, time.Now().Add(-10*time.Minute)),
			"forged":  "Bearer " + mint(t, forger, time.Now().Add(time.Hour)),
		}
		for name, authz := range cases {
			if code := upgradeStatus(t, authz); code != http.StatusUnauthorized {
				t.Errorf("%s token: upgrade status %d, want 401 from jwt_authn", name, code)
			}
		}
	})

	t.Run("refresh through Envoy, then reconnect with the new token", func(t *testing.T) {
		old := CurrentGatewayJWT()
		time.Sleep(1100 * time.Millisecond) // a new iat, so a different token
		id, err := RefreshGatewayJWT(t.Context())
		if err != nil {
			t.Fatalf("RefreshGatewayJWT through Envoy: %v", err)
		}
		if id != sproutID {
			t.Errorf("refresh re-issued sprout %q, want %q", id, sproutID)
		}
		fresh := CurrentGatewayJWT()
		if fresh == "" || fresh == old {
			t.Fatal("refresh did not install a new gateway JWT")
		}
		onDisk, err := os.ReadFile(config.SproutGatewayJWTFile)
		if err != nil || strings.TrimSpace(string(onDisk)) != fresh {
			t.Fatalf("refreshed token not persisted (err=%v)", err)
		}
		roundTrip(t)
	})

	t.Run("recipe download through Envoy's /files/ route", func(t *testing.T) {
		key := "sprouts/t_1/" + sproutID + "/recipe.json"
		data, err := FetchFarmerFile(t.Context(), key)
		if err != nil {
			t.Fatalf("FetchFarmerFile through Envoy: %v", err)
		}
		if string(data) != recipe {
			t.Errorf("downloaded %q, want %q", data, recipe)
		}
		filesMu.Lock()
		defer filesMu.Unlock()
		if filesPath != "/files/"+key {
			t.Errorf("farmer saw path %q", filesPath)
		}
		if filesAuthz != "Bearer "+CurrentGatewayJWT() {
			t.Error("farmer did not receive the sprout's gateway JWT (farmer re-verifies it, so Envoy must forward it)")
		}
		if filesNKey != sproutNKey {
			t.Errorf("x-imas-sprout-nkey = %q, want the token's sub %q", filesNKey, sproutNKey)
		}
	})
}

// newTransitGatewaySigner is a production GatewaySigner over a mock
// Transit holding a fresh key.
func newTransitGatewaySigner(t *testing.T) *gatewayjwt.GatewaySigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return transittest.NewSigner(t, priv)
}
