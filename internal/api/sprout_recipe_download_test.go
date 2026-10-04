package api

// End to end: farmer stages a sprout's recipe through its real dispatch
// path (cook.SendCookEventContext, workstream D), and the sprout
// downloads it with cook.FetchStagedRecipe, which sends its gateway JWT
// to this package's real router (Auth, GetFile) over the
// SproutRootCA-pinned client pki.LoadRootCA builds.
//
// POST /v1/refresh is a stand-in here that opens the sprout's sealed
// refresh (J.2: s2f.refresh, under its box key and the tenant key) and
// answers with a sealed reply carrying a gateway JWT minted with the key
// Auth verifies against. The real handler's server side
// (pki.RefreshSprout) needs PKI state this package can't set up;
// internal/api/handlers' TestEnrollClient_AgainstHandler runs the same
// client refresh against it.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// sproutFarmer is a TLS farmer: NewRouter, plus the refresh stand-in,
// recording the Authorization header of every GET /files/ request.
type sproutFarmer struct {
	mu        sync.Mutex
	downloads []recordedDownload
	refreshes int
}

type recordedDownload struct {
	path, authz string
}

func (f *sproutFarmer) snapshot() ([]recordedDownload, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedDownload(nil), f.downloads...), f.refreshes
}

// testSprout is an enrolled sprout's on-disk identity, and the tenant
// keypair farmer would hold for it.
type testSprout struct {
	kp       nkeys.KeyPair
	pub      string
	tenantID string
	sproutID string
	userJWT  string
	// boxPub is the tenant's X25519 public key, which the sprout pinned.
	boxPub     string
	tenantPriv *[32]byte
	// sproutBoxPub is the sprout's own box public key, as farmer records
	// it at enrollment.
	sproutBoxPub *[32]byte
}

// newTestSprout points the sprout's credential paths at a temp dir and
// writes what a completed enrollment leaves there, minus the gateway JWT
// (see setGatewayJWT). The tenant key it pins is tenantID's real one from
// the mock OpenBao newStagingTestServer starts, and farmer records its box
// key, as enrollment would, so what farmer stages for it is sealed to it
// (security review 2026-10-b, B1) and opens with cook.FetchStagedRecipe.
// Call it before dispatching to it.
func newTestSprout(t *testing.T, tenantID, sproutID string) *testSprout {
	t.Helper()
	dir := t.TempDir()
	for p, name := range map[*string]string{
		&config.NKeySproutPrivFile:        "sprout.nkey",
		&config.SproutRootCA:              "tls-rootca.pem",
		&config.SproutUserJWTFile:         "sprout.jwt",
		&config.SproutGatewayJWTFile:      "gateway.jwt",
		&config.SproutTenantX25519PubFile: "tenant-x25519.pub",
		&config.SproutBoxPrivFile:         "sprout-x25519.key",
		&config.SproutBoxPubFile:          "sprout-x25519.pub",
	} {
		old := *p
		*p = filepath.Join(dir, name)
		t.Cleanup(func() { *p = old })
	}

	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	acct, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	userJWT, err := natsjwt.NewUserClaims(pub).Encode(acct)
	if err != nil {
		t.Fatal(err)
	}
	tenantKeys, err := pki.TenantBoxKeys(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	tenantPub, tenantPriv := tenantKeys[0].Pub, tenantKeys[0].Priv
	s := &testSprout{
		kp: kp, pub: pub, tenantID: tenantID, sproutID: sproutID,
		userJWT: userJWT, boxPub: base64.StdEncoding.EncodeToString(tenantPub[:]), tenantPriv: tenantPriv,
	}
	for path, data := range map[string]string{
		config.NKeySproutPrivFile:        string(seed),
		config.SproutUserJWTFile:         userJWT,
		config.SproutTenantX25519PubFile: s.boxPub,
		// The tenant and sprout ID an enrolled sprout pinned: every
		// refresh is sealed naming them, and checked against them.
		pki.SproutTenantIDFile(): tenantID,
		pki.SproutIDFile():       sproutID,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sproutBoxPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if s.sproutBoxPub, err = pki.DecodeBoxPubKey(sproutBoxPub); err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenantID, sproutID, sproutBoxPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	// So the stub sprout answering farmer's sealed push opens it too.
	encodedPriv, err := os.ReadFile(config.SproutBoxPrivFile)
	if err != nil {
		t.Fatal(err)
	}
	rawPriv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedPriv)))
	if err != nil || len(rawPriv) != 32 {
		t.Fatalf("decoding the sprout's box key: %v", err)
	}
	var priv [32]byte
	copy(priv[:], rawPriv)
	stagingSproutsMu.Lock()
	stagingSprouts[[2]string{tenantID, sproutID}] = &priv
	stagingSproutsMu.Unlock()
	return s
}

// mintFor signs a gateway JWT for s in the shape gatewayjwt.MintGatewayJWT
// produces: sub is the sprout's NKey, kid is the key version.
func (s *testSprout) mintFor(t *testing.T, key testGatewayKey, iat, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Subject(s.pub).
		Issuer(gatewayjwt.GatewayIssuer).
		IssuedAt(iat).
		Expiration(exp).
		Claim("tenant_id", s.tenantID).
		Claim("sprout_id", s.sproutID).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, "1"); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, key.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// setGatewayJWT persists tok as the sprout's gateway JWT and loads it,
// as the sprout does at startup.
func (s *testSprout) setGatewayJWT(t *testing.T, tok string) {
	t.Helper()
	if err := os.WriteFile(config.SproutGatewayJWTFile, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadGatewayJWT(); err != nil {
		t.Fatal(err)
	}
}

// startSproutFarmer serves NewRouter over TLS, pins its certificate as
// the sprout's root CA, and points the sprout at it.
func startSproutFarmer(t *testing.T, key testGatewayKey, s *testSprout) *sproutFarmer {
	t.Helper()
	f := &sproutFarmer{}
	router := NewRouter("")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/refresh", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NKeyPub string          `json:"nkey_pub"`
			Sealed  json.RawMessage `json:"sealed"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NKeyPub != s.pub {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		pair := []payloadbox.KeyPair{{PeerPub: s.sproutBoxPub, Priv: s.tenantPriv}}
		msg, err := payloadbox.Open(req.Sealed, pair,
			payloadbox.Expect{Purpose: payloadbox.PurposeRefresh, TenantID: s.tenantID, SproutID: s.sproutID})
		var body struct {
			NKeyPub string `json:"nkey_pub"`
		}
		if err != nil || msg.ReplyTo != "" || json.Unmarshal(msg.Body, &body) != nil || body.NKeyPub != s.pub {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reply, err := payloadbox.SealReply(payloadbox.Reply{
			Purpose: pki.PurposeRefreshReply, TenantID: s.tenantID, Principal: s.sproutID, ReplyTo: msg.ID,
			Method: pki.RefreshMethod, Subject: pki.RefreshSubject,
			Result: pki.RefreshResponse{
				SproutID: s.sproutID, TenantID: s.tenantID, JWT: s.userJWT,
				GatewayJWT:   s.mintFor(t, key, time.Now(), time.Now().Add(time.Hour)),
				NKeyIdentity: s.pub, TenantX25519Pub: s.boxPub,
			},
		}, pair)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.refreshes++
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]json.RawMessage{"sealed": reply})
	})
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/files/") {
			f.mu.Lock()
			f.downloads = append(f.downloads, recordedDownload{r.URL.Path, r.Header.Get("Authorization")})
			f.mu.Unlock()
		}
		router.ServeHTTP(w, r)
	}))
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	oldURL := config.FarmerURL
	config.FarmerURL = ts.URL
	t.Cleanup(func() { config.FarmerURL = oldURL })
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(config.SproutRootCA, rootPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pki.LoadRootCA("sprout"); err != nil {
		t.Fatalf("LoadRootCA: %v", err)
	}
	return f
}

// checkEnvelope checks env is the recipe dispatched as jobID to sproutID.
func checkEnvelope(t *testing.T, env cook.RecipeEnvelope, jobID, sproutID string) {
	t.Helper()
	if env.JobID != jobID || len(env.Steps) != 1 || env.Steps[0].Properties["name"] != "echo "+sproutID {
		t.Errorf("downloaded recipe is not %s's dispatch %s: %+v", sproutID, jobID, env)
	}
	if age := time.Since(env.DispatchedAt); env.DispatchedAt.IsZero() || age < 0 || age > time.Minute {
		t.Errorf("downloaded recipe's DispatchedAt = %v, want farmer's dispatch time", env.DispatchedAt)
	}
}

func TestSproutDownloadsStagedRecipe(t *testing.T) {
	const tenantID, sproutID = "t_acme", "web-01"
	stagedPath := "/files/sprouts/" + tenantID + "/" + sproutID + "/recipe.json"

	t.Run("fresh gateway JWT sent as the bearer token", func(t *testing.T) {
		key := installGatewayKey(t)
		newStagingTestServer(t, tenantID)
		s := newTestSprout(t, tenantID, sproutID)
		jid := dispatch(t, tenantID, sproutID)
		farmer := startSproutFarmer(t, key, s)
		tok := s.mintFor(t, key, time.Now(), time.Now().Add(time.Hour))
		s.setGatewayJWT(t, tok)

		env, err := cook.FetchStagedRecipe(t.Context())
		if err != nil {
			t.Fatalf("FetchStagedRecipe: %v", err)
		}
		checkEnvelope(t, env, jid, sproutID)
		downloads, refreshes := farmer.snapshot()
		if len(downloads) != 1 || downloads[0] != (recordedDownload{stagedPath, "Bearer " + tok}) {
			t.Errorf("GET /files/ requests = %+v, want one for %s carrying the gateway JWT", downloads, stagedPath)
		}
		if refreshes != 0 {
			t.Errorf("refreshes = %d, want 0", refreshes)
		}
	})

	// An expired token (a sprout powered off past the TTL) or one about
	// to expire goes through the refresh path first; the download succeeds
	// with the new token, and the stale one is never sent.
	for name, exp := range map[string]time.Duration{"expired": -time.Hour, "about to expire": 30 * time.Second} {
		t.Run(name+" gateway JWT refreshed first", func(t *testing.T) {
			key := installGatewayKey(t)
			newStagingTestServer(t, tenantID)
			s := newTestSprout(t, tenantID, sproutID)
			jid := dispatch(t, tenantID, sproutID)
			farmer := startSproutFarmer(t, key, s)
			stale := s.mintFor(t, key, time.Now().Add(exp-time.Hour), time.Now().Add(exp))
			s.setGatewayJWT(t, stale)

			env, err := cook.FetchStagedRecipe(t.Context())
			if err != nil {
				t.Fatalf("FetchStagedRecipe: %v", err)
			}
			checkEnvelope(t, env, jid, sproutID)
			downloads, refreshes := farmer.snapshot()
			if refreshes != 1 {
				t.Errorf("refreshes = %d, want 1", refreshes)
			}
			fresh := pki.CurrentGatewayJWT()
			if fresh == stale {
				t.Fatal("gateway JWT was not replaced")
			}
			if len(downloads) != 1 || downloads[0].authz != "Bearer "+fresh {
				t.Errorf("GET /files/ requests = %+v, want one carrying only the refreshed token", downloads)
			}
			if b, _ := os.ReadFile(config.SproutGatewayJWTFile); string(b) != fresh {
				t.Error("refreshed gateway JWT was not persisted")
			}
		})
	}

	// A token that looks fine to the sprout but that Auth rejects (here,
	// signed by a key version farmer no longer serves) is refreshed and
	// the download retried.
	t.Run("rejected gateway JWT refreshed and retried", func(t *testing.T) {
		key := installGatewayKey(t)
		_, retiredPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		retired := testGatewayKey{priv: retiredPriv}
		newStagingTestServer(t, tenantID)
		s := newTestSprout(t, tenantID, sproutID)
		jid := dispatch(t, tenantID, sproutID)
		farmer := startSproutFarmer(t, key, s)
		s.setGatewayJWT(t, s.mintFor(t, retired, time.Now(), time.Now().Add(time.Hour)))

		env, err := cook.FetchStagedRecipe(t.Context())
		if err != nil {
			t.Fatalf("FetchStagedRecipe: %v", err)
		}
		checkEnvelope(t, env, jid, sproutID)
		downloads, refreshes := farmer.snapshot()
		if refreshes != 1 || len(downloads) != 2 || downloads[1].authz != "Bearer "+pki.CurrentGatewayJWT() {
			t.Errorf("refreshes = %d, downloads = %+v; want one refresh and a retry with the new token", refreshes, downloads)
		}
	})

	// The key comes from the gateway JWT's own (tenant_id, sprout_id), so
	// two tenants' sprouts sharing a sprout_id each get their own recipe.
	t.Run("same sprout_id in another tenant", func(t *testing.T) {
		key := installGatewayKey(t)
		newStagingTestServer(t, tenantID, "t_other")
		dispatch(t, tenantID, sproutID)
		s := newTestSprout(t, "t_other", sproutID)
		otherJID := dispatch(t, "t_other", sproutID)
		farmer := startSproutFarmer(t, key, s)
		s.setGatewayJWT(t, s.mintFor(t, key, time.Now(), time.Now().Add(time.Hour)))

		env, err := cook.FetchStagedRecipe(t.Context())
		if err != nil {
			t.Fatalf("FetchStagedRecipe: %v", err)
		}
		checkEnvelope(t, env, otherJID, sproutID)
		if downloads, _ := farmer.snapshot(); len(downloads) != 1 || downloads[0].path != "/files/sprouts/t_other/web-01/recipe.json" {
			t.Errorf("GET /files/ requests = %+v, want t_other's key", downloads)
		}
	})

	t.Run("nothing staged yet", func(t *testing.T) {
		key := installGatewayKey(t)
		newStagingTestServer(t, tenantID)
		s := newTestSprout(t, tenantID, sproutID)
		startSproutFarmer(t, key, s)
		s.setGatewayJWT(t, s.mintFor(t, key, time.Now(), time.Now().Add(time.Hour)))

		if _, err := cook.FetchStagedRecipe(t.Context()); !errors.Is(err, pki.ErrFarmerFileNotFound) {
			t.Fatalf("FetchStagedRecipe = %v, want pki.ErrFarmerFileNotFound", err)
		}
	})
}
