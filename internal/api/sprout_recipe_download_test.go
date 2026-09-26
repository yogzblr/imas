package api

// End to end: farmer stages a sprout's recipe through its real dispatch
// path (cook.SendCookEventContext, workstream D), and the sprout
// downloads it with cook.FetchStagedRecipe, which sends its gateway JWT
// to this package's real router (Auth, GetFile) over the
// SproutRootCA-pinned client pki.LoadRootCA builds.
//
// POST /v1/refresh is a stand-in here that checks the sprout's NKey
// proof of possession and mints a gateway JWT with the key Auth verifies
// against. The real handler's server side (pki.RefreshSprout) needs PKI
// state this package can't set up; internal/api/handlers'
// TestEnrollClient_AgainstHandler runs the same client refresh against
// it.

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

// testSprout is an enrolled sprout's on-disk identity.
type testSprout struct {
	kp       nkeys.KeyPair
	pub      string
	tenantID string
	sproutID string
	userJWT  string
	boxPub   string
}

// newTestSprout points the sprout's credential paths at a temp dir and
// writes what a completed enrollment leaves there, minus the gateway JWT
// (see setGatewayJWT).
func newTestSprout(t *testing.T, tenantID, sproutID string) *testSprout {
	t.Helper()
	dir := t.TempDir()
	for p, name := range map[*string]string{
		&config.NKeySproutPrivFile:        "sprout.nkey",
		&config.SproutRootCA:              "tls-rootca.pem",
		&config.SproutUserJWTFile:         "sprout.jwt",
		&config.SproutGatewayJWTFile:      "gateway.jwt",
		&config.SproutTenantX25519PubFile: "tenant-x25519.pub",
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
	var box [32]byte
	if _, err := rand.Read(box[:]); err != nil {
		t.Fatal(err)
	}
	s := &testSprout{
		kp: kp, pub: pub, tenantID: tenantID, sproutID: sproutID,
		userJWT: userJWT, boxPub: base64.StdEncoding.EncodeToString(box[:]),
	}
	for path, data := range map[string]string{
		config.NKeySproutPrivFile:        string(seed),
		config.SproutUserJWTFile:         userJWT,
		config.SproutTenantX25519PubFile: s.boxPub,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
			NKeyPub   string `json:"nkey_pub"`
			Timestamp int64  `json:"timestamp"`
			NKeySig   string `json:"nkey_sig"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NKeyPub != s.pub {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sig, err := base64.RawURLEncoding.DecodeString(req.NKeySig)
		verifier, _ := nkeys.FromPublicKey(req.NKeyPub)
		if err != nil || verifier.Verify(pki.RefreshSigningPayload(req.Timestamp, req.NKeyPub), sig) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.refreshes++
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{
			"sprout_id":         s.sproutID,
			"jwt":               s.userJWT,
			"gateway_jwt":       s.mintFor(t, key, time.Now(), time.Now().Add(time.Hour)),
			"nkey_identity":     s.pub,
			"tenant_x25519_pub": s.boxPub,
		})
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
		jid := dispatch(t, tenantID, sproutID)
		s := newTestSprout(t, tenantID, sproutID)
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
			jid := dispatch(t, tenantID, sproutID)
			s := newTestSprout(t, tenantID, sproutID)
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
		jid := dispatch(t, tenantID, sproutID)
		s := newTestSprout(t, tenantID, sproutID)
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
		otherJID := dispatch(t, "t_other", sproutID)
		s := newTestSprout(t, "t_other", sproutID)
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
