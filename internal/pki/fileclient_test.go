package pki

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/config"
)

// fileServer is a TLS farmer stand-in serving GET /files/ from a map and
// passing POST /v1/refresh through to an enrollServer (the real
// RefreshSprout). It records the Authorization header of every
// GET /files/ request, and answers 403 to any token reject returns true
// for, the way farmer's Auth does for a token it won't accept.
type fileServer struct {
	mu     sync.Mutex
	authz  []string
	files  map[string]string
	reject func(token string) bool
}

func (s *fileServer) sent() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.authz...)
}

// startFileServer must run after enrollForTest: it proxies refreshes to
// the enroll server enrollForTest pointed config.FarmerURL at, then takes
// config.FarmerURL and the pinned client over for itself.
func startFileServer(t *testing.T, files map[string]string) *fileServer {
	t.Helper()
	s := &fileServer{files: files}
	enrollURL, err := url.Parse(config.FarmerURL)
	if err != nil {
		t.Fatal(err)
	}
	nkeyClientMu.RLock()
	enrollClient := nkeyClient
	nkeyClientMu.RUnlock()
	proxy := httputil.NewSingleHostReverseProxy(enrollURL)
	proxy.Transport = enrollClient.Transport

	mux := http.NewServeMux()
	mux.Handle("POST /v1/refresh", proxy)
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		s.mu.Lock()
		s.authz = append(s.authz, authz)
		reject := s.reject
		s.mu.Unlock()
		tok, ok := strings.CutPrefix(authz, "Bearer ")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if reject != nil && reject(tok) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, ok := s.files[strings.TrimPrefix(r.URL.Path, "/files/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	oldURL := config.FarmerURL
	config.FarmerURL = ts.URL
	nkeyClientMu.Lock()
	oldClient := nkeyClient
	nkeyClient = ts.Client()
	nkeyClientMu.Unlock()
	t.Cleanup(func() {
		config.FarmerURL = oldURL
		nkeyClientMu.Lock()
		nkeyClient = oldClient
		nkeyClientMu.Unlock()
	})
	return s
}

// installGatewayJWT makes a token for this sprout's NKey, expiring at
// exp, the persisted and in-memory gateway JWT.
func installGatewayJWT(t *testing.T, minter *jwsGatewayMinter, exp time.Time) string {
	t.Helper()
	kp, err := loadSproutNKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	tok, err := signTestGatewayJWT(minter.key, pub, exp.Add(-time.Hour), exp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutGatewayJWTFile, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	setCurrentGatewayJWT(tok)
	return tok
}

const testFileKey = "sprouts/t_1/web-01/recipe.json"

func TestFetchFarmerFile_SendsGatewayJWTAsBearer(t *testing.T) {
	enroll, _, _ := enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	tok := CurrentGatewayJWT()
	refreshesBefore := enroll.refreshCount()

	data, err := FetchFarmerFile(t.Context(), testFileKey)
	if err != nil {
		t.Fatalf("FetchFarmerFile: %v", err)
	}
	if string(data) != "recipe" {
		t.Errorf("body = %q, want %q", data, "recipe")
	}
	if got := files.sent(); len(got) != 1 || got[0] != "Bearer "+tok {
		t.Errorf("Authorization headers sent = %q, want exactly [\"Bearer <current gateway JWT>\"]", got)
	}
	if n := enroll.refreshCount() - refreshesBefore; n != 0 {
		t.Errorf("a fresh token was refreshed %d times, want 0", n)
	}
}

// A token loaded from disk only (as right after a sprout restart, before
// the refresher has run) is used without a refresh.
func TestFetchFarmerFile_LoadsPersistedToken(t *testing.T) {
	enroll, _, _ := enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	onDisk, _ := os.ReadFile(config.SproutGatewayJWTFile)
	setCurrentGatewayJWT("")
	refreshesBefore := enroll.refreshCount()

	if _, err := FetchFarmerFile(t.Context(), testFileKey); err != nil {
		t.Fatalf("FetchFarmerFile: %v", err)
	}
	if got := files.sent(); len(got) != 1 || got[0] != "Bearer "+string(onDisk) {
		t.Errorf("did not send the persisted gateway JWT: %q", got)
	}
	if n := enroll.refreshCount() - refreshesBefore; n != 0 {
		t.Errorf("refreshes = %d, want 0", n)
	}
}

// An expired or nearly expired token is refreshed through
// RefreshGatewayJWT before the download, and never sent.
func TestFetchFarmerFile_RefreshesStaleTokenFirst(t *testing.T) {
	for name, exp := range map[string]time.Duration{
		"expired":         -time.Minute,
		"expiring soon":   config.DefaultGatewayJWTRefreshMargin / 2,
		"no token loaded": 0,
	} {
		t.Run(name, func(t *testing.T) {
			enroll, minter, _ := enrollForTest(t)
			files := startFileServer(t, map[string]string{testFileKey: "recipe"})
			stale := ""
			if exp != 0 {
				stale = installGatewayJWT(t, minter, time.Now().Add(exp))
			} else {
				os.Remove(config.SproutGatewayJWTFile)
				setCurrentGatewayJWT("")
			}
			refreshesBefore := enroll.refreshCount()

			if _, err := FetchFarmerFile(t.Context(), testFileKey); err != nil {
				t.Fatalf("FetchFarmerFile: %v", err)
			}
			if n := enroll.refreshCount() - refreshesBefore; n != 1 {
				t.Errorf("refreshes = %d, want 1", n)
			}
			fresh := CurrentGatewayJWT()
			if fresh == stale || !gatewayJWTFresh(fresh, time.Now()) {
				t.Fatal("expected a fresh gateway JWT after the download")
			}
			if got := files.sent(); len(got) != 1 || got[0] != "Bearer "+fresh {
				t.Errorf("Authorization headers sent = %q, want only the refreshed token", got)
			}
			if b, _ := os.ReadFile(config.SproutGatewayJWTFile); string(b) != fresh {
				t.Error("the refreshed token was not persisted")
			}
		})
	}
}

// A token the sprout thinks is fine but farmer rejects is refreshed and
// the download retried once.
func TestFetchFarmerFile_RetriesOnceAfterRejection(t *testing.T) {
	enroll, minter, _ := enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	// Unexpired by the sprout's clock, so only farmer's rejection can
	// trigger the refresh.
	rejected := installGatewayJWT(t, minter, time.Now().Add(30*time.Minute))
	files.reject = func(tok string) bool { return tok == rejected }
	refreshesBefore := enroll.refreshCount()

	data, err := FetchFarmerFile(t.Context(), testFileKey)
	if err != nil {
		t.Fatalf("FetchFarmerFile: %v", err)
	}
	if string(data) != "recipe" {
		t.Errorf("body = %q", data)
	}
	if n := enroll.refreshCount() - refreshesBefore; n != 1 {
		t.Errorf("refreshes = %d, want 1", n)
	}
	got := files.sent()
	if len(got) != 2 || got[0] != "Bearer "+rejected || got[1] != "Bearer "+CurrentGatewayJWT() {
		t.Errorf("Authorization headers sent = %q, want the rejected token then the refreshed one", got)
	}
}

// shortRetryBackoff makes the waits between auth retries negligible.
func shortRetryBackoff(t *testing.T) {
	t.Helper()
	old := fileRetryBackoff
	fileRetryBackoff = time.Millisecond
	t.Cleanup(func() { fileRetryBackoff = old })
}

// Rejections are retried, each with a newly refreshed token, until one is
// accepted.
func TestFetchFarmerFile_RetriesUntilAccepted(t *testing.T) {
	shortRetryBackoff(t)
	enroll, _, _ := enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	var mu sync.Mutex
	rejections := 0
	files.reject = func(string) bool {
		mu.Lock()
		defer mu.Unlock()
		rejections++
		return rejections <= 3
	}
	refreshesBefore := enroll.refreshCount()

	if _, err := FetchFarmerFile(t.Context(), testFileKey); err != nil {
		t.Fatalf("FetchFarmerFile: %v", err)
	}
	if n := enroll.refreshCount() - refreshesBefore; n != 3 {
		t.Errorf("refreshes = %d, want 3", n)
	}
	if n := len(files.sent()); n != 4 {
		t.Errorf("requests = %d, want 4 (the original and 3 retries)", n)
	}
}

// After maxFileAuthRetries rejected retries the download fails.
func TestFetchFarmerFile_GivesUpAfterMaxRetries(t *testing.T) {
	shortRetryBackoff(t)
	enroll, _, _ := enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	files.reject = func(string) bool { return true }
	refreshesBefore := enroll.refreshCount()

	if _, err := FetchFarmerFile(t.Context(), testFileKey); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("FetchFarmerFile = %v, want an HTTP 403 error", err)
	}
	if n := enroll.refreshCount() - refreshesBefore; n != maxFileAuthRetries {
		t.Errorf("refreshes = %d, want %d", n, maxFileAuthRetries)
	}
	if n := len(files.sent()); n != maxFileAuthRetries+1 {
		t.Errorf("requests = %d, want %d", n, maxFileAuthRetries+1)
	}
}

// A cancelled context stops the retries during the backoff.
func TestFetchFarmerFile_RetryBackoffHonoursContext(t *testing.T) {
	enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	old := fileRetryBackoff
	fileRetryBackoff = time.Hour
	t.Cleanup(func() { fileRetryBackoff = old })
	ctx, cancel := context.WithCancel(t.Context())
	files.reject = func(string) bool {
		if len(files.sent()) >= 2 {
			cancel()
		}
		return true
	}

	done := make(chan error, 1)
	go func() { _, err := FetchFarmerFile(ctx, testFileKey); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("FetchFarmerFile = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("FetchFarmerFile kept waiting after its context was cancelled")
	}
}

// If the refresh a stale token needs fails, the download fails with that
// error and the stale token is never sent.
func TestFetchFarmerFile_FailedRefreshFailsDownload(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	files := startFileServer(t, map[string]string{testFileKey: "recipe"})
	installGatewayJWT(t, minter, time.Now().Add(-time.Minute))
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(otherBoxPub(t)), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := FetchFarmerFile(t.Context(), testFileKey); !errors.Is(err, ErrTenantKeyMismatch) {
		t.Fatalf("FetchFarmerFile = %v, want ErrTenantKeyMismatch", err)
	}
	if got := files.sent(); len(got) != 0 {
		t.Errorf("sent %d download requests with a token that couldn't be refreshed", len(got))
	}
}

// Concurrent downloads holding the same stale token refresh it once.
func TestFetchFarmerFile_ConcurrentDownloadsRefreshOnce(t *testing.T) {
	enroll, minter, _ := enrollForTest(t)
	startFileServer(t, map[string]string{testFileKey: "recipe"})
	installGatewayJWT(t, minter, time.Now().Add(-time.Minute))
	refreshesBefore := enroll.refreshCount()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := FetchFarmerFile(t.Context(), testFileKey)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("FetchFarmerFile: %v", err)
		}
	}
	if n := enroll.refreshCount() - refreshesBefore; n != 1 {
		t.Errorf("refreshes = %d, want 1", n)
	}
}

func TestFetchFarmerFile_NotFound(t *testing.T) {
	enrollForTest(t)
	startFileServer(t, map[string]string{})
	if _, err := FetchFarmerFile(t.Context(), testFileKey); !errors.Is(err, ErrFarmerFileNotFound) {
		t.Fatalf("FetchFarmerFile = %v, want ErrFarmerFileNotFound", err)
	}
}

// A redirect is not followed, so the bearer token never reaches the
// redirect target.
func TestFetchFarmerFile_DoesNotFollowRedirects(t *testing.T) {
	enrollForTest(t)
	var leaked sync.Map
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store("authz", r.Header.Get("Authorization"))
	}))
	t.Cleanup(elsewhere.Close)
	startFileServer(t, nil)
	redirect := httptest.NewTLSServer(http.RedirectHandler(elsewhere.URL+"/x", http.StatusFound))
	t.Cleanup(redirect.Close)
	config.FarmerURL = redirect.URL

	if _, err := FetchFarmerFile(t.Context(), testFileKey); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("FetchFarmerFile = %v, want an HTTP 302 error", err)
	}
	if v, ok := leaked.Load("authz"); ok {
		t.Errorf("redirect target received a request (Authorization %q)", v)
	}
}

func TestFetchFarmerFile_RejectsBadKeys(t *testing.T) {
	enrollForTest(t)
	files := startFileServer(t, nil)
	for _, key := range []string{"", "/sprouts/t_1/web-01/recipe.json", "sprouts/t_1/web-01/", "sprouts//web-01", "sprouts/t_1/../t_2/web-01/recipe.json", "sprouts/./x", `sprouts\x`, "sprouts/\x00"} {
		if _, err := FetchFarmerFile(t.Context(), key); err == nil {
			t.Errorf("FetchFarmerFile(%q) succeeded, want an invalid-key error", key)
		}
	}
	if n := len(files.sent()); n != 0 {
		t.Errorf("sent %d requests for invalid keys", n)
	}
}

func TestFetchFarmerFile_NotEnrolled(t *testing.T) {
	setupSproutFiles(t)
	if _, err := FetchFarmerFile(t.Context(), testFileKey); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("FetchFarmerFile = %v, want ErrNotEnrolled", err)
	}
}

func TestGatewayJWTIdentity(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	kp, _ := loadSproutNKey()
	pub, _ := kp.PublicKey()
	sign := func(claims map[string]string) string {
		b := jwxjwt.NewBuilder().Subject(pub).IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour))
		for k, v := range claims {
			b = b.Claim(k, v)
		}
		tok, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.EdDSA, minter.key))
		if err != nil {
			t.Fatal(err)
		}
		return string(signed)
	}

	setCurrentGatewayJWT(sign(map[string]string{"tenant_id": "t_1", "sprout_id": "web-01"}))
	tenantID, sproutID, err := GatewayJWTIdentity(t.Context())
	if err != nil || tenantID != "t_1" || sproutID != "web-01" {
		t.Errorf("GatewayJWTIdentity = %q, %q, %v; want t_1, web-01, nil", tenantID, sproutID, err)
	}

	setCurrentGatewayJWT(sign(map[string]string{"tenant_id": "t_1"}))
	if _, _, err := GatewayJWTIdentity(t.Context()); err == nil {
		t.Error("GatewayJWTIdentity accepted a token without sprout_id")
	}
}

func TestGatewayJWTFresh(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	now := time.Now()
	for _, margin := range []time.Duration{0, 10 * time.Minute} {
		old := config.GatewayJWTRefreshMargin
		config.GatewayJWTRefreshMargin = margin
		t.Cleanup(func() { config.GatewayJWTRefreshMargin = old })
		want := margin
		if margin == 0 {
			want = config.DefaultGatewayJWTRefreshMargin
		}
		if got := gatewayJWTMinRemaining(); got != want {
			t.Errorf("margin setting %s: gatewayJWTMinRemaining = %s, want %s", margin, got, want)
		}
		for name, tc := range map[string]struct {
			exp  time.Duration
			want bool
		}{
			"plenty left":           {time.Hour, true},
			"just over the margin":  {want + time.Second, true},
			"just under the margin": {want - time.Second, false},
			"expired":               {-time.Second, false},
		} {
			tok := installGatewayJWT(t, minter, now.Add(tc.exp))
			if got := gatewayJWTFresh(tok, now); got != tc.want {
				t.Errorf("margin setting %s, %s: gatewayJWTFresh = %v, want %v", margin, name, got, tc.want)
			}
		}
	}
	if gatewayJWTFresh("", now) || gatewayJWTFresh("not a jwt", now) {
		t.Error("an empty or unparseable token counted as fresh")
	}
}
