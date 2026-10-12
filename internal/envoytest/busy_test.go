package envoytest_test

// The shipped deploy/envoy/envoy.yaml passes farmer's busy answer on
// /v1/enroll and /v1/refresh (503 with a Retry-After: another farmer
// replica holds the sprout's User JWT mint lease) straight to the sprout,
// without retrying it at the proxy, so the sprout's own Retry-After
// handling (internal/pki/enrollclient.go) is what paces the retry.
// Skipped unless IMAS_TEST_ENVOY_BIN names an Envoy binary.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/envoytest"
	"github.com/yogzblr/imas/internal/pki"
)

// busyFarmer answers every POST on /v1/enroll and /v1/refresh with
// farmer's busy answer and counts them; the JWKS fetch gets an empty key
// set.
type busyFarmer struct {
	mu   sync.Mutex
	hits map[string]int
}

func (f *busyFarmer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/.well-known/jwks.json" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
		return
	}
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.mu.Unlock()
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
}

func (f *busyFarmer) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func TestBusyAnswerPassesThroughEnvoy(t *testing.T) {
	farmer := &busyFarmer{hits: map[string]int{}}
	up := httptest.NewTLSServer(farmer)
	t.Cleanup(up.Close)
	env := envoytest.Start(t, envoytest.Upstreams{
		FarmerAPI:     strings.TrimPrefix(up.URL, "https://"),
		NATSWebsocket: "127.0.0.1:" + strconv.Itoa(envoytest.FreePort(t)),
	})

	for _, path := range []string{"/v1/enroll", "/v1/refresh"} {
		resp, err := env.HTTPClient().Post(env.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
			t.Errorf("%s through Envoy: %d, Retry-After %q (%s); want farmer's 503 with Retry-After 1",
				path, resp.StatusCode, resp.Header.Get("Retry-After"), body)
		}
		if n := farmer.count(path); n != 1 {
			t.Errorf("%s: farmer saw %d requests, want 1 (Envoy must not retry a 503)", path, n)
		}
	}

	// The sprout's client, through Envoy: it waits each Retry-After and
	// gives up at its attempt limit, and every one of its tries reaches
	// farmer exactly once.
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	var box [32]byte
	box[0] = 1
	c := &pki.EnrollClient{HTTP: env.HTTPClient(), FarmerURL: env.URL}
	before := farmer.count("/v1/enroll")
	start := time.Now()
	_, err = c.Enroll(t.Context(), "ek_test.secret", "web-01", pki.EnrollKeys{NKey: kp, BoxPriv: &box})
	if !errors.Is(err, pki.ErrFarmerBusy) {
		t.Fatalf("Enroll through Envoy: %v, want ErrFarmerBusy", err)
	}
	tries := farmer.count("/v1/enroll") - before
	if tries < 2 {
		t.Fatalf("farmer saw %d enrollment requests, want the client's retries", tries)
	}
	if waited := time.Since(start); waited < time.Duration(tries-1)*time.Second {
		t.Errorf("%d tries in %s: the client did not wait Retry-After between them", tries, waited)
	}
}
