package pki

// Live-bus proof of the JWT -> OpenBao hand-off (FLAG FOR SECURITY
// REVIEW — see deploy/farmer/README.md): what `farmer
// publish-saasapi-credential` writes to OpenBao KV, from a Job pod that
// shares only farmer's mounted seeds (not its PKI directory), is a
// credential the real bus accepts with exactly the SaaS API's scoping —
// equivalent to the one farmer itself mints at boot.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/openbaokv"
)

type kvCall struct {
	method, path string
	data         map[string]any
}

// startKVMock serves KV v2 GET/POST at /v1/<mount>/data/..., recording
// every call.
func startKVMock(t *testing.T, token string) (calls func() []kvCall, url string) {
	t.Helper()
	var mu sync.Mutex
	var log []kvCall
	stored := map[string]map[string]any{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Data map[string]any `json:"data"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		defer mu.Unlock()
		log = append(log, kvCall{method: r.Method, path: r.URL.Path, data: body.Data})
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet:
			d, ok := stored[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d}})
		case http.MethodPost:
			stored[r.URL.Path] = body.Data
			w.Write([]byte(`{"data":{"version":1}}`))
		}
	}))
	t.Cleanup(ts.Close)
	return func() []kvCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]kvCall(nil), log...)
	}, ts.URL
}

func TestPublishSaaSAPICredential_JobTopologyOnLiveBus(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	defer startTestBus(t)()
	farmerPKI := config.FarmerPKI

	// Farmer's boot: the SaaS API seed arrives from OpenBao via ESO as a
	// mounted file; farmer mints its own copy of the credential, the one
	// saasapi_user_integration_test.go already verifies on this bus.
	saasPub, saasSeed := useExternalSaaSAPISeed(t)
	farmerJWT, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("farmer's EnsureSaaSAPICredential: %v", err)
	}
	farmerClaims, err := jwt.DecodeUserClaims(farmerJWT)
	if err != nil {
		t.Fatal(err)
	}

	// The Job's pod: farmer's image, a fresh emptyDir PKI directory, and
	// the SYS Account seed mounted from the same Secret as farmer's.
	jobPKI := filepath.Join(t.TempDir(), "job-pki") + "/"
	config.FarmerPKI = jobPKI
	t.Setenv("IMAS_NATS_SYS_ACCOUNT_SEED_FILE", filepath.Join(farmerPKI, natsAuthSubdir, "sys-account.nk"))

	const kvPath = "platform/imas/saasapi-nats-user"
	calls, kvURL := startKVMock(t, "s.job-token")
	t.Setenv(openbaokv.EnvOpenBaoAddr, kvURL)
	t.Setenv(openbaokv.EnvOpenBaoKVMount, "imas-kv")
	t.Setenv(openbaokv.EnvOpenBaoAuthMethod, openbaokv.AuthMethodToken)
	t.Setenv(openbaokv.EnvOpenBaoToken, "s.job-token")
	t.Setenv(openbaokv.EnvOpenBaoCACert, "")
	client, err := openbaokv.NewClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := client.At(kvPath)
	if err != nil {
		t.Fatal(err)
	}

	res, err := PublishSaaSAPICredential(context.Background(), secret)
	if err != nil {
		t.Fatalf("PublishSaaSAPICredential (Job): %v", err)
	}
	if !res.Written || res.PublicKey != saasPub {
		t.Fatalf("result = %+v", res)
	}

	// The KV client received exactly one write, at the configured mount
	// and path, carrying the JWT and public key only.
	var posts []kvCall
	for _, c := range calls() {
		if c.method == http.MethodPost {
			posts = append(posts, c)
		}
	}
	if len(posts) != 1 {
		t.Fatalf("expected one KV write, got %+v", calls())
	}
	if want := "/v1/imas-kv/data/" + kvPath; posts[0].path != want {
		t.Fatalf("KV write went to %s, want %s", posts[0].path, want)
	}
	if len(posts[0].data) != 2 || posts[0].data["public_key"] != saasPub {
		t.Fatalf("KV payload = %v, want exactly jwt + public_key", posts[0].data)
	}
	publishedJWT, _ := posts[0].data["jwt"].(string)

	// Same credential as farmer's: same key, same SYS issuer, same
	// permissions and connection types (byte-identical isn't expected:
	// iat/jti differ between two mints).
	pc, err := jwt.DecodeUserClaims(publishedJWT)
	if err != nil {
		t.Fatalf("published JWT doesn't verify: %v", err)
	}
	if pc.Subject != farmerClaims.Subject || pc.Issuer != farmerClaims.Issuer ||
		!reflect.DeepEqual(pc.Permissions, farmerClaims.Permissions) ||
		!reflect.DeepEqual(pc.AllowedConnectionTypes, farmerClaims.AllowedConnectionTypes) {
		t.Fatalf("published credential differs from farmer's:\n job:    %+v\n farmer: %+v", pc, farmerClaims)
	}

	// The Job must never have generated a SaaS API or SYS key of its own.
	for _, f := range []string{"saasapi-user.nk", "sys-account.nk"} {
		if _, err := os.Stat(filepath.Join(jobPKI, natsAuthSubdir, f)); !os.IsNotExist(err) {
			t.Errorf("Job generated %s locally (stat err=%v)", f, err)
		}
	}

	// A re-run from a fresh pod is a no-op: a read, no write.
	config.FarmerPKI = filepath.Join(t.TempDir(), "job-pki-2") + "/"
	res, err = PublishSaaSAPICredential(context.Background(), secret)
	if err != nil || res.Written {
		t.Fatalf("re-run: res=%+v err=%v, want a no-op", res, err)
	}
	if n := len(calls()); n != 3 { // GET, POST, GET
		t.Fatalf("expected GET, POST, GET; got %+v", calls())
	}

	// What saasapi would receive from ESO works on the real bus, scoped
	// exactly like farmer's copy.
	config.FarmerPKI = farmerPKI
	farmer, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	defer farmer.Close()
	requests, _ := farmer.SubscribeSync("internal.tenant.provision")
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	var perrs permissionErrors
	saas, err := dialWithCreds(t, publishedJWT, saasSeed, nats.ErrorHandler(perrs.handler))
	if err != nil {
		t.Fatalf("expected the published credential to connect: %v", err)
	}
	defer saas.Close()
	if err := saas.Publish("internal.tenant.provision", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := saas.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := requests.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected farmer to receive the request sent with the published credential: %v", err)
	}
	for _, subj := range []string{"$SYS.REQ.SERVER.PING", "imas.api.health"} {
		_ = saas.Publish(subj, []byte(`{}`))
		_ = saas.Flush()
		if !perrs.waitFor(subj) {
			t.Errorf("expected publish to %q with the published credential to be denied", subj)
		}
	}
}
