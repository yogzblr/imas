package saasapicred

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/openbaokv"
)

const testToken = "s.publisher"

type recordedRequest struct {
	Method, Path string
	Body         map[string]any
}

// mockOpenBao is an in-memory KV v2 mount ("secret") that records every
// request it receives.
type mockOpenBao struct {
	mu      sync.Mutex
	reqs    []recordedRequest
	secrets map[string]map[string]any
}

func startMockOpenBao(t *testing.T) (*mockOpenBao, *httptest.Server) {
	t.Helper()
	m := &mockOpenBao{secrets: map[string]map[string]any{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := recordedRequest{Method: r.Method, Path: r.URL.Path}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &rec.Body)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.reqs = append(m.reqs, rec)
		if r.Header.Get("X-Vault-Token") != testToken {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		key, ok := strings.CutPrefix(r.URL.Path, "/v1/secret/data/")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			d, ok := m.secrets[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"errors":[]}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d}})
		case http.MethodPost:
			d, _ := rec.Body["data"].(map[string]any)
			m.secrets[key] = d
			w.Write([]byte(`{"data":{"version":1}}`))
		}
	}))
	t.Cleanup(ts.Close)
	return m, ts
}

func (m *mockOpenBao) requests() []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recordedRequest(nil), m.reqs...)
}

func (m *mockOpenBao) posts() []recordedRequest {
	var out []recordedRequest
	for _, r := range m.requests() {
		if r.Method == http.MethodPost {
			out = append(out, r)
		}
	}
	return out
}

type jobEnv struct {
	sysPub, saasPub string
	saasSeed        []byte
}

// setupJobEnv reproduces the reference Job's environment
// (deploy/farmer/saasapi-credential-publish-job.yaml): an empty PKI
// directory, the SYS Account and SaaS API seeds mounted as files from the
// same Secret farmer uses, and a token-authenticated OpenBao client.
func setupJobEnv(t *testing.T, openbaoURL string) jobEnv {
	t.Helper()
	config.FarmerPKI = filepath.Join(t.TempDir(), "pki") + "/"
	config.FarmerOrganization = "imas-test"

	seedDir := t.TempDir()
	sysKP, _ := nkeys.CreateAccount()
	sysSeed, _ := sysKP.Seed()
	sysPub, _ := sysKP.PublicKey()
	saasKP, _ := nkeys.CreateUser()
	saasSeed, _ := saasKP.Seed()
	saasPub, _ := saasKP.PublicKey()
	sysFile := filepath.Join(seedDir, "sys-account.nk")
	saasFile := filepath.Join(seedDir, "saasapi-user.nk")
	if err := os.WriteFile(sysFile, sysSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saasFile, saasSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"OPERATOR", "OPERATOR_SIGNING", "SYS_ACCOUNT", "SYS_USER", "TENANT", "TENANT_SIGNING", "SAASAPI_USER"} {
		t.Setenv("IMAS_NATS_"+name+"_SEED", "")
		t.Setenv("IMAS_NATS_"+name+"_SEED_FILE", "")
	}
	t.Setenv("IMAS_NATS_SYS_ACCOUNT_SEED_FILE", sysFile)
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED_FILE", saasFile)

	t.Setenv(openbaokv.EnvOpenBaoAddr, openbaoURL)
	t.Setenv(openbaokv.EnvOpenBaoKVMount, "")
	t.Setenv(openbaokv.EnvOpenBaoAuthMethod, openbaokv.AuthMethodToken)
	t.Setenv(openbaokv.EnvOpenBaoToken, testToken)
	t.Setenv(openbaokv.EnvOpenBaoCACert, "")
	t.Setenv(EnvKVPath, "")
	return jobEnv{sysPub: sysPub, saasPub: saasPub, saasSeed: saasSeed}
}

func TestRun_MintsAndPublishesToConfiguredPath(t *testing.T) {
	m, ts := startMockOpenBao(t)
	env := setupJobEnv(t, ts.URL)

	var stderr bytes.Buffer
	if code := Run([]string{"-kv-path", "imas/saasapi/nats-user"}, &stderr); code != 0 {
		t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
	}

	posts := m.posts()
	if len(posts) != 1 {
		t.Fatalf("expected exactly one write, got %d (%v)", len(posts), m.requests())
	}
	if posts[0].Path != "/v1/secret/data/imas/saasapi/nats-user" {
		t.Fatalf("wrote to %s, want the configured path", posts[0].Path)
	}
	data, _ := posts[0].Body["data"].(map[string]any)
	if len(data) != 2 || data["public_key"] != env.saasPub {
		t.Fatalf("published fields = %v, want exactly jwt + public_key", data)
	}
	for k, v := range data {
		if s, _ := v.(string); strings.Contains(s, string(env.saasSeed)) {
			t.Fatalf("field %q carries the SaaS API seed — only the JWT may be published", k)
		}
	}
	token, _ := data["jwt"].(string)
	uc, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatalf("published JWT doesn't verify: %v", err)
	}
	if uc.Subject != env.saasPub || uc.Issuer != env.sysPub || uc.IssuerAccount != "" {
		t.Fatalf("JWT sub=%s iss=%s issuer_account=%q, want the SaaS API key signed directly by the mounted SYS Account key",
			uc.Subject, uc.Issuer, uc.IssuerAccount)
	}
	if !reflect.DeepEqual(uc.Pub.Allow, jwt.StringList{"internal.tenant.provision", "internal.tenant.deprovision", "internal.sprout.action"}) ||
		!reflect.DeepEqual(uc.Sub.Allow, jwt.StringList{"internal.tenant.provisioned.*", "internal.tenant.deprovisioned.*", "_INBOX.saasapi.>"}) ||
		!reflect.DeepEqual(uc.AllowedConnectionTypes, jwt.StringList{jwt.ConnectionTypeStandard}) {
		t.Fatalf("unexpected permissions on the published JWT: %+v conn=%v", uc.Permissions, uc.AllowedConnectionTypes)
	}

	// Run again in a fresh pod (fresh emptyDir): nothing changed, so
	// nothing is written — the property the post-deploy hook relies on.
	config.FarmerPKI = filepath.Join(t.TempDir(), "pki") + "/"
	stderr.Reset()
	if code := Run([]string{"-kv-path", "imas/saasapi/nats-user"}, &stderr); code != 0 {
		t.Fatalf("second Run = %d, stderr: %s", code, stderr.String())
	}
	if n := len(m.posts()); n != 1 {
		t.Fatalf("expected the re-run to write nothing, got %d writes total", n)
	}
}

func TestRun_KVPathFromEnvAndFlagOverride(t *testing.T) {
	m, ts := startMockOpenBao(t)
	setupJobEnv(t, ts.URL)
	t.Setenv(EnvKVPath, "from/env")

	if code := Run(nil, io.Discard); code != 0 {
		t.Fatalf("Run (env path) = %d", code)
	}
	if code := Run([]string{"-kv-path", "from/flag"}, io.Discard); code != 0 {
		t.Fatalf("Run (flag path) = %d", code)
	}
	posts := m.posts()
	if len(posts) != 2 || posts[0].Path != "/v1/secret/data/from/env" || posts[1].Path != "/v1/secret/data/from/flag" {
		t.Fatalf("writes = %+v", posts)
	}
}

func TestRun_UsageErrors(t *testing.T) {
	m, ts := startMockOpenBao(t)
	setupJobEnv(t, ts.URL)

	for name, args := range map[string][]string{
		"no kv path":     nil,
		"bad kv path":    {"-kv-path", "a/../b"},
		"extra argument": {"-kv-path", "p", "extra"},
		"unknown flag":   {"-nope"},
	} {
		t.Run(name, func(t *testing.T) {
			if code := Run(args, io.Discard); code != 2 {
				t.Fatalf("Run = %d, want 2", code)
			}
		})
	}

	t.Setenv(openbaokv.EnvOpenBaoAddr, "")
	if code := Run([]string{"-kv-path", "p"}, io.Discard); code != 2 {
		t.Fatalf("Run without OpenBao configured = %d, want 2", code)
	}
	if n := len(m.requests()); n != 0 {
		t.Fatalf("expected no OpenBao requests on usage errors, got %d", n)
	}
}

// A Job missing its SYS Account seed mount must fail without minting
// under a random key or touching OpenBao.
func TestRun_MissingSYSSeedFailsClosed(t *testing.T) {
	m, ts := startMockOpenBao(t)
	setupJobEnv(t, ts.URL)
	t.Setenv("IMAS_NATS_SYS_ACCOUNT_SEED_FILE", "")

	var stderr bytes.Buffer
	if code := Run([]string{"-kv-path", "p"}, &stderr); code != 1 {
		t.Fatalf("Run = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "IMAS_NATS_SYS_ACCOUNT_SEED_FILE") {
		t.Errorf("expected the error to name the missing mount's env var, got: %s", stderr.String())
	}
	if n := len(m.requests()); n != 0 {
		t.Fatalf("expected no OpenBao requests, got %d", n)
	}
}

func TestRun_OpenBaoRejectsWrite(t *testing.T) {
	_, ts := startMockOpenBao(t)
	setupJobEnv(t, ts.URL)
	t.Setenv(openbaokv.EnvOpenBaoToken, "a-daemon-token-without-kv-write")

	var stderr bytes.Buffer
	if code := Run([]string{"-kv-path", "p"}, &stderr); code != 1 {
		t.Fatalf("Run = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "permission denied") {
		t.Errorf("expected OpenBao's error surfaced, got: %s", stderr.String())
	}
}
