package farmerchart

// The chart's P21 slice 1 OpenBao policies (files/openbao-policies:
// imas-farmer-natssign, imas-nats-sys-signer, imas-nats-bootstrap)
// against a real OpenBao, through internal/pki/natskeys's own client.
// Skipped unless IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN (a
// root or admin token) are set, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./deploy/helm/farmer -run TestOpenBao -v
//
// .github/workflows/natskeys-openbao-realserver.yml runs it. It mounts
// Transit at a fresh, random path, retargets the policy files at it, and
// removes the mount and the policies when done. It tests our policies
// against OpenBao's documented behaviour (design D7), in particular the
// owner decisions of 2026-10-11 (issue #197): Transit keys are created
// with "update" on an exact path (platform keys) or a single path
// segment (tenant keys), and rotate and config stay refused.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/openbao/openbaotest"
	"github.com/yogzblr/imas/internal/pki/natskeys"
)

type policyServer struct {
	t      *testing.T
	addr   string
	mount  string
	suffix string
	admin  *openbaotest.Admin
}

func newPolicyServer(t *testing.T) *policyServer {
	t.Helper()
	addr, token := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || token == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	b := make([]byte, 4)
	rand.Read(b)
	s := &policyServer{t: t, addr: strings.TrimRight(addr, "/"), suffix: hex.EncodeToString(b), admin: openbaotest.NewAdmin(t, addr, token)}
	s.mount = "chartpolicytest-" + s.suffix
	s.admin.Must(http.MethodPost, "sys/mounts/"+s.mount, map[string]any{"type": "transit"})
	t.Cleanup(func() { s.admin.Delete("sys/mounts/" + s.mount) })
	return s
}

// policy writes the chart's policy file, retargeted from transit/ to s's
// mount, and returns a token carrying it (plus "default", as a
// kubernetes-auth login without token_no_default_policy would get).
func (s *policyServer) policyToken(file string) string {
	s.t.Helper()
	hcl, err := os.ReadFile(filepath.Join(chartDir(s.t), "files", "openbao-policies", file))
	if err != nil {
		s.t.Fatal(err)
	}
	name := strings.TrimSuffix(file, ".hcl") + "-" + s.suffix
	s.admin.Must(http.MethodPut, "sys/policies/acl/"+name,
		map[string]any{"policy": strings.ReplaceAll(string(hcl), `"transit/`, `"`+s.mount+`/`)})
	s.t.Cleanup(func() { s.admin.Delete("sys/policies/acl/" + name) })
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(s.admin.Must(http.MethodPost, "auth/token/create",
		map[string]any{"policies": []string{name}, "ttl": "10m"}), &out); err != nil || out.Auth.ClientToken == "" {
		s.t.Fatalf("creating token: %v", err)
	}
	return out.Auth.ClientToken
}

// store is a natskeys store on s's mount authenticating with token ("":
// the admin token). It uses t.Setenv, so the tests are not parallel.
func (s *policyServer) store(token string) *natskeys.TransitKeyStore {
	s.t.Helper()
	if token == "" {
		token = os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	}
	p := natskeys.EnvPrefixSign
	s.t.Setenv(p+natskeys.EnvOpenBaoAddr, s.addr)
	s.t.Setenv(p+natskeys.EnvOpenBaoAuthMethod, openbao.AuthMethodToken)
	s.t.Setenv(p+natskeys.EnvOpenBaoToken, token)
	s.t.Setenv(p+natskeys.EnvOpenBaoTransitMount, s.mount)
	cfg, err := natskeys.ConfigFromEnv(p, os.Getenv)
	if err != nil {
		s.t.Fatal(err)
	}
	ks, err := natskeys.NewTransitKeyStore(cfg)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { ks.Close() })
	return ks
}

// refused checks that token gets a 403 for each call.
func (s *policyServer) refused(who, token string, calls []refusedCall) {
	s.t.Helper()
	for _, c := range calls {
		status, body := s.admin.Call(token, c.method, s.mount+c.path, c.body)
		if status != http.StatusForbidden {
			s.t.Errorf("%s %s %s: status %d (%s), want 403", who, c.method, c.path, status, strings.TrimSpace(string(body)))
		}
	}
}

type refusedCall struct {
	method, path string
	body         map[string]any
}

// keyState is a key's latest_version and deletion_allowed, read as admin.
func (s *policyServer) keyState(name string) (int, bool) {
	s.t.Helper()
	var out struct {
		Data struct {
			LatestVersion   int  `json:"latest_version"`
			DeletionAllowed bool `json:"deletion_allowed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(s.admin.Must(http.MethodGet, s.mount+"/keys/"+name, nil), &out); err != nil {
		s.t.Fatal(err)
	}
	return out.Data.LatestVersion, out.Data.DeletionAllowed
}

// mutations are the calls that would change an existing key: rotate
// (with and without a body) and config (deletion_allowed, which opens a
// hard delete; exportable).
func mutations(name string) []refusedCall {
	return []refusedCall{
		{http.MethodPost, "/keys/" + name + "/rotate", nil},
		{http.MethodPost, "/keys/" + name + "/rotate", map[string]any{"type": "ed25519"}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"deletion_allowed": true}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"exportable": true}},
	}
}

var platformKeys = map[string]natskeys.Prefix{
	natskeys.OperatorKey():        nkeys.PrefixByteOperator,
	natskeys.OperatorSigningKey(): nkeys.PrefixByteOperator,
	natskeys.SysAccountKey():      nkeys.PrefixByteAccount,
}

// TestOpenBaoBootstrapPolicy: the ephemeral imas-nats-bootstrap policy
// creates the three platform keys ("update" on exact paths, owner
// decision 1), signs with all three, and can neither rotate nor
// reconfigure them nor touch a tenant key.
func TestOpenBaoBootstrapPolicy(t *testing.T) {
	s := newPolicyServer(t)
	ctx := t.Context()
	token := s.policyToken("imas-nats-bootstrap.hcl")
	boot := s.store(token)
	for name, prefix := range platformKeys {
		kp, err := boot.EnsureKeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("bootstrap EnsureKeyPair(%s): %v", name, err)
		}
		if _, err := kp.Sign([]byte("boot")); err != nil {
			t.Errorf("bootstrap sign with %s: %v", name, err)
		}
		s.refused("bootstrap", token, mutations(name))
		if v, del := s.keyState(name); v != 1 || del {
			t.Errorf("%s after the refused calls: version %d, deletion_allowed %v", name, v, del)
		}
	}
	tenant := natskeys.TenantSigningKey("acme")
	if _, err := boot.EnsureKeyPair(ctx, tenant, nkeys.PrefixByteAccount); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("bootstrap creating %s: %v, want 403", tenant, err)
	}
	s.refused("bootstrap", token, []refusedCall{{http.MethodGet, "/keys/" + tenant, nil}})
}

// TestOpenBaoFarmerPolicy: imas-farmer-natssign (owner decision 2, in the
// single-segment form chosen on 2026-10-12) lets farmer create a tenant
// key, sign with it (tenant signing only) and soft-delete it, and refuses
// rotate and config on it; on the platform keys it reads, signs with
// operator-signing and SYS only, and changes nothing.
func TestOpenBaoFarmerPolicy(t *testing.T) {
	s := newPolicyServer(t)
	ctx := t.Context()
	admin := s.store("")
	for name, prefix := range platformKeys {
		if _, err := admin.EnsureKeyPair(ctx, name, prefix); err != nil {
			t.Fatalf("admin EnsureKeyPair(%s): %v", name, err)
		}
	}
	token := s.policyToken("imas-farmer-natssign.hcl")
	farmer := s.store(token)

	// Provisioning: farmer creates both tenant keys.
	tsignName, tacctName := natskeys.TenantSigningKey("acme"), natskeys.TenantAccountKey("acme")
	tsign, err := farmer.EnsureKeyPair(ctx, tsignName, nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatalf("farmer creating %s: %v", tsignName, err)
	}
	tacct, err := farmer.EnsureKeyPair(ctx, tacctName, nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatalf("farmer creating %s: %v", tacctName, err)
	}
	if _, err := tsign.Sign([]byte("user jwt")); err != nil {
		t.Errorf("farmer sign with %s: %v", tsignName, err)
	}
	if _, err := tacct.Sign([]byte("x")); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("farmer sign with %s: %v, want 403", tacctName, err)
	}

	// Rotate and config on a tenant key are refused, and change nothing.
	for _, name := range []string{tsignName, tacctName} {
		s.refused("farmer", token, mutations(name))
		if v, del := s.keyState(name); v != 1 || del {
			t.Errorf("%s after the refused calls: version %d, deletion_allowed %v", name, v, del)
		}
	}

	// Platform keys: read and sign (never the operator identity), no
	// change of any kind.
	for name, prefix := range platformKeys {
		kp, err := farmer.KeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("farmer KeyPair(%s): %v", name, err)
		}
		_, err = kp.Sign([]byte("farmer"))
		if name == natskeys.OperatorKey() {
			if !errors.Is(err, natskeys.ErrSignFailed) || openbao.StatusCode(err) != http.StatusForbidden {
				t.Errorf("farmer sign with %s: %v, want a 403", name, err)
			}
		} else if err != nil {
			t.Errorf("farmer sign with %s: %v", name, err)
		}
		s.refused("farmer", token, append(mutations(name),
			refusedCall{http.MethodPost, "/keys/" + name, map[string]any{"type": "ed25519"}},
			refusedCall{http.MethodDelete, "/keys/" + name + "/soft-delete", nil}))
	}

	// keys/+ lets farmer create a key of any name (the accepted cost, see
	// the policy file), but it signs with none outside nats-tsign-*, and
	// retires no other client's key. No key material out, no hard delete,
	// no restore.
	other, err := farmer.EnsureKeyPair(ctx, "other-key", nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatalf("farmer creating other-key: %v", err)
	}
	if _, err := other.Sign([]byte("x")); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("farmer sign with other-key: %v, want 403", err)
	}
	s.admin.Must(http.MethodPost, s.mount+"/keys/imas-gateway-jwt", map[string]any{"type": "ed25519"})
	s.refused("farmer", token, []refusedCall{
		{http.MethodGet, "/export/signing-key/" + tsignName, nil},
		{http.MethodGet, "/backup/" + tsignName, nil},
		{http.MethodDelete, "/keys/" + tsignName, nil},
		{http.MethodPost, "/keys/" + tsignName + "/soft-delete-restore", nil},
		{http.MethodPost, "/keys/" + tsignName + "/trim", map[string]any{"min_available_version": 1}},
		{http.MethodDelete, "/keys/imas-gateway-jwt/soft-delete", nil},
		{http.MethodPost, "/keys/imas-gateway-jwt/rotate", nil},
	})

	// Offboarding: soft delete, after which the key can't sign.
	if err := farmer.RetireKey(ctx, tsignName); err != nil {
		t.Errorf("farmer retiring %s: %v", tsignName, err)
	}
	if _, err := tsign.Sign([]byte("after retire")); err == nil {
		t.Error("retired tenant signing key still signs")
	}
}

// TestOpenBaoSysSignerPolicy: the publish Job's imas-nats-sys-signer
// signs with the SYS account key only and changes nothing.
func TestOpenBaoSysSignerPolicy(t *testing.T) {
	s := newPolicyServer(t)
	ctx := t.Context()
	admin := s.store("")
	for name, prefix := range platformKeys {
		if _, err := admin.EnsureKeyPair(ctx, name, prefix); err != nil {
			t.Fatalf("admin EnsureKeyPair(%s): %v", name, err)
		}
	}
	token := s.policyToken("imas-nats-sys-signer.hcl")
	signer := s.store(token)
	for name, prefix := range platformKeys {
		kp, err := signer.KeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("sys signer KeyPair(%s): %v", name, err)
		}
		_, err = kp.Sign([]byte("saasapi user"))
		if name == natskeys.SysAccountKey() {
			if err != nil {
				t.Errorf("sys signer sign with %s: %v", name, err)
			}
		} else if openbao.StatusCode(err) != http.StatusForbidden {
			t.Errorf("sys signer sign with %s: %v, want 403", name, err)
		}
		s.refused("sys signer", token, mutations(name))
	}
	if _, err := signer.EnsureKeyPair(ctx, natskeys.TenantSigningKey("acme"), nkeys.PrefixByteAccount); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("sys signer creating a tenant key: %v, want 403", err)
	}
}
