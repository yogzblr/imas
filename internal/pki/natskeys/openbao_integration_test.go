package natskeys

// Tests against a real OpenBao (brief §6.3), skipped unless
// IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN (a root or admin
// token) are set, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./internal/pki/natskeys -run TestOpenBao -v
//
// .github/workflows/natskeys-openbao-realserver.yml runs them on every
// change here. Each test mounts Transit at a fresh, random path and
// removes the mount and its policies when done. They test our client and
// our policies against OpenBao's documented behaviour, not OpenBao
// (design D7), and record the brief's UNVERIFIED items.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/openbao/openbaotest"
)

const (
	envTestOpenBaoAddr  = "IMAS_TEST_OPENBAO_ADDR"
	envTestOpenBaoToken = "IMAS_TEST_OPENBAO_TOKEN"
)

// The policies of brief §3.2, for the default "transit/" mount. The
// chart's copies (deploy/helm/farmer/files/openbao-policies/, P21 slice
// 1 PR6) must keep to these; once they exist this test should load them
// instead.
const (
	policyFarmerNatssign = `
path "transit/keys/nats-operator"         { capabilities = ["read"] }
path "transit/keys/nats-operator-signing" { capabilities = ["read"] }
path "transit/keys/nats-sys-account"      { capabilities = ["read"] }
path "transit/sign/nats-operator-signing" { capabilities = ["update"] }
path "transit/sign/nats-sys-account"      { capabilities = ["update"] }
path "transit/keys/nats-tsign-*"          { capabilities = ["create", "read", "delete"] }
path "transit/keys/nats-tacct-*"          { capabilities = ["create", "read", "delete"] }
path "transit/sign/nats-tsign-*"          { capabilities = ["update"] }
`
	policyNatsSysSigner = `
path "transit/keys/nats-operator"         { capabilities = ["read"] }
path "transit/keys/nats-operator-signing" { capabilities = ["read"] }
path "transit/keys/nats-sys-account"      { capabilities = ["read"] }
path "transit/sign/nats-sys-account"      { capabilities = ["update"] }
`
	policyNatsBootstrap = `
path "transit/keys/nats-operator"         { capabilities = ["create", "read"] }
path "transit/keys/nats-operator-signing" { capabilities = ["create", "read"] }
path "transit/keys/nats-sys-account"      { capabilities = ["create", "read"] }
path "transit/sign/nats-operator"         { capabilities = ["update"] }
path "transit/sign/nats-operator-signing" { capabilities = ["update"] }
path "transit/sign/nats-sys-account"      { capabilities = ["update"] }
path "auth/token/revoke-self"             { capabilities = ["update"] }
path "auth/token/lookup-self"             { capabilities = ["read"] }
`
)

type realServer struct {
	t      *testing.T
	addr   string
	mount  string
	suffix string
	admin  *openbaotest.Admin
}

// newRealServer skips unless a real OpenBao is configured, and mounts
// Transit at a fresh path removed when t ends.
func newRealServer(t *testing.T) *realServer {
	t.Helper()
	addr, token := os.Getenv(envTestOpenBaoAddr), os.Getenv(envTestOpenBaoToken)
	if addr == "" || token == "" {
		t.Skipf("%s and %s not set; this test needs a real OpenBao", envTestOpenBaoAddr, envTestOpenBaoToken)
	}
	b := make([]byte, 4)
	rand.Read(b)
	r := &realServer{t: t, addr: strings.TrimRight(addr, "/"), suffix: hex.EncodeToString(b), admin: openbaotest.NewAdmin(t, addr, token)}
	r.mount = "natskeystest-" + r.suffix
	r.admin.Must(http.MethodPost, "sys/mounts/"+r.mount, map[string]any{"type": "transit"})
	t.Cleanup(func() { r.admin.Delete("sys/mounts/" + r.mount) })
	return r
}

// policy writes hcl, retargeted at r's mount, and returns its name.
func (r *realServer) policy(name, hcl string) string {
	r.t.Helper()
	name += "-" + r.suffix
	r.admin.Must(http.MethodPut, "sys/policies/acl/"+name,
		map[string]any{"policy": strings.ReplaceAll(hcl, `"transit/`, `"`+r.mount+`/`)})
	r.t.Cleanup(func() { r.admin.Delete("sys/policies/acl/" + name) })
	return name
}

// tokenFor creates a token carrying policy (plus "default", as a
// kubernetes-auth login gets).
func (r *realServer) tokenFor(policy string) string {
	r.t.Helper()
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(r.admin.Must(http.MethodPost, "auth/token/create",
		map[string]any{"policies": []string{policy}, "ttl": "10m"}), &out); err != nil || out.Auth.ClientToken == "" {
		r.t.Fatalf("creating token: %v", err)
	}
	return out.Auth.ClientToken
}

// store builds a TransitKeyStore on r's mount authenticating with token
// ("" is the admin token). It uses t.Setenv, so tests are not parallel.
func (r *realServer) store(token string) *TransitKeyStore {
	r.t.Helper()
	if token == "" {
		token = os.Getenv(envTestOpenBaoToken)
	}
	r.t.Setenv(EnvPrefixSign+EnvOpenBaoAddr, r.addr)
	r.t.Setenv(EnvPrefixSign+EnvOpenBaoAuthMethod, openbao.AuthMethodToken)
	r.t.Setenv(EnvPrefixSign+EnvOpenBaoToken, token)
	r.t.Setenv(EnvPrefixSign+EnvOpenBaoTransitMount, r.mount)
	cfg, err := ConfigFromEnv(EnvPrefixSign, os.Getenv)
	if err != nil {
		r.t.Fatal(err)
	}
	s, err := NewTransitKeyStore(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { s.Close() })
	return s
}

// TestOpenBaoSlashKeyNames records brief UNVERIFIED item 1: whether
// Transit accepts "/" in a key name. It never fails: names.go uses flat
// names either way, and switching is a separate decision.
func TestOpenBaoSlashKeyNames(t *testing.T) {
	r := newRealServer(t)
	status, body := r.admin.Call("", http.MethodPost, r.mount+"/keys/nats/operator", map[string]any{"type": "ed25519"})
	if status/100 != 2 {
		t.Skipf("UNVERIFIED item 1 answered: Transit refuses a key name with a slash (status %d: %s); flat names stay", status, body)
	}
	readStatus, _ := r.admin.Call("", http.MethodGet, r.mount+"/keys/nats/operator", nil)
	signStatus, _ := r.admin.Call("", http.MethodPost, r.mount+"/sign/nats/operator", map[string]any{"input": "aGk="})
	t.Logf("UNVERIFIED item 1 answered: Transit accepts a key name with a slash (create %d, read %d, sign %d)", status, readStatus, signStatus)
}

// TestOpenBaoSignerWithNatsServer is design test T1 against a real
// OpenBao: keys created by EnsureKeyPair, the trust chain signed through
// Transit, accepted by nats-server. It also checks a real batch sign
// (UNVERIFIED item 4: versions come from the "vault:vN:" prefix) and
// version pinning across a real rotation.
func TestOpenBaoSignerWithNatsServer(t *testing.T) {
	r := newRealServer(t)
	s := r.store("")
	checkTrustChainWithNatsServer(t, s, "realserver")

	// A real batch request, sent directly so it is a batch for certain.
	kp, err := s.KeyPair(t.Context(), TenantSigningKey("realserver"), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	tkp := kp.(*transitKeyPair)
	jobs := make([]*signJob, 3)
	for i := range jobs {
		jobs[i] = &signJob{ctx: t.Context(), key: groupKey{tkp.name, tkp.version, tkp.pubStr}, pub: tkp.pub,
			input: fmt.Appendf(nil, "batch item %d", i), done: make(chan signResult, 1)}
	}
	s.signGroup(t.Context(), jobs[0].key, jobs)
	for i, j := range jobs {
		if res := <-j.done; res.err != nil {
			t.Errorf("batch item %d: %v", i, res.err)
		}
	}

	// Pinning: rotate for real; the loaded pair keeps signing with v1.
	r.admin.Must(http.MethodPost, r.mount+"/keys/"+TenantSigningKey("realserver")+"/rotate", nil)
	sig, err := kp.Sign([]byte("after rotate"))
	if err != nil {
		t.Fatalf("pinned pair after rotation: %v", err)
	}
	if !ed25519.Verify(tkp.pub, []byte("after rotate"), sig) {
		t.Fatal("pinned pair's signature does not verify under its v1 key")
	}
	kp2, err := s.KeyPair(t.Context(), TenantSigningKey("realserver"), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	if kp2.(*transitKeyPair).version != 2 {
		t.Errorf("reload after rotation pinned version %d, want 2", kp2.(*transitKeyPair).version)
	}
}

// TestOpenBaoPolicyEnforcement drives the brief's policies through this
// package's own client and checks that OpenBao refuses what they leave
// out, and that the `*` suffix globs match the tenant keys and their
// soft-delete sub-path (UNVERIFIED item 2 and the §3.2 note).
//
// Key creation is recorded, not asserted: on OpenBao 2.7.1 a POST to
// keys/<name> needs "update", not "create", and "update" on a
// keys/nats-tsign-* glob also grants keys/<name>/rotate and /config.
// The brief's policies (create only) therefore cannot create keys; the
// fix belongs to the chart's policies (PR6). Here the admin token
// creates the keys the policies would.
func TestOpenBaoPolicyEnforcement(t *testing.T) {
	r := newRealServer(t)
	ctx := t.Context()
	farmerPolicy := r.policy("imas-farmer-natssign", policyFarmerNatssign)
	sysSignerPolicy := r.policy("imas-nats-sys-signer", policyNatsSysSigner)
	bootPolicy := r.policy("imas-nats-bootstrap", policyNatsBootstrap)
	bootToken := r.tokenFor(bootPolicy)
	farmerToken := r.tokenFor(farmerPolicy)

	// Record what creation needs (see the doc comment).
	for _, c := range []struct{ who, token, key string }{
		{"bootstrap", bootToken, OperatorKey()},
		{"farmer", farmerToken, TenantSigningKey("probe")},
	} {
		status, body := r.admin.Call(c.token, http.MethodPost, r.mount+"/keys/"+c.key, map[string]any{"type": "ed25519"})
		t.Logf("RECORDED: %s policy (create, no update) creating %s: status %d %s", c.who, c.key, status, strings.TrimSpace(string(body)))
	}
	probe := r.policy("probe-update-glob", `path "transit/keys/nats-tsign-*" { capabilities = ["update", "read"] }`)
	probeToken := r.tokenFor(probe)
	createStatus, _ := r.admin.Call(probeToken, http.MethodPost, r.mount+"/keys/"+TenantSigningKey("probe2"), map[string]any{"type": "ed25519"})
	rotateStatus, _ := r.admin.Call(probeToken, http.MethodPost, r.mount+"/keys/"+TenantSigningKey("probe2")+"/rotate", nil)
	configStatus, _ := r.admin.Call(probeToken, http.MethodPost, r.mount+"/keys/"+TenantSigningKey("probe2")+"/config", map[string]any{"deletion_allowed": false})
	t.Logf("RECORDED: update on keys/nats-tsign-*: create %d, rotate %d, config %d", createStatus, rotateStatus, configStatus)

	admin := r.store("")
	platform := map[string]Prefix{
		OperatorKey():        nkeys.PrefixByteOperator,
		OperatorSigningKey(): nkeys.PrefixByteOperator,
		SysAccountKey():      nkeys.PrefixByteAccount,
	}
	for name, prefix := range platform {
		if _, err := admin.EnsureKeyPair(ctx, name, prefix); err != nil {
			t.Fatalf("admin EnsureKeyPair(%s): %v", name, err)
		}
	}
	for _, name := range []string{TenantSigningKey("acme"), TenantAccountKey("acme")} {
		if _, err := admin.EnsureKeyPair(ctx, name, nkeys.PrefixByteAccount); err != nil {
			t.Fatalf("admin EnsureKeyPair(%s): %v", name, err)
		}
	}

	// The bootstrap token may sign with all three platform keys, the
	// operator identity included, and touches no tenant key.
	boot := r.store(bootToken)
	for name, prefix := range platform {
		kp, err := boot.KeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("bootstrap KeyPair(%s): %v", name, err)
		}
		if _, err := kp.Sign([]byte("boot")); err != nil {
			t.Errorf("bootstrap sign with %s: %v", name, err)
		}
	}
	if _, err := boot.KeyPair(ctx, TenantSigningKey("acme"), nkeys.PrefixByteAccount); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("bootstrap reading a tenant key: %v, want 403", err)
	}

	// The farmer: reads the platform keys, signs with operator-signing
	// and SYS but never the operator identity.
	farmer := r.store(farmerToken)
	for name, prefix := range platform {
		kp, err := farmer.KeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("farmer KeyPair(%s): %v", name, err)
		}
		_, err = kp.Sign([]byte("farmer"))
		if name == OperatorKey() {
			if !errors.Is(err, ErrSignFailed) || openbao.StatusCode(err) != http.StatusForbidden {
				t.Errorf("farmer sign with %s: %v, want a 403", name, err)
			}
		} else if err != nil {
			t.Errorf("farmer sign with %s: %v", name, err)
		}
	}
	// Tenant keys: tsign signs, tacct never.
	tsign, err := farmer.KeyPair(ctx, TenantSigningKey("acme"), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatalf("farmer reading tenant signing key: %v", err)
	}
	if _, err := tsign.Sign([]byte("user jwt")); err != nil {
		t.Errorf("farmer sign with tenant signing key: %v", err)
	}
	tacct, err := farmer.KeyPair(ctx, TenantAccountKey("acme"), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatalf("farmer reading tenant account key: %v", err)
	}
	if _, err := tacct.Sign([]byte("x")); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("farmer sign with tenant account key: %v, want 403", err)
	}
	if _, err := farmer.EnsureKeyPair(ctx, "other-key", nkeys.PrefixByteAccount); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("farmer creating other-key: %v, want 403", err)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/keys/" + TenantSigningKey("acme") + "/rotate"},
		{http.MethodPost, "/keys/" + TenantSigningKey("acme") + "/config"},
		{http.MethodPost, "/keys/" + OperatorSigningKey() + "/rotate"},
		{http.MethodPost, "/keys/" + OperatorSigningKey() + "/config"},
		{http.MethodPost, "/keys/" + OperatorSigningKey()},
		{http.MethodDelete, "/keys/" + OperatorSigningKey()},
		{http.MethodDelete, "/keys/" + OperatorSigningKey() + "/soft-delete"},
		{http.MethodGet, "/export/signing-key/" + TenantSigningKey("acme")},
		{http.MethodGet, "/backup/" + TenantSigningKey("acme")},
		{http.MethodPost, "/sign/" + OperatorKey()},
		{http.MethodPost, "/sign/" + TenantAccountKey("acme")},
	} {
		if status, body := r.admin.Call(farmerToken, c.method, r.mount+c.path, map[string]any{"input": "aGk="}); status != http.StatusForbidden {
			t.Errorf("farmer %s %s: status %d (%s), want 403", c.method, c.path, status, body)
		}
	}
	// Offboarding: the farmer may soft-delete tenant keys (the glob
	// covers the soft-delete sub-path), after which they can't sign.
	if err := farmer.RetireKey(ctx, TenantSigningKey("acme")); err != nil {
		t.Errorf("farmer retiring tenant signing key: %v", err)
	}
	if _, err := tsign.Sign([]byte("after retire")); err == nil {
		t.Error("retired tenant signing key still signs")
	}

	// The publish Job's signer: SYS only.
	sysSigner := r.store(r.tokenFor(sysSignerPolicy))
	sys, err := sysSigner.KeyPair(ctx, SysAccountKey(), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sys.Sign([]byte("saasapi user")); err != nil {
		t.Errorf("sys signer sign with SYS: %v", err)
	}
	opsign, err := sysSigner.KeyPair(ctx, OperatorSigningKey(), nkeys.PrefixByteOperator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opsign.Sign([]byte("x")); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("sys signer sign with operator-signing: %v, want 403", err)
	}

	// Cleanup as the bootstrap Job does it: once the policy is deleted,
	// the token that held it can no longer sign as the operator.
	op, err := boot.KeyPair(ctx, OperatorKey(), nkeys.PrefixByteOperator)
	if err != nil {
		t.Fatal(err)
	}
	r.admin.Must(http.MethodDelete, "sys/policies/acl/"+bootPolicy, nil)
	if _, err := op.Sign([]byte("after cleanup")); openbao.StatusCode(err) != http.StatusForbidden {
		t.Errorf("bootstrap token sign with the operator key after policy delete: %v, want 403", err)
	}
}

// TestOpenBaoSoftDeleteBlocksSigning checks RetireKey against a real
// server: soft-delete uses DELETE (brief UNVERIFIED note in §3.2), a
// retired key refuses to sign and reads as retired, a second retire
// succeeds.
func TestOpenBaoSoftDeleteBlocksSigning(t *testing.T) {
	r := newRealServer(t)
	s := r.store("")
	name := TenantSigningKey("retire")
	kp, err := s.EnsureKeyPair(t.Context(), name, nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kp.Sign([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireKey(t.Context(), name); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	if _, err := kp.Sign([]byte("after")); !errors.Is(err, ErrSignFailed) {
		t.Errorf("sign after retire: %v, want ErrSignFailed", err)
	}
	if _, err := s.KeyPair(t.Context(), name, nkeys.PrefixByteAccount); !errors.Is(err, ErrKeyRetired) {
		t.Errorf("KeyPair after retire: %v, want ErrKeyRetired", err)
	}
	if err := s.RetireKey(t.Context(), name); err != nil {
		t.Errorf("second RetireKey: %v", err)
	}
	if err := s.RetireKey(t.Context(), TenantSigningKey("never-existed")); err != nil {
		t.Errorf("RetireKey of a missing key: %v", err)
	}
}
