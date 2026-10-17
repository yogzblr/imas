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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/openbao/openbaotest"
	"github.com/yogzblr/imas/internal/pki"
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
	s.t.Setenv(p+natskeys.EnvOpenBaoAllowInsecure, "true") // CI's dev server is plain http
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
// hard delete, as a bool and as the string natskeys sends; exportable).
func mutations(name string) []refusedCall {
	return append(tenantKeyMutations(name),
		refusedCall{http.MethodPost, "/keys/" + name + "/config", map[string]any{"deletion_allowed": "true"}})
}

// tenantKeyMutations are the mutations farmer is refused even on a tenant
// key, whose deletion_allowed it may set to the string "true" (S6): rotate,
// and config with any other parameter or value.
func tenantKeyMutations(name string) []refusedCall {
	return []refusedCall{
		{http.MethodPost, "/keys/" + name + "/rotate", nil},
		{http.MethodPost, "/keys/" + name + "/rotate", map[string]any{"type": "ed25519"}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"deletion_allowed": true}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"deletion_allowed": "false"}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"exportable": true}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"deletion_allowed": "true", "exportable": true}},
		{http.MethodPost, "/keys/" + name + "/config", map[string]any{"auto_rotate_period": "1h"}},
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
// key, sign with it (tenant signing only), soft-delete it and, at a purge
// (S6), destroy it; it refuses rotate on it and every config but
// deletion_allowed="true"; on the platform keys and the gateway key it
// reads, signs with operator-signing and SYS only, and changes nothing.
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

	// Rotate, and config other than deletion_allowed="true", on a tenant
	// key are refused, and change nothing.
	for _, name := range []string{tsignName, tacctName} {
		s.refused("farmer", token, tenantKeyMutations(name))
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
			refusedCall{http.MethodDelete, "/keys/" + name + "/soft-delete", nil},
			refusedCall{http.MethodDelete, "/keys/" + name, nil}))
		if v, del := s.keyState(name); v != 1 || del {
			t.Errorf("%s after the refused calls: version %d, deletion_allowed %v", name, v, del)
		}
	}

	// keys/+ lets farmer create a key of any name (the accepted cost, see
	// the policy file), but it signs with none outside nats-tsign-*. No
	// key material out, no restore, and the gateway key can be neither
	// retired, reconfigured nor deleted.
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
		{http.MethodPost, "/keys/" + tsignName + "/soft-delete-restore", nil},
		{http.MethodPost, "/keys/" + tsignName + "/trim", map[string]any{"min_available_version": 1}},
		{http.MethodDelete, "/keys/imas-gateway-jwt/soft-delete", nil},
		{http.MethodPost, "/keys/imas-gateway-jwt/rotate", nil},
		{http.MethodPost, "/keys/imas-gateway-jwt/config", map[string]any{"deletion_allowed": "true"}},
		{http.MethodDelete, "/keys/imas-gateway-jwt", nil},
	})
	if v, del := s.keyState("imas-gateway-jwt"); v != 1 || del {
		t.Errorf("imas-gateway-jwt after the refused calls: version %d, deletion_allowed %v", v, del)
	}

	// Offboarding: soft delete, after which the key can't sign.
	if err := farmer.RetireKey(ctx, tsignName); err != nil {
		t.Errorf("farmer retiring %s: %v", tsignName, err)
	}
	if _, err := tsign.Sign([]byte("after retire")); err == nil {
		t.Error("retired tenant signing key still signs")
	}

	// Purge (S6): farmer destroys both tenant keys, retired or not, the
	// way natskeys does it (config deletion_allowed="true", then delete).
	for _, name := range []string{tsignName, tacctName} {
		if destroyed, err := farmer.DestroyKey(ctx, name); err != nil || !destroyed {
			t.Fatalf("farmer destroying %s: %v, %v", name, destroyed, err)
		}
		if status, _ := s.admin.Call("", http.MethodGet, s.mount+"/keys/"+name, nil); status != http.StatusNotFound {
			t.Errorf("%s after farmer's DestroyKey: read status %d, want 404", name, status)
		}
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

// farmerKeyOps are the Transit operations on one key name, each as the
// path and capability OpenBao checks for it.
var farmerKeyOps = []struct {
	op, path, capability string
}{
	{"create", "keys/%s", "update"},
	{"read", "keys/%s", "read"},
	{"sign", "sign/%s", "update"},
	{"soft-delete", "keys/%s/soft-delete", "delete"},
	{"soft-delete-restore", "keys/%s/soft-delete-restore", "update"},
	{"rotate", "keys/%s/rotate", "update"},
	{"config", "keys/%s/config", "update"},
	{"trim", "keys/%s/trim", "update"},
	{"hard-delete", "keys/%s", "delete"},
	{"export", "export/signing-key/%s", "read"},
	{"backup", "backup/%s", "read"},
	{"restore", "restore/%s", "update"},
}

// TestOpenBaoFarmerPolicyKeySet lists what a farmer token may do with each
// kind of key name on the Transit mount, as OpenBao's own ACL evaluation
// answers it (sys/capabilities-self), and asserts exactly the set the
// merged imas-farmer-natssign policy allows (owner decision 2, #215; the
// single-segment form of 2026-10-12). Any change to the policy that adds or
// removes an operation for any of these names fails it. It then shows the
// accepted cost on a real key: farmer soft-deletes a key another client
// keeps on the mount (deploy/helm/farmer/README.md, security review P3).
func TestOpenBaoFarmerPolicyKeySet(t *testing.T) {
	s := newPolicyServer(t)
	token := s.policyToken("imas-farmer-natssign.hcl")

	tsign, tacct := natskeys.TenantSigningKey("acme"), natskeys.TenantAccountKey("acme")
	want := map[string][]string{
		// The platform keys: read; sign with operator-signing and SYS
		// only (never the operator identity); exact denies on soft delete.
		natskeys.OperatorKey():        {"read"},
		natskeys.OperatorSigningKey(): {"read", "sign"},
		natskeys.SysAccountKey():      {"read", "sign"},
		// The gateway key: its exact rule allows create (on an existing
		// key it changes nothing, checked below) and read; exact denies
		// keep it from being soft-deleted or reconfigured, and with no
		// delete it can't be destroyed.
		"imas-gateway-jwt": {"create", "read"},
		// Tenant keys: created at provisioning, soft-deleted at
		// offboarding, destroyed at a purge (config is deletion_allowed
		// only: allowed_parameters, which capabilities-self doesn't show;
		// TestOpenBaoFarmerPolicy checks it); only the signing key signs.
		tsign: {"create", "read", "sign", "soft-delete", "config", "hard-delete"},
		tacct: {"create", "read", "soft-delete", "config", "hard-delete"},
		// Any other name (the accepted cost): create, read, soft delete
		// and destroy, never sign.
		"other-client-key": {"create", "read", "soft-delete", "config", "hard-delete"},
		"nats-tsignx":      {"create", "read", "soft-delete", "config", "hard-delete"},
	}
	// Never, for any name: rotate, trim, export, backup, restore,
	// soft-delete-restore.
	for name, ops := range want {
		paths := make([]string, 0, len(farmerKeyOps))
		for _, o := range farmerKeyOps {
			paths = append(paths, s.mount+"/"+fmt.Sprintf(o.path, name))
		}
		status, body := s.admin.Call(token, http.MethodPost, "sys/capabilities-self", map[string]any{"paths": paths})
		if status != http.StatusOK {
			t.Fatalf("capabilities-self: %d %s", status, body)
		}
		var caps map[string]any
		if err := json.Unmarshal(body, &caps); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, o := range farmerKeyOps {
			p := s.mount + "/" + fmt.Sprintf(o.path, name)
			list, _ := caps[p].([]any)
			for _, c := range list {
				if c == o.capability || c == "root" {
					got = append(got, o.op)
					break
				}
			}
		}
		if strings.Join(got, ",") != strings.Join(ops, ",") {
			t.Errorf("farmer on %q may %v, want exactly %v", name, got, ops)
		}
	}

	// On real keys: create on the existing gateway key changes nothing,
	// and the gateway key is not soft-deleted.
	s.admin.Must(http.MethodPost, s.mount+"/keys/imas-gateway-jwt", map[string]any{"type": "ed25519"})
	if status, body := s.admin.Call(token, http.MethodPost, s.mount+"/keys/imas-gateway-jwt", map[string]any{"type": "ed25519"}); status/100 != 2 {
		t.Fatalf("farmer create on the existing imas-gateway-jwt: %d %s, want 2xx and no change", status, body)
	}
	if v, del := s.keyState("imas-gateway-jwt"); v != 1 || del {
		t.Errorf("imas-gateway-jwt after farmer's create: version %d, deletion_allowed %v", v, del)
	}
	s.refused("farmer", token, []refusedCall{{http.MethodDelete, "/keys/imas-gateway-jwt/soft-delete", nil}})

	// The accepted cost: a key another client keeps here, with no exact
	// deny, is soft-deleted by a farmer token (and can then no longer
	// sign for that client). Restoring it needs a token other than
	// farmer's.
	s.admin.Must(http.MethodPost, s.mount+"/keys/other-client-key", map[string]any{"type": "ed25519"})
	if status, body := s.admin.Call(token, http.MethodDelete, s.mount+"/keys/other-client-key/soft-delete", nil); status/100 != 2 {
		t.Fatalf("farmer soft-deleting another client's key: %d %s; the accepted cost in the README no longer holds, update it", status, body)
	}
	if status, _ := s.admin.Call("", http.MethodPost, s.mount+"/sign/other-client-key", map[string]any{"input": "eA=="}); status/100 == 2 {
		t.Error("a soft-deleted key still signs")
	}
	s.refused("farmer", token, []refusedCall{{http.MethodPost, "/keys/other-client-key/soft-delete-restore", nil}})

	// And, since S6, destroys it for good.
	if status, body := s.admin.Call(token, http.MethodPost, s.mount+"/keys/other-client-key/config", map[string]any{"deletion_allowed": "true"}); status/100 != 2 {
		t.Fatalf("farmer allowing deletion of another client's key: %d %s; the accepted cost in the README no longer holds, update it", status, body)
	}
	if status, body := s.admin.Call(token, http.MethodDelete, s.mount+"/keys/other-client-key", nil); status/100 != 2 {
		t.Fatalf("farmer destroying another client's key: %d %s; the accepted cost in the README no longer holds, update it", status, body)
	}
}

// TestOpenBaoFarmerTenantBoxPolicy: the rendered imas-farmer-tenantbox
// policy, on a fresh KV v2 mount, lets farmer create a tenant's keypair
// and, at a purge (S6), delete it whole through internal/pki's own client
// (every version and the metadata); it refuses a metadata read or list,
// a soft delete or destroy of single versions, and any delete outside
// <kvPath>/tenants/.
func TestOpenBaoFarmerTenantBoxPolicy(t *testing.T) {
	addr, rootToken := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || rootToken == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	b := make([]byte, 4)
	rand.Read(b)
	suffix := hex.EncodeToString(b)
	mount := "tenantboxpolicytest-" + suffix
	admin := openbaotest.NewAdmin(t, addr, rootToken)
	admin.Must(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	t.Cleanup(func() { admin.Delete("sys/mounts/" + mount) })

	cm := find(t, mustRender(t), "ConfigMap", "t-farmer-openbao-policies")
	hcl := strings.ReplaceAll(get(cm, "data", "imas-farmer-tenantbox.hcl").(string), `"secret/`, `"`+mount+`/`)
	name := "imas-farmer-tenantbox-" + suffix
	admin.Must(http.MethodPut, "sys/policies/acl/"+name, map[string]any{"policy": hcl})
	t.Cleanup(func() { admin.Delete("sys/policies/acl/" + name) })
	var tok struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(admin.Must(http.MethodPost, "auth/token/create",
		map[string]any{"policies": []string{name}, "ttl": "10m"}), &tok); err != nil || tok.Auth.ClientToken == "" {
		t.Fatalf("creating token: %v", err)
	}
	token := tok.Auth.ClientToken

	base := "imas/tenant-x25519"
	t.Setenv(pki.EnvTenantBoxOpenBaoAddr, addr)
	t.Setenv(pki.EnvTenantBoxOpenBaoAllowInsecure, "true") // CI's dev server is plain http
	t.Setenv(pki.EnvTenantBoxOpenBaoKVMount, mount)
	t.Setenv(pki.EnvTenantBoxOpenBaoKVPath, base)
	t.Setenv(pki.EnvTenantBoxOpenBaoAuthMethod, pki.TenantBoxAuthMethodToken)
	t.Setenv(pki.EnvTenantBoxOpenBaoToken, token)
	for _, tenant := range []string{"acme", "acme2"} {
		pki.InvalidateTenantBoxKeys(tenant)
		t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
		if _, err := pki.GetTenantX25519PublicKey(tenant); err != nil {
			t.Fatalf("farmer creating %s's keypair: %v", tenant, err)
		}
	}
	// A second version, as a rotation leaves it.
	admin.Must(http.MethodPost, mount+"/data/"+base+"/tenants/acme", map[string]any{"data": map[string]string{"pub": "x", "priv": "y"}})
	admin.Must(http.MethodPost, mount+"/data/"+base+"/platform", map[string]any{"data": map[string]string{"pub": "p", "priv": "q"}})

	for _, c := range []refusedCall{
		{http.MethodGet, "/metadata/" + base + "/tenants/acme", nil},
		{"LIST", "/metadata/" + base + "/tenants", nil},
		{http.MethodDelete, "/data/" + base + "/tenants/acme", nil},
		{http.MethodPost, "/delete/" + base + "/tenants/acme", map[string]any{"versions": []int{1}}},
		{http.MethodPost, "/destroy/" + base + "/tenants/acme", map[string]any{"versions": []int{1}}},
		{http.MethodDelete, "/metadata/" + base + "/platform", nil},
		{http.MethodDelete, "/metadata/" + base + "/tenants/acme/deeper", nil},
		{http.MethodDelete, "/metadata/" + base, nil},
	} {
		if status, body := admin.Call(token, c.method, mount+c.path, c.body); status != http.StatusForbidden {
			t.Errorf("farmer %s %s: status %d (%s), want 403", c.method, c.path, status, strings.TrimSpace(string(body)))
		}
	}

	if n, err := pki.PurgeTenantBoxKeys(t.Context(), "acme"); err != nil || n != 1 {
		t.Fatalf("farmer purging acme's keypair: %d, %v", n, err)
	}
	if status, _ := admin.Call("", http.MethodGet, mount+"/metadata/"+base+"/tenants/acme", nil); status != http.StatusNotFound {
		t.Errorf("acme's metadata after the purge: status %d, want 404", status)
	}
	for _, p := range []string{"/tenants/acme2", "/platform"} {
		if status, _ := admin.Call("", http.MethodGet, mount+"/data/"+base+p, nil); status != http.StatusOK {
			t.Errorf("%s after acme's purge: status %d, want 200", p, status)
		}
	}
	if n, err := pki.PurgeTenantBoxKeys(t.Context(), "acme"); err != nil || n != 0 {
		t.Errorf("purging acme again: %d, %v; want 0 and no error", n, err)
	}
}
