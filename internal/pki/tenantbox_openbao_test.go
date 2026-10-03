package pki

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/openbao/openbaotest"
)

// TestTenantBoxLive_KVv2AgainstRealOpenBao runs tenant key custody
// against a real OpenBao's KV v2 engine, which tenantboxtest only
// imitates: creation, a rotation, the check-and-set guard refusing a
// stale write (OpenBao answers 400), a deleted version reading as absent,
// and a token without access failing closed. It needs a server it may
// configure, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./internal/pki -run TestTenantBoxLive -v
//
// and is skipped otherwise. It mounts KV v2 at a fresh random path and
// removes it when done.
func TestTenantBoxLive_KVv2AgainstRealOpenBao(t *testing.T) {
	addr, rootToken := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || rootToken == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	suffix := make([]byte, 4)
	rand.Read(suffix)
	mount := "tenantboxtest-" + hex.EncodeToString(suffix)
	bao := openbaotest.NewAdmin(t, addr, rootToken)
	bao.Must(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	t.Cleanup(func() { bao.Delete("sys/mounts/" + mount) })

	t.Setenv(EnvTenantBoxOpenBaoAddr, addr)
	t.Setenv(EnvTenantBoxOpenBaoKVMount, mount)
	t.Setenv(EnvTenantBoxOpenBaoKVPath, "imas/tenant-x25519")
	t.Setenv(EnvTenantBoxOpenBaoAuthMethod, TenantBoxAuthMethodToken)
	t.Setenv(EnvTenantBoxOpenBaoToken, rootToken)
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)
	stubTenantHasSproutBoxKeys(t, noEnrolledSprouts)
	withTenantBoxGrace(t, time.Hour)

	const tenant = "t_live"
	pub1, err := GetTenantX25519PublicKey(tenant)
	if err != nil {
		t.Fatalf("first use creates the keypair: %v", err)
	}
	resetTenantX25519KeypairCache()
	if again, err := GetTenantX25519PublicKey(tenant); err != nil || again != pub1 {
		t.Fatalf("re-read = %q, %v; want the stored %q", again, err, pub1)
	}

	rot, err := RotateTenantX25519Keypair(tenant, false)
	if err != nil || rot.PreviousVersion != 1 || rot.Version != 2 {
		t.Fatalf("rotation = %+v, %v", rot, err)
	}
	keys, err := TenantBoxKeys(tenant)
	if err != nil || len(keys) != 2 || keys[0].Version != 2 || keys[1].Version != 1 || b64(keys[1].Pub) != pub1 {
		t.Fatalf("keys after rotation = %+v, %v; want v2 then v1 in grace", keys, err)
	}

	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	path := client.tenantPath(tenant)
	pub, priv, _ := box.GenerateKey(rand.Reader)
	if written, err := client.writeKeypair(t.Context(), path, pub, priv, 1, nil); err != nil || written {
		t.Fatalf("stale check-and-set: written=%v err=%v; want refused without error", written, err)
	}

	bao.Must(http.MethodPost, mount+"/delete/"+path, map[string]any{"versions": []int{1}})
	if _, found, err := client.readKeypair(t.Context(), path, 1); err != nil || found {
		t.Fatalf("deleted version: found=%v err=%v; want absent", found, err)
	}
	if cur, found, err := client.readKeypair(t.Context(), path, 0); err != nil || !found || cur.version != 2 {
		t.Fatalf("current version = %+v, %v, %v; want version 2", cur, found, err)
	}

	// A token whose policy grants nothing on the mount fails closed: a
	// 403 is an error, never "absent" or "lost the race".
	out := bao.Must(http.MethodPost, "auth/token/create", map[string]any{"policies": []string{"default"}, "ttl": "5m"})
	var created struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(out, &created); err != nil || created.Auth.ClientToken == "" {
		t.Fatalf("auth/token/create: %s (%v)", out, err)
	}
	t.Setenv(EnvTenantBoxOpenBaoToken, created.Auth.ClientToken)
	weakClient, err := newTenantBoxClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	defer weakClient.Close()
	if _, _, err := weakClient.readKeypair(t.Context(), path, 0); !errors.Is(err, ErrTenantBoxReadFailed) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("read without access: %v; want ErrTenantBoxReadFailed (403)", err)
	}
	if _, err := weakClient.writeKeypair(t.Context(), path, pub, priv, 2, nil); !errors.Is(err, ErrTenantBoxWriteFailed) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("write without access: %v; want ErrTenantBoxWriteFailed (403)", err)
	}
}
