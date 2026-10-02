package main

// TestOpenBaoEnforcesReadOnlyFleetKey is the test that proves the
// signing split (FLAG FOR SECURITY REVIEW): against a real OpenBao, with
// the policy files this repo ships in deploy/fleetreleaser/policies/, a
// token carrying saasapi's (and farmer's) policy is refused a sign on
// imas-fleet-signing *by OpenBao*, when driven through the very same
// sign-capable client fleetreleaser itself uses. The Go code never
// calling sign is not what's being tested; OpenBao saying no is.
//
// It needs a running OpenBao (or Vault) it may configure, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./cmd/fleetreleaser -run TestOpenBaoEnforcesReadOnlyFleetKey -v
//
// and is skipped otherwise. It mounts Transit at a fresh, random path and
// removes the mount and policies when it's done. The shipped policies
// name the default "transit/" mount; the test rewrites that prefix to
// its own mount and changes nothing else.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/saasapi"
)

const (
	envTestOpenBaoAddr  = "IMAS_TEST_OPENBAO_ADDR"
	envTestOpenBaoToken = "IMAS_TEST_OPENBAO_TOKEN"
)

type baoAdmin struct {
	t     *testing.T
	addr  string
	token string
}

// call sends one request as token and returns the status and the decoded
// body.
func (b baoAdmin) call(token, method, path string, body any) (int, map[string]any) {
	b.t.Helper()
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, b.addr+"/v1/"+path, r)
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (b baoAdmin) must(method, path string, body any) map[string]any {
	b.t.Helper()
	status, out := b.call(b.token, method, path, body)
	if status/100 != 2 {
		b.t.Fatalf("admin %s %s: status %d: %v", method, path, status, out)
	}
	return out
}

// tokenFor creates a token with policy (plus OpenBao's "default", as a
// Kubernetes-auth role login would get).
func (b baoAdmin) tokenFor(policy string) string {
	b.t.Helper()
	out := b.must(http.MethodPost, "auth/token/create", map[string]any{"policies": []string{policy}, "ttl": "10m"})
	auth, _ := out["auth"].(map[string]any)
	tok, _ := auth["client_token"].(string)
	if tok == "" {
		b.t.Fatalf("no client_token in %v", out)
	}
	return tok
}

// capabilities is `bao token capabilities <token> <path>`, as the token.
func (b baoAdmin) capabilities(token, path string) []string {
	b.t.Helper()
	_, out := b.call(token, http.MethodPost, "sys/capabilities-self", map[string]any{"paths": []string{path}})
	raw, _ := out[path].([]any)
	if raw == nil {
		raw, _ = out["capabilities"].([]any)
	}
	caps := make([]string, 0, len(raw))
	for _, c := range raw {
		caps = append(caps, fmt.Sprint(c))
	}
	return caps
}

func TestOpenBaoEnforcesReadOnlyFleetKey(t *testing.T) {
	addr, rootToken := os.Getenv(envTestOpenBaoAddr), os.Getenv(envTestOpenBaoToken)
	if addr == "" || rootToken == "" {
		t.Skipf("%s and %s not set; this test needs a real OpenBao to prove policy enforcement", envTestOpenBaoAddr, envTestOpenBaoToken)
	}
	b := baoAdmin{t: t, addr: strings.TrimRight(addr, "/"), token: rootToken}

	suffix := make([]byte, 4)
	rand.Read(suffix)
	mount := "fleettest-" + hex.EncodeToString(suffix)
	key := fleetsign.DefaultTransitKeyName

	b.must(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "transit"})
	t.Cleanup(func() { b.call(rootToken, http.MethodDelete, "sys/mounts/"+mount, nil) })
	b.must(http.MethodPost, mount+"/keys/"+key, map[string]any{"type": "ed25519", "exportable": false, "allow_plaintext_backup": false})

	// Load the shipped policies, retargeted at this test's mount.
	policy := func(file string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fleetreleaser", "policies", file))
		if err != nil {
			t.Fatalf("reading shipped policy: %v", err)
		}
		name := strings.TrimSuffix(file, ".hcl") + "-" + hex.EncodeToString(suffix)
		b.must(http.MethodPut, "sys/policies/acl/"+name,
			map[string]any{"policy": strings.ReplaceAll(string(data), `"transit/`, `"`+mount+`/`)})
		t.Cleanup(func() { b.call(rootToken, http.MethodDelete, "sys/policies/acl/"+name, nil) })
		return name
	}
	signerPolicy := policy("imas-fleet-signer.hcl")
	verifyPolicy := policy("imas-fleet-verify.hcl")

	signerToken := b.tokenFor(signerPolicy)
	// Two separate tokens on the same read-only policy, one per service,
	// as deploy/fleetreleaser/README.md prescribes.
	readOnly := map[string]string{"saasapi": b.tokenFor(verifyPolicy), "farmer": b.tokenFor(verifyPolicy)}

	signerEnv := func(token string) *obTransitClient {
		t.Helper()
		t.Setenv(EnvOpenBaoAddr, b.addr)
		t.Setenv(EnvOpenBaoTransitMount, mount)
		t.Setenv(EnvOpenBaoAuthMethod, authMethodToken)
		t.Setenv(EnvOpenBaoToken, token)
		t.Setenv(EnvTransitKeyName, key)
		c, err := newTransitClientFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// 1. The signer publishes a release for real.
	db := newTestDB(t)
	rel := testRelease()
	if out, err := publish(t.Context(), db, signerEnv(signerToken), rel, "", time.Now()); err != nil || out != outcomeInserted {
		t.Fatalf("publish with the signer's token = %q, %v", out, err)
	}
	var row saasapi.FleetVersion
	if err := db.First(&row, "version = ?", rel.Version).Error; err != nil {
		t.Fatal(err)
	}

	for service, token := range readOnly {
		t.Run(service, func(t *testing.T) {
			// 2. The read-only token, driven through fleetreleaser's own
			// sign-capable client, is refused by OpenBao.
			_, _, err := signerEnv(token).sign(t.Context(), []byte("v6.6.6|https://evil.example.com/x|"+testChecksum))
			if !errors.Is(err, errSignFailed) || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("sign with %s's token = %v, want an OpenBao 403 permission denied", service, err)
			}
			// ...and publish with it writes nothing.
			db2 := newTestDB(t)
			if _, err := publish(t.Context(), db2, signerEnv(token), rel, "", time.Now()); !errors.Is(err, errSignFailed) {
				t.Fatalf("publish with %s's token = %v, want errSignFailed", service, err)
			}

			// 3. OpenBao's own view of the token: no capability on any
			// path that signs, re-keys, reconfigures or exports.
			for _, p := range []string{
				mount + "/sign/" + key,
				mount + "/sign/" + key + "/sha2-256",
				mount + "/keys/" + key + "/rotate",
				mount + "/keys/" + key + "/config",
				mount + "/keys/" + key + "/trim",
				mount + "/export/signing-key/" + key,
				mount + "/backup/" + key,
				mount + "/restore/" + key,
				mount + "/keys/some-other-key",
			} {
				if caps := b.capabilities(token, p); len(caps) != 1 || caps[0] != "deny" {
					t.Errorf("%s token capabilities on %s = %v, want [deny]", service, p, caps)
				}
			}
			for _, raw := range []struct{ method, path string }{
				{http.MethodPost, mount + "/keys/" + key + "/rotate"},
				{http.MethodPost, mount + "/keys/" + key + "/config"},
				{http.MethodDelete, mount + "/keys/" + key},
				{http.MethodPost, mount + "/keys/" + key},
			} {
				if status, _ := b.call(token, raw.method, raw.path, map[string]any{}); status != http.StatusForbidden {
					t.Errorf("%s %s %s with %s's token: status %d, want 403", raw.method, raw.path, service, service, status)
				}
			}

			// 4. What it may do: read the public key and verify.
			if caps := b.capabilities(token, mount+"/keys/"+key); len(caps) != 1 || caps[0] != "read" {
				t.Errorf("%s token capabilities on keys/%s = %v, want [read]", service, key, caps)
			}
			t.Setenv(fleetsign.EnvOpenBaoAddr, b.addr)
			t.Setenv(fleetsign.EnvOpenBaoTransitMount, mount)
			t.Setenv(fleetsign.EnvOpenBaoAuthMethod, fleetsign.AuthMethodToken)
			t.Setenv(fleetsign.EnvOpenBaoToken, token)
			t.Setenv(fleetsign.EnvTransitKeyName, key)
			src, err := fleetsign.NewTransitKeySourceFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if err := src.Verify(t.Context(), rel.withSignature(row.Signature)); err != nil {
				t.Fatalf("%s verifying the published row via Transit public key: %v", service, err)
			}
			msg, _ := rel.Message()
			_, rawSig, _ := fleetsign.DecodeSignature(row.Signature)
			status, out := b.call(token, http.MethodPost, mount+"/verify/"+key, map[string]any{
				"input":     base64.StdEncoding.EncodeToString(msg),
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(rawSig),
			})
			data, _ := out["data"].(map[string]any)
			if status != http.StatusOK || data["valid"] != true {
				t.Fatalf("Transit verify with %s's token: status %d, %v", service, status, out)
			}
		})
	}

	// 5. And the signer holds nothing beyond sign + read either.
	for _, p := range []string{mount + "/keys/" + key + "/rotate", mount + "/keys/" + key + "/config", mount + "/export/signing-key/" + key} {
		if caps := b.capabilities(signerToken, p); len(caps) != 1 || caps[0] != "deny" {
			t.Errorf("signer token capabilities on %s = %v, want [deny]", p, caps)
		}
	}
}
