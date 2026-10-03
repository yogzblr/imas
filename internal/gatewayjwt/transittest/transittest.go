// Package transittest provides a real *gatewayjwt.GatewaySigner backed by
// an in-process mock of the two OpenBao Transit endpoints it uses
// (POST <mount>/sign/<key>, GET <mount>/keys/<key>), for tests outside
// internal/gatewayjwt that need production gateway JWT minting and JWKS
// serving without an OpenBao server. It's a separate, exported package
// (like objectstoretest) because internal/pki's and internal/api's
// real-Envoy tests both need it; internal/gatewayjwt's own tests keep
// their richer, multi-version mock.
//
// The response shapes match captured real OpenBao responses (see
// internal/gatewayjwt/testdata): an Ed25519 public_key is standard base64
// of the raw 32 bytes, and a signature is "vault:v1:<base64>". The
// signer reaches it through internal/openbao like a real server: the mock
// only checks the X-Vault-Token the official client sends.
package transittest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/gatewayjwt"
)

// KeyName is the Transit key name the signer is created for.
const KeyName = "imas-gateway-jwt"

// NewSigner returns a GatewaySigner whose single key version (1, so
// minted tokens carry kid "1") is priv. It sets the IMAS_GATEWAY_OPENBAO_*
// environment variables with t.Setenv, so t must not be parallel.
func NewSigner(t testing.TB, priv ed25519.PrivateKey) *gatewayjwt.GatewaySigner {
	t.Helper()
	const token = "transittest-token"
	pub := priv.Public().(ed25519.PublicKey)
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/sign/"+KeyName, func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		var req struct {
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		input, err := base64.StdEncoding.DecodeString(req.Input)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"signature":   "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, input)),
			"key_version": 1,
		}})
	})
	mux.HandleFunc("/v1/transit/keys/"+KeyName, func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"type": "ed25519",
			"keys": map[string]any{"1": map[string]any{
				"name":          "ed25519",
				"public_key":    base64.StdEncoding.EncodeToString(pub),
				"creation_time": time.Now().UTC().Format(time.RFC3339Nano),
			}},
			"min_encryption_version": 1,
			"latest_version":         1,
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv(gatewayjwt.EnvOpenBaoAddr, srv.URL)
	t.Setenv(gatewayjwt.EnvOpenBaoTransitMount, "transit")
	t.Setenv(gatewayjwt.EnvOpenBaoAuthMethod, gatewayjwt.AuthMethodToken)
	t.Setenv(gatewayjwt.EnvOpenBaoToken, token)
	signer, err := gatewayjwt.NewGatewaySigner(KeyName)
	if err != nil {
		t.Fatalf("transittest: NewGatewaySigner: %v", err)
	}
	return signer
}
