package gatewayjwt

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	log "github.com/yogzblr/imas/internal/log"
)

// JWKSHandler serves the gateway key's public keys as a standard JWKS
// document (RFC 7517), for Envoy's jwt_authn remote_jwks and, per the
// implementation brief this package was built from, an external
// validator such as Keycloak's OIDC identity-provider JWKS import — the
// point of using a real, standard alg:EdDSA JWS (unlike the native NATS
// User JWT) is that any spec-compliant consumer can validate against
// this document, not just code written specifically for imas.
//
// Deliberately not wrapped in any auth middleware at the route-
// registration call site (see internal/api/routers.go) — a JWKS document
// contains only public keys, and is meaningless without a token to
// validate, so there's nothing here worth gating.
func JWKSHandler(signer *GatewaySigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := signer.PublicKeys(r.Context())
		if err != nil {
			log.Errorf("gatewayjwt: serving JWKS: %v", err)
			http.Error(w, "jwks_unavailable", http.StatusServiceUnavailable)
			return
		}

		set := jwk.NewSet()
		for _, k := range keys {
			key, err := jwk.FromRaw(k.PublicKey)
			if err != nil {
				log.Errorf("gatewayjwt: converting Transit key version %d to JWK: %v", k.Version, err)
				http.Error(w, "jwks_unavailable", http.StatusInternalServerError)
				return
			}
			if err := key.Set(jwk.KeyIDKey, strconv.Itoa(k.Version)); err != nil {
				log.Errorf("gatewayjwt: setting kid on JWK version %d: %v", k.Version, err)
				http.Error(w, "jwks_unavailable", http.StatusInternalServerError)
				return
			}
			if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
				log.Errorf("gatewayjwt: setting use on JWK version %d: %v", k.Version, err)
				http.Error(w, "jwks_unavailable", http.StatusInternalServerError)
				return
			}
			// jwt.WithKeySet (used by this package's own round-trip test,
			// and by any well-behaved verifier) requires a JWK's "alg" to
			// be set explicitly before it'll trust that key for
			// verification — see jwx/v2/jwt's WithKeySet doc: "we do NOT
			// trust the token's headers" for algorithm selection.
			if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA.String()); err != nil {
				log.Errorf("gatewayjwt: setting alg on JWK version %d: %v", k.Version, err)
				http.Error(w, "jwks_unavailable", http.StatusInternalServerError)
				return
			}
			if err := set.AddKey(key); err != nil {
				log.Errorf("gatewayjwt: adding JWK version %d to set: %v", k.Version, err)
				http.Error(w, "jwks_unavailable", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(set); err != nil {
			log.Errorf("gatewayjwt: writing JWKS response: %v", err)
		}
	}
}
