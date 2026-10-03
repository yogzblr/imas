package fleetsign

import (
	"context"
	"net/http"

	log "github.com/yogzblr/imas/internal/log"
)

// KeySetSource is anything that can report the current fleet signing key
// set. *TransitKeySource is the production implementation.
type KeySetSource interface {
	KeySet(ctx context.Context) (KeySet, error)
}

// JWKSHandler serves src's key set as a JWKS document, the same way
// internal/gatewayjwt.JWKSHandler serves the gateway key: public keys
// only, so it needs no auth middleware. No route serves it since CL.1
// (see the package comment).
func JWKSHandler(src KeySetSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ks, err := src.KeySet(r.Context())
		if err != nil {
			log.Errorf("fleetsign: serving JWKS: %v", err)
			http.Error(w, "jwks_unavailable", http.StatusServiceUnavailable)
			return
		}
		body, err := ks.MarshalJWKS()
		if err != nil {
			log.Errorf("fleetsign: encoding JWKS: %v", err)
			http.Error(w, "jwks_unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			log.Errorf("fleetsign: writing JWKS response: %v", err)
		}
	}
}
