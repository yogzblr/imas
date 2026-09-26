package handlers

// GET /v1/.well-known/fleet-signing-jwks.json — design doc §2.5. Serves
// the public half of the imas-fleet-signing OpenBao Transit key sprout
// releases are signed with, read through farmer's READ-ONLY Transit
// token (internal/fleetsign). Same trust model as jwks.go's gateway JWKS:
// public keys only, no auth. A sprout pins this key set at enrollment
// (POST /v1/enroll's fleet_signing_jwks) rather than fetching it live;
// this route is for operators and tooling to compare against.

import (
	"net/http"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// fleetKeySource is set once at startup via SetFleetKeySource
// (cmd/farmer/main.go), mirroring SetGatewaySigner.
var fleetKeySource fleetsign.KeySetSource

// SetFleetKeySource installs the read-only fleet signing key source that
// FleetSigningJWKS and Enroll use.
func SetFleetKeySource(s fleetsign.KeySetSource) { fleetKeySource = s }

// FleetSigningJWKS handles GET /v1/.well-known/fleet-signing-jwks.json.
// Deliberately not wrapped in Auth (see routers.go).
func FleetSigningJWKS(w http.ResponseWriter, r *http.Request) {
	if fleetKeySource == nil {
		http.Error(w, "jwks_unavailable", http.StatusServiceUnavailable)
		return
	}
	fleetsign.JWKSHandler(fleetKeySource)(w, r)
}
