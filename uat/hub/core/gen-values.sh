#!/usr/bin/env bash
# gen-values.sh <endpoints.json> <admin.json> <release_tag>
#
# Prints the run-specific deploy/helm/farmer values (JSON, which Helm reads
# as YAML) that install.sh passes after values/farmer-uat.yaml. A helper:
# it reads files only and touches no cluster. admin.json is admin-keys.sh's
# public output ({"pubkey", "boxpub", ...}); nothing secret goes in here.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"

[[ $# -eq 3 ]] || die "usage: gen-values.sh <endpoints.json> <admin.json> <release_tag>"
ENDPOINTS="$1"
admin_json="$2"
version=$(release_version "$3")
[[ -f "$ENDPOINTS" ]] || die "endpoints file not found: $ENDPOINTS"
[[ -f "$admin_json" ]] || die "admin file not found: $admin_json"
need_cmd jq
load_endpoints

pubkey=$(jq -r '.pubkey // empty' "$admin_json")
boxpub=$(jq -r '.boxpub // empty' "$admin_json")
# An NKey user public key (U...) or account key (A...) as imas auth pubkey
# prints it, and a standard base64 X25519 key (32 bytes).
[[ "$pubkey" =~ ^[A-Z2-7]{56}$ ]] || die "admin.json pubkey is not an NKey public key"
[[ "$boxpub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "admin.json boxpub is not a base64 X25519 key"
[[ "$boxpub" != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ]] || die "admin.json boxpub is the all-zero placeholder"

jq -n \
	--arg version "$version" \
	--arg busService "$BUS_SERVICE" \
	--arg busNamespace "$BUS_NAMESPACE" \
	--arg busPort "$DMZ_BUS_PORT" \
	--arg sproutBusURL "$SPROUT_BUS_URL" \
	--arg clusterDomain "$CLUSTER_DOMAIN" \
	--arg jwks "$KEYCLOAK_JWKS_URL" \
	--arg issuer "$KEYCLOAK_ISSUER" \
	--arg audience "$SAASAPI_AUDIENCE" \
	--arg pubkey "$pubkey" \
	--arg boxpub "$boxpub" \
	--arg adminName "$BOOTSTRAP_ADMIN_NAME" \
	'{
	  clusterDomain: $clusterDomain,
	  bus: {
	    serviceName: $busService,
	    namespace: $busNamespace,
	    port: ($busPort | tonumber),
	    sproutBusURLs: [$sproutBusURL]
	  },
	  networkPolicy: {dmz: {namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": $busNamespace}}}},
	  farmer: {
	    image: {tag: $version},
	    bootstrapAdmin: {pubkey: $pubkey, boxpub: $boxpub, username: $adminName}
	  },
	  saasapi: {
	    image: {tag: $version},
	    jwt: {keycloakJWKSURL: $jwks, issuer: $issuer, audience: $audience}
	  },
	  database: {migrate: {image: {tag: $version}}}
	}'
