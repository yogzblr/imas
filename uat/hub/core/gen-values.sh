#!/usr/bin/env bash
# gen-values.sh <endpoints.json> <admin.json> <release_tag> <bus-loader-user.pub>
#
# Prints the run-specific deploy/helm/farmer values (JSON, which Helm reads
# as YAML) that install.sh passes after values/farmer-uat.yaml. A helper:
# it reads files only and touches no cluster. admin.json is admin-keys.sh's
# public output ({"pubkey", "boxpub", ...}); bus-loader-user.pub is the DMZ
# bus loader's NKey public key seeds.sh writes (natsTrust.busLoaderUserPub).
# Nothing secret goes in here.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"

[[ $# -eq 4 ]] || die "usage: gen-values.sh <endpoints.json> <admin.json> <release_tag> <bus-loader-user.pub>"
ENDPOINTS="$1"
admin_json="$2"
version=$(release_version "$3")
loader_pub_file="$4"
[[ -f "$ENDPOINTS" ]] || die "endpoints file not found: $ENDPOINTS"
[[ -f "$admin_json" ]] || die "admin file not found: $admin_json"
[[ -f "$loader_pub_file" ]] || die "bus loader public key file not found: $loader_pub_file (seeds.sh writes it)"
need_cmd jq
load_endpoints

pubkey=$(jq -r '.pubkey // empty' "$admin_json")
boxpub=$(jq -r '.boxpub // empty' "$admin_json")
# An NKey user public key (U...) or account key (A...) as imas auth pubkey
# prints it, and a standard base64 X25519 key (32 bytes).
[[ "$pubkey" =~ ^[A-Z2-7]{56}$ ]] || die "admin.json pubkey is not an NKey public key"
[[ "$boxpub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "admin.json boxpub is not a base64 X25519 key"
[[ "$boxpub" != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ]] || die "admin.json boxpub is the all-zero placeholder"
loader_pub=$(tr -d '\n' <"$loader_pub_file")
[[ "$loader_pub" =~ ^U[A-Z2-7]{55}$ ]] || die "$loader_pub_file is not an NKey user public key (U...)"

jq -n \
	--arg version "$version" \
	--arg busHost "$DMZ_PRIVATE_FQDN" \
	--arg busCIDR "$DMZ_IP/32" \
	--arg busPort "$DMZ_BUS_PORT" \
	--arg sproutBusURL "$SPROUT_BUS_URL" \
	--arg clusterDomain "$CLUSTER_DOMAIN" \
	--arg jwks "$KEYCLOAK_JWKS_URL" \
	--arg issuer "$KEYCLOAK_ISSUER" \
	--arg audience "$SAASAPI_AUDIENCE" \
	--arg pubkey "$pubkey" \
	--arg boxpub "$boxpub" \
	--arg adminName "$BOOTSTRAP_ADMIN_NAME" \
	--arg loaderPub "$loader_pub" \
	--arg s3Endpoint "$S3_ENDPOINT" \
	--argjson s3SSL "$S3_USE_SSL" \
	--argjson s3CIDRs "$S3_EGRESS_CIDRS" \
	'{
	  clusterDomain: $clusterDomain,
	  bus: {
	    host: $busHost,
	    port: ($busPort | tonumber),
	    egressCIDRs: [$busCIDR],
	    sproutBusURLs: [$sproutBusURL]
	  },
	  farmer: {
	    image: {tag: $version},
	    bootstrapAdmin: {pubkey: $pubkey, boxpub: $boxpub, username: $adminName}
	  },
	  saasapi: {
	    image: {tag: $version},
	    jwt: {keycloakJWKSURL: $jwks, issuer: $issuer, audience: $audience}
	  },
	  natsTrust: {busLoaderUserPub: $loaderPub},
	  database: {migrate: {image: {tag: $version}}},
	  objectStore: {endpoint: $s3Endpoint, useSSL: $s3SSL}
	}
	+ (if ($s3CIDRs | length) > 0
	   then {networkPolicy: {external: {objectStore: ($s3CIDRs | map({ipBlock: {cidr: .}}))}}}
	   else {} end)'
