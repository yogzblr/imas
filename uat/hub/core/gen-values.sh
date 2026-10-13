#!/usr/bin/env bash
# gen-values.sh <endpoints.json> <admin.json> <release_tag> <bus-loader-user.pub> [<bus-fence-user.pub>]
#
# Prints the run-specific deploy/helm/farmer values (JSON, which Helm reads
# as YAML) that install.sh passes after values/farmer-uat.yaml. A helper:
# it reads files only and touches no cluster. admin.json is admin-keys.sh's
# public output ({"pubkey", "boxpub", ...}); bus-loader-user.pub is the DMZ
# bus loader's NKey public key seeds.sh writes (natsTrust.busLoaderUserPub).
# bus-fence-user.pub (seeds.sh, required when the DMZ hub has several
# nodes) is a clustered bus's fence user (natsTrust.busFenceUserPub). Nothing
# secret goes in here.
#
# The hubs' layout (lib/common.sh load_endpoints) decides the rest: the bus
# egress goes to the DMZ's private address (its internal load balancer on an
# HA DMZ), bus.expectedNodes is the DMZ's bus nodes when there are several,
# and on an HA core hub objectStore.endpoint is empty, so farmer and saasapi
# use Versity Gateway (values/values-ha.yaml).
#
# IMAS_UAT_DISPATCH_FLAGS (the workflow input dispatch_flags: on or off,
# default off; true/yes/1 and false/no/0 too) sets both fleet update switches the same way:
# farmer.selfUpdate.enabled (IMAS_SELF_UPDATE_ENABLED) and
# saasapi.fleetUpdateDispatch.enabled (SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED).
# Anything else is refused, so a typo never leaves them half on.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"

[[ $# -eq 4 || $# -eq 5 ]] || die "usage: gen-values.sh <endpoints.json> <admin.json> <release_tag> <bus-loader-user.pub> [<bus-fence-user.pub>]"
ENDPOINTS="$1"
admin_json="$2"
version=$(release_version "$3")
loader_pub_file="$4"
fence_pub_file="${5:-}"
[[ -f "$ENDPOINTS" ]] || die "endpoints file not found: $ENDPOINTS"
[[ -f "$admin_json" ]] || die "admin file not found: $admin_json"
[[ -f "$loader_pub_file" ]] || die "bus loader public key file not found: $loader_pub_file (seeds.sh writes it)"
need_cmd jq
load_endpoints

# The spellings uat/tests reads the same variable with (ingredients.FlagOn).
case "${IMAS_UAT_DISPATCH_FLAGS:-off}" in
on | true | yes | 1) dispatch=true ;;
off | false | no | 0) dispatch=false ;;
*) die "IMAS_UAT_DISPATCH_FLAGS must be on or off, got: ${IMAS_UAT_DISPATCH_FLAGS}" ;;
esac

pubkey=$(jq -r '.pubkey // empty' "$admin_json")
boxpub=$(jq -r '.boxpub // empty' "$admin_json")
# An NKey user public key (U...) or account key (A...) as imas auth pubkey
# prints it, and a standard base64 X25519 key (32 bytes).
[[ "$pubkey" =~ ^[A-Z2-7]{56}$ ]] || die "admin.json pubkey is not an NKey public key"
[[ "$boxpub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "admin.json boxpub is not a base64 X25519 key"
[[ "$boxpub" != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ]] || die "admin.json boxpub is the all-zero placeholder"
loader_pub=$(tr -d '\n' <"$loader_pub_file")
[[ "$loader_pub" =~ ^U[A-Z2-7]{55}$ ]] || die "$loader_pub_file is not an NKey user public key (U...)"
fence_pub=""
if ((DMZ_NODE_COUNT > 1)); then
	[[ -n "$fence_pub_file" && -f "$fence_pub_file" ]] ||
		die "the DMZ hub has $DMZ_NODE_COUNT nodes: a clustered bus needs its fence user's public key file (seeds.sh writes $FENCE_PUB_FILE)"
	fence_pub=$(tr -d '\n' <"$fence_pub_file")
	[[ "$fence_pub" =~ ^U[A-Z2-7]{55}$ ]] || die "$fence_pub_file is not an NKey user public key (U...)"
	[[ "$fence_pub" != "$loader_pub" ]] || die "the bus fence user and the bus loader user must be different keys"
fi

jq -n \
	--arg version "$version" \
	--arg busHost "$DMZ_PRIVATE_FQDN" \
	--arg busCIDR "$DMZ_ADDR/32" \
	--argjson dmzNodes "$DMZ_NODE_COUNT" \
	--arg fencePub "$fence_pub" \
	--arg s3Mode "$S3_MODE" \
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
	--argjson dispatch "$dispatch" \
	'({
	  clusterDomain: $clusterDomain,
	  bus: {
	    host: $busHost,
	    port: ($busPort | tonumber),
	    egressCIDRs: [$busCIDR],
	    sproutBusURLs: [$sproutBusURL]
	  },
	  farmer: {
	    image: {tag: $version},
	    bootstrapAdmin: {pubkey: $pubkey, boxpub: $boxpub, username: $adminName},
	    selfUpdate: {enabled: $dispatch}
	  },
	  saasapi: {
	    image: {tag: $version},
	    jwt: {keycloakJWKSURL: $jwks, issuer: $issuer, audience: $audience},
	    fleetUpdateDispatch: {enabled: $dispatch}
	  },
	  natsTrust: {busLoaderUserPub: $loaderPub},
	  database: {migrate: {image: {tag: $version}}},
	  objectStore: (if $s3Mode == "versity" then {endpoint: ""} else {endpoint: $s3Endpoint, useSSL: $s3SSL} end)
	}
	* (if $dmzNodes > 1
	   then {bus: {expectedNodes: $dmzNodes}, natsTrust: {busFenceUserPub: $fencePub}}
	   else {} end))
	+ (if ($s3CIDRs | length) > 0
	   then {networkPolicy: {external: {objectStore: ($s3CIDRs | map({ipBlock: {cidr: .}}))}}}
	   else {} end)'
