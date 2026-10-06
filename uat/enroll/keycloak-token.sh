#!/usr/bin/env bash
# A reference --token-cmd for create-tenants.sh, wait-connected.sh and
# enroll.sh: prints an access token for tenant N's admin user whose
# organization.id is TENANT_ID, mapping the tenant's users to TENANT_ID in
# Keycloak first.
#
#   UAT_KEYCLOAK_JSON=keycloak.json [UAT_KEYCLOAK_CA=uat-ca.pem] keycloak-token.sh N [TENANT_ID]
#
# keycloak.json is the file uat/tests/harness reads (UAT.5), written by the
# Keycloak setup (UAT.3b):
#   issuer            https://<core fqdn>/realms/<realm>, exactly the token's iss
#   client_id, client_secret (optional)
#                     the client users get tokens from (password grant)
#   tenant_attribute  the user attribute the realm maps to organization.id
#   admin             {realm (default master), client_id, and username and
#                     password, or client_secret}: may manage the realm's users
#   tenants           {"1": {"admin": {username, password},
#                            "readonly": {username, password}}, "2": ...}
#
# With TENANT_ID, admin and tenant_attribute all set, tenant_attribute of the
# tenant's admin and readonly users is set to TENANT_ID (only if it differs)
# before the token is taken, so the token carries organization.id = TENANT_ID.
# Without TENANT_ID (before the tenant exists) the token is taken as is.
#
# Prints the token on stdout and nothing else. Passwords and tokens travel
# only in mode 0600 files that curl reads (--data-binary @file, -H @file).
# lint: jq programs are single-quoted on purpose; their $names are jq variables.
# shellcheck disable=SC2016
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME=keycloak-token.sh
# shellcheck source=lib.sh
. "$here/lib.sh"

n="${1:-}" tid="${2:-}"
[[ "$n" == 1 || "$n" == 2 ]] || { usage_text "${BASH_SOURCE[0]}" >&2; exit 2; }
[[ -z "$tid" || "$tid" =~ ^t_[A-Za-z0-9]+$ ]] || die "tenant id '$tid' is not t_..."
cfg="${UAT_KEYCLOAK_JSON:-}"
[[ -n "$cfg" && -r "$cfg" ]] || die "UAT_KEYCLOAK_JSON must name a readable keycloak.json"
need jq curl
issuer="$(jq -r '.issuer // empty' "$cfg")"
[[ "$issuer" =~ ^(https?://[^/]+(/[^[:space:]]*)?)/realms/([^/[:space:]]+)$ ]] ||
	die "keycloak.json issuer must be <base URL>/realms/<realm>, got '$issuer'"
base="${BASH_REMATCH[1]}" realm="${BASH_REMATCH[3]}"
jq -e --arg n "$n" '.client_id and .tenants[$n].admin.username and .tenants[$n].admin.password' "$cfg" >/dev/null ||
	die "keycloak.json needs client_id and tenants.$n.admin.username and password"

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tls=()
if [[ -n "${UAT_KEYCLOAK_CA:-}" ]]; then tls=(--cacert "$UAT_KEYCLOAK_CA"); fi

# grant REALM JQ_FILTER: run the token endpoint of REALM with the form the
# filter builds from keycloak.json; print the access token.
grant() {
	local url="$base/realms/$1/protocol/openid-connect/token" status
	jq -j --arg n "$n" "$2"' | to_entries | map("\(.key | @uri)=\(.value | @uri)") | join("&")' "$cfg" >"$WORK/form"
	status="$(curl -sS "${tls[@]}" --max-time 30 --data-binary "@$WORK/form" -o "$WORK/tok" -w '%{http_code}' "$url" 2>"$WORK/err")" || status=000
	rm -f "$WORK/form"
	[[ "$status" == 200 ]] || die "token request to $url: HTTP $status $(jq -r '.error // empty' "$WORK/tok" 2>/dev/null || head -c 200 "$WORK/err")"
	jq -j '.access_token // empty' "$WORK/tok"
	rm -f "$WORK/tok"
}

# admin_call METHOD PATH [JSON_FILE]: the realm's admin API, as the admin.
admin_call() {
	local status data=()
	if [[ $# -ge 3 ]]; then data=(-H 'Content-Type: application/json' --data-binary "@$3"); fi
	status="$(curl -sS "${tls[@]}" --max-time 30 -X "$1" -H "@$WORK/hdr" "${data[@]}" \
		-o "$WORK/resp" -w '%{http_code}' "$base/admin/realms/$realm$2" 2>"$WORK/err")" || status=000
	printf '%s' "$status"
}

attr="$(jq -r '.tenant_attribute // empty' "$cfg")"
if [[ -n "$tid" && -n "$attr" ]] && jq -e '.admin.client_id' "$cfg" >/dev/null; then
	admin_realm="$(jq -r '.admin.realm // "master"' "$cfg")"
	admin_tok="$(grant "$admin_realm" '.admin | {client_id} + (if .username then {grant_type: "password", username, password} + (if .client_secret then {client_secret} else {} end) else {grant_type: "client_credentials", client_secret} end)')"
	[[ "$admin_tok" =~ $TOKEN_RE ]] || die "no admin token from realm $admin_realm"
	printf 'Authorization: Bearer %s\nAccept: application/json\n' "$admin_tok" >"$WORK/hdr"
	for who in admin readonly; do
		user="$(jq -r --arg n "$n" --arg w "$who" '.tenants[$n][$w].username // empty' "$cfg")"
		[[ -n "$user" ]] || continue
		q="$(jq -rn --arg u "$user" '$u | @uri')"
		status="$(admin_call GET "/users?exact=true&username=$q")"
		[[ "$status" == 200 ]] || die "looking up $user in realm $realm: HTTP $status"
		jq --arg u "$user" '[.[] | select((.username | ascii_downcase) == ($u | ascii_downcase))][0] // empty' "$WORK/resp" >"$WORK/user"
		[[ -s "$WORK/user" ]] || die "no user $user in realm $realm"
		jq -e --arg a "$attr" --arg t "$tid" '.attributes[$a] == [$t]' "$WORK/user" >/dev/null && continue
		id="$(jq -r .id "$WORK/user")"
		jq --arg a "$attr" --arg t "$tid" '.attributes = ((.attributes // {}) + {($a): [$t]})' "$WORK/user" >"$WORK/user.new"
		status="$(admin_call PUT "/users/$(jq -rn --arg i "$id" '$i | @uri')" "$WORK/user.new")"
		[[ "$status" == 204 ]] || die "setting $attr of $user: HTTP $status (is the attribute allowed by the realm's user profile?)"
		log "tenant $n: $user mapped to $tid"
	done
	rm -f "$WORK/hdr"
fi

tok="$(grant "$realm" '{grant_type: "password", client_id: .client_id, username: .tenants[$n].admin.username, password: .tenants[$n].admin.password} + (if .client_secret then {client_secret} else {} end)')"
[[ "$tok" =~ $TOKEN_RE ]] || die "no token for tenant $n's admin"
printf '%s\n' "$tok"
