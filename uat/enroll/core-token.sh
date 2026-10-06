#!/usr/bin/env bash
# The --token-cmd for create-tenants.sh, wait-connected.sh and enroll.sh on the
# UAT core hub (UAT.3b, uat/hub/core): prints an access token for tenant N's
# admin user whose organization.id is TENANT_ID, binding the tenant first with
# uat/hub/core/bind-tenant.sh if core.json doesn't record it yet.
#
#   UAT_CORE_STATE=DIR UAT_CORE_KUBECONFIG=FILE UAT_CORE_ENDPOINTS=FILE \
#     [UAT_CORE_SCRIPTS=uat/hub/core] core-token.sh N [TENANT_ID]
#
# UAT_CORE_STATE, UAT_CORE_KUBECONFIG and UAT_CORE_ENDPOINTS are the
# <state-dir>, <kubeconfig> and <endpoints.json> the core hub's scripts take.
# It reads, as uat/hub/core writes them (owner decision, 2026-10-06):
#   <state>/core/out/core.json                keycloak.token_url and client_id,
#                                             ca_file, users (tenant, roles),
#                                             tenants {"1": "t_..."} (bindings)
#   <state>/core/sensitive/credentials.json   keycloak.client_secret and
#                                             keycloak.passwords[<user>]
# With TENANT_ID, a tenant core.json doesn't yet bind to it is bound once:
#   bind-tenant.sh <kubeconfig> <endpoints.json> <state> N TENANT_ID
# which sets the user attribute behind organization.id on the tenant's users
# (kcadm.sh in the Keycloak pod) and records the binding in core.json. Without
# TENANT_ID (before the tenant exists) the token is taken as is: POST
# /v1/tenants doesn't check organization.id.
#
# Prints the token on stdout and nothing else. The password and client secret
# reach curl only in a mode 0600 file (--data-binary @file).
# lint: jq programs are single-quoted on purpose; their $names are jq variables.
# shellcheck disable=SC2016
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME=core-token.sh
# shellcheck source=lib.sh
. "$here/lib.sh"

n="${1:-}" tid="${2:-}"
[[ "$n" == 1 || "$n" == 2 ]] || { usage_text "${BASH_SOURCE[0]}" >&2; exit 2; }
[[ -z "$tid" || "$tid" =~ ^t_[A-Za-z0-9]+$ ]] || die "tenant id '$tid' is not t_..."
state="${UAT_CORE_STATE:-}"
[[ -n "$state" && -d "$state" ]] || die "UAT_CORE_STATE must name the core hub's state directory"
core_json="$state/core/out/core.json"
creds="$state/core/sensitive/credentials.json"
[[ -s "$core_json" ]] || die "no $core_json: has uat/hub/core/install.sh run?"
[[ -r "$creds" ]] || die "no $creds: has uat/hub/core/install.sh run?"
need jq curl

if [[ -n "$tid" ]]; then
	bound="$(jq -r --arg n "$n" '.tenants[$n] // empty' "$core_json")"
	if [[ "$bound" != "$tid" ]]; then
		[[ -z "$bound" ]] || die "core.json binds tenant $n to $bound, not $tid: a stale core state directory?"
		scripts="${UAT_CORE_SCRIPTS:-$here/../hub/core}"
		[[ -x "$scripts/bind-tenant.sh" ]] || die "no bind-tenant.sh in $scripts (set UAT_CORE_SCRIPTS)"
		[[ -n "${UAT_CORE_KUBECONFIG:-}" && -n "${UAT_CORE_ENDPOINTS:-}" ]] ||
			die "binding tenant $n needs UAT_CORE_KUBECONFIG and UAT_CORE_ENDPOINTS"
		# Its log lines name users and the tenant id only; keep stdout for the token.
		"$scripts/bind-tenant.sh" "$UAT_CORE_KUBECONFIG" "$UAT_CORE_ENDPOINTS" "$state" "$n" "$tid" >&2 ||
			die "bind-tenant.sh failed for tenant $n"
		[[ "$(jq -r --arg n "$n" '.tenants[$n] // empty' "$core_json")" == "$tid" ]] ||
			die "bind-tenant.sh did not record tenant $n as $tid in $core_json"
	fi
fi

# Tenant N's admin: the user of that tenant holding the write role.
user="$(jq -r --arg n "$n" '.keycloak.write_role as $w | [.users | to_entries[]
	| select((.value.tenant | tostring) == $n and (.value.roles | index($w)))] | sort_by(.key) | .[0].key // empty' "$core_json")"
[[ -n "$user" ]] || die "core.json has no admin user for tenant $n"
url="$(jq -r '.keycloak.token_url // empty' "$core_json")"
[[ "$url" =~ ^https?://[^[:space:]]+$ ]] || die "core.json has no keycloak.token_url"
ca="$(jq -r '.ca_file // empty' "$core_json")"

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
jq -j --slurpfile c "$core_json" --arg u "$user" '
	($c[0].keycloak.client_id) as $id | .keycloak as $k |
	{grant_type: "password", scope: "openid", client_id: $id, client_secret: ($k.client_secret | rtrimstr("\n")),
	 username: $u, password: ($k.passwords[$u] // "" | rtrimstr("\n"))}
	| to_entries | map("\(.key | @uri)=\(.value | @uri)") | join("&")' "$creds" >"$WORK/form"
tls=()
if [[ -n "$ca" ]]; then tls=(--cacert "$ca"); fi
status="$(curl -sS "${tls[@]}" --max-time 30 --data-binary "@$WORK/form" -o "$WORK/tok" -w '%{http_code}' "$url" 2>"$WORK/err")" || status=000
rm -f "$WORK/form"
[[ "$status" == 200 ]] || die "token request for $user: HTTP $status $(jq -r '.error // empty' "$WORK/tok" 2>/dev/null || head -c 200 "$WORK/err")"
tok="$(jq -j '.access_token // empty' "$WORK/tok")"
[[ "$tok" =~ $TOKEN_RE ]] || die "no token for $user"
printf '%s\n' "$tok"
