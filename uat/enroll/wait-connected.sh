#!/usr/bin/env bash
# Waits until every enrolled UAT sprout is connected, as farmer sees it.
#
#   wait-connected.sh --state DIR --internal-auth-file FILE \
#     (--token-cmd EXE | --token-t1 FILE --token-t2 FILE) \
#     [--saasapi-url URL] [--ca-file uat-ca.pem] [--timeout 600]
#
# Reads DIR/run.json and DIR/tenants.json (create-tenants.sh) and
# DIR/enrolled.json (playbooks/collect.yml). For each sprout it links the asset
# id uat-<run_id>-<vm> to the sprout ID it enrolled with in its own tenant
# (POST .../sprouts/{sprout_id}/asset-link: 201 new, 200 already linked),
# then polls GET /v1/tenants/{tenant_id}/sprouts?asset_ids=... until every
# sprout has key_state "accepted" and connected true. "connected" is farmer's
# view: the Valkey heartbeat key farmer sets per (tenant_id, sprout_id) when
# the bus reports the sprout's connection (internal/heartbeat), which saasapi
# reads; it is never true when saasapi has no Valkey configured.
#
# Writes, for the tests (no secrets):
#   DIR/sprouts.json         {"<vm>": {"sprout_id", "asset_id"}}, the shape
#                            uat/tests/harness reads (strictly: no other field)
#   DIR/sprouts-detail.json  {"run_id", "sprouts": {"<vm>": {"tenant",
#                            "tenant_id", "os", "sprout_id", "asset_id"}}}
#
# Exit codes: 0 all connected; 1 error or timeout; 2 usage; 3 token mismatch.
# lint: TOKEN_FILE_1 and _2 are read by lib.sh's token_for.
# shellcheck disable=SC2034
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME=wait-connected.sh
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() {
	usage_text "${BASH_SOURCE[0]}" >&2
	exit 2
}

STATE="" SAAS_URL="" CA_FILE="" INTERNAL_AUTH_FILE="" TOKEN_CMD=""
TOKEN_FILE_1="" TOKEN_FILE_2="" TIMEOUT=600
POLL="${UAT_ENROLL_POLL_SECONDS:-5}"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--state) STATE="${2:?}"; shift 2 ;;
	--saasapi-url) SAAS_URL="${2:?}"; shift 2 ;;
	--ca-file) CA_FILE="${2:?}"; shift 2 ;;
	--internal-auth-file) INTERNAL_AUTH_FILE="${2:?}"; shift 2 ;;
	--token-cmd) TOKEN_CMD="${2:?}"; shift 2 ;;
	--token-t1) TOKEN_FILE_1="${2:?}"; shift 2 ;;
	--token-t2) TOKEN_FILE_2="${2:?}"; shift 2 ;;
	--timeout) TIMEOUT="${2:?}"; shift 2 ;;
	-h | --help) usage ;;
	*) echo "wait-connected.sh: unknown argument: $1" >&2; usage ;;
	esac
done
[[ -n "$STATE" ]] || usage
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be a number of seconds"
need jq curl base64
tenants_json="$STATE/tenants.json"
enrolled_json="$STATE/enrolled.json"
[[ -s "$tenants_json" ]] || die "no $tenants_json: run create-tenants.sh first"
[[ -s "$enrolled_json" ]] || die "no $enrolled_json: run playbooks/collect.yml first"
jq -e '.sprouts | type == "object" and length > 0' "$enrolled_json" >/dev/null || die "$enrolled_json lists no sprouts"
[[ -n "$SAAS_URL" ]] || SAAS_URL="$(jq -r '.saasapi_url // empty' "$STATE/run.json" 2>/dev/null || true)"
SAAS_URL="${SAAS_URL%/}"

umask 077
WORK="$(mktemp -d "$STATE/.work.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
saas_init

# One line per sprout: vm tenant tenant_id sprout_id asset_id.
mapfile -t rows < <(jq -r --slurpfile t "$tenants_json" '
	.sprouts | to_entries[] |
	(.value.tenant | tostring) as $n |
	[.key, $n, ($t[0][$n].tenant_id // ""), .value.sprout_id, .value.asset_id] | @tsv' "$enrolled_json")

declare -A asset_of tenant_of
for row in "${rows[@]}"; do
	IFS=$'\t' read -r vm n tid sid aid <<<"$row"
	[[ -n "$tid" ]] || die "$vm is in tenant $n, which $tenants_json doesn't have"
	[[ "$sid" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "$vm: bad sprout id '$sid' in $enrolled_json"
	[[ "$aid" =~ ^[A-Za-z0-9._-]+$ ]] || die "$vm: bad asset id '$aid' in $enrolled_json"
	check_token_tenant "$n" "$tid"
	body="$(jq -nc --arg a "$aid" '{asset_id: $a}')"
	status="$(saas_call POST "/v1/tenants/$tid/sprouts/$sid/asset-link" "$n" "$tid" "$body")" || exit 1
	case "$status" in
	201) log "$vm: linked asset $aid to sprout $sid in $tid" ;;
	200) log "$vm: asset $aid already linked to sprout $sid in $tid" ;;
	404) die "$vm: tenant $tid has no sprout '$sid' (did it enroll in this tenant?)" ;;
	409) die "$vm: asset $aid or sprout $sid is already linked differently (asset_link_conflict)" ;;
	*) die "$vm: asset link: HTTP $status $(resp_error)" ;;
	esac
	asset_of[$vm]="$aid"
	tenant_of[$vm]="$n $tid"
done

deadline=$((SECONDS + TIMEOUT))
declare -A connected
while :; do
	waiting=()
	for n in 1 2; do
		ids=() tid=""
		for vm in "${!tenant_of[@]}"; do
			read -r tn ttid <<<"${tenant_of[$vm]}"
			[[ "$tn" == "$n" ]] || continue
			tid="$ttid"
			ids+=("${asset_of[$vm]}")
		done
		((${#ids[@]})) || continue
		list="$(IFS=,; echo "${ids[*]}")"
		status="$(saas_call GET "/v1/tenants/$tid/sprouts?asset_ids=$list" "$n" "$tid")" || exit 1
		[[ "$status" == 200 ]] || die "lookup in tenant $n: HTTP $status $(resp_error)"
		for vm in "${!tenant_of[@]}"; do
			read -r tn _ <<<"${tenant_of[$vm]}"
			[[ "$tn" == "$n" ]] || continue
			if jq -e --arg a "${asset_of[$vm]}" '[.results[] | select(.asset_id == $a and .key_state == "accepted" and .connected == true)] | length == 1' \
				"$WORK/resp" >/dev/null; then
				[[ -n "${connected[$vm]:-}" ]] || log "$vm: connected"
				connected[$vm]=1
			else
				connected[$vm]=""
				waiting+=("$vm($(jq -r --arg a "${asset_of[$vm]}" '([.results[] | select(.asset_id == $a)][0] // null) as $r |
					if $r == null then "unresolved" else "key \($r.key_state), connected \($r.connected)" end' "$WORK/resp"))")
			fi
		done
	done
	((${#waiting[@]})) || break
	((SECONDS < deadline)) || die "not connected after ${TIMEOUT}s: ${waiting[*]}"
	sleep "$POLL"
done

jq --slurpfile t "$tenants_json" '{run_id: .run_id, sprouts: (.sprouts | with_entries(
	(.value.tenant | tostring) as $n |
	.value = {tenant: (.value.tenant | tonumber), tenant_id: $t[0][$n].tenant_id, os: .value.os,
		sprout_id: .value.sprout_id, asset_id: .value.asset_id}))}' \
	"$enrolled_json" >"$STATE/sprouts-detail.json.tmp"
jq '.sprouts | map_values({sprout_id, asset_id})' "$STATE/sprouts-detail.json.tmp" >"$STATE/sprouts.json.tmp"
chmod 644 "$STATE/sprouts-detail.json.tmp" "$STATE/sprouts.json.tmp"
mv "$STATE/sprouts-detail.json.tmp" "$STATE/sprouts-detail.json"
mv "$STATE/sprouts.json.tmp" "$STATE/sprouts.json"
log "all ${#rows[@]} sprouts connected; wrote $STATE/sprouts.json"
jq -r '.sprouts | to_entries[] | "\(.key): tenant \(.value.tenant) \(.value.tenant_id) sprout \(.value.sprout_id) asset \(.value.asset_id)"' "$STATE/sprouts-detail.json"
