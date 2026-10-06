#!/usr/bin/env bash
# Creates the UAT tenants through the SaaS API and mints one one-time
# enrollment key per sprout, each in the sprout's own tenant.
#
#   create-tenants.sh --uat uat.json --state DIR --internal-auth-file FILE \
#     (--token-cmd EXE | --token-t1 FILE --token-t2 FILE) \
#     [--saasapi-url https://host[:port]] [--ca-file uat-ca.pem] \
#     [--key-hours 6] [--status-timeout 300] [--new-keys]
#
# uat.json is `tofu output -json uat` (plan section 4h, Shared contract): a
# tenant is created for every tenant number its sprouts use (1 and 2).
#
# Writes into DIR (created mode 0700):
#   run.json            {"run_id", "saasapi_url"}
#   tenants.json        {"1": {"tenant_id", "name", "status"}, "2": {...}}
#   keys.json           {"<vm>": {"tenant", "tenant_id", "key_id", "expires_at", "key_file"}}
#   keys/<vm>.key       the registration_key, mode 0600: the only secret written
#
# Re-running is safe: a tenant already in tenants.json is reused (never created
# twice), and a sprout that already has a key keeps it unless --new-keys.
# Prints tenant ids and key ids only, never a key, token or the shared secret.
#
# Exit codes: 0 done; 1 error; 2 usage; 3 a token's organization.id doesn't
# match its tenant (see README.md, "Tokens and the tenant id").
# lint: jq programs are single-quoted on purpose (their $names are jq
# lint: variables); TOKEN_FILE_1 and _2 are read by lib.sh's token_for.
# shellcheck disable=SC2016,SC2034
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME=create-tenants.sh
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() {
	usage_text "${BASH_SOURCE[0]}" >&2
	exit 2
}

UAT="" STATE="" SAAS_URL="" CA_FILE="" INTERNAL_AUTH_FILE="" TOKEN_CMD=""
TOKEN_FILE_1="" TOKEN_FILE_2="" KEY_HOURS=6 STATUS_TIMEOUT=300 NEW_KEYS=0
POLL="${UAT_ENROLL_POLL_SECONDS:-5}"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--uat) UAT="${2:?}"; shift 2 ;;
	--state) STATE="${2:?}"; shift 2 ;;
	--saasapi-url) SAAS_URL="${2:?}"; shift 2 ;;
	--ca-file) CA_FILE="${2:?}"; shift 2 ;;
	--internal-auth-file) INTERNAL_AUTH_FILE="${2:?}"; shift 2 ;;
	--token-cmd) TOKEN_CMD="${2:?}"; shift 2 ;;
	--token-t1) TOKEN_FILE_1="${2:?}"; shift 2 ;;
	--token-t2) TOKEN_FILE_2="${2:?}"; shift 2 ;;
	--key-hours) KEY_HOURS="${2:?}"; shift 2 ;;
	--status-timeout) STATUS_TIMEOUT="${2:?}"; shift 2 ;;
	--new-keys) NEW_KEYS=1; shift ;;
	-h | --help) usage ;;
	*) echo "create-tenants.sh: unknown argument: $1" >&2; usage ;;
	esac
done
[[ -n "$UAT" && -n "$STATE" ]] || usage
need jq curl base64
[[ -r "$UAT" ]] || die "uat JSON not readable: $UAT"
if ! [[ "$KEY_HOURS" =~ ^[0-9]+$ ]] || ((KEY_HOURS < 1 || KEY_HOURS > 720)); then
	die "--key-hours must be 1 to 720 (saasapi's expires_in_hours range)"
fi
[[ "$STATUS_TIMEOUT" =~ ^[0-9]+$ ]] || die "--status-timeout must be a number of seconds"

jq -e '(.run_id | type == "string" and test("^[a-z0-9]{6,10}$"))
	and (.sprouts | type == "object" and length > 0)
	and ([.sprouts[] | .tenant | tostring | ltrimstr("t")] | all(. == "1" or . == "2"))' "$UAT" >/dev/null ||
	die "$UAT is not the uat object of the contract (run_id, and sprouts with tenant 1 or 2)"
run_id="$(jq -r .run_id "$UAT")"
if [[ -z "$SAAS_URL" ]]; then
	fqdn="$(jq -r '.core.fqdn // empty' "$UAT")"
	[[ -n "$fqdn" ]] || die "no --saasapi-url and no core.fqdn in $UAT"
	SAAS_URL="https://$fqdn"
fi
SAAS_URL="${SAAS_URL%/}"

umask 077
mkdir -p "$STATE/keys"
chmod 700 "$STATE" "$STATE/keys"
WORK="$(mktemp -d "$STATE/.work.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
saas_init

run_json="$STATE/run.json"
tenants_json="$STATE/tenants.json"
keys_json="$STATE/keys.json"
if [[ -s "$run_json" ]]; then
	[[ "$(jq -r .run_id "$run_json")" == "$run_id" ]] ||
		die "$STATE belongs to run $(jq -r .run_id "$run_json"), not $run_id: use a fresh --state"
else
	jq -n --arg r "$run_id" --arg u "$SAAS_URL" '{run_id: $r, saasapi_url: $u}' >"$run_json"
fi
[[ -s "$tenants_json" ]] || echo '{}' >"$tenants_json"
[[ -s "$keys_json" ]] || echo '{}' >"$keys_json"

# json_set FILE JQ_FILTER ARGS...: update FILE atomically.
json_set() {
	local file="$1" filter="$2"
	shift 2
	jq "$@" "$filter" "$file" >"$file.tmp" && mv "$file.tmp" "$file"
}

create_tenant() {
	local n="$1" status tid body
	local name="uat-$run_id-t$n"
	body="$(jq -nc --arg name "$name" '{name: $name}')"
	status="$(saas_call POST /v1/tenants "$n" "" "$body")" || exit 1
	[[ "$status" == 202 ]] || die "creating tenant $n: HTTP $status $(resp_error)"
	tid="$(jq -r '.tenant_id // empty' "$WORK/resp")"
	[[ "$tid" =~ ^t_[A-Za-z0-9]+$ ]] || die "creating tenant $n: no tenant_id in the answer"
	json_set "$tenants_json" '.[$n] = {tenant_id: $tid, name: $name, status: "pending"}' \
		--arg n "$n" --arg tid "$tid" --arg name "$name"
	log "tenant $n: created $tid ($name)"
}

wait_active() {
	local n="$1" tid="$2" status st deadline=$((SECONDS + STATUS_TIMEOUT))
	while :; do
		status="$(saas_call GET "/v1/tenants/$tid/status" "$n" "$tid")" || exit 1
		case "$status" in
		200)
			st="$(jq -r '.status // empty' "$WORK/resp")"
			case "$st" in
			active)
				json_set "$tenants_json" '.[$n].status = "active"' --arg n "$n"
				log "tenant $n: $tid is active"
				return 0
				;;
			failed | offboarding | offboarded)
				die "tenant $n ($tid) is $st: $(jq -r '.last_error // "no last_error"' "$WORK/resp")"
				;;
			esac
			;;
		404) die "tenant $n ($tid) is unknown to saasapi: a stale --state directory?" ;;
		401 | 403) die "tenant $n status: HTTP $status $(resp_error)" ;;
		esac
		((SECONDS < deadline)) || die "tenant $n ($tid) not active after ${STATUS_TIMEOUT}s (last: HTTP $status ${st:-})"
		sleep "$POLL"
	done
}

mint_key() {
	local n="$1" tid="$2" vm="$3" status body kid exp tries=0
	local keyfile="$STATE/keys/$vm.key"
	body="$(jq -nc --argjson h "$KEY_HOURS" '{expires_in_hours: $h, max_uses: 1}')"
	while :; do
		status="$(saas_call POST "/v1/tenants/$tid/enrollment-keys" "$n" "$tid" "$body")" || exit 1
		# Minting is rate limited per tenant (1/s, burst 5): back off and retry.
		[[ "$status" == 429 ]] || break
		((++tries <= 10)) || die "enrollment key for $vm: still rate limited after 10 tries"
		sleep "$((tries < 5 ? tries : 5))"
	done
	[[ "$status" == 200 ]] || die "enrollment key for $vm: HTTP $status $(resp_error)"
	kid="$(jq -r '.key_id // empty' "$WORK/resp")"
	exp="$(jq -r '.expires_at // empty' "$WORK/resp")"
	jq -e --arg kid "$kid" '.registration_key | type == "string" and startswith($kid + ".") and (test("\\s") | not)' \
		"$WORK/resp" >/dev/null || die "enrollment key for $vm: no usable registration_key in the answer"
	jq -j .registration_key "$WORK/resp" >"$keyfile.tmp"
	rm -f "$WORK/resp"
	chmod 600 "$keyfile.tmp"
	mv "$keyfile.tmp" "$keyfile"
	json_set "$keys_json" '.[$vm] = {tenant: ($n | tonumber), tenant_id: $tid, key_id: $kid, expires_at: $exp, key_file: ("keys/" + $vm + ".key")}' \
		--arg vm "$vm" --arg n "$n" --arg tid "$tid" --arg kid "$kid" --arg exp "$exp"
	log "  $vm: key $kid (one use, expires $exp)"
}

mapfile -t tenants < <(uat_tenants "$UAT")
for n in 1 2; do
	[[ " ${tenants[*]} " == *" $n "* ]] || log "warning: no sprout in tenant $n; tenant $n is not created"
done

for n in "${tenants[@]}"; do
	tid="$(jq -r --arg n "$n" '.[$n].tenant_id // empty' "$tenants_json")"
	if [[ -n "$tid" ]]; then
		log "tenant $n: reusing $tid from $tenants_json"
	else
		create_tenant "$n"
		tid="$(jq -r --arg n "$n" '.[$n].tenant_id' "$tenants_json")"
	fi
	check_token_tenant "$n" "$tid"
	wait_active "$n" "$tid"
	mapfile -t vms < <(jq -r --arg n "$n" '.sprouts | to_entries[] | select((.value.tenant | tostring | ltrimstr("t")) == $n) | .key' "$UAT" | sort)
	for vm in "${vms[@]}"; do
		[[ "$vm" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "VM name '$vm' is not a plain host name"
		if ((NEW_KEYS == 0)) && [[ -s "$STATE/keys/$vm.key" ]] && jq -e --arg vm "$vm" --arg tid "$tid" '.[$vm].tenant_id == $tid' "$keys_json" >/dev/null; then
			log "  $vm: keeping key $(jq -r --arg vm "$vm" '.[$vm].key_id' "$keys_json")"
			continue
		fi
		mint_key "$n" "$tid" "$vm"
	done
done

jq -r 'to_entries[] | "tenant \(.key): \(.value.tenant_id) \(.value.status)"' "$tenants_json"
jq -r 'to_entries[] | "\(.key): tenant \(.value.tenant) key \(.value.key_id)"' "$keys_json"
