#!/usr/bin/env bash
# check.sh <kubeconfig> <endpoints.json> <state-dir>
#
# Confirms the core hub is up, after install.sh:
#   - farmer, saasapi, PXC (cluster, pxc and haproxy), Valkey and OpenBao
#     (initialised, unsealed, the ed25519 gateway key) are Ready, and so
#     are RustFS, Keycloak and the edge proxy;
#   - on an HA core hub (several core nodes; values/values-ha.yaml): farmer,
#     saasapi and Versity Gateway run 3 replicas on 3 different nodes, the
#     edge one per node, PXC 3 nodes and 3 HAProxy, Valkey a primary and 2
#     replicas, and OpenBao 3 raft pods, every one unsealed (static seal)
#     and a voter;
#   - design T4 (docs/design/imas-openbao-signing-design.md section 11, the
#     OpenBao bootstrap Job): the trust ConfigMap is complete, public, and
#     byte for byte what the first install wrote, so re-runs (finish.sh's
#     upgrade, an install.sh re-run) wrote nothing; the token the Job was
#     handed is revoked and its Secret gone; the ephemeral policy
#     imas-nats-bootstrap is deleted; farmer's and the publish Job's
#     policies cannot sign with the operator identity key; the three
#     platform Transit keys are hardened. farmer being Ready also means
#     its start-up check found the trust matching Transit;
#   - the migration finished: the release is deployed (its migrate hook
#     succeeded), no failed migrate Job is left, and both schemas carry
#     applied goose versions;
#   - every imas image runs the release's version, never latest;
#   - Keycloak's issuer on the core FQDN is the one saasapi is configured
#     with, and its tokens carry that iss, saasapi's audience and the roles;
#   - saasapi answers GET /v1/versions with each tenant admin's Keycloak
#     token (and the BFF secret), and refuses a request with no token,
#     with no BFF secret, with neither, and with a forged token: each
#     refusal is checked by status and by the error code of saasapi's JSON
#     body ({"error": "unauthorized"}), so a 401 from anything else (the
#     edge proxy, a wrong route) fails the check. saasapi gives every
#     authentication failure the one code on purpose (internal/saasapi
#     middleware.go): the reason is in its log, never on the wire;
#   - once bind-tenant.sh has run: each admin reads its own tenant and is
#     refused on the other's (403, error code forbidden);
#   - the operator plane is on (P20 option C): its listener address, TLS
#     Secret and token Secret, and the fleet update flags are what the
#     install was asked for (core.json dispatch_flags: saasapi
#     SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED, farmer IMAS_SELF_UPDATE_ENABLED).
# Prints one line per check and exits non zero if any failed. Nothing
# secret is printed.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "check.sh <kubeconfig> <endpoints.json> <state-dir>" "$@"
need_cmd kubectl helm jq curl base64

core_json="$OUT_DIR/core.json"
[[ -s "$core_json" ]] || die "no $core_json: run install.sh first"
version=$(jq -r .version "$core_json")
ca="$OUT_DIR/uat-ca.crt"
ias="$SENSITIVE_DIR/internal-auth-secret"
[[ -s "$ca" && -s "$ias" ]] || die "missing $ca or $ias"

failed=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() {
	printf 'FAIL  %s%s\n' "$1" "${2:+: $2}"
	failed=$((failed + 1))
}
# check <description> <command...>
check() {
	local what="$1"
	shift
	if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

deploy_ready() {
	kc -n "$2" get deployment "$1" -o json |
		jq -e '(.spec.replicas // 0) > 0 and (.status.readyReplicas // 0) == .spec.replicas and (.status.updatedReplicas // 0) == .spec.replicas' >/dev/null
}

# --- workloads ---------------------------------------------------------------
check "farmer ($FARMER_FULLNAME) Ready" deploy_ready "$FARMER_FULLNAME" "$CORE_NS"
check "saasapi ($SAASAPI_FULLNAME) Ready" deploy_ready "$SAASAPI_FULLNAME" "$CORE_NS"
check "PXC cluster $PXC_CLUSTER state ready" pxc_ready "$PXC_CLUSTER" "$CORE_NS"
check "PXC statefulset $PXC_CLUSTER-pxc Ready" sts_ready "$PXC_CLUSTER-pxc" "$CORE_NS"
check "PXC HAProxy $PXC_CLUSTER-haproxy Ready" sts_ready "$PXC_CLUSTER-haproxy" "$CORE_NS"
check "Valkey ($VALKEY_NAME) Ready" valkey_ready
check "OpenBao ($OPENBAO_STS) Ready" sts_ready "$OPENBAO_STS" "$CORE_NS"
[[ "$S3_MODE" == rustfs ]] && check "RustFS Ready (UAT)" deploy_ready "$RUSTFS_SVC" "$UAT_NS"
check "Keycloak Ready" deploy_ready "$KEYCLOAK_DEPLOY" "$UAT_NS"
check "edge proxy Ready" deploy_ready "$EDGE_DEPLOY" "$UAT_NS"

# --- HA core hub --------------------------------------------------------------
# replicas_on_nodes <kind> <name> <ns> <n>: n replicas, all Ready, and the
# pods (by the workload's own selector) on n different nodes.
replicas_on_nodes() {
	local obj sel
	obj=$(kc -n "$3" get "$1" "$2" -o json) || return 1
	jq -e --argjson n "$4" '.spec.replicas == $n and (.status.readyReplicas // 0) == $n' <<<"$obj" >/dev/null || return 1
	sel=$(jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")' <<<"$obj")
	kc -n "$3" get pods -l "$sel" -o json |
		jq -e --argjson n "$4" '[.items[] | select(.metadata.deletionTimestamp == null) | .spec.nodeName] | (length == $n) and (unique | length == $n)' >/dev/null
}
if [[ $HA_CORE == true ]]; then
	check "HA: farmer runs 3 replicas on 3 nodes" replicas_on_nodes deployment "$FARMER_FULLNAME" "$CORE_NS" 3
	check "HA: saasapi runs 3 replicas on 3 nodes" replicas_on_nodes deployment "$SAASAPI_FULLNAME" "$CORE_NS" 3
	check "HA: Versity Gateway runs 3 replicas on 3 nodes" replicas_on_nodes deployment "$VERSITY_FULLNAME" "$CORE_NS" 3
	check "HA: the edge proxy runs one pod on each of the $CORE_NODE_COUNT nodes" replicas_on_nodes deployment "$EDGE_DEPLOY" "$UAT_NS" "$CORE_NODE_COUNT"
	check "HA: OpenBao runs 3 raft pods on 3 nodes" replicas_on_nodes statefulset "$OPENBAO_STS" "$CORE_NS" 3
	check "HA: PXC runs 3 nodes on 3 nodes" replicas_on_nodes statefulset "$PXC_CLUSTER-pxc" "$CORE_NS" 3
	check "HA: PXC HAProxy runs 3 pods on 3 nodes" replicas_on_nodes statefulset "$PXC_CLUSTER-haproxy" "$CORE_NS" 3
	check "HA: Valkey runs a primary and 2 replicas on 3 nodes" replicas_on_nodes statefulset "$VALKEY_NAME" "$CORE_NS" 3
	for ((i = 0; i < 3; i++)); do
		st=$(kc -n "$CORE_NS" exec "$OPENBAO_STS-$i" -c openbao -- env BAO_ADDR=http://127.0.0.1:8200 bao status -format=json 2>/dev/null || true)
		check "HA: OpenBao $OPENBAO_STS-$i unsealed by the static seal" jq -e '.initialized == true and .sealed == false and .type == "static"' <<<"${st:-{\}}"
	done
fi
for s in "$SAASAPI_NATS_SECRET" "$SAASAPI_BOX_SECRET" "$SEEDS_SECRET" "$FARMER_NKEY_SECRET" "$INTERNAL_AUTH_SECRET" "$OPERATOR_TLS_SECRET" "$OPERATOR_TOKEN_SECRET"; do
	check "Secret $CORE_NS/$s exists" kc -n "$CORE_NS" get secret "$s"
done

bao_st=$(kc -n "$CORE_NS" exec "$OPENBAO_POD" -c openbao -- env BAO_ADDR=http://127.0.0.1:8200 bao status -format=json 2>/dev/null || true)
[[ -n "$bao_st" ]] || bao_st='{}'
check "OpenBao initialised and unsealed" jq -e '.initialized == true and .sealed == false' <<<"$bao_st"
token_file="$SENSITIVE_DIR/openbao-root-token"
if [[ $HA_CORE == true ]]; then
	voters=$(kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- /bin/sh -ec \
		'IFS= read -r BAO_TOKEN || [ -n "$BAO_TOKEN" ]; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; bao operator raft list-peers -format=json' \
		<"$token_file" 2>/dev/null || true)
	check "HA: OpenBao storage is raft with 3 voters and a leader" \
		jq -e '[.data.config.servers[] | select(.voter)] | length == 3 and (map(select(.leader)) | length == 1)' <<<"${voters:-{\}}"
else
	check "OpenBao storage is single-node raft, active" jq -e '.storage_type == "raft" and .is_self == true' <<<"$bao_st"
fi
if [[ -s "$token_file" ]]; then
	key_type=$(kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- /bin/sh -ec \
		'IFS= read -r BAO_TOKEN || [ -n "$BAO_TOKEN" ]; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; bao read -field=type transit/keys/'"$GATEWAY_KEY" \
		<"$token_file" 2>/dev/null || true)
	check "transit/keys/$GATEWAY_KEY is ed25519" test "$key_type" = ed25519
else
	fail "transit/keys/$GATEWAY_KEY" "no root token at $token_file"
fi

# --- design T4: the OpenBao bootstrap Job ----------------------------------
trust_now=$(trust_snapshot 2>/dev/null || true)
[[ -n "$trust_now" ]] || trust_now='null'
check "ConfigMap $CORE_NS/$NATS_TRUST_CONFIGMAP holds ${NATS_TRUST_KEYS[*]}" \
	jq -e --args '. as $d | all($ARGS.positional[]; ($d.data[.] // "") | length > 0)' "${NATS_TRUST_KEYS[@]}" <<<"$trust_now"
check "T4: ConfigMap $CORE_NS/$NATS_TRUST_CONFIGMAP holds no NKey seed" \
	jq -e '.data | type == "object" and all(.[]; test("(^|[^A-Z2-7])S[A-Z2-7]{57}([^A-Z2-7]|$)") | not)' <<<"$trust_now"
if [[ -s "$OUT_DIR/nats-trust.json" ]]; then
	check "T4: the trust is byte for byte what the first install wrote (re-runs wrote nothing)" \
		test "$trust_now" = "$(cat "$OUT_DIR/nats-trust.json")"
else
	fail "T4: the first trust" "no $OUT_DIR/nats-trust.json (install.sh records it)"
fi
secret_absent() { ! kc -n "$CORE_NS" get secret "$1" >/dev/null 2>&1; }
check "T4: no bootstrap token Secret left ($CORE_NS/$OPENBAO_ROOT_SECRET)" secret_absent "$OPENBAO_ROOT_SECRET"
if [[ -s "$token_file" ]]; then
	while IFS= read -r line; do
		case "$line" in
		PASS\ *) pass "${line#PASS }" ;;
		FAIL\ *) fail "${line#FAIL }" ;;
		esac
	done < <(openbao_t4 "$token_file" "$SENSITIVE_DIR/openbao-bootstrap-token")
else
	fail "T4: OpenBao checks" "no root token at $token_file"
fi

# --- migration ---------------------------------------------------------------
check "helm release $CORE_RELEASE deployed (its migrate hook succeeded)" \
	bash -c '[[ "$(helm --kubeconfig "$1" -n "$2" status "$3" -o json | jq -r .info.status)" == deployed ]]' _ \
	"$KUBECONFIG_PATH" "$CORE_NS" "$CORE_RELEASE"
failed_jobs=$(kc -n "$CORE_NS" get jobs -o json 2>/dev/null |
	jq -r '[.items[] | select(.metadata.name | test("db-migrate")) | select((.status.failed // 0) > 0 and (.status.succeeded // 0) == 0) | .metadata.name] | join(",")')
check "no failed migrate Job${failed_jobs:+ ($failed_jobs)}" test -z "$failed_jobs"
goose=$(kc -n "$CORE_NS" get secret "$PXC_ROOT_SECRET" -o jsonpath='{.data.root}' 2>/dev/null | base64 -d |
	kc -n "$CORE_NS" exec -i "$PXC_CLUSTER-pxc-0" -c pxc -- /bin/sh -ec \
		'IFS= read -r p || [ -n "$p" ]; MYSQL_PWD="$p" mysql -uroot -N -B -e "SELECT COALESCE(MAX(version_id),0) FROM farmer.goose_db_version WHERE is_applied=1; SELECT COALESCE(MAX(version_id),0) FROM saas.goose_db_version WHERE is_applied=1"' \
		2>/dev/null || true)
check "farmer and saas schemas migrated (goose versions: $(tr '\n' ' ' <<<"$goose"))" \
	bash -c '[[ $(grep -cE "^[1-9][0-9]*$" <<<"$1") -eq 2 ]]' _ "$goose"

# --- images ------------------------------------------------------------------
bad_images=$(kc -n "$CORE_NS" get pods -o json | jq -r --arg v "$version" '
	[.items[].spec | (.containers + (.initContainers // []))[] | .image
	 | select(test("^ghcr.io/yogzblr/imas-")) | select(test(":" + ($v | gsub("\\."; "\\.")) + "(@sha256:[0-9a-f]+)?$") | not)]
	| unique | join(" ")')
check "imas images are $version${bad_images:+ (not: $bad_images)}" test -z "$bad_images"
pods_json=$(kc get pods -n "$CORE_NS" -o json && kc get pods -n "$UAT_NS" -o json)
latest=$(jq -rs '[.[].items[].spec | (.containers + (.initContainers // []))[] | .image | select(test(":latest$") or (contains(":") | not))] | unique | join(" ")' <<<"$pods_json")
check "no image runs latest or untagged${latest:+ (found: $latest)}" test -z "$latest"

# --- Keycloak issuer ---------------------------------------------------------
curl_tls() { curl -sS --proto '=https' --cacert "$ca" --max-time 20 "$@"; }
disco=$(curl_tls "$KEYCLOAK_ISSUER/.well-known/openid-configuration" 2>/dev/null || true)
jq -e 'type == "object"' <<<"$disco" >/dev/null 2>&1 || disco='{}'
check "Keycloak issuer is $KEYCLOAK_ISSUER" jq -e --arg i "$KEYCLOAK_ISSUER" '.issuer == $i' <<<"$disco"
check "Keycloak jwks_uri is saasapi's JWKS URL" jq -e --arg j "$KEYCLOAK_JWKS_URL" '.jwks_uri == $j' <<<"$disco"
saas_env=$(kc -n "$CORE_NS" get deployment "$SAASAPI_FULLNAME" -o json |
	jq '[.spec.template.spec.containers[] | select(.name == "saasapi") | .env[] | {(.name): .value}] | add')
check "saasapi SAASAPI_JWT_ISSUER is the Keycloak issuer" jq -e --arg i "$KEYCLOAK_ISSUER" '.SAASAPI_JWT_ISSUER == $i' <<<"$saas_env"
check "saasapi SAASAPI_KEYCLOAK_JWKS_URL is on the core FQDN" jq -e --arg j "$KEYCLOAK_JWKS_URL" '.SAASAPI_KEYCLOAK_JWKS_URL == $j' <<<"$saas_env"
check "saasapi SAASAPI_JWT_AUDIENCE is $SAASAPI_AUDIENCE" jq -e --arg a "$SAASAPI_AUDIENCE" '.SAASAPI_JWT_AUDIENCE == $a' <<<"$saas_env"

# --- operator plane and fleet update flags ------------------------------------
check "saasapi runs its operator listener (SAASAPI_OPERATOR_LISTEN_ADDR on :$SAASAPI_OPERATOR_PORT)" \
	jq -e --arg p ":$SAASAPI_OPERATOR_PORT" '(.SAASAPI_OPERATOR_LISTEN_ADDR // "") | endswith($p)' <<<"$saas_env"
dispatch=$(jq -r '.dispatch_flags // "off"' "$core_json")
want_flag=false
[[ "$dispatch" != on ]] || want_flag=true
farmer_env=$(kc -n "$CORE_NS" get deployment "$FARMER_FULLNAME" -o json |
	jq '[.spec.template.spec.containers[] | select(.name == "farmer") | .env[] | {(.name): .value}] | add')
check "saasapi SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED is $want_flag (dispatch_flags $dispatch)" \
	jq -e --arg w "$want_flag" '.SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED == $w' <<<"$saas_env"
check "farmer IMAS_SELF_UPDATE_ENABLED is $want_flag (dispatch_flags $dispatch)" \
	jq -e --arg w "$want_flag" '.IMAS_SELF_UPDATE_ENABLED == $w' <<<"$farmer_env"

# --- tokens and saasapi -------------------------------------------------------
# status <token or ""> <send BFF secret: 1|0> <path>: the HTTP status, and
# after a space the error code of saasapi's JSON error body when there is
# one ("401 unauthorized", "403 forbidden", "200"). Secrets go in header
# files, not argv.
status() {
	local tok="$1" bff="$2" path="$3" hdr=() tokhdr="" code body
	if [[ "$bff" == 1 ]]; then hdr+=(-H "@$ias.hdr"); fi
	if [[ -n "$tok" ]]; then
		# A real file, not -H @<(...): a process substitution stored in an
		# array is closed before curl runs, so curl sent no Authorization
		# header at all (older curl silently, newer curl with an error).
		tokhdr=$(umask 077 && mktemp "${TMPDIR:-/tmp}/imas-uat-auth.XXXXXX")
		printf 'Authorization: Bearer %s\n' "$tok" >"$tokhdr"
		hdr+=(-H "@$tokhdr")
	fi
	body=$(umask 077 && mktemp "${TMPDIR:-/tmp}/imas-uat-body.XXXXXX")
	code=$(curl_tls -o "$body" -w '%{http_code}' "${hdr[@]}" "$SAASAPI_URL$path" 2>/dev/null) || code=000
	[[ -z "$tokhdr" ]] || rm -f "$tokhdr"
	status_line "$code" "$body"
	rm -f "$body"
}
(umask 077 && printf 'X-Internal-Auth: %s\n' "$(cat "$ias")" >"$ias.hdr")
trap 'rm -f "$ias.hdr"' EXIT

declare -A TOK
for u in "${UAT_USERS[@]}"; do
	TOK[$u]=$("$here/token.sh" "$KUBECONFIG_PATH" "$ENDPOINTS" "$STATE_ROOT" "$u" 2>/dev/null || true)
	check "Keycloak issues a token to $u" test -n "${TOK[$u]}"
done
for u in "${UAT_USERS[@]}"; do
	[[ -n "${TOK[$u]}" ]] || continue
	claims=$(jwt_payload "${TOK[$u]}")
	check "$u token iss is the issuer" jq -e --arg i "$KEYCLOAK_ISSUER" '.iss == $i' <<<"$claims"
	check "$u token aud includes $SAASAPI_AUDIENCE" jq -e --arg a "$SAASAPI_AUDIENCE" '(.aud | if type == "array" then . else [.] end) | index($a)' <<<"$claims"
	if [[ "$u" == *-admin ]]; then
		check "$u token has $READ_ROLE and $WRITE_ROLE" jq -e --arg r "$READ_ROLE" --arg w "$WRITE_ROLE" \
			'(.realm_access.roles | index($r)) and (.realm_access.roles | index($w))' <<<"$claims"
	else
		check "$u token has $READ_ROLE and not $WRITE_ROLE" jq -e --arg r "$READ_ROLE" --arg w "$WRITE_ROLE" \
			'(.realm_access.roles | index($r)) and ((.realm_access.roles | index($w)) | not)' <<<"$claims"
	fi
done

for u in t1-admin t2-admin; do
	got=$(status "${TOK[$u]:-}" 1 /v1/versions)
	check "saasapi answers $u's token: GET /v1/versions is 200 (got $got)" test "$got" = 200
done
got=$(status "" 1 /v1/versions)
check "saasapi refuses a request with no token: 401 unauthorized (got $got)" test "$got" = "401 unauthorized"
got=$(status "" 0 /v1/versions)
check "saasapi refuses a request with no token and no BFF secret: 401 unauthorized (got $got)" test "$got" = "401 unauthorized"
got=$(status "${TOK[t1-admin]:-}" 0 /v1/versions)
check "saasapi refuses a valid token without the BFF secret: 401 unauthorized (got $got)" test "$got" = "401 unauthorized"
other_tok=$("$here/token.sh" "$KUBECONFIG_PATH" "$ENDPOINTS" "$STATE_ROOT" t1-admin other 2>/dev/null || true)
check "Keycloak issues a token to t1-admin on $OTHER_CLIENT" test -n "$other_tok"
if [[ -n "$other_tok" ]]; then
	check "$OTHER_CLIENT token lacks $SAASAPI_AUDIENCE" jq -e --arg a "$SAASAPI_AUDIENCE" \
		'(.aud // [] | if type == "array" then . else [.] end) | index($a) | not' <<<"$(jwt_payload "$other_tok")"
	got=$(status "$other_tok" 1 /v1/versions)
	check "saasapi refuses a token without its audience: 401 unauthorized (got $got)" test "$got" = "401 unauthorized"
fi
forged="${TOK[t1-admin]:-x.y.z}"
forged="${forged%.*}.AAAA"
got=$(status "$forged" 1 /v1/versions)
check "saasapi refuses a token with a bad signature: 401 unauthorized (got $got)" test "$got" = "401 unauthorized"

# Tenant scoping, once UAT.4 has created the tenants and bind-tenant.sh has
# mapped them.
t1=$(jq -r '.tenants["1"] // empty' "$core_json")
t2=$(jq -r '.tenants["2"] // empty' "$core_json")
if [[ -n "$t1" && -n "$t2" ]]; then
	check "t1-admin token organization.id is $t1" jq -e --arg t "$t1" '.organization.id == $t' <<<"$(jwt_payload "${TOK[t1-admin]:-x.e30.x}")"
	check "t2-admin token organization.id is $t2" jq -e --arg t "$t2" '.organization.id == $t' <<<"$(jwt_payload "${TOK[t2-admin]:-x.e30.x}")"
	got=$(status "${TOK[t1-admin]:-}" 1 "/v1/tenants/$t1")
	check "t1-admin reads tenant 1: 200 (got $got)" test "$got" = 200
	got=$(status "${TOK[t1-admin]:-}" 1 "/v1/tenants/$t2")
	check "t1-admin is refused on tenant 2: 403 forbidden (got $got)" test "$got" = "403 forbidden"
	got=$(status "${TOK[t2-admin]:-}" 1 "/v1/tenants/$t2")
	check "t2-admin reads tenant 2: 200 (got $got)" test "$got" = 200
	got=$(status "${TOK[t2-admin]:-}" 1 "/v1/tenants/$t1")
	check "t2-admin is refused on tenant 1: 403 forbidden (got $got)" test "$got" = "403 forbidden"
else
	printf 'SKIP  tenant scoping: tenants not bound yet (UAT.4 creates them; bind-tenant.sh maps them)\n'
fi

if ((failed)); then
	printf '%d check(s) failed\n' "$failed"
	exit 1
fi
printf 'all checks passed\n'
