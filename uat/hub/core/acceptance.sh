#!/usr/bin/env bash
# acceptance.sh <kubeconfig> <endpoints.json> <state-dir> <verb> [args...]
#
# What uat/tests' acceptance cases (brief W1: B1, E1, D1, U1, RB1) need to
# see or nudge inside the core hub, beyond saasapi's and Envoy's own
# routes: the databases, the object store, Valkey, OpenBao, saasapi's
# operator plane, the workloads. Every verb prints one JSON line on stdout
# and exits 0; anything that can't be done exits 1 saying why on stderr.
# Nothing secret is printed: the PXC root password, Valkey's password, the
# OpenBao token and the RustFS root credential go from a Secret or the
# state directory over stdin into the pod, and the operator token into a
# header file, never onto a command line.
#
# Reads:
#   purge <tenant_id>
#       POST /v1/operator/tenants/<tenant_id>/purge on saasapi's operator
#       plane (kubectl port-forward, as operator-release.sh): prints
#       {"status": <http status>, "body": <response>}.
#   inventory                   (a JSON spec on stdin)
#       Counts what is stored for one tenant. The spec:
#         {"tenant_id": "t_...",
#          "tables": ["farmer.props", "saas.enrollment_keys", ...],
#          "objects": [{"category": "objects.recipes", "bucket": "recipes", "prefix": "tenants/t_.../"}],
#          "valkey": [{"category": "valkey.heartbeat", "pattern": "imas:heartbeat:{t_...:*"}],
#          "openbao_kv": ["secret/imas/tenant-x25519/tenants/t_..."],
#          "transit": ["transit/nats-tsign-t_..."]}
#       Prints {"counts": {"farmer.props": n, "objects.recipes": n,
#       "valkey.heartbeat": n, "kv:<path>": 0|1, "transit:<mount>/<key>":
#       0|1, ...}}. Tables are counted by tenant_id; buckets are recipes,
#       jobs, sprout_jwts, accounts or logs (RustFS only).
#   provisioning-jobs <tenant_id>
#       {"jobs": [{"id", "type", "status"}]}, oldest first.
#   props <tenant_id> <sprout_id>
#       {"props": [{"name", "value", "expires_in"}]}: farmer.props rows,
#       expires_in in seconds from now.
#   job-status <tenant_id> <sprout_id> <jid>
#       {"exists": bool, "status": "..."}: farmer.job_status.
#   valkey-get <key>
#       {"exists": bool, "value": "..."} (an imas:<kind>:{<tenant>:<sprout>} key).
#   objects <bucket> <prefix>
#       {"keys": [...]}: every key under prefix (RustFS only).
#   retention
#       The retention settings the workloads run with: {"farmer": {env},
#       "saasapi": {env}, "log_shipper": {"daemonset", "ready",
#       "configmap"}, "log_retention": {"cronjob", "schedule", "days"}}.
#   log-count <farmer|saasapi> <since_seconds>   (a fixed string on stdin)
#       {"count": n}: lines of the workload's logs since then holding it.
# Changes (UAT only; every one on rows or objects a test made, or a restart):
#   put-object <bucket> <key>   (the body on stdin)      {"status": 200}
#   delete-object <bucket> <key>                          {"status": 204}
#   backdate                    (a JSON spec on stdin)
#       Moves a tenant's rows' times back by "seconds":
#         {"tenant_id": "t_...", "seconds": 172800, "offboarded": true,
#          "provisioning_jobs": ["pj_..."], "batches": ["b_..."],
#          "enrollment_keys": ["ek_..."]}
#       offboarded: saas.tenants offboarded_at (an offboarded tenant's
#       retention delay starts there); provisioning_jobs: created_at and
#       updated_at; batches: the batch's created_at and lease_until and its
#       items' updated_at; enrollment_keys: expiry and created_at. Prints
#       {"updated": <rows>}.
#   restart <farmer|saasapi>
#       kubectl rollout restart, then waits for the rollout: {"restarted": name}.
#   sweep recipe-audit
#       Clears the recipe audit sweep's last run (farmer.job_leases row
#       recipe_audit_expiry, so the 23-hour minimum interval doesn't hold
#       it back) and restarts farmer, whose sweep runs at start:
#       {"sweep": "recipe-audit", "restarted": name}.
#   sweep log-retention
#       Runs the log retention CronJob once (a Job from it) and waits for
#       it: {"sweep": "log-retention", "job": name, "succeeded": true}.
#
# FLAG FOR SECURITY REVIEW: this reads the PXC root password, Valkey's
# password, the OpenBao root token and the RustFS root credential of a UAT
# hub, and changes rows and objects. UAT only.
set -euo pipefail
# A failure inside $(...) (a die in a helper) stops the script too.
shopt -s inherit_errexit
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
usage="acceptance.sh <kubeconfig> <endpoints.json> <state-dir> <verb> [args...] (the verbs are listed at the top of the script)"
parse_common_args "$usage" "$@"
shift 3
[[ $# -ge 1 ]] || die "usage: $usage"
verb=$1
shift
need_cmd kubectl jq base64

# --- argument checks ---------------------------------------------------------
tenant_re='^t_[a-z2-7]{16}$'
sprout_re='^[0-9a-z][-0-9_a-z]{0,252}$'
id_re='^(pj|b|ek)_[a-z2-7]{16}$'
jid_re='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
key_re='^[A-Za-z0-9._/-]{1,512}$'
want_tenant() { [[ "$1" =~ $tenant_re ]] || die "not a tenant ID: $1"; }
want_sprout() { [[ "$1" =~ $sprout_re ]] || die "not a sprout ID: $1"; }
# want_args <n> "$@": the verb was given exactly n arguments.
want_args() {
	local n=$1
	shift
	[[ $# -eq $n ]] || die "$verb takes $n argument(s), got $#: $usage"
}

# --- PXC ---------------------------------------------------------------------
# sql <statements>: runs them as root in the first PXC node and prints the
# rows tab-separated, without column names. The password goes from the
# Secret over stdin.
sql() {
	kc -n "$CORE_NS" get secret "$PXC_ROOT_SECRET" -o jsonpath='{.data.root}' | base64 -d |
		kc -n "$CORE_NS" exec -i "$PXC_CLUSTER-pxc-0" -c pxc -- /bin/sh -ec \
			'IFS= read -r p || [ -n "$p" ]; MYSQL_PWD="$p" mysql -uroot -N -B -e "$1"' _ "$1"
}
# in_list <id>...: a SQL list of quoted IDs, each checked against id_re
# (so nothing in it needs escaping). An empty list is ('') and matches
# nothing.
in_list() {
	local out="" id
	for id in "$@"; do
		[[ "$id" =~ $id_re ]] || die "not a row ID: $id"
		out+="${out:+,}'$id'"
	done
	printf '(%s)' "${out:-''}"
}

# --- the object store (RustFS) ---------------------------------------------
bucket_name() {
	case "$1" in
	recipes) printf '%s' "$RECIPE_BUCKET" ;;
	jobs) printf '%s' "$JOB_BUCKET" ;;
	sprout_jwts) printf '%s' "$SPROUT_JWT_BUCKET" ;;
	accounts) printf '%s' "$ACCOUNTS_BUCKET" ;;
	logs) printf '%s' "$LOG_BUCKET" ;;
	*) die "unknown bucket $1 (recipes, jobs, sprout_jwts, accounts or logs)" ;;
	esac
}
# rustfs <script>: runs script in the RustFS pod with rustfs-setup.sh's
# helper `rf METHOD PATH [BODYFILE]` (SigV4 with the root credential from
# the pod's own environment; the HTTP status on stdout, the body in
# /tmp/rf.out).
rustfs() {
	[[ "$S3_MODE" == rustfs ]] ||
		die "the object store is $S3_MODE: acceptance.sh reads and writes objects on the UAT's RustFS only (the single-node run and the local rig)"
	kc -n "$UAT_NS" exec -i "deploy/$RUSTFS_SVC" -c rustfs -- /bin/sh -ec '
rf() {
	m=$1; p=$2; f=${3:-}
	if [ -n "$f" ]; then h=$(sha256sum "$f" | cut -d" " -f1); set -- --data-binary "@$f"
	else h=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; set --; fi
	curl -sS -o /tmp/rf.out -w "%{http_code}" -X "$m" "$@" \
		--aws-sigv4 "aws:amz:us-east-1:s3" --user "$RUSTFS_ACCESS_KEY:$RUSTFS_SECRET_KEY" \
		-H "x-amz-content-sha256: $h" "http://127.0.0.1:9000$p"
}
'"$1"
}
uri() { jq -rn --arg v "$1" '$v | @uri'; }
# list_keys <bucket> <prefix>: every key under prefix, one per line.
list_keys() {
	local b p token="" out code
	b=$(bucket_name "$1")
	[[ -z "$2" || "$2" =~ $key_re ]] || die "not an object prefix: $2"
	p=$(uri "$2")
	while :; do
		# The query in canonical (sorted) order, the token only when there
		# is one.
		q="list-type=2&max-keys=1000&prefix=$p"
		[[ -z "$token" ]] || q="continuation-token=$(uri "$token")&$q"
		out=$(rustfs "c=\$(rf GET '/$b?$q'); echo \"\$c\"; cat /tmp/rf.out" </dev/null) ||
			die "listing $b/$2 failed"
		code=$(head -n 1 <<<"$out")
		[[ "$code" == 200 ]] || die "listing $b/$2: http $code"
		tail -n +2 <<<"$out" | grep -o '<Key>[^<]*</Key>' | sed -e 's/^<Key>//' -e 's/<\/Key>$//' || true
		grep -q '<IsTruncated>true</IsTruncated>' <<<"$out" || break
		token=$(tail -n +2 <<<"$out" | grep -o '<NextContinuationToken>[^<]*</NextContinuationToken>' |
			sed -e 's/^<NextContinuationToken>//' -e 's/<\/NextContinuationToken>$//')
		[[ -n "$token" ]] || die "listing $b/$2: truncated without a continuation token"
	done
}

# --- Valkey and OpenBao ---------------------------------------------------------
# valkey <args...>: valkey-cli in Valkey's primary, the password from the
# Secret over stdin (check.sh's valkey_cli).
valkey() {
	local target="deploy/$VALKEY_NAME"
	[[ $HA_CORE == true ]] && target="$VALKEY_NAME-0"
	kc -n "$CORE_NS" get secret "$VALKEY_AUTH_SECRET" -o json | jq -je --arg k "$VALKEY_AUTH_KEY" '.data[$k] | @base64d' |
		kc -n "$CORE_NS" exec -i "$target" -- /bin/sh -ec \
			'IFS= read -r VALKEY_PASSWORD || [ -n "$VALKEY_PASSWORD" ]; VALKEYCLI_AUTH="$VALKEY_PASSWORD" valkey-cli -e "$@"' _ "$@"
}
# bao_exists <path>: 1 if `bao read <path>` finds it, 0 if OpenBao says
# there is nothing there; anything else is an error. The root token from
# the state directory (openbao-bootstrap.sh) over stdin.
bao_exists() {
	local token_file="$SENSITIVE_DIR/openbao-root-token" out rc=0
	[[ -s "$token_file" ]] || die "no OpenBao token at $token_file (openbao-bootstrap.sh writes it)"
	out=$(kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- /bin/sh -ec \
		'IFS= read -r BAO_TOKEN || [ -n "$BAO_TOKEN" ]; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; bao read -format=json "$1" >/dev/null' _ "$1" \
		<"$token_file" 2>&1) || rc=$?
	if [[ $rc -eq 0 ]]; then
		echo 1
	elif grep -q 'No value found' <<<"$out"; then
		echo 0
	else
		die "bao read $1: $(tail -n 3 <<<"$out")"
	fi
}

# --- workloads --------------------------------------------------------------------
workload() {
	case "$1" in
	farmer) printf '%s' "$FARMER_FULLNAME" ;;
	saasapi) printf '%s' "$SAASAPI_FULLNAME" ;;
	*) die "unknown workload $1 (farmer or saasapi)" ;;
	esac
}
restart() {
	local name
	name=$(workload "$1")
	kc -n "$CORE_NS" rollout restart "deployment/$name" >&2 || die "kubectl rollout restart deployment/$name failed"
	kc -n "$CORE_NS" rollout status "deployment/$name" --timeout=600s >&2 || die "deployment/$name did not roll out within 600s"
	printf '%s' "$name"
}
# env_of <deployment> <container>: the container's literal env as a JSON object.
env_of() {
	kc -n "$CORE_NS" get deployment "$1" -o json |
		jq -c --arg c "$2" '[.spec.template.spec.containers[] | select(.name == $c) | .env[]? | select(has("value")) | {(.name): .value}] | add // {}'
}

case "$verb" in
purge)
	want_args 1 "$@"
	want_tenant "$1"
	need_cmd curl
	token_file="$SENSITIVE_DIR/$OPERATOR_TOKEN_FILE"
	[[ -s "$token_file" ]] || die "no operator token at $token_file: run saasapi-secrets.sh (install.sh) first"
	tmp=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/imas-uat-acceptance.XXXXXX")
	pf_pid=""
	trap '[[ -z "$pf_pid" ]] || kill "$pf_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
	kc -n "$CORE_NS" get secret "$OPERATOR_TLS_SECRET" -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d >"$tmp/ca.crt" ||
		die "can't read ca.crt of Secret $CORE_NS/$OPERATOR_TLS_SECRET"
	grep -q 'BEGIN CERTIFICATE' "$tmp/ca.crt" || die "Secret $CORE_NS/$OPERATOR_TLS_SECRET has no ca.crt"
	printf 'Authorization: Bearer %s\n' "$(tr -d '[:space:]' <"$token_file")" >"$tmp/auth.hdr"
	# As operator-release.sh: kubectl itself in the background, its log
	# there before it starts.
	: >"$tmp/pf.log"
	kubectl --kubeconfig "$KUBECONFIG_PATH" -n "$CORE_NS" port-forward "service/$SAASAPI_OPERATOR_FULLNAME" ":$SAASAPI_OPERATOR_PORT" >>"$tmp/pf.log" 2>&1 &
	pf_pid=$!
	lport=""
	for _ in $(seq 1 60); do
		lport=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> .*/\1/p' "$tmp/pf.log" | head -n 1)
		[[ -z "$lport" ]] || break
		kill -0 "$pf_pid" 2>/dev/null || die "kubectl port-forward to service/$SAASAPI_OPERATOR_FULLNAME failed: $(tail -n 3 "$tmp/pf.log")"
		sleep 0.5
	done
	[[ -n "$lport" ]] || die "kubectl port-forward to service/$SAASAPI_OPERATOR_FULLNAME gave no local port in 30s"
	code=$(curl -sS --proto '=https' --max-time 60 --cacert "$tmp/ca.crt" -X POST \
		--resolve "$OPERATOR_FQDN:$lport:127.0.0.1" -H "@$tmp/auth.hdr" \
		-o "$tmp/response.json" -w '%{http_code}' \
		"https://$OPERATOR_FQDN:$lport/v1/operator/tenants/$1/purge") || code=000
	[[ "$code" != 000 ]] || die "POST /v1/operator/tenants/$1/purge got no answer"
	[[ -s "$tmp/response.json" ]] && jq -e . "$tmp/response.json" >/dev/null 2>&1 || printf 'null' >"$tmp/response.json"
	jq -cn --argjson status "$((10#$code))" --slurpfile body "$tmp/response.json" '{status: $status, body: $body[0]}'
	;;
inventory)
	want_args 0 "$@"
	spec=$(cat)
	tenant=$(jq -er '.tenant_id' <<<"$spec") || die "the inventory spec has no tenant_id"
	want_tenant "$tenant"
	counts='{}'
	mapfile -t tables < <(jq -r '.tables[]?' <<<"$spec")
	if [[ ${#tables[@]} -gt 0 ]]; then
		q=""
		for t in "${tables[@]}"; do
			[[ "$t" =~ ^(farmer|saas)\.[a-z_]+$ ]] || die "not a farmer or saas table: $t"
			q+="SELECT '$t', COUNT(*) FROM $t WHERE tenant_id = '$tenant';"
		done
		rows=$(sql "$q") || die "counting the tenant's rows failed"
		counts=$(jq -c --arg rows "$rows" '. + ($rows | split("\n") | map(select(length > 0) | split("\t") | {(.[0]): (.[1] | tonumber)}) | add // {})' <<<"$counts")
	fi
	while IFS=$'\t' read -r cat b p; do
		[[ -n "$cat" ]] || continue
		[[ "$p" == *"$tenant"* ]] || die "object prefix $p is not the tenant's"
		n=$(list_keys "$b" "$p" | grep -c . || true)
		counts=$(jq -c --arg k "$cat" --argjson n "$n" '.[$k] = $n' <<<"$counts")
	done < <(jq -r '.objects[]? | [.category, .bucket, .prefix] | @tsv' <<<"$spec")
	while IFS=$'\t' read -r cat pattern; do
		[[ -n "$cat" ]] || continue
		[[ "$pattern" == "imas:"*"{$tenant:"* ]] || die "Valkey pattern $pattern is not the tenant's"
		n=$(valkey --scan --pattern "$pattern" | grep -c . || true)
		counts=$(jq -c --arg k "$cat" --argjson n "$n" '.[$k] = $n' <<<"$counts")
	done < <(jq -r '.valkey[]? | [.category, .pattern] | @tsv' <<<"$spec")
	while IFS= read -r path; do
		[[ -n "$path" ]] || continue
		[[ "$path" =~ ^[a-z0-9_-]+/[a-z0-9_./-]+$ && "$path" == *"/$tenant" ]] || die "not a tenant's KV path: $path"
		mount=${path%%/*}
		n=$(bao_exists "$mount/metadata/${path#*/}")
		counts=$(jq -c --arg k "kv:$path" --argjson n "$n" '.[$k] = $n' <<<"$counts")
	done < <(jq -r '.openbao_kv[]?' <<<"$spec")
	while IFS= read -r key; do
		[[ -n "$key" ]] || continue
		[[ "$key" =~ ^[a-z0-9_-]+/[a-z0-9_-]+$ && "$key" == *"-$tenant" ]] || die "not a tenant's Transit key: $key"
		n=$(bao_exists "${key%%/*}/keys/${key#*/}")
		counts=$(jq -c --arg k "transit:$key" --argjson n "$n" '.[$k] = $n' <<<"$counts")
	done < <(jq -r '.transit[]?' <<<"$spec")
	jq -c '{counts: .}' <<<"$counts"
	;;
provisioning-jobs)
	want_args 1 "$@"
	want_tenant "$1"
	rows=$(sql "SELECT id, type, status FROM saas.provisioning_jobs WHERE tenant_id = '$1' ORDER BY created_at, id") ||
		die "reading the tenant's provisioning jobs failed"
	jq -cn --arg rows "$rows" '{jobs: ($rows | split("\n") | map(select(length > 0) | split("\t") | {id: .[0], type: .[1], status: .[2]}))}'
	;;
props)
	want_args 2 "$@"
	want_tenant "$1"
	want_sprout "$2"
	# mysql -B writes a tab, a newline or a backslash in a value as \t, \n
	# or \\, so every row is one line of three fields.
	rows=$(sql "SELECT name, value, TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), expiry) FROM farmer.props WHERE tenant_id = '$1' AND sprout_id = '$2' ORDER BY name") ||
		die "reading the sprout's props failed"
	jq -cn --arg rows "$rows" '{props: ($rows | split("\n") | map(select(length > 0) | split("\t") | {name: .[0], value: .[1], expires_in: (.[2] | tonumber)}))}'
	;;
job-status)
	want_args 3 "$@"
	want_tenant "$1"
	want_sprout "$2"
	[[ "$3" =~ $jid_re ]] || die "not a job ID: $3"
	st=$(sql "SELECT status FROM farmer.job_status WHERE tenant_id = '$1' AND sprout_id = '$2' AND jid = '$3'") ||
		die "reading the job's status failed"
	jq -cn --arg s "$st" '{exists: ($s != ""), status: $s}'
	;;
valkey-get)
	want_args 1 "$@"
	[[ "$1" =~ ^imas:[a-z]+:\{t_[a-z2-7]{16}:[0-9a-z][-0-9_a-z]*\}$ ]] || die "not a sprout's Valkey key: $1"
	n=$(valkey exists "$1") || die "Valkey EXISTS failed"
	v=""
	[[ "$n" == 1 ]] && { v=$(valkey get "$1") || die "Valkey GET failed"; }
	jq -cn --argjson e "$([[ "$n" == 1 ]] && echo true || echo false)" --arg v "$v" '{exists: $e, value: $v}'
	;;
objects)
	want_args 2 "$@"
	list_keys "$1" "$2" | jq -Rsc '{keys: (split("\n") | map(select(length > 0)))}'
	;;
put-object | delete-object)
	want_args 2 "$@"
	b=$(bucket_name "$1")
	[[ "$2" =~ $key_re && "$2" != *..* ]] || die "not an object key: $2"
	if [[ "$verb" == put-object ]]; then
		code=$(rustfs "cat > /tmp/obj; rf PUT '/$b/$2' /tmp/obj; rm -f /tmp/obj") || die "PUT $b/$2 failed"
		[[ "$code" == 200 ]] || die "PUT $b/$2: http $code"
	else
		code=$(rustfs "rf DELETE '/$b/$2'" </dev/null) || die "DELETE $b/$2 failed"
		[[ "$code" == 204 || "$code" == 200 ]] || die "DELETE $b/$2: http $code"
	fi
	jq -cn --argjson s "$code" '{status: $s}'
	;;
backdate)
	want_args 0 "$@"
	spec=$(cat)
	tenant=$(jq -er '.tenant_id' <<<"$spec") || die "the backdate spec has no tenant_id"
	want_tenant "$tenant"
	secs=$(jq -er '.seconds | select(type == "number" and . > 0 and . <= 31536000 and . == floor)' <<<"$spec") ||
		die "the backdate spec's seconds must be a whole number from 1 to 31536000"
	mapfile -t jobs < <(jq -r '.provisioning_jobs[]?' <<<"$spec")
	mapfile -t batches < <(jq -r '.batches[]?' <<<"$spec")
	mapfile -t keys < <(jq -r '.enrollment_keys[]?' <<<"$spec")
	q=""
	if jq -e '.offboarded == true' <<<"$spec" >/dev/null; then
		q+="UPDATE saas.tenants SET offboarded_at = COALESCE(offboarded_at, updated_at) - INTERVAL $secs SECOND WHERE id = '$tenant' AND status = 'offboarded'; SELECT ROW_COUNT();"
	fi
	if [[ ${#jobs[@]} -gt 0 ]]; then
		q+="UPDATE saas.provisioning_jobs SET created_at = created_at - INTERVAL $secs SECOND, updated_at = updated_at - INTERVAL $secs SECOND WHERE tenant_id = '$tenant' AND id IN $(in_list "${jobs[@]}"); SELECT ROW_COUNT();"
	fi
	if [[ ${#batches[@]} -gt 0 ]]; then
		# The batch's lease too: the prune passes over a leased batch.
		q+="UPDATE saas.asset_action_batches SET created_at = created_at - INTERVAL $secs SECOND, lease_until = lease_until - INTERVAL $secs SECOND WHERE tenant_id = '$tenant' AND id IN $(in_list "${batches[@]}"); SELECT ROW_COUNT();"
		q+="UPDATE saas.asset_action_items SET updated_at = updated_at - INTERVAL $secs SECOND WHERE tenant_id = '$tenant' AND batch_id IN $(in_list "${batches[@]}"); SELECT ROW_COUNT();"
	fi
	if [[ ${#keys[@]} -gt 0 ]]; then
		q+="UPDATE saas.enrollment_keys SET expiry = expiry - INTERVAL $secs SECOND, created_at = created_at - INTERVAL $secs SECOND WHERE tenant_id = '$tenant' AND key_id IN $(in_list "${keys[@]}"); SELECT ROW_COUNT();"
	fi
	[[ -n "$q" ]] || die "the backdate spec names nothing to move"
	rows=$(sql "$q") || die "moving the rows' times failed"
	jq -cn --arg rows "$rows" '{updated: ($rows | split("\n") | map(select(length > 0) | tonumber) | add)}'
	;;
restart)
	want_args 1 "$@"
	name=$(restart "$1")
	jq -cn --arg n "$name" '{restarted: $n}'
	;;
sweep)
	want_args 1 "$@"
	case "$1" in
	recipe-audit)
		sql "UPDATE farmer.job_leases SET last_run_at = NULL WHERE name = 'recipe_audit_expiry'" >/dev/null ||
			die "clearing the recipe audit sweep's last run failed"
		name=$(restart farmer)
		jq -cn --arg n "$name" '{sweep: "recipe-audit", restarted: $n}'
		;;
	log-retention)
		job="imas-uat-log-retention-$(date +%s)"
		kc -n "$CORE_NS" create job "$job" --from="cronjob/$LOG_RETENTION_CRONJOB" >&2 ||
			die "creating a Job from cronjob/$LOG_RETENTION_CRONJOB failed (is logShipping on?)"
		if ! kc -n "$CORE_NS" wait "job/$job" --for=condition=complete --timeout=600s >&2; then
			logs=$(kc -n "$CORE_NS" logs "job/$job" --tail=20 2>&1 || true)
			kc -n "$CORE_NS" delete job "$job" --wait=false >/dev/null 2>&1 || true
			die "the log retention Job $job did not complete within 600s: $logs"
		fi
		kc -n "$CORE_NS" delete job "$job" --wait=false >/dev/null 2>&1 || true
		jq -cn --arg j "$job" '{sweep: "log-retention", job: $j, succeeded: true}'
		;;
	*) die "sweep recipe-audit or sweep log-retention" ;;
	esac
	;;
retention)
	want_args 0 "$@"
	fe=$(env_of "$FARMER_FULLNAME" farmer) || die "reading $FARMER_FULLNAME failed"
	se=$(env_of "$SAASAPI_FULLNAME" saasapi) || die "reading $SAASAPI_FULLNAME failed"
	ds=$(kc -n "$CORE_NS" get daemonset "$LOG_SHIPPER_DS" -o json 2>/dev/null || echo null)
	cm=false
	kc -n "$CORE_NS" get configmap "$LOG_SHIPPER_DS" >/dev/null 2>&1 && cm=true
	cj=$(kc -n "$CORE_NS" get cronjob "$LOG_RETENTION_CRONJOB" -o json 2>/dev/null || echo null)
	jq -cn --argjson fe "$fe" --argjson se "$se" --argjson ds "$ds" --argjson cm "$cm" --argjson cj "$cj" '{
		farmer: $fe, saasapi: $se,
		log_shipper: {daemonset: ($ds != null), configmap: $cm,
			ready: ($ds != null and ($ds.status.desiredNumberScheduled // 0) > 0 and ($ds.status.numberReady // 0) == $ds.status.desiredNumberScheduled)},
		log_retention: {cronjob: ($cj != null), schedule: ($cj.spec.schedule // ""),
			days: ([$cj.spec.jobTemplate.spec.template.spec.containers[]?.args[]? | strings | select(startswith("-days=")) | ltrimstr("-days=") | tonumber] | first // 0)}}'
	;;
log-count)
	want_args 2 "$@"
	name=$(workload "$1")
	[[ "$2" =~ ^[0-9]{1,6}$ ]] || die "since must be seconds"
	needle=$(cat)
	[[ -n "$needle" && ${#needle} -le 200 ]] || die "the string to count is empty or too long"
	sel=$(kc -n "$CORE_NS" get deployment "$name" -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")') ||
		die "reading deployment/$name failed"
	n=$(kc -n "$CORE_NS" logs -l "$sel" -c "$1" --since="${2}s" --tail=-1 --max-log-requests=10 2>/dev/null | grep -cF -- "$needle" || true)
	jq -cn --argjson n "${n:-0}" '{count: $n}'
	;;
*) die "unknown verb $verb: $usage" ;;
esac
