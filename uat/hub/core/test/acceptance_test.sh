#!/usr/bin/env bash
# test/acceptance_test.sh: acceptance.sh (the in-cluster reads and changes
# of uat/tests' W1 cases) against a stub kubectl and curl
# (test/acceptance-stubs). Run by test/run.sh and core_test.go's
# TestAcceptanceScript.
#   - without containers: the argument checks, the operator purge (the
#     token in a header file, never argv), restart, the log retention Job,
#     the retention settings and log-count;
#   - with Docker: the stub kubectl's exec runs in real containers, so the
#     SQL runs on PXC 8.4 (the farmer chart's image) with the repository's
#     farmer and saas migrations, the objects on the UAT's RustFS image, the
#     Valkey reads on Valkey 9.1.2 (the chart's) with a password, and the
#     OpenBao reads on an OpenBao dev server. Without Docker (or without the images) that part is reported
#     SKIPPED, never passed.
# The checks use `test && ok || bad` on purpose: ok and bad always return 0.
# shellcheck disable=SC2015
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
core=$(cd "$here/.." && pwd)
repo=$(cd "$core/../../.." && pwd)
tmp=$(mktemp -d)
containers=()
cleanup() {
	[[ ${#containers[@]} -eq 0 ]] || docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

failed=0 skipped=()
ok() { printf 'ok    %s\n' "$1"; }
bad() {
	printf 'FAIL  %s\n' "$1"
	failed=$((failed + 1))
}
skip() {
	printf 'SKIP  %s\n' "$1"
	skipped+=("$1")
}

export PATH="$here/acceptance-stubs:$PATH"
export ACC_STATE="$tmp/stub"
mkdir -p "$ACC_STATE"
kubeconfig="$tmp/kubeconfig"
echo "apiVersion: v1" >"$kubeconfig"
ep="$core/testdata/endpoints.json"
state="$tmp/state"
mkdir -p "$state/core/sensitive"
chmod 700 "$state/core/sensitive"
ACC_OPERATOR_TOKEN=$(openssl rand -hex 32)
# Per-run credentials for the containers below (none is a fixture value).
bao_token=$(openssl rand -hex 16)
ACC_MYSQL_PW=$(openssl rand -hex 16) ACC_VALKEY_PW=$(openssl rand -hex 16)
export ACC_MYSQL_PW ACC_VALKEY_PW
rustfs_key=$(openssl rand -hex 8) rustfs_secret=$(openssl rand -hex 16)
printf '%s\n' "$ACC_OPERATOR_TOKEN" >"$state/core/sensitive/saasapi-operator-token"
printf '%s' "$bao_token" >"$state/core/sensitive/openbao-root-token"
acc() { "$core/acceptance.sh" "$kubeconfig" "$ep" "$state" "$@"; }

ta=t_aaaaaaaaaaaaaaaa
tb=t_bbbbbbbbbbbbbbbb

# --- argument checks -----------------------------------------------------------------
refused() {
	local d="$1" re="$2"
	shift 2
	if "$@" >"$tmp/out" 2>&1; then
		bad "$d (succeeded)"
	elif grep -Eq -- "$re" "$tmp/out"; then ok "$d"; else
		bad "$d (wrong message)"
		sed 's/^/      /' "$tmp/out" | tail -n 5
	fi
}
refused "an unknown verb is refused" "unknown verb" acc frobnicate
refused "a tenant ID that isn't one is refused" "not a tenant ID" acc provisioning-jobs "t_x'; DROP TABLE x; --"
refused "a sprout ID with a quote is refused" "not a sprout ID" acc props "$ta" "a'b"
refused "a job ID that isn't a UUID is refused" "not a job ID" acc job-status "$ta" web-01 "1 OR 1=1"
refused "a wrong argument count is refused" "takes 1 argument" acc purge
refused "a Valkey key of no sprout is refused" "not a sprout's Valkey key" acc valkey-get 'imas:*'
refused "a table outside farmer and saas is refused" "not a farmer or saas table" \
	bash -c 'echo "{\"tenant_id\":\"$1\",\"tables\":[\"mysql.user\"]}" | "$2" "$3" "$4" "$5" inventory' _ "$ta" "$core/acceptance.sh" "$kubeconfig" "$ep" "$state"
refused "a backdate naming nothing is refused" "names nothing" \
	bash -c 'echo "{\"tenant_id\":\"$1\",\"seconds\":60}" | "$2" "$3" "$4" "$5" backdate' _ "$ta" "$core/acceptance.sh" "$kubeconfig" "$ep" "$state"
jq -cn --arg t "$ta" '{tenant_id: $t, seconds: 60, batches: ["b_x'"'"' OR 1=1"]}' >"$tmp/bad-backdate.json"
refused "a backdate row ID that isn't one is refused" "not a row ID" \
	bash -c '"$1" "$2" "$3" "$4" backdate <"$5"' _ "$core/acceptance.sh" "$kubeconfig" "$ep" "$state" "$tmp/bad-backdate.json"
refused "an object key with .. is refused" "not an object key" acc delete-object recipes "tenants/../x"
refused "an unknown bucket is refused" "unknown bucket" acc objects secrets tenants/
refused "an unknown workload is refused" "unknown workload" acc restart keycloak

# --- the operator purge --------------------------------------------------------------
export ACC_PURGE_STATUS=202 ACC_PURGE_BODY="{\"tenant_id\":\"$ta\",\"job_id\":\"pj_cccccccccccccccc\",\"status\":\"offboarded\"}"
if out=$(acc purge "$ta" 2>"$tmp/err"); then
	jq -e --arg t "$ta" '.status == 202 and .body.tenant_id == $t and .body.status == "offboarded"' <<<"$out" >/dev/null &&
		ok "purge: the operator plane's 202 and body" || bad "purge: printed $out"
	grep -q "https://imas-core-farmer-saasapi-operator.imas-core.svc.cluster.local:40125/v1/operator/tenants/$ta/purge" "$ACC_STATE/curl.log" &&
		grep -q -- "-X POST" "$ACC_STATE/curl.log" && ok "purge: POST through the port-forward, for the operator Service's name" ||
		bad "purge: the request: $(cat "$ACC_STATE/curl.log")"
	! grep -q "$ACC_OPERATOR_TOKEN" "$ACC_STATE/curl.log" "$ACC_STATE/calls.log" && grep -q "Bearer $ACC_OPERATOR_TOKEN" "$ACC_STATE/curl-headers.log" &&
		ok "purge: the operator token in a header file, never argv" || bad "purge: the token is on a command line, or missing"
else
	bad "purge failed: $(cat "$tmp/err")"
fi
ACC_PURGE_STATUS=409 ACC_PURGE_BODY='{"error":"not_offboarded","message":"x"}' acc purge "$ta" >"$tmp/out" 2>&1 &&
	jq -e '.status == 409 and .body.error == "not_offboarded"' "$tmp/out" >/dev/null && ok "purge: a 409 is printed, not an error" ||
	bad "purge 409: $(cat "$tmp/out")"

# --- restart, the log retention Job, retention, log-count ---------------------------------
out=$(acc restart saasapi 2>/dev/null) && [[ "$(jq -r .restarted <<<"$out")" == imas-core-farmer-saasapi ]] &&
	grep -q "rollout restart deployment/imas-core-farmer-saasapi" "$ACC_STATE/calls.log" &&
	grep -q "rollout status deployment/imas-core-farmer-saasapi --timeout=600s" "$ACC_STATE/calls.log" &&
	ok "restart saasapi: rollout restart, then waits" || bad "restart saasapi: $out"
ACC_ROLLOUT_RC=1 refused "restart fails when the rollout doesn't finish" "did not roll out" acc restart farmer
out=$(acc sweep log-retention 2>/dev/null) && jq -e '.sweep == "log-retention" and .succeeded == true' <<<"$out" >/dev/null &&
	grep -q "create job imas-uat-log-retention-[0-9]* --from=cronjob/imas-core-farmer-log-retention" "$ACC_STATE/calls.log" &&
	ok "sweep log-retention: a Job from the CronJob, waited for" || bad "sweep log-retention: $out"
ACC_JOB_RC=1 refused "sweep log-retention fails when the Job doesn't complete" "did not complete" acc sweep log-retention

jq -n '{spec: {selector: {matchLabels: {"app.kubernetes.io/name": "farmer", "app.kubernetes.io/component": "farmer"}},
	template: {spec: {containers: [{name: "farmer", env: [{name: "IMAS_RECIPE_AUDIT_RETENTION_DAYS", value: "1"},
		{name: "IMAS_S3_ACCESS_KEY_ID", valueFrom: {secretKeyRef: {name: "s", key: "k"}}}]}]}}}}' >"$ACC_STATE/get-deployment-imas-core-farmer.json"
jq -n '{spec: {template: {spec: {containers: [{name: "saasapi", env: [{name: "SAASAPI_TERMINAL_ROW_RETENTION", value: "24h"},
	{name: "SAASAPI_TENANT_PURGE_AFTER", value: "1h"}]}]}}}}' >"$ACC_STATE/get-deployment-imas-core-farmer-saasapi.json"
jq -n '{status: {desiredNumberScheduled: 1, numberReady: 1}}' >"$ACC_STATE/get-daemonset-imas-core-farmer-log-shipper.json"
echo '{}' >"$ACC_STATE/get-configmap-imas-core-farmer-log-shipper.json"
jq -n '{spec: {schedule: "17 3 * * *", jobTemplate: {spec: {template: {spec: {containers: [{name: "log-retention",
	args: ["log-retention", "-bucket=imas-logs", "-days=1", "-timeout=30m"]}]}}}}}}' >"$ACC_STATE/get-cronjob-imas-core-farmer-log-retention.json"
out=$(acc retention 2>"$tmp/err") && jq -e '.farmer.IMAS_RECIPE_AUDIT_RETENTION_DAYS == "1" and (.farmer | has("IMAS_S3_ACCESS_KEY_ID") | not)
	and .saasapi.SAASAPI_TERMINAL_ROW_RETENTION == "24h" and .saasapi.SAASAPI_TENANT_PURGE_AFTER == "1h"
	and .log_shipper == {daemonset: true, configmap: true, ready: true}
	and .log_retention == {cronjob: true, schedule: "17 3 * * *", days: 1}' <<<"$out" >/dev/null &&
	ok "retention: the workloads' settings, the shipper and the CronJob's days" || bad "retention: $out $(cat "$tmp/err")"
rm "$ACC_STATE/get-cronjob-imas-core-farmer-log-retention.json" "$ACC_STATE/get-daemonset-imas-core-farmer-log-shipper.json"
out=$(acc retention 2>/dev/null) && jq -e '.log_retention == {cronjob: false, schedule: "", days: 0} and .log_shipper.daemonset == false' <<<"$out" >/dev/null &&
	ok "retention: no log shipping says so" || bad "retention without log shipping: $out"
printf '%s\n' 'error cooking recipe for web-01: cook exceeded its render budget: total range iterations over 100000' \
	'other line' 'error cooking recipe for web-02: cook exceeded its render budget: total rendered bytes over 1' >"$ACC_STATE/logs.txt"
out=$(printf 'cook exceeded its render budget' | acc log-count farmer 600 2>/dev/null) && [[ "$(jq .count <<<"$out")" == 2 ]] &&
	grep -q "logs -l app.kubernetes.io/name=farmer,app.kubernetes.io/component=farmer -c farmer --since=600s" "$ACC_STATE/calls.log" &&
	ok "log-count: matching lines of the workload's pods since then" || bad "log-count: $out"

# --- with containers ----------------------------------------------------------------------
rustfs_image=$(sed -n 's/^  image: \(docker.io\/rustfs\/rustfs:[^ ]*\)$/\1/p' "$core/chart/values.yaml")
images=(percona/percona-xtradb-cluster:8.4.8-8.1 valkey/valkey:9.1.2 "$rustfs_image" openbao/openbao:2.6.3)
have_images() {
	command -v docker >/dev/null && docker info >/dev/null 2>&1 || return 1
	local i
	for i in "${images[@]}"; do
		docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i" >/dev/null 2>&1 || return 1
	done
}
if ! have_images; then
	skip "acceptance.sh against PXC, Valkey, RustFS and OpenBao containers (no Docker, or the images ${images[*]} can't be pulled)"
else
	run=imas-acc-$$
	export ACC_MYSQL=$run-mysql ACC_VALKEY=$run-valkey ACC_RUSTFS=$run-rustfs ACC_OPENBAO=$run-openbao
	containers=("$ACC_MYSQL" "$ACC_VALKEY" "$ACC_RUSTFS" "$ACC_OPENBAO")
	docker run -d --name "$ACC_MYSQL" -e MYSQL_ROOT_PASSWORD="$ACC_MYSQL_PW" -e CLUSTER_NAME=acc percona/percona-xtradb-cluster:8.4.8-8.1 >/dev/null
	docker run -d --name "$ACC_VALKEY" valkey/valkey:9.1.2 valkey-server --requirepass "$ACC_VALKEY_PW" >/dev/null
	docker run -d --name "$ACC_RUSTFS" -e RUSTFS_ACCESS_KEY="$rustfs_key" -e RUSTFS_SECRET_KEY="$rustfs_secret" \
		-e RUSTFS_VOLUMES=/data -e RUSTFS_ADDRESS=:9000 -e RUSTFS_CONSOLE_ENABLE=false "$rustfs_image" >/dev/null
	docker run -d --name "$ACC_OPENBAO" openbao/openbao:2.6.3 server -dev -dev-root-token-id="$bao_token" \
		-dev-listen-address=0.0.0.0:8200 >/dev/null
	wait_for() {
		local i
		for i in $(seq 1 90); do
			"$@" >/dev/null 2>&1 && return 0
			sleep 1
		done
		return 1
	}
	# Over TCP: the image's entrypoint first runs a socket-only server to
	# initialise, then restarts; only the final server answers on 3306.
	wait_for docker exec "$ACC_MYSQL" mysql -h127.0.0.1 -uroot "-p$ACC_MYSQL_PW" -e 'SELECT 1' || bad "PXC did not start"
	wait_for docker exec "$ACC_RUSTFS" curl -sf http://127.0.0.1:9000/health/ready || bad "RustFS did not start"
	wait_for docker exec -e BAO_ADDR=http://127.0.0.1:8200 "$ACC_OPENBAO" bao status || bad "OpenBao did not start"
	mysql_root() { docker exec -i "$ACC_MYSQL" mysql -uroot "-p$ACC_MYSQL_PW" "$@" 2>/dev/null; }

	# The two schemas from the repository's migrations (goose Up sections).
	for schema in farmer saas; do
		echo "CREATE DATABASE $schema" | mysql_root
		for f in "$repo/internal/migrations/$schema"/*.sql; do
			sed -n '/^-- +goose Up/,/^-- +goose Down/p' "$f" | grep -v '^-- +goose' | mysql_root "$schema" ||
				bad "migration $f does not apply"
		done
	done
	cat <<SQL | mysql_root
INSERT INTO saas.tenants (id, name, status, created_at, updated_at, offboarded_at) VALUES
	('$ta', 'a', 'offboarded', NOW(3), NOW(3), '2026-10-01 10:00:00'), ('$tb', 'b', 'active', NOW(3), NOW(3), NULL);
INSERT INTO saas.provisioning_jobs (id, tenant_id, type, status, created_at, updated_at) VALUES
	('pj_aaaaaaaaaaaaaaa3', '$ta', 'provision', 'succeeded', '2026-10-01 09:00:00', '2026-10-01 09:00:00'),
	('pj_aaaaaaaaaaaaaaa2', '$ta', 'deprovision', 'succeeded', '2026-10-01 10:00:00', '2026-10-01 10:00:00'),
	('pj_bbbbbbbbbbbbbbb3', '$tb', 'provision', 'succeeded', '2026-10-01 09:00:00', '2026-10-01 09:00:00');
INSERT INTO saas.enrollment_keys (key_id, tenant_id, key_hash, expiry, max_uses, created_at) VALUES
	('ek_aaaaaaaaaaaaaaa3', '$ta', 'h', '2026-11-01 00:00:00', 1, '2026-10-01 00:00:00'),
	('ek_bbbbbbbbbbbbbbb3', '$tb', 'h', '2026-11-01 00:00:00', 1, '2026-10-01 00:00:00');
INSERT INTO saas.asset_action_batches (id, tenant_id, action_type, action_params, requested_asset_ids, created_at, lease_until) VALUES
	('b_aaaaaaaaaaaaaaa3', '$ta', 'cmd.run', '{}', '[]', '2026-10-01 00:00:00', '2026-10-01 00:02:00'),
	('b_bbbbbbbbbbbbbbb3', '$tb', 'cmd.run', '{}', '[]', '2026-10-01 00:00:00', NULL);
INSERT INTO saas.asset_action_items (batch_id, asset_id, tenant_id, position, status, created_at, updated_at) VALUES
	('b_aaaaaaaaaaaaaaa3', 'a1', '$ta', 0, 'unresolved', '2026-10-01 00:00:00', '2026-10-01 00:00:00'),
	('b_bbbbbbbbbbbbbbb3', 'b1', '$tb', 0, 'unresolved', '2026-10-01 00:00:00', '2026-10-01 00:00:00');
INSERT INTO farmer.props (tenant_id, sprout_id, name, value, static, expiry) VALUES
	('$tb', 'web-01', 'os', 'linux', 0, UTC_TIMESTAMP() + INTERVAL 300 SECOND),
	('$tb', 'web-01', 'hostname', 'a\\tb', 0, UTC_TIMESTAMP() + INTERVAL 600 SECOND),
	('$tb', 'web-02', 'os', 'windows', 0, UTC_TIMESTAMP() + INTERVAL 300 SECOND);
INSERT INTO farmer.job_status (tenant_id, sprout_id, jid, status, steps_total, steps_reported, started, finished, updated_at) VALUES
	('$tb', 'web-01', '0b5f2a2e-1b9d-4d6e-9c1a-2f3e4d5c6b7a', 'succeeded', 1, 1, 1, 1, NOW(3));
INSERT INTO farmer.job_leases (name, last_run_at) VALUES ('recipe_audit_expiry', NOW(3));
SQL
	[[ "$(mysql_root -N -e "SELECT COUNT(*) FROM saas.tenants")" == 2 ]] && ok "PXC: the migrations and the seed rows apply" ||
		bad "PXC: seeding failed"

	spec=$(jq -cn --arg t "$tb" '{tenant_id: $t, tables: ["farmer.props", "farmer.job_status", "saas.enrollment_keys", "saas.asset_action_items", "farmer.pki_nkeys"]}')
	out=$(acc inventory <<<"$spec" 2>"$tmp/err") &&
		jq -e '.counts == {"farmer.props": 3, "farmer.job_status": 1, "saas.enrollment_keys": 1, "saas.asset_action_items": 1, "farmer.pki_nkeys": 0}' <<<"$out" >/dev/null &&
		ok "inventory: rows counted by tenant_id" || bad "inventory tables: $out $(cat "$tmp/err")"
	out=$(acc provisioning-jobs "$ta" 2>/dev/null) &&
		jq -e '.jobs == [{id: "pj_aaaaaaaaaaaaaaa3", type: "provision", status: "succeeded"}, {id: "pj_aaaaaaaaaaaaaaa2", type: "deprovision", status: "succeeded"}]' <<<"$out" >/dev/null &&
		ok "provisioning-jobs: the tenant's jobs, oldest first" || bad "provisioning-jobs: $out"
	out=$(acc props "$tb" web-01 2>/dev/null) &&
		jq -e '(.props | map(.name)) == ["hostname", "os"] and .props[1].value == "linux" and .props[0].value == "a\\tb"
			and (.props[1].expires_in > 250 and .props[1].expires_in <= 300)' <<<"$out" >/dev/null &&
		ok "props: one sprout's rows, a tab kept on one line, expiry in seconds" || bad "props: $out"
	out=$(acc job-status "$tb" web-01 0b5f2a2e-1b9d-4d6e-9c1a-2f3e4d5c6b7a 2>/dev/null) &&
		jq -e '. == {exists: true, status: "succeeded"}' <<<"$out" >/dev/null &&
		out=$(acc job-status "$ta" web-01 0b5f2a2e-1b9d-4d6e-9c1a-2f3e4d5c6b7a 2>/dev/null) &&
		jq -e '. == {exists: false, status: ""}' <<<"$out" >/dev/null &&
		ok "job-status: by tenant, sprout and jid; another tenant's row doesn't count" || bad "job-status: $out"

	spec=$(jq -cn --arg t "$ta" '{tenant_id: $t, seconds: 172800, offboarded: true, provisioning_jobs: ["pj_aaaaaaaaaaaaaaa3"],
		batches: ["b_aaaaaaaaaaaaaaa3", "b_bbbbbbbbbbbbbbb3"], enrollment_keys: ["ek_aaaaaaaaaaaaaaa3", "ek_bbbbbbbbbbbbbbb3"]}')
	out=$(acc backdate <<<"$spec" 2>"$tmp/err") && [[ "$(jq .updated <<<"$out")" == 5 ]] &&
		[[ "$(mysql_root -N -e "SELECT offboarded_at FROM saas.tenants WHERE id = '$ta'")" == "2026-09-29 10:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT updated_at FROM saas.provisioning_jobs WHERE id = 'pj_aaaaaaaaaaaaaaa3'")" == "2026-09-29 09:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT updated_at FROM saas.provisioning_jobs WHERE id = 'pj_aaaaaaaaaaaaaaa2'")" == "2026-10-01 10:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT created_at FROM saas.asset_action_batches WHERE id = 'b_aaaaaaaaaaaaaaa3'")" == "2026-09-29 00:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT lease_until FROM saas.asset_action_batches WHERE id = 'b_aaaaaaaaaaaaaaa3'")" == "2026-09-29 00:02:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT updated_at FROM saas.asset_action_items WHERE batch_id = 'b_aaaaaaaaaaaaaaa3'")" == "2026-09-29 00:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT created_at FROM saas.asset_action_batches WHERE id = 'b_bbbbbbbbbbbbbbb3'")" == "2026-10-01 00:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT expiry FROM saas.enrollment_keys WHERE key_id = 'ek_aaaaaaaaaaaaaaa3'")" == "2026-10-30 00:00:00.000" ]] &&
		[[ "$(mysql_root -N -e "SELECT expiry FROM saas.enrollment_keys WHERE key_id = 'ek_bbbbbbbbbbbbbbb3'")" == "2026-11-01 00:00:00.000" ]] &&
		ok "backdate: the named rows of the tenant move back, another tenant's never" || bad "backdate: $out $(cat "$tmp/err")"
	out=$(acc sweep recipe-audit 2>"$tmp/err") && jq -e '.sweep == "recipe-audit" and .restarted == "imas-core-farmer"' <<<"$out" >/dev/null &&
		[[ "$(mysql_root -N -e "SELECT COALESCE(last_run_at, 'none') FROM farmer.job_leases WHERE name = 'recipe_audit_expiry'")" == none ]] &&
		ok "sweep recipe-audit: the sweep's last run cleared, farmer restarted" || bad "sweep recipe-audit: $out $(cat "$tmp/err")"

	# RustFS: buckets as rustfs-setup.sh makes them, then objects.
	for b in imas-recipes imas-logs; do
		docker exec "$ACC_RUSTFS" curl -sS -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 "aws:amz:us-east-1:s3" --user "$rustfs_key:$rustfs_secret" \
			-H "x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" "http://127.0.0.1:9000/$b" >/dev/null
	done
	put() { printf '%s' "$3" | acc put-object "$1" "$2"; }
	put recipes "tenants/$tb/recipes/uat/a.imas" "steps: {}" >/dev/null 2>&1 &&
		put recipes "tenants/$tb/recipe-audit/2026-10-01/r1.json" '{"a":1}' >/dev/null 2>&1 &&
		put recipes "tenants/$ta/recipes/uat/b.imas" "steps: {}" >/dev/null 2>&1 &&
		out=$(put logs "logs/2026/10/01/pod-1.gz" "x" 2>"$tmp/err") && [[ "$(jq .status <<<"$out")" == 200 ]] &&
		ok "put-object: objects written as the RustFS root" || bad "put-object: $out $(cat "$tmp/err")"
	out=$(acc objects recipes "tenants/$tb/" 2>"$tmp/err") &&
		jq -e --arg t "$tb" '.keys == ["tenants/\($t)/recipe-audit/2026-10-01/r1.json", "tenants/\($t)/recipes/uat/a.imas"]' <<<"$out" >/dev/null &&
		ok "objects: every key under the prefix, and nothing of another tenant" || bad "objects: $out $(cat "$tmp/err")"
	out=$(acc delete-object logs "logs/2026/10/01/pod-1.gz" 2>/dev/null) && out=$(acc objects logs logs/ 2>/dev/null) &&
		jq -e '.keys == []' <<<"$out" >/dev/null && ok "delete-object: the object is gone" || bad "delete-object: $out"

	# Valkey with its password.
	docker exec "$ACC_VALKEY" valkey-cli -a "$ACC_VALKEY_PW" --no-auth-warning set "imas:upgrade:{$tb:web-01}" facts >/dev/null
	docker exec "$ACC_VALKEY" valkey-cli -a "$ACC_VALKEY_PW" --no-auth-warning set "imas:heartbeat:{$tb:web-01}" 1 >/dev/null
	docker exec "$ACC_VALKEY" valkey-cli -a "$ACC_VALKEY_PW" --no-auth-warning set "imas:heartbeat:{$ta:web-01}" 1 >/dev/null
	out=$(acc valkey-get "imas:upgrade:{$tb:web-01}" 2>"$tmp/err") && jq -e '. == {exists: true, value: "facts"}' <<<"$out" >/dev/null &&
		out=$(acc valkey-get "imas:upgrade:{$tb:web-02}" 2>/dev/null) && jq -e '. == {exists: false, value: ""}' <<<"$out" >/dev/null &&
		ok "valkey-get: a marker and its value, and a missing one" || bad "valkey-get: $out $(cat "$tmp/err")"

	# OpenBao (dev server: KV v2 at secret/), and the full inventory.
	bao() { docker exec -e BAO_TOKEN="$bao_token" -e BAO_ADDR=http://127.0.0.1:8200 "$ACC_OPENBAO" bao "$@" >/dev/null; }
	bao secrets enable transit
	bao kv put "secret/imas/tenant-x25519/tenants/$tb" pub=x
	bao write -f "transit/keys/nats-tsign-$tb"
	spec=$(jq -cn --arg t "$tb" '{tenant_id: $t, tables: ["farmer.props"],
		objects: [{category: "objects.recipes", bucket: "recipes", prefix: "tenants/\($t)/"}, {category: "objects.jobs", bucket: "recipes", prefix: "sprouts/\($t)/"}],
		valkey: [{category: "valkey.heartbeat", pattern: "imas:heartbeat:{\($t):*"}, {category: "valkey.upgrade", pattern: "imas:upgrade:{\($t):*"}],
		openbao_kv: ["secret/imas/tenant-x25519/tenants/\($t)"], transit: ["transit/nats-tsign-\($t)", "transit/nats-tacct-\($t)"]}')
	out=$(acc inventory <<<"$spec" 2>"$tmp/err") && jq -e --arg t "$tb" '.counts == {"farmer.props": 3, "objects.recipes": 2, "objects.jobs": 0,
		"valkey.heartbeat": 1, "valkey.upgrade": 1, ("kv:secret/imas/tenant-x25519/tenants/" + $t): 1,
		("transit:transit/nats-tsign-" + $t): 1, ("transit:transit/nats-tacct-" + $t): 0}' <<<"$out" >/dev/null &&
		ok "inventory: rows, objects, Valkey keys, the KV keypair and the Transit keys of one tenant" ||
		bad "inventory: $out $(cat "$tmp/err")"
	spec=$(jq -cn --arg t "$tb" --arg o "$ta" '{tenant_id: $t, valkey: [{category: "valkey.heartbeat", pattern: "imas:heartbeat:{\($o):*"}]}')
	refused "inventory refuses another tenant's Valkey pattern" "is not the tenant's" bash -c 'acc() { "$1" "$2" "$3" "$4" inventory; }; acc "$@" <<<"$5"' _ \
		"$core/acceptance.sh" "$kubeconfig" "$ep" "$state" "$spec"
	grep -qF "$bao_token" "$ACC_STATE/calls.log" && bad "the OpenBao token reached a command line" || ok "the OpenBao token never on a command line"
	grep -qF -e "$ACC_MYSQL_PW" -e "$ACC_VALKEY_PW" "$ACC_STATE/calls.log" && bad "a database or Valkey password reached a command line" ||
		ok "the PXC and Valkey passwords never on a command line"
fi

echo
for s in "${skipped[@]}"; do echo "skipped (not passed): $s"; done
if [[ $failed -gt 0 ]]; then
	echo "$failed check(s) failed"
	exit 1
fi
echo "all run checks passed"
