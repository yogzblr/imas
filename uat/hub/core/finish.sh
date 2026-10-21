#!/usr/bin/env bash
# finish.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>
#
# The second half of the core install, run after the DMZ hub is up
# (uat/hub/dmz/install.sh). install.sh stops short of three things that need
# the DMZ's NATS bus: farmer's /ready latches only once it has connected to
# it, saasapi exits at startup without it, and the sprout release
# registration hook POSTs to saasapi. So here, in order:
#    1. wait for the farmer and saasapi rollouts, FIRST_START_SECONDS
#       (1200 s) each with their progress deadline raised to match; on a
#       timeout print the core pods, `kubectl describe` with events, farmer's
#       last 40 log lines and the DMZ bus and loader tails (DMZ_KUBECONFIG,
#       default dmz.kubeconfig next to <kubeconfig>), then fail (W7)
#    2. register the sprout release (P20 option C): `helm upgrade` of the
#       same chart with sproutRelease.register=true (--reuse-values, so
#       nothing else moves; the chart's post-upgrade hooks are idempotent,
#       as for any re-run of install.sh). saasapi.operator is on in
#       values/farmer-uat.yaml, so the chart renders the registration hook
#       Job (`farmer register-sprout-release`), and helm waits for it. A
#       failed Job (a 409, an unreachable or refusing operator listener)
#       fails the upgrade, and this script, with the Job's logs
#    3. check the Job ran and completed: it is in the release's hooks, and
#       no copy of it is left failed or unfinished
#    4. check, through the operator API (operator-release.sh verify), that
#       release_tag is registered with the GPG-signed checksums.txt and
#       signature the chart stamped; fail if it is not
#    5. run check.sh (SKIP_CHECK=1 skips it)
# Safe to re-run. FLAG FOR SECURITY REVIEW (the registration Job and step 4
# hold the operator token; see deploy/helm/farmer/README.md).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
usage="finish.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>"
parse_common_args "$usage" "$@"
[[ $# -ge 4 ]] || die "usage: $usage"
release_tag="$4"
version=$(release_version "$release_tag")
need_cmd kubectl helm jq curl base64
HELM_TIMEOUT="${HELM_TIMEOUT:-45m}"
# How long step 3 waits for a registration Job helm left behind.
REGISTER_WAIT="${REGISTER_WAIT:-600s}"
common=("$KUBECONFIG_PATH" "$ENDPOINTS" "$STATE_ROOT")
register_job="$FARMER_FULLNAME-sprout-release-register"

chart_tgz="$STATE_DIR/chart/farmer-$version.tgz"
[[ -s "$chart_tgz" ]] || die "no $chart_tgz: has install.sh run for $release_tag?"
kc -n "$CORE_NS" get deployment "$FARMER_FULLNAME" >/dev/null 2>&1 ||
	die "deployment $FARMER_FULLNAME not found in $CORE_NS: has install.sh run?"

job_logs() {
	local j
	for j in $(kc -n "$CORE_NS" get jobs -o name 2>/dev/null | grep sprout-release || true); do
		log "logs of $j"
		kc -n "$CORE_NS" logs "$j" --all-containers --tail=50 >&2 || true
	done
}

log "waiting for farmer and saasapi (they need the DMZ bus: run uat/hub/dmz/install.sh first)"
# FIRST_START_SECONDS each, with the diagnostics on a timeout (W7,
# lib/common.sh): a clean first start of farmer takes about ten minutes.
first_start_rollout "$FARMER_FULLNAME"
first_start_rollout "$SAASAPI_FULLNAME"

# --- 2. register ---------------------------------------------------------------
helm_log="$STATE_DIR/helm-register.log"
log "registering the sprout release $release_tag (helm upgrade --reuse-values, sproutRelease.register=true; log $helm_log)"
if ! hc upgrade "$CORE_RELEASE" "$chart_tgz" -n "$CORE_NS" --reuse-values --timeout "$HELM_TIMEOUT" \
	--set sproutRelease.register=true >"$helm_log" 2>&1; then
	cat "$helm_log" >&2
	job_logs
	die "registering the sprout release failed: the registration Job $register_job did not complete"
fi

# --- 3. the Job ran and completed ------------------------------------------------
# Rendered at all? (saasapi.operator off, or a chart without the stamped
# release, renders no Job, and the upgrade then succeeds having done nothing.)
hc get hooks "$CORE_RELEASE" -n "$CORE_NS" 2>/dev/null | grep -Eq "^[[:space:]]*name: $register_job\$" ||
	die "the release has no registration hook Job $register_job: the chart did not render it (is saasapi.operator.enabled on, and is $chart_tgz release-stamped?)"
# hook-succeeded deletes the Job once it completes; one that is still there
# either failed (kept for its logs) or has not finished.
if job=$(kc -n "$CORE_NS" get job "$register_job" -o json 2>/dev/null); then
	if jq -e '[.status.conditions[]? | select(.type == "Failed" and .status == "True")] | length > 0' <<<"$job" >/dev/null; then
		job_logs
		die "the registration Job $register_job failed"
	fi
	log "waiting for the registration Job $register_job to complete"
	if ! kc -n "$CORE_NS" wait "job/$register_job" --for=condition=complete --timeout="$REGISTER_WAIT" >&2; then
		job_logs
		die "the registration Job $register_job did not complete"
	fi
fi
log "the registration Job $register_job completed"

# --- 4. registered, with the signed checksums -------------------------------------
if ! registered=$("$here/operator-release.sh" "${common[@]}" verify "$release_tag"); then
	die "the operator API does not hold release $release_tag as the chart stamped it (see above)"
fi
log "registered: $registered"
first_start_rollout "$SAASAPI_FULLNAME"

if [[ "${SKIP_CHECK:-}" != 1 ]]; then
	"$here/check.sh" "${common[@]}"
fi
