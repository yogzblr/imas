#!/usr/bin/env bash
# finish.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>
#
# The second half of the core install, run after the DMZ hub is up
# (uat/hub/dmz/install.sh). install.sh stops short of three things that need
# the DMZ's NATS bus: farmer's /ready latches only once it has connected to
# it, saasapi exits at startup without it, and the sprout release
# registration hook POSTs to saasapi. So here, in order:
#    1. wait for the farmer and saasapi rollouts
#    2. register the sprout release: `helm upgrade` of the same chart with
#       sproutRelease.register=true (--reuse-values, so nothing else moves;
#       the chart's post-upgrade hooks are idempotent, as for any re-run of
#       install.sh)
#    3. run check.sh (SKIP_CHECK=1 skips it)
# Safe to re-run. FLAG FOR SECURITY REVIEW (the registration Job holds the
# operator token; see deploy/helm/farmer/README.md).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
usage="finish.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>"
parse_common_args "$usage" "$@"
[[ $# -ge 4 ]] || die "usage: $usage"
release_tag="$4"
version=$(release_version "$release_tag")
need_cmd kubectl helm jq
HELM_TIMEOUT="${HELM_TIMEOUT:-45m}"
common=("$KUBECONFIG_PATH" "$ENDPOINTS" "$STATE_ROOT")

chart_tgz="$STATE_DIR/chart/farmer-$version.tgz"
[[ -s "$chart_tgz" ]] || die "no $chart_tgz: has install.sh run for $release_tag?"
kc -n "$CORE_NS" get deployment "$FARMER_FULLNAME" >/dev/null 2>&1 ||
	die "deployment $FARMER_FULLNAME not found in $CORE_NS: has install.sh run?"

log "waiting for farmer and saasapi (they need the DMZ bus: run uat/hub/dmz/install.sh first)"
rollout "deployment/$FARMER_FULLNAME" "$CORE_NS" 900s
rollout "deployment/$SAASAPI_FULLNAME" "$CORE_NS" 900s

helm_log="$STATE_DIR/helm-register.log"
log "registering the sprout release (helm upgrade --reuse-values, sproutRelease.register=true; log $helm_log)"
if ! hc upgrade "$CORE_RELEASE" "$chart_tgz" -n "$CORE_NS" --reuse-values --timeout "$HELM_TIMEOUT" \
	--set sproutRelease.register=true >"$helm_log" 2>&1; then
	cat "$helm_log" >&2
	for j in $(kc -n "$CORE_NS" get jobs -o name 2>/dev/null | grep sprout-release || true); do
		log "logs of $j"
		kc -n "$CORE_NS" logs "$j" --all-containers --tail=50 >&2 || true
	done
	die "registering the sprout release failed"
fi
rollout "deployment/$SAASAPI_FULLNAME" "$CORE_NS" 300s

if [[ "${SKIP_CHECK:-}" != 1 ]]; then
	"$here/check.sh" "${common[@]}"
fi
