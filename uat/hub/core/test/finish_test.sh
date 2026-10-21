#!/usr/bin/env bash
# test/finish_test.sh: finish.sh and operator-release.sh against stub
# kubectl, helm and curl (test/finish-stubs). No cluster. Run by
# test/run.sh and by core_test.go's TestFinishScript.
#   - a failed registration Job fails finish.sh, with the Job's logs, and
#     the operator API is not asked;
#   - no hook rendered, a Job left failed or unfinished: finish.sh fails;
#   - the operator API's answer decides: 200 with nothing created and the
#     chart's packages passes; 201, 409, another version's chart or other
#     packages fail;
#   - the token goes in a header file, never argv; TLS is for the operator
#     Service's name, through the port-forward;
#   - operator-release.sh post-altered: the scratch version's body (version
#     in every file name rewritten, checksums.txt altered, the signature
#     kept), and its exit status.
# The checks use `test && ok || bad` on purpose: ok and bad always return 0.
# shellcheck disable=SC2015
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
core=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failed=0
ok() { printf 'ok    %s\n' "$1"; }
bad() {
	printf 'FAIL  %s\n' "$1"
	failed=$((failed + 1))
}

export PATH="$here/finish-stubs:$PATH"
kubeconfig="$tmp/kubeconfig"
echo "apiVersion: v1" >"$kubeconfig"
ep="$core/testdata/endpoints.json"
tag=v0.1.0-rc.4
# A per-run dummy token (generated, so no token-shaped literal sits in the repo).
FS_TOKEN=$(openssl rand -hex 32)
export FS_TOKEN

# The request the chart's hook sends (ConfigMap imas-core-farmer-sprout-release).
deb=imas-sprout_0.1.0-rc.4_linux_amd64.deb
rpm=imas-sprout_0.1.0-rc.4_linux_amd64.rpm
a64=$(printf 'a%.0s' $(seq 64))
b64=$(printf 'b%.0s' $(seq 64))
jq -n --arg deb "$deb" --arg rpm "$rpm" --arg a "$a64" --arg b "$b64" '{
	version: "v0.1.0-rc.4", channel: "stable", min_sprout_version: "v0.1.0",
	packages: [
		{os: "linux", arch: "amd64", package_type: "deb", file_name: $deb, checksum_sha256: $a},
		{os: "linux", arch: "amd64", package_type: "rpm", file_name: $rpm, checksum_sha256: $b}],
	checksums_txt: ($a + "  " + $deb + "\n" + $b + "  " + $rpm + "\n"),
	checksums_sig: "c2lnbmF0dXJlIG92ZXIgY2hlY2tzdW1zLnR4dA=="}' >"$tmp/request.json"
# saasapi's answer to a repeat of what it holds.
jq '{version, min_sprout_version, revoked: false, created: 0,
	packages: [.packages[] | {os, arch, package_type, file_name, checksum_sha256}] | reverse}' \
	"$tmp/request.json" >"$tmp/held.json"

# scenario <name>: a fresh state directory (the chart install.sh pulled and
# the operator token saasapi-secrets.sh wrote) and default stub answers.
scenario() {
	state="$tmp/$1"
	mkdir -p "$state/core/chart" "$state/core/sensitive"
	echo chart >"$state/core/chart/farmer-0.1.0-rc.4.tgz"
	(umask 077 && printf '%s' "$FS_TOKEN" >"$state/core/sensitive/saasapi-operator-token")
	export FS_STATE="$state"
	: >"$state/calls.log"
	export FS_REQUEST="$tmp/request.json" FS_RESPONSE="$tmp/held.json" FS_STATUS=200
	export FS_HELM_RC=0 FS_JOB_STATE=absent FS_WAIT_RC=0 FS_NO_HOOK="" FS_ROLLOUT_RC=0
}
finish() { SKIP_CHECK=1 "$core/finish.sh" "$kubeconfig" "$ep" "$state" "$tag" >"$state/out" 2>&1; }
says() { grep -qF -- "$1" "$state/out"; }
show() { sed 's/^/      /' "$state/out" | tail -n 8; }

scenario job-fails
export FS_HELM_RC=1 FS_JOB_STATE=failed
if finish; then bad "a failed registration Job fails finish.sh (it succeeded)"; show
elif says "registering the sprout release failed" && says "409 release_conflict" && says "BackoffLimitExceeded"; then
	ok "a failed registration Job fails finish.sh, with the helm error and the Job's logs"
else bad "a failed registration Job: wrong message"; show; fi
[[ ! -e "$state/curl.log" ]] && ok "... and the operator API is not asked" || bad "the operator API was asked after a failed Job"
grep -q -- '--reuse-values' "$state/calls.log" && grep -q -- '--set sproutRelease.register=true' "$state/calls.log" &&
	ok "the registration is helm upgrade --reuse-values --set sproutRelease.register=true" || bad "the helm upgrade's arguments"

# W7: farmer and saasapi each get 1200 s, their progress deadline raised to
# 3600 s (it runs from install.sh, before the DMZ install); a timeout prints
# the diagnostics, then fails before registering.
scenario first-start-waits
finish && grep -qF 'patch deployment imas-core-farmer --type=merge -p {"spec":{"progressDeadlineSeconds":3600}}' "$state/calls.log" &&
	grep -qF 'patch deployment imas-core-farmer-saasapi --type=merge -p {"spec":{"progressDeadlineSeconds":3600}}' "$state/calls.log" &&
	grep -qF 'rollout status deployment/imas-core-farmer --timeout=1200s' "$state/calls.log" &&
	[[ $(grep -c 'rollout status deployment/imas-core-farmer-saasapi --timeout=1200s' "$state/calls.log") -eq 2 ]] &&
	! grep -q 'rollout status .*--timeout=\(300\|600\|900\)s' "$state/calls.log" &&
	ok "farmer and saasapi: progress deadline 3600 s, rollout waits 1200 s (W7)" || { bad "the first start waits"; show; }

scenario first-start-timeout
export FS_ROLLOUT_RC=1
echo "apiVersion: v1" >"$tmp/dmz.kubeconfig"
if finish; then bad "a farmer that does not roll out passes"; show
elif says "deployment/imas-core-farmer in imas-core did not become ready within 1200s" &&
	says "(stub pods)" && says "Events: (stub describe deployment imas-core-farmer)" &&
	says "Events: (stub describe deployment imas-core-farmer-saasapi)" &&
	says "Events: (stub describe pods -l app.kubernetes.io/instance=imas-core,app.kubernetes.io/component=farmer)" &&
	says "farmer-a: announcing 2 reconciled Accounts" && says "farmer-b: current run" && says "farmer-b: before its restart" &&
	says "saasapi-a: nats: no servers available for connection" && says "saasapi-a: before its restart" &&
	says "bus-0 farmerbus: TLS handshake error" && says "bus-0 loader: accountloader: initial load complete"; then
	ok "a farmer rollout timeout prints pods, describe with events, farmer's and saasapi's last 40 lines and the DMZ bus and loader tails, then fails"
else bad "a farmer rollout timeout: wrong output"; sed 's/^/      /' "$state/out"; fi
grep -qF "kubectl --kubeconfig $tmp/dmz.kubeconfig -n imas-dmz logs imas-dmz-nats-bus-0 -c loader --tail=40" "$state/calls.log" &&
	ok "... the DMZ tails come from dmz.kubeconfig next to the core kubeconfig" || bad "the DMZ tails' kubeconfig"
! grep -q 'helm upgrade' "$state/calls.log" 2>/dev/null && ok "... and nothing is registered" || bad "registered after a failed rollout"
rm -f "$tmp/dmz.kubeconfig"
finish && bad "a timeout without a DMZ kubeconfig passes" ||
	{ says "no DMZ kubeconfig at $tmp/dmz.kubeconfig" && says "did not become ready within 1200s" &&
		ok "no DMZ kubeconfig: the core diagnostics still print, and it fails" || { bad "no DMZ kubeconfig: wrong output"; show; }; }

scenario no-hook
export FS_NO_HOOK=1
finish && { bad "a release without the hook Job passes"; show; } ||
	{ says "has no registration hook Job" && ok "no registration hook rendered: finish.sh fails" || { bad "no hook: wrong message"; show; }; }

scenario job-left-failed
export FS_JOB_STATE=failed
finish && { bad "a Job left failed passes"; show; } ||
	{ says "registration Job imas-core-farmer-sprout-release-register failed" && ok "a registration Job left failed: finish.sh fails" || { bad "Job left failed: wrong message"; show; }; }

scenario job-unfinished
export FS_JOB_STATE=running FS_WAIT_RC=1
finish && { bad "an unfinished Job passes"; show; } ||
	{ says "did not complete" && ok "a registration Job that does not complete: finish.sh fails" || { bad "unfinished Job: wrong message"; show; }; }

scenario job-finishes
export FS_JOB_STATE=running FS_WAIT_RC=0
finish && grep -q 'wait job/imas-core-farmer-sprout-release-register --for=condition=complete' "$state/calls.log" &&
	ok "a registration Job still running is waited for, then verified" || { bad "a running Job that completes"; show; }

scenario registered
if finish; then
	ok "registered as stamped (200, created 0, the chart's packages): finish.sh passes"
	says '"status":200' && says '"version":"v0.1.0-rc.4"' && ok "... and says what is registered" || { bad "the registered line"; show; }
else bad "registered as stamped: finish.sh fails"; show; fi
grep -qxF "curl https://imas-core-farmer-saasapi-operator.imas-core.svc.cluster.local:40123/v1/operator/fleet-releases resolve=imas-core-farmer-saasapi-operator.imas-core.svc.cluster.local:40123:127.0.0.1 auth=yes" "$state/curl.log" &&
	ok "the operator API is asked on the Service's name through the port-forward, with the operator token" ||
	bad "the operator API call ($(cat "$state/curl.log" 2>/dev/null))"
jq -e --slurpfile r "$tmp/request.json" '. == $r[0]' "$state/body.json" >/dev/null && ok "verify sends exactly the hook's request" || bad "verify sent another body"
! grep -rqF "$FS_TOKEN" "$state/calls.log" "$state/curl.log" "$state/out" && ok "the token is never in argv or the output" || bad "the token leaked into argv or the output"

scenario not-stored
export FS_STATUS=201
jq '.created = 2' "$tmp/held.json" >"$tmp/created.json"
export FS_RESPONSE="$tmp/created.json"
finish && { bad "a release the verify had to create (201) passes"; show; } ||
	{ says "answered 201" && ok "201 (the Job had not stored it): finish.sh fails" || { bad "201: wrong message"; show; }; }

scenario conflict
export FS_STATUS=409
echo '{"error":"release_conflict","message":"checksums_txt differs"}' >"$tmp/conflict.json"
export FS_RESPONSE="$tmp/conflict.json"
finish && { bad "409 passes"; show; } ||
	{ says "answered 409" && says "release_conflict" && ok "409 (other checksums or signature stored): finish.sh fails, naming the error" || { bad "409: wrong message"; show; }; }

scenario other-packages
jq '.packages |= .[:1]' "$tmp/held.json" >"$tmp/fewer.json"
export FS_RESPONSE="$tmp/fewer.json"
finish && { bad "an answer missing a package passes"; show; } ||
	{ says "does not match the chart's release" && ok "an answer without every package: finish.sh fails" || { bad "missing package: wrong message"; show; }; }

scenario other-version
jq '.version = "v0.1.0-rc.3"' "$tmp/request.json" >"$tmp/rc3.json"
export FS_REQUEST="$tmp/rc3.json"
finish && { bad "a chart of another release passes"; show; } ||
	{ says "not $tag" && ok "the chart's release is not release_tag: finish.sh fails" || { bad "another release: wrong message"; show; }; }
[[ ! -e "$state/curl.log" ]] && ok "... before asking the operator API" || bad "the operator API was asked for another release"

scenario no-configmap
export FS_REQUEST=""
finish && { bad "no request ConfigMap passes"; show; } ||
	{ says "did not render" && ok "no request ConfigMap: finish.sh fails" || { bad "no ConfigMap: wrong message"; show; }; }

# --- operator-release.sh post-altered --------------------------------------------
scenario altered
export FS_STATUS=201
echo '{"version":"v0.1.1-uat.altered","created":2}' >"$tmp/scratch.json"
export FS_RESPONSE="$tmp/scratch.json"
if "$core/operator-release.sh" "$kubeconfig" "$ep" "$state" post-altered v0.1.1-uat.altered >"$state/out" 2>&1; then
	jq -e '.status == 201 and .body.version == "v0.1.1-uat.altered"' "$state/out" >/dev/null &&
		ok "post-altered prints the operator API's status and answer" || { bad "post-altered output"; show; }
else bad "post-altered against a 201"; show; fi
jq -e --slurpfile o "$tmp/request.json" '
	.version == "v0.1.1-uat.altered"
	and ([.packages[].file_name] == ["imas-sprout_0.1.1-uat.altered_linux_amd64.deb", "imas-sprout_0.1.1-uat.altered_linux_amd64.rpm"])
	and ([.packages[].checksum_sha256] == [$o[0].packages[].checksum_sha256])
	and .checksums_txt != $o[0].checksums_txt
	and (.checksums_txt | contains("imas-sprout_0.1.1-uat.altered_linux_amd64.deb"))
	and .checksums_sig == $o[0].checksums_sig and .min_sprout_version == $o[0].min_sprout_version' "$state/body.json" >/dev/null &&
	ok "post-altered: the scratch version in every file name and checksums.txt, the release's signature kept" ||
	{ bad "post-altered body"; sed 's/^/      /' "$state/body.json"; }
scenario altered-refused
export FS_STATUS=422
echo '{"error":"invalid_checksums"}' >"$tmp/refused.json"
export FS_RESPONSE="$tmp/refused.json"
"$core/operator-release.sh" "$kubeconfig" "$ep" "$state" post-altered v0.1.1-uat.altered >"$state/out" 2>&1 &&
	{ bad "post-altered exits 0 on a 422"; show; } ||
	{ jq -e '.status == 422 and .body.error == "invalid_checksums"' "$state/out" >/dev/null && ok "post-altered exits 1 on a refusal, printing it" || { bad "post-altered on a 422"; show; }; }
scenario altered-self
"$core/operator-release.sh" "$kubeconfig" "$ep" "$state" post-altered "$tag" >"$state/out" 2>&1 &&
	bad "post-altered accepts the release's own version" ||
	{ says "must not be the release itself" && ok "post-altered refuses the release's own version" || { bad "post-altered self: wrong message"; show; }; }
"$core/operator-release.sh" "$kubeconfig" "$ep" "$state" post-altered latest >"$state/out" 2>&1 &&
	bad "post-altered accepts a non-semver version" ||
	{ says "vMAJOR.MINOR.PATCH" && ok "post-altered refuses a non-semver version" || { bad "post-altered latest: wrong message"; show; }; }
rm -f "$state/core/sensitive/saasapi-operator-token"
"$core/operator-release.sh" "$kubeconfig" "$ep" "$state" verify "$tag" >"$state/out" 2>&1 &&
	bad "operator-release.sh runs without the operator token" ||
	{ says "no operator token" && ok "operator-release.sh needs the operator token file" || { bad "no token: wrong message"; show; }; }

if ((failed)); then
	printf '%d finish.sh check(s) failed\n' "$failed"
	exit 1
fi
printf 'all finish.sh checks passed\n'
