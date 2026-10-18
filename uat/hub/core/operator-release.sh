#!/usr/bin/env bash
# operator-release.sh <kubeconfig> <endpoints.json> <state-dir> verify <release_tag>
# operator-release.sh <kubeconfig> <endpoints.json> <state-dir> post-altered <scratch_version>
#
# saasapi's operator API (POST /v1/operator/fleet-releases, API design
# §2.5), reached from outside the cluster through `kubectl port-forward` to
# the operator Service (it has no other way in: its NetworkPolicy admits the
# registration hook Job only). TLS is verified against the ca.crt of the
# operator listener's Secret, for the Service's name (the name on its
# certificate), and the request carries the operator token from
# <state>/core/sensitive/saasapi-operator-token (saasapi-secrets.sh), from a
# header file, never argv. The request body is the one the chart's
# registration hook Job sends: request.json of ConfigMap
# imas-core-farmer-sprout-release (the stamped files/sprout-release.json and
# the chart's channel).
#
#   verify <release_tag>
#       finish.sh's check that the release is registered: POSTs that same
#       request again. saasapi stores a release immutably and answers a
#       repeat of exactly what it holds with 200 and nothing created
#       (created 0); a version holding different checksums_txt or
#       checksums_sig is 409, and one missing rows or its checksums row would
#       be written now (201). So only a 200 with created 0, the version
#       release_tag, not revoked and every package of the request proves the
#       release is registered with its GPG-signed checksums.txt and signature
#       stored. Prints one JSON line (status, version, packages); exit 1
#       otherwise, saying why.
#   post-altered <scratch_version>
#       The L5 refusal case (uat/tests): registers <scratch_version> with the
#       release's packages and checksums.txt, its version rewritten in every
#       file name, and the release's own checksums.txt.sig. checksums.txt
#       is then altered, so the signature no longer verifies and a sprout
#       must refuse the version. saasapi checks only that checksums.txt is
#       well formed and lists the packages (it never verifies the
#       signature: D20), so it accepts the pair. Prints one JSON line
#       {"status": <http status>, "body": <response>}; exit 0 on 200 or 201.
#
# FLAG FOR SECURITY REVIEW: this presents the operator token. UAT only.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
usage="operator-release.sh <kubeconfig> <endpoints.json> <state-dir> verify <release_tag> | post-altered <scratch_version>"
parse_common_args "$usage" "$@"
[[ $# -eq 5 ]] || die "usage: $usage"
mode="$4"
arg="$5"
semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
case "$mode" in
verify) release_version "$arg" >/dev/null ;;
post-altered) [[ "$arg" =~ $semver_re ]] || die "scratch version must be vMAJOR.MINOR.PATCH[-PRERELEASE], got: $arg" ;;
*) die "usage: $usage" ;;
esac
need_cmd kubectl jq curl base64

token_file="$SENSITIVE_DIR/$OPERATOR_TOKEN_FILE"
[[ -s "$token_file" ]] || die "no operator token at $token_file: run saasapi-secrets.sh (install.sh) first"

tmp=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/imas-uat-operator.XXXXXX")
pf_pid=""
cleanup() {
	[[ -z "$pf_pid" ]] || kill "$pf_pid" 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT

kc -n "$CORE_NS" get configmap "$SPROUT_RELEASE_CONFIGMAP" -o json 2>/dev/null |
	jq -er '.data["request.json"]' >"$tmp/request.json" ||
	die "no ConfigMap $CORE_NS/$SPROUT_RELEASE_CONFIGMAP with request.json: the registration hook did not render (is saasapi.operator.enabled on, and the chart release-stamped?)"
jq -e 'type == "object" and (.version | type == "string") and (.packages | type == "array" and length > 0)
	and (.checksums_txt | type == "string" and length > 0) and (.checksums_sig | type == "string" and length > 0)' \
	"$tmp/request.json" >/dev/null || die "$SPROUT_RELEASE_CONFIGMAP request.json is not a sprout release request"
kc -n "$CORE_NS" get secret "$OPERATOR_TLS_SECRET" -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d >"$tmp/ca.crt" ||
	die "can't read ca.crt of Secret $CORE_NS/$OPERATOR_TLS_SECRET"
grep -q 'BEGIN CERTIFICATE' "$tmp/ca.crt" || die "Secret $CORE_NS/$OPERATOR_TLS_SECRET has no ca.crt"
printf 'Authorization: Bearer %s\n' "$(tr -d '[:space:]' <"$token_file")" >"$tmp/auth.hdr"

case "$mode" in
verify)
	jq -e --arg v "$arg" '.version == $v' "$tmp/request.json" >/dev/null ||
		die "the chart's sprout release is $(jq -r .version "$tmp/request.json"), not $arg: the chart under test must be the one published with $arg"
	cp "$tmp/request.json" "$tmp/body.json"
	;;
post-altered)
	jq -e --arg v "$arg" '.version != $v' "$tmp/request.json" >/dev/null ||
		die "the scratch version must not be the release itself ($arg)"
	jq --arg v "$arg" '
		(.version | ltrimstr("v")) as $old | ($v | ltrimstr("v")) as $new |
		.version = $v
		| .packages |= map(.file_name |= gsub($old | gsub("\\."; "\\."); $new))
		| .checksums_txt |= gsub($old | gsub("\\."; "\\."); $new)' "$tmp/request.json" >"$tmp/body.json"
	# Altered means altered: the signature is over the original bytes.
	jq -e --slurpfile o "$tmp/request.json" '.checksums_txt != $o[0].checksums_txt and .checksums_sig == $o[0].checksums_sig' \
		"$tmp/body.json" >/dev/null || die "could not alter checksums.txt for $arg (no file name carries the release's version)"
	;;
esac

# The operator Service through a local port kubectl picks.
# kubectl itself in the background (not the kc function), so $! is its own
# pid and killing it ends the tunnel.
# The log exists before kubectl starts: the shell opens a ">" redirect
# only in the forked child, and the loop below would otherwise run sed on
# a file that is not there yet (and, with pipefail, exit).
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

code=$(curl -sS --proto '=https' --max-time 60 --cacert "$tmp/ca.crt" \
	--resolve "$OPERATOR_FQDN:$lport:127.0.0.1" -H "@$tmp/auth.hdr" -H 'Content-Type: application/json' \
	--data-binary "@$tmp/body.json" -o "$tmp/response.json" -w '%{http_code}' \
	"https://$OPERATOR_FQDN:$lport/v1/operator/fleet-releases") || code=000
[[ -s "$tmp/response.json" ]] && jq -e . "$tmp/response.json" >/dev/null 2>&1 || printf 'null' >"$tmp/response.json"

case "$mode" in
verify)
	if [[ "$code" != 200 ]]; then
		die "release $arg is not registered as the chart stamped it: the operator API answered $code to the same request ($(jq -c '{error, message}' "$tmp/response.json" 2>/dev/null))"
	fi
	jq -e --arg v "$arg" --slurpfile req "$tmp/request.json" '
		.version == $v and .created == 0 and .revoked == false
		and ([.packages[] | {os, arch, package_type, file_name, checksum_sha256}] | sort)
		    == ([$req[0].packages[] | {os, arch, package_type, file_name, checksum_sha256}] | sort)' \
		"$tmp/response.json" >/dev/null ||
		die "the operator API's answer for $arg does not match the chart's release: $(jq -c . "$tmp/response.json")"
	jq -c '{status: 200, version, packages: (.packages | length), checksums: "stored, identical to the stamped checksums.txt and checksums.txt.sig"}' "$tmp/response.json"
	;;
post-altered)
	jq -cn --argjson status "$((10#$code))" --slurpfile body "$tmp/response.json" '{status: $status, body: $body[0]}'
	[[ "$code" == 200 || "$code" == 201 ]] || exit 1
	;;
esac
