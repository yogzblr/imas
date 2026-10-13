#!/usr/bin/env bash
# validate-rustfs.sh <kubeconfig> <endpoints.json> <state-dir>
#
# Proves, against the UAT RustFS, that each scoped credential
# rustfs-setup.sh made reaches what it must and nothing else (design D22,
# P13): with each user's own access key it PUTs, GETs and lists in the
# recipe, job and sprout JWT buckets and the accounts bucket, and expects
# 200 where its policy allows the call and 403 where it does not:
#
#   farmer           recipes, jobs, sprout JWTs: put, get, list. accounts: none
#   saasapi          recipes under tenants/*/recipes/: put, get, list; the
#                    rest of the recipe bucket, jobs, sprout JWTs, accounts: none
#   accounts writer  accounts: put, get, list. recipes, sprout JWTs: none
#   accounts reader  accounts: get, list, but no put. recipes, sprout JWTs: none
#
# Probe objects live under a per-run prefix (uat-validate-<random>/, and
# tenants/uat-validate-<random>/recipes/ for saasapi) and are deleted at the
# end with the root credential, so the account loader and farmer never see
# them. Runs in the RustFS pod through kubectl exec with the curl in the
# image (as rustfs-setup.sh does); each user's secret key goes over stdin,
# never argv. Prints one PASS or FAIL line per call and a count; exits 1 if
# any failed. install.sh runs it after rustfs-setup.sh. Not for
# object_store.mode external (the operator's store, which install.sh does
# not provision). FLAG FOR SECURITY REVIEW.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "validate-rustfs.sh <kubeconfig> <endpoints.json> <state-dir>" "$@"
need_cmd kubectl openssl
[[ "$S3_MODE" == rustfs ]] || die "object_store.mode is $S3_MODE: validate-rustfs.sh checks the UAT RustFS only"

s3dir="$SENSITIVE_DIR/s3"
for f in farmer-access-key-id farmer-secret-access-key saasapi-access-key-id saasapi-secret-access-key \
	accounts-writer-access-key-id accounts-writer-secret-access-key \
	accounts-reader/access-key-id accounts-reader/secret-access-key; do
	[[ -s "$s3dir/$f" ]] || die "no $s3dir/$f: run rustfs-setup.sh first"
done

run_id="uat-validate-$(openssl rand -hex 4)"
R=$RECIPE_BUCKET J=$JOB_BUCKET W=$SPROUT_JWT_BUCKET A=$ACCOUNTS_BUCKET
P=$run_id
T="tenants/$run_id/recipes"

# The program each exec runs: line 1 of stdin is the access key, line 2 the
# secret key (empty: the pod's root credential), the rest one probe per
# line, "<allow|deny|any> <METHOD> <path> <label>". The body of a PUT is a
# fixed string; the root credential's DELETEs accept any answer.
# shellcheck disable=SC2016
probe_sh='
IFS= read -r ak; IFS= read -r sk
if [ -z "$sk" ]; then ak=$RUSTFS_ACCESS_KEY; sk=$RUSTFS_SECRET_KEY; fi
printf "imas uat validate-rustfs probe\n" >/tmp/vr.body
bh=$(sha256sum /tmp/vr.body | cut -d" " -f1)
eh=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
while read -r want m p label; do
	[ -n "$want" ] || continue
	if [ "$m" = PUT ]; then set -- --data-binary @/tmp/vr.body -H "x-amz-content-sha256: $bh"
	else set -- -H "x-amz-content-sha256: $eh"; fi
	c=$(curl -sS -o /dev/null -w "%{http_code}" -X "$m" "$@" --aws-sigv4 "aws:amz:us-east-1:s3" \
		--user "$ak:$sk" "http://127.0.0.1:9000$p" 2>/dev/null) || c=000
	case "$want:$c" in
	allow:200 | allow:204 | deny:403 | any:*) echo "PASS $label (http $c)" ;;
	*) echo "FAIL $label: http $c, want $want" ;;
	esac
done
rm -f /tmp/vr.body
'

# probes <user label> <access key file> <secret key file> <probe lines...>
results=()
probes() {
	local who="$1" ak="$2" sk="$3" line out
	shift 3
	out=$({ cat "$ak"; echo; cat "$sk"; echo; printf '%s\n' "$@"; } |
		kc -n "$UAT_NS" exec -i "deploy/$RUSTFS_SVC" -c rustfs -- /bin/sh -ec "$probe_sh" 2>/dev/null) ||
		out="FAIL $who: could not run the probes in deploy/$RUSTFS_SVC"
	while IFS= read -r line; do
		[[ -n "$line" ]] && results+=("${line%% *} $who: ${line#* }")
	done <<<"$out"
}
list() { printf '/%s?list-type=2&prefix=%s/' "$1" "$2"; }

probes farmer "$s3dir/farmer-access-key-id" "$s3dir/farmer-secret-access-key" \
	"allow PUT /$R/$P/recipe put on $R" "allow GET /$R/$P/recipe get on $R" "allow GET $(list "$R" "$P") list on $R" \
	"allow PUT /$J/$P/job put on $J" "allow GET /$J/$P/job get on $J" "allow GET $(list "$J" "$P") list on $J" \
	"allow PUT /$W/$P/jwt put on $W" "allow GET /$W/$P/jwt get on $W" "allow GET $(list "$W" "$P") list on $W" \
	"deny PUT /$A/$P/farmer put on $A" "deny GET $(list "$A" "$P") list on $A"
probes saasapi "$s3dir/saasapi-access-key-id" "$s3dir/saasapi-secret-access-key" \
	"allow PUT /$R/$T/recipe put on $R/tenants/*/recipes/" "allow GET /$R/$T/recipe get on $R/tenants/*/recipes/" \
	"allow GET $(list "$R" "$T") list on $R/tenants/*/recipes/" \
	"deny PUT /$R/$P/saasapi put outside tenants/*/recipes/" "deny GET /$R/$P/recipe get outside tenants/*/recipes/" \
	"deny PUT /$J/$P/saasapi put on $J" "deny GET $(list "$J" "$P") list on $J" \
	"deny GET /$W/$P/jwt get on $W" "deny PUT /$A/$P/saasapi put on $A"
probes "accounts writer" "$s3dir/accounts-writer-access-key-id" "$s3dir/accounts-writer-secret-access-key" \
	"allow PUT /$A/$P/account put on $A" "allow GET /$A/$P/account get on $A" "allow GET $(list "$A" "$P") list on $A" \
	"deny PUT /$R/$P/writer put on $R" "deny GET /$R/$P/recipe get on $R" "deny GET /$W/$P/jwt get on $W"
probes "accounts reader" "$s3dir/accounts-reader/access-key-id" "$s3dir/accounts-reader/secret-access-key" \
	"allow GET /$A/$P/account get on $A" "allow GET $(list "$A" "$P") list on $A" "deny PUT /$A/$P/reader put on $A" \
	"deny GET /$R/$P/recipe get on $R" "deny GET $(list "$R" "$P") list on $R" "deny GET /$W/$P/jwt get on $W"

# Clean up with the pod's root credential (empty key lines).
cleanup=()
for o in "$R/$P/recipe" "$R/$T/recipe" "$J/$P/job" "$W/$P/jwt" "$A/$P/account" \
	"$R/$P/saasapi" "$J/$P/saasapi" "$A/$P/saasapi" "$A/$P/farmer" "$R/$P/writer" "$A/$P/reader"; do
	cleanup+=("any DELETE /$o delete $o")
done
if ! { printf '\n\n'; printf '%s\n' "${cleanup[@]}"; } |
	kc -n "$UAT_NS" exec -i "deploy/$RUSTFS_SVC" -c rustfs -- /bin/sh -ec "$probe_sh" >/dev/null 2>&1; then
	results+=("FAIL root: could not delete the probe objects under $P/ and $T/")
fi

failed=0
for r in "${results[@]}"; do
	case "$r" in
	PASS\ *) printf 'PASS  %s\n' "${r#PASS }" ;;
	*)
		printf 'FAIL  %s\n' "${r#FAIL }"
		failed=$((failed + 1))
		;;
	esac
done
total=${#results[@]}
((total > 0)) || die "no probe ran"
if ((failed)); then
	die "validate-rustfs: $failed of $total checks failed"
fi
log "validate-rustfs: $total of $total checks passed (prefix $P/, removed)"
