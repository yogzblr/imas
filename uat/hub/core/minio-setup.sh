#!/usr/bin/env bash
# minio-setup.sh <kubeconfig> <endpoints.json> <state-dir> <saasapi-policy.json>
#
# Inside the UAT RustFS object store (Apache-2.0): the recipe and job
# buckets, a user for farmer and a user for saasapi, each with its own
# policy, and the two Kubernetes Secrets the farmer chart names
# (objectStore.credentialsSecret, saasapi.recipes.credentialsSecret).
# FLAG FOR SECURITY REVIEW.
#
# <saasapi-policy.json> is files/objectstore-policies/saasapi-recipes.json
# from the published chart (install.sh extracts it), so saasapi runs with
# the release's own reviewed policy; saasapi's startup check
# (saasapi.recipes.credentialCheck) then proves the limit holds.
#
# Uses the curl that ships inside the RustFS server image (Alpine), through
# kubectl exec: no extra client image is pulled (the repo avoids it) and no
# RustFS admin credential leaves the RustFS pod. The root credential is read
# from the pod's own environment (RUSTFS_ACCESS_KEY / RUSTFS_SECRET_KEY).
# Requests are SigV4-signed by curl itself (--aws-sigv4) against RustFS's
# admin API (/rustfs/admin/v3, plain JSON bodies) and its S3 API. A user's
# secret key is passed on stdin and written to a file inside the RustFS pod
# only (its /tmp emptyDir, removed straight after).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "minio-setup.sh <kubeconfig> <endpoints.json> <state-dir> <saasapi-policy.json>" "$@"
[[ $# -ge 4 && -f "$4" ]] || die "usage: minio-setup.sh <kubeconfig> <endpoints.json> <state-dir> <saasapi-policy.json>"
saasapi_policy_src="$4"
need_cmd kubectl jq

grep -q RECIPE_BUCKET "$saasapi_policy_src" || die "$saasapi_policy_src has no RECIPE_BUCKET placeholder"

# rustfs_sh <script>: runs <script> in the RustFS pod with the helper
# `rf METHOD PATH [BODYFILE]` defined. rf signs with the root credential
# from the pod's env, sends the body's sha256 (RustFS requires
# x-amz-content-sha256), prints the HTTP status code on the last line and
# any response body before it.
rustfs_sh() {
	kc -n "$UAT_NS" exec -i "deploy/$MINIO_SVC" -c rustfs -- /bin/sh -ec '
rf() {
	m=$1; p=$2; f=${3:-}
	if [ -n "$f" ]; then h=$(sha256sum "$f" | cut -d" " -f1); set -- --data-binary "@$f" -H "Content-Type: application/json"
	else h=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; set --; fi
	curl -sS -o /tmp/rf.out -w "%{http_code}" -X "$m" "$@" \
		--aws-sigv4 "aws:amz:us-east-1:s3" --user "$RUSTFS_ACCESS_KEY:$RUSTFS_SECRET_KEY" \
		-H "x-amz-content-sha256: $h" "http://127.0.0.1:9000$p"
}
'"$1"
}

# Ready? (the readiness probe already gates the rollout; this proves the
# root credential works against the S3 API.)
code=$(rustfs_sh 'rf GET /' </dev/null) || die "RustFS is not reachable (or its image has no curl)"
[[ "$code" == 200 ]] || die "RustFS root credential rejected on GET / (http $code)"

bucket() {
	local c
	c=$(rustfs_sh "rf PUT /$1" </dev/null) || die "could not create bucket $1"
	# 200 = created; 409 = already ours (BucketAlreadyOwnedByYou / Exists).
	[[ "$c" == 200 || "$c" == 409 ]] || die "creating bucket $1: http $c"
}
bucket "$RECIPE_BUCKET"
bucket "$JOB_BUCKET"
log "buckets $RECIPE_BUCKET and $JOB_BUCKET exist"

# policy <name> <json on stdin>
policy() {
	local c
	c=$(rustfs_sh "cat > /tmp/p.json; rf PUT '/rustfs/admin/v3/add-canned-policy?name=$1' /tmp/p.json; rm -f /tmp/p.json") ||
		die "could not write RustFS policy $1"
	[[ "$c" == 200 ]] || die "RustFS add-canned-policy $1: http $c"
	log "RustFS policy $1 written"
}
sed -e "s/RECIPE_BUCKET/$RECIPE_BUCKET/g" -e "s/JOB_BUCKET/$JOB_BUCKET/g" "$here/minio/farmer-policy.json" |
	policy imas-uat-farmer
sed -e "s/RECIPE_BUCKET/$RECIPE_BUCKET/g" "$saasapi_policy_src" | policy imas-uat-saasapi-recipes

# user <name> <policy> <secret file>: creates or updates the user and
# attaches exactly that policy.
user() {
	local c
	c=$(jq -nc --rawfile s "$3" '{secretKey: ($s | rtrimstr("\n")), status: "enabled"}' |
		rustfs_sh "cat > /tmp/u.json; rf PUT '/rustfs/admin/v3/add-user?accessKey=$1' /tmp/u.json; rm -f /tmp/u.json") ||
		die "could not add RustFS user $1"
	[[ "$c" == 200 ]] || die "RustFS add-user $1: http $c"
	c=$(rustfs_sh "rf PUT '/rustfs/admin/v3/set-user-or-group-policy?policyName=$2&userOrGroup=$1&isGroup=false'" </dev/null) ||
		die "could not attach RustFS policy $2 to $1"
	[[ "$c" == 200 ]] || die "attaching RustFS policy $2 to $1: http $c"
	log "RustFS user $1 has policy $2"
}

s3dir="$SENSITIVE_DIR/s3"
(umask 077 && mkdir -p "$s3dir")
printf '%s' "$S3_FARMER_USER" >"$s3dir/farmer-access-key-id"
printf '%s' "$S3_SAASAPI_USER" >"$s3dir/saasapi-access-key-id"
gen_secret_file "$s3dir/farmer-secret-access-key" 24
gen_secret_file "$s3dir/saasapi-secret-access-key" 24

user "$S3_FARMER_USER" imas-uat-farmer "$s3dir/farmer-secret-access-key"
user "$S3_SAASAPI_USER" imas-uat-saasapi-recipes "$s3dir/saasapi-secret-access-key"

apply_secret "$CORE_NS" "$S3_FARMER_SECRET" \
	"access-key-id=$s3dir/farmer-access-key-id" "secret-access-key=$s3dir/farmer-secret-access-key"
apply_secret "$CORE_NS" "$S3_SAASAPI_SECRET" \
	"access-key-id=$s3dir/saasapi-access-key-id" "secret-access-key=$s3dir/saasapi-secret-access-key"
