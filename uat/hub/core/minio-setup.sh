#!/usr/bin/env bash
# minio-setup.sh <kubeconfig> <endpoints.json> <state-dir> <saasapi-policy.json>
#
# Inside the UAT-only MinIO (AGPL-3.0, test only): the recipe and job
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
# Uses the mc client that ships inside the MinIO server image, through
# kubectl exec: no mc image is pulled (the repo avoids it) and no MinIO
# admin credential leaves the MinIO pod. The root credential is read from
# the pod's own environment. A user's secret key is passed on stdin; it is
# an argument of mc inside the MinIO pod only.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "minio-setup.sh <kubeconfig> <endpoints.json> <state-dir> <saasapi-policy.json>" "$@"
[[ $# -ge 4 && -f "$4" ]] || die "usage: minio-setup.sh <kubeconfig> <endpoints.json> <state-dir> <saasapi-policy.json>"
saasapi_policy_src="$4"
need_cmd kubectl jq

grep -q RECIPE_BUCKET "$saasapi_policy_src" || die "$saasapi_policy_src has no RECIPE_BUCKET placeholder"

# mc in the MinIO pod, as root, with the alias taken from the pod's env.
minio_sh() {
	kc -n "$UAT_NS" exec -i "deploy/$MINIO_SVC" -c minio -- /bin/sh -ec \
		'export MC_HOST_local="http://${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}@127.0.0.1:9000"; '"$1"
}

minio_sh 'command -v mc >/dev/null || { echo "no mc in the MinIO image" >&2; exit 1; }; mc ready local' </dev/null >/dev/null ||
	die "MinIO is not ready, or its image has no mc client"
minio_sh "mc mb --ignore-existing local/$RECIPE_BUCKET && mc mb --ignore-existing local/$JOB_BUCKET" </dev/null >/dev/null
log "buckets $RECIPE_BUCKET and $JOB_BUCKET exist"

# policy <name> <json on stdin>
policy() {
	minio_sh "cat > /tmp/$1.json && mc admin policy create local $1 /tmp/$1.json >/dev/null && rm -f /tmp/$1.json"
	log "MinIO policy $1 written"
}
sed -e "s/RECIPE_BUCKET/$RECIPE_BUCKET/g" -e "s/JOB_BUCKET/$JOB_BUCKET/g" "$here/minio/farmer-policy.json" |
	policy imas-uat-farmer
sed -e "s/RECIPE_BUCKET/$RECIPE_BUCKET/g" "$saasapi_policy_src" | policy imas-uat-saasapi-recipes

# user <name> <policy> <secret file>: creates or updates the user and
# attaches exactly that policy.
user() {
	tr -d '\n' <"$3" | minio_sh "IFS= read -r s || [ -n \"\$s\" ]; mc admin user add local $1 \"\$s\" >/dev/null"
	minio_sh "mc admin policy attach local $2 --user $1 >/dev/null 2>&1 || mc admin user info local $1 --json | grep -q '\"$2\"'" </dev/null ||
		die "could not attach MinIO policy $2 to $1"
	log "MinIO user $1 has policy $2"
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
