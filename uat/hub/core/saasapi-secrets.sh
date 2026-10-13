#!/usr/bin/env bash
# saasapi-secrets.sh <kubeconfig> <endpoints.json> <state-dir>
#
# The Secrets saasapi waits for, made by hand because this UAT install
# runs no External Secrets Operator (deploy/helm/farmer README, "Eval
# install"): imas-saasapi-nats (saasapi's NATS seed and the User JWT the
# publish Job wrote to OpenBao) and imas-saasapi-box (saasapi's box
# private key and the platform public key the keygen Job wrote). Exactly
# the fields the README names, and never <base>/platform. And the operator
# plane's bearer token (saasapi.operator.token, P20 option C): a random
# 64-character token, generated once per run into
# <state>/core/sensitive/saasapi-operator-token and kept on re-runs, in
# Secret imas-saasapi-operator-token (key current), a Secret of its own
# (the chart refuses a shared one). The operator listener's TLS Secret is
# cert-manager's (chart/templates/certificates.yaml).
# FLAG FOR SECURITY REVIEW.
#
# Run after `helm install` returns (its post-install hooks write the KV
# entries). Reads OpenBao with the UAT root token over stdin. The values go
# to files in a private temporary directory, into the Secrets, and are
# deleted; none is printed.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "saasapi-secrets.sh <kubeconfig> <endpoints.json> <state-dir>" "$@"
need_cmd kubectl

token_file="$SENSITIVE_DIR/openbao-root-token"
[[ -s "$token_file" ]] || die "no OpenBao root token at $token_file: run openbao-bootstrap.sh first"
[[ -s "$SEEDS_DIR/saasapi-user.nk" ]] || die "no saasapi-user.nk in $SEEDS_DIR: run seeds.sh first"

# kv_field <path> <field> <out file>
kv_field() {
	(umask 077 && kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- /bin/sh -ec \
		'IFS= read -r BAO_TOKEN || [ -n "$BAO_TOKEN" ]; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; bao kv get -field="$1" "$2"' \
		_ "$2" "$1" <"$token_file" >"$3") || die "could not read field $2 of secret/$1 from OpenBao"
	[[ -s "$3" ]] || die "secret/$1 field $2 is empty"
}

tmp=$(umask 077 && mktemp -d "$SENSITIVE_DIR/saasapi-secrets.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

kv_field "secret/platform/imas/saasapi-nats-user" jwt "$tmp/jwt"
kv_field "secret/imas/tenant-x25519/saasapi-box" priv "$tmp/box.key"
kv_field "secret/imas/tenant-x25519/controlplane-pub" platform_pub "$tmp/platform.pub"

apply_secret "$CORE_NS" "$SAASAPI_NATS_SECRET" \
	"nats-user.nk=$SEEDS_DIR/saasapi-user.nk" "SAASAPI_NATS_USER_JWT=$tmp/jwt"
apply_secret "$CORE_NS" "$SAASAPI_BOX_SECRET" \
	"saasapi-box.key=$tmp/box.key" "SAASAPI_PLATFORM_BOX_PUB=$tmp/platform.pub"

# saasapi refuses an operator token equal to the BFF's secret; two random
# draws never are, but a hand-edited state directory could be.
gen_secret_file "$SENSITIVE_DIR/$OPERATOR_TOKEN_FILE" 32
if cmp -s "$SENSITIVE_DIR/$OPERATOR_TOKEN_FILE" "$SENSITIVE_DIR/internal-auth-secret"; then
	die "$SENSITIVE_DIR/$OPERATOR_TOKEN_FILE equals the BFF secret: delete it and re-run"
fi
apply_secret "$CORE_NS" "$OPERATOR_TOKEN_SECRET" "current=$SENSITIVE_DIR/$OPERATOR_TOKEN_FILE"
