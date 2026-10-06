#!/usr/bin/env bash
# openbao-bootstrap.sh <kubeconfig> <endpoints.json> <state-dir>
#
# Initialises and unseals the farmer chart's OpenBao subchart (standalone,
# file storage; values/farmer-uat.yaml turns dev mode off), enables the
# Transit engine and creates the Ed25519 key the gateway JWT needs under
# the name the chart expects (farmer.openbao.gateway.keyName,
# imas-gateway-jwt), then hands the chart's own bootstrap Job its token
# (openbaoBootstrap.tokenSecretName). The chart's Job does the rest
# (policies, roles, KV, the fleet key) and is idempotent.
#
# FLAG FOR SECURITY REVIEW.
# !!! UAT ONLY: THE UNSEAL KEYS AND THE ROOT TOKEN ARE STORED IN A        !!!
# !!! KUBERNETES SECRET IN THE CORE NAMESPACE (imas-uat-openbao-unseal,   !!!
# !!! imas-uat-openbao-root) AND IN <state>/core/sensitive/openbao-init.json,
# !!! WHICH THE RUN KEEPS AS A SENSITIVE ARTIFACT. Anyone who can read     !!!
# !!! either can unseal this OpenBao and read everything in it. That is   !!!
# !!! acceptable for a throwaway per-run environment and nowhere else.    !!!
#
# Safe to re-run: an initialised OpenBao is not re-initialised; a sealed
# one (after a pod restart) is unsealed with the stored keys.
# install.sh runs it while `helm install` is in progress: OpenBao's pod
# is created by the install, and the chart's post-install hooks wait for
# it (the bootstrap Job loops on `bao status` until it is unsealed).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "openbao-bootstrap.sh <kubeconfig> <endpoints.json> <state-dir>" "$@"
need_cmd kubectl jq
KEY_SHARES="${OPENBAO_KEY_SHARES:-3}"
KEY_THRESHOLD="${OPENBAO_KEY_THRESHOLD:-2}"
if ! [[ "$KEY_SHARES" =~ ^[1-9]$ && "$KEY_THRESHOLD" =~ ^[1-9]$ ]] || ((KEY_THRESHOLD > KEY_SHARES)); then
	die "OPENBAO_KEY_SHARES/OPENBAO_KEY_THRESHOLD must be 1-9 with threshold <= shares"
fi

init_file="$SENSITIVE_DIR/openbao-init.json"
token_file="$SENSITIVE_DIR/openbao-root-token"
unseal_file="$SENSITIVE_DIR/openbao-unseal-keys.json"

bao() { kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- env BAO_ADDR=http://127.0.0.1:8200 bao "$@"; }
# bao_root <command string>: runs a bao shell snippet in the pod with the
# root token, which goes over stdin (never argv, never the log).
bao_root() {
	kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- /bin/sh -ec \
		'IFS= read -r BAO_TOKEN || [ -n "$BAO_TOKEN" ]; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; '"$1" <"$token_file"
}

# bao status exits 0 unsealed, 2 sealed, 1 on error; any of 0/2 means the
# server answers.
status_json() {
	local out rc=0
	out=$(bao status -format=json </dev/null 2>/dev/null) || rc=$?
	[[ $rc -eq 0 || $rc -eq 2 ]] || return 1
	printf '%s' "$out"
}

log "waiting for $CORE_NS/$OPENBAO_POD to answer (created by the farmer chart install)"
wait_for 1200 "OpenBao server in $OPENBAO_POD" status_json
st=$(status_json)

if [[ "$(jq -r .initialized <<<"$st")" != true ]]; then
	[[ ! -s "$init_file" ]] || die "$init_file exists but OpenBao is not initialised: a different OpenBao? Move the old file away first"
	log "initialising OpenBao ($KEY_SHARES key shares, threshold $KEY_THRESHOLD)"
	(umask 077 && bao operator init -format=json -key-shares="$KEY_SHARES" -key-threshold="$KEY_THRESHOLD" </dev/null >"$init_file") ||
		die "bao operator init failed"
	jq -e '(.unseal_keys_b64 | length) > 0 and (.root_token | length) > 0' "$init_file" >/dev/null ||
		die "bao operator init gave no unseal keys or root token"
	log "!!! UAT ONLY: unseal keys and root token written to $init_file (sensitive artifact)"
fi

# The local files are derived from the init output, or restored from the
# cluster when this runner never saw the init (e.g. a re-run elsewhere).
if [[ -s "$init_file" ]]; then
	(umask 077 && jq -j .root_token "$init_file" >"$token_file")
	(umask 077 && jq '{threshold: .unseal_threshold, keys: .unseal_keys_b64}' "$init_file" >"$unseal_file")
else
	log "no $init_file here: restoring the unseal keys and root token from the cluster"
	(umask 077 && kc -n "$CORE_NS" get secret "$OPENBAO_UNSEAL_SECRET" -o json |
		jq -r '.data["unseal-keys.json"] | @base64d' >"$unseal_file") ||
		die "OpenBao is initialised but neither $init_file nor Secret $OPENBAO_UNSEAL_SECRET exists: it can't be unsealed (rebuild the cluster)"
	(umask 077 && kc -n "$CORE_NS" get secret "$OPENBAO_ROOT_SECRET" -o json |
		jq -j '.data.token | @base64d' >"$token_file") ||
		die "Secret $OPENBAO_ROOT_SECRET is missing"
fi
jq -e '(.keys | length) >= .threshold' "$unseal_file" >/dev/null || die "unseal key file is malformed"

# UAT ONLY: the unseal keys in a Kubernetes Secret, so a re-run (or a
# person) can unseal after a pod restart without this runner's files.
apply_secret "$CORE_NS" "$OPENBAO_UNSEAL_SECRET" "unseal-keys.json=$unseal_file"

st=$(status_json)
if [[ "$(jq -r .sealed <<<"$st")" == true ]]; then
	log "unsealing OpenBao"
	threshold=$(jq -r .threshold "$unseal_file")
	for ((i = 0; i < threshold; i++)); do
		# sys/unseal needs no token; the key goes on stdin (key=-).
		jq -j --argjson i "$i" '.keys[$i]' "$unseal_file" |
			bao write -format=json sys/unseal key=- >/dev/null ||
			die "unseal with key $((i + 1)) failed"
	done
	st=$(status_json)
	[[ "$(jq -r .sealed <<<"$st")" == false ]] || die "OpenBao is still sealed after $threshold keys"
fi
log "OpenBao is initialised and unsealed"

# Transit and the gateway JWT key. The chart's bootstrap Job makes the same
# checks before it creates anything, so whichever runs first wins and the
# other changes nothing.
key_json=$(bao_root "
	bao secrets list -format=json | grep -q '\"transit/\"' || bao secrets enable -path=transit transit >/dev/null
	bao read transit/keys/$GATEWAY_KEY >/dev/null 2>&1 || bao write -f transit/keys/$GATEWAY_KEY type=ed25519 >/dev/null
	bao read -format=json transit/keys/$GATEWAY_KEY") || die "enabling Transit or creating $GATEWAY_KEY failed"
[[ "$(jq -r .data.type <<<"$key_json")" == ed25519 ]] ||
	die "transit/keys/$GATEWAY_KEY exists but is not ed25519 ($(jq -r .data.type <<<"$key_json"))"
log "transit/keys/$GATEWAY_KEY is ed25519"

# Last: the chart's bootstrap Job can't start until this Secret exists, so
# it never races the Transit setup above.
apply_secret "$CORE_NS" "$OPENBAO_ROOT_SECRET" "token=$token_file"
log "!!! UAT ONLY: OpenBao root token in Secret $CORE_NS/$OPENBAO_ROOT_SECRET, unseal keys in $CORE_NS/$OPENBAO_UNSEAL_SECRET"
