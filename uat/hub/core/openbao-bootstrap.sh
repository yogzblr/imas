#!/usr/bin/env bash
# openbao-bootstrap.sh <kubeconfig> <endpoints.json> <state-dir>
#
# Initialises and unseals the farmer chart's OpenBao subchart (standalone,
# single-node raft storage; values/farmer-uat.yaml turns dev mode off and
# sets the raft config), waits for the raft node to become active, enables the
# Transit engine and creates the Ed25519 key the gateway JWT needs under
# the name the chart expects (farmer.openbao.gateway.keyName,
# imas-gateway-jwt), then hands the chart's own bootstrap Job a token
# (openbaoBootstrap.tokenSecretName). The chart's Job does the rest
# (policies, roles, KV, the fleet key, the NATS platform Transit keys and
# the trust ConfigMap) and is idempotent.
#
# The Job revokes the token it is handed when it is done (owner decision a,
# no standing admin; openbaoBootstrap.revokeToken), so it is never handed
# the root token: every run of this script mints a fresh orphan token with
# the root policy, one hour, not renewable, and puts that in
# imas-uat-openbao-root. That is UAT's stand-in for "a fresh root token from
# the recovery quorum". install.sh deletes the Secret once the install's
# hooks are done; check.sh confirms the token is revoked (design T4).
#
# FLAG FOR SECURITY REVIEW.
# !!! UAT ONLY: THE UNSEAL KEYS AND THE ROOT TOKEN ARE STORED IN A        !!!
# !!! KUBERNETES SECRET IN THE CORE NAMESPACE (imas-uat-openbao-unseal)   !!!
# !!! AND IN <state>/core/sensitive/openbao-init.json, WHICH THE RUN      !!!
# !!! KEEPS AS A SENSITIVE ARTIFACT. Anyone who can read either can       !!!
# !!! unseal this OpenBao and read everything in it. That is acceptable   !!!
# !!! for a throwaway per-run environment and nowhere else.               !!!
#
# Safe to re-run: an initialised OpenBao is not re-initialised; a sealed
# one (after a pod restart) is unsealed with the stored keys.
#
# HA core hub (values/values-ha.yaml; brief H4): three raft pods with the
# static seal, so there are no unseal keys and no pod is ever unsealed
# here. Every pod unseals itself with the key in Secret imas-uat-openbao-seal
# (install.sh makes it before the chart) and joins the others (retry_join).
# This script initialises pod 0 once, with recovery keys (3 shares,
# threshold 2) instead of unseal keys, keeps them and the root token as in
# the single-node run (openbao-init.json, Secret imas-uat-openbao-unseal,
# keys recovery-keys.json and root-token), waits until every pod is
# unsealed and the raft configuration has every pod as a voter, and runs
# the Transit setup and the token mint below on the active node.
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
bootstrap_file="$SENSITIVE_DIR/openbao-bootstrap-token"

# The pod the bao commands below run in: pod 0, or on an HA hub the active
# raft node once there is one (active_pod).
bao_pod=$OPENBAO_POD
bao() { kc -n "$CORE_NS" exec -i "$bao_pod" -c openbao -- env BAO_ADDR=http://127.0.0.1:8200 bao "$@"; }
# bao_root <command string>: runs a bao shell snippet in the pod with the
# root token, which goes over stdin (never argv, never the log).
bao_root() {
	kc -n "$CORE_NS" exec -i "$bao_pod" -c openbao -- /bin/sh -ec \
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

if [[ $HA_CORE == true ]]; then
	# --- HA: three raft pods with the static seal ---------------------------
	recovery_file="$SENSITIVE_DIR/openbao-recovery-keys.json"
	kc -n "$CORE_NS" get secret "$OPENBAO_SEAL_SECRET" >/dev/null 2>&1 ||
		die "Secret $CORE_NS/$OPENBAO_SEAL_SECRET (the static seal key) is missing: install.sh makes it before the farmer chart"
	replicas=$(kc -n "$CORE_NS" get statefulset "$OPENBAO_STS" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)
	if [[ -z "$replicas" ]]; then
		wait_for 1200 "StatefulSet $OPENBAO_STS (created by the farmer chart install)" \
			kc -n "$CORE_NS" get statefulset "$OPENBAO_STS"
		replicas=$(kc -n "$CORE_NS" get statefulset "$OPENBAO_STS" -o jsonpath='{.spec.replicas}')
	fi
	[[ "$replicas" =~ ^[1-9]$ ]] || die "StatefulSet $OPENBAO_STS has $replicas replicas"
	log "waiting for $CORE_NS/$OPENBAO_POD to answer ($replicas raft pods, static seal)"
	wait_for 1200 "OpenBao server in $OPENBAO_POD" status_json
	st=$(status_json)
	[[ "$(jq -r .type <<<"$st")" == static ]] || die "$OPENBAO_POD's seal is $(jq -r .type <<<"$st"), not the static seal of values/values-ha.yaml"
	if [[ "$(jq -r .initialized <<<"$st")" != true ]]; then
		[[ ! -s "$init_file" ]] || die "$init_file exists but OpenBao is not initialised: a different OpenBao? Move the old file away first"
		log "initialising OpenBao on $OPENBAO_POD ($KEY_SHARES recovery key shares, threshold $KEY_THRESHOLD)"
		(umask 077 && bao operator init -format=json -recovery-shares="$KEY_SHARES" -recovery-threshold="$KEY_THRESHOLD" </dev/null >"$init_file") ||
			die "bao operator init failed"
		jq -e '(.recovery_keys_b64 | length) > 0 and (.root_token | length) > 0' "$init_file" >/dev/null ||
			die "bao operator init gave no recovery keys or root token"
		log "!!! UAT ONLY: recovery keys and root token written to $init_file (sensitive artifact)"
	fi
	if [[ -s "$init_file" ]]; then
		(umask 077 && jq -j .root_token "$init_file" >"$token_file")
		(umask 077 && jq '{threshold: .recovery_keys_threshold, keys: .recovery_keys_b64}' "$init_file" >"$recovery_file")
	else
		log "no $init_file here: restoring the recovery keys and root token from the cluster"
		(umask 077 && kc -n "$CORE_NS" get secret "$OPENBAO_UNSEAL_SECRET" -o json |
			jq -r '.data["recovery-keys.json"] | @base64d' >"$recovery_file") ||
			die "OpenBao is initialised but neither $init_file nor Secret $OPENBAO_UNSEAL_SECRET exists (rebuild the cluster)"
		(umask 077 && kc -n "$CORE_NS" get secret "$OPENBAO_UNSEAL_SECRET" -o json |
			jq -je '.data["root-token"] | @base64d' >"$token_file") ||
			die "Secret $OPENBAO_UNSEAL_SECRET has no root-token"
	fi
	jq -e '(.keys | length) >= .threshold' "$recovery_file" >/dev/null || die "recovery key file is malformed"
	# UAT ONLY: the recovery keys and the root token in a Kubernetes Secret.
	apply_secret "$CORE_NS" "$OPENBAO_UNSEAL_SECRET" "recovery-keys.json=$recovery_file" "root-token=$token_file"

	# Every pod unseals itself (static seal) once it has joined the raft
	# cluster through retry_join.
	unsealed() {
		local s
		s=$(status_json) || return 1
		jq -e '.initialized == true and .sealed == false' <<<"$s" >/dev/null
	}
	for ((i = 0; i < replicas; i++)); do
		bao_pod="$OPENBAO_STS-$i"
		wait_for 900 "OpenBao $bao_pod initialised and unsealed (static seal, raft joined)" unsealed
	done
	# The active node: the pod whose status says it is the leader.
	active_pod() {
		local i s
		for ((i = 0; i < replicas; i++)); do
			bao_pod="$OPENBAO_STS-$i"
			s=$(status_json) || continue
			if jq -e '.sealed == false and .is_self == true' <<<"$s" >/dev/null; then
				printf '%s' "$bao_pod"
				return 0
			fi
		done
		return 1
	}
	wait_for 300 "an active OpenBao raft node" active_pod
	bao_pod=$(active_pod)
	# Every pod a raft voter (autopilot promotes a new node once it is
	# stable), so losing any one pod keeps a quorum.
	voters() {
		bao_root 'bao operator raft list-peers -format=json' |
			jq -e --argjson n "$replicas" '[.data.config.servers[] | select(.voter == true)] | length == $n' >/dev/null
	}
	wait_for 300 "all $replicas OpenBao pods raft voters" voters
	log "OpenBao is initialised; $replicas raft voters, all unsealed; active node $bao_pod"
else
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
		(umask 077 && kc -n "$CORE_NS" get secret "$OPENBAO_UNSEAL_SECRET" -o json |
			jq -je '.data["root-token"] | @base64d' >"$token_file") ||
			die "Secret $OPENBAO_UNSEAL_SECRET has no root-token"
	fi
	jq -e '(.keys | length) >= .threshold' "$unseal_file" >/dev/null || die "unseal key file is malformed"

	# UAT ONLY: the unseal keys and the root token in a Kubernetes Secret, so a
	# re-run (or a person) can unseal after a pod restart, and mint the next
	# bootstrap token, without this runner's files.
	apply_secret "$CORE_NS" "$OPENBAO_UNSEAL_SECRET" "unseal-keys.json=$unseal_file" "root-token=$token_file"

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
	# Single-node raft: once unsealed, the node elects itself leader and only
	# then serves writes (until then they fail with "local node not active").
	active() {
		local s
		s=$(status_json) || return 1
		jq -e '.sealed == false and (.ha_enabled != true or .is_self == true)' <<<"$s" >/dev/null
	}
	wait_for 120 "OpenBao raft node active" active
	log "OpenBao is initialised, unsealed and active"
fi

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
# it never races the Transit setup above. A fresh token every run: the Job
# revoked the last one.
(umask 077 && bao_root 'bao token create -orphan -policy=root -ttl=1h -explicit-max-ttl=1h -renewable=false -display-name=imas-uat-chart-bootstrap -field=token' | tr -d '\n' >"$bootstrap_file") ||
	die "could not mint the chart's bootstrap token"
[[ -s "$bootstrap_file" ]] || die "bao token create gave no token"
apply_secret "$CORE_NS" "$OPENBAO_ROOT_SECRET" "token=$bootstrap_file"
log "the chart's bootstrap Job gets a one-hour root-policy token (Secret $CORE_NS/$OPENBAO_ROOT_SECRET), which it revokes when done"
log "!!! UAT ONLY: OpenBao unseal keys and root token in Secret $CORE_NS/$OPENBAO_UNSEAL_SECRET"
