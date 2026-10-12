#!/usr/bin/env bash
# seeds.sh <kubeconfig> <endpoints.json> <state-dir>
#
# Creates the NATS NKey user seeds the UAT needs and the core Secrets that
# carry them (deploy/helm/farmer README, "Seeds"):
#   - SYS_USER (sys-user.nk, farmer's SYS account user) and SAASAPI_USER
#     (saasapi-user.nk, saasapi's credential) in Secret natsSeeds.secretName
#     (imas-farmer-nats-seeds);
#   - farmer's NKey (farmer.nk) in Secret farmer.nkeySecret.secretName
#     (imas-farmer-nkey), the one seed every farmer replica mounts;
#   - the DMZ bus loader's SYS user (bus-loader-user.nk). It is a file only,
#     never a core Secret, and never regenerated once the trust ConfigMap
#     names a loader (see below): uat/hub/dmz/install.sh --loader-seed puts it in
#     the DMZ cluster. Its public key goes to <state-dir>/core/out/
#     bus-loader-user.pub (not secret), which gen-values.sh turns into
#     natsTrust.busLoaderUserPub, so the chart's bootstrap Job mints
#     bus-loader-user.jwt into the trust ConfigMap the DMZ copies.
# Since P21 slice 1 the operator, operator-signing, SYS account and tenant
# keys are OpenBao Transit keys the chart's bootstrap Job and farmer create;
# no seed of theirs exists anywhere, and the chart refuses them.
# FLAG FOR SECURITY REVIEW.
#
# - Seeds are generated with nk (github.com/nats-io/nkeys/nk), the tool the
#   chart README names, built from this repo's own go.mod pin of
#   github.com/nats-io/nkeys, so they are never hand written.
# - They live in $UAT_SEEDS_DIR (default <state-dir>/core/sensitive/seeds),
#   one file per Secret key, mode 0600. A seed file that already exists is
#   used as is, never regenerated.
# - On a cluster that already has a Secret, different local seeds are an
#   error (the README: never replace the seeds of an existing install), and
#   missing local files are restored from that Secret. Each Secret is
#   handled on its own, so a cluster installed before imas-farmer-nkey
#   existed gets it on the next run.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "seeds.sh <kubeconfig> <endpoints.json> <state-dir>" "$@"
need_cmd kubectl jq go base64

# Every seed here is a user seed (SU...). Secret -> its keys.
declare -A SECRET_KEYS=(
	[$SEEDS_SECRET]="sys-user.nk saasapi-user.nk"
	[$FARMER_NKEY_SECRET]="$FARMER_NKEY_KEY"
)

(umask 077 && mkdir -p "$SEEDS_DIR")
chmod 700 "$SEEDS_DIR"

check_seed() { # <file>
	local s
	s=$(tr -d '\n' <"$1")
	[[ "$s" =~ ^SU[A-Z2-7]{56}$ ]] || die "$(basename "$1") is not an nk user seed"
}

nk="$STATE_DIR/bin/nk"
build_nk() {
	[[ -x "$nk" ]] && return 0
	local repo_root
	repo_root=$(cd "$here/../../.." && pwd)
	mkdir -p "$STATE_DIR/bin"
	log "building nk from $repo_root/go.mod's github.com/nats-io/nkeys"
	(cd "$repo_root" && CGO_ENABLED=0 go build -o "$nk" github.com/nats-io/nkeys/nk) ||
		die "could not build nk (github.com/nats-io/nkeys/nk)"
}

# ensure_seed <file>: uses an existing seed file, or generates one.
ensure_seed() {
	local f=$1
	if [[ -s "$f" ]]; then
		log "using existing seed $(basename "$f")"
	else
		build_nk
		# No trailing newline, the same bytes as the README's
		# --from-literal="$(nk -gen user)" (farmer trims either way).
		(umask 077 && "$nk" -gen user | tr -d '\n' >"$f.new") || die "nk -gen user failed"
		mv "$f.new" "$f"
		log "generated seed $(basename "$f")"
	fi
	check_seed "$f"
}

# ensure_secret <secret>: restores or checks the local files against an
# existing Secret, or generates them and creates it.
ensure_secret() {
	local secret=$1 existing key f in_cluster args=()
	existing=$(kc -n "$CORE_NS" get secret "$secret" -o json 2>/dev/null || true)
	if [[ -n "$existing" ]]; then
		for key in ${SECRET_KEYS[$secret]}; do
			f="$SEEDS_DIR/$key"
			in_cluster=$(jq -r --arg k "$key" '.data[$k] // empty' <<<"$existing")
			[[ -n "$in_cluster" ]] || die "Secret $CORE_NS/$secret exists without $key; fix it by hand, never by regenerating"
			if [[ -s "$f" ]]; then
				[[ "$(base64 <"$f" | tr -d '\n')" == "$in_cluster" ]] ||
					die "$key in $SEEDS_DIR differs from Secret $CORE_NS/$secret: refusing to replace the seeds of an existing install"
			else
				(umask 077 && base64 -d <<<"$in_cluster" >"$f")
				log "restored $key from the cluster"
			fi
			check_seed "$f"
		done
		log "seed Secret $CORE_NS/$secret already matches $SEEDS_DIR"
		return 0
	fi
	for key in ${SECRET_KEYS[$secret]}; do
		ensure_seed "$SEEDS_DIR/$key"
		args+=("$key=$SEEDS_DIR/$key")
	done
	apply_secret "$CORE_NS" "$secret" "${args[@]}"
}

ensure_secret "$SEEDS_SECRET"
ensure_secret "$FARMER_NKEY_SECRET"

# The loader's seed: no core Secret holds it. Before the first install it
# is generated here; gen-values.sh sets its public key, the bootstrap Job
# mints bus-loader-user.jwt into the trust ConfigMap, and
# uat/hub/dmz/install.sh --loader-seed puts it in the DMZ Secret. Once the
# trust exists it is never rewritten (design T4: a re-run of the bootstrap
# Job only checks it), so a new loader seed would have no JWT: with a trust
# that names a loader, a missing seed is an error (restore it from the DMZ
# Secret) and a seed for another key is refused.
loader_seed="$SEEDS_DIR/$LOADER_SEED_FILE"
trust_loader_jwt=$(kc -n "$CORE_NS" get configmap "$NATS_TRUST_CONFIGMAP" -o json 2>/dev/null |
	jq -r '.data["bus-loader-user.jwt"] // empty' || true)
trust_loader=""
if [[ -n "$trust_loader_jwt" ]]; then
	trust_loader=$(jwt_payload "$trust_loader_jwt" | jq -r '.sub // empty') ||
		die "ConfigMap $CORE_NS/$NATS_TRUST_CONFIGMAP has a bus-loader-user.jwt that is not a JWT"
	[[ -s "$loader_seed" ]] ||
		die "$loader_seed is missing, but ConfigMap $CORE_NS/$NATS_TRUST_CONFIGMAP already carries bus-loader-user.jwt for $trust_loader, which is never re-minted: restore the seed (the DMZ's Secret imas-bus-loader-sys-user, key user.nk), never regenerate it"
fi
ensure_seed "$loader_seed"
build_nk
pub=$("$nk" -inkey "$loader_seed" -pubout | tr -d '\n') || die "nk -pubout failed for $LOADER_SEED_FILE"
[[ "$pub" =~ ^U[A-Z2-7]{55}$ ]] || die "$LOADER_SEED_FILE's public key '$pub' is not an NKey user key"
[[ -z "$trust_loader" || "$trust_loader" == "$pub" ]] ||
	die "$loader_seed is for $pub, but the trust's bus-loader-user.jwt is for $trust_loader: refusing a loader seed the bus would not accept"
printf '%s\n' "$pub" >"$OUT_DIR/$LOADER_PUB_FILE"
log "bus loader user $pub ($OUT_DIR/$LOADER_PUB_FILE; seed $loader_seed for uat/hub/dmz/install.sh --loader-seed)"
