#!/usr/bin/env bash
# seeds.sh <kubeconfig> <endpoints.json> <state-dir>
#
# Creates the two NATS NKey user seeds deploy/helm/farmer requires (README,
# "Seeds"): SYS_USER (sys-user.nk, farmer's SYS account user) and
# SAASAPI_USER (saasapi-user.nk, saasapi's credential), and the Secret
# natsSeeds.secretName (imas-farmer-nats-seeds) in the core namespace.
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
#   used as is, never regenerated. The DMZ needs none of them: its bus
#   starts from the public trust ConfigMap (uat/hub/dmz/install.sh).
# - On a cluster that already has the Secret, different local seeds are an
#   error (the README: never replace the seeds of an existing install), and
#   missing local files are restored from the Secret.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "seeds.sh <kubeconfig> <endpoints.json> <state-dir>" "$@"
need_cmd kubectl jq go base64

# Secret key -> nk key type. Users only: user seeds start SU.
declare -A SEED_TYPES=(
	[sys-user.nk]=user
	[saasapi-user.nk]=user
)
declare -A SEED_PREFIX=([user]=SU)

(umask 077 && mkdir -p "$SEEDS_DIR")
chmod 700 "$SEEDS_DIR"

check_seed() { # <file> <type>
	local s
	s=$(tr -d '\n' <"$1")
	[[ "$s" =~ ^${SEED_PREFIX[$2]}[A-Z2-7]{56}$ ]] || die "$(basename "$1") is not an nk $2 seed"
}

existing=$(kc -n "$CORE_NS" get secret "$SEEDS_SECRET" -o json 2>/dev/null || true)
if [[ -n "$existing" ]]; then
	for key in "${!SEED_TYPES[@]}"; do
		f="$SEEDS_DIR/$key"
		in_cluster=$(jq -r --arg k "$key" '.data[$k] // empty' <<<"$existing")
		[[ -n "$in_cluster" ]] || die "Secret $CORE_NS/$SEEDS_SECRET exists without $key; fix it by hand, never by regenerating"
		if [[ -s "$f" ]]; then
			[[ "$(base64 <"$f" | tr -d '\n')" == "$in_cluster" ]] ||
				die "$key in $SEEDS_DIR differs from Secret $CORE_NS/$SEEDS_SECRET: refusing to replace the seeds of an existing install"
		else
			(umask 077 && base64 -d <<<"$in_cluster" >"$f")
			log "restored $key from the cluster"
		fi
	done
	log "seed Secret $CORE_NS/$SEEDS_SECRET already matches $SEEDS_DIR"
	exit 0
fi

nk="$STATE_DIR/bin/nk"
if [[ ! -x "$nk" ]]; then
	repo_root=$(cd "$here/../../.." && pwd)
	mkdir -p "$STATE_DIR/bin"
	log "building nk from $repo_root/go.mod's github.com/nats-io/nkeys"
	(cd "$repo_root" && CGO_ENABLED=0 go build -o "$nk" github.com/nats-io/nkeys/nk) ||
		die "could not build nk (github.com/nats-io/nkeys/nk)"
fi

for key in "${!SEED_TYPES[@]}"; do
	f="$SEEDS_DIR/$key"
	if [[ -s "$f" ]]; then
		log "using existing seed $key"
	else
		# No trailing newline, the same bytes as the README's
		# --from-literal="$(nk -gen ...)" (farmer trims either way).
		(umask 077 && "$nk" -gen "${SEED_TYPES[$key]}" | tr -d '\n' >"$f.new") || die "nk -gen ${SEED_TYPES[$key]} failed"
		mv "$f.new" "$f"
		log "generated seed $key"
	fi
	check_seed "$f" "${SEED_TYPES[$key]}"
done

args=()
for key in "${!SEED_TYPES[@]}"; do args+=("$key=$SEEDS_DIR/$key"); done
apply_secret "$CORE_NS" "$SEEDS_SECRET" "${args[@]}"
