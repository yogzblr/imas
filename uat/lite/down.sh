#!/usr/bin/env bash
# down.sh: remove the local UAT rig (UAT.8; README.md, "Cleaning up").
#
# Usage: down.sh [--state DIR] [--keep-state] [--images] [--hosts-file FILE|none]
#
#   --state DIR     the rig's state (default LITE_STATE in config.env)
#   --keep-state    keep the state directory (kubeconfigs, keys, the UAT CA
#                   key, reports); by default it is deleted, since it holds
#                   secrets of clusters that no longer exist
#   --images        also remove the sprout images up.sh built
#   --hosts-file    the hosts file up.sh wrote to (default: what rig.json
#                   says, else /etc/hosts); none leaves it alone
#
# It removes, in order: the sprout containers (by the rig's labels), the two
# kind clusters (only ones up.sh recorded, or whose node is on the rig's
# network), the Docker network (only with the rig's label), the rig's block
# in the hosts file, and the state directory. A cluster, container or
# network that is not the rig's is never touched. Safe to repeat: exits 0
# when nothing is left. Exit 2 on a usage error, 1 when something could not
# be removed.
set -euo pipefail
LITE_PROG=down.sh
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

keep_state=0 images=0 cli_state="" cli_hosts=""
while (($#)); do
	case $1 in
	--state | --hosts-file)
		(($# >= 2)) || lite_usage_die "$1 needs a value"
		if [[ $1 == --state ]]; then cli_state=$2; else cli_hosts=$2; fi
		shift 2
		;;
	--keep-state) keep_state=1 && shift ;;
	--images) images=1 && shift ;;
	-h | --help) usage ;;
	*) lite_usage_die "unknown argument '$1' (see --help)" ;;
	esac
done
[[ -z $cli_state ]] || LITE_STATE=$cli_state
lite_need docker kind jq
lite_load_settings

have_rig=0
if [[ -d $LITE_STATE ]]; then
	LITE_STATE=$(cd "$LITE_STATE" && pwd)
	if lite_restore_settings; then have_rig=1; fi
fi
[[ -z $cli_hosts ]] || LITE_HOSTS_FILE=$cli_hosts
lite_check_settings
((have_rig)) || lite_log "no rig.json in $LITE_STATE: removing by the configured names and the rig's labels only"
rc=0

# 1. sprout containers: only ones carrying the rig's labels.
mapfile -t containers < <(docker ps -aq --filter label=imas.io/purpose=imas-uat-lite \
	--filter "label=imas.io/run-id=$LITE_RUN_ID" 2>/dev/null || true)
for c in "${containers[@]}"; do
	[[ -n $c ]] || continue
	lite_log "removing sprout container $c"
	docker rm -f "$c" >/dev/null || rc=1
done

# 2. kind clusters: recorded in rig.json, or named as configured; deleted
# only when the node is on the rig's network, so a user's own cluster of
# the same name is left alone.
declare -A clusters=()
if ((have_rig)); then
	while IFS= read -r n; do [[ -z $n ]] || clusters[$n]=1; done < <(jq -r '.clusters // {} | .[].name' "$(lite_rig_file)")
fi
clusters[$LITE_DMZ_CLUSTER]=1
clusters[$LITE_CORE_CLUSTER]=1
existing=$(kind get clusters 2>/dev/null || true)
for n in "${!clusters[@]}"; do
	grep -qx "$n" <<<"$existing" || continue
	node="$n-control-plane"
	if [[ -z $(lite_container_ip "$node") ]]; then
		lite_log "leaving kind cluster $n: its node is not on $LITE_NETWORK, so it is not this rig's"
		continue
	fi
	lite_log "deleting kind cluster $n"
	kind delete cluster --name "$n" >&2 || rc=1
done

# 3. the network, only with the rig's label.
if net=$(docker network inspect "$LITE_NETWORK" 2>/dev/null) && [[ -n $net && $net != "[]" ]]; then
	if jq -e '.[0].Labels["imas.io/purpose"] == "imas-uat-lite"' <<<"$net" >/dev/null; then
		lite_log "removing Docker network $LITE_NETWORK"
		docker network rm "$LITE_NETWORK" >/dev/null || {
			lite_log "Docker network $LITE_NETWORK is still in use: $(jq -r '[.[0].Containers // {} | .[].Name] | join(", ")' <<<"$net")"
			rc=1
		}
	else
		lite_log "leaving Docker network $LITE_NETWORK: it has no imas.io/purpose=imas-uat-lite label"
	fi
fi

# 4. the hosts file block.
if [[ $LITE_HOSTS_FILE != none && -e $LITE_HOSTS_FILE ]] && grep -q "^# BEGIN imas-uat-lite $LITE_RUN_ID" "$LITE_HOSTS_FILE"; then
	lite_log "removing the rig's names from $LITE_HOSTS_FILE"
	lite_hosts_update "$LITE_HOSTS_FILE" "" || rc=1
fi

# 5. images.
if ((images)); then
	for os in ubuntu alma; do
		img=$(lite_sprout_image "$os")
		if docker image inspect "$img" >/dev/null 2>&1; then
			lite_log "removing image $img"
			docker image rm "$img" >/dev/null || rc=1
		fi
	done
fi

# 6. the state directory: only one up.sh made (it holds rig.json).
if ((!keep_state)) && [[ -d $LITE_STATE ]]; then
	if ((have_rig)); then
		lite_log "removing the state directory $LITE_STATE"
		rm -rf -- "$LITE_STATE" || rc=1
	else
		lite_log "leaving $LITE_STATE: it has no rig.json, so up.sh did not make it"
	fi
fi

if ((rc == 0)); then lite_log "the rig is down"; else lite_log "some parts could not be removed (above)"; fi
exit "$rc"
