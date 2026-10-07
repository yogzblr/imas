#!/usr/bin/env bash
# vmctl.sh for the local rig (UAT.8): the same interface as
# uat/access/vmctl.sh (Access interface of the Shared contract, plan section
# 4h), built on Docker instead of the Azure control plane.
#
#   vmctl.sh <uat.json> restart      <vm>
#   vmctl.sh <uat.json> stop-sprout  <vm>
#   vmctl.sh <uat.json> start-sprout <vm>
#   vmctl.sh <uat.json> run          <vm> <command...>
#
# <vm> is a VM name from uat.json: uat-dmz, uat-core or a key of sprouts.
# uat.json is the one uat/lite/write-material.sh writes: each VM's id is
# its Docker container (a kind node for the hubs), or "host" for the host
# sprout of the WSL2 fallback, which is reached over SSH (access.json and
# ssh/id_ed25519 next to uat.json).
#
# restart       a reboot is a container restart (docker restart): waits until
#               systemd is up again (running or degraded) and, for a hub,
#               the API server answers and the node kept its address. Up to
#               VMCTL_WAIT_SECONDS. The host sprout cannot be restarted.
# stop-sprout   systemctl stop|start imas-sprout on a sprout; refused for
# start-sprout  the hubs.
# run           runs <command...> (joined with spaces) as root with bash in
#               the container (docker exec; on a hub with KUBECONFIG set to
#               the node's admin kubeconfig). Prints the command's stdout on
#               stdout and its stderr on stderr, then "vmctl.sh: exit_code=N"
#               on stderr, and exits N.
#
# Exit status: the command's for run, stop-sprout and start-sprout; 0 for a
# restart that came back; 2 on a usage error, an unknown VM or a Windows VM
# (the rig has none); 255 when Docker could not run the command (the
# container is not running, or docker itself failed).
#
# Environment:
#   DOCKER                docker command (default docker)
#   VMCTL_SPROUT_SERVICE  service name (default imas-sprout, as packaged)
#   VMCTL_WAIT_SECONDS    restart wait (default 300)
#   VMCTL_POLL_SECONDS    restart poll interval (default 2)
#   LITE_SSH_KEY          the host sprout's key (default <uat.json dir>/ssh/id_ed25519)
set -euo pipefail

prog=$(basename "$0")
DOCKER=${DOCKER:-docker}
service=${VMCTL_SPROUT_SERVICE:-imas-sprout}
wait_seconds=${VMCTL_WAIT_SECONDS:-300}
poll_seconds=${VMCTL_POLL_SECONDS:-2}
node_kubeconfig=/etc/kubernetes/admin.conf

usage() {
	cat >&2 <<EOF
usage: $prog <uat.json> restart|stop-sprout|start-sprout <vm>
       $prog <uat.json> run <vm> <command...>
EOF
	exit 2
}

log() { echo "$prog: $*" >&2; }

[ $# -ge 3 ] || usage
uat=$1
action=$2
vm=$3
shift 3
case "$action" in
restart | stop-sprout | start-sprout) [ $# -eq 0 ] || usage ;;
run) [ $# -ge 1 ] || usage ;;
*)
	log "unknown action '$action'"
	usage
	;;
esac
[[ "$service" =~ ^[A-Za-z0-9._@-]+$ ]] || {
	log "VMCTL_SPROUT_SERVICE has unexpected characters"
	exit 2
}
[[ $wait_seconds =~ ^[0-9]+$ && $poll_seconds =~ ^[0-9]+$ ]] || {
	log "VMCTL_WAIT_SECONDS and VMCTL_POLL_SECONDS must be numbers"
	exit 2
}
[ -r "$uat" ] || {
	log "cannot read $uat"
	exit 2
}
command -v jq >/dev/null 2>&1 || {
	log "jq is not on PATH"
	exit 2
}

# Look the VM up: kind (hub or sprout), container, OS, address and user.
lookup=$(jq -r --arg vm "$vm" '
  def row(k; v; os): [k, (v.id // ""), os, (v.private_ip // ""), (v.admin_user // "root")];
  if .dmz.name == $vm then row("hub"; .dmz; "ubuntu")
  elif .core.name == $vm then row("hub"; .core; "ubuntu")
  elif (.sprouts // {}) | has($vm) then row("sprout"; .sprouts[$vm]; .sprouts[$vm].os)
  else empty end
  | @tsv' "$uat") || {
	log "$uat is not valid JSON"
	exit 2
}
[ -n "$lookup" ] || {
	log "no VM named '$vm' in $uat"
	exit 2
}
IFS=$'\t' read -r kind target os address user <<<"$lookup"
[ -n "$target" ] || {
	log "VM '$vm' has no id (container) in $uat"
	exit 2
}
if [ "$os" = windows ]; then
	log "$vm is a Windows VM: the local rig has none (uat/lite/README.md)"
	exit 2
fi
[[ $target =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || {
	log "VM '$vm' has an id that is not a container name: $target"
	exit 2
}

state_dir=$(cd "$(dirname "$uat")" && pwd)

# --- the host sprout (WSL2 fallback): SSH ----------------------------------

ssh_run() {
	local access="$state_dir/access.json" key=${LITE_SSH_KEY:-$state_dir/ssh/id_ed25519} host port b64 rc
	host=$(jq -r --arg vm "$vm" '.[$vm].host // empty' "$access" 2>/dev/null || true)
	port=$(jq -r --arg vm "$vm" '.[$vm].ssh_port // empty' "$access" 2>/dev/null || true)
	if [ -z "$host" ] || [ -z "$port" ]; then
		log "no host or ssh_port for $vm in $access"
		log "exit_code=255"
		exit 255
	fi
	b64=$(printf '%s' "$1" | base64 | tr -d '\n')
	set +e
	ssh -n -i "$key" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
		-o "UserKnownHostsFile=$state_dir/ssh/known_hosts" -o "HostKeyAlias=$vm" -o ConnectTimeout=20 \
		"$user@$host" \
		"__c=\$(printf '%s' '$b64' | base64 -d); if [ \"\$(id -u)\" = 0 ]; then bash -c \"\$__c\"; else sudo -n bash -c \"\$__c\"; fi"
	rc=$?
	set -e
	log "exit_code=$rc"
	exit "$rc"
}

# --- containers: docker exec -----------------------------------------------

running() {
	[ "$("$DOCKER" inspect --type container "$target" 2>/dev/null | jq -r '.[0].State.Running // false' 2>/dev/null)" = true ]
}

# exec_container <script>: run as root with bash, print the streams, exit
# with the command's code; 255 when docker could not run it.
exec_container() {
	local rc envs=()
	if ! running; then
		log "container $target of $vm is not running"
		log "exit_code=255"
		exit 255
	fi
	[ "$kind" != hub ] || envs=(-e "KUBECONFIG=$node_kubeconfig")
	set +e
	"$DOCKER" exec "${envs[@]}" "$target" bash -c "$1" </dev/null
	rc=$?
	set -e
	# docker exec's own failures are 125 (daemon), 126 and 127 (bash could
	# not be run); bash -c returns 127 for a missing command too, so only
	# 125 is taken for Docker's.
	if [ "$rc" -eq 125 ]; then
		log "docker could not run the command on $vm ($target)"
		rc=255
	fi
	log "exit_code=$rc"
	exit "$rc"
}

booted() {
	local s
	running || return 1
	s=$("$DOCKER" exec "$target" systemctl is-system-running 2>/dev/null || true)
	[ "$s" = running ] || [ "$s" = degraded ] || return 1
	if [ "$kind" = hub ]; then
		"$DOCKER" exec -e "KUBECONFIG=$node_kubeconfig" "$target" kubectl get --raw /readyz >/dev/null 2>&1 || return 1
	fi
}

current_ip() {
	"$DOCKER" inspect --type container "$target" 2>/dev/null |
		jq -r --arg ip "$address" '[.[0].NetworkSettings.Networks // {} | .[].IPAddress] | if index($ip) then $ip else (.[0] // "") end'
}

case "$action" in
run)
	[ "$target" != host ] || ssh_run "$*"
	exec_container "$*"
	;;
stop-sprout | start-sprout)
	if [ "$kind" != sprout ]; then
		log "$action works on sprout VMs only; $vm is a hub"
		exit 2
	fi
	verb=${action%-sprout}
	[ "$target" != host ] || ssh_run "systemctl $verb '$service'"
	exec_container "systemctl $verb '$service'"
	;;
restart)
	if [ "$target" = host ]; then
		log "$vm is this host (the WSL2 fallback): the rig cannot reboot it"
		exit 255
	fi
	log "restarting $vm ($target)"
	if ! "$DOCKER" restart -t 30 "$target" >/dev/null; then
		log "docker restart failed for $vm"
		exit 255
	fi
	deadline=$((SECONDS + wait_seconds))
	while ! booted; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			log "$vm not back after ${wait_seconds}s"
			exit 255
		fi
		sleep "$poll_seconds"
	done
	if [ -n "$address" ] && [ "$(current_ip)" != "$address" ]; then
		log "$vm came back at $(current_ip), not $address: uat.json and the hub names no longer match; run uat/lite/up.sh again"
		exit 255
	fi
	log "$vm is back"
	exit 0
	;;
esac
