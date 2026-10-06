#!/usr/bin/env bash
# tunnels.sh: the management path of the UAT gate (UAT.1, Access interface of
# the Shared contract in section 4h of docs/claude-code-parallel-build-plan.md).
#
#   tunnels.sh open  <uat.json> <state-dir>
#   tunnels.sh close <state-dir>
#
# open starts one `az network bastion tunnel` in the background for
#   SSH (22)            on every Linux VM (both hubs, and sprouts with connection ssh),
#   WinRM HTTPS (5986)  on every Windows VM (sprouts with connection winrm),
#   Kubernetes API (6443) on both hubs,
# each on its own free local port on 127.0.0.1, waits until each accepts
# connections (an SSH tunnel must also return the server's SSH banner), and
# writes <state-dir>/access.json:
#
#   { "<vm name>": { "host": "127.0.0.1", "ssh_port": N, "kube_port": N,
#                    "winrm_port": N, "pids": [ ... ] }, ... }
#
# with only the ports that VM has. Sprouts with connection docker (the local
# rig) are skipped. If any tunnel fails, open stops every tunnel it started,
# writes no access.json and exits non zero.
#
# close stops every tunnel listed in <state-dir>/tunnels.pids (only processes
# that are still `az ... bastion tunnel` processes), removes tunnels.pids and
# access.json, and is safe to repeat.
#
# All Azure calls of the UAT gate live here and in vmctl.sh.
#
# Environment:
#   AZ                   az command (default az; the bastion extension is needed)
#   TUNNEL_PORT_BASE     first local port tried (default 20100, below the
#                        Linux, macOS and Windows ephemeral port ranges)
#   TUNNEL_WAIT_SECONDS  how long to wait for each tunnel (default 300)
#   TUNNEL_START_ATTEMPTS  starts per tunnel that exits before it is ready
#                        (default 3), each on a new port
set -euo pipefail

prog=$(basename "$0")
AZ=${AZ:-az}
OPENING_DIR=""
port_base=${TUNNEL_PORT_BASE:-20100}
wait_seconds=${TUNNEL_WAIT_SECONDS:-300}
start_attempts=${TUNNEL_START_ATTEMPTS:-3}

usage() {
  cat >&2 <<EOF
usage: $prog open <uat.json> <state-dir>
       $prog close <state-dir>
EOF
  exit 2
}

log() { echo "$prog: $*" >&2; }
die() { log "$*"; exit 1; }

# Is something listening on 127.0.0.1:$1?
port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# Reads the first bytes the server sends on 127.0.0.1:$1 (an SSH banner).
read_banner() {
  # shellcheck disable=SC2016 # $1 is expanded by the inner bash
  timeout 5 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1" && head -c 4 <&3' _ "$1" 2>/dev/null || true
}

# Is pid $1 alive and still a bastion tunnel (not a reused pid)?
is_tunnel_pid() {
  local pid=$1 args
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  args=$(ps -o args= -p "$pid" 2>/dev/null || true)
  [[ "$args" == *"bastion tunnel"* ]]
}

# Stops one tunnel: its process group when it leads one (setsid), else the
# process and its children.
stop_pid() {
  local pid=$1 i
  is_tunnel_pid "$pid" || return 0
  if [ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" = "$pid" ]; then
    kill -TERM -- "-$pid" 2>/dev/null || true
  else
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
  fi
  for ((i = 0; i < 20; i++)); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.5
  done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

close_tunnels() {
  local dir=$1 pid rest
  if [ -f "$dir/tunnels.pids" ]; then
    while read -r pid rest; do
      [ -n "${pid:-}" ] || continue
      stop_pid "$pid"
    done <"$dir/tunnels.pids"
  fi
  rm -f "$dir/tunnels.pids" "$dir/tunnels.pids.tmp" "$dir/access.json" "$dir/access.json.tmp"
}

cmd_close() {
  [ $# -eq 1 ] || usage
  local dir=$1
  [ -d "$dir" ] || { log "no state directory $dir; nothing to close"; return 0; }
  close_tunnels "$dir"
  log "tunnels closed"
}

cmd_open() {
  [ $# -eq 2 ] || usage
  local uat=$1 dir=$2
  [ -r "$uat" ] || die "cannot read $uat"
  command -v jq >/dev/null 2>&1 || die "jq is not on PATH"
  command -v "$AZ" >/dev/null 2>&1 || die "$AZ is not on PATH"
  if ! [[ "$start_attempts" =~ ^[1-9][0-9]*$ ]]; then
    die "TUNNEL_START_ATTEMPTS must be a whole number of 1 or more"
  fi
  if ! [[ "$port_base" =~ ^[0-9]+$ ]] || [ "$port_base" -lt 1024 ] || [ "$port_base" -gt 65000 ]; then
    die "TUNNEL_PORT_BASE must be a number between 1024 and 65000"
  fi

  local rg bastion
  rg=$(jq -er '.resource_group' "$uat") || die "$uat has no resource_group"
  bastion=$(jq -er '.bastion.name' "$uat") || die "$uat has no bastion.name"

  # One line per tunnel: vm, kind, remote port, VM resource id.
  local targets
  targets=$(jq -er '
    def need(f): if (f // "") == "" then error("missing field") else f end;
    ( ["dmz", "core"][] as $h | .[$h]
      | (need(.name)) as $n | (need(.id)) as $id
      | ([$n, "ssh", 22, $id], [$n, "kube", 6443, $id]) ),
    ( .sprouts // {} | to_entries[]
      | .key as $n | .value as $s
      | if $s.connection == "ssh" then [$n, "ssh", 22, need($s.id)]
        elif $s.connection == "winrm" then [$n, "winrm", 5986, need($s.id)]
        elif $s.connection == "docker" then empty
        else error("sprout \($n): unknown connection \($s.connection)") end )
    | @tsv' "$uat") || die "$uat does not have the uat shape (dmz, core, sprouts with connection and id)"

  mkdir -p "$dir/logs"
  if [ -f "$dir/tunnels.pids" ]; then
    local pid rest
    while read -r pid rest; do
      if is_tunnel_pid "$pid"; then
        die "tunnels from an earlier open are still running in $dir; run '$prog close $dir' first"
      fi
    done <"$dir/tunnels.pids"
    rm -f "$dir/tunnels.pids"
  fi
  rm -f "$dir/access.json"
  : >"$dir/tunnels.pids"

  # From here on, any exit before access.json is written (a failure, set -e,
  # or an interrupt) closes what was started.
  OPENING_DIR=$dir
  trap 'if [ -n "$OPENING_DIR" ]; then close_tunnels "$OPENING_DIR"; fi' EXIT
  trap 'exit 1' INT TERM

  # Tunnel i: vms[i], kinds[i], rports[i], ids[i], and once started pids[i]
  # and ports[i]. tunnels.pids is rewritten after every start, so the exit
  # trap always knows every process.
  local -a vms=() kinds=() rports=() ids=() pids=() ports=()
  local vm kind rport id
  while IFS=$'\t' read -r vm kind rport id; do
    vms+=("$vm") kinds+=("$kind") rports+=("$rport") ids+=("$id")
  done <<<"$targets"

  local next_port=$port_base used=" "
  write_pids() {
    local i
    : >"$dir/tunnels.pids.tmp"
    for i in "${!pids[@]}"; do
      printf '%s\t%s\t%s\t%s\n' "${pids[$i]}" "${vms[$i]}" "${kinds[$i]}" "${ports[$i]}" >>"$dir/tunnels.pids.tmp"
    done
    mv "$dir/tunnels.pids.tmp" "$dir/tunnels.pids"
  }
  # start i: start tunnel i on the next free port.
  start() {
    local i=$1 log
    while port_in_use "$next_port" || [[ "$used" == *" $next_port "* ]]; do
      next_port=$((next_port + 1))
      [ "$next_port" -le 65535 ] || die "no free local port above $port_base"
    done
    used="$used$next_port "
    ports[i]=$next_port
    next_port=$((next_port + 1))
    log="$dir/logs/${vms[$i]}-${kinds[$i]}.log"
    # setsid gives the tunnel its own process group, so close can stop az and
    # its python child together. The tunnel outlives this script on purpose.
    if command -v setsid >/dev/null 2>&1; then
      setsid "$AZ" network bastion tunnel --name "$bastion" --resource-group "$rg" \
        --target-resource-id "${ids[$i]}" --resource-port "${rports[$i]}" --port "${ports[$i]}" \
        </dev/null >>"$log" 2>&1 &
    else
      nohup "$AZ" network bastion tunnel --name "$bastion" --resource-group "$rg" \
        --target-resource-id "${ids[$i]}" --resource-port "${rports[$i]}" --port "${ports[$i]}" \
        </dev/null >>"$log" 2>&1 &
    fi
    pids[i]=$!
    write_pids
  }

  local i
  for i in "${!vms[@]}"; do
    : >"$dir/logs/${vms[$i]}-${kinds[$i]}.log"
    start "$i"
  done

  # Wait for every tunnel. One that exits before it is ready (for example
  # because something took its port first) is started again on a new port, up
  # to TUNNEL_START_ATTEMPTS times in all.
  local deadline banner tries
  for i in "${!vms[@]}"; do
    deadline=$((SECONDS + wait_seconds))
    tries=1
    while :; do
      if ! kill -0 "${pids[$i]}" 2>/dev/null; then
        if [ "$tries" -lt "$start_attempts" ]; then
          tries=$((tries + 1))
          log "tunnel to ${vms[$i]} (${kinds[$i]}) exited; starting it again (attempt $tries of $start_attempts)"
          start "$i"
          continue
        fi
        log "tunnel to ${vms[$i]} (${kinds[$i]}) exited; its log:"
        sed 's/^/  /' "$dir/logs/${vms[$i]}-${kinds[$i]}.log" >&2 || true
        exit 1
      fi
      if port_in_use "${ports[$i]}"; then
        if [ "${kinds[$i]}" != ssh ]; then break; fi
        banner=$(read_banner "${ports[$i]}" </dev/null)
        [ "$banner" = "SSH-" ] && break
      fi
      if [ "$SECONDS" -ge "$deadline" ]; then
        log "tunnel to ${vms[$i]} (${kinds[$i]}) on 127.0.0.1:${ports[$i]} not ready after ${wait_seconds}s"
        exit 1
      fi
      sleep 1
    done
    log "${vms[$i]} ${kinds[$i]} ready on 127.0.0.1:${ports[$i]}"
  done

  jq -Rn '
    [inputs | split("\t") | {pid: (.[0] | tonumber), vm: .[1], kind: .[2], port: (.[3] | tonumber)}]
    | group_by(.vm)
    | map({key: .[0].vm, value: (
        {host: "127.0.0.1"}
        + (map({key: "\(.kind)_port", value: .port}) | from_entries)
        + {pids: map(.pid)})})
    | from_entries' <"$dir/tunnels.pids" >"$dir/access.json.tmp"
  mv "$dir/access.json.tmp" "$dir/access.json"
  OPENING_DIR=""
  trap - INT TERM EXIT
  log "wrote $dir/access.json"
}

[ $# -ge 1 ] || usage
action=$1
shift
case "$action" in
  open) cmd_open "$@" ;;
  close) cmd_close "$@" ;;
  -h | --help | help) usage ;;
  *) log "unknown command '$action'"; usage ;;
esac
