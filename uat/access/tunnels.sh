#!/usr/bin/env bash
# tunnels.sh: the management path of the UAT gate (UAT.1, Access interface of
# the Shared contract in section 4h of docs/claude-code-parallel-build-plan.md).
#
#   tunnels.sh open       <uat.json> <state-dir>
#   tunnels.sh reopen     <uat.json> <state-dir>
#   tunnels.sh reopen-one <uat.json> <state-dir> <vm> <kind>
#   tunnels.sh close      <state-dir>
#
# open starts one `az network bastion tunnel` in the background for
#   SSH (22)            on every Linux VM (every hub node, and sprouts with
#                       connection ssh),
#   WinRM HTTPS (5986)  on every Windows VM (sprouts with connection winrm),
#   Kubernetes API (6443) on every hub node, and on an HA hub (more than one
#                       node) also on the hub's API address (uat
#                       <hub>.api_address, the internal load balancer), by
#                       IP (the Bastion's IP-based connection),
# each on its own free local port on 127.0.0.1, waits until each accepts
# connections (an SSH tunnel must also return the server's SSH banner), and
# writes <state-dir>/access.json:
#
#   { "<vm name>": { "host": "127.0.0.1", "ssh_port": N, "kube_port": N,
#                    "winrm_port": N, "pids": [ ... ] }, ...,
#     "<hub>-api": { "host": "127.0.0.1", "kube_port": N, "pids": [ ... ] } }
#
# with only the ports that VM has; "dmz-api" and "core-api" only for an HA
# hub. Sprouts with connection docker (the local rig) are skipped. If any tunnel fails, open stops every tunnel it started,
# writes no access.json and exits non zero.
#
# open also writes <state-dir>/opened_at, the time (seconds since the epoch)
# the tunnels were ready: the tunnels' age that uat/access/session.sh reports
# and guards (W6); and <state-dir>/opened/<vm>-<kind>, the same for each
# tunnel (W10), which reopen-one renews for its tunnel alone, so opened_at
# is then the oldest tunnel's.
#
# reopen closes the tunnels of <state-dir> and opens them again, each on the
# local port it had where that port is free, so access.json and the files
# made from it (kubeconfigs, inventory) stay valid. A tunnel whose old port
# is taken gets a new one, and reopen names it on stderr ("port changed").
# The new az processes run with the az login as it is now: that is the
# point (session.sh refresh, W6).
#
# reopen-one closes one tunnel (<vm> <kind>: ssh, winrm or kube, as in
# tunnels.pids) and opens it again on the SAME local port, waits until it is
# ready as open does, and records it in tunnels.pids, access.json and its
# opened/ stamp (W10: session.sh's supervisor and vmctl.sh's recovery, one
# tunnel at a time, each under the VM's slots). It never moves the port:
# when the port is still taken after the old process stopped, it fails, and
# the caller tries again later. The tunnel's log keeps its earlier lines.
#
# close stops every tunnel listed in <state-dir>/tunnels.pids (only processes
# that are still `az ... bastion tunnel` processes), removes tunnels.pids,
# access.json, opened_at and opened/, and is safe to repeat.
#
# open, reopen, reopen-one and close hold <state-dir>/tunnels.lock (flock),
# so two of them never rewrite the state at once.
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
usage: $prog open       <uat.json> <state-dir>
       $prog reopen     <uat.json> <state-dir>
       $prog reopen-one <uat.json> <state-dir> <vm> <kind>
       $prog close      <state-dir>
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

# port_listeners <port>: the pids listening on 127.0.0.1:<port> (ss), one
# per line; nothing without ss.
port_listeners() {
  command -v ss >/dev/null 2>&1 || return 0
  ss -Hltnp "( sport = :$1 )" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}

# Is pid $1 running? A zombie (exited, not yet reaped by whatever adopted
# it) is not.
alive() {
  kill -0 "$1" 2>/dev/null || return 1
  [[ "$(ps -o stat= -p "$1" 2>/dev/null)" != Z* ]]
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
    alive "$pid" || return 0
    sleep 0.5
  done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  for ((i = 0; i < 10; i++)); do
    alive "$pid" || return 0
    sleep 0.2
  done
}

close_tunnels() {
  local dir=$1 pid rest
  if [ -f "$dir/tunnels.pids" ]; then
    while read -r pid rest; do
      [ -n "${pid:-}" ] || continue
      stop_pid "$pid"
    done <"$dir/tunnels.pids"
  fi
  rm -f "$dir/tunnels.pids" "$dir/tunnels.pids.tmp" "$dir/access.json" "$dir/access.json.tmp" "$dir/opened_at"
  rm -rf "$dir/opened"
}

# lock_state <dir>: holds <dir>/tunnels.lock (fd 8) until the script exits.
lock_state() {
  mkdir -p "$1"
  exec 8>>"$1/tunnels.lock"
  flock -w "${TUNNEL_LOCK_WAIT_SECONDS:-600}" 8 || die "another tunnels.sh held $1/tunnels.lock for too long"
}

# write_access <dir>: access.json from tunnels.pids.
write_access() {
  local dir=$1
  jq -Rn '
    [inputs | split("\t") | {pid: (.[0] | tonumber), vm: .[1], kind: .[2], port: (.[3] | tonumber)}]
    | group_by(.vm)
    | map({key: .[0].vm, value: (
        {host: "127.0.0.1"}
        + (map({key: "\(.kind)_port", value: .port}) | from_entries)
        + {pids: map(.pid)})})
    | from_entries' <"$dir/tunnels.pids" >"$dir/access.json.tmp"
  mv "$dir/access.json.tmp" "$dir/access.json"
}

# write_opened_at <dir>: opened_at, the oldest tunnel's opened/ stamp.
write_opened_at() {
  local dir=$1 oldest
  oldest=$(cat "$dir"/opened/* 2>/dev/null | sort -n | head -n 1)
  [ -n "$oldest" ] || oldest=$(date +%s)
  echo "$oldest" >"$dir/opened_at.tmp"
  mv "$dir/opened_at.tmp" "$dir/opened_at"
}

# start_tunnel <bastion> <rg> <target> <remote port> <local port> <log>:
# starts one az bastion tunnel in the background, in its own process group
# where setsid exists, and prints its pid.
start_tunnel() {
  local bastion=$1 rg=$2 id=$3 rport=$4 port=$5 log=$6
  local -a target
  case $id in
    id:*) target=(--target-resource-id "${id#id:}") ;;
    ip:*) target=(--target-ip-address "${id#ip:}") ;;
    *) die "internal error: bad tunnel target $id" ;;
  esac
  # setsid gives the tunnel its own process group, so close can stop az and
  # its python child together. The tunnel outlives this script on purpose,
  # so it gets no file descriptor of ours but its log: a lock we hold
  # (tunnels.lock, a caller's vmctl.sh slot) must not live on in it.
  local runner=nohup
  command -v setsid >/dev/null 2>&1 && runner=setsid
  (
    for fd in /proc/"$BASHPID"/fd/*; do
      n=${fd##*/}
      if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -le 2 ]; then continue; fi
      eval "exec $n>&-" 2>/dev/null || true
    done
    exec 8>&-
    exec "$runner" "$AZ" network bastion tunnel --name "$bastion" --resource-group "$rg" \
      "${target[@]}" --resource-port "$rport" --port "$port"
  ) </dev/null >>"$log" 2>&1 &
  echo "$!"
}

# wait_ready <pid> <kind> <port> <seconds>: waits until the tunnel accepts
# (an SSH tunnel: and returns the SSH banner); 1 when its process exited, 2
# when it was not ready in time.
wait_ready() {
  local pid=$1 kind=$2 port=$3 deadline=$((SECONDS + $4)) banner
  while :; do
    kill -0 "$pid" 2>/dev/null || return 1
    if port_in_use "$port"; then
      [ "$kind" != ssh ] && return 0
      banner=$(read_banner "$port" </dev/null)
      [ "$banner" = "SSH-" ] && return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 2
    sleep 1
  done
}

# targets <uat.json>: one line per tunnel: target name, kind, remote port,
# target. The target is "id:<VM resource id>" or, for an HA hub's API
# address, "ip:<address>". A hub's nodes are node_names and node_ids
# (uat/tofu, P24), or its name and id where the file has no node lists.
targets() {
  local uat=$1
  jq -er '
    def need(f): if (f // "") == "" then error("missing field") else f end;
    def ipv4: if test("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
      then . else error("not an IPv4 address: \(.)") end;
    ( ["dmz", "core"][] as $h | .[$h]
      | (if (.node_names // null) == null then [need(.name)] else .node_names end) as $names
      | (if (.node_ids // null) == null then [need(.id)] else .node_ids end) as $ids
      | if ($names | length) == 0 or ($names | length) != ($ids | length)
        then error("\($h): node_names and node_ids differ") else . end
      | ( range($names | length) as $i
          | ($names[$i] | need(.)) as $n | ("id:" + ($ids[$i] | need(.))) as $id
          | ([$n, "ssh", 22, $id], [$n, "kube", 6443, $id]) ),
        ( if ($names | length) > 1
          then ["\($h)-api", "kube", 6443, ("ip:" + (need(.api_address) | ipv4))]
          else empty end ) ),
    ( .sprouts // {} | to_entries[]
      | .key as $n | .value as $s
      | if $s.connection == "ssh" then [$n, "ssh", 22, "id:" + need($s.id)]
        elif $s.connection == "winrm" then [$n, "winrm", 5986, "id:" + need($s.id)]
        elif $s.connection == "docker" then empty
        else error("sprout \($n): unknown connection \($s.connection)") end )
    | @tsv' "$uat"
}

cmd_close() {
  [ $# -eq 1 ] || usage
  local dir=$1
  [ -d "$dir" ] || { log "no state directory $dir; nothing to close"; return 0; }
  lock_state "$dir"
  close_tunnels "$dir"
  log "tunnels closed"
}

# The port each tunnel had before a reopen, by "<vm>/<kind>".
declare -A PREFER=()

cmd_reopen() {
  [ $# -eq 2 ] || usage
  local dir=$2 pid vm kind port
  lock_state "$dir"
  if [ -f "$dir/tunnels.pids" ]; then
    while IFS=$'\t' read -r pid vm kind port; do
      if [ -z "${vm:-}" ] || ! [[ "${port:-}" =~ ^[0-9]+$ ]]; then continue; fi
      PREFER["$vm/$kind"]=$port
    done <"$dir/tunnels.pids"
    close_tunnels "$dir"
    log "tunnels closed; opening them again, on the same ports where free"
  fi
  cmd_open "$@"
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

  lock_state "$dir"
  local rg bastion
  rg=$(jq -er '.resource_group' "$uat") || die "$uat has no resource_group"
  bastion=$(jq -er '.bastion.name' "$uat") || die "$uat has no bastion.name"

  # One line per tunnel: target name, kind, remote port, target (targets).
  local targets
  targets=$(targets "$uat") || die "$uat does not have the uat shape (dmz, core with nodes, ids and an HA hub's api_address, sprouts with connection and id)"

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

  # A port another tunnel had before a reopen is kept for it.
  local next_port=$port_base used=" " reserved=" " key
  for key in "${!PREFER[@]}"; do reserved="$reserved${PREFER[$key]} "; done
  local -a tried_prefer=()
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
    local i=$1 log want=${PREFER["${vms[$1]}/${kinds[$1]}"]:-}
    # The tunnel's old port first, once; a restart takes a new port.
    if [ -n "$want" ] && [ -z "${tried_prefer[$i]:-}" ] &&
      ! port_in_use "$want" && [[ "$used" != *" $want "* ]]; then
      tried_prefer[i]=1
      used="$used$want "
      ports[i]=$want
    else
      tried_prefer[i]=1
      while port_in_use "$next_port" || [[ "$used" == *" $next_port "* ]] || [[ "$reserved" == *" $next_port "* ]]; do
        next_port=$((next_port + 1))
        [ "$next_port" -le 65535 ] || die "no free local port above $port_base"
      done
      used="$used$next_port "
      ports[i]=$next_port
      next_port=$((next_port + 1))
    fi
    log="$dir/logs/${vms[$i]}-${kinds[$i]}.log"
    # A VM by its resource id; an HA hub's API address by IP (the Bastion's
    # IP-based connection, uat/tofu ip_connect_enabled).
    pids[i]=$(start_tunnel "$bastion" "$rg" "${ids[$i]}" "${rports[$i]}" "${ports[$i]}" "$log")
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
    key="${vms[$i]}/${kinds[$i]}"
    if [ -n "${PREFER[$key]:-}" ] && [ "${PREFER[$key]}" != "${ports[$i]}" ]; then
      log "${vms[$i]} ${kinds[$i]}: port changed from ${PREFER[$key]} to ${ports[$i]} (the old port was taken)"
    fi
  done

  write_access "$dir"
  mkdir -p "$dir/opened"
  local now
  now=$(date +%s)
  for i in "${!vms[@]}"; do echo "$now" >"$dir/opened/${vms[$i]}-${kinds[$i]}"; done
  echo "$now" >"$dir/opened_at"
  OPENING_DIR=""
  trap - INT TERM EXIT
  log "wrote $dir/access.json"
}

# reopen-one: the same port, or a failure (see the header).
cmd_reopen_one() {
  [ $# -eq 4 ] || usage
  local uat=$1 dir=$2 want_vm=$3 want_kind=$4
  [ -r "$uat" ] || die "cannot read $uat"
  command -v jq >/dev/null 2>&1 || die "jq is not on PATH"
  command -v "$AZ" >/dev/null 2>&1 || die "$AZ is not on PATH"
  lock_state "$dir"
  if [ ! -s "$dir/access.json" ] || [ ! -f "$dir/tunnels.pids" ]; then die "no tunnels are open in $dir"; fi
  local rg bastion line target all
  rg=$(jq -er '.resource_group' "$uat") || die "$uat has no resource_group"
  bastion=$(jq -er '.bastion.name' "$uat") || die "$uat has no bastion.name"
  all=$(targets "$uat") || die "$uat does not have the uat shape"
  target=$(awk -F'\t' -v vm="$want_vm" -v k="$want_kind" '$1 == vm && $2 == k { print; exit }' <<<"$all")
  [ -n "$target" ] || die "$uat has no $want_kind tunnel for $want_vm"
  line=$(awk -F'\t' -v vm="$want_vm" -v k="$want_kind" '$2 == vm && $3 == k { print; exit }' "$dir/tunnels.pids")
  [ -n "$line" ] || die "$dir/tunnels.pids has no $want_kind tunnel for $want_vm"
  local old_pid port rport id i _vm _kind
  IFS=$'\t' read -r old_pid _vm _kind port <<<"$line"
  IFS=$'\t' read -r _vm _kind rport id <<<"$target"
  stop_pid "$old_pid"
  for ((i = 0; i < 20; i++)); do
    port_in_use "$port" || break
    sleep 0.5
  done
  # A bastion tunnel process left holding the port (not the one in
  # tunnels.pids: an orphan of an earlier reopen) is stopped too (W11: a
  # reopen of uat-dmz's kube tunnel failed after 25 s with no reason given).
  if port_in_use "$port"; then
    local holder
    for holder in $(port_listeners "$port"); do
      if is_tunnel_pid "$holder"; then
        log "$want_vm $want_kind: port $port is held by another bastion tunnel process ($holder); stopping it"
        stop_pid "$holder"
      fi
    done
    for ((i = 0; i < 10; i++)); do
      port_in_use "$port" || break
      sleep 0.5
    done
  fi
  if port_in_use "$port"; then
    die "$want_vm $want_kind: port $port is still taken after its tunnel stopped (by: $(port_listeners "$port" | tr '\n' ' ')); not moving it"
  fi
  local log="$dir/logs/$want_vm-$want_kind.log" pid rc=0
  mkdir -p "$dir/logs"
  echo "--- tunnels.sh reopen-one at $(date -u +%Y-%m-%dT%H:%M:%SZ) on port $port (was pid $old_pid)" >>"$log"
  pid=$(start_tunnel "$bastion" "$rg" "$id" "$rport" "$port" "$log")
  # tunnels.pids first, so close finds the new process whatever happens next.
  awk -F'\t' -v OFS='\t' -v vm="$want_vm" -v k="$want_kind" -v pid="$pid" \
    '$2 == vm && $3 == k { $1 = pid } { print }' "$dir/tunnels.pids" >"$dir/tunnels.pids.tmp"
  mv "$dir/tunnels.pids.tmp" "$dir/tunnels.pids"
  write_access "$dir"
  wait_ready "$pid" "$want_kind" "$port" "$wait_seconds" || rc=$?
  case $rc in
    0) ;;
    1)
      log "$want_vm $want_kind: the reopened tunnel exited; the end of its log:"
      tail -n 20 "$log" | sed 's/^/  /' >&2
      exit 1
      ;;
    *)
      log "$want_vm $want_kind: the reopened tunnel on 127.0.0.1:$port not ready after ${wait_seconds}s"
      exit 1
      ;;
  esac
  mkdir -p "$dir/opened"
  date +%s >"$dir/opened/$want_vm-$want_kind"
  write_opened_at "$dir"
  log "$want_vm $want_kind reopened on 127.0.0.1:$port"
}

[ $# -ge 1 ] || usage
action=$1
shift
case "$action" in
  open) cmd_open "$@" ;;
  reopen) cmd_reopen "$@" ;;
  reopen-one) cmd_reopen_one "$@" ;;

  close) cmd_close "$@" ;;
  -h | --help | help) usage ;;
  *) log "unknown command '$action'"; usage ;;
esac
