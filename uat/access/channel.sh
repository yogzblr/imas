# shellcheck shell=bash
# channel.sh: the UAT test channel's shared pieces (W10), sourced (not run)
# by vmctl.sh and session.sh.
#
#   . uat/access/channel.sh
#
# The ages. The Azure login's age is the modification time of
# az-relogin.sh's stamp ($AZ_RELOGIN_DIR/az-relogin.stamp). Each tunnel has
# its own age: <access dir>/opened/<vm>-<kind>, the time (seconds since the
# epoch) tunnels.sh last opened it; <access dir>/opened_at, the age of the
# set, is the fallback. ch_due says whether either is past
# UAT_REFRESH_AFTER_MIN (REFRESH_AFTER, default 10 minutes): UAT Run 2 #6's
# tunnels stopped opening connections at about 20 minutes old.
#
# The probe. ch_probe checks a tunnel end to end by its protocol, not just
# that the local port accepts (a stale Bastion tunnel keeps accepting and
# hangs every new connection): SSH by the server's banner within
# UAT_PROBE_SSH_SECONDS (5), WinRM by an HTTPS request to /wsman answered
# 401 or 405 (the TLS handshake and the listener) within
# UAT_PROBE_HTTPS_SECONDS (10), the Kubernetes API by any HTTP answer to
# /version within the same time.
#
# The slots. Calls to one VM share a counting semaphore of N slots (flock on
# <state dir>/<vm>.slot.<i>): VMCTL_SLOTS_LINUX (4) for a Linux VM,
# VMCTL_SLOTS_WINDOWS (2) for Windows, as sshd's MaxStartups and WinRM's
# MaxShellsPerUser allow far more. ch_slots_exclusive takes every slot, in
# order: nothing else runs on the VM while it holds them. A tunnel is only
# ever reopened under them (or, for a kube tunnel, which has no vmctl.sh
# caller, once no connection is open on its port), so a reopen never cuts a
# running command.
#
# The reopen. ch_reopen <vm> <kind> closes one tunnel and opens it again on
# the same port (tunnels.sh reopen-one), closing first the SSH master or the
# pooled WinRM session that runs over it, then probes it; any success clears
# the VM's dead mark.
#
# The record. ch_error_line is the one line every channel error prints:
# epoch and UTC time, VM, kind, port, both ages and the probe's verdict,
# stamped when it happens (the Go tests print their output only at the end
# of a subtest). ch_capture writes, before any recovery, what explains a
# failed channel into <diag dir>/channel/: the tunnel processes, the
# listening ports, the connections on each tunnel port, the end of the
# tunnel's own log, and (once per VM per 10 minutes, in the background,
# through az vm run-command, never the tunnel) the VM side's sshd or WinRM
# limits and logs.
#
# Needs CH_ACCESS_DIR (tunnels.sh's state directory, which holds access.json)
# and CH_STATE_DIR (vmctl.sh's locks and marks) set by the caller.
#
# Environment:
#   UAT_REFRESH_AFTER_MIN    REFRESH_AFTER, in minutes (default 10)
#   UAT_PROBE_SSH_SECONDS    SSH banner wait (default 5)
#   UAT_PROBE_HTTPS_SECONDS  WinRM and Kubernetes HTTPS wait (default 10)
#   VMCTL_SLOTS_LINUX, VMCTL_SLOTS_WINDOWS  slots per VM (default 4 and 2)
#   VMCTL_DIAG_DIR           where ch_capture writes (unset: nowhere)
#   UAT_TUNNELS              tunnels.sh (default the one here)
#   UAT_UAT_JSON             uat.json, for tunnels.sh and run-command
#   AZ_RELOGIN_DIR           the login stamp's directory
#   CURL, AZ                 the tools (default curl, az)

ch_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../scripts/redact.sh
. "$ch_here/../scripts/redact.sh"
ch_refresh_after=${UAT_REFRESH_AFTER_MIN:-10}
ch_probe_ssh=${UAT_PROBE_SSH_SECONDS:-5}
ch_probe_https=${UAT_PROBE_HTTPS_SECONDS:-10}
ch_tunnels=${UAT_TUNNELS:-$ch_here/tunnels.sh}
ch_login_dir=${AZ_RELOGIN_DIR:-${RUNNER_TEMP:-/tmp}}
ch_slots_fds=()

ch_valid_knobs() {
  local n
  for n in "$ch_refresh_after" "$ch_probe_ssh" "$ch_probe_https" "${VMCTL_SLOTS_LINUX:-4}" "${VMCTL_SLOTS_WINDOWS:-2}"; do
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || return 1
  done
}

ch_now() { date +%s; }

# ch_closefds: closes every file descriptor above 2 of the current (sub)shell.
# Run it in the subshell that starts anything that may outlive this call (an
# SSH master, a tunnel, a background capture): a slot or state lock is held
# as long as any process has its file open, so a long-lived child that
# inherited it would hold the VM's slot after we exit.
ch_closefds() {
  local fd n
  for fd in /proc/"$BASHPID"/fd/*; do
    n=${fd##*/}
    if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -le 2 ]; then continue; fi
    eval "exec $n>&-" 2>/dev/null || true
  done
  for n in "${ch_slots_fds[@]}"; do eval "exec $n>&-" 2>/dev/null || true; done
  [ -z "${ch_kube_lock_fd:-}" ] || eval "exec ${ch_kube_lock_fd}>&-" 2>/dev/null || true
}

# ch_login_age: seconds since the Azure login, or empty when none is recorded.
ch_login_age() {
  local f=$ch_login_dir/az-relogin.stamp
  [ -f "$f" ] || return 0
  echo $(($(ch_now) - $(stat -c %Y "$f")))
}

# ch_tunnel_age <vm> <kind>: seconds since that tunnel was opened, or empty
# when it is not open.
ch_tunnel_age() {
  local d=${CH_ACCESS_DIR:-} t=""
  [ -n "$d" ] && [ -s "$d/access.json" ] || return 0
  if [ -s "$d/opened/$1-$2" ]; then
    t=$(cat "$d/opened/$1-$2")
  elif [ -s "$d/opened_at" ]; then
    t=$(cat "$d/opened_at")
  fi
  [[ "$t" =~ ^[0-9]+$ ]] || return 0
  echo $(($(ch_now) - t))
}

# ch_fmt_age <seconds or empty>: "12m05s", or "unknown".
ch_fmt_age() {
  if [ -z "${1:-}" ]; then echo unknown; else printf '%dm%02ds\n' $(($1 / 60)) $(($1 % 60)); fi
}

# ch_due <age or empty>: is that age past REFRESH_AFTER (an unknown age is
# not due: there is nothing to refresh)?
ch_due() { [ -n "${1:-}" ] && [ "$1" -ge $((ch_refresh_after * 60)) ]; }

# ch_tunnel_limit <vm> <kind>: the age in seconds at which that tunnel is
# due. Staggered (W11): tunnels.sh opens every tunnel at once, so with one
# limit they all came due in the same supervisor round and were reopened
# together (UAT Run 2 on rc.21: D1's kubectl hit uat-core's kube tunnel
# mid-reopen). Tunnel i of the n in tunnels.pids is due i * REFRESH_AFTER /
# (2n) early, so the reopens spread over half of REFRESH_AFTER and stay
# apart. UAT_TUNNEL_STAGGER=0: every tunnel at REFRESH_AFTER.
ch_tunnel_limit() {
  local limit=$((ch_refresh_after * 60)) n i
  if [ "${UAT_TUNNEL_STAGGER:-1}" != 0 ] && [ -s "${CH_ACCESS_DIR:-}/tunnels.pids" ]; then
    n=$(grep -c . "$CH_ACCESS_DIR/tunnels.pids")
    i=$(awk -F'\t' -v vm="$1" -v k="$2" '$2 == vm && $3 == k { print NR - 1; exit }' "$CH_ACCESS_DIR/tunnels.pids")
    if [ -n "$i" ] && [ "$n" -gt 0 ]; then limit=$((limit - i * limit / (2 * n))); fi
  fi
  echo "$limit"
}

# ch_tunnel_due <vm> <kind> <age or empty>: is that tunnel's age past its
# (staggered) limit?
ch_tunnel_due() { [ -n "${3:-}" ] && [ "$3" -ge "$(ch_tunnel_limit "$1" "$2")" ]; }

# ch_port <vm> <kind>: the tunnel's local port from access.json, or empty.
ch_port() {
  [ -s "${CH_ACCESS_DIR:-}/access.json" ] || return 0
  jq -r --arg vm "$1" --arg k "$2_port" '.[$vm][$k] // empty' "$CH_ACCESS_DIR/access.json" 2>/dev/null || true
}

# ch_tunnels_of <vm>: the kinds of tunnel the VM has, one per line.
ch_tunnels_of() {
  [ -s "${CH_ACCESS_DIR:-}/access.json" ] || return 0
  jq -r --arg vm "$1" '.[$vm] // {} | keys[] | select(test("^(ssh|winrm|kube)_port$")) | sub("_port$"; "")' \
    "$CH_ACCESS_DIR/access.json" 2>/dev/null || true
}

# ch_probe <kind> <port>: prints "ok <detail>" or "fail <detail>", always
# exits 0.
ch_probe() {
  local kind=$1 port=$2 banner code
  case $kind in
    ssh)
      # shellcheck disable=SC2016 # $1 is expanded by the inner bash
      banner=$(timeout -k 1 "$ch_probe_ssh" bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1" && head -c 4 <&3' _ "$port" 2>/dev/null || true)
      if [ "$banner" = "SSH-" ]; then
        echo "ok SSH banner"
      elif [ -z "$banner" ]; then
        echo "fail no SSH banner within ${ch_probe_ssh}s"
      else
        echo "fail not an SSH banner"
      fi
      ;;
    winrm | kube)
      local path=/wsman
      [ "$kind" = kube ] && path=/version
      code=$("${CURL:-curl}" -sk -m "$ch_probe_https" -o /dev/null -w '%{http_code}' "https://127.0.0.1:$port$path" 2>/dev/null || true)
      code=${code:-000}
      if [ "$code" = 000 ]; then
        echo "fail no HTTPS answer on $path within ${ch_probe_https}s"
      elif [ "$kind" = kube ] || [ "$code" = 401 ] || [ "$code" = 405 ]; then
        echo "ok HTTP $code on $path"
      else
        echo "fail HTTP $code on $path (expected 401 or 405)"
      fi
      ;;
    *) echo "fail unknown tunnel kind $kind" ;;
  esac
}

# ch_error_line <vm> <kind> <port> <probe verdict> <what>: the channel error
# line, on stdout.
ch_error_line() {
  local now
  now=$(ch_now)
  printf 'CHANNEL ERROR at %s (epoch %s): vm=%s kind=%s port=%s login_age=%s tunnel_age=%s probe=%s: %s\n' \
    "$(date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ)" "$now" "$1" "$2" "${3:-none}" \
    "$(ch_fmt_age "$(ch_login_age)")" "$(ch_fmt_age "$(ch_tunnel_age "$1" "$2")")" "${4:-not run}" "$5"
}

# --- slots

ch_slots() { # ch_slots <os>: the VM's slot count
  if [ "$1" = windows ]; then echo "${VMCTL_SLOTS_WINDOWS:-2}"; else echo "${VMCTL_SLOTS_LINUX:-4}"; fi
}

# ch_slot_shared <vm> <slots> <wait seconds>: takes one free slot, waiting
# up to <wait>; 1 when none came free.
ch_slot_shared() {
  local vm=$1 n=$2 deadline=$((SECONDS + $3)) i fd
  while :; do
    for ((i = 0; i < n; i++)); do
      exec {fd}>>"$CH_STATE_DIR/$vm.slot.$i"
      if flock -n "$fd"; then
        ch_slots_fds=("$fd")
        return 0
      fi
      exec {fd}>&-
    done
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}

# ch_slots_exclusive <vm> <slots> <wait seconds>: takes every slot, in
# order, waiting up to <wait> in all; 1 (holding none) when they did not
# come free.
ch_slots_exclusive() {
  local vm=$1 n=$2 deadline=$((SECONDS + $3)) i fd left
  ch_slots_fds=()
  for ((i = 0; i < n; i++)); do
    exec {fd}>>"$CH_STATE_DIR/$vm.slot.$i"
    left=$((deadline - SECONDS))
    [ "$left" -ge 0 ] || left=0
    if ! flock -w "$left" "$fd"; then
      exec {fd}>&-
      ch_slots_release
      return 1
    fi
    ch_slots_fds+=("$fd")
  done
}

ch_slots_release() {
  local fd
  for fd in "${ch_slots_fds[@]}"; do
    flock -u "$fd" 2>/dev/null || true
    exec {fd}>&-
  done
  ch_slots_fds=()
}

# --- the SSH master

# ch_ssh_control <vm>: the VM's SSH master socket. Short (a Unix socket
# path is at most 107 bytes) and per runner user.
ch_ssh_control() { echo "${VMCTL_SSH_CONTROL_DIR:-/tmp/imas-cm-$(id -u)}/$1"; }

# ch_ssh_master_close <vm>: stops the VM's SSH master, if one runs.
ch_ssh_master_close() {
  local sock
  sock=$(ch_ssh_control "$1")
  [ -S "$sock" ] || return 0
  timeout -k 1 5 ssh -o ControlPath="$sock" -O exit "imas-$1" >/dev/null 2>&1 || true
  rm -f "$sock"
}

# --- the WinRM pool

# ch_winrm_pool <vm>: the VM's pooled WinRM session's socket (winrm_exec.py
# --pool), next to the SSH masters.
ch_winrm_pool() { echo "${VMCTL_SSH_CONTROL_DIR:-/tmp/imas-cm-$(id -u)}/winrm-$1.sock"; }

# ch_winrm_pool_close <vm>: ends the VM's pooled session, if one runs.
ch_winrm_pool_close() {
  local sock
  sock=$(ch_winrm_pool "$1")
  [ -S "$sock" ] || return 0
  timeout -k 1 5 python3 "$ch_here/winrm_exec.py" --close-pool "$sock" >/dev/null 2>&1 || true
}

# --- dead marks

# The mark of a VM: <state dir>/<vm>.fails, three lines: "<count> <epoch of
# the last failure> <epoch of the last re-probe>", the last failure, and
# nothing else.
ch_clear_mark() { rm -f "$CH_STATE_DIR/$1.fails"; }
ch_clear_marks() { rm -f "$CH_STATE_DIR"/*.fails; }

# --- the reopen

# ch_reopen <vm> <kind>: reopens one tunnel on its port and probes it, up
# to CH_REOPEN_ATTEMPTS (3) times in a row (W11: a failed reopen left the
# port with no listener until the next round); prints the probe's verdict,
# or tunnels.sh's own error. The caller holds the VM's slots
# (ch_slots_exclusive) or, for a kube tunnel, its lock (ch_kube_lock).
# While it runs, <access dir>/reopening/<vm>-<kind> exists (the harness
# retries a refused kubectl call while a kube tunnel's does). Exits 0 when
# the reopened tunnel answers.
ch_reopen() {
  local vm=$1 kind=$2 port verdict errf attempt tries=${CH_REOPEN_ATTEMPTS:-3}
  port=$(ch_port "$vm" "$kind")
  [ "$kind" = ssh ] && ch_ssh_master_close "$vm"
  [ "$kind" = winrm ] && ch_winrm_pool_close "$vm"
  mkdir -p "$CH_ACCESS_DIR/reopening"
  : >"$CH_ACCESS_DIR/reopening/$vm-$kind"
  errf=$(mktemp)
  for ((attempt = 1; attempt <= tries; attempt++)); do
    if ! (ch_closefds; TUNNEL_WAIT_SECONDS=${CH_REOPEN_WAIT_SECONDS:-60} exec "$ch_tunnels" reopen-one "${UAT_UAT_JSON:?}" "$CH_ACCESS_DIR" "$vm" "$kind" 2>"$errf"); then
      # tunnels.sh's own reason: its last line that is not a log line of
      # the tunnel's (those are indented).
      verdict="fail tunnels.sh reopen-one failed (attempt $attempt of $tries): $(grep -v '^[[:space:]]' "$errf" | grep -v '^[[:space:]]*$' | tail -n 1)"
      cat "$errf" >&2
      continue
    fi
    cat "$errf" >&2
    port=$(ch_port "$vm" "$kind")
    verdict=$(ch_probe "$kind" "$port")
    [ "${verdict%% *}" = ok ] && break
  done
  rm -f "$errf" "$CH_ACCESS_DIR/reopening/$vm-$kind"
  if [ "${verdict%% *}" != ok ] && [ -n "$port" ] && ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    verdict="$verdict; nothing listens on 127.0.0.1:$port now (the next round tries again)"
  fi
  echo "$verdict"
  if [ "${verdict%% *}" = ok ]; then
    ch_clear_mark "$vm"
    return 0
  fi
  return 1
}

# --- the kube tunnel lock (W11)

# ch_kube_lock_file <port>: the reader/writer lock of the kube tunnel on
# that port. The harness's kubectl and acceptance.sh calls hold it shared
# for their whole run (uat/tests/harness/kubelock.go); a reopen holds it
# exclusively.
ch_kube_lock_file() { echo "$CH_ACCESS_DIR/locks/kube-$1.lock"; }

# ch_kube_lock <port> <wait seconds>: takes the kube tunnel's lock
# exclusively, waiting up to <wait> for the calls that hold it shared; 1
# when they did not finish. ch_kube_unlock gives it back.
ch_kube_lock() {
  local fd
  mkdir -p "$CH_ACCESS_DIR/locks"
  exec {fd}>>"$(ch_kube_lock_file "$1")"
  if ! flock -x -w "$2" "$fd"; then
    exec {fd}>&-
    return 1
  fi
  ch_kube_lock_fd=$fd
}
ch_kube_unlock() {
  [ -n "${ch_kube_lock_fd:-}" ] || return 0
  flock -u "$ch_kube_lock_fd" 2>/dev/null || true
  exec {ch_kube_lock_fd}>&-
  ch_kube_lock_fd=""
}

# ch_port_connections <port>: established connections to a local port
# (ss, or /proc/net/tcp where ss is missing).
ch_port_connections() {
  if command -v ss >/dev/null 2>&1; then
    ss -Htn state established "( sport = :$1 )" 2>/dev/null | wc -l
    return 0
  fi
  local hex
  hex=$(printf '%04X' "$1")
  # local_address is IP:PORT in hex; state 01 is ESTABLISHED.
  cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p=":$hex" '$2 ~ p"$" && $4 == "01"' | wc -l
}

# --- the record

# ch_vm_field <vm> <id|os>: the VM's resource id or OS, from uat.json.
ch_vm_field() {
  jq -r --arg vm "$1" --arg f "$2" '
    ( [ (.dmz, .core) | objects | [(.node_names // [.name]), (.node_ids // [.id])] | transpose[]
        | select(.[0] == $vm) | {id: .[1], os: "ubuntu"} ] | first )
    // (.sprouts // {} | .[$vm] // empty) | .[$f] // empty' "${UAT_UAT_JSON:?}" 2>/dev/null || true
}

# ch_capture <vm> <kind> <port> <error line>: the channel's state at a
# failure, into $VMCTL_DIAG_DIR/channel/<epoch>-<vm>-<kind>.txt (redacted);
# no-op without VMCTL_DIAG_DIR. Never fails.
ch_capture() {
  local vm=$1 kind=$2 port=$3 line=$4 dir=${VMCTL_DIAG_DIR:-} f ports p
  [ -n "$dir" ] || return 0
  mkdir -p "$dir/channel" 2>/dev/null || return 0
  f="$dir/channel/$(ch_now)-$vm-$kind.txt"
  ports=$(jq -r '[.[] | to_entries[] | select(.key | endswith("_port")) | .value] | unique | .[]' \
    "$CH_ACCESS_DIR/access.json" 2>/dev/null | tr '\n' ' ')
  {
    echo "$line"
    echo
    echo "== tunnel processes (tunnels.pids: pid vm kind port; then every bastion tunnel process)"
    cat "$CH_ACCESS_DIR/tunnels.pids" 2>/dev/null
    ps -eo pid,ppid,pgid,etime,stat,args 2>/dev/null | awk 'NR == 1 || /bastion tunnel/ && !/awk/'
    echo
    echo "== listening TCP ports"
    ss -Hltnp 2>/dev/null || ss -ltn 2>/dev/null
    echo
    echo "== connections per tunnel port (state count)"
    for p in $ports; do
      echo "port $p: $(ss -Htan "( sport = :$p )" 2>/dev/null | awk '{print $1}' | sort | uniq -c | tr -s ' \n' ' ')"
    done
    echo
    echo "== the end of the $vm $kind tunnel's log"
    tail -n 50 "$CH_ACCESS_DIR/logs/$vm-$kind.log" 2>/dev/null
  } 2>&1 | redact >"$f"
  # In the background, holding none of the caller's streams: the caller's
  # reader (the Go harness) must not wait for it.
  # A WinRM call that timed out while the tunnel's probe answers points at
  # the VM itself (busy CPU, WinRM out of shells): always look (W11).
  local force=0
  if [ "$kind" = winrm ] && [[ "$line" == *"probe=ok "* ]] && [[ "$line" == *"timed out"* ]]; then force=1; fi
  (ch_closefds; ch_capture_vm_limits "$vm" "$force") </dev/null >/dev/null 2>&1 &
  disown 2>/dev/null || true
  return 0
}

# ch_capture_vm_limits <vm> [force]: the VM side of the channel, through
# az vm run-command (never the tunnel), at most once per VM per
# UAT_VM_LIMITS_EVERY_SECONDS (600) unless force is 1, into
# $VMCTL_DIAG_DIR/channel/<epoch>-<vm>-vm-side.txt, holding every slot of
# the VM (waiting up to UAT_VM_LIMITS_WAIT_SECONDS, 600) as any run-command
# call does. Azure keeps only the last 4096 bytes of the output, so what
# matters most comes last: on Windows the WinRM events, then its limits,
# then (W11) the CPU load, the WinRM service and its shells (the
# wsmprovhost processes and the WSMan shell instances).
ch_capture_vm_limits() {
  local vm=$1 force=${2:-0} dir=${VMCTL_DIAG_DIR:-} stamp id os out f
  [ -n "$dir" ] && [ -n "${UAT_UAT_JSON:-}" ] || return 0
  stamp="$CH_STATE_DIR/$vm.vm-side"
  if [ "$force" != 1 ] && [ -f "$stamp" ] && [ $(($(ch_now) - $(stat -c %Y "$stamp"))) -lt "${UAT_VM_LIMITS_EVERY_SECONDS:-600}" ]; then
    return 0
  fi
  touch "$stamp"
  id=$(ch_vm_field "$vm" id)
  os=$(ch_vm_field "$vm" os)
  [ -n "$id" ] || return 0
  # Azure runs one run-command per VM at a time: hold every slot, as
  # vmctl.sh does for its own (this waits for the caller to finish).
  ch_slots_exclusive "$vm" "$(ch_slots "$os")" "${UAT_VM_LIMITS_WAIT_SECONDS:-600}" || return 0
  f="$dir/channel/$(ch_now)-$vm-vm-side.txt"
  if [ "$os" = windows ]; then
    # shellcheck disable=SC2016 # PowerShell, expanded on the VM
    out=$(timeout -k 10 "${UAT_RUNCOMMAND_TIMEOUT:-240}" "${AZ:-az}" vm run-command invoke --ids "$id" \
      --command-id RunPowerShellScript -o json --scripts \
      'Get-WinEvent -LogName Microsoft-Windows-WinRM/Operational -MaxEvents 12 -ErrorAction SilentlyContinue | ForEach-Object { $m = $_.Message -replace "\s+", " "; if ($m.Length -gt 160) { $m = $m.Substring(0, 160) + "..." }; "$($_.TimeCreated.ToUniversalTime().ToString("o")) $($_.Id): $m" }' \
      'winrm get winrm/config/winrs' 'winrm get winrm/config/service' \
      'Get-NetTCPConnection -LocalPort 5986 -ErrorAction SilentlyContinue | Group-Object State | Format-Table Name, Count' \
      '"== CPU load: $((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)%; top processes by CPU time:"' \
      'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Format-Table -AutoSize Name, Id, CPU, WorkingSet64' \
      '"== WinRM service: $((Get-Service WinRM).Status); wsmprovhost processes: $(@(Get-Process wsmprovhost -ErrorAction SilentlyContinue).Count); WSMan shells open: $(@(Get-WSManInstance -ResourceURI shell -Enumerate -ErrorAction SilentlyContinue).Count)"' \
      2>&1) || true
  else
    # shellcheck disable=SC2016 # expanded on the VM
    out=$(timeout -k 10 "${UAT_RUNCOMMAND_TIMEOUT:-240}" "${AZ:-az}" vm run-command invoke --ids "$id" \
      --command-id RunShellScript -o json --scripts \
      'sshd -T 2>/dev/null | grep -Ei "^(maxstartups|maxsessions|maxauthtries|logingracetime|clientalive)"' \
      'echo "established on 22: $(ss -Htn state established "( sport = :22 )" | wc -l)"' \
      'journalctl -u ssh -u sshd --no-pager -n 60 -o short-iso 2>/dev/null' \
      2>&1) || true
  fi
  ch_slots_release
  {
    echo "== $vm, VM side, through az vm run-command (not the tunnel)"
    printf '%s\n' "$out" | jq -r '[.value[]?.message] | join("\n")' 2>/dev/null || printf '%s\n' "$out"
  } | redact >"$f"
}
