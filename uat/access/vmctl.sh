#!/usr/bin/env bash
# vmctl.sh: control a UAT VM (UAT.1, Access interface of the Shared contract
# in section 4h of docs/claude-code-parallel-build-plan.md).
#
#   vmctl.sh <uat.json> restart      <vm>
#   vmctl.sh <uat.json> stop-sprout  <vm>
#   vmctl.sh <uat.json> start-sprout <vm>
#   vmctl.sh <uat.json> stop-vm      <vm>
#   vmctl.sh <uat.json> start-vm     <vm>
#   vmctl.sh <uat.json> run          <vm> <command...>
#
# <vm> is a VM name from uat.json: a hub node (uat-dmz and uat-core, or on an
# HA hub uat-dmz-1 to uat-dmz-N and uat-core-1 to uat-core-N: the hub's
# node_names) or a key of sprouts.
#
# The channel. A command runs over the VM's Bastion tunnel when access.json
# (tunnels.sh) has one for it: SSH (ssh_port, the admin user and sudo, over
# one persistent SSH master per VM) on Linux, WinRM (winrm_port, HTTPS with
# NTLM, through winrm_exec.py and the runner's pywinrm, one pooled session
# per VM) on Windows. Only a VM
# with no tunnel entry, or VMCTL_CHANNEL=runcommand, uses az vm run-command,
# which takes 30 to 60 s a call and runs one command per VM at a time (UAT
# Run 2, uat/RUNBOOK.md). The power operations (restart, stop-vm, start-vm)
# always go through the Azure control plane.
#
# restart       az vm restart (when it fails: a reboot through run-command),
#               then waits, up to VMCTL_RESTART_WAIT_SECONDS in all, until
#               Azure reports the VM running and its guest answers: the
#               tunnel's protocol probe, then a command over it. Every failed
#               probe recreates the tunnel (a tunnel opened before the reboot
#               can stop serving: UAT Run 2's Windows L1). With no tunnel, the
#               guest agent reporting Ready after the restart began. A
#               failure names the reason and the last probe's error.
# stop-sprout   stops the sprout service (systemd unit or Windows service
# start-sprout  imas-sprout) on a sprout VM; refused for the hubs.
# stop-vm       az vm stop (powered off, still allocated) on a hub node, then
#               waits until Azure reports it stopped, up to
#               VMCTL_POWER_WAIT_SECONDS: the ha tier's node stop (uat/tests,
#               HA2); refused for sprouts.
# start-vm      az vm start on a hub node, then waits as restart does.
# run           runs <command...> (joined with spaces): bash as root (sudo)
#               on Linux, PowerShell on Windows (the admin user over WinRM,
#               SYSTEM through run-command). Prints the command's stdout on
#               stdout and its stderr on stderr, then "vmctl.sh: exit_code=N"
#               on stderr, and exits N. On Windows, N is $LASTEXITCODE of the
#               last native command, or 1 when the script failed with an
#               error, else 0. Through run-command Azure keeps only the last
#               4096 bytes of each stream.
#
# Every timeout here runs with --foreground, so it stays in vmctl.sh's process
# group and the harness's group kill reaches it and its child.
#
# The slots (W10, uat/access/channel.sh). Calls to one VM share
# VMCTL_SLOTS_LINUX (4) or VMCTL_SLOTS_WINDOWS (2) slots, across processes;
# restart, stop-vm, start-vm, a run-command call and every tunnel reopen
# take them all. Each channel call has its own timeout (VMCTL_CALL_TIMEOUT)
# and is killed when it runs over.
#
# Fresh before each command (W10). When the Azure login or the VM's tunnel is
# REFRESH_AFTER (UAT_REFRESH_AFTER_MIN, 10) minutes old or more, vmctl.sh
# logs in again (UAT_AZ_RELOGIN) and reopens the tunnel on its port, under
# the VM's slots, before the command. session.sh's supervisor does the same
# every minute; this is for a call that comes first.
#
# A channel failure (W10). When a call over the tunnel fails with no exit
# code, vmctl.sh prints one CHANNEL ERROR line (epoch and time, VM, kind,
# port, both ages, the probe's verdict and the failure), captures the
# channel's state into $VMCTL_DIAG_DIR/channel/ before touching anything,
# probes the tunnel by its protocol, and reopens it (under the VM's slots)
# when the probe fails. A call that certainly never started is then tried
# once more (VMCTL_CONNECT_RETRIES); one that may have run never is. Only a
# failure that remains counts as a strike. After VMCTL_DEAD_AFTER strikes in
# a row the VM is marked dead: a call to it fails at once ("CHANNEL
# UNAVAILABLE"), except that, VMCTL_REPROBE_SECONDS (120) after the last
# failure or re-probe, the call re-probes the tunnel first (reopening it
# when it does not answer) and, when it answers, clears the mark and runs.
# A success, a restart or start-vm that comes back, a reopen that answers,
# and every session.sh refresh clear the mark. A run-command refused with
# "(Conflict) Run command extension execution is in progress" (Azure never
# started it) is retried with backoff.
#
# Exit status: the command's for run, stop-sprout and start-sprout; 0 for a
# restart or start-vm that came back and a stop-vm that stopped; 2 on a usage
# error or an unknown VM; 255 when the command could not be run or gave no
# exit code (the channel failed, timed out, or the VM is marked dead: the
# output then has a line with "CHANNEL UNAVAILABLE").
#
# All Azure calls of the UAT gate live here, in channel.sh and in tunnels.sh.
#
# Environment:
#   AZ                    az command (default az)
#   UAT_AZ_RELOGIN        a command (uat/access/az-relogin.sh in the gate) that
#                         logs az in again: before a command when the login is
#                         REFRESH_AFTER old, and once, the az call repeated,
#                         when az fails with AADSTS700024 (expired session)
#   UAT_REFRESH_AFTER_MIN REFRESH_AFTER, in minutes (default 10)
#   VMCTL_ACCESS          tunnels.sh's access.json (default
#                         $UAT_SESSION_ACCESS/access.json, else
#                         <uat.json's directory>/access/access.json); a VM it
#                         does not list uses run-command
#   VMCTL_CHANNEL         runcommand: use az vm run-command even where there
#                         is a tunnel (the harness's way past a dead tunnel
#                         to the sprout's job log)
#   VMCTL_SSH_KEY         the SSH private key for the Linux tunnels
#   VMCTL_SSH_USER        the SSH user (default the VM's admin_user)
#   VMCTL_SSH_PERSIST     seconds an idle SSH master stays (default 300)
#   VMCTL_SSH_CONTROL_DIR the SSH masters' sockets (default /tmp/imas-cm-<uid>)
#   VMCTL_WINRM_PASSWORD_FILE  the WinRM password for the Windows tunnels
#   VMCTL_WINRM_USER      the WinRM user (default the VM's admin_user)
#   VMCTL_WINRM_POOL      0: a WinRM session per call instead of one pooled
#                         session per VM (default 1)
#   VMCTL_WINRM_POOL_IDLE seconds an idle pooled session stays (default 300)
#                         A tunnel without its credential falls back to
#                         run-command, saying so.
#   VMCTL_STATE_DIR       slots, dead marks and SSH known hosts (default
#                         <access.json's directory>/vmctl, else
#                         ${TMPDIR:-/tmp}/imas-vmctl-<uid>)
#   VMCTL_DIAG_DIR        where a channel failure's state goes (channel/);
#                         unset: nowhere
#   VMCTL_CALL_TIMEOUT    seconds for one channel call (default 120)
#   VMCTL_AZ_TIMEOUT      seconds for one az power operation (default 600)
#   VMCTL_LOCK_WAIT_SECONDS  how long to wait for the VM's slots (default 900)
#   VMCTL_SLOTS_LINUX, VMCTL_SLOTS_WINDOWS  slots per VM (default 4 and 2)
#   VMCTL_CONFLICT_RETRIES   run-command Conflict retries (default 4; 15 s,
#                         30 s, 60 s, 120 s apart)
#   VMCTL_CONNECT_RETRIES    tries again of a call that never started, after
#                         the probe and any reopen (default 1)
#   VMCTL_DEAD_AFTER      strikes in a row that mark the VM dead (default 3;
#                         0 never marks)
#   VMCTL_REPROBE_SECONDS how often a dead VM's tunnel is re-probed by a call
#                         to it (default 120)
#   VMCTL_SPROUT_SERVICE  service name (default imas-sprout, as packaged)
#   VMCTL_POWER_WAIT_SECONDS  wait for the power state (stop-vm; default 300)
#   VMCTL_RESTART_WAIT_SECONDS  the whole wait after a restart or start-vm:
#                         running, the probe and a command (default
#                         VMCTL_WAIT_SECONDS, else 600)
#   VMCTL_PROBE_TIMEOUT   seconds for one guest command in that wait
#                         (default 30)
#   VMCTL_POLL_SECONDS    the waits' poll interval (default 10)
#   VMCTL_BACKOFF_SCALE   multiplies every retry backoff (default 1; the
#                         tests set 0)
set -euo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AZ=${AZ:-az}
service=${VMCTL_SPROUT_SERVICE:-imas-sprout}
wait_seconds=${VMCTL_WAIT_SECONDS:-600}
power_wait=${VMCTL_POWER_WAIT_SECONDS:-300}
restart_wait=${VMCTL_RESTART_WAIT_SECONDS:-$wait_seconds}
poll_seconds=${VMCTL_POLL_SECONDS:-10}
call_timeout=${VMCTL_CALL_TIMEOUT:-120}
az_timeout=${VMCTL_AZ_TIMEOUT:-600}
probe_timeout=${VMCTL_PROBE_TIMEOUT:-30}
lock_wait=${VMCTL_LOCK_WAIT_SECONDS:-900}
conflict_retries=${VMCTL_CONFLICT_RETRIES:-4}
connect_retries=${VMCTL_CONNECT_RETRIES:-1}
dead_after=${VMCTL_DEAD_AFTER:-3}
reprobe_seconds=${VMCTL_REPROBE_SECONDS:-120}
ssh_persist=${VMCTL_SSH_PERSIST:-300}
winrm_pool=${VMCTL_WINRM_POOL:-1}
winrm_idle=${VMCTL_WINRM_POOL_IDLE:-300}
backoff_scale=${VMCTL_BACKOFF_SCALE:-1}
marker="__IMAS_VMCTL_RC__"

usage() {
  cat >&2 <<EOF
usage: $prog <uat.json> restart|stop-sprout|start-sprout|stop-vm|start-vm <vm>
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
  restart | stop-sprout | start-sprout | stop-vm | start-vm) [ $# -eq 0 ] || usage ;;
  run) [ $# -ge 1 ] || usage ;;
  *) log "unknown action '$action'"; usage ;;
esac
[[ "$service" =~ ^[A-Za-z0-9._@-]+$ ]] || { log "VMCTL_SPROUT_SERVICE has unexpected characters"; exit 2; }
for n in "$wait_seconds" "$power_wait" "$restart_wait" "$poll_seconds" "$call_timeout" "$az_timeout" "$probe_timeout" \
  "$lock_wait" "$conflict_retries" "$connect_retries" "$dead_after" "$reprobe_seconds" "$ssh_persist" "$winrm_pool" "$winrm_idle" "$backoff_scale"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { log "the VMCTL_* timeouts, waits and counts must be whole numbers (got '$n')"; exit 2; }
done
if [ "$call_timeout" -eq 0 ] || [ "$probe_timeout" -eq 0 ] || [ "$az_timeout" -eq 0 ]; then
  log "VMCTL_CALL_TIMEOUT, VMCTL_PROBE_TIMEOUT and VMCTL_AZ_TIMEOUT must be above 0"
  exit 2
fi
[ -r "$uat" ] || { log "cannot read $uat"; exit 2; }
for tool in jq timeout flock; do
  command -v "$tool" >/dev/null 2>&1 || { log "$tool is not on PATH"; exit 2; }
done
command -v "$AZ" >/dev/null 2>&1 || { log "$AZ is not on PATH"; exit 2; }

# Look the VM up: kind (hub or sprout), resource id, OS and admin user. A
# hub's VMs are its node_names and node_ids (every node of an HA hub, P24),
# or its name and id where uat.json has no node lists.
lookup=$(jq -r --arg vm "$vm" '
  ( [ (.dmz, .core) | objects | (.admin_user // "") as $u
      | [(.node_names // [.name]), (.node_ids // [.id])] | transpose[]
      | select(.[0] == $vm) | ["hub", .[1], "ubuntu", $u] ] | first )
  // (if (.sprouts // {}) | has($vm)
      then ["sprout", .sprouts[$vm].id, .sprouts[$vm].os, (.sprouts[$vm].admin_user // "")] else empty end)
  | @tsv' "$uat") || { log "$uat is not valid JSON"; exit 2; }
[ -n "$lookup" ] || { log "no VM named '$vm' in $uat"; exit 2; }
IFS=$'\t' read -r kind vm_id os admin_user <<<"$lookup"
[ -n "$vm_id" ] || { log "VM '$vm' has no id in $uat"; exit 2; }

# The channel: ssh or winrm over the VM's tunnel, else runcommand.
access=${VMCTL_ACCESS:-}
if [ -z "$access" ]; then
  if [ -n "${UAT_SESSION_ACCESS:-}" ]; then
    access=$UAT_SESSION_ACCESS/access.json
  else
    access=$(dirname "$uat")/access/access.json
  fi
fi
channel=runcommand
tunnel_kind=""
tunnel_host=""
tunnel_port=""
if [ -r "$access" ] && [ "${VMCTL_CHANNEL:-}" != runcommand ]; then
  tunnel_kind=ssh
  [ "$os" = windows ] && tunnel_kind=winrm
  if ! read -r tunnel_host tunnel_port < <(jq -r --arg vm "$vm" --arg k "${tunnel_kind}_port" \
    '.[$vm] // {} | select(.[$k] != null) | "\(.host // "127.0.0.1") \(.[$k])"' "$access" 2>/dev/null); then
    tunnel_host="" tunnel_port=""
  fi
fi
if [ -n "$tunnel_port" ]; then
  if [ "$os" = windows ]; then
    if [ -z "${VMCTL_WINRM_PASSWORD_FILE:-}" ] || [ ! -r "${VMCTL_WINRM_PASSWORD_FILE:-}" ]; then
      log "$vm has a WinRM tunnel but VMCTL_WINRM_PASSWORD_FILE is not a readable file; using run-command"
    elif ! command -v python3 >/dev/null 2>&1; then
      log "$vm has a WinRM tunnel but python3 is not on PATH; using run-command"
    else
      channel=winrm
    fi
  else
    if [ -z "${VMCTL_SSH_KEY:-}" ] || [ ! -r "${VMCTL_SSH_KEY:-}" ]; then
      log "$vm has an SSH tunnel but VMCTL_SSH_KEY is not a readable file; using run-command"
    elif ! command -v ssh >/dev/null 2>&1; then
      log "$vm has an SSH tunnel but ssh is not on PATH; using run-command"
    else
      channel=ssh
    fi
  fi
fi
ssh_user=${VMCTL_SSH_USER:-$admin_user}
winrm_user=${VMCTL_WINRM_USER:-$admin_user}
if [ "$channel" = ssh ] && [ -z "$ssh_user" ]; then
  log "no SSH user for $vm: uat.json has no admin_user and VMCTL_SSH_USER is not set"
  exit 2
fi
if [ "$channel" = winrm ] && [ -z "$winrm_user" ]; then
  log "no WinRM user for $vm: uat.json has no admin_user and VMCTL_WINRM_USER is not set"
  exit 2
fi

# State: slots, a dead mark and the SSH known hosts per VM.
state_dir=${VMCTL_STATE_DIR:-}
if [ -z "$state_dir" ]; then
  if [ -r "$access" ]; then
    state_dir=$(dirname "$access")/vmctl
  else
    state_dir=${TMPDIR:-/tmp}/imas-vmctl-$(id -u)
  fi
fi
mkdir -p "$state_dir"
fails_file=$state_dir/$vm.fails

CH_ACCESS_DIR=$(dirname "$access")
CH_STATE_DIR=$state_dir
UAT_UAT_JSON=$uat
export UAT_UAT_JSON
# shellcheck source=channel.sh
. "$here/channel.sh"
ch_valid_knobs || { log "UAT_REFRESH_AFTER_MIN, UAT_PROBE_*_SECONDS and VMCTL_SLOTS_* must be whole numbers above 0"; exit 2; }

# The slots: every one (exclusive) for the power operations and run-command
# (Azure runs one run-command per VM at a time), one for a tunnel call.
slots=$(ch_slots "$os")
slot_mode=shared
case $action in restart | stop-vm | start-vm) slot_mode=exclusive ;; esac
[ "$channel" = runcommand ] && slot_mode=exclusive
lock_start=$SECONDS
take_slots() {
  if [ "$slot_mode" = exclusive ]; then
    ch_slots_exclusive "$vm" "$slots" "$lock_wait"
  else
    ch_slot_shared "$vm" "$slots" "$lock_wait"
  fi
}
if ! take_slots; then
  log "other vmctl.sh calls held the slots of $vm for ${lock_wait}s; giving up"
  log "exit_code=255"
  exit 255
fi
if [ $((SECONDS - lock_start)) -ge 5 ]; then
  log "waited $((SECONDS - lock_start))s for other calls on $vm to finish"
fi

# with_all_slots <command...>: runs the command holding every slot of the VM
# (a tunnel reopen): gives a shared slot back first, and takes it again
# after. 1 when the slots did not come free.
with_all_slots() {
  local rc=0
  if [ "$slot_mode" = exclusive ]; then
    "$@" || rc=$?
    return "$rc"
  fi
  ch_slots_release
  if ! ch_slots_exclusive "$vm" "$slots" "$lock_wait"; then
    take_slots || true
    return 1
  fi
  "$@" || rc=$?
  ch_slots_release
  if ! take_slots; then
    log "lost the slot of $vm while the tunnel was reopened; giving up"
    log "exit_code=255"
    exit 255
  fi
  return "$rc"
}

# fail_count, fail_epoch, probe_epoch and fail_reason: the VM's strikes in a
# row, when the last was, when the tunnel was last re-probed, and what the
# last failure was.
read_fails() {
  fail_count=0 fail_epoch=0 probe_epoch=0 fail_reason=""
  if [ -f "$fails_file" ]; then
    { read -r fail_count fail_epoch probe_epoch && IFS= read -r fail_reason; } <"$fails_file" || true
    [[ "$fail_count" =~ ^[0-9]+$ ]] || fail_count=0
    [[ "$fail_epoch" =~ ^[0-9]+$ ]] || fail_epoch=0
    [[ "${probe_epoch:-}" =~ ^[0-9]+$ ]] || probe_epoch=0
  fi
}
write_fails() { # write_fails <count> <fail epoch> <probe epoch> <reason>
  printf '%s %s %s\n%s\n' "$1" "$2" "$3" "$4" >"$fails_file.tmp"
  mv "$fails_file.tmp" "$fails_file"
}
note_ok() { ch_clear_mark "$vm"; }
note_fail() {
  read_fails
  write_fails "$((fail_count + 1))" "$(date +%s)" 0 "$1"
  if [ "$dead_after" -gt 0 ] && [ $((fail_count + 1)) -ge "$dead_after" ]; then
    log "$vm is now marked dead: $((fail_count + 1)) channel failures in a row (last: $1); a call re-probes it ${reprobe_seconds}s from now"
  fi
}

# backoff <seconds>: sleeps seconds times VMCTL_BACKOFF_SCALE.
backoff() { sleep $(($1 * backoff_scale)); }

# relogin: logs az in again with UAT_AZ_RELOGIN (its stdout, which in the
# workflow can carry a ::add-mask:: line with the token, is dropped: ours is
# read into the report).
relogin() {
  [ -n "${UAT_AZ_RELOGIN:-}" ] || return 1
  AZ_RELOGIN_ADD_MASK=0 "$UAT_AZ_RELOGIN" >/dev/null
}

# az_run <timeout> <az args>: "$AZ" with the args, killed after <timeout>
# seconds; when it fails with AADSTS700024 and UAT_AZ_RELOGIN is set, logs
# in again and repeats the call once. stdout is az's; its stderr goes to our
# stderr and stays in $az_err_file (az_run often runs in a subshell).
az_err_file=$(mktemp)
trap 'rm -f "$az_err_file"' EXIT
az_run() {
  local secs=$1 rc=0 started=$SECONDS
  shift
  timeout --foreground -k 10 "$secs" "$AZ" "$@" 2>"$az_err_file" || rc=$?
  if [ "$rc" -ne 0 ] && [ -n "${UAT_AZ_RELOGIN:-}" ] && grep -q AADSTS700024 "$az_err_file"; then
    log "the Azure login expired; logging in again"
    if relogin; then
      rc=0
      timeout --foreground -k 10 "$secs" "$AZ" "$@" 2>"$az_err_file" || rc=$?
    else
      log "logging in again failed"
    fi
  fi
  # 124: timed out; 137: timed out and killed after ignoring TERM (or killed
  # otherwise, hence the elapsed time check).
  if [ "$rc" -eq 124 ] || { [ "$rc" -eq 137 ] && [ $((SECONDS - started)) -ge "$secs" ]; }; then
    echo "az $1 $2 timed out after ${secs}s" >>"$az_err_file"
  fi
  cat "$az_err_file" >&2
  return "$rc"
}

# ps_wrapper <base64>: the PowerShell wrapper of both Windows channels. It
# decodes the command (UTF-8, base64), runs it, and prints the exit code
# marker.
ps_wrapper() {
  printf '%s\n' \
    "\$__c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$1'))" \
    "\$global:LASTEXITCODE = 0; \$__ok = \$true" \
    "try { & ([ScriptBlock]::Create(\$__c)); \$__ok = \$? } catch { Write-Error \$_; \$__ok = \$false }" \
    "if (\$LASTEXITCODE -ne 0) { \$__rc = \$LASTEXITCODE } elseif (-not \$__ok) { \$__rc = 1 } else { \$__rc = 0 }" \
    "Write-Output \"$marker\$__rc\""
}

# The channels. Each sets remote_out, remote_err and remote_rc (the
# command's code, from the marker), and returns 0 when the command ran and
# its code came back, 1 when it did not (remote_why says why), 2 when it
# certainly never started (worth retrying).
remote_why=""

rc_from_marker() {
  local rc_line
  rc_line=$(printf '%s\n' "$remote_out" | grep -E "^${marker}[0-9]+\$" | tail -n 1 || true)
  remote_out=$(printf '%s\n' "$remote_out" | grep -vE "^${marker}[0-9]+\$" || true)
  [ -n "$rc_line" ] || return 1
  remote_rc=${rc_line#"$marker"}
  return 0
}

run_runcommand() {
  local script=$1 secs=$2 b64 json attempt=0
  b64=$(printf '%s' "$script" | base64 | tr -d '\n')
  while :; do
    if [ "$os" = windows ]; then
      local -a lines=()
      mapfile -t lines < <(ps_wrapper "$b64")
      json=$(az_run "$secs" vm run-command invoke --ids "$vm_id" --command-id RunPowerShellScript -o json --scripts "${lines[@]}") && break
    else
      json=$(az_run "$secs" vm run-command invoke --ids "$vm_id" --command-id RunShellScript -o json --scripts \
        "__imas_cmd=\$(printf '%s' '$b64' | base64 -d)" \
        "bash -c \"\$__imas_cmd\" </dev/null" \
        "echo \"$marker\$?\"") && break
    fi
    if grep -q "Run command extension execution is in progress" "$az_err_file" &&
      [ "$attempt" -lt "$conflict_retries" ]; then
      attempt=$((attempt + 1))
      local wait=$((15 * (1 << (attempt - 1))))
      log "$vm: run-command is busy with an earlier command (Conflict); retry $attempt of $conflict_retries in ${wait}s"
      backoff "$wait"
      continue
    fi
    if grep -q "timed out after" "$az_err_file"; then
      remote_why="az vm run-command timed out after ${secs}s (VMCTL_CALL_TIMEOUT)"
    elif grep -q "Run command extension execution is in progress" "$az_err_file"; then
      remote_why="run-command stayed busy (Conflict) through $conflict_retries retries"
    else
      remote_why="az vm run-command failed: $(grep -v '^[[:space:]]*$' "$az_err_file" | head -n 1)"
    fi
    return 1
  done
  if [ "$os" = windows ]; then
    remote_out=$(printf '%s' "$json" | jq -r '[.value[]? | select(.code | test("StdOut"))][0].message // ""' | tr -d '\r')
    remote_err=$(printf '%s' "$json" | jq -r '[.value[]? | select(.code | test("StdErr"))][0].message // ""' | tr -d '\r')
  else
    # Linux run-command returns one message: "...[stdout]\n<out>\n[stderr]\n<err>".
    local msg
    msg=$(printf '%s' "$json" | jq -r '.value[0].message // ""')
    remote_out=$(printf '%s\n' "$msg" | awk '/^\[stdout\]$/{f=1;next} /^\[stderr\]$/{f=0} f')
    remote_err=$(printf '%s\n' "$msg" | awk '/^\[stderr\]$/{f=1;next} f')
  fi
  if ! rc_from_marker; then
    remote_why="Azure gave no exit code (output truncated?)"
    return 1
  fi
}

# An SSH error before the command started: the tunnel or sshd refused, or
# the connection (or the session over the master) never opened.
ssh_preexec_re='kex_exchange_identification|ssh_exchange_identification|Connection refused|banner exchange|Connection closed by [0-9]|Connection reset by [0-9]|Connection timed out$|mux_client_request_session|Control socket connect'

run_ssh() {
  local script=$1 secs=$2 errf rc=0 control
  errf=$(mktemp)
  control=$(ch_ssh_control "$vm")
  mkdir -p "$(dirname "$control")" && chmod 700 "$(dirname "$control")"
  # The script goes on stdin into a file, then runs as root with stdin
  # /dev/null (as through run-command); the marker comes from the login
  # shell after it. One master per VM (ControlMaster) carries every call
  # until it has been idle for VMCTL_SSH_PERSIST seconds; ServerAlive ends a
  # master whose tunnel died within a minute.
  # shellcheck disable=SC2016 # expanded on the VM
  remote_out=$(ch_closefds; printf '%s' "$script" | timeout --foreground -k 5 "$secs" ssh -p "$tunnel_port" -i "$VMCTL_SSH_KEY" \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$state_dir/known_hosts" -o HostKeyAlias="$vm" \
    -o ControlMaster=auto -o ControlPath="$control" -o ControlPersist="$ssh_persist" \
    -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR \
    "$ssh_user@$tunnel_host" \
    '__f=$(mktemp) && cat >"$__f" && sudo -n -H bash "$__f" </dev/null; __rc=$?; rm -f "$__f"; echo "'"$marker"'$__rc"' \
    2>"$errf") || rc=$?
  remote_err=$(cat "$errf")
  rm -f "$errf"
  if rc_from_marker; then return 0; fi
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    remote_why="ssh to $vm ($tunnel_host:$tunnel_port) timed out after ${secs}s (VMCTL_CALL_TIMEOUT); killed"
    return 1
  fi
  # The line that says why: ssh's own reason for a connection that never
  # opened ("... during banner exchange"), else its last line.
  local why
  why=$(printf '%s\n' "$remote_err" | grep -E "$ssh_preexec_re" | head -n 1 || true)
  [ -n "$why" ] || why=$(printf '%s' "$remote_err" | grep -v '^[[:space:]]*$' | tail -n 1 || true)
  remote_why="ssh to $vm ($tunnel_host:$tunnel_port) exited $rc with no exit code: $why"
  if [ "$rc" -eq 255 ] && printf '%s' "$remote_err" | grep -Eq "$ssh_preexec_re"; then return 2; fi
  return 1
}

run_winrm() {
  local script=$1 secs=$2 errf b64 rc=0
  local -a pool=()
  errf=$(mktemp)
  b64=$(printf '%s' "$script" | base64 | tr -d '\n')
  # One pooled session per VM (winrm_exec.py --pool): no new connection
  # and no new shell through the tunnel per call.
  if [ "$winrm_pool" != 0 ]; then
    pool=(--pool "$(ch_winrm_pool "$vm")" --pool-idle "$winrm_idle" --deadline "$secs")
    mkdir -p "$(dirname "${pool[1]}")" && chmod 700 "$(dirname "${pool[1]}")"
  fi
  remote_out=$(ch_closefds; ps_wrapper "$b64" | timeout --foreground -k 5 "$secs" python3 "$here/winrm_exec.py" \
    --host "$tunnel_host" --port "$tunnel_port" --user "$winrm_user" \
    --password-file "$VMCTL_WINRM_PASSWORD_FILE" "${pool[@]}" 2>"$errf") || rc=$?
  remote_out=$(printf '%s' "$remote_out" | tr -d '\r')
  remote_err=$(tr -d '\r' <"$errf")
  rm -f "$errf"
  if rc_from_marker; then return 0; fi
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    remote_why="WinRM to $vm ($tunnel_host:$tunnel_port) timed out after ${secs}s (VMCTL_CALL_TIMEOUT); killed"
    return 1
  fi
  remote_why="WinRM to $vm ($tunnel_host:$tunnel_port) exited $rc with no exit code: $(printf '%s' "$remote_err" | grep -v '^[[:space:]]*$' | tail -n 1)"
  # winrm_exec.py exits 254 when it could not open a shell: nothing ran.
  [ "$rc" -eq 254 ] && return 2
  return 1
}

# run_channel <script> <timeout>: one call over the channel, no retry.
run_channel() {
  case $channel in
    ssh) run_ssh "$1" "$2" ;;
    winrm) run_winrm "$1" "$2" ;;
    *) run_runcommand "$1" "$2" ;;
  esac
}

# reopen_tunnel: reopens the VM's tunnel on its port (the caller holds every
# slot) and sets recover_verdict to the probe's verdict on the new one.
reopen_tunnel() {
  recover_verdict=$(ch_reopen "$vm" "$tunnel_kind") || true
  tunnel_port=$(ch_port "$vm" "$tunnel_kind")
}

# recover_tunnel: under every slot of the VM, probes its tunnel again (a
# call that held the slots before us may have reopened it already) and,
# when it does not answer, reopens it. Sets recover_verdict; 0 when the
# tunnel answers. Never call it in $(...): a subshell that gives back the
# caller's slot gives it back for the caller too (flock locks belong to the
# open file, which the subshell shares).
recover_once() {
  recover_verdict=$(ch_probe "$tunnel_kind" "$tunnel_port")
  if [ "${recover_verdict%% *}" != ok ]; then
    log "$vm: the $tunnel_kind tunnel does not answer ($recover_verdict); reopening it on 127.0.0.1:$tunnel_port"
    reopen_tunnel
    log "$vm: after the reopen: $recover_verdict"
  fi
}
recover_tunnel() {
  recover_verdict="fail could not take the slots of $vm to reopen its tunnel"
  with_all_slots recover_once || true
  [ "${recover_verdict%% *}" = ok ]
}

# fresh_once: ensure_fresh's reopen, under every slot.
fresh_once() {
  # Another call may have reopened it while we waited for the slots.
  ch_due "$(ch_tunnel_age "$vm" "$tunnel_kind")" || return 0
  reopen_tunnel
  log "$vm: after the reopen: $recover_verdict"
}

# ensure_fresh: before a command over a tunnel, a login or a tunnel past
# REFRESH_AFTER is renewed (W10).
ensure_fresh() {
  [ "$channel" != runcommand ] || return 0
  local la ta
  la=$(ch_login_age)
  if ch_due "$la" && [ -n "${UAT_AZ_RELOGIN:-}" ]; then
    log "$vm: the Azure login is $(ch_fmt_age "$la") old (REFRESH_AFTER ${ch_refresh_after}m); logging in again first"
    relogin || log "logging in again failed; going on with the old login"
  fi
  ta=$(ch_tunnel_age "$vm" "$tunnel_kind")
  ch_due "$ta" || return 0
  log "$vm: its $tunnel_kind tunnel is $(ch_fmt_age "$ta") old (REFRESH_AFTER ${ch_refresh_after}m); reopening it first"
  with_all_slots fresh_once || log "$vm: could not take its slots to reopen the tunnel; going on"
}

# run_remote <script> [timeout]: runs a script over the VM's channel, with
# the recovery above, and sets remote_out, remote_err and remote_rc.
run_remote() {
  local script=$1 secs=${2:-$call_timeout} attempt=0 rc started=$SECONDS verdict line
  remote_out="" remote_err="" remote_rc=255 remote_why=""
  while :; do
    rc=0
    run_channel "$script" "$secs" || rc=$?
    [ "$rc" -ne 0 ] || break
    if [ "$channel" = runcommand ]; then break; fi
    # A channel failure: say so with the ages and the probe, keep the
    # channel's state, then mend the tunnel when it does not answer.
    verdict=$(ch_probe "$tunnel_kind" "$tunnel_port")
    line=$(ch_error_line "$vm" "$tunnel_kind" "$tunnel_port" "$verdict" "$remote_why")
    log "$line"
    ch_capture "$vm" "$tunnel_kind" "$tunnel_port" "$line"
    if [ "${verdict%% *}" != ok ]; then
      recover_tunnel || true
      verdict=$recover_verdict
    fi
    if [ "$rc" -eq 2 ] && [ "$attempt" -lt "$connect_retries" ]; then
      attempt=$((attempt + 1))
      log "$vm: the call never started; retry $attempt of $connect_retries (tunnel: $verdict)"
      backoff $((2 * attempt))
      continue
    fi
    break
  done
  if [ "$rc" -eq 0 ]; then
    if [ "$channel" = runcommand ]; then
      log "$vm: ran over run-command in $((SECONDS - started))s"
    else
      log "$vm: ran over $channel ($tunnel_host:$tunnel_port) in $((SECONDS - started))s"
    fi
    return 0
  fi
  return 1
}

# unavailable <text>: the channel-unavailable failure, which the harness
# reports apart from a product failure.
unavailable() {
  log "CHANNEL UNAVAILABLE: $*"
  log "exit_code=255"
  exit 255
}

# refuse_if_dead: a dead VM fails at once, unless its re-probe is due: then
# its tunnel is probed (and reopened when it does not answer), and a tunnel
# that answers clears the mark.
refuse_if_dead() {
  [ "$dead_after" -gt 0 ] || return 0
  read_fails
  [ "$fail_count" -ge "$dead_after" ] || return 0
  local now last since verdict
  now=$(date +%s)
  last=$fail_epoch
  [ "$probe_epoch" -gt "$last" ] && last=$probe_epoch
  since=$((now - last))
  if [ "$since" -ge "$reprobe_seconds" ]; then
    if [ "$channel" = runcommand ]; then
      log "$vm was marked dead ${since}s ago ($fail_reason); trying once more"
      return 0
    fi
    log "$vm is marked dead ($fail_count channel failures in a row, the last $((now - fail_epoch))s ago: $fail_reason); re-probing its $tunnel_kind tunnel"
    if recover_tunnel; then
      log "$vm: its tunnel answers again ($recover_verdict); the dead mark is cleared"
      note_ok
      return 0
    fi
    verdict=$recover_verdict
    read_fails
    write_fails "$fail_count" "$fail_epoch" "$(date +%s)" "$fail_reason"
    since=0
  else
    verdict="not re-probed (last ${since}s ago)"
  fi
  log "$(ch_error_line "$vm" "${tunnel_kind:-runcommand}" "$tunnel_port" "$verdict" "marked dead")"
  unavailable "$vm is marked dead after $fail_count channel failures in a row (last $((now - fail_epoch))s ago: $fail_reason); next re-probe in $((reprobe_seconds - since))s (any session.sh refresh, a restart that comes back, or removing $fails_file, clears it)"
}

# exec_remote <script>: run_remote, print the streams and exit with the code.
exec_remote() {
  refuse_if_dead
  ensure_fresh
  if ! run_remote "$1"; then
    [ -z "$remote_out" ] || printf '%s\n' "$remote_out"
    [ -z "$remote_err" ] || printf '%s\n' "$remote_err" >&2
    note_fail "$remote_why"
    unavailable "could not run the command on $vm over $channel, or no exit code came back: $remote_why"
  fi
  note_ok
  [ -z "$remote_out" ] || printf '%s\n' "$remote_out"
  [ -z "$remote_err" ] || printf '%s\n' "$remote_err" >&2
  log "exit_code=$remote_rc"
  exit "$remote_rc"
}

# power_state: the VM's PowerState/... code, empty when Azure did not say.
power_state() {
  az_run "$probe_timeout" vm get-instance-view --ids "$vm_id" \
    --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" -o tsv 2>/dev/null || true
}

# agent_ready <since>: without a tunnel, the guest agent reporting Ready at
# or after <since> (seconds since the epoch), so a status from before the
# restart does not count. Sets guest_why when not.
agent_ready() {
  local since=$1 st ready at at_s
  st=$(az_run "$probe_timeout" vm get-instance-view --ids "$vm_id" \
    --query "instanceView.vmAgent.statuses[0].[displayStatus, time]" -o tsv 2>/dev/null || true)
  read -r ready at <<<"$(printf '%s' "$st" | tr '\n' ' ')" || true
  at_s=$(date -d "${at:-}" +%s 2>/dev/null || echo 0)
  if [ "${ready:-}" = Ready ] && [ "$at_s" -ge "$since" ]; then return 0; fi
  guest_why="guest agent '${ready:-unknown}' at '${at:-unknown}'"
  return 1
}

# guest_back: over the tunnel, its protocol probe and then a trivial
# command; a failed probe recreates the tunnel for the next poll. Sets
# guest_why when not back.
guest_back() {
  local verdict rc=0
  verdict=$(ch_probe "$tunnel_kind" "$tunnel_port")
  if [ "${verdict%% *}" != ok ]; then
    guest_why="probe: ${verdict#* }"
    log "$vm: $guest_why; recreating its tunnel"
    reopen_tunnel
    log "$vm: after the reopen: $recover_verdict"
    return 1
  fi
  remote_out="" remote_err="" remote_rc=255
  run_channel "exit 0" "$probe_timeout" || rc=$?
  if [ "$rc" -eq 0 ] && [ "$remote_rc" = 0 ]; then return 0; fi
  guest_why="the probe answers, but a command does not: $remote_why"
  return 1
}

# wait_back <since>: waits, up to VMCTL_RESTART_WAIT_SECONDS in all, until
# Azure reports the VM running and its guest answers; exits 0 when it does,
# 255 if not.
wait_back() {
  local since=$1 deadline power="" guest_why="" running=0
  deadline=$((SECONDS + restart_wait))
  while :; do
    if [ "$running" = 0 ]; then
      power=$(power_state)
      if [ "$power" = "PowerState/running" ]; then
        running=1
        log "$vm is running; waiting for its guest (over $channel)"
      else
        guest_why="Azure reports power state '${power:-unknown}'"
      fi
    fi
    if [ "$running" = 1 ]; then
      if [ "$channel" = runcommand ]; then
        agent_ready "$since" && break
      else
        guest_back && break
      fi
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      note_fail "not back ${restart_wait}s after the power operation: $guest_why"
      if [ "$running" = 0 ]; then
        log "$vm not running after ${restart_wait}s (power state '${power:-unknown}')"
      else
        log "$vm not back after ${restart_wait}s: running, but its guest does not answer over $channel (last: $guest_why)"
      fi
      exit 255
    fi
    sleep "$poll_seconds"
  done
  note_ok
  log "$vm is back"
  exit 0
}

# reboot_by_runcommand: the restart's fallback when az vm restart fails: a
# reboot a few seconds out, so run-command returns before it. The first
# line marks it (the tests' az never runs it).
reboot_by_runcommand() {
  if [ "$os" = windows ]; then
    az_run "$az_timeout" vm run-command invoke --ids "$vm_id" --command-id RunPowerShellScript -o none \
      --scripts '# imas-uat-reboot' 'shutdown.exe /r /t 10 /f /d p:4:1 /c "imas UAT restart"' >/dev/null
  else
    az_run "$az_timeout" vm run-command invoke --ids "$vm_id" --command-id RunShellScript -o none \
      --scripts '# imas-uat-reboot' 'systemd-run --on-active=10 systemctl reboot || (sleep 10; reboot) >/dev/null 2>&1 &' >/dev/null
  fi
}

case "$action" in
  run)
    exec_remote "$*"
    ;;
  stop-sprout | start-sprout)
    if [ "$kind" != sprout ]; then
      log "$action works on sprout VMs only; $vm is a hub"
      exit 2
    fi
    verb=${action%-sprout}
    if [ "$os" = windows ]; then
      if [ "$verb" = stop ]; then
        exec_remote "Stop-Service -Name '$service' -ErrorAction Stop"
      else
        exec_remote "Start-Service -Name '$service' -ErrorAction Stop"
      fi
    else
      exec_remote "systemctl $verb '$service'"
    fi
    ;;
  restart)
    log "restarting $vm"
    # A session held across the reboot would only fail later.
    ch_ssh_master_close "$vm"
    ch_winrm_pool_close "$vm"
    since=$(date +%s)
    if ! az_run "$az_timeout" vm restart --ids "$vm_id" -o none; then
      log "az vm restart failed for $vm; rebooting it through run-command instead"
      since=$(date +%s)
      if ! reboot_by_runcommand; then
        log "the run-command reboot failed for $vm too"
        exit 255
      fi
    fi
    wait_back "$since"
    ;;
  stop-vm | start-vm)
    if [ "$kind" != hub ]; then
      log "$action works on hub nodes only; $vm is a sprout"
      exit 2
    fi
    verb=${action%-vm}
    log "${verb/stop/stopp}ing $vm"
    ch_ssh_master_close "$vm"
    ch_winrm_pool_close "$vm"
    since=$(date +%s)
    if ! az_run "$az_timeout" vm "$verb" --ids "$vm_id" -o none; then
      log "az vm $verb failed for $vm"
      exit 255
    fi
    if [ "$verb" = start ]; then
      wait_back "$since"
    fi
    deadline=$((SECONDS + power_wait))
    while :; do
      power=$(power_state)
      if [ "$power" = "PowerState/stopped" ]; then
        log "$vm is stopped"
        exit 0
      fi
      if [ "$SECONDS" -ge "$deadline" ]; then
        log "$vm not stopped after ${power_wait}s (power state '${power:-unknown}')"
        exit 255
      fi
      sleep "$poll_seconds"
    done
    ;;
esac
