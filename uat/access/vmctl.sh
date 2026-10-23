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
# (tunnels.sh) has one for it: SSH (ssh_port, the admin user and sudo) on
# Linux, WinRM (winrm_port, HTTPS with NTLM, through winrm_exec.py and the
# runner's pywinrm) on Windows. Only a VM with no tunnel entry falls back to
# az vm run-command, which takes 30 to 60 s a call and runs one command per VM
# at a time (UAT Run 2, uat/RUNBOOK.md). The power operations (restart,
# stop-vm, start-vm) always go through the Azure control plane.
#
# restart       az vm restart, then waits until Azure reports the VM running
#               (up to VMCTL_POWER_WAIT_SECONDS) and then until its guest
#               answers (up to VMCTL_GUEST_WAIT_SECONDS): a command over the
#               tunnel, or, with no tunnel, the guest agent reporting Ready
#               after the restart began. Never a run-command.
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
# Every call to one VM holds that VM's lock (flock, in VMCTL_STATE_DIR), so
# two calls never overlap on a VM, across processes too. Each channel call
# has its own timeout (VMCTL_CALL_TIMEOUT) and is killed when it runs over.
# Retried, with backoff: a run-command refused with "(Conflict) Run command
# extension execution is in progress" (Azure never started it), and an SSH or
# WinRM connection that failed before the command started. Never retried: a
# command that may have run. After VMCTL_DEAD_AFTER channel failures in a row
# (exit 255: no exit code came back) the VM is marked dead, and run,
# stop-sprout and start-sprout fail at once, naming the last failure, for
# VMCTL_DEAD_SECONDS; then one call may try again. A success, or a restart or
# start-vm that comes back, clears the mark.
#
# Exit status: the command's for run, stop-sprout and start-sprout; 0 for a
# restart or start-vm that came back and a stop-vm that stopped; 2 on a usage
# error or an unknown VM; 255 when the command could not be run or gave no
# exit code (the channel failed, timed out, or the VM is marked dead).
#
# All Azure calls of the UAT gate live here and in tunnels.sh.
#
# Environment:
#   AZ                    az command (default az)
#   UAT_AZ_RELOGIN        a command (uat/access/az-relogin.sh in the gate) that
#                         logs az in again; run once, and the az call repeated,
#                         when az fails with AADSTS700024 (expired session)
#   VMCTL_ACCESS          tunnels.sh's access.json (default
#                         $UAT_SESSION_ACCESS/access.json, else
#                         <uat.json's directory>/access/access.json); a VM it
#                         does not list uses run-command
#   VMCTL_SSH_KEY         the SSH private key for the Linux tunnels
#   VMCTL_SSH_USER        the SSH user (default the VM's admin_user)
#   VMCTL_WINRM_PASSWORD_FILE  the WinRM password for the Windows tunnels
#   VMCTL_WINRM_USER      the WinRM user (default the VM's admin_user)
#                         A tunnel without its credential falls back to
#                         run-command, saying so.
#   VMCTL_STATE_DIR       locks, failure counts and SSH known hosts (default
#                         <access.json's directory>/vmctl, else
#                         ${TMPDIR:-/tmp}/imas-vmctl-<uid>)
#   VMCTL_CALL_TIMEOUT    seconds for one channel call (default 120)
#   VMCTL_AZ_TIMEOUT      seconds for one az power operation (default 600)
#   VMCTL_LOCK_WAIT_SECONDS  how long to wait for the VM's lock (default 900)
#   VMCTL_CONFLICT_RETRIES   run-command Conflict retries (default 4; 15 s,
#                         30 s, 60 s, 120 s apart)
#   VMCTL_CONNECT_RETRIES    SSH or WinRM connection retries (default 2)
#   VMCTL_DEAD_AFTER      channel failures in a row that mark the VM dead
#                         (default 3; 0 never marks)
#   VMCTL_DEAD_SECONDS    how long a dead mark holds (default 1800)
#   VMCTL_SPROUT_SERVICE  service name (default imas-sprout, as packaged)
#   VMCTL_POWER_WAIT_SECONDS  wait for the power state (restart, stop-vm,
#                         start-vm; default 300)
#   VMCTL_GUEST_WAIT_SECONDS  wait for the guest after the power state
#                         (default VMCTL_WAIT_SECONDS, else 600)
#   VMCTL_PROBE_TIMEOUT   seconds for one guest probe (default 30)
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
guest_wait=${VMCTL_GUEST_WAIT_SECONDS:-$wait_seconds}
poll_seconds=${VMCTL_POLL_SECONDS:-10}
call_timeout=${VMCTL_CALL_TIMEOUT:-120}
az_timeout=${VMCTL_AZ_TIMEOUT:-600}
probe_timeout=${VMCTL_PROBE_TIMEOUT:-30}
lock_wait=${VMCTL_LOCK_WAIT_SECONDS:-900}
conflict_retries=${VMCTL_CONFLICT_RETRIES:-4}
connect_retries=${VMCTL_CONNECT_RETRIES:-2}
dead_after=${VMCTL_DEAD_AFTER:-3}
dead_seconds=${VMCTL_DEAD_SECONDS:-1800}
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
for n in "$wait_seconds" "$power_wait" "$guest_wait" "$poll_seconds" "$call_timeout" "$az_timeout" "$probe_timeout" \
  "$lock_wait" "$conflict_retries" "$connect_retries" "$dead_after" "$dead_seconds" "$backoff_scale"; do
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
tunnel_host=""
tunnel_port=""
if [ -r "$access" ]; then
  port_key=ssh_port
  [ "$os" = windows ] && port_key=winrm_port
  if ! read -r tunnel_host tunnel_port < <(jq -r --arg vm "$vm" --arg k "$port_key" \
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

# State: one lock, one failure count and one known hosts file per VM.
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

lock_start=$SECONDS
exec 9>>"$state_dir/$vm.lock"
if ! flock -w "$lock_wait" 9; then
  log "another vmctl.sh call held the lock of $vm for ${lock_wait}s; giving up"
  log "exit_code=255"
  exit 255
fi
if [ $((SECONDS - lock_start)) -ge 5 ]; then
  log "waited $((SECONDS - lock_start))s for another call on $vm to finish"
fi

# fail_count, fail_epoch and fail_reason: the VM's consecutive channel
# failures, when the last was, and what it was.
read_fails() {
  fail_count=0 fail_epoch=0 fail_reason=""
  if [ -f "$fails_file" ]; then
    { read -r fail_count fail_epoch && IFS= read -r fail_reason; } <"$fails_file" || true
    [[ "$fail_count" =~ ^[0-9]+$ ]] || fail_count=0
    [[ "$fail_epoch" =~ ^[0-9]+$ ]] || fail_epoch=0
  fi
}
note_ok() { rm -f "$fails_file"; }
note_fail() {
  read_fails
  printf '%s %s\n%s\n' "$((fail_count + 1))" "$(date +%s)" "$1" >"$fails_file.tmp"
  mv "$fails_file.tmp" "$fails_file"
  if [ "$dead_after" -gt 0 ] && [ $((fail_count + 1)) -ge "$dead_after" ]; then
    log "$vm is now marked dead: $((fail_count + 1)) channel failures in a row (last: $1)"
  fi
}
# refuse_if_dead: exits 255 at once when the VM is marked dead.
refuse_if_dead() {
  [ "$dead_after" -gt 0 ] || return 0
  read_fails
  [ "$fail_count" -ge "$dead_after" ] || return 0
  local age=$(($(date +%s) - fail_epoch))
  if [ "$age" -lt "$dead_seconds" ]; then
    log "$vm is marked dead after $fail_count channel failures in a row (last ${age}s ago: $fail_reason); not trying again for $((dead_seconds - age))s (a restart that comes back, or removing $fails_file, clears it)"
    log "exit_code=255"
    exit 255
  fi
  log "$vm was marked dead ${age}s ago ($fail_reason); trying once more"
}

# backoff <seconds>: sleeps seconds times VMCTL_BACKOFF_SCALE.
backoff() { sleep $(($1 * backoff_scale)); }

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
    if "$UAT_AZ_RELOGIN" >&2; then
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

# An SSH error before the command started: the tunnel or sshd refused.
ssh_preexec_re='kex_exchange_identification|ssh_exchange_identification|Connection refused|banner exchange|Connection closed by [0-9]|Connection reset by [0-9]'

run_ssh() {
  local script=$1 secs=$2 errf rc=0
  errf=$(mktemp)
  # The script goes on stdin into a file, then runs as root with stdin
  # /dev/null (as through run-command); the marker comes from the login
  # shell after it.
  # shellcheck disable=SC2016 # expanded on the VM
  remote_out=$(printf '%s' "$script" | timeout --foreground -k 5 "$secs" ssh -p "$tunnel_port" -i "$VMCTL_SSH_KEY" \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$state_dir/known_hosts" -o HostKeyAlias="$vm" \
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
  remote_why="ssh to $vm ($tunnel_host:$tunnel_port) exited $rc with no exit code: $(printf '%s' "$remote_err" | grep -v '^[[:space:]]*$' | tail -n 1)"
  if [ "$rc" -eq 255 ] && printf '%s' "$remote_err" | grep -Eq "$ssh_preexec_re"; then return 2; fi
  return 1
}

run_winrm() {
  local script=$1 secs=$2 errf b64 rc=0
  errf=$(mktemp)
  b64=$(printf '%s' "$script" | base64 | tr -d '\n')
  remote_out=$(ps_wrapper "$b64" | timeout --foreground -k 5 "$secs" python3 "$here/winrm_exec.py" \
    --host "$tunnel_host" --port "$tunnel_port" --user "$winrm_user" \
    --password-file "$VMCTL_WINRM_PASSWORD_FILE" 2>"$errf") || rc=$?
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

# run_remote <script> [timeout]: runs a script over the VM's channel, with
# the retries above, and sets remote_out, remote_err and remote_rc.
run_remote() {
  local script=$1 secs=${2:-$call_timeout} attempt=0 rc started=$SECONDS
  remote_out="" remote_err="" remote_rc=255 remote_why=""
  while :; do
    rc=0
    case $channel in
      ssh) run_ssh "$script" "$secs" || rc=$? ;;
      winrm) run_winrm "$script" "$secs" || rc=$? ;;
      *) run_runcommand "$script" "$secs" || rc=$? ;;
    esac
    if [ "$rc" -eq 2 ] && [ "$attempt" -lt "$connect_retries" ]; then
      attempt=$((attempt + 1))
      log "$vm: $remote_why; retry $attempt of $connect_retries"
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

# exec_remote <script>: run_remote, print the streams and exit with the code.
exec_remote() {
  refuse_if_dead
  if ! run_remote "$1"; then
    [ -z "$remote_out" ] || printf '%s\n' "$remote_out"
    [ -z "$remote_err" ] || printf '%s\n' "$remote_err" >&2
    note_fail "$remote_why"
    log "could not run the command on $vm over $channel, or no exit code came back: $remote_why"
    log "exit_code=255"
    exit 255
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

# guest_back <since>: does the guest answer? Over the tunnel a trivial
# command; without one, the guest agent reporting Ready at or after <since>
# (seconds since the epoch), so a status from before the restart does not
# count. Sets guest_why when not.
guest_back() {
  local since=$1 st ready at at_s
  if [ "$channel" != runcommand ]; then
    local probe="exit 0"
    if run_remote "$probe" "$probe_timeout" && [ "$remote_rc" = 0 ]; then return 0; fi
    guest_why=$remote_why
    return 1
  fi
  st=$(az_run "$probe_timeout" vm get-instance-view --ids "$vm_id" \
    --query "instanceView.vmAgent.statuses[0].[displayStatus, time]" -o tsv 2>/dev/null || true)
  read -r ready at <<<"$(printf '%s' "$st" | tr '\n' ' ')" || true
  at_s=$(date -d "${at:-}" +%s 2>/dev/null || echo 0)
  if [ "${ready:-}" = Ready ] && [ "$at_s" -ge "$since" ]; then return 0; fi
  guest_why="guest agent '${ready:-unknown}' at '${at:-unknown}'"
  return 1
}

# wait_back <since>: waits until Azure reports the VM running (up to
# VMCTL_POWER_WAIT_SECONDS), then until the guest answers (up to
# VMCTL_GUEST_WAIT_SECONDS); exits 0 when it does, 255 if not.
wait_back() {
  local since=$1 deadline power guest_why=""
  deadline=$((SECONDS + power_wait))
  while :; do
    power=$(power_state)
    [ "$power" = "PowerState/running" ] && break
    if [ "$SECONDS" -ge "$deadline" ]; then
      note_fail "not running ${power_wait}s after the power operation"
      log "$vm not running after ${power_wait}s (power state '${power:-unknown}')"
      exit 255
    fi
    sleep "$poll_seconds"
  done
  log "$vm is running; waiting for its guest (over $channel)"
  deadline=$((SECONDS + guest_wait))
  while :; do
    if guest_back "$since"; then
      note_ok
      log "$vm is back"
      exit 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      note_fail "guest not back ${guest_wait}s after the VM ran: $guest_why"
      log "$vm not back after ${guest_wait}s: running, but its guest does not answer over $channel (last: $guest_why)"
      exit 255
    fi
    sleep "$poll_seconds"
  done
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
    since=$(date +%s)
    if ! az_run "$az_timeout" vm restart --ids "$vm_id" -o none; then
      log "az vm restart failed for $vm"
      exit 255
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
