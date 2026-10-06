#!/usr/bin/env bash
# vmctl.sh: control a UAT VM through the Azure control plane (UAT.1, Access
# interface of the Shared contract in section 4h of
# docs/claude-code-parallel-build-plan.md). No network path to the VM is used.
#
#   vmctl.sh <uat.json> restart      <vm>
#   vmctl.sh <uat.json> stop-sprout  <vm>
#   vmctl.sh <uat.json> start-sprout <vm>
#   vmctl.sh <uat.json> run          <vm> <command...>
#
# <vm> is a VM name from uat.json: uat-dmz, uat-core or a key of sprouts.
#
# restart       az vm restart, then waits until the VM runs and its guest agent
#               answers a run-command (the guest is back), up to
#               VMCTL_WAIT_SECONDS.
# stop-sprout   stops the sprout service (systemd unit or Windows service
# start-sprout  imas-sprout) on a sprout VM; refused for the hubs.
# run           runs <command...> (joined with spaces) with az vm run-command:
#               bash on Linux, PowerShell on Windows, as root or SYSTEM.
#               Prints the command's stdout on stdout and its stderr on stderr,
#               then "vmctl: exit_code=N" on stderr, and exits N. On Windows, N
#               is $LASTEXITCODE of the last native command, or 1 when the
#               script failed with an error, else 0. Azure keeps only the last
#               4096 bytes of each stream.
#
# Exit status: the command's for run, stop-sprout and start-sprout; 0 for a
# restart that came back; 2 on a usage error or an unknown VM; 255 when Azure
# could not run the command or gave no exit code.
#
# All Azure calls of the UAT gate live here and in tunnels.sh.
#
# Environment:
#   AZ                    az command (default az)
#   VMCTL_SPROUT_SERVICE  service name (default imas-sprout, as packaged)
#   VMCTL_WAIT_SECONDS    restart wait (default 600)
#   VMCTL_POLL_SECONDS    restart poll interval (default 10)
set -euo pipefail

prog=$(basename "$0")
AZ=${AZ:-az}
service=${VMCTL_SPROUT_SERVICE:-imas-sprout}
wait_seconds=${VMCTL_WAIT_SECONDS:-600}
poll_seconds=${VMCTL_POLL_SECONDS:-10}
marker="__IMAS_VMCTL_RC__"

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
  *) log "unknown action '$action'"; usage ;;
esac
[[ "$service" =~ ^[A-Za-z0-9._@-]+$ ]] || { log "VMCTL_SPROUT_SERVICE has unexpected characters"; exit 2; }
[ -r "$uat" ] || { log "cannot read $uat"; exit 2; }
command -v jq >/dev/null 2>&1 || { log "jq is not on PATH"; exit 2; }
command -v "$AZ" >/dev/null 2>&1 || { log "$AZ is not on PATH"; exit 2; }

# Look the VM up: kind (hub or sprout), resource id and OS.
lookup=$(jq -r --arg vm "$vm" '
  if .dmz.name == $vm then ["hub", .dmz.id, "ubuntu"]
  elif .core.name == $vm then ["hub", .core.id, "ubuntu"]
  elif (.sprouts // {}) | has($vm) then ["sprout", .sprouts[$vm].id, .sprouts[$vm].os]
  else empty end
  | @tsv' "$uat") || { log "$uat is not valid JSON"; exit 2; }
[ -n "$lookup" ] || { log "no VM named '$vm' in $uat"; exit 2; }
IFS=$'\t' read -r kind vm_id os <<<"$lookup"
[ -n "$vm_id" ] || { log "VM '$vm' has no id in $uat"; exit 2; }

# run_remote <script>: runs a script through run-command and sets
# remote_out, remote_err and remote_rc. Returns 1 when Azure gave no exit code.
run_remote() {
  local script=$1 b64 json
  b64=$(printf '%s' "$script" | base64 | tr -d '\n')
  remote_out=""
  remote_err=""
  remote_rc=255
  if [ "$os" = windows ]; then
    json=$("$AZ" vm run-command invoke --ids "$vm_id" --command-id RunPowerShellScript -o json --scripts \
      "\$__c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64'))" \
      "\$global:LASTEXITCODE = 0; \$__ok = \$true" \
      "try { & ([ScriptBlock]::Create(\$__c)); \$__ok = \$? } catch { Write-Error \$_; \$__ok = \$false }" \
      "if (\$LASTEXITCODE -ne 0) { \$__rc = \$LASTEXITCODE } elseif (-not \$__ok) { \$__rc = 1 } else { \$__rc = 0 }" \
      "Write-Output \"$marker\$__rc\"") || return 1
    remote_out=$(printf '%s' "$json" | jq -r '[.value[]? | select(.code | test("StdOut"))][0].message // ""' | tr -d '\r')
    remote_err=$(printf '%s' "$json" | jq -r '[.value[]? | select(.code | test("StdErr"))][0].message // ""' | tr -d '\r')
  else
    json=$("$AZ" vm run-command invoke --ids "$vm_id" --command-id RunShellScript -o json --scripts \
      "__imas_cmd=\$(printf '%s' '$b64' | base64 -d)" \
      "bash -c \"\$__imas_cmd\" </dev/null" \
      "echo \"$marker\$?\"") || return 1
    # Linux run-command returns one message: "...[stdout]\n<out>\n[stderr]\n<err>".
    local msg
    msg=$(printf '%s' "$json" | jq -r '.value[0].message // ""')
    remote_out=$(printf '%s\n' "$msg" | awk '/^\[stdout\]$/{f=1;next} /^\[stderr\]$/{f=0} f')
    remote_err=$(printf '%s\n' "$msg" | awk '/^\[stderr\]$/{f=1;next} f')
  fi
  local rc_line
  rc_line=$(printf '%s\n' "$remote_out" | grep -E "^${marker}[0-9]+\$" | tail -n 1 || true)
  remote_out=$(printf '%s\n' "$remote_out" | grep -vE "^${marker}[0-9]+\$" || true)
  [ -n "$rc_line" ] || return 1
  remote_rc=${rc_line#"$marker"}
  return 0
}

# exec_remote <script>: run_remote, print the streams and exit with the code.
exec_remote() {
  if ! run_remote "$1"; then
    [ -z "$remote_out" ] || printf '%s\n' "$remote_out"
    [ -z "$remote_err" ] || printf '%s\n' "$remote_err" >&2
    log "Azure did not run the command on $vm or gave no exit code (output truncated?)"
    log "exit_code=255"
    exit 255
  fi
  [ -z "$remote_out" ] || printf '%s\n' "$remote_out"
  [ -z "$remote_err" ] || printf '%s\n' "$remote_err" >&2
  log "exit_code=$remote_rc"
  exit "$remote_rc"
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
    if ! "$AZ" vm restart --ids "$vm_id" -o none; then
      log "az vm restart failed for $vm"
      exit 255
    fi
    deadline=$((SECONDS + wait_seconds))
    probe="exit 0"
    while :; do
      power=$("$AZ" vm get-instance-view --ids "$vm_id" \
        --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" -o tsv 2>/dev/null || true)
      if [ "$power" = "PowerState/running" ] && run_remote "$probe" && [ "$remote_rc" = 0 ]; then
        log "$vm is back"
        exit 0
      fi
      if [ "$SECONDS" -ge "$deadline" ]; then
        log "$vm not back after ${wait_seconds}s (power state '${power:-unknown}')"
        exit 255
      fi
      sleep "$poll_seconds"
    done
    ;;
esac
