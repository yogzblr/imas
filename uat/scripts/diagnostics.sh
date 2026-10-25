#!/usr/bin/env bash
# diagnostics.sh: collect what explains a failed UAT test, before the run's
# environment is gone (W8; uat/RUNBOOK.md, "The test channel").
#
#   diagnostics.sh kube <out-dir>     the hubs only (uat/tests/run.sh, after
#                                     each failed top-level test)
#   diagnostics.sh full <out-dir>     the hubs, the sprouts' service logs and
#                                     Azure's run-command state (the
#                                     workflow, after a failed test step)
#   diagnostics.sh vm <out-dir> <vm> [<job id>...]
#                                     one VM's side of a failure (the
#                                     harness, after a failed cook or a
#                                     channel failure on it; W10)
#
# For each hub (core and dmz, through their kubeconfigs and so through the
# Bastion kube tunnels), into <out-dir>/<hub>/:
#   nodes.txt, pods.txt (get -o wide), jobs.txt, events.txt (all namespaces,
#   by time), top.txt (top nodes and pods), endpoints.txt (get endpoints -A,
#   and the RustFS ones in full), and pods/<ns>.<pod>.txt with describe,
#   logs and logs --previous of: every RustFS pod, every pod of a failed or
#   unfinished Job, and every pod that is not Running or Succeeded, has a
#   container not ready, or restarted (at most DIAG_MAX_PODS per hub);
#   keycloak/<ns>.<pod>.txt for every Keycloak pod, healthy or not: its
#   login-error, brute-force and lockout lines from the whole log (a token
#   refused as user_temporarily_disabled is explained there), then the last
#   DIAG_KEYCLOAK_LINES lines and logs --previous.
# full also writes:
#   sprouts/<vm>.txt   the sprout service's state and last log lines, through
#                      vmctl.sh run: journalctl -u imas-sprout on Linux,
#                      %ProgramData%\imas\logs\sprout.log (and
#                      sprout-crash.log) on Windows
#   azure/<vm>.json    per VM: az vm run-command list, and the instance
#                      view's power state, guest agent and run-command
#                      extension status ("execution is in progress" shows
#                      there)
# vm writes <out-dir>/<epoch>.txt (the harness passes
# <report>/diagnostics/<vm>), read through az vm run-command and never the
# test channel (vmctl.sh with VMCTL_CHANNEL=runcommand), so it works when
# the tunnel is what failed: the sprout service's state, every log line of
# each job id (W11: from the whole log, however far back), the last
# DIAG_VM_LOG_LINES (300) lines of its log (journalctl -u imas-sprout on
# Linux, %ProgramData%\imas\logs\sprout.log and the end of
# sprout-crash.log on Windows) and each job id's record (the sprout's
# <joblogdir>/<id>.jsonl: /var/cache/imas/sprout/jobs on Linux,
# %ProgramData%\imas\cache\sprout\jobs on Windows). When the sprout
# restarted without a reboot (a second startup line, "registered sdb
# backend awssm", since the boot; on Linux also systemd's NRestarts) or a job is
# lost (no record, or no completion in it), or DIAG_VM_EVENTS=1, it also
# takes what killed the process (W11: UAT Run 2's win_shortcut cook): on
# Windows the Application log's Application Error, Windows Error Reporting
# and .NET Runtime events (faulting module, exception code), the System
# log's Service Control Manager 7031, 7034, 7023 and 7024 events since the
# boot (at most 3 hours back) and `sc.exe qfailure imas-sprout`; on Linux
# coredumpctl's list, the kernel's OOM kills and the unit's exit lines. Azure keeps only the
# last 4096 bytes of a run-command's output, so the VM packs it all
# (gzip, base64) into a file and hands it over in pieces, one call each, at
# most DIAG_VM_CHUNKS (6) of them; when it does not fit, it is made again
# with fewer log lines.
#
# Every command is bounded (DIAG_TIMEOUT seconds; kubectl
# --request-timeout too), a failure is written into the file it was for,
# and the script always exits 0: it is a diagnostic, never a gate. Each
# file is filtered on the way out (redact): values of keys that look like a
# password, secret, token, access or secret key or credential, Bearer and
# Basic Authorization credentials, JWTs, NKey
# seeds and private key blocks are replaced by [redacted]. collect-artifacts.sh
# scans the result again before anything is uploaded.
#
# Environment:
#   DIAG_KUBECONFIGS   name=path pairs, colon separated (default
#                      core=$IMAS_UAT_CORE_KUBECONFIG:dmz=$IMAS_UAT_DMZ_KUBECONFIG,
#                      the ones set)
#   DIAG_UAT           uat.json, for full (default $UAT_SESSION_UAT)
#   DIAG_VMCTL         vmctl.sh, for full (default uat/access/vmctl.sh)
#   DIAG_TIMEOUT       seconds per command (default 60)
#   DIAG_MAX_PODS      pods described per hub (default 25)
#   DIAG_KEYCLOAK_LINES  Keycloak log lines kept per section (default 2000)
#   DIAG_SPROUT_SERVICE  the sprout service (default imas-sprout)
#   DIAG_VM_LOG_LINES  sprout log lines for vm (default 300)
#   DIAG_VM_CHUNKS     run-command calls for vm's pieces (default 6)
#   DIAG_VM_EVENTS     1: take the event logs (vm) even when the sprout did
#                      not restart and no job is lost (default 0)
#   DIAG_VM_JOBDIR     the Linux sprout's joblogdir (default
#                      /var/cache/imas/sprout/jobs, as packaged)
#   KUBECTL, AZ        the tools (default kubectl, az)
set -uo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KUBECTL=${KUBECTL:-kubectl}
AZ=${AZ:-az}
secs=${DIAG_TIMEOUT:-60}
max_pods=${DIAG_MAX_PODS:-25}
service=${DIAG_SPROUT_SERVICE:-imas-sprout}
kc_lines=${DIAG_KEYCLOAK_LINES:-2000}

usage() {
  echo "usage: $prog kube|full <out-dir>" >&2
  echo "       $prog vm <out-dir> <vm> [<job id>...]" >&2
  exit 2
}
log() { echo "$prog: $*" >&2; }

[ $# -ge 2 ] || usage
mode=$1 out=$2
case "$mode" in
  kube | full) [ $# -eq 2 ] || usage ;;
  vm) [ $# -ge 3 ] || usage ;;
  *) usage ;;
esac
[[ "$secs" =~ ^[1-9][0-9]*$ && "$max_pods" =~ ^[0-9]+$ && "$kc_lines" =~ ^[1-9][0-9]*$ ]] || { log "DIAG_TIMEOUT, DIAG_MAX_PODS and DIAG_KEYCLOAK_LINES must be numbers"; exit 2; }
[[ "$service" =~ ^[A-Za-z0-9._@-]+$ ]] || { log "DIAG_SPROUT_SERVICE has unexpected characters"; exit 2; }
mkdir -p "$out"

# redact: stdin to stdout with anything secret-shaped replaced (shared
# with collect-artifacts.sh, run.sh and the channel's captures).
# shellcheck source=redact.sh
. "$here/redact.sh"

# section FILE TITLE CMD...: appends "== TITLE" and the bounded command's
# output (redacted) to FILE; a failure is noted there, not fatal.
section() {
  local file=$1 title=$2 rc=0 tmp
  shift 2
  tmp=$(mktemp)
  timeout -k 5 "$secs" "$@" >"$tmp" 2>&1 || rc=$?
  {
    echo "== $title"
    redact <"$tmp"
    if [ "$rc" -eq 124 ]; then
      echo "(timed out after ${secs}s)"
    elif [ "$rc" -ne 0 ]; then
      echo "(exited $rc)"
    fi
    echo
  } >>"$file"
  rm -f "$tmp"
}

# vm_bundle_linux <lines> <limit> <file> <job id>...: the Linux script that
# packs the sprout's state, log and job records into <file> (gzip, base64),
# with fewer log lines until it fits <limit> characters, and prints its size.
vm_bundle_linux() {
  local lines=$1 limit=$2 file=$3 jobs="" jobdir=${DIAG_VM_JOBDIR:-/var/cache/imas/sprout/jobs}
  shift 3
  [ $# -eq 0 ] || jobs=$(printf "'%s' " "$@")
  cat <<EOF
# W11: did the sprout restart since boot (systemd's NRestarts, or more
# than one start in this boot's journal), or is a job lost (no record, or
# no completion in it)? Then what killed it: core dumps and OOM kills.
starts=\$(journalctl -b -u '$service' --no-pager -o cat 2>/dev/null | grep -c 'registered sdb backend awssm')
restarts=\$(systemctl show -p NRestarts --value '$service' 2>/dev/null)
lost=0
for j in $jobs; do grep -qs '"ID":"completed-' "$jobdir/\$j.jsonl" || lost=1; done
for n in $lines 150 60 20; do
  {
    echo "== the sprout service"; systemctl status '$service' --no-pager -l 2>&1 | head -n 20
    echo "== sprout starts in this boot's journal: \${starts:-0}; systemd NRestarts: \${restarts:-unknown}; a job lost: \$lost"
    for j in $jobs; do
      echo "== journalctl -u $service: every line of job \$j"
      journalctl -u '$service' --no-pager -o short-iso 2>&1 | grep -F -- "\$j" | tail -n 100
    done
    echo "== journalctl -u $service (last \$n lines)"; journalctl -u '$service' --no-pager -n "\$n" -o short-iso 2>&1
    for j in $jobs; do
      echo "== job \$j ($jobdir/\$j.jsonl)"
      cat "$jobdir/\$j.jsonl" 2>&1 || echo "(no record)"
    done
    if [ "\${starts:-0}" -gt 1 ] || [ "\${restarts:-0}" != 0 ] || [ "\$lost" = 1 ] || [ '${DIAG_VM_EVENTS:-0}' = 1 ]; then
      echo "== the sprout restarted or a job was lost: core dumps and OOM kills"
      coredumpctl list --no-pager 2>&1 | tail -n 10
      journalctl -k -b --no-pager -o short-iso 2>/dev/null | grep -Ei 'out of memory|oom-kill|killed process' | tail -n 20
      journalctl -b --no-pager -o short-iso -u '$service' 2>/dev/null | grep -Ei 'main process exited|dumped core|failed with result|scheduled restart' | tail -n 20
    fi
  } | gzip -9 | base64 -w0 >'$file'
  [ "\$(wc -c <'$file')" -le $limit ] && break
done
echo "__IMAS_DIAG_SIZE=\$(wc -c <'$file')"
EOF
}

# vm_bundle_windows: the same in PowerShell.
vm_bundle_windows() {
  local lines=$1 limit=$2 file=$3 jobs="" j
  shift 3
  for j in "$@"; do jobs="$jobs'$j',"; done
  jobs=${jobs%,}
  cat <<EOF
\$f = Join-Path \$env:TEMP '$file'
\$d = Join-Path \$env:ProgramData 'imas\\logs'
\$log = Join-Path \$d 'sprout.log'
# W11: a sprout that restarted without a reboot (more than one startup
# line, "registered sdb backend awssm" (one per start), after the boot) or a lost job (no record,
# or no completion in it): what killed it, from the event logs.
\$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
\$starts = 0
if (Test-Path -LiteralPath \$log) {
  foreach (\$m in (Select-String -LiteralPath \$log -Pattern 'registered sdb backend awssm' -SimpleMatch)) {
    \$t = \$null
    if (\$m.Line -match '^(\\d{4}[/-]\\d{2}[/-]\\d{2}[ T]\\d{2}:\\d{2}:\\d{2})') { try { \$t = [datetime]::Parse((\$Matches[1] -replace '/', '-')) } catch { } }
    if (-not \$t -or \$t -ge \$boot) { \$starts++ }
  }
}
\$lost = \$false
foreach (\$j in @($jobs)) {
  \$p = Join-Path \$env:ProgramData "imas\\cache\\sprout\\jobs\\\$j.jsonl"
  if (-not (Test-Path -LiteralPath \$p) -or -not (Select-String -LiteralPath \$p -Pattern '"ID":"completed-' -SimpleMatch -Quiet)) { \$lost = \$true }
}
\$ev = New-Object Text.StringBuilder
[void]\$ev.AppendLine("== sprout starts since the boot at \$(\$boot.ToUniversalTime().ToString('o')): \$starts; a job lost: \$lost")
if (\$starts -gt 1 -or \$lost -or '${DIAG_VM_EVENTS:-0}' -eq '1') {
  \$since = (Get-Date).AddHours(-3)
  if (\$boot -gt \$since) { \$since = \$boot }
  \$short = { param(\$e) "\$(\$e.TimeCreated.ToUniversalTime().ToString('o')) \$(\$e.ProviderName) \$(\$e.Id): " + ((\$e.Message -replace '\\s+', ' ') -replace '^(.{600}).*', '\$1...') }
  [void]\$ev.AppendLine('== Application log: Application Error, Windows Error Reporting, .NET Runtime (faulting module, exception code)')
  Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error', 'Windows Error Reporting', '.NET Runtime'; StartTime = \$since } -MaxEvents 12 -ErrorAction SilentlyContinue | ForEach-Object { [void]\$ev.AppendLine((& \$short \$_)) }
  [void]\$ev.AppendLine('== System log: Service Control Manager 7031, 7034, 7023, 7024 (a service ended unexpectedly)')
  Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034, 7023, 7024; StartTime = \$since } -MaxEvents 12 -ErrorAction SilentlyContinue | ForEach-Object { [void]\$ev.AppendLine((& \$short \$_)) }
  [void]\$ev.AppendLine('== sc.exe qfailure $service')
  [void]\$ev.AppendLine((sc.exe qfailure '$service' | Out-String))
}
foreach (\$n in @($lines, 150, 60, 20)) {
  \$sb = New-Object Text.StringBuilder
  [void]\$sb.AppendLine('== the sprout service')
  [void]\$sb.AppendLine((Get-Service -Name '$service' -ErrorAction SilentlyContinue | Format-List Name, Status, StartType | Out-String))
  [void]\$sb.Append(\$ev.ToString())
  foreach (\$j in @($jobs)) {
    [void]\$sb.AppendLine("== \$log: every line of job \$j")
    if (Test-Path -LiteralPath \$log) { Select-String -LiteralPath \$log -Pattern \$j -SimpleMatch | Select-Object -Last 100 | ForEach-Object { [void]\$sb.AppendLine(\$_.Line) } }
  }
  foreach (\$p in @(@((Join-Path \$d 'sprout.log'), \$n), @((Join-Path \$d 'sprout-crash.log'), 50))) {
    if (Test-Path -LiteralPath \$p[0]) {
      [void]\$sb.AppendLine("== \$(\$p[0]) (last \$(\$p[1]) lines)")
      Get-Content -LiteralPath \$p[0] -Tail \$p[1] | ForEach-Object { [void]\$sb.AppendLine(\$_) }
    } else { [void]\$sb.AppendLine("== \$(\$p[0]): none") }
  }
  foreach (\$j in @($jobs)) {
    \$p = Join-Path \$env:ProgramData "imas\\cache\\sprout\\jobs\\\$j.jsonl"
    [void]\$sb.AppendLine("== job \$j (\$p)")
    if (Test-Path -LiteralPath \$p) { [void]\$sb.AppendLine((Get-Content -LiteralPath \$p -Raw)) } else { [void]\$sb.AppendLine('(no record)') }
  }
  \$bytes = [Text.Encoding]::UTF8.GetBytes(\$sb.ToString())
  \$ms = New-Object IO.MemoryStream
  \$gz = New-Object IO.Compression.GzipStream(\$ms, [IO.Compression.CompressionMode]::Compress)
  \$gz.Write(\$bytes, 0, \$bytes.Length)
  \$gz.Close()
  \$b64 = [Convert]::ToBase64String(\$ms.ToArray())
  if (\$b64.Length -le $limit) { break }
}
[IO.File]::WriteAllText(\$f, \$b64)
Write-Output ('__IMAS_DIAG_SIZE=' + \$b64.Length)
EOF
}

# vm_chunk <os> <file> <start> <length> <last>: prints one piece of the
# bundle; the last call removes it.
vm_chunk() {
  local os=$1 file=$2 start=$3 len=$4 last=$5
  if [ "$os" = windows ]; then
    cat <<EOF
\$f = Join-Path \$env:TEMP '$file'
\$s = [IO.File]::ReadAllText(\$f)
\$n = [Math]::Max(0, [Math]::Min($len, \$s.Length - $start))
Write-Output ('__IMAS_DIAG_CHUNK=' + \$s.Substring([Math]::Min($start, \$s.Length), \$n))
if ($last) { Remove-Item -Force -LiteralPath \$f -ErrorAction SilentlyContinue }
EOF
  else
    printf '%s\n' "printf '__IMAS_DIAG_CHUNK=%s\\n' \"\$(cut -c$((start + 1))-$((start + len)) '$file')\""
    [ "$last" = 1 ] && echo "rm -f '$file'"
  fi
  return 0
}

# vm_mode <out-dir> <vm> <job id>...: see the header.
vm_mode() {
  local dir=$1 vm=$2 uat vmctl os j f stamp size chunk=3000 max lines i n data part rc=0
  shift 2
  uat=${DIAG_UAT:-${UAT_SESSION_UAT:-}}
  vmctl=${DIAG_VMCTL:-$here/../access/vmctl.sh}
  lines=${DIAG_VM_LOG_LINES:-300}
  max=${DIAG_VM_CHUNKS:-6}
  [[ "$lines" =~ ^[1-9][0-9]*$ && "$max" =~ ^[1-9][0-9]*$ ]] || { log "DIAG_VM_LOG_LINES and DIAG_VM_CHUNKS must be numbers"; exit 2; }
  [[ "$vm" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { log "bad VM name"; exit 2; }
  local -a jids=()
  for j in "$@"; do
    if [[ "$j" =~ ^[A-Za-z0-9_.:-]{1,128}$ ]]; then jids+=("$j"); else log "skipping a malformed job id"; fi
  done
  if [ -z "$uat" ] || [ ! -r "$uat" ]; then
    log "no uat.json (DIAG_UAT, UAT_SESSION_UAT); no VM diagnostics"
    exit 0
  fi
  os=$(jq -r --arg vm "$vm" '.sprouts[$vm].os // "ubuntu"' "$uat")
  mkdir -p "$dir"
  stamp=$(date +%s)
  f="$dir/$stamp.txt"
  local file="imas-diag-$stamp-$RANDOM.b64" script
  [ "$os" = windows ] || file="/tmp/$file"
  local tmp
  tmp=$(mktemp -d)
  # Through run-command, not the tunnel: VMCTL_CHANNEL=runcommand.
  run_vm() { VMCTL_CHANNEL=runcommand timeout -k 10 "$((secs * 4))" "$vmctl" "$uat" run "$vm" "$1" >"$tmp/out" 2>"$tmp/err"; }
  if [ "$os" = windows ]; then
    script=$(vm_bundle_windows "$lines" $((chunk * max)) "$file" "${jids[@]}")
  else
    script=$(vm_bundle_linux "$lines" $((chunk * max)) "$file" "${jids[@]}")
  fi
  run_vm "$script" || rc=$?
  size=$(sed -n 's/^__IMAS_DIAG_SIZE=\([0-9][0-9]*\).*/\1/p' "$tmp/out" | tail -n 1)
  {
    echo "== $vm, through az vm run-command (not the test channel), at $(date -u -d "@$stamp" +%Y-%m-%dT%H:%M:%SZ); jobs: ${jids[*]:-none}"
    if [ -z "$size" ]; then
      echo "(the VM did not pack its diagnostics: vmctl.sh exited $rc)"
      redact <"$tmp/err" | tail -n 20
    else
      n=$(((size + chunk - 1) / chunk))
      [ "$n" -le "$max" ] || n=$max
      data=""
      for ((i = 0; i < n; i++)); do
        run_vm "$(vm_chunk "$os" "$file" $((i * chunk)) "$chunk" "$([ $((i + 1)) -eq "$n" ] && echo 1 || echo 0)")" || true
        part=$(sed -n 's/^__IMAS_DIAG_CHUNK=//p' "$tmp/out" | tr -d '\r\n' | tail -c "$chunk")
        data+=$part
      done
      if ! printf '%s' "$data" | base64 -d 2>/dev/null | gunzip 2>/dev/null | redact; then
        echo "(the pieces did not unpack: $size characters packed, ${#data} received)"
      fi
    fi
  } >"$f"
  rm -rf "$tmp"
  log "$vm: $f"
}

if [ "$mode" = vm ]; then
  shift 2
  vm_mode "$out" "$@"
  exit 0
fi

kubeconfigs=${DIAG_KUBECONFIGS:-}
if [ -z "$kubeconfigs" ]; then
  [ -z "${IMAS_UAT_CORE_KUBECONFIG:-}" ] || kubeconfigs=core=$IMAS_UAT_CORE_KUBECONFIG
  [ -z "${IMAS_UAT_DMZ_KUBECONFIG:-}" ] || kubeconfigs=${kubeconfigs:+$kubeconfigs:}dmz=$IMAS_UAT_DMZ_KUBECONFIG
fi

# The pods worth describing, as "<namespace> <pod>" lines: RustFS pods, pods
# of failed or unfinished Jobs, and unhealthy pods.
pick_pods() {
  local pods=$1 jobs=$2
  {
    jq -r '.items[] | select(.metadata.name | test("rustfs")) | "\(.metadata.namespace) \(.metadata.name)"' "$pods"
    jq -r --slurpfile jobs "$jobs" '
      ([ $jobs[0].items[]
         | select((.status.failed // 0) > 0 or ((.status.succeeded // 0) == 0 and (.status.completionTime == null)))
         | "\(.metadata.namespace)/\(.metadata.name)" ]) as $bad
      | .items[]
      | select("\(.metadata.namespace)/\(.metadata.labels["job-name"] // "")" as $key | $bad | index($key))
      | "\(.metadata.namespace) \(.metadata.name)"' "$pods"
    jq -r '.items[]
      | select(.status.phase != "Succeeded")
      | select(.status.phase != "Running"
          or ([.status.containerStatuses[]? | select(.ready | not)] | length) > 0
          or ([.status.containerStatuses[]?.restartCount] | add // 0) > 0)
      | "\(.metadata.namespace) \(.metadata.name)"' "$pods"
  } 2>/dev/null | awk '!seen[$0]++' | head -n "$max_pods"
}

# The Keycloak pods, as "<namespace> <pod>" lines, by their
# app.kubernetes.io/name label or, without one, their name.
keycloak_pods() {
  jq -r '.items[]
    | select((.metadata.labels["app.kubernetes.io/name"] // .metadata.name) | test("keycloak"))
    | "\(.metadata.namespace) \(.metadata.name)"' "$1" 2>/dev/null
}

# What in a Keycloak log explains a refused token: login and token errors
# (the jboss-logging event listener's WARN lines), and the brute-force
# protector's lockouts and failure counts (debug, uat/hub/core's chart).
kc_pattern='LOGIN_ERROR|CODE_TO_TOKEN_ERROR|REFRESH_TOKEN_ERROR|CLIENT_LOGIN_ERROR|user_temporarily_disabled|invalid_user_credentials|BruteForce|brute.force|quick login|num failures|notBefore|lockout'

hub() {
  local name=$1 kc=$2 dir=$out/$1 pods jobs ns pod
  local -a k=("$KUBECTL" --kubeconfig "$kc" --request-timeout=30s)
  mkdir -p "$dir/pods"
  if [ ! -r "$kc" ]; then
    echo "no kubeconfig at $kc" >"$dir/error.txt"
    return
  fi
  log "$name: cluster state into $dir"
  section "$dir/nodes.txt" "get nodes -o wide" "${k[@]}" get nodes -o wide
  section "$dir/pods.txt" "get pods -A -o wide" "${k[@]}" get pods -A -o wide
  section "$dir/jobs.txt" "get jobs -A -o wide" "${k[@]}" get jobs -A -o wide
  section "$dir/events.txt" "get events -A (by time)" "${k[@]}" get events -A --sort-by=.lastTimestamp
  section "$dir/top.txt" "top nodes" "${k[@]}" top nodes
  section "$dir/top.txt" "top pods -A" "${k[@]}" top pods -A
  section "$dir/endpoints.txt" "get endpoints -A" "${k[@]}" get endpoints -A
  section "$dir/endpoints.txt" "RustFS services and endpoints" bash -c '
    "$@" get svc,endpoints -A -o wide | awk "NR==1 || /rustfs/"
    "$@" get endpoints -A -o json | jq ".items[] | select(.metadata.name | test(\"rustfs\"))"' _ "${k[@]}"
  pods=$(mktemp) jobs=$(mktemp)
  timeout -k 5 "$secs" "${k[@]}" get pods -A -o json >"$pods" 2>/dev/null || echo '{"items":[]}' >"$pods"
  timeout -k 5 "$secs" "${k[@]}" get jobs -A -o json >"$jobs" 2>/dev/null || echo '{"items":[]}' >"$jobs"
  while read -r ns pod; do
    [ -n "${pod:-}" ] || continue
    local f="$dir/pods/$ns.$pod.txt"
    section "$f" "describe pod -n $ns $pod" "${k[@]}" describe pod -n "$ns" "$pod"
    section "$f" "logs -n $ns $pod (all containers, last 500 lines each)" "${k[@]}" logs -n "$ns" "$pod" --all-containers --tail=500 --timestamps
    section "$f" "logs --previous -n $ns $pod" "${k[@]}" logs -n "$ns" "$pod" --all-containers --previous --tail=500 --timestamps
  done < <(pick_pods "$pods" "$jobs")
  while read -r ns pod; do
    [ -n "${pod:-}" ] || continue
    mkdir -p "$dir/keycloak"
    local f="$dir/keycloak/$ns.$pod.txt"
    # shellcheck disable=SC2016 # expanded by the inner bash
    section "$f" "logs -n $ns $pod: login errors and brute-force lines (whole log, last $kc_lines)" bash -c '
      set -o pipefail
      n=$1 pattern=$2
      shift 2
      "$@" | { grep -Ei -- "$pattern" || true; } | tail -n "$n"' _ "$kc_lines" "$kc_pattern" "${k[@]}" logs -n "$ns" "$pod" --all-containers --timestamps
    section "$f" "logs -n $ns $pod (all containers, last $kc_lines lines)" "${k[@]}" logs -n "$ns" "$pod" --all-containers --tail="$kc_lines" --timestamps
    section "$f" "logs --previous -n $ns $pod" "${k[@]}" logs -n "$ns" "$pod" --all-containers --previous --tail="$kc_lines" --timestamps
  done < <(keycloak_pods "$pods")
  rm -f "$pods" "$jobs"
}

if [ -n "$kubeconfigs" ]; then
  IFS=: read -r -a pairs <<<"$kubeconfigs"
  for p in "${pairs[@]}"; do
    [ -n "$p" ] || continue
    hub "${p%%=*}" "${p#*=}" &
  done
  wait
else
  log "no kubeconfig (DIAG_KUBECONFIGS, IMAS_UAT_CORE_KUBECONFIG, IMAS_UAT_DMZ_KUBECONFIG); no cluster state"
fi

[ "$mode" = full ] || { log "done: $out"; exit 0; }

uat=${DIAG_UAT:-${UAT_SESSION_UAT:-}}
vmctl=${DIAG_VMCTL:-$here/../access/vmctl.sh}
if [ -z "$uat" ] || [ ! -r "$uat" ]; then
  log "no uat.json (DIAG_UAT, UAT_SESSION_UAT); no sprout logs or Azure state"
  exit 0
fi

linux_logs="systemctl status '$service' --no-pager -l; echo; journalctl -u '$service' --no-pager -n 400 -o short-iso"
# shellcheck disable=SC2016 # PowerShell, expanded on the VM
windows_logs='Get-Service '"$service"' | Format-List Name, Status, StartType
$d = Join-Path $env:ProgramData "imas\logs"
foreach ($f in @("sprout.log", "sprout-crash.log")) {
  $p = Join-Path $d $f
  if (Test-Path $p) { "== $p (last 400 lines)"; Get-Content -LiteralPath $p -Tail 400 } else { "== $p: none" }
}'
mkdir -p "$out/sprouts" "$out/azure"
rg=$(jq -r '.resource_group // empty' "$uat")
while IFS=$'\t' read -r vm os; do
  [ -n "$vm" ] || continue
  (
    if [ "$os" = windows ]; then
      section "$out/sprouts/$vm.txt" "the sprout service on $vm" "$vmctl" "$uat" run "$vm" "$windows_logs"
    else
      section "$out/sprouts/$vm.txt" "the sprout service on $vm" "$vmctl" "$uat" run "$vm" "$linux_logs"
    fi
  ) &
done < <(jq -r '.sprouts // {} | to_entries[] | select(.value.connection != "docker") | [.key, .value.os] | @tsv' "$uat")
while IFS=$'\t' read -r vm id; do
  [ -n "$vm" ] || continue
  (
    section "$out/azure/$vm.json" "az vm run-command list ($vm)" "$AZ" vm run-command list --resource-group "$rg" --vm-name "${id##*/}" -o json
    section "$out/azure/$vm.json" "instance view: power, guest agent, run-command extension ($vm)" "$AZ" vm get-instance-view --ids "$id" \
      --query "{power: instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0], agent: instanceView.vmAgent, runCommand: instanceView.extensions[?contains(name, 'RunCommand')]}" -o json
  ) &
done < <(jq -r '
  ( [ (.dmz, .core) | objects | [(.node_names // [.name]), (.node_ids // [.id])] | transpose[] ] ),
  ( [ .sprouts // {} | to_entries[] | select(.value.connection != "docker") | [.key, .value.id] ] )
  | .[] | @tsv' "$uat")
wait
log "done: $out"
exit 0
