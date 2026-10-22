#!/usr/bin/env bash
# diagnostics.sh: collect what explains a failed UAT test, before the run's
# environment is gone (W8; uat/RUNBOOK.md, "The test channel").
#
#   diagnostics.sh kube <out-dir>     the hubs only (uat/tests/run.sh, after
#                                     each failed top-level test)
#   diagnostics.sh full <out-dir>     the hubs, the sprouts' service logs and
#                                     Azure's run-command state (the
#                                     workflow, after a failed test step)
#
# For each hub (core and dmz, through their kubeconfigs and so through the
# Bastion kube tunnels), into <out-dir>/<hub>/:
#   nodes.txt, pods.txt (get -o wide), jobs.txt, events.txt (all namespaces,
#   by time), top.txt (top nodes and pods), endpoints.txt (get endpoints -A,
#   and the RustFS ones in full), and pods/<ns>.<pod>.txt with describe,
#   logs and logs --previous of: every RustFS pod, every pod of a failed or
#   unfinished Job, and every pod that is not Running or Succeeded, has a
#   container not ready, or restarted (at most DIAG_MAX_PODS per hub).
# full also writes:
#   sprouts/<vm>.txt   the sprout service's state and last log lines, through
#                      vmctl.sh run: journalctl -u imas-sprout on Linux,
#                      %ProgramData%\imas\logs\sprout.log (and
#                      sprout-crash.log) on Windows
#   azure/<vm>.json    per VM: az vm run-command list, and the instance
#                      view's power state, guest agent and run-command
#                      extension status ("execution is in progress" shows
#                      there)
#
# Every command is bounded (DIAG_TIMEOUT seconds; kubectl
# --request-timeout too), a failure is written into the file it was for,
# and the script always exits 0: it is a diagnostic, never a gate. Each
# file is filtered on the way out (redact): values of keys that look like a
# password, secret, token, access or secret key or credential, Bearer
# credentials, JWTs, NKey
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
#   DIAG_SPROUT_SERVICE  the sprout service (default imas-sprout)
#   KUBECTL, AZ        the tools (default kubectl, az)
set -uo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KUBECTL=${KUBECTL:-kubectl}
AZ=${AZ:-az}
secs=${DIAG_TIMEOUT:-60}
max_pods=${DIAG_MAX_PODS:-25}
service=${DIAG_SPROUT_SERVICE:-imas-sprout}

usage() {
  echo "usage: $prog kube|full <out-dir>" >&2
  exit 2
}
log() { echo "$prog: $*" >&2; }

[ $# -eq 2 ] || usage
mode=$1 out=$2
case "$mode" in kube | full) ;; *) usage ;; esac
[[ "$secs" =~ ^[1-9][0-9]*$ && "$max_pods" =~ ^[0-9]+$ ]] || { log "DIAG_TIMEOUT and DIAG_MAX_PODS must be numbers"; exit 2; }
[[ "$service" =~ ^[A-Za-z0-9._@-]+$ ]] || { log "DIAG_SPROUT_SERVICE has unexpected characters"; exit 2; }
mkdir -p "$out"

# redact: stdin to stdout with anything secret-shaped replaced.
redact() {
  sed -E \
    -e '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c\[redacted private key]' \
    -e 's/(Bearer[[:space:]]+)[^[:space:]",;}]+/\1[redacted]/Ig' \
    -e 's/((pass(word|wd)?|secret|token|access[_-]?key|secret[_-]?key|api[_-]?key|credential|client-key-data|client-certificate-data|root[_-]?(user|pass(word)?))[A-Za-z0-9_.-]*"?[[:space:]]*[:=][[:space:]]*)("[^"]*"|[^[:space:],;}]+)/\1[redacted]/Ig' \
    -e 's/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/[redacted jwt]/g' \
    -e 's/(^|[^A-Z0-9])S[OAUNCX][A-Z2-7]{56}([^A-Z2-7]|$)/\1[redacted seed]\2/g'
}

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
