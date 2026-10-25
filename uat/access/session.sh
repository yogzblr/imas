#!/usr/bin/env bash
# session.sh: keep the UAT run's Azure login and Bastion tunnels fresh, at the
# run's phase boundaries (W6) and, during the tests, every minute (W10), and
# say how old they are.
#
#   session.sh mark-login
#   session.sh phase <name> [--force] [--probe] [--no-tunnels]
#   session.sh refresh [--no-tunnels]
#   session.sh probe <name>
#   session.sh ages <name>
#   session.sh supervise start|stop|run|tick
#   session.sh ensure kube
#
# Why. The runner's az session comes from a GitHub OIDC login, which cannot
# renew itself once its access token expires (about an hour). UAT Run 2 hung
# 55 to 60 minutes after its login: every Bastion tunnel stopped opening new
# connections (Ansible over SSH and WinRM went UNREACHABLE or timed out),
# while a fresh tunnel from a laptop worked. The cause is inferred from that
# timing, not proven, so every phase prints both ages, and a failure names
# them (docs/briefs/W6-azure-auth-age-and-tunnels.md, uat/RUNBOOK.md).
#
# mark-login  records that the az CLI has just logged in (after the
#             azure/login action, which cannot record it itself).
# phase       starts a phase: refreshes (below) when --force is given or the
#             login or the tunnels are UAT_SESSION_REFRESH_AFTER_MIN minutes
#             old or more, then fails if either is older than
#             UAT_SESSION_MAX_AGE_MIN minutes (the age guard), then prints
#             "<name>: azure login age Xm, tunnels age Ym". --probe then
#             probes the tunnels. --no-tunnels: only the login (a phase that
#             needs no tunnel, or after they are closed).
# refresh     logs the az CLI in again from the job's OIDC token
#             (az-relogin.sh), then closes the tunnels and opens them again
#             (tunnels.sh reopen: the same local ports where they are free)
#             so the new az processes carry the new login. If a port changed,
#             every kubeconfig in UAT_SESSION_KUBECONFIGS that points at the
#             old port is rewritten to the new one; the inventory is made
#             from access.json again by uat/enroll. Never call it while
#             something (Ansible, a test) is using a tunnel.
# probe       checks that every tunnel answers end to end: SSH by
#             `ssh-keyscan -T 15`, WinRM by an HTTPS request to /wsman (HTTP
#             401 or 405 is alive), the Kubernetes API by an HTTPS request
#             to /version (any HTTP answer is alive). A failure names the
#             tunnel, its port and both ages.
# ages        prints both ages, each tunnel's process state and the last
#             lines of each tunnel's log, and never fails: the workflow's
#             failure-time diagnostic.
# supervise   the refresh that does not wait for a boundary (W10). UAT Run 2
#             #6's TestIngredients ran 15 minutes as one top-level test; its
#             tunnels, refreshed only between tests, stopped opening
#             connections at about 20 minutes old. `supervise start` starts
#             one supervisor per run in the background (its pid in
#             <access dir>/supervisor.pid, its log in
#             <access dir>/logs/supervisor.log; a second start is a no-op
#             while it runs); `stop` stops it; `run` is the loop itself; `tick`
#             is one round of it. Each UAT_SUPERVISE_INTERVAL seconds (60) a
#             round:
#               1. logs az in again when the login is REFRESH_AFTER
#                  (UAT_REFRESH_AFTER_MIN, 10) minutes old;
#               2. takes the tunnels one at a time, oldest first, and reopens
#                  one that is REFRESH_AFTER old or whose protocol probe fails
#                  (channel.sh), on the SAME port, then probes it. It never
#                  reopens a tunnel under a running command: an SSH or WinRM
#                  tunnel only holding every vmctl.sh slot of its VM, a kube
#                  tunnel only once no connection is open on its port
#                  (kubectl, a port-forward), waiting up to
#                  UAT_SUPERVISE_WAIT_SECONDS (30) and otherwise leaving it
#                  for the next round;
#               3. re-probes every VM vmctl.sh marked dead, at most every
#                  VMCTL_REPROBE_SECONDS (120), reopening its tunnel when the
#                  probe fails, and clears the mark when the tunnel answers.
#             A round skips while <access dir>/supervisor.pause exists (a
#             full refresh is running).
# ensure kube logs in again and reopens each kube tunnel, as a round does,
#             when it is REFRESH_AFTER old; the Go harness runs it before a
#             kubectl call that would otherwise go out on an old one.
#
# Every refresh that reopens the tunnels clears vmctl.sh's dead marks.
#
# The login time is the modification time of az-relogin.sh's stamp,
# $AZ_RELOGIN_DIR/az-relogin.stamp, so a relogin by vmctl.sh counts too; the
# tunnels' time is <access dir>/opened_at, written by tunnels.sh open.
#
# Environment:
#   UAT_SESSION_UAT          the uat.json the tunnels were opened from
#   UAT_SESSION_ACCESS       tunnels.sh's state directory (holds access.json)
#   UAT_SESSION_KUBECONFIGS  colon-separated kubeconfigs to keep on the
#                            tunnels' ports (missing files are skipped)
#   UAT_SESSION_REFRESH_AFTER_MIN  refresh at a phase start from this age
#                            (default UAT_REFRESH_AFTER_MIN, else 10)
#   UAT_REFRESH_AFTER_MIN    REFRESH_AFTER: the supervisor's and vmctl.sh's
#                            age limit (default 10)
#   UAT_SUPERVISE_INTERVAL   seconds between the supervisor's rounds
#                            (default 60)
#   UAT_SUPERVISE_WAIT_SECONDS  how long a round waits for a VM's slots or a
#                            kube port's connections (default 30)
#   UAT_SUPERVISE_PROBE      0: a round reopens by age only, no probes
#                            (default 1)
#   VMCTL_STATE_DIR          vmctl.sh's slots and dead marks (default
#                            <access dir>/vmctl, as vmctl.sh)
#   UAT_SESSION_MAX_AGE_MIN  the age guard (default 40)
#   AZ_RELOGIN_DIR           where the login stamp lives (default
#                            $RUNNER_TEMP or /tmp, as az-relogin.sh)
#   UAT_SESSION_RELOGIN      the login command (default az-relogin.sh here)
#   UAT_SESSION_TUNNELS      tunnels.sh (default the one here)
#   SSH_KEYSCAN, CURL        the probe tools (default ssh-keyscan, curl)
#
# Exit status: 0 ok, 1 a refresh, the guard or a probe failed, 2 usage.
set -euo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "$0")" && pwd)
relogin=${UAT_SESSION_RELOGIN:-$here/az-relogin.sh}
tunnels=${UAT_SESSION_TUNNELS:-$here/tunnels.sh}
login_dir=${AZ_RELOGIN_DIR:-${RUNNER_TEMP:-/tmp}}
stamp="$login_dir/az-relogin.stamp"
refresh_after=${UAT_SESSION_REFRESH_AFTER_MIN:-${UAT_REFRESH_AFTER_MIN:-10}}
max_age=${UAT_SESSION_MAX_AGE_MIN:-40}
SSH_KEYSCAN=${SSH_KEYSCAN:-ssh-keyscan}
CURL=${CURL:-curl}
UAT_UAT_JSON=${UAT_SESSION_UAT:-}
export UAT_UAT_JSON AZ_RELOGIN_DIR=$login_dir
# shellcheck source=channel.sh
. "$here/channel.sh"

log() { echo "$prog: $*" >&2; }
die() { log "$*"; exit 1; }
usage() {
  cat >&2 <<EOF
usage: $prog mark-login
       $prog phase <name> [--force] [--probe] [--no-tunnels]
       $prog refresh [--no-tunnels]
       $prog probe <name>
       $prog ages <name>
       $prog supervise start|stop|run|tick
       $prog ensure kube
EOF
  exit 2
}

ch_valid_knobs || { log "UAT_REFRESH_AFTER_MIN, UAT_PROBE_*_SECONDS and VMCTL_SLOTS_* must be whole numbers above 0"; exit 2; }
for n in "${UAT_SUPERVISE_INTERVAL:-60}" "${UAT_SUPERVISE_WAIT_SECONDS:-30}" "${VMCTL_REPROBE_SECONDS:-120}" "${VMCTL_DEAD_AFTER:-3}"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { log "UAT_SUPERVISE_INTERVAL, UAT_SUPERVISE_WAIT_SECONDS, VMCTL_REPROBE_SECONDS and VMCTL_DEAD_AFTER must be whole numbers"; exit 2; }
done
for v in refresh_after max_age; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { log "UAT_SESSION_REFRESH_AFTER_MIN and UAT_SESSION_MAX_AGE_MIN must be whole minutes"; exit 2; }
done

access_dir() {
  [ -n "${UAT_SESSION_ACCESS:-}" ] || { log "UAT_SESSION_ACCESS is not set"; exit 2; }
  printf '%s\n' "$UAT_SESSION_ACCESS"
}

# Seconds since the login, or empty when there is no record.
login_age_s() {
  [ -f "$stamp" ] || return 0
  echo $(($(date +%s) - $(stat -c %Y "$stamp")))
}

# Seconds since the tunnels were opened, or empty when they are not open.
tunnel_age_s() {
  local d=${UAT_SESSION_ACCESS:-} t
  if [ -z "$d" ] || [ ! -s "$d/opened_at" ] || [ ! -s "$d/access.json" ]; then return 0; fi
  t=$(cat "$d/opened_at")
  [[ "$t" =~ ^[0-9]+$ ]] || return 0
  echo $(($(date +%s) - t))
}

fmt_age() { # fmt_age <seconds or empty> <what is missing>
  if [ -z "$1" ]; then echo "unknown ($2)"; else echo "$(($1 / 60))m"; fi
}

ages_line() {
  echo "azure login age $(fmt_age "$(login_age_s)" "no login recorded"), tunnels age $(fmt_age "$(tunnel_age_s)" "not open")"
}

cmd_mark_login() {
  [ $# -eq 0 ] || usage
  mkdir -p "$login_dir"
  touch "$stamp"
  log "azure login recorded"
}

# Rewrites, in every UAT_SESSION_KUBECONFIGS file, a server on 127.0.0.1 at
# an old kube port to that tunnel's new port. $1, $2: access.json before and
# after.
remap_kubeconfigs() {
  local old=$1 new=$2 map f tmp
  map=$(jq -nr --slurpfile o "$old" --slurpfile n "$new" '
    [$o[0] | to_entries[] | select(.value.kube_port) | .key as $k | .value.kube_port as $p
     | ($n[0][$k].kube_port // empty) as $q | select($p != $q) | "\($p)=\($q)"] | join(" ")')
  [ -n "$map" ] || return 0
  log "kube tunnel ports changed ($map); updating the kubeconfigs"
  local IFS=:
  for f in ${UAT_SESSION_KUBECONFIGS:-}; do
    [ -f "$f" ] || continue
    tmp=$(mktemp "$f.XXXXXX")
    awk -v map="$map" '
      BEGIN { n = split(map, a, " "); for (i = 1; i <= n; i++) { split(a[i], kv, "="); m[kv[1]] = kv[2] } }
      /^[[:space:]]*server:[[:space:]]*https:\/\/127\.0\.0\.1:[0-9]+[[:space:]]*$/ {
        p = $0; sub(/^.*127\.0\.0\.1:/, "", p); sub(/[[:space:]]*$/, "", p)
        if (p in m) sub("127\\.0\\.0\\.1:" p, "127.0.0.1:" m[p])
      }
      { print }' "$f" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$f"
    log "updated $f"
  done
}

cmd_refresh() {
  local tunnels_too=1
  while [ $# -gt 0 ]; do
    case $1 in
      --no-tunnels) tunnels_too=0 ;;
      *) usage ;;
    esac
    shift
  done
  log "refresh: $(ages_line); logging in again"
  AZ_RELOGIN_MIN_AGE=0 AZ_RELOGIN_DIR="$login_dir" "$relogin" || die "refresh: the Azure login failed"
  mkdir -p "$login_dir"
  touch "$stamp"
  if [ "$tunnels_too" = 1 ]; then
    local dir old
    dir=$(access_dir)
    [ -n "${UAT_SESSION_UAT:-}" ] || { log "UAT_SESSION_UAT is not set"; exit 2; }
    mkdir -p "$dir"
    old="$dir/access.json.before-refresh"
    if [ -s "$dir/access.json" ]; then cp "$dir/access.json" "$old"; else echo '{}' >"$old"; fi
    # The supervisor waits, and the SSH masters and pooled WinRM sessions go
    # with their tunnels.
    touch "$dir/supervisor.pause"
    local m
    for m in $(jq -r 'to_entries[] | select(.value.ssh_port) | .key' "$old" 2>/dev/null); do ch_ssh_master_close "$m"; done
    for m in $(jq -r 'to_entries[] | select(.value.winrm_port) | .key' "$old" 2>/dev/null); do ch_winrm_pool_close "$m"; done
    if ! "$tunnels" reopen "$UAT_SESSION_UAT" "$dir"; then
      rm -f "$dir/supervisor.pause"
      die "refresh: reopening the tunnels failed (they are closed now); $(ages_line)"
    fi
    rm -f "$dir/supervisor.pause"
    remap_kubeconfigs "$old" "$dir/access.json"
    rm -f "$old"
    # Fresh tunnels: no VM is dead because of the old ones (W10).
    CH_STATE_DIR=$(state_dir) ch_clear_marks
  fi
  log "refresh: done; $(ages_line)"
}

# probe_one <kind> <port>: prints "ok <detail>" or "fail <detail>".
probe_one() {
  local kind=$1 port=$2 out code
  case $kind in
    ssh)
      out=$("$SSH_KEYSCAN" -T 15 -p "$port" 127.0.0.1 2>/dev/null || true)
      if grep -q '^\[127\.0\.0\.1\]' <<<"$out" || grep -q '^127\.0\.0\.1 ' <<<"$out"; then
        echo "ok SSH host key"
      else
        echo "fail no SSH host key within 15s"
      fi
      ;;
    winrm | kube)
      local path=/wsman
      [ "$kind" = kube ] && path=/version
      code=$("$CURL" -sk -m 20 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$port$path" 2>/dev/null || true)
      code=${code:-000}
      if [ "$kind" = winrm ]; then
        case $code in
          401 | 405) echo "ok HTTP $code on $path" ;;
          000) echo "fail no HTTPS answer on $path within 20s" ;;
          *) echo "fail HTTP $code on $path (expected 401 or 405)" ;;
        esac
      elif [ "$code" = 000 ]; then
        echo "fail no HTTPS answer on $path within 20s"
      else
        echo "ok HTTP $code on $path"
      fi
      ;;
    *) echo "fail unknown tunnel kind $kind" ;;
  esac
}

cmd_probe() {
  [ $# -eq 1 ] || usage
  local name=$1 dir age
  dir=$(access_dir)
  [ -s "$dir/access.json" ] || die "$name: probe: no $dir/access.json (the tunnels are not open); $(ages_line)"
  age=$(fmt_age "$(tunnel_age_s)" "not open")
  local results vm kind port i=0 failed=0
  results=$(mktemp -d)
  # Every tunnel at once: a dead one costs its timeout, not the sum.
  while IFS=$'\t' read -r vm kind port; do
    i=$((i + 1))
    { printf '%s\t%s\t%s\t%s\n' "$vm" "$kind" "$port" "$(probe_one "$kind" "$port")" >"$results/$i"; } &
  done < <(jq -r 'to_entries[] | .key as $vm | .value | to_entries[]
      | select(.key | test("^(ssh|winrm|kube)_port$")) | [$vm, (.key | sub("_port$"; "")), .value] | @tsv' "$dir/access.json")
  wait
  local line rest verdict detail
  for line in "$results"/*; do
    [ -e "$line" ] || continue
    IFS=$'\t' read -r vm kind port rest <"$line"
    verdict=${rest%% *} detail=${rest#* }
    if [ "$verdict" = ok ]; then
      log "$name: probe: $vm $kind tunnel (127.0.0.1:$port, tunnel age $age): $detail"
    else
      failed=$((failed + 1))
      log "$name: probe FAILED: $vm $kind tunnel (127.0.0.1:$port) is stale or dead: $detail; tunnel age $age, $(ages_line)"
    fi
  done
  rm -rf "$results"
  [ "$i" -gt 0 ] || die "$name: probe: access.json lists no tunnel"
  [ "$failed" -eq 0 ] || die "$name: $failed of $i tunnels did not answer; $(ages_line) (uat/RUNBOOK.md, 'All tunnels hang')"
  log "$name: probe: all $i tunnels answer"
}

cmd_phase() {
  [ $# -ge 1 ] || usage
  local name=$1 force=0 probe=0 tunnels_too=1
  shift
  while [ $# -gt 0 ]; do
    case $1 in
      --force) force=1 ;;
      --probe) probe=1 ;;
      --no-tunnels) tunnels_too=0 ;;
      *) usage ;;
    esac
    shift
  done
  [ "$tunnels_too" = 1 ] && access_dir >/dev/null
  local la ta limit=$((refresh_after * 60)) due=$force
  la=$(login_age_s)
  { [ -z "$la" ] || [ "$la" -ge "$limit" ]; } && due=1
  if [ "$tunnels_too" = 1 ]; then
    ta=$(tunnel_age_s)
    { [ -z "$ta" ] || [ "$ta" -ge "$limit" ]; } && due=1
  fi
  if [ "$due" = 1 ]; then
    if [ "$tunnels_too" = 1 ]; then cmd_refresh; else cmd_refresh --no-tunnels; fi
  fi
  # The age guard: a phase never starts on a login or tunnels this old.
  local max=$((max_age * 60))
  la=$(login_age_s)
  if [ -z "$la" ] || [ "$la" -gt "$max" ]; then
    die "$name: refusing to start: $(ages_line); the limit is ${max_age}m (the OIDC login stops working after about an hour; uat/RUNBOOK.md)"
  fi
  if [ "$tunnels_too" = 1 ]; then
    ta=$(tunnel_age_s)
    if [ -z "$ta" ] || [ "$ta" -gt "$max" ]; then
      die "$name: refusing to start: $(ages_line); the limit is ${max_age}m (tunnels opened on an expiring login hang; uat/RUNBOOK.md)"
    fi
  fi
  log "$name: $(ages_line)"
  if [ "$probe" = 1 ]; then cmd_probe "$name"; fi
}

cmd_ages() {
  [ $# -eq 1 ] || usage
  local name=$1 dir pid vm kind port state f
  log "$name: $(ages_line)"
  dir=${UAT_SESSION_ACCESS:-}
  if [ -z "$dir" ] || [ ! -f "$dir/tunnels.pids" ]; then return 0; fi
  while IFS=$'\t' read -r pid vm kind port; do
    [ -n "${vm:-}" ] || continue
    if kill -0 "$pid" 2>/dev/null && [[ "$(ps -o stat= -p "$pid" 2>/dev/null)" != Z* ]]; then
      state=running
    else
      state=exited
    fi
    log "$name: tunnel $vm $kind on 127.0.0.1:$port: process $pid $state"
    f="$dir/logs/$vm-$kind.log"
    [ -s "$f" ] && tail -n 5 "$f" | sed "s/^/    /" >&2
  done <"$dir/tunnels.pids"
  return 0
}

# --- the supervisor (W10)

state_dir() { echo "${VMCTL_STATE_DIR:-$(access_dir)/vmctl}"; }
slog() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $prog: $*" >&2; }
supervise_wait=${UAT_SUPERVISE_WAIT_SECONDS:-30}
supervise_interval=${UAT_SUPERVISE_INTERVAL:-60}
reprobe_seconds=${VMCTL_REPROBE_SECONDS:-120}
dead_after=${VMCTL_DEAD_AFTER:-3}

# relogin_if_due: a login REFRESH_AFTER old is renewed. Its stdout (a
# ::add-mask:: line) is dropped: this output is kept in files.
relogin_if_due() {
  local la
  la=$(ch_login_age)
  if [ -n "$la" ] && ! ch_due "$la"; then return 0; fi
  slog "azure login age $(ch_fmt_age "$la") (REFRESH_AFTER ${ch_refresh_after}m); logging in again"
  if AZ_RELOGIN_MIN_AGE=0 AZ_RELOGIN_ADD_MASK=0 AZ_RELOGIN_DIR="$login_dir" "$relogin" >/dev/null; then
    mkdir -p "$login_dir"
    touch "$stamp"
  else
    slog "logging in again failed; the next round tries again"
  fi
}

# reopen_held <vm> <kind>: reopens a tunnel once nothing uses it: every
# slot of an SSH or WinRM tunnel's VM, or no connection on a kube tunnel's
# port. 1 when it had to be left for later.
reopen_held() {
  local vm=$1 kind=$2 port verdict i
  port=$(ch_port "$vm" "$kind")
  if [ "$kind" = kube ]; then
    for ((i = 0; i < supervise_wait; i++)); do
      [ "$(ch_port_connections "$port")" -eq 0 ] && break
      sleep 1
    done
    if [ "$(ch_port_connections "$port")" -ne 0 ]; then
      slog "$vm kube tunnel (127.0.0.1:$port): $(ch_port_connections "$port") connections still open after ${supervise_wait}s; leaving it for the next round"
      return 1
    fi
    verdict=$(ch_reopen "$vm" "$kind") || true
  else
    local os
    os=$(ch_vm_field "$vm" os)
    if ! ch_slots_exclusive "$vm" "$(ch_slots "$os")" "$supervise_wait"; then
      slog "$vm $kind tunnel (127.0.0.1:$port): its VM's slots stayed busy for ${supervise_wait}s; leaving it for the next round"
      return 1
    fi
    verdict=$(ch_reopen "$vm" "$kind") || true
    ch_slots_release
  fi
  slog "$vm $kind tunnel reopened on 127.0.0.1:$port: $verdict"
  return 0
}

# supervise_tunnels: one round over the tunnels, one at a time, oldest
# first.
supervise_tunnels() {
  local dir vm kind port age reason verdict
  dir=$(access_dir)
  [ -s "$dir/tunnels.pids" ] || return 0
  while IFS=$'\t' read -r age vm kind port; do
    [ -n "${vm:-}" ] || continue
    reason=""
    if ch_due "$age"; then
      reason="age $(ch_fmt_age "$age") (REFRESH_AFTER ${ch_refresh_after}m)"
    elif [ "${UAT_SUPERVISE_PROBE:-1}" = 1 ]; then
      verdict=$(ch_probe "$kind" "$port")
      [ "${verdict%% *}" = ok ] || reason="probe: ${verdict#* }"
    fi
    [ -n "$reason" ] || continue
    slog "$vm $kind tunnel (127.0.0.1:$port): $reason; reopening it"
    reopen_held "$vm" "$kind" || true
  done < <(while IFS=$'\t' read -r _pid vm kind port; do
      [ -n "${vm:-}" ] || continue
      printf '%s\t%s\t%s\t%s\n' "$(ch_tunnel_age "$vm" "$kind")" "$vm" "$kind" "$port"
    done <"$dir/tunnels.pids" | sort -t$'\t' -k1,1nr)
}

# supervise_dead: re-probes the VMs vmctl.sh marked dead.
supervise_dead() {
  local f vm count fepoch pepoch reason last now kind port verdict os
  [ "$dead_after" -gt 0 ] || return 0
  for f in "$CH_STATE_DIR"/*.fails; do
    [ -f "$f" ] || continue
    vm=$(basename "$f" .fails)
    { read -r count fepoch pepoch && IFS= read -r reason; } <"$f" || continue
    if ! [[ "${count:-}" =~ ^[0-9]+$ ]] || [ "$count" -lt "$dead_after" ]; then continue; fi
    [[ "${pepoch:-}" =~ ^[0-9]+$ ]] || pepoch=0
    now=$(date +%s)
    last=$fepoch
    [ "$pepoch" -gt "$last" ] && last=$pepoch
    [ $((now - last)) -ge "$reprobe_seconds" ] || continue
    kind=$(ch_tunnels_of "$vm" | grep -v '^kube$' | head -n 1)
    [ -n "$kind" ] || continue
    port=$(ch_port "$vm" "$kind")
    os=$(ch_vm_field "$vm" os)
    if ! ch_slots_exclusive "$vm" "$(ch_slots "$os")" "$supervise_wait"; then
      slog "$vm is marked dead; its slots are busy, re-probing it next round"
      continue
    fi
    verdict=$(ch_probe "$kind" "$port")
    if [ "${verdict%% *}" != ok ]; then
      slog "$vm is marked dead and its $kind tunnel does not answer ($verdict); reopening it"
      verdict=$(ch_reopen "$vm" "$kind") || true
    fi
    if [ "${verdict%% *}" = ok ]; then
      ch_clear_mark "$vm"
      slog "$vm was marked dead ($count channel failures; last: $reason); its $kind tunnel answers ($verdict): un-marked"
    elif [ -f "$f" ]; then
      printf '%s %s %s\n%s\n' "$count" "$fepoch" "$(date +%s)" "$reason" >"$f.tmp" && mv "$f.tmp" "$f"
      slog "$vm stays marked dead: $verdict"
    fi
    ch_slots_release
  done
}

supervise_tick() {
  local dir
  dir=$(access_dir)
  CH_ACCESS_DIR=$dir
  CH_STATE_DIR=$(state_dir)
  mkdir -p "$CH_STATE_DIR"
  if [ -e "$dir/supervisor.pause" ]; then
    slog "a full refresh is running; skipping this round"
    return 0
  fi
  # One round at a time, also against ensure.
  exec 7>>"$dir/session.lock"
  flock -w "$supervise_wait" 7 || { slog "another round still runs; skipping"; return 0; }
  relogin_if_due
  if [ -s "$dir/access.json" ]; then
    supervise_tunnels
    supervise_dead
  fi
  flock -u 7
}

cmd_supervise() {
  [ $# -eq 1 ] || usage
  [ -n "${UAT_SESSION_UAT:-}" ] || { log "UAT_SESSION_UAT is not set"; exit 2; }
  local dir pidf pid
  dir=$(access_dir)
  mkdir -p "$dir/logs"
  pidf=$dir/supervisor.pid
  case $1 in
    start)
      if [ -s "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
        log "supervise: already running (pid $(cat "$pidf"))"
        return 0
      fi
      if command -v setsid >/dev/null 2>&1; then
        setsid "$0" supervise run </dev/null >>"$dir/logs/supervisor.log" 2>&1 &
      else
        nohup "$0" supervise run </dev/null >>"$dir/logs/supervisor.log" 2>&1 &
      fi
      echo "$!" >"$pidf"
      log "supervise: started (pid $!, every ${supervise_interval}s, REFRESH_AFTER ${ch_refresh_after}m; log $dir/logs/supervisor.log)"
      ;;
    stop)
      if [ -s "$pidf" ]; then
        pid=$(cat "$pidf")
        if kill -0 "$pid" 2>/dev/null; then
          kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
          log "supervise: stopped (pid $pid)"
        fi
        rm -f "$pidf"
      fi
      ;;
    run)
      slog "supervise: every ${supervise_interval}s, REFRESH_AFTER ${ch_refresh_after}m"
      trap 'slog "supervise: stopping"; exit 0' TERM INT
      while :; do
        supervise_tick || slog "supervise: a round failed; going on"
        sleep "$supervise_interval" &
        wait $! || true
      done
      ;;
    tick) supervise_tick ;;
    *) usage ;;
  esac
}

# ensure kube: the kube tunnels and the login, fresh, for a kubectl call.
cmd_ensure() {
  if [ $# -ne 1 ] || [ "$1" != kube ]; then usage; fi
  local dir vm age
  dir=$(access_dir)
  CH_ACCESS_DIR=$dir
  CH_STATE_DIR=$(state_dir)
  exec 7>>"$dir/session.lock"
  flock -w 120 7 || { log "ensure: the session is busy; going on as it is"; return 0; }
  relogin_if_due
  [ -s "$dir/access.json" ] || return 0
  for vm in $(jq -r 'to_entries[] | select(.value.kube_port) | .key' "$dir/access.json"); do
    age=$(ch_tunnel_age "$vm" kube)
    ch_due "$age" || continue
    slog "$vm kube tunnel: age $(ch_fmt_age "$age") (REFRESH_AFTER ${ch_refresh_after}m); reopening it"
    reopen_held "$vm" kube || true
  done
}

[ $# -ge 1 ] || usage
action=$1
shift
case $action in
  mark-login) cmd_mark_login "$@" ;;
  phase) cmd_phase "$@" ;;
  refresh) cmd_refresh "$@" ;;
  probe) cmd_probe "$@" ;;
  ages) cmd_ages "$@" || true ;;
  supervise) cmd_supervise "$@" ;;
  ensure) cmd_ensure "$@" ;;
  -h | --help | help) usage ;;
  *) log "unknown command '$action'"; usage ;;
esac
