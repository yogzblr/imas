#!/usr/bin/env bash
# session.sh: keep the UAT run's Azure login and Bastion tunnels fresh at the
# run's phase boundaries, and say how old they are (W6).
#
#   session.sh mark-login
#   session.sh phase <name> [--force] [--probe] [--no-tunnels]
#   session.sh refresh [--no-tunnels]
#   session.sh probe <name>
#   session.sh ages <name>
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
#                            (default 15)
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
refresh_after=${UAT_SESSION_REFRESH_AFTER_MIN:-15}
max_age=${UAT_SESSION_MAX_AGE_MIN:-40}
SSH_KEYSCAN=${SSH_KEYSCAN:-ssh-keyscan}
CURL=${CURL:-curl}

log() { echo "$prog: $*" >&2; }
die() { log "$*"; exit 1; }
usage() {
  cat >&2 <<EOF
usage: $prog mark-login
       $prog phase <name> [--force] [--probe] [--no-tunnels]
       $prog refresh [--no-tunnels]
       $prog probe <name>
       $prog ages <name>
EOF
  exit 2
}

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
    "$tunnels" reopen "$UAT_SESSION_UAT" "$dir" ||
      die "refresh: reopening the tunnels failed (they are closed now); $(ages_line)"
    remap_kubeconfigs "$old" "$dir/access.json"
    rm -f "$old"
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

[ $# -ge 1 ] || usage
action=$1
shift
case $action in
  mark-login) cmd_mark_login "$@" ;;
  phase) cmd_phase "$@" ;;
  refresh) cmd_refresh "$@" ;;
  probe) cmd_probe "$@" ;;
  ages) cmd_ages "$@" || true ;;
  -h | --help | help) usage ;;
  *) log "unknown command '$action'"; usage ;;
esac
