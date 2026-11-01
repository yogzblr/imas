#!/usr/bin/env bash
# check-bastion-ports.sh: fails when a Bastion tunnel of the UAT gate would go
# by IP to a port Azure refuses (W12).
#
#   check-bastion-ports.sh [--root DIR] [uat.json ...]
#
# Azure Bastion's IP-based connection (`az network bastion tunnel
# --target-ip-address`) tunnels to ports 22 and 3389 only. Azure UAT Run 3
# (tier ha, hub_nodes 3) failed in setup with "Custom ports are not allowed.
# Allowed ports for Tunnel with IP connect is 22, 3389." three times: the
# tunnel to each HA hub's internal load balancer on 6443. A tunnel by the
# VM's resource id (--target-resource-id) may use any port.
#
# Two checks:
#   1. the plan: for each uat.json (default: every uat*.json under
#      uat/access/testdata), `tunnels.sh plan` lists the tunnels open would
#      start; any one by IP ("ip:<address>") to a port other than 22 or 3389
#      fails (tunnels.sh refuses it too, before any tunnel starts);
#   2. the code: no script, workflow or program under DIR's uat/ and
#      .github/ (default: this repository) passes --target-ip-address except
#      uat/access/tunnels.sh, whose start_tunnel checks the port, this
#      script and the access tests (their az stub refuses such a tunnel as
#      Azure does). A new caller must go through tunnels.sh.
#
# Exit status: 0 when both pass, 1 when either fails, 2 on a usage error.
set -euo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tunnels=$here/tunnels.sh

log() { echo "$prog: $*" >&2; }
usage() {
  echo "usage: $prog [--root DIR] [uat.json ...]" >&2
  exit 2
}

files=()
while [ $# -gt 0 ]; do
  case $1 in
    --root)
      [ $# -ge 2 ] || usage
      root=$2
      shift 2
      ;;
    -h | --help) usage ;;
    -*) usage ;;
    *)
      files+=("$1")
      shift
      ;;
  esac
done
[ -d "$root" ] || { log "no directory $root"; exit 2; }
if [ ${#files[@]} -eq 0 ]; then
  for f in "$here"/testdata/uat*.json; do [ -e "$f" ] && files+=("$f"); done
fi

failed=0

# 1. The plan of each uat.json.
for f in "${files[@]}"; do
  if ! plan=$(bash "$tunnels" plan "$f" 2>&1); then
    log "FAIL: $f: tunnels.sh plan refused it:"
    printf '%s\n' "$plan" | sed 's/^/  /' >&2
    failed=1
    continue
  fi
  bad=$(printf '%s\n' "$plan" | awk -F'\t' '$4 ~ /^ip:/ && $3 != 22 && $3 != 3389')
  if [ -n "$bad" ]; then
    log "FAIL: $f: Bastion tunnels by IP to a port other than 22 or 3389:"
    printf '%s\n' "$bad" | sed 's/^/  /' >&2
    failed=1
  else
    log "ok: $f: $(printf '%s\n' "$plan" | grep -c .) tunnels, none by IP to a port Azure refuses"
  fi
done

# 2. The code: who passes --target-ip-address.
allowed='^(uat/access/tunnels\.sh|uat/access/check-bastion-ports\.sh|uat/access/tests/.*)$'
hits=""
for d in uat .github; do
  [ -d "$root/$d" ] || continue
  while IFS= read -r f; do
    rel=${f#"$root"/}
    [[ "$rel" =~ $allowed ]] && continue
    # Prose (Markdown) may name the flag; code may not.
    case $rel in *.md) continue ;; esac
    hits+="$rel"$'\n'
  done < <(grep -rlI -e '--target-ip-address' "$root/$d" 2>/dev/null || true)
done
if [ -n "$hits" ]; then
  log "FAIL: these pass --target-ip-address outside uat/access/tunnels.sh (open Bastion tunnels through tunnels.sh, which allows IP-based tunnels on 22 and 3389 only):"
  printf '%s' "$hits" | sed 's/^/  /' >&2
  failed=1
else
  log "ok: only uat/access/tunnels.sh passes --target-ip-address"
fi

exit "$failed"
