#!/usr/bin/env bash
# quota-check.sh: fail before tofu apply when the subscription cannot hold the
# VMs the plan creates (brief H-azure-next-runs.md H1, item 5).
#
#   uat/tofu/quota-check.sh <plan.json> <region>
#
# <plan.json> is `tofu show -json <planfile>` of the run's plan. For every VM
# the plan creates (azurerm_linux_virtual_machine and
# azurerm_windows_virtual_machine with a create action) it looks the size up
# with `az vm list-skus` (its quota family and vCPUs) and then checks, with
# `az vm list-usage`, that for each family and for the region's total
# ("cores", Total Regional vCPUs) the vCPUs in use plus the vCPUs needed fit
# the limit. It also fails when a size is not offered to the subscription in
# the region, or not in the zone the plan puts a VM in.
#
# On a shortfall it prints, per quota, the vCPUs needed, in use, the limit and
# the limit to request, as ::error:: lines, and exits 1. Nothing is created.
#
# Exit status: 0 when everything fits; 1 when a quota is short or a size is
# not offered; 2 on a usage error or when az cannot answer (fail closed: the
# apply does not start).
#
# Environment: AZ (default az), and an az login to the subscription.
set -euo pipefail

prog=$(basename "$0")
AZ=${AZ:-az}

usage() {
  echo "usage: $prog <plan.json> <region>" >&2
  exit 2
}
log() { echo "$prog: $*" >&2; }

[ $# -eq 2 ] || usage
plan=$1
region=$2
[ -r "$plan" ] || { log "cannot read $plan"; exit 2; }
[[ "$region" =~ ^[a-z][a-z0-9]{2,40}$ ]] || { log "'$region' is not an Azure region name"; exit 2; }
command -v jq >/dev/null 2>&1 || { log "jq is not on PATH"; exit 2; }
command -v "$AZ" >/dev/null 2>&1 || { log "$AZ is not on PATH"; exit 2; }

# The VMs the plan creates: one "<size>\t<zone or ->" line each.
vms=$(jq -r '
  [.resource_changes[]?
   | select(.type == "azurerm_linux_virtual_machine" or .type == "azurerm_windows_virtual_machine")
   | select(.change.actions | index("create"))
   | [.change.after.size, (.change.after.zone // "-")]]
  | .[] | @tsv' "$plan") || { log "$plan is not a tofu plan in JSON (tofu show -json)"; exit 2; }

if [ -z "$vms" ]; then
  log "the plan creates no VM; nothing to check"
  exit 0
fi

problems=()

# Per size: family and vCPUs, and whether the subscription may use it here.
declare -A family vcpus need_family
declare -A restricted_zones
sizes=$(printf '%s\n' "$vms" | cut -f1 | sort -u)
for size in $sizes; do
  [[ "$size" =~ ^[A-Za-z0-9_]+$ ]] || { log "unexpected VM size '$size' in the plan"; exit 2; }
  if ! sku=$("$AZ" vm list-skus --location "$region" --resource-type virtualMachines --size "$size" --all -o json 2>/dev/null); then
    log "az vm list-skus failed for $size in $region; cannot check the quota"
    exit 2
  fi
  sku=$(printf '%s' "$sku" | jq -c --arg s "$size" '[.[] | select(.name == $s)][0] // empty') || sku=""
  if [ -z "$sku" ]; then
    problems+=("size $size is not offered in $region")
    continue
  fi
  family[$size]=$(printf '%s' "$sku" | jq -r '.family')
  vcpus[$size]=$(printf '%s' "$sku" | jq -r '[.capabilities[]? | select(.name == "vCPUs") | .value][0] // "0" | tonumber')
  if printf '%s' "$sku" | jq -e '[.restrictions[]? | select(.type == "Location")] | length > 0' >/dev/null; then
    problems+=("size $size is not available to this subscription in $region ($(printf '%s' "$sku" | jq -r '[.restrictions[] | select(.type == "Location") | .reasonCode] | join(", ")'))")
  fi
  restricted_zones[$size]=$(printf '%s' "$sku" | jq -r '[.restrictions[]? | select(.type == "Zone") | .restrictionInfo.zones[]?] | join(" ")')
done

# Zones the plan uses that a size is restricted in.
while IFS=$'\t' read -r size zone; do
  [ "$zone" != "-" ] || continue
  for z in ${restricted_zones[$size]:-}; do
    if [ "$z" = "$zone" ]; then
      problems+=("size $size is not available to this subscription in zone $zone of $region")
    fi
  done
done <<<"$vms"

# vCPUs needed per family and in all.
total=0
while IFS=$'\t' read -r size _; do
  [ -n "${family[$size]:-}" ] || continue
  f=${family[$size]}
  need_family[$f]=$((${need_family[$f]:-0} + ${vcpus[$size]}))
  total=$((total + ${vcpus[$size]}))
done <<<"$vms"

if ! usage_json=$("$AZ" vm list-usage --location "$region" -o json 2>/dev/null); then
  log "az vm list-usage failed in $region; cannot check the quota"
  exit 2
fi
printf '%s' "$usage_json" | jq -e 'type == "array"' >/dev/null 2>&1 || { log "az vm list-usage gave no list"; exit 2; }

# check_quota NAME NEEDED: one line of the table; a problem when it is short.
check_quota() {
  local name=$1 needed=$2 row current limit label free
  row=$(printf '%s' "$usage_json" | jq -r --arg n "$name" '
    [.[] | select(.name.value == $n)][0] // empty
    | [(.currentValue | tonumber), (.limit | tonumber), (.name.localizedValue // .name.value)] | @tsv')
  if [ -z "$row" ]; then
    problems+=("no quota named $name in $region (az vm list-usage); cannot place $needed vCPU")
    return
  fi
  IFS=$'\t' read -r current limit label <<<"$row"
  free=$((limit - current))
  printf '%-40s need %4d  in use %4d  limit %4d  free %4d\n' "$label" "$needed" "$current" "$limit" "$free"
  if [ "$needed" -gt "$free" ]; then
    problems+=("quota short: $label ($name) in $region: this run needs $needed vCPU, $current of $limit are in use ($free free); request a limit of at least $((current + needed))")
  fi
}

echo "$prog: vCPU quota in $region for the VMs this plan creates:"
for f in "${!need_family[@]}"; do
  check_quota "$f" "${need_family[$f]}"
done
check_quota cores "$total"

if [ "${#problems[@]}" -gt 0 ]; then
  for p in "${problems[@]}"; do
    echo "::error::$p"
  done
  log "${#problems[@]} problem(s); not applying"
  exit 1
fi
log "the quota holds this run ($total vCPU)"
