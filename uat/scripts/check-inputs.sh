#!/usr/bin/env bash
# check-inputs.sh: the up-front check of the UAT workflow (.github/workflows/uat.yml).
# Everything the run needs from GitHub is checked before anything is created in
# Azure, and every problem is reported at once, by name, with a ::error:: line.
#
# Reads the environment (the workflow passes inputs and variables through env,
# never through ${{ }} inside a script):
#   AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
#                      the uat environment's variables (GUIDs)
#   RELEASE_TAG        required: vX.Y.Z or vX.Y.Z-rc.N, an existing tag with a
#                      published (not draft) GitHub release that is GPG
#                      signed: it has the checksums.txt and checksums.txt.sig
#                      assets (P22). Its published farmer chart, the one the
#                      core hub installs, carries the stamped sprout release
#                      finish.sh registers, so the tag is the chart reference
#                      too
#   UPGRADE_FROM_TAG   optional, the same checks; must differ from RELEASE_TAG
#   REGION             Azure region name (default centralindia)
#   KEEP_HOURS         0 to 168, a whole number (default 0)
#   TIER               smoke, core, resilience, ingredients, lifecycle, ha or
#                      all; ha needs HUB_NODES 3 (the ha tier tests the HA
#                      run's hubs and skips every scenario on one node)
#   SCENARIOS          optional scenario ids, separated by spaces or commas
#   HUB_NODES          nodes per hub: 1 (default, the single-node run) or 3
#                      (the HA run: 3 core and 3 DMZ k0s nodes, P24)
#   DISPATCH_FLAGS     true or false (default false): the workflow input
#                      dispatch_flags, which turns the fleet update flags on
#                      in the hubs' values (uat/hub/core/gen-values.sh) and
#                      tells the tests they are on
#   INGRESS_CIDRS      optional public IPv4 ranges, separated by spaces or
#                      commas (a.b.c.d/N, N from 8 to 32, no host bits set,
#                      at most 50): the hardened mode of uat/tofu's
#                      public_ingress. Empty (default) opens the three
#                      internet-facing ports (Bastion 443, core 443, DMZ
#                      Envoy) to the Internet, so they follow whatever egress
#                      address the runner uses (owner, 2026-10-20, W5)
#   GITHUB_REPOSITORY  owner/repo, for the tag and release lookups (gh api)
#
# Writes, when GITHUB_OUTPUT is set, the normalised values as step outputs:
#   release_tag region keep_hours tier upgrade_from_tag scenarios hub_nodes
#   dispatch_flags     on or off: IMAS_UAT_DISPATCH_FLAGS for the core hub
#                      install and the tests
#   public_ingress     internet (no INGRESS_CIDRS) or cidrs: uat/tofu's
#                      public_ingress
#   public_ingress_cidrs
#                      the ranges as a JSON list ([] for internet): uat/tofu's
#                      public_ingress_cidrs
#   core_node_count, dmz_node_count
#                      uat/tofu's node counts (both equal hub_nodes)
#   core_node_size     uat/tofu's core_node_size: Standard_D4s_v5 for the HA
#                      run (owner, 2026-10-13), empty for one node (the tofu
#                      default stays); the DMZ keeps its default size either way
#   destroy            true when keep_hours is 0 (the final destroy runs)
#   run_budget_hours   how long the janitor waits before the run's own
#                      expires_at, before keep_hours: 3 for smoke, else 7
#                      (a GitHub hosted job lasts at most 6 hours)
# and prints them on stdout either way.
#
# Exit status: 0 when everything is there; 1 naming everything missing or
# malformed.
set -euo pipefail

prog=$(basename "$0")
problems=()
problem() { problems+=("$1"); }

guid='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
tag_re='^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'

# The three Azure variables of the uat environment.
for name in AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID; do
  value=${!name:-}
  if [ -z "$value" ]; then
    problem "variable $name is not set in the uat environment"
  elif ! [[ "$value" =~ $guid ]]; then
    problem "variable $name is not a GUID"
  fi
done

repo=${GITHUB_REPOSITORY:-}
[ -n "$repo" ] || problem "GITHUB_REPOSITORY is not set (run this inside GitHub Actions)"

# check_release INPUT TAG [signed]: TAG is a release tag, exists, and has a
# published release; with "signed", the release also carries checksums.txt
# and its detached GPG signature checksums.txt.sig (the sprout installs only
# what that signature verifies, and finish.sh registers both).
check_release() {
  local input=$1 tag=$2 want_signed=${3:-} info draft has_sums has_sig
  if ! [[ "$tag" =~ $tag_re ]]; then
    problem "input $input '$tag' is not a release tag (want vX.Y.Z or vX.Y.Z-rc.N)"
    return
  fi
  [ -n "$repo" ] || return
  if ! gh api "repos/$repo/git/ref/tags/$tag" --jq .ref >/dev/null 2>&1; then
    problem "input $input: tag $tag does not exist in $repo"
    return
  fi
  if ! info=$(gh api "repos/$repo/releases/tags/$tag" \
    --jq '[(.draft | tostring), ([.assets[]?.name] | index("checksums.txt") != null | tostring), ([.assets[]?.name] | index("checksums.txt.sig") != null | tostring)] | join(" ")' 2>/dev/null); then
    problem "input $input: tag $tag has no published release in $repo (a draft release does not count)"
    return
  fi
  read -r draft has_sums has_sig <<<"$info"
  if [ "$draft" != "false" ]; then
    problem "input $input: the release for $tag is still a draft; publish it first"
  fi
  if [ "$want_signed" = signed ] && { [ "$has_sums" != true ] || [ "$has_sig" != true ]; }; then
    problem "input $input: the release for $tag is not GPG signed (it needs the checksums.txt and checksums.txt.sig assets; docs/RELEASING.md): the sprout release it registers could not be verified"
  fi
}

release_tag=${RELEASE_TAG:-}
if [ -z "$release_tag" ]; then
  problem "input release_tag is empty"
else
  check_release release_tag "$release_tag" signed
fi

upgrade_from_tag=${UPGRADE_FROM_TAG:-}
if [ -n "$upgrade_from_tag" ]; then
  if [ "$upgrade_from_tag" = "$release_tag" ]; then
    problem "input upgrade_from_tag equals release_tag ($release_tag); L4 needs an earlier release"
  else
    check_release upgrade_from_tag "$upgrade_from_tag"
  fi
fi

region=${REGION:-centralindia}
[[ "$region" =~ ^[a-z][a-z0-9]{2,40}$ ]] || problem "input region '$region' is not an Azure region name (lowercase letters and digits)"

keep_hours=${KEEP_HOURS:-0}
# A number input may arrive as 2 or 2.0.
keep_hours=${keep_hours%.0}
if ! [[ "$keep_hours" =~ ^[0-9]{1,3}$ ]] || [ "$((10#$keep_hours))" -gt 168 ]; then
  problem "input keep_hours '${KEEP_HOURS:-}' must be a whole number from 0 to 168"
  keep_hours=0
fi
keep_hours=$((10#$keep_hours))

tier=${TIER:-all}
case "$tier" in
  smoke | core | resilience | ingredients | lifecycle | ha | all) ;;
  *) problem "input tier '$tier' must be smoke, core, resilience, ingredients, lifecycle, ha or all" ;;
esac

hub_nodes=${HUB_NODES:-1}
case "$hub_nodes" in
  1) core_node_size="" ;;
  3) core_node_size=Standard_D4s_v5 ;;
  *)
    problem "input hub_nodes '$hub_nodes' must be 1 (single-node run) or 3 (HA run)"
    core_node_size=""
    ;;
esac

if [ "$tier" = ha ] && [ "$hub_nodes" != 3 ]; then
  problem "input tier ha needs hub_nodes 3: the ha tier tests the HA run's hubs, and a single-node run would skip every scenario"
fi

dispatch_flags=off
case "${DISPATCH_FLAGS:-false}" in
  true) dispatch_flags=on ;;
  false | "") ;;
  *) problem "input dispatch_flags '${DISPATCH_FLAGS}' must be true or false" ;;
esac

# The hardened ingress ranges. The same rule as uat/tofu (variables.tf), so a
# bad range fails here, before anything is created.
public_ingress=internet
public_ingress_cidrs="[]"
cidrs=()
raw=${INGRESS_CIDRS:-}
raw=${raw//,/ }
for c in $raw; do
  if ! [[ "$c" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})/(0|[1-9][0-9]?)$ ]]; then
    problem "input ingress_cidrs: '$c' is not an IPv4 range a.b.c.d/N"
    continue
  fi
  o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]} bits=${BASH_REMATCH[5]}
  if [ "$o1" -gt 255 ] || [ "$o2" -gt 255 ] || [ "$o3" -gt 255 ] || [ "$o4" -gt 255 ]; then
    problem "input ingress_cidrs: '$c' is not an IPv4 range a.b.c.d/N"
    continue
  fi
  if [ "$bits" -lt 8 ] || [ "$bits" -gt 32 ]; then
    problem "input ingress_cidrs: '$c' must be a /8 to a /32 (leave ingress_cidrs empty to open the ports to the Internet)"
    continue
  fi
  addr=$(((o1 << 24) | (o2 << 16) | (o3 << 8) | o4))
  host=$(((1 << (32 - bits)) - 1))
  if [ $((addr & host)) -ne 0 ]; then
    problem "input ingress_cidrs: '$c' has host bits set"
    continue
  fi
  for seen in "${cidrs[@]}"; do
    if [ "$seen" = "$c" ]; then
      problem "input ingress_cidrs: '$c' is repeated"
      continue 2
    fi
  done
  cidrs+=("$c")
done
if [ "${#cidrs[@]}" -gt 50 ]; then
  problem "input ingress_cidrs: ${#cidrs[@]} ranges is more than 50"
elif [ "${#cidrs[@]}" -gt 0 ]; then
  public_ingress=cidrs
  # Each range is digits, dots and a slash only (checked above), so it needs
  # no JSON escaping.
  public_ingress_cidrs="[$(printf '"%s",' "${cidrs[@]}")"
  public_ingress_cidrs="${public_ingress_cidrs%,}]"
fi

# Scenario ids reach uat/tests/run.sh as separate arguments, so only plain ids
# get through; run.sh itself rejects an id that is not in the tier.
scenarios=""
raw=${SCENARIOS:-}
raw=${raw//,/ }
count=0
for id in $raw; do
  count=$((count + 1))
  if ! [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]]; then
    problem "input scenarios: '$id' is not a scenario id (letters, digits, '.', '_' and '-' only)"
    continue
  fi
  scenarios+="${scenarios:+ }$id"
done
[ "$count" -le 200 ] || problem "input scenarios: $count ids is more than 200"

if [ "${#problems[@]}" -gt 0 ]; then
  for p in "${problems[@]}"; do
    echo "::error::$p"
  done
  echo "$prog: ${#problems[@]} problem(s); nothing was created" >&2
  exit 1
fi

destroy=true
[ "$keep_hours" -eq 0 ] || destroy=false
run_budget_hours=7
[ "$tier" != smoke ] || run_budget_hours=3

out=$(
  cat <<EOF
release_tag=$release_tag
region=$region
keep_hours=$keep_hours
tier=$tier
upgrade_from_tag=$upgrade_from_tag
scenarios=$scenarios
hub_nodes=$hub_nodes
dispatch_flags=$dispatch_flags
public_ingress=$public_ingress
public_ingress_cidrs=$public_ingress_cidrs
core_node_count=$hub_nodes
dmz_node_count=$hub_nodes
core_node_size=$core_node_size
destroy=$destroy
run_budget_hours=$run_budget_hours
EOF
)
echo "$out"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "$out" >>"$GITHUB_OUTPUT"
fi
