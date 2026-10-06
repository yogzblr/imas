#!/usr/bin/env bash
# material.sh: complete the test suite's material directory (IMAS_UAT_DIR,
# uat/tests/README.md) for one run of the UAT workflow.
#
#   material.sh <uat.json> <endpoints.json> <enroll-state> <material-dir>
#
# <material-dir> is the core hub's state directory (uat/hub/core install.sh's
# <state-dir>), which already holds core/out/core.json and core/sensitive/.
# This adds what the other steps wrote:
#   uat.json        a copy of tofu output -json uat (UAT.1)
#   tenants.json    from <enroll-state> (UAT.4)
#   sprouts.json    from <enroll-state> (UAT.4)
#   harness.json    written here from uat.json and endpoints.json (UAT.2):
#     envoy_url             https://<dmz.fqdn>:<dmz.ports.envoy>: Envoy as the
#                           runner reaches it. The harness's own default has no
#                           port (443); this layout's Envoy is node port 8443.
#     sprout_envoy_address  dmz.<private_dns_zone>:<dmz.ports.envoy>: Envoy as
#                           a sprout dials it (X3's positive control), the
#                           private name the sprouts were enrolled with (UAT.4).
# An existing harness.json is kept and only these two keys are set in it.
#
# Nothing secret is read or written here.
set -euo pipefail

prog=$(basename "$0")
die() { echo "$prog: $*" >&2; exit 1; }

[ $# -eq 4 ] || { echo "usage: $prog <uat.json> <endpoints.json> <enroll-state> <material-dir>" >&2; exit 2; }
uat=$1 endpoints=$2 enroll=$3 material=$4

for f in "$uat" "$endpoints" "$enroll/tenants.json" "$enroll/sprouts.json"; do
  [ -s "$f" ] || die "missing or empty: $f"
  jq -e 'type == "object"' "$f" >/dev/null 2>&1 || die "not a JSON object: $f"
done
[ -d "$material" ] || die "not a directory: $material"
[ -s "$material/core/out/core.json" ] || [ -s "$material/core.json" ] ||
  die "$material holds no core.json: is it the core hub's state directory?"

fqdn=$(jq -r '.dmz.fqdn // empty' "$endpoints")
[ -n "$fqdn" ] || fqdn=$(jq -r '.dmz.fqdn // empty' "$uat")
[[ "$fqdn" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] ||
  die "dmz.fqdn '$fqdn' is not a DNS name"

port=$(jq -r '.dmz.ports.envoy // 8443' "$endpoints")
if ! [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$port" -gt 65535 ]; then
  die "dmz.ports.envoy '$port' is not a port"
fi

zone=$(jq -r '.private_dns_zone // empty' "$endpoints")
[ -n "$zone" ] || zone=$(jq -r '.private_dns_zone // empty' "$uat")
[ -n "$zone" ] || zone=uat.imas.internal
[[ "$zone" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] ||
  die "private_dns_zone '$zone' is not a DNS name"

umask 022
cp "$uat" "$material/uat.json"
cp "$enroll/tenants.json" "$material/tenants.json"
cp "$enroll/sprouts.json" "$material/sprouts.json"

harness="$material/harness.json"
[ -s "$harness" ] || echo '{}' >"$harness"
tmp=$(mktemp "$material/.harness.XXXXXX")
jq --arg envoy "https://$fqdn:$port" --arg sprout "dmz.$zone:$port" \
  '.envoy_url = $envoy | .sprout_envoy_address = $sprout' "$harness" >"$tmp"
mv "$tmp" "$harness"

echo "$prog: $material ready: uat.json, tenants.json, sprouts.json, harness.json (envoy_url https://$fqdn:$port, sprout_envoy_address dmz.$zone:$port)" >&2
