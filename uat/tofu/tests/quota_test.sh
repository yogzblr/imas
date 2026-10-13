#!/usr/bin/env bash
# Tests uat/tofu/quota-check.sh against a stubbed az (tests/stubs/az) and the
# plan, SKU and usage fixtures in tests/testdata. Nothing reaches Azure.
# Run: bash uat/tofu/tests/quota_test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/../quota-check.sh"
stubs="$here/stubs"
data="$here/testdata"

pass=0
fail=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ok() { pass=$((pass + 1)); echo "ok   - $1"; }
nok() { fail=$((fail + 1)); echo "FAIL - $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /'; }

# new_case: a fresh STUB_STATE with the fixtures' SKUs and a usage of 20 Dsv5,
# 12 Bsv2 and 40 regional vCPUs, nothing in use.
new_case() {
  STUB_STATE="$work/$1"
  mkdir -p "$STUB_STATE"
  cp "$data/skus.json" "$STUB_STATE/skus.json"
  cp "$data/usage.json" "$STUB_STATE/usage.json"
  : >"$STUB_STATE/calls.log"
  export STUB_STATE
}

# set_usage NAME CURRENT LIMIT: one quota of usage.json.
set_usage() {
  jq --arg n "$1" --argjson c "$2" --argjson l "$3" \
    'map(if .name.value == $n then .currentValue = $c | .limit = $l else . end)' \
    "$STUB_STATE/usage.json" >"$STUB_STATE/usage.tmp" && mv "$STUB_STATE/usage.tmp" "$STUB_STATE/usage.json"
}

run_check() {
  out=$(PATH="$stubs:$PATH" bash "$script" "$@" 2>&1)
  rc=$?
}

has() { grep -qF -- "$1" <<<"$out"; }

# The single-node run: 10 Dsv5 (D2s_v5 + D8s_v5) and 12 Bsv2, 22 in all.
new_case single
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 0 ]; then ok "single-node plan fits 20 Dsv5 / 12 Bsv2 / 40 total"; else nok "single-node fits (rc=$rc)" "$out"; fi
if has "need   10" && has "need   12" && has "need   22"; then ok "prints 10 Dsv5, 12 Bsv2 and 22 regional vCPU needed"; else nok "single-node numbers" "$out"; fi
if grep -q "az vm list-skus --location centralindia --resource-type virtualMachines --size Standard_D8s_v5 --all" "$STUB_STATE/calls.log" &&
  grep -q "az vm list-usage --location centralindia" "$STUB_STATE/calls.log"; then
  ok "looks sizes up with list-skus --all and quotas with list-usage in the region"
else nok "az calls" "$(cat "$STUB_STATE/calls.log")"; fi

# The HA run (owner, 2026-10-13): 3 x D4s_v5 + 3 x D2s_v5 = 18 Dsv5.
new_case ha
run_check "$data/plan-ha.json" centralindia
if [ "$rc" -eq 0 ] && has "need   18" && has "need   30"; then ok "HA plan: 18 Dsv5 and 30 regional vCPU fit"; else nok "HA fits (rc=$rc)" "$out"; fi

# Today's quota (about 10 Dsv5): the HA run is refused with the numbers.
new_case ha_short
set_usage standardDSv5Family 0 10
run_check "$data/plan-ha.json" centralindia
if [ "$rc" -eq 1 ]; then ok "HA plan against 10 Dsv5 exits 1"; else nok "HA short exits 1 (rc=$rc)" "$out"; fi
if has "::error::quota short: Standard DSv5 Family vCPUs (standardDSv5Family) in centralindia: this run needs 18 vCPU, 0 of 10 are in use (10 free); request a limit of at least 18"; then
  ok "names the family, the vCPU needed, in use and the limit to request"
else nok "shortfall message" "$out"; fi
if ! has "Bsv2 Family vCPUs (standardBsv2Family) in centralindia: this run"; then ok "a family that fits is not reported short"; else nok "Bsv2 wrongly short" "$out"; fi

# In-use vCPUs count against the limit.
new_case in_use
set_usage standardBsv2Family 2 12
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 1 ] && has "this run needs 12 vCPU, 2 of 12 are in use (10 free); request a limit of at least 14"; then
  ok "vCPUs already in use count against the limit"
else nok "in use (rc=$rc)" "$out"; fi

# The regional total is checked on its own.
new_case total
set_usage cores 0 21
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 1 ] && has "Total Regional vCPUs (cores) in centralindia: this run needs 22 vCPU"; then
  ok "the Total Regional vCPUs quota is checked"
else nok "regional total (rc=$rc)" "$out"; fi

# A size the subscription may not use in the region.
new_case restricted
jq 'map(if .name == "Standard_D4s_v5" then .restrictions = [{"type": "Location", "reasonCode": "NotAvailableForSubscription", "values": ["centralindia"], "restrictionInfo": {"locations": ["centralindia"], "zones": null}}] else . end)' \
  "$data/skus.json" >"$STUB_STATE/skus.json"
run_check "$data/plan-ha.json" centralindia
if [ "$rc" -eq 1 ] && has "size Standard_D4s_v5 is not available to this subscription in centralindia (NotAvailableForSubscription)"; then
  ok "a size restricted in the region fails"
else nok "restricted size (rc=$rc)" "$out"; fi

# A zone the plan uses that the size is restricted in.
new_case zone
jq 'map(if .name == "Standard_D2s_v5" then .restrictions = [{"type": "Zone", "reasonCode": "NotAvailableForSubscription", "values": ["centralindia"], "restrictionInfo": {"locations": ["centralindia"], "zones": ["3"]}}] else . end)' \
  "$data/skus.json" >"$STUB_STATE/skus.json"
run_check "$data/plan-ha.json" centralindia
if [ "$rc" -eq 1 ] && has "size Standard_D2s_v5 is not available to this subscription in zone 3 of centralindia"; then
  ok "a zone restriction on a zone the plan uses fails"
else nok "zone restriction (rc=$rc)" "$out"; fi
new_case zone_unused
jq 'map(if .name == "Standard_D2s_v5" then .restrictions = [{"type": "Zone", "reasonCode": "NotAvailableForSubscription", "values": ["centralindia"], "restrictionInfo": {"locations": ["centralindia"], "zones": ["3"]}}] else . end)' \
  "$data/skus.json" >"$STUB_STATE/skus.json"
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 0 ]; then ok "a zone restriction does not matter to an unzoned VM"; else nok "zone unused (rc=$rc)" "$out"; fi

# A size that does not exist in the region (exact name only: list-skus
# --size also matches Standard_D2s_v5_promo).
new_case missing
jq 'map(select(.name != "Standard_D8s_v5"))' "$data/skus.json" >"$STUB_STATE/skus.json"
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 1 ] && has "size Standard_D8s_v5 is not offered in centralindia"; then ok "a size missing from the region fails"; else nok "missing size (rc=$rc)" "$out"; fi

# Nothing to create (a re-apply): no az call is needed.
new_case noop
run_check "$data/plan-noop.json" centralindia
if [ "$rc" -eq 0 ] && ! grep -q "az vm" "$STUB_STATE/calls.log"; then ok "a plan that creates no VM passes without asking az"; else nok "noop (rc=$rc)" "$out"; fi

# az cannot answer: fail closed.
new_case skus_down
touch "$STUB_STATE/skus_fail"
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 2 ]; then ok "list-skus failing exits 2 (fail closed)"; else nok "skus down (rc=$rc)" "$out"; fi
new_case usage_down
touch "$STUB_STATE/usage_fail"
run_check "$data/plan-single.json" centralindia
if [ "$rc" -eq 2 ]; then ok "list-usage failing exits 2 (fail closed)"; else nok "usage down (rc=$rc)" "$out"; fi

# Arguments.
new_case args
run_check
if [ "$rc" -eq 2 ]; then ok "no arguments: exit 2"; else nok "no arguments (rc=$rc)" "$out"; fi
run_check "$work/nope.json" centralindia
if [ "$rc" -eq 2 ]; then ok "unreadable plan: exit 2"; else nok "unreadable plan (rc=$rc)" "$out"; fi
echo '{' >"$work/bad.json"
run_check "$work/bad.json" centralindia
if [ "$rc" -eq 2 ]; then ok "a plan that is not JSON: exit 2"; else nok "bad plan (rc=$rc)" "$out"; fi
run_check "$data/plan-single.json" "Central India"
if [ "$rc" -eq 2 ]; then ok "a malformed region: exit 2"; else nok "bad region (rc=$rc)" "$out"; fi

echo
echo "quota_test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
