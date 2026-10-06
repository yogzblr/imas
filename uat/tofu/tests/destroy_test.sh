#!/usr/bin/env bash
# Tests uat/tofu/destroy.sh against stubbed tofu and az (tests/stubs). Nothing
# reaches Azure. Run: bash uat/tofu/tests/destroy_test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/../destroy.sh"
stubs="$here/stubs"

pass=0
fail=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ok() { pass=$((pass + 1)); echo "ok   - $1"; }
nok() { fail=$((fail + 1)); echo "FAIL - $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /'; }

# new_case sets STUB_STATE to a fresh directory with the default "clean" world:
# the state account exists, tofu destroy succeeds and removes everything.
new_case() {
  STUB_STATE="$work/$1"
  mkdir -p "$STUB_STATE"
  echo imasuatstateabc12345 >"$STUB_STATE/account"
  echo true >"$STUB_STATE/group_exists"
  echo '{"purpose":"imas-uat","run_id":"abc123","expires_at":"2026-10-06T12:00:00Z"}' >"$STUB_STATE/group_tags"
  printf '%s\n' "/subscriptions/x/resourceGroups/imas-uat-abc123/providers/Microsoft.Compute/virtualMachines/uat-dmz" >"$STUB_STATE/leftovers"
  echo 0 >"$STUB_STATE/destroy_rc"
  touch "$STUB_STATE/destroy_clears"
  : >"$STUB_STATE/calls.log"
  export STUB_STATE
}

# run_destroy runs the script with the stubs first on PATH; sets rc and out.
run_destroy() {
  out=$(PATH="$stubs:$PATH" DESTROY_VERIFY_ATTEMPTS=2 DESTROY_VERIFY_INTERVAL=0 \
    TFSTATE_STORAGE_ACCOUNT="${TFSTATE_STORAGE_ACCOUNT:-}" bash "$script" "$@" 2>&1)
  rc=$?
}

calls() { cat "$STUB_STATE/calls.log"; }

# Branch 1: tofu destroy succeeds, the group is gone, nothing tagged remains.
new_case clean
run_destroy abc123
if [ "$rc" -eq 0 ]; then ok "clean destroy exits 0"; else nok "clean destroy exits 0 (rc=$rc)" "$out"; fi
if calls | grep -q "tofu -chdir=.* init -input=false -reconfigure .*storage_account_name=imasuatstateabc12345.*key=imas-uat/abc123.tfstate"; then
  ok "init points at the run's state blob in the looked-up account"
else nok "init points at the run's state blob" "$(calls)"; fi
if calls | grep -q "az storage account list --resource-group imas-uat-state"; then ok "state account looked up in imas-uat-state"; else nok "state account lookup" "$(calls)"; fi
if calls | grep -q "tofu -chdir=.* destroy -auto-approve -input=false"; then ok "runs tofu destroy -auto-approve"; else nok "runs tofu destroy" "$(calls)"; fi
if ! calls | grep -q "az group delete"; then ok "no fallback when tofu destroy is clean"; else nok "no fallback when clean" "$(calls)"; fi
if calls | grep -q "az resource list --tag run_id=abc123"; then ok "checks for anything tagged run_id"; else nok "checks tags" "$(calls)"; fi

# Branch 2: tofu destroy fails, the group (ours) remains: az group delete.
new_case fallback
echo 1 >"$STUB_STATE/destroy_rc"
touch "$STUB_STATE/delete_clears"
run_destroy abc123
if [ "$rc" -eq 0 ]; then ok "fallback that cleans up exits 0"; else nok "fallback exits 0 (rc=$rc)" "$out"; fi
if calls | grep -q "az group delete --name imas-uat-abc123 --yes"; then ok "falls back to az group delete imas-uat-<run_id>"; else nok "falls back to az group delete" "$(calls)"; fi
if printf '%s' "$out" | grep -q WARNING; then ok "fallback is reported loudly"; else nok "fallback warning" "$out"; fi

# Branch 2b: tofu destroy "succeeds" but the group is still there.
new_case stale_state
rm -f "$STUB_STATE/destroy_clears"
touch "$STUB_STATE/delete_clears"
run_destroy abc123
if [ "$rc" -eq 0 ] && calls | grep -q "az group delete --name imas-uat-abc123"; then
  ok "group left after a clean tofu destroy is deleted too"
else nok "group left after clean destroy" "rc=$rc $out"; fi

# Branch 3: something tagged with the run_id remains: non zero, listed.
new_case leftovers
echo 1 >"$STUB_STATE/destroy_rc"
echo 0 >"$STUB_STATE/delete_rc"
# The run's group is gone, but a resource tagged with the run_id sits in
# another group (where neither tofu nor the fallback looks).
echo "/subscriptions/x/resourceGroups/elsewhere/providers/Microsoft.Network/publicIPAddresses/stray" >"$STUB_STATE/leftovers"
echo false >"$STUB_STATE/group_exists"
run_destroy abc123
if [ "$rc" -eq 1 ]; then ok "leftover tagged resource exits 1"; else nok "leftover exits 1 (rc=$rc)" "$out"; fi
if printf '%s' "$out" | grep -q "publicIPAddresses/stray"; then ok "leftovers are listed"; else nok "leftovers listed" "$out"; fi

# Branch 3b: the group survives az group delete.
new_case undeletable
echo 1 >"$STUB_STATE/destroy_rc"
echo 1 >"$STUB_STATE/delete_rc"
run_destroy abc123
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "resource group imas-uat-abc123"; then
  ok "a group that survives az group delete exits 1"
else nok "surviving group exits 1 (rc=$rc)" "$out"; fi

# Safety: a group without our tags is never deleted.
new_case foreign
echo 1 >"$STUB_STATE/destroy_rc"
echo '{"purpose":"something-else","run_id":"abc123"}' >"$STUB_STATE/group_tags"
run_destroy abc123
if [ "$rc" -eq 3 ] && ! calls | grep -q "az group delete"; then ok "refuses a group without purpose=imas-uat"; else nok "refuses foreign group (rc=$rc)" "$(calls)"; fi

new_case wrong_run
echo 1 >"$STUB_STATE/destroy_rc"
echo '{"purpose":"imas-uat","run_id":"zzz999"}' >"$STUB_STATE/group_tags"
run_destroy abc123
if [ "$rc" -eq 3 ] && ! calls | grep -q "az group delete"; then ok "refuses a group tagged with another run_id"; else nok "refuses other run_id (rc=$rc)" "$(calls)"; fi

# az cannot answer: never delete, never report success.
new_case az_down
echo 1 >"$STUB_STATE/destroy_rc"
echo error >"$STUB_STATE/group_exists"
run_destroy abc123
if [ "$rc" -eq 1 ] && ! calls | grep -q "az group delete"; then ok "az errors fail closed"; else nok "az errors fail closed (rc=$rc)" "$out"; fi

# No state account: skip tofu, still clean up through the fallback.
new_case no_account
: >"$STUB_STATE/account"
touch "$STUB_STATE/delete_clears"
run_destroy abc123
if [ "$rc" -eq 0 ] && ! calls | grep -q "^tofu" && calls | grep -q "az group delete"; then
  ok "no state account: az fallback only"
else nok "no state account (rc=$rc)" "$(calls)"; fi

# --skip-init: no init, destroy only; explicit account is not looked up.
new_case skip_init
run_destroy --skip-init abc123
if [ "$rc" -eq 0 ] && ! calls | grep -q " init " && ! calls | grep -q "storage account list"; then
  ok "--skip-init runs destroy without init"
else nok "--skip-init (rc=$rc)" "$(calls)"; fi

new_case explicit_account
TFSTATE_STORAGE_ACCOUNT=givenaccount run_destroy abc123
if [ "$rc" -eq 0 ] && calls | grep -q "storage_account_name=givenaccount" && ! calls | grep -q "storage account list"; then
  ok "TFSTATE_STORAGE_ACCOUNT is used as given"
else nok "explicit account (rc=$rc)" "$(calls)"; fi

# Argument handling.
new_case args
run_destroy
if [ "$rc" -eq 2 ]; then ok "no run_id: usage, exit 2"; else nok "no run_id (rc=$rc)" "$out"; fi
for bad in ABC123 abc12 abcdefghijk "abc-123" "abc123;rm"; do
  run_destroy "$bad"
  if [ "$rc" -eq 2 ] && ! calls | grep -q "^tofu\|group delete"; then ok "rejects run_id '$bad'"; else nok "rejects run_id '$bad' (rc=$rc)" "$out"; fi
done
run_destroy abc123 def456
if [ "$rc" -eq 2 ]; then ok "two run_ids: exit 2"; else nok "two run_ids (rc=$rc)" "$out"; fi
run_destroy --bogus abc123
if [ "$rc" -eq 2 ]; then ok "unknown option: exit 2"; else nok "unknown option (rc=$rc)" "$out"; fi

echo
echo "destroy_test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
