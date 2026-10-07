#!/usr/bin/env bash
# verify-teardown.sh: prove a UAT run left nothing behind in Azure.
#
#   verify-teardown.sh <run_id>
#
# Runs after uat/tofu/destroy.sh, as its own step, so the job fails on a
# leftover even if destroy.sh itself got it wrong. It passes only when, on
# the same check:
#   - the resource group imas-uat-<run_id> does not exist;
#   - no resource group is tagged run_id=<run_id>;
#   - no resource anywhere in the subscription is tagged run_id=<run_id>.
# Deletions take a while to show, so it checks up to VERIFY_ATTEMPTS times,
# VERIFY_INTERVAL seconds apart. An az call that fails counts as "something may
# remain" (fail closed). It deletes nothing.
#
# Environment: VERIFY_ATTEMPTS (default 10), VERIFY_INTERVAL (default 30),
# AZ (default az), and an az login to the subscription.
#
# Exit status: 0 when nothing remains; 1 listing what remains; 2 on a usage
# error.
set -euo pipefail

prog=$(basename "$0")
AZ=${AZ:-az}
attempts=${VERIFY_ATTEMPTS:-10}
interval=${VERIFY_INTERVAL:-30}

[ $# -eq 1 ] || { echo "usage: $prog <run_id>" >&2; exit 2; }
run_id=$1
[[ "$run_id" =~ ^[a-z0-9]{6,10}$ ]] || { echo "$prog: '$run_id' is not a run_id" >&2; exit 2; }
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || { echo "$prog: VERIFY_ATTEMPTS must be a positive number" >&2; exit 2; }
[[ "$interval" =~ ^[0-9]+$ ]] || { echo "$prog: VERIFY_INTERVAL must be a number" >&2; exit 2; }
rg="imas-uat-$run_id"

# leftovers: prints one line per thing that remains (or may remain).
leftovers() {
  local exists groups resources
  if exists=$($AZ group exists --name "$rg" -o tsv 2>/dev/null); then
    case "$exists" in
      false) ;;
      true) echo "resource group $rg" ;;
      *) echo "resource group $rg (az group exists answered '$exists')" ;;
    esac
  else
    echo "resource group $rg (az group exists failed)"
  fi
  if groups=$($AZ group list --tag "run_id=$run_id" --query "[].name" -o tsv 2>/dev/null); then
    printf '%s\n' "$groups" | sed '/^[[:space:]]*$/d' | sed 's/^/resource group tagged run_id: /'
  else
    echo "resource groups tagged run_id=$run_id (az group list failed)"
  fi
  if resources=$($AZ resource list --tag "run_id=$run_id" --query "[].id" -o tsv 2>/dev/null); then
    printf '%s\n' "$resources" | sed '/^[[:space:]]*$/d'
  else
    echo "resources tagged run_id=$run_id (az resource list failed)"
  fi
}

remaining=""
for ((i = 1; i <= attempts; i++)); do
  remaining=$(leftovers | sort -u)
  [ -z "$remaining" ] && break
  if [ "$i" -lt "$attempts" ]; then
    echo "$prog: something remains (check $i of $attempts), waiting ${interval}s" >&2
    sleep "$interval"
  fi
done

if [ -n "$remaining" ]; then
  echo "::error::$prog: teardown of run $run_id is incomplete; these remain:"
  printf '%s\n' "$remaining" | sed 's/^/  /'
  echo "$prog: delete them by hand (uat/README.md, 'Cleaning up by hand'); the janitor removes the group after its expires_at" >&2
  exit 1
fi
echo "$prog: run $run_id is gone: no group $rg, nothing tagged run_id=$run_id"
