#!/usr/bin/env bash
# destroy.sh: tear down one UAT run and prove nothing is left (UAT.1).
#
#   uat/tofu/destroy.sh [--skip-init] <run_id>
#
# 1. tofu init against the run's state blob (imas-uat/<run_id>.tfstate in the
#    bootstrap storage account), unless --skip-init (the caller's working
#    directory is already initialised for this run), then tofu destroy.
# 2. If the resource group imas-uat-<run_id> still exists (destroy failed, or
#    the state was lost), delete it with az group delete. It only does so when
#    the group carries purpose=imas-uat and run_id=<run_id>; a group without
#    those tags is never touched.
# 3. Checks, with retries, that the group is gone and that no resource tagged
#    run_id=<run_id> remains anywhere in the subscription.
#
# Exit status: 0 when nothing is left (a fallback deletion still exits 0 but
# says so loudly); 1 when something remains; 2 on a usage error; 3 when the
# group exists without the UAT tags and was left alone.
#
# Environment:
#   TFSTATE_RESOURCE_GROUP   bootstrap group (default imas-uat-state)
#   TFSTATE_STORAGE_ACCOUNT  state account (default: looked up in that group by
#                            its purpose=imas-uat-state tag)
#   TFSTATE_CONTAINER        state container (default tfstate)
#   TOFU_DIR                 the main stack (default: this script's directory)
#   DESTROY_VERIFY_ATTEMPTS  checks before giving up (default 10)
#   DESTROY_VERIFY_INTERVAL  seconds between checks (default 30)
#   ARM_* / az login         Azure auth, as for tofu apply. Nothing is hard coded.
set -euo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "$0")" && pwd)

usage() {
  echo "usage: $prog [--skip-init] <run_id>" >&2
  exit 2
}

log() { echo "$prog: $*" >&2; }

skip_init=0
run_id=""
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-init) skip_init=1 ;;
    -h | --help) usage ;;
    -*) log "unknown option $1"; usage ;;
    *)
      [ -z "$run_id" ] || { log "only one run_id"; usage; }
      run_id=$1
      ;;
  esac
  shift
done
[ -n "$run_id" ] || usage
if ! [[ "$run_id" =~ ^[a-z0-9]{6,10}$ ]]; then
  log "run_id must be 6 to 10 lowercase letters and digits: '$run_id'"
  exit 2
fi

rg="imas-uat-$run_id"
tofu_dir=${TOFU_DIR:-$here}
attempts=${DESTROY_VERIFY_ATTEMPTS:-10}
interval=${DESTROY_VERIFY_INTERVAL:-30}
state_rg=${TFSTATE_RESOURCE_GROUP:-imas-uat-state}
state_container=${TFSTATE_CONTAINER:-tfstate}

for tool in tofu az jq; do
  command -v "$tool" >/dev/null 2>&1 || { log "$tool is not on PATH"; exit 2; }
done

# Destroy does not depend on these, but the configuration requires them. The
# caller's own values win.
export TF_VAR_run_id="$run_id"
export TF_VAR_release_tag="${TF_VAR_release_tag:-v0.0.0}"
export TF_VAR_runner_cidr="${TF_VAR_runner_cidr:-192.0.2.1/32}"

tofu_ok=1

# Step 1: tofu destroy.
if [ "$skip_init" -eq 0 ]; then
  account=${TFSTATE_STORAGE_ACCOUNT:-}
  if [ -z "$account" ]; then
    account=$(az storage account list --resource-group "$state_rg" \
      --query "[?tags.purpose=='imas-uat-state'].name | [0]" -o tsv 2>/dev/null || true)
  fi
  if [ -z "$account" ]; then
    log "no state storage account found in $state_rg; skipping tofu, going to the az fallback"
    tofu_ok=0
  elif ! tofu -chdir="$tofu_dir" init -input=false -reconfigure \
    -backend-config="resource_group_name=$state_rg" \
    -backend-config="storage_account_name=$account" \
    -backend-config="container_name=$state_container" \
    -backend-config="key=imas-uat/$run_id.tfstate" >&2; then
    log "tofu init failed; going to the az fallback"
    tofu_ok=0
  fi
fi

if [ "$tofu_ok" -eq 1 ]; then
  if tofu -chdir="$tofu_dir" destroy -auto-approve -input=false -no-color >&2; then
    log "tofu destroy finished"
  else
    log "tofu destroy failed; going to the az fallback"
    tofu_ok=0
  fi
fi

# Prints true, false, or unknown when az cannot answer.
group_state() {
  local out
  out=$(az group exists --name "$rg" -o tsv 2>/dev/null) || out=unknown
  case "$out" in
    true | false) echo "$out" ;;
    *) echo unknown ;;
  esac
}

# Step 2: the fallback, only for a group that is ours.
fallback=0
state=$(group_state)
if [ "$state" = unknown ]; then
  log "cannot tell whether $rg exists (az group exists failed); not deleting anything"
elif [ "$state" = true ]; then
  tags=$(az group show --name "$rg" --query tags -o json 2>/dev/null || echo '{}')
  purpose=$(printf '%s' "$tags" | jq -r '.purpose // empty' 2>/dev/null || true)
  tag_run=$(printf '%s' "$tags" | jq -r '.run_id // empty' 2>/dev/null || true)
  if [ "$purpose" != "imas-uat" ] || [ "$tag_run" != "$run_id" ]; then
    log "REFUSING to delete $rg: its tags are purpose='$purpose' run_id='$tag_run', not purpose=imas-uat run_id=$run_id"
    exit 3
  fi
  log "resource group $rg still exists; deleting it with az group delete"
  fallback=1
  if ! az group delete --name "$rg" --yes \
    --force-deletion-types Microsoft.Compute/virtualMachines >&2; then
    log "az group delete returned an error; checking what is left"
  fi
fi

# Step 3: verify. Deletions can take a while to show, so check a few times.
remaining=""
for ((i = 1; i <= attempts; i++)); do
  remaining=$(az resource list --tag "run_id=$run_id" --query "[].id" -o tsv 2>/dev/null) || remaining="(az resource list failed)"
  case "$(group_state)" in
    false) ;;
    true) remaining=$(printf '%s\n%s' "resource group $rg" "$remaining") ;;
    *) remaining=$(printf '%s\n%s' "resource group $rg (az group exists failed)" "$remaining") ;;
  esac
  remaining=$(printf '%s\n' "$remaining" | sed '/^[[:space:]]*$/d')
  [ -z "$remaining" ] && break
  if [ "$i" -lt "$attempts" ]; then
    log "still present (check $i of $attempts), waiting ${interval}s"
    sleep "$interval"
  fi
done

if [ -n "$remaining" ]; then
  log "FAILED: these remain for run_id=$run_id:"
  printf '%s\n' "$remaining" | sed 's/^/  /' >&2
  exit 1
fi

if [ "$fallback" -eq 1 ] || [ "$tofu_ok" -eq 0 ]; then
  log "WARNING: tofu destroy did not finish cleanly; az group delete removed $rg. Run state imas-uat/$run_id.tfstate may still list resources."
fi
log "run $run_id is gone: no resource group $rg and nothing tagged run_id=$run_id"
