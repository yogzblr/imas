#!/usr/bin/env bash
# tofu-outputs.sh: hands uat/tofu's outputs to the rest of the UAT workflow
# (.github/workflows/uat.yml, after tofu apply). Run from the repository root.
#
#   tofu-outputs.sh outputs STATE
#       writes STATE/uat.json, STATE/ha_node_names.json and
#       STATE/object_store.json (no credential in any of them)
#   tofu-outputs.sh credentials STATE SECRETS
#       writes SECRETS/ssh_key and SECRETS/winrm_password (0600) and, when
#       STATE/object_store.json is an object (the HA run), the storage
#       account's name and key under STATE/hub/core/sensitive/azure-blob/.
#       Every secret is masked (::add-mask::) before it is used.
#
# uat/tofu/outputs.tf gives object_store the value null in the single-node
# run, and OpenTofu does not store a null output in state: `tofu output -json
# object_store` then fails with 'Output "object_store" not found'. So
# object_store is read from the full `tofu output -json` (piped, never
# written: it holds the sensitive outputs too), and a missing or null output
# writes null. uat and ha_node_names are objects for every node count and
# object_store_account_key is a string (empty in the single-node run), so
# those keep the direct call, which fails loudly if one is ever missing.
#
# TOFU_DIR (default uat/tofu) is the tofu root.
set -euo pipefail

prog=$(basename "$0")
die() { echo "$prog: $*" >&2; exit 1; }
usage() { die "usage: $prog outputs STATE | $prog credentials STATE SECRETS"; }

TOFU_DIR=${TOFU_DIR:-uat/tofu}
out() { tofu -chdir="$TOFU_DIR" output "$@"; }

outputs() {
  local state=$1
  out -json uat >"$state/uat.json"
  # The VMs the HA tests stop (empty lists for a single-node hub).
  out -json ha_node_names >"$state/ha_node_names.json"
  # The HA run's Azure Blob account for Versity Gateway (null in the
  # single-node run, which keeps RustFS). Name only; the key is read by
  # credentials.
  out -json | jq '.object_store.value // null' >"$state/object_store.json"
  jq -e 'type == "null" or (type == "object" and (.account_name | strings | length > 0))' \
    "$state/object_store.json" >/dev/null ||
    die "tofu output object_store is neither null nor an object with account_name"
}

credentials() {
  local state=$1 secrets=$2 line pw key blob
  umask 077
  out -raw ssh_private_key >"$secrets/ssh_key"
  while IFS= read -r line; do
    case "$line" in -----*) ;; ?????*) echo "::add-mask::$line" ;; esac
  done <"$secrets/ssh_key"
  pw=$(out -raw windows_admin_password)
  echo "::add-mask::$pw"
  printf '%s' "$pw" >"$secrets/winrm_password"
  unset pw
  # The HA run's storage account (uat/tofu object-store.tf): its name and key
  # for Versity Gateway, where uat/hub/core/install.sh reads them
  # (<state>/hub/core/sensitive/azure-blob). The key is masked first.
  if [ "$(jq -r 'type' "$state/object_store.json")" = object ]; then
    blob="$state/hub/core/sensitive/azure-blob"
    mkdir -p "$blob"
    key=$(out -raw object_store_account_key)
    [ -n "$key" ] || die "object_store is set but object_store_account_key is empty"
    echo "::add-mask::$key"
    printf '%s' "$key" >"$blob/account-key"
    unset key
    jq -j .account_name "$state/object_store.json" >"$blob/account-name"
  fi
}

case "${1:-}" in
  outputs) [ $# -eq 2 ] || usage; outputs "$2" ;;
  credentials) [ $# -eq 3 ] || usage; credentials "$2" "$3" ;;
  *) usage ;;
esac
