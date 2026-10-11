#!/usr/bin/env bash
# az-relogin.sh: log the az CLI in again from the GitHub Actions OIDC token.
#
# An az session made from a GitHub OIDC token stops renewing about ten
# minutes after the login (AADSTS700024: the client assertion is past its
# validity), and the tests run for much longer. vmctl.sh calls this when it
# sees that error (UAT_AZ_RELOGIN names this script), then repeats the call.
#
#   az-relogin.sh
#
# Several vmctl.sh processes run at once and hit the error together, so the
# login is serialised with flock and skipped when another process logged in
# less than AZ_RELOGIN_MIN_AGE seconds ago.
#
# Environment:
#   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN
#                          set by Actions for a job with id-token: write
#   AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
#   AZ                     az command (default az)
#   AZ_RELOGIN_MIN_AGE     seconds (default 60)
#   AZ_RELOGIN_DIR         lock and stamp directory (default $RUNNER_TEMP or /tmp)
set -euo pipefail

prog=$(basename "$0")
AZ=${AZ:-az}
min_age=${AZ_RELOGIN_MIN_AGE:-60}
dir=${AZ_RELOGIN_DIR:-${RUNNER_TEMP:-/tmp}}
log() { echo "$prog: $*" >&2; }

for v in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID; do
  [ -n "${!v:-}" ] || { log "$v is not set"; exit 2; }
done

stamp="$dir/az-relogin.stamp"
exec 9>"$dir/az-relogin.lock"
flock 9
if [ -f "$stamp" ]; then
  age=$(($(date +%s) - $(stat -c %Y "$stamp")))
  if [ "$age" -lt "$min_age" ]; then
    log "another process logged in ${age}s ago; not repeating it"
    exit 0
  fi
fi

sep='?'
case "$ACTIONS_ID_TOKEN_REQUEST_URL" in *\?*) sep='&' ;; esac
token=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}${sep}audience=api://AzureADTokenExchange" | jq -r '.value // empty')
[ -n "$token" ] || { log "no OIDC token in the answer"; exit 1; }
echo "::add-mask::$token"

"$AZ" login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
  --federated-token "$token" --allow-no-subscriptions -o none
"$AZ" account set --subscription "$AZURE_SUBSCRIPTION_ID"
touch "$stamp"
log "logged in again"
