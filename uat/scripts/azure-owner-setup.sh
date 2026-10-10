#!/usr/bin/env bash
# azure-owner-setup.sh: the Azure side of the owner prerequisites of the UAT
# gate (uat/README.md, "Owner prerequisites", steps 1 to 3 and the OIDC part of
# 7). Run it ONCE, by hand, as the subscription Owner, on a subscription used
# for UAT only. It is not used by any workflow.
#
#   azure-owner-setup.sh [--subscription ID] [--repo OWNER/REPO]
#                        [--no-janitor] [--accept-image-terms] [--yes]
#
#   --subscription ID     the subscription to use (default: the az CLI's
#                         current one, after az login)
#   --repo OWNER/REPO     the GitHub repository (default yogzblr/imas)
#   --no-janitor          do not add the federated credential of the
#                         uat-janitor environment
#   --accept-image-terms  also accept the AlmaLinux marketplace terms
#                         (az vm image terms accept ...). Confirm the image
#                         URNs first, see uat/tofu/README.md, Inputs.
#   --yes                 do not ask before changing anything
#
# What it does, each step only when it is not already done (so a second run
# changes nothing):
#   1. az login with a device code, if the CLI is not logged in (works in WSL,
#      where there is no browser on the Linux side);
#   2. shows the subscription and asks before it changes anything;
#   3. registers the resource providers Compute, Network, Storage,
#      Authorization and Consumption (registration finishes in the background);
#   4. creates the app registration imas-uat-github and its service principal;
#   5. gives the service principal Contributor on the subscription;
#   6. adds the federated credentials, which are the only link between Azure
#      and GitHub: subjects repo:OWNER/REPO:environment:uat and, unless
#      --no-janitor, repo:OWNER/REPO:environment:uat-janitor. No client secret
#      is created.
# It then prints the three values for the GitHub environments' variables and
# the service principal's object id for the bootstrap stack
# (uat/tofu/README.md, "Bootstrap, once"). It never prints a secret, and
# creates none.
#
# Environment: AZ (default az); SETUP_RETRY_SLEEP (seconds between the retries
# of the role assignment, default 10; a new service principal can take a
# while to be visible).
#
# Exit status: 0 when everything is in place; 1 on a usage error, a refused
# confirmation or any failed step.
set -euo pipefail

prog=$(basename "$0")
az_cmd=${AZ:-az}
app_name=imas-uat-github
repo=yogzblr/imas
sub=""
janitor=1
terms=0
yes=0

die() {
  echo "$prog: $*" >&2
  exit 1
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
}

while [ $# -gt 0 ]; do
  case $1 in
    --subscription)
      [ $# -ge 2 ] || die "--subscription needs a value"
      sub=$2
      shift
      ;;
    --repo)
      [ $# -ge 2 ] || die "--repo needs a value"
      repo=$2
      shift
      ;;
    --no-janitor) janitor=0 ;;
    --accept-image-terms) terms=1 ;;
    --yes) yes=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown argument: $1"
      ;;
  esac
  shift
done

guid='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
[[ $repo =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "--repo must be OWNER/REPO, got '$repo'"
if [ -n "$sub" ]; then
  [[ $sub =~ $guid ]] || die "--subscription must be a subscription id (a GUID), got '$sub'"
fi

command -v "$az_cmd" >/dev/null 2>&1 ||
  die "the Azure CLI ($az_cmd) is not installed; see https://learn.microsoft.com/cli/azure/install-azure-cli-linux"

# 1. Login.
if ! "$az_cmd" account show >/dev/null 2>&1; then
  echo "Not logged in to Azure. Starting a device code login: open the URL it prints in any browser."
  "$az_cmd" login --use-device-code -o none || die "az login failed"
fi
if [ -n "$sub" ]; then
  "$az_cmd" account set --subscription "$sub" || die "cannot select subscription $sub"
fi

# 2. The subscription, and the confirmation.
sub=$("$az_cmd" account show --query id -o tsv) || die "cannot read the current subscription"
sub_name=$("$az_cmd" account show --query name -o tsv) || die "cannot read the subscription name"
tenant=$("$az_cmd" account show --query tenantId -o tsv) || die "cannot read the tenant id"
[[ $sub =~ $guid ]] || die "az returned an unexpected subscription id: '$sub'"
[[ $tenant =~ $guid ]] || die "az returned an unexpected tenant id: '$tenant'"

echo
echo "Subscription: $sub_name ($sub)"
echo "Tenant:       $tenant"
echo "Repository:   $repo"
echo
echo "This will, where it is not already done:"
echo "  - register five resource providers;"
echo "  - create the app registration and service principal $app_name;"
echo "  - give it the Contributor role on the WHOLE subscription (use a subscription for UAT only);"
echo "  - add a federated credential for repo:$repo:environment:uat"
[ "$janitor" -eq 1 ] && echo "  - add a federated credential for repo:$repo:environment:uat-janitor"
[ "$terms" -eq 1 ] && echo "  - accept the AlmaLinux marketplace terms"
echo
if [ "$yes" -ne 1 ]; then
  printf 'Proceed? [y/N] '
  ans=""
  read -r ans || ans=""
  case $ans in
    y | Y | yes | YES) ;;
    *) die "not confirmed; nothing was changed" ;;
  esac
fi

# 3. Resource providers.
for ns in Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.Authorization Microsoft.Consumption; do
  "$az_cmd" provider register --namespace "$ns" || die "cannot register $ns"
  echo "provider $ns: registration requested"
done

# 4. The app registration and its service principal.
mapfile -t apps < <("$az_cmd" ad app list --display-name "$app_name" --query "[].appId" -o tsv)
case ${#apps[@]} in
  0)
    app_id=$("$az_cmd" ad app create --display-name "$app_name" --query appId -o tsv) ||
      die "cannot create the app registration (does your account have the right to create applications in this tenant?)"
    echo "app registration $app_name: created"
    ;;
  1)
    app_id=${apps[0]}
    echo "app registration $app_name: already there"
    ;;
  *) die "more than one app registration is named $app_name; remove the extra ones in the portal and run again" ;;
esac
[[ $app_id =~ $guid ]] || die "az returned an unexpected application id: '$app_id'"

if "$az_cmd" ad sp show --id "$app_id" >/dev/null 2>&1; then
  echo "service principal: already there"
else
  "$az_cmd" ad sp create --id "$app_id" -o none || die "cannot create the service principal"
  echo "service principal: created"
fi
sp_oid=$("$az_cmd" ad sp show --id "$app_id" --query id -o tsv) || die "cannot read the service principal's object id"

# 5. Contributor on the subscription. A new service principal can take a
# while to be visible, so the assignment is retried.
scope="/subscriptions/$sub"
have=$("$az_cmd" role assignment list --assignee "$sp_oid" --role Contributor --scope "$scope" --query "length(@)" -o tsv) ||
  die "cannot list role assignments"
if [ "${have:-0}" -gt 0 ]; then
  echo "Contributor on the subscription: already there"
else
  assigned=0
  for attempt in 1 2 3 4 5 6; do
    if "$az_cmd" role assignment create --assignee-object-id "$sp_oid" --assignee-principal-type ServicePrincipal \
      --role Contributor --scope "$scope" -o none; then
      assigned=1
      break
    fi
    echo "role assignment attempt $attempt failed; the new service principal may not be visible yet" >&2
    sleep "${SETUP_RETRY_SLEEP:-10}"
  done
  [ "$assigned" -eq 1 ] || die "cannot assign Contributor on $scope (you need to be Owner of the subscription)"
  echo "Contributor on the subscription: assigned"
fi

# 6. The federated credentials.
existing=$("$az_cmd" ad app federated-credential list --id "$app_id" --query "[].subject" -o tsv) ||
  die "cannot list the federated credentials"

# ensure_federated NAME ENVIRONMENT
ensure_federated() {
  local name=$1 env=$2 subject params
  subject="repo:$repo:environment:$env"
  if grep -Fxq -- "$subject" <<<"$existing"; then
    echo "federated credential for $env: already there"
    return 0
  fi
  params=$(printf '{"name": "%s", "issuer": "https://token.actions.githubusercontent.com", "subject": "%s", "audiences": ["api://AzureADTokenExchange"]}' "$name" "$subject")
  "$az_cmd" ad app federated-credential create --id "$app_id" --parameters "$params" -o none ||
    die "cannot create the federated credential for $env"
  echo "federated credential for $env: created"
}
ensure_federated imas-uat-env uat
[ "$janitor" -eq 1 ] && ensure_federated imas-uat-janitor-env uat-janitor

# 7. Optional: the marketplace terms.
if [ "$terms" -eq 1 ]; then
  "$az_cmd" vm image terms accept --publisher almalinux --offer almalinux-x86_64 --plan 9-gen2 -o none ||
    die "cannot accept the AlmaLinux marketplace terms"
  echo "AlmaLinux marketplace terms: accepted"
fi

cat <<EOF

Done. Put these three values in the variables (not secrets) of the GitHub
environment uat$([ "$janitor" -eq 1 ] && echo " and of uat-janitor"):

  AZURE_CLIENT_ID=$app_id
  AZURE_TENANT_ID=$tenant
  AZURE_SUBSCRIPTION_ID=$sub

After the environments exist, with the GitHub CLI:

  gh variable set AZURE_CLIENT_ID       --env uat --repo $repo --body "$app_id"
  gh variable set AZURE_TENANT_ID       --env uat --repo $repo --body "$tenant"
  gh variable set AZURE_SUBSCRIPTION_ID --env uat --repo $repo --body "$sub"

For the bootstrap stack (uat/tofu/README.md, "Bootstrap, once"), the service
principal's object id is:

  $sp_oid

Still to do by hand: quota, the bootstrap stack, and the GitHub environments
(a required reviewer on uat, a deployment branch rule for main on both).
EOF
