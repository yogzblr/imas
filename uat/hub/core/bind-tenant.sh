#!/usr/bin/env bash
# bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>
#
# Maps UAT tenant 1 or 2 to the tenant_id saasapi generated for it.
# saasapi takes the tenant from the token's organization.id claim and
# matches it against the path's {tenant_id} (docs/api/saasapi.md,
# "Authentication"); a tenant_id exists only after POST /v1/tenants, so the
# realm import can't carry it. This sets the user attribute organization_id
# (which the imas-uat-tests client's "organization-id" mapper puts in the
# token as organization.id) on t<N>-admin and t<N>-reader, and records the
# binding in <state>/core/out/core.json. Tokens fetched after this carry
# the claim. FLAG FOR SECURITY REVIEW (the UAT identity provider).
#
# The realm's user profile lets only an admin edit organization_id, so a
# user can't move themselves to another tenant. Keycloak is administered
# through kubectl exec only (kcadm.sh in the Keycloak pod, master realm,
# the generated admin password over stdin); the edge proxy never routes
# /admin or the master realm.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>" "$@"
[[ $# -ge 5 ]] || die "usage: bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>"
n="$4"
tenant_id="$5"
[[ "$n" == 1 || "$n" == 2 ]] || die "tenant number must be 1 or 2, not $n"
[[ "$tenant_id" =~ ^t_[a-z2-7]{16}$ ]] || die "not a saasapi tenant_id (t_ and 16 base32 characters): $tenant_id"
need_cmd kubectl jq
creds="$SENSITIVE_DIR/keycloak"
[[ -s "$creds/admin-password" ]] || die "no Keycloak admin password in $creds"

core_json="$OUT_DIR/core.json"
[[ -s "$core_json" ]] || die "no $core_json: run install.sh first"
other=$((3 - n))
bound_other=$(jq -r --arg o "$other" '.tenants[$o] // empty' "$core_json")
[[ "$bound_other" != "$tenant_id" ]] || die "$tenant_id is already bound to tenant $other: the two tenants must differ"

# kcadm <script>: a kcadm.sh session in the Keycloak pod. The first stdin
# line is the admin password.
kcadm() {
	{
		cat "$creds/admin-password"
		printf '\n'
	} | kc -n "$UAT_NS" exec -i "deploy/$KEYCLOAK_DEPLOY" -c keycloak -- /bin/bash -ec '
		IFS= read -r pw
		k=/opt/keycloak/bin/kcadm.sh
		cfg=$(mktemp)
		trap "rm -f \"$cfg\"" EXIT
		$k config credentials --config "$cfg" --server http://127.0.0.1:8080 --realm master --user "$1" --password "$pw" >/dev/null
		unset pw
		'"$1" _ "$(cat "$creds/admin-username")"
}

for role in admin reader; do
	user="t$n-$role"
	kcadm "
		id=\$(\$k get users --config \"\$cfg\" -r $REALM -q username=$user -q exact=true --fields id --format csv --noquotes)
		[ -n \"\$id\" ] || { echo 'no user $user' >&2; exit 1; }
		\$k update users/\$id --config \"\$cfg\" -r $REALM -s 'attributes.organization_id=[\"$tenant_id\"]'
		\$k get users/\$id --config \"\$cfg\" -r $REALM --fields attributes" >"$STATE_DIR/bind-$user.json" ||
		die "could not set organization_id on $user"
	got=$(jq -r '.attributes.organization_id[0] // empty' "$STATE_DIR/bind-$user.json")
	rm -f "$STATE_DIR/bind-$user.json"
	[[ "$got" == "$tenant_id" ]] || die "$user has organization_id '$got', not $tenant_id"
	log "$user -> organization.id $tenant_id"
done

tmp=$(mktemp "$OUT_DIR/core.json.XXXXXX")
jq --arg n "$n" --arg t "$tenant_id" '.tenants[$n] = $t' "$core_json" >"$tmp" && mv "$tmp" "$core_json"
log "tenant $n bound to $tenant_id (recorded in $core_json); fetch new tokens to get the claim"
