#!/usr/bin/env bash
# bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>
# bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> --scratch-user <username> <admin|readonly> <tenant_id>
#
# Maps Keycloak users to the tenant_id saasapi generated for a tenant.
# saasapi takes the tenant from the token's organization.id claim and
# matches it against the path's {tenant_id} (docs/api/saasapi.md,
# "Authentication"); a tenant_id exists only after POST /v1/tenants, so the
# realm import can't carry it. The user attribute organization_id is what
# the imas-uat-tests client's "organization-id" mapper puts in the token as
# organization.id. Tokens fetched after a binding carry the claim.
# FLAG FOR SECURITY REVIEW (the UAT identity provider).
#
# Tenant mode (<1|2>): sets organization_id on t<N>-admin and t<N>-reader
# and records the binding in out/core.json (.tenants) and
# sensitive/keycloak.json (.tenants.<N>.tenant_id). UAT.4 calls it for
# tenants 1 and 2.
#
# Scratch mode (--scratch-user, owner decision 2026-10-06): for a tenant
# created during a test run (uat/tests T1, T4, T5). Creates the user if it
# doesn't exist, with a password generated into
# sensitive/keycloak/scratch/<username>.password (0600), gives it the
# recipe roles of <admin> (read and write) or <readonly> (read), sets
# organization_id to <tenant_id>, records it in out/core.json
# (.scratch_users) and prints one JSON line on stdout:
#   {"username": ..., "tenant_id": ..., "role": "admin"|"readonly",
#    "password_file": "<abs path>"}
# The password itself is never printed. The name must start with
# "scratch-" (so the realm's own users can't be touched). Running it again
# for the same user and tenant is a no-op apart from re-setting the
# password from its file; a scratch user bound to another tenant is refused.
#
# The realm's user profile lets only an admin edit organization_id, so a
# user can't move themselves to another tenant. Keycloak is administered
# through kubectl exec only (kcadm.sh in the Keycloak pod, master realm, the
# generated admin password and any user password over stdin, never argv);
# the edge proxy never routes /admin or the master realm.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
usage="bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>
       bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> --scratch-user <username> <admin|readonly> <tenant_id>"
parse_common_args "$usage" "$@"
mode=tenant
if [[ "${4:-}" == --scratch-user ]]; then
	mode=scratch
	[[ $# -eq 7 ]] || die "usage: $usage"
	user="$5"
	role="$6"
	tenant_id="$7"
	[[ "$user" =~ ^scratch-[a-z0-9][a-z0-9-]{0,50}$ ]] ||
		die "scratch user names are scratch- and up to 51 lowercase letters, digits or dashes: $user"
	[[ "$role" == admin || "$role" == readonly ]] || die "role must be admin or readonly, not $role"
else
	[[ $# -eq 5 ]] || die "usage: $usage"
	n="$4"
	tenant_id="$5"
	[[ "$n" == 1 || "$n" == 2 ]] || die "tenant number must be 1 or 2, not $n"
fi
[[ "$tenant_id" =~ ^t_[a-z2-7]{16}$ ]] || die "not a saasapi tenant_id (t_ and 16 base32 characters): $tenant_id"
need_cmd kubectl jq
creds="$SENSITIVE_DIR/keycloak"
[[ -s "$creds/admin-password" ]] || die "no Keycloak admin password in $creds"
core_json="$OUT_DIR/core.json"
[[ -s "$core_json" ]] || die "no $core_json: run install.sh first"
# Tests point this at a fake; in the pod it is Keycloak's own kcadm.sh.
kcadm_path="${UAT_KCADM:-/opt/keycloak/bin/kcadm.sh}"

# kcadm <script> [file]: a kcadm.sh session in the Keycloak pod. Its stdin
# is the admin password, then (optionally) one line from <file>, read into
# $upw. The script sees $k (kcadm.sh) and $cfg (its session config).
kcadm() {
	{
		cat "$creds/admin-password"
		printf '\n'
		if [[ -n "${2:-}" ]]; then
			cat "$2"
			printf '\n'
		fi
	} | kc -n "$UAT_NS" exec -i "deploy/$KEYCLOAK_DEPLOY" -c keycloak -- /bin/bash -ec '
		IFS= read -r pw
		IFS= read -r upw || true
		k="$2"
		cfg=$(mktemp)
		trap "rm -f \"$cfg\"" EXIT
		"$k" config credentials --config "$cfg" --server http://127.0.0.1:8080 --realm master --user "$1" --password "$pw" >/dev/null
		unset pw
		'"$1" _ "$(cat "$creds/admin-username")" "$kcadm_path"
}

# update_json <file> <jq filter> [jq args...]: rewrites a JSON file in place,
# keeping its mode.
update_json() {
	local f="$1" filter="$2" tmp
	shift 2
	tmp=$(umask 077 && mktemp "$f.XXXXXX")
	jq "$@" "$filter" "$f" >"$tmp"
	chmod --reference="$f" "$tmp"
	mv "$tmp" "$f"
}

# set_org <user>: organization_id := $tenant_id, then reads it back.
# The read-back asks for userProfileMetadata=true: Keycloak 26.4 leaves an
# attribute whose user-profile view permission is admin-only out of a plain
# GET users/<id>, so without it the attribute looks unset right after a
# successful update (found on the first local-rig run).
set_org() {
	local out
	out=$(kcadm "
		id=\$(\"\$k\" get users --config \"\$cfg\" -r $REALM -q username=$1 -q exact=true --fields id --format csv --noquotes)
		[ -n \"\$id\" ] || { echo 'no user $1' >&2; exit 1; }
		\"\$k\" update users/\$id --config \"\$cfg\" -r $REALM -s 'attributes.$TENANT_ATTRIBUTE=[\"$tenant_id\"]'
		\"\$k\" get \"users/\$id?userProfileMetadata=true\" --config \"\$cfg\" -r $REALM") ||
		die "could not set $TENANT_ATTRIBUTE on $1"
	[[ "$(jq -r --arg a "$TENANT_ATTRIBUTE" '.attributes[$a][0] // empty' <<<"$out")" == "$tenant_id" ]] ||
		die "$1 does not have $TENANT_ATTRIBUTE $tenant_id after the update"
	log "$1 -> organization.id $tenant_id"
}

if [[ "$mode" == tenant ]]; then
	other=$((3 - n))
	bound_other=$(jq -r --arg o "$other" '.tenants[$o] // empty' "$core_json")
	[[ "$bound_other" != "$tenant_id" ]] || die "$tenant_id is already bound to tenant $other: the two tenants must differ"
	set_org "t$n-admin"
	set_org "t$n-reader"
	update_json "$core_json" '.tenants[$n] = $t' --arg n "$n" --arg t "$tenant_id"
	kc_json="$SENSITIVE_DIR/keycloak.json"
	[[ ! -s "$kc_json" ]] || update_json "$kc_json" '.tenants[$n].tenant_id = $t' --arg n "$n" --arg t "$tenant_id"
	log "tenant $n bound to $tenant_id (out/core.json, sensitive/keycloak.json); fetch new tokens to get the claim"
	exit 0
fi

# --- scratch mode --------------------------------------------------------------
for t in $(jq -r '.tenants // {} | .[]' "$core_json"); do
	[[ "$t" != "$tenant_id" ]] || die "$tenant_id is tenant 1 or 2; scratch users are for tenants created during a run"
done
prev=$(jq -r --arg u "$user" '.scratch_users[$u].tenant_id // empty' "$core_json")
[[ -z "$prev" || "$prev" == "$tenant_id" ]] || die "$user is already bound to $prev; use a new scratch user name"

sdir="$creds/scratch"
(umask 077 && mkdir -p "$sdir")
pwfile="$sdir/$user.password"
gen_secret_file "$pwfile"
roles="--rolename $READ_ROLE"
[[ "$role" == readonly ]] || roles="$roles --rolename $WRITE_ROLE"

# Create if absent (managed attributes only, so the user profile accepts
# it), set the password from stdin ($upw, never argv), grant the roles.
kcadm "
	id=\$(\"\$k\" get users --config \"\$cfg\" -r $REALM -q username=$user -q exact=true --fields id --format csv --noquotes)
	if [ -z \"\$id\" ]; then
		id=\$(\"\$k\" create users --config \"\$cfg\" -r $REALM -i -s username=$user -s enabled=true \\
			-s email=$user@imas-uat.invalid -s emailVerified=true -s firstName=Scratch -s lastName=User)
	fi
	[ -n \"\$id\" ] || { echo 'could not create $user' >&2; exit 1; }
	printf '{\"type\":\"password\",\"temporary\":false,\"value\":\"%s\"}' \"\$upw\" |
		\"\$k\" update users/\$id/reset-password --config \"\$cfg\" -r $REALM -f - -n
	unset upw
	\"\$k\" add-roles --config \"\$cfg\" -r $REALM --uusername $user $roles" "$pwfile" >/dev/null ||
	die "could not create or update scratch user $user"
set_org "$user"
update_json "$core_json" '.scratch_users[$u] = {tenant_id: $t, role: $r}' --arg u "$user" --arg t "$tenant_id" --arg r "$role"
jq -cn --arg u "$user" --arg t "$tenant_id" --arg r "$role" --arg p "$pwfile" \
	'{username: $u, tenant_id: $t, role: $r, password_file: $p}'
