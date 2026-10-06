#!/usr/bin/env bash
# token.sh <kubeconfig> <endpoints.json> <state-dir> <username> [tests|other]
#
# Prints a Keycloak access token for one UAT user (t1-admin, t1-reader,
# t2-admin, t2-reader) on stdout, from the realm's token endpoint on the
# core FQDN (password grant on the imas-uat-tests client, or with "other" on
# imas-uat-other-audience, whose tokens lack saasapi's audience). The token is a
# credential: capture it, don't log it. The kubeconfig is not used; the
# argument is there so every script in this directory takes the same
# inputs.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "token.sh <kubeconfig> <endpoints.json> <state-dir> <username>" "$@"
[[ $# -ge 4 ]] || die "usage: token.sh <kubeconfig> <endpoints.json> <state-dir> <username>"
user="$4"
case "${5:-tests}" in
tests) client="$TESTS_CLIENT" secret_file=tests-client-secret ;;
other) client="$OTHER_CLIENT" secret_file=other-client-secret ;;
*) die "client must be tests or other, not $5" ;;
esac
need_cmd curl jq

creds="$SENSITIVE_DIR/keycloak"
pwfile="$creds/$user.password"
known=0
for u in "${UAT_USERS[@]}"; do [[ "$u" == "$user" ]] && known=1; done
if [[ "$user" =~ ^scratch-[a-z0-9][a-z0-9-]{0,50}$ ]]; then
	known=1
	pwfile="$creds/scratch/$user.password"
fi
((known)) || die "unknown UAT user: $user (one of ${UAT_USERS[*]}, or a scratch- user of bind-tenant.sh)"
[[ -s "$pwfile" && -s "$creds/$secret_file" ]] || die "no generated credentials for $user in $creds"
ca="$OUT_DIR/uat-ca.crt"
[[ -s "$ca" ]] || die "no UAT CA at $ca: run install.sh first"

# The form body goes on stdin, so the password and client secret are never
# in argv.
body=$(jq -rn --arg u "$user" --arg c "$client" \
	--rawfile p "$pwfile" --rawfile s "$creds/$secret_file" \
	'"grant_type=password&scope=openid&client_id=\($c|@uri)&client_secret=\($s|@uri)&username=\($u|@uri)&password=\($p|@uri)"')
resp=$(printf '%s' "$body" | curl -sS --fail-with-body --proto '=https' --cacert "$ca" \
	-H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$KEYCLOAK_TOKEN_URL") ||
	die "token request for $user failed: $(jq -r '.error_description // .error // empty' <<<"$resp" 2>/dev/null)"
tok=$(jq -r '.access_token // empty' <<<"$resp")
[[ -n "$tok" ]] || die "no access_token for $user"
printf '%s\n' "$tok"
