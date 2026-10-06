# shellcheck shell=bash
# Shared helpers for the uat/enroll scripts: logging, and calls to the SaaS
# API (docs/api/saasapi.md) that keep every credential out of process
# arguments, the terminal and the logs.
#
# Every saasapi call needs two credentials (docs/api/saasapi.md,
# "Authentication"): the BFF's shared secret in X-Internal-Auth, and a
# Keycloak user token whose organization.id equals the path's tenant_id. Both
# are read from files (or, for tokens, from a hook) on every call, written to
# a mode 0600 header file that curl reads with -H @file, and never echoed.
#
# Callers set these globals before calling saas_init:
#   SAAS_URL            https://host[:port], no trailing slash (no /v1)
#   CA_FILE             CA bundle for saasapi's certificate, or empty
#   INTERNAL_AUTH_FILE  file holding the X-Internal-Auth secret
#   TOKEN_CMD           executable printing a token (see token_for), or empty
#   TOKEN_FILE_1/_2     files holding tenant 1's and tenant 2's token
#   WORK                a private (0700) scratch directory

SCRIPT_NAME="${SCRIPT_NAME:-$(basename "$0")}"

log() { printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2; }
die() {
	printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2
	exit "${DIE_CODE:-1}"
}
# usage_text FILE: FILE's header comment, without lint directives.
usage_text() {
	awk 'NR == 1 { next } /^#/ { if ($0 ~ /^# ?(shellcheck|lint:)/) next; sub(/^# ?/, ""); print; next } { exit }' "$1"
}
need() {
	local t
	for t in "$@"; do
		command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
	done
}

# Tokens are compact JWS: three base64url parts, the last may be empty in
# tests. Nothing else (no whitespace, no quotes) may reach the header file.
TOKEN_RE='^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'

saas_init() {
	[[ -n "${SAAS_URL:-}" ]] || die "no saasapi URL"
	[[ "$SAAS_URL" =~ ^https?://[^/[:space:]]+$ ]] ||
		die "saasapi URL must be scheme://host[:port] with no path: $SAAS_URL"
	if [[ -n "${CA_FILE:-}" ]]; then
		[[ -r "$CA_FILE" ]] || die "CA file not readable: $CA_FILE"
	fi
	[[ -n "${INTERNAL_AUTH_FILE:-}" && -r "$INTERNAL_AUTH_FILE" ]] ||
		die "--internal-auth-file is required and must be readable (the saasapi X-Internal-Auth secret)"
	if [[ -n "${TOKEN_CMD:-}" ]]; then
		[[ -x "$TOKEN_CMD" ]] || die "--token-cmd is not an executable file: $TOKEN_CMD"
	fi
	[[ -n "${WORK:-}" && -d "$WORK" ]] || die "internal: no WORK directory"
}

# token_for N [TENANT_ID]: print a Keycloak access token for tenant N's admin.
# With TOKEN_CMD, runs "TOKEN_CMD N TENANT_ID" (TENANT_ID empty before the
# tenant exists) and takes its stdout; otherwise reads TOKEN_FILE_N. Read
# afresh on every call, so a short-lived token can be refreshed behind us.
token_for() {
	local n="$1" tid="${2:-}" tok file
	if [[ -n "${TOKEN_CMD:-}" ]]; then
		tok="$("$TOKEN_CMD" "$n" "$tid")" || die "token command failed for tenant $n"
	else
		file="TOKEN_FILE_$n"
		file="${!file:-}"
		[[ -n "$file" && -r "$file" ]] || die "no token for tenant $n: pass --token-t$n FILE or --token-cmd"
		tok="$(<"$file")"
	fi
	tok="${tok//[$'\r\n\t ']/}"
	[[ "$tok" =~ $TOKEN_RE ]] || die "the token for tenant $n is not a compact JWT"
	printf '%s' "$tok"
}

# jwt_org_id TOKEN: print the token's organization.id claim (the claim saasapi
# checks against the path's tenant_id), or nothing. Only this one non-secret
# field is ever printed.
jwt_org_id() {
	local p="${1#*.}"
	p="${p%%.*}"
	p="$(printf '%s' "$p" | tr '_-' '/+')"
	case $((${#p} % 4)) in
	2) p="$p==" ;;
	3) p="$p=" ;;
	esac
	printf '%s' "$p" | base64 -d 2>/dev/null | jq -r '.organization.id // empty' 2>/dev/null || true
}

# saas_call METHOD PATH N TENANT_ID [BODY_JSON]: call saasapi as tenant N's
# admin. The response body lands in $WORK/resp; the HTTP status is printed
# ("000" when the request never got an answer).
saas_call() {
	local method="$1" path="$2" n="$3" tid="$4" body="${5:-}" tok secret status
	local hdr="$WORK/hdr" data=()
	tok="$(token_for "$n" "$tid")" || exit 1
	secret="$(<"$INTERNAL_AUTH_FILE")"
	secret="${secret%$'\n'}"
	secret="${secret%$'\r'}"
	[[ -n "$secret" && "$secret" != *[$'\r\n']* ]] || die "the internal auth secret file is empty or has more than one line"
	(
		umask 077
		printf 'X-Internal-Auth: %s\nAuthorization: Bearer %s\nAccept: application/json\n' "$secret" "$tok" >"$hdr"
		if [[ -n "$body" ]]; then
			printf 'Content-Type: application/json\n' >>"$hdr"
		fi
	)
	if [[ -n "$body" ]]; then
		printf '%s' "$body" >"$WORK/body"
		data=(--data-binary "@$WORK/body")
	fi
	local tls=()
	[[ -n "${CA_FILE:-}" ]] && tls=(--cacert "$CA_FILE")
	: >"$WORK/resp"
	status="$(curl -sS -X "$method" --max-time 30 "${tls[@]}" -H "@$hdr" "${data[@]}" \
		-o "$WORK/resp" -w '%{http_code}' "$SAAS_URL$path" 2>"$WORK/curl.err")" || status="000"
	rm -f "$hdr" "$WORK/body"
	[[ "$status" =~ ^[0-9]{3}$ ]] || status="000"
	printf '%s' "$status"
}

# resp_error: the saasapi error code of the last response, for messages.
resp_error() {
	jq -r '(.error // "") + (if .message then ": " + .message else "" end)' "$WORK/resp" 2>/dev/null ||
		head -c 200 "$WORK/curl.err" 2>/dev/null || true
}

# check_token_tenant N TENANT_ID: fail early, and say why, when tenant N's
# token can't be used on TENANT_ID's routes (saasapi would answer 403).
check_token_tenant() {
	local n="$1" tid="$2" tok org
	tok="$(token_for "$n" "$tid")" || exit 1
	org="$(jwt_org_id "$tok")"
	if [[ "$org" != "$tid" ]]; then
		DIE_CODE=3 die "tenant $n is $tid, but its token's organization.id is '${org:-<none>}'.
saasapi only accepts a token whose organization.id equals the tenant_id, and it
generates that id itself (POST /v1/tenants). Map tenant $n's Keycloak users to
$tid, mint new tokens and re-run (the tenant is reused from the state
directory), or pass --token-cmd so this happens in one run (see README.md)."
	fi
}

# uat_tenants UAT_JSON: the tenant numbers that have sprouts, one per line.
uat_tenants() {
	jq -r '[.sprouts[] | .tenant | tostring | ltrimstr("t")] | unique | .[]' "$1"
}
