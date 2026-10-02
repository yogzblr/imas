#!/bin/sh
# Registers the sprout release this farmer chart carries with saasapi's
# operator plane: POST /v1/operator/fleet-releases (API design §2.5,
# docs/api/saasapi-operator-openapi.yaml). Run by the chart's
# post-install/post-upgrade hook Job (templates/sprout-release-register-job.yaml).
#
# Environment (all set by the Job):
#   REGISTER_URL      https://<saasapi operator Service>:<port>/v1/operator/fleet-releases
#   REQUEST_FILE      the request body the chart rendered
#   TOKEN_FILE        the operator bearer token (a mounted Secret file)
#   CA_FILE           the CA saasapi's operator certificate is verified against
#   RETRY_ATTEMPTS, RETRY_INITIAL_DELAY_SECONDS, RETRY_MAX_DELAY_SECONDS,
#   REQUEST_TIMEOUT_SECONDS
#
# Exit status:
#   0  201 (registered) or 200 (already registered with these contents:
#      the idempotent re-run of every later `helm upgrade`)
#   2  a final refusal: 409 (this version is registered with different
#      contents, or is revoked), any other 4xx, or a TLS or local error.
#      Retrying can't fix it; the Job's podFailurePolicy fails the Job, and
#      with it the release, without another pod.
#   1  saasapi unreachable, or 408/429/5xx, on every attempt
#
# The token is read into the shell and handed to curl on stdin as a header
# (`--header @-`), so it is never in argv, the environment or a file of
# ours, and never printed.
set -eu

: "${REGISTER_URL:?}" "${REQUEST_FILE:?}" "${TOKEN_FILE:?}" "${CA_FILE:?}"
attempts="${RETRY_ATTEMPTS:-8}"
delay="${RETRY_INITIAL_DELAY_SECONDS:-5}"
max_delay="${RETRY_MAX_DELAY_SECONDS:-60}"
timeout="${REQUEST_TIMEOUT_SECONDS:-600}"
resp="${TMPDIR:-/tmp}/register-sprout-release.response"

log() { printf 'register-sprout-release: %s\n' "$*" >&2; }

token="$(cat "$TOKEN_FILE")"
case "$token" in
'' | *[[:space:]]* | *[[:cntrl:]]*)
	log "the operator token in $TOKEN_FILE is empty or contains whitespace or control characters"
	exit 2
	;;
esac

n=1
while :; do
	rm -f "$resp"
	set +e
	code="$(printf 'Authorization: Bearer %s\n' "$token" | curl --silent --show-error \
		--proto '=https' --tlsv1.2 --cacert "$CA_FILE" \
		--connect-timeout 10 --max-time "$timeout" --max-filesize 1048576 \
		--request POST --header @- --header 'Content-Type: application/json' \
		--data-binary "@$REQUEST_FILE" --output "$resp" --write-out '%{http_code}' \
		"$REGISTER_URL")"
	rc=$?
	set -e
	body=""
	[ -f "$resp" ] && body="$(cat "$resp")"

	case "$rc" in
	0) ;;
	# Not https (--proto), bad URL or options, unreadable request, local
	# certificate problems, or saasapi's certificate doesn't verify against
	# CA_FILE: final.
	1 | 2 | 3 | 26 | 58 | 60 | 77)
		log "curl failed (exit $rc) before saasapi answered; this is a configuration error, not retrying"
		exit 2
		;;
	*) code="curl exit $rc" ;;
	esac

	case "$code" in
	200)
		log "sprout release already registered with these contents; nothing changed"
		printf '%s\n' "$body"
		exit 0
		;;
	201)
		log "sprout release registered"
		printf '%s\n' "$body"
		exit 0
		;;
	409)
		log "REFUSED (409): saasapi already holds this version with different contents, or has revoked it."
		log "Releases are immutable and nothing was changed. Register a new version; never re-stamp this one."
		log "saasapi says:"
		printf '%s\n' "$body" >&2
		log "this chart sent:"
		cat "$REQUEST_FILE" >&2
		printf '\n' >&2
		exit 2
		;;
	408 | 429 | 5??) what="HTTP $code: $body" ;;
	"curl exit"*) what="saasapi not reachable ($code)" ;;
	*)
		log "REFUSED (HTTP $code), not retrying:"
		printf '%s\n' "$body" >&2
		exit 2
		;;
	esac

	if [ "$n" -ge "$attempts" ]; then
		log "giving up after $n attempts; last: $what"
		exit 1
	fi
	log "attempt $n/$attempts: $what; retrying in ${delay}s"
	sleep "$delay"
	n=$((n + 1))
	delay=$((delay * 2))
	if [ "$delay" -gt "$max_delay" ]; then delay="$max_delay"; fi
done
