#!/usr/bin/env bash
# Check the DMZ hub from the runner, with curl and openssl only (UAT.3a).
#
# Usage:
#   check.sh --endpoints FILE --ca-file FILE [--kubeconfig FILE]
#            [--connect ADDRESS] [--refill-wait SECONDS] [--max-burst N]
#
# --endpoints    the same endpoints file install.sh took (README.md)
# --ca-file      the UAT CA certificate (PEM) UAT.2 writes; the only trust
#                anchor used, the system store is switched off
# --kubeconfig   the DMZ cluster: D13 to D15 read the bus pods and the
#                trust ConfigMap with it (skipped without it), and pod and
#                Service state is printed when a check fails
# --connect      where to connect instead of dmz.public_ip (or dmz.fqdn),
#                e.g. the address of a LoadBalancer (install.sh --expose
#                loadbalancer writes it to dmz.json); the DMZ FQDN is still
#                sent and verified
# --refill-wait  seconds to wait at the end for /v1/enroll's bucket to
#                refill (default 75; 0 skips, and then enrolment through
#                this Envoy is refused for up to 60s)
# --max-burst    most /v1/enroll requests sent to drain its bucket
#                (default 41: two buckets of 20, in case a refill lands
#                mid-burst, plus one)
#
# What it checks, against deploy/envoy/envoy.yaml's header and the nats
# chart (deploy/helm/nats/templates/envoy-configmap.yaml):
#   D1  the listener answers TLS on the DMZ FQDN and verifies with the UAT CA
#   D2  ... and does not verify without it (not a public certificate)
#   D3  /files/ without a token: 401 from jwt_authn ("Jwt is missing")
#   D4  /files/ with a forged EdDSA token: 401 from jwt_authn
#   D5  the websocket route (/), upgrade without a token: 401 from jwt_authn
#   D6  the websocket route, upgrade with a forged token: 401 from jwt_authn
#   D7  /v1/sprout/update-manifest without a token: 401 from jwt_authn
#   D8  /v1/enroll has no JWT gate and reaches farmer: an empty request gets
#       farmer's 401 {"error":"enrollment_failed"}
#   D9  /v1/enroll is rate limited: within --max-burst requests Envoy
#       answers 429 local_rate_limited (bucket: 20 per 60s per Envoy)
#   D10 /v1/refresh has its own bucket and no JWT gate: with /v1/enroll's
#       bucket empty it still reaches farmer (401 enrollment_failed)
#   D11 /v1/enroll's bucket refills (skipped with --refill-wait 0)
#   D12 the same certificate verifies for the DMZ private name sprouts use
#       (dmz.<private_dns_zone>, their farmerinterface), sent as SNI over the
#       same connection, since the runner cannot resolve that name
#   D13 (T5) the bus's farmerbus container has no trust chain seed: no
#       IMAS_NATS_*_SEED[_FILE] but the clustered fence user's
#   D14 (T5) ... and no OpenBao signing access (no IMAS_NATSSIGN_* or
#       IMAS_NATSBOOT_*), and reads the trust ConfigMap at IMAS_NATS_TRUST_DIR
#   D15 (T5) the trust ConfigMap here is a complete, public trust (no seed,
#       the chain hangs together) and every bus pod is Ready: the bus
#       started from the published operator JWT alone
# D8, D10 and D11 need farmer running on the core hub (UAT.3b); the others
# do not. Run it before enrolment: D9 empties /v1/enroll's bucket.
set -uo pipefail

DMZ_PROG=check.sh
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"

usage() {
	sed -n '2,/^set -uo/{/^set -uo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

endpoints="" ca_file="" kubeconfig="" connect="" refill_wait=75 max_burst=41
while (($#)); do
	case $1 in
	--endpoints | --ca-file | --kubeconfig | --connect | --refill-wait | --max-burst)
		(($# >= 2)) || dmz_die "$1 needs a value"
		case $1 in
		--endpoints) endpoints=$2 ;;
		--ca-file) ca_file=$2 ;;
		--kubeconfig) kubeconfig=$2 ;;
		--connect) connect=$2 ;;
		--refill-wait) refill_wait=$2 ;;
		--max-burst) max_burst=$2 ;;
		esac
		shift 2
		;;
	-h | --help) usage ;;
	*) dmz_die "unknown argument '$1' (see --help)" ;;
	esac
done
[[ -n $endpoints ]] || dmz_die "--endpoints is required"
[[ -n $ca_file ]] || dmz_die "--ca-file is required"
[[ -r $ca_file ]] || dmz_die "CA file '$ca_file' is not readable"
[[ $refill_wait =~ ^[0-9]+$ ]] || dmz_die "--refill-wait must be a whole number of seconds"
[[ $max_burst =~ ^[1-9][0-9]*$ ]] || dmz_die "--max-burst must be a whole number of 1 or more"
[[ -z $kubeconfig || -r $kubeconfig ]] || dmz_die "kubeconfig '$kubeconfig' is not readable"

dmz_need jq curl openssl timeout
openssl version | grep -q '^OpenSSL 3' || dmz_die "OpenSSL 3 is required (-no-CAstore, pkeyutl -rawin)"
openssl x509 -in "$ca_file" -noout 2>/dev/null || dmz_die "'$ca_file' is not a PEM certificate"
dmz_load_endpoints "$endpoints"
if [[ -n $connect ]]; then
	_dmz_is_ipv4 "$connect" || _dmz_is_fqdn "$connect" || dmz_die "--connect '$connect' is not an IPv4 address or a DNS name"
	DMZ_CONNECT_ADDR=$connect
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/uat-dmz-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/capath"

host=$DMZ_FQDN port=$DMZ_ENVOY_PORT
base="https://$host:$port"
# Connect to the public address while sending the FQDN as SNI and Host, so
# the check needs no public DNS and still verifies the name. Never through a
# proxy: the DMZ admits only the runner's own address (runner_cidr).
curl_args=(-sS --http1.1 --noproxy '*' --max-time 20 --cacert "$ca_file" --capath "$tmp/capath")
if [[ $DMZ_CONNECT_ADDR != "$host" ]]; then
	curl_args+=(--resolve "$host:$port:$DMZ_CONNECT_ADDR")
fi
dmz_log "checking Envoy at $base (connecting to $DMZ_CONNECT_ADDR:$port)"

failed=0
pass() { printf 'PASS %-4s %s\n' "$1" "$2"; }
fail() {
	printf 'FAIL %-4s %s\n' "$1" "$2"
	failed=$((failed + 1))
}
skip() { printf 'SKIP %-4s %s\n' "$1" "$2"; }

# http METHOD PATH [curl args...]: sets code (000 when there was no HTTP
# answer) and body (its first 200 bytes, one line).
code="" body=""
http() {
	local method=$1 path=$2
	shift 2
	: >"$tmp/body"
	code=$(curl "${curl_args[@]}" -o "$tmp/body" -w '%{http_code}' -X "$method" "$@" "$base$path" 2>"$tmp/curl.err")
	[[ $code =~ ^[0-9]{3}$ ]] || code=000
	body=$(head -c 200 "$tmp/body" | tr -s '\r\n' ' ')
	body=${body% }
	if [[ $code == 000 ]]; then
		body="no HTTP answer: $(head -c 200 "$tmp/curl.err" | tr -s '\r\n' ' ')"
	fi
}

# jwt_refused ID WHAT: the last answer must be jwt_authn's own refusal, a
# 401 whose body is Envoy's reason ("Jwt is missing", "Jwt verification
# fails", "Jwks doesn't have key to match kid or alg from Jwt"...), never
# an upstream's answer.
jwt_refused() {
	local reason='^(Jwt|Jwks) '
	if [[ $code == 401 && $body =~ $reason ]]; then
		pass "$1" "$2: 401 \"$body\""
	else
		fail "$1" "$2: got $code \"$body\", want 401 from jwt_authn (body starting \"Jwt\")"
	fi
}

# farmer_failed: the last answer is farmer's generic enrollment failure.
farmer_failed() { [[ $code == 401 && $body == *'"error":"enrollment_failed"'* ]]; }

enroll() { http POST /v1/enroll -H 'Content-Type: application/json' --data '{}'; }

# A forged gateway JWT: the right shape, alg and issuer, signed by a key
# nobody published. jwt_authn must refuse it on the signature.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
forged_jwt() {
	local now hdr pl sig
	openssl genpkey -algorithm ed25519 -out "$tmp/forger.pem" 2>/dev/null || return 1
	now=$(date +%s)
	hdr=$(printf '{"alg":"EdDSA","typ":"JWT","kid":"uat-dmz-check"}' | b64url)
	pl=$(printf '{"iss":"imas-gateway","sub":"UAAUATDMZCHECKPROBE","iat":%d,"nbf":%d,"exp":%d}' \
		"$now" "$now" "$((now + 600))" | b64url)
	printf '%s.%s' "$hdr" "$pl" >"$tmp/signing-input"
	sig=$(openssl pkeyutl -sign -rawin -inkey "$tmp/forger.pem" -in "$tmp/signing-input" | b64url) || return 1
	printf '%s.%s.%s\n' "$hdr" "$pl" "$sig"
}
forged=$(forged_jwt) || dmz_die "could not make the forged probe token with openssl"

# A fresh nonce per run: RFC 6455 asks for 16 random bytes, base64.
ws_nonce=$(openssl rand -base64 16) || dmz_die "could not make a websocket nonce with openssl"
ws_headers=(-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13'
	-H "Sec-WebSocket-Key: $ws_nonce")

# --- TLS ---------------------------------------------------------------------
# s_client NAME [ARGS]: a handshake to the listener, sending and verifying NAME.
s_client() {
	local name=$1
	shift
	timeout 30 openssl s_client -connect "$DMZ_CONNECT_ADDR:$port" -servername "$name" \
		-verify_hostname "$name" -verify_return_error "$@" </dev/null 2>&1
}
out=$(s_client "$host" -no-CAfile -no-CApath -no-CAstore -CAfile "$ca_file")
rc=$?
if ((rc == 0)) && grep -q 'Verify return code: 0 (ok)' <<<"$out"; then
	pass D1 "TLS on $host:$port verifies against the UAT CA ($(grep -m1 '^New, ' <<<"$out"))"
else
	fail D1 "TLS on $host:$port does not verify against the UAT CA for $host: $(grep -m1 -E 'Verify return code|verify error|errno|connect:' <<<"$out")"
fi
out=$(s_client "$host")
rc=$?
if ((rc != 0)) || ! grep -q 'Verify return code: 0 (ok)' <<<"$out"; then
	pass D2 "the listener's certificate does not verify against the system store alone"
else
	fail D2 "the listener's certificate verifies without the UAT CA: it is not the UAT certificate"
fi

# --- jwt_authn gates -----------------------------------------------------
http GET /files/uat-dmz-check
jwt_refused D3 "GET /files/ without a token"
http GET /files/uat-dmz-check -H "Authorization: Bearer $forged"
jwt_refused D4 "GET /files/ with a forged token"
http GET / --max-time 5 "${ws_headers[@]}"
jwt_refused D5 "websocket upgrade on / without a token"
http GET / --max-time 5 "${ws_headers[@]}" -H "Authorization: Bearer $forged"
jwt_refused D6 "websocket upgrade on / with a forged token"
http GET /v1/sprout/update-manifest
jwt_refused D7 "GET /v1/sprout/update-manifest without a token"

# --- /v1/enroll: reachable, then rate limited ------------------------------
enroll
if [[ $code == 429 ]]; then
	dmz_log "/v1/enroll's bucket is already empty; waiting up to 65s for it to refill"
	for _ in $(seq 13); do
		sleep 5
		enroll
		[[ $code == 429 ]] || break
	done
fi
if farmer_failed; then
	pass D8 "POST /v1/enroll without a JWT reaches farmer: 401 $body"
	enroll_ok=1
else
	case $code in
	502 | 503 | 504) why="Envoy cannot reach farmer at the core private IP (is the core hub up?)" ;;
	401) why="refused before farmer (a JWT gate on /v1/enroll?)" ;;
	*) why="unexpected answer" ;;
	esac
	fail D8 "POST /v1/enroll: got $code \"$body\": $why"
	enroll_ok=""
fi

passed_before=1 limited=""
for ((i = 1; i <= max_burst; i++)); do
	enroll
	if [[ $code == 429 ]]; then
		limited=$i
		break
	fi
	if [[ $code == 000 ]] || { [[ -n $enroll_ok ]] && ! farmer_failed; }; then
		break
	fi
	passed_before=$((passed_before + 1))
done
if [[ -n $limited && $body == *local_rate_limited* ]]; then
	note=""
	((passed_before <= 20)) || note=" (more than 20: a refill tick may have landed mid-burst)"
	pass D9 "POST /v1/enroll is rate limited: 429 \"$body\" after $passed_before answered request(s)$note"
elif [[ -n $limited ]]; then
	fail D9 "POST /v1/enroll: 429 without Envoy's local_rate_limited body: \"$body\""
elif ((i <= max_burst)); then
	fail D9 "POST /v1/enroll: got $code \"$body\" during the burst, want farmer's 401 or Envoy's 429"
else
	fail D9 "POST /v1/enroll: no 429 after $max_burst requests (bucket should be 20 per 60s)"
fi

http POST /v1/refresh -H 'Content-Type: application/json' --data '{}'
if farmer_failed; then
	pass D10 "POST /v1/refresh with /v1/enroll's bucket empty reaches farmer: 401 $body"
else
	fail D10 "POST /v1/refresh: got $code \"$body\", want farmer's 401 enrollment_failed (own bucket, no JWT gate)"
fi

if ((refill_wait == 0)); then
	skip D11 "not waiting for /v1/enroll's bucket: enrolment through this Envoy is refused (429) for up to 60s"
elif [[ -n $limited ]]; then
	waited=0 refilled=""
	while ((waited < refill_wait)); do
		step=$((refill_wait - waited < 5 ? refill_wait - waited : 5))
		sleep "$step"
		waited=$((waited + step))
		enroll
		if [[ $code != 429 ]]; then
			refilled=1
			break
		fi
	done
	if [[ -n $refilled ]] && farmer_failed; then
		pass D11 "/v1/enroll's bucket refilled within ${waited}s"
	elif [[ -n $refilled ]]; then
		fail D11 "after the refill POST /v1/enroll got $code \"$body\""
	else
		fail D11 "/v1/enroll still answers 429 after ${refill_wait}s"
	fi
else
	skip D11 "the bucket was never drained (D9 failed)"
fi

out=$(s_client "$DMZ_PRIVATE_NAME" -no-CAfile -no-CApath -no-CAstore -CAfile "$ca_file")
rc=$?
if ((rc == 0)) && grep -q 'Verify return code: 0 (ok)' <<<"$out"; then
	pass D12 "the certificate also verifies for $DMZ_PRIVATE_NAME, the name sprouts use"
else
	fail D12 "the certificate does not verify for $DMZ_PRIVATE_NAME: $(grep -m1 -E 'Verify return code|verify error|errno|connect:' <<<"$out")"
fi

# --- T5: the bus starts from the public trust alone --------------------------
if [[ -z $kubeconfig ]]; then
	for id in D13 D14 D15; do skip "$id" "no --kubeconfig: the bus pods and the trust ConfigMap are not read"; done
elif ! command -v kubectl >/dev/null 2>&1 || ! command -v base64 >/dev/null 2>&1; then
	for id in D13 D14 D15; do skip "$id" "kubectl or base64 not found on PATH"; done
else
	kd() { kubectl --kubeconfig "$kubeconfig" -n "$DMZ_NAMESPACE" "$@"; }
	pods=$(kd get pods -l "app.kubernetes.io/instance=$DMZ_RELEASE,app.kubernetes.io/component=bus" -o json 2>/dev/null) || pods='{"items":[]}'
	n=$(jq '.items | length' <<<"$pods")
	bus_env='.items[].spec.containers[] | select(.name == "farmerbus") | (.env // [])[] | .name'
	if ((n == 0)); then
		fail D13 "no bus pod found (app.kubernetes.io/instance=$DMZ_RELEASE, component=bus)"
		fail D14 "no bus pod found"
	else
		seeds=$(jq -r "[$bus_env | select(test(\"^IMAS_NATS_.*_SEED(_FILE)?\$\")) | select(. != \"IMAS_NATS_BUS_FENCE_USER_SEED_FILE\")] | unique | join(\" \")" <<<"$pods")
		if [[ -z $seeds ]]; then
			pass D13 "the $n bus pod(s) carry no trust chain seed"
		else
			fail D13 "the bus is given seeds it must not have: $seeds"
		fi
		signer=$(jq -r "[$bus_env | select(test(\"^IMAS_(NATSSIGN|NATSBOOT)_\"))] | unique | join(\" \")" <<<"$pods")
		if [[ -n $signer ]]; then
			fail D14 "the bus has OpenBao signing settings: $signer"
		elif jq -e --arg cm "$DMZ_TRUST_CONFIGMAP" "all(.items[]; any(.spec.volumes[]?; .configMap.name? == \$cm)) and ([$bus_env] | index(\"IMAS_NATS_TRUST_DIR\"))" <<<"$pods" >/dev/null; then
			pass D14 "no OpenBao signing access; the bus reads ConfigMap $DMZ_TRUST_CONFIGMAP (IMAS_NATS_TRUST_DIR)"
		else
			fail D14 "the bus pods do not all mount ConfigMap $DMZ_TRUST_CONFIGMAP at IMAS_NATS_TRUST_DIR"
		fi
	fi
	mkdir "$tmp/trust"
	problem=""
	if cm=$(kd get configmap "$DMZ_TRUST_CONFIGMAP" -o json 2>/dev/null); then
		for key in "${DMZ_TRUST_KEYS[@]}" "${DMZ_TRUST_OPTIONAL_KEYS[@]}"; do
			jq -j --arg k "$key" '.data[$k] // empty' <<<"$cm" >"$tmp/trust/$key"
		done
		problem=$(dmz_trust_problem "$tmp/trust")
	else
		problem="ConfigMap $DMZ_NAMESPACE/$DMZ_TRUST_CONFIGMAP not found"
	fi
	ready=$(jq '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length' <<<"$pods")
	if [[ -n $problem ]]; then
		fail D15 "the NATS trust: $problem"
	elif ((n == 0 || ready != n)); then
		fail D15 "$ready of $n bus pod(s) Ready"
	else
		pass D15 "the trust is public and complete, and all $n bus pod(s) are Ready on it"
	fi
fi

if ((failed)); then
	if [[ -n $kubeconfig ]] && command -v kubectl >/dev/null 2>&1; then
		kubectl --kubeconfig "$kubeconfig" -n "$DMZ_NAMESPACE" get pods,svc,endpointslices -o wide >&2 || true
	fi
	dmz_log "$failed check(s) failed"
	exit 1
fi
dmz_log "all checks passed"
