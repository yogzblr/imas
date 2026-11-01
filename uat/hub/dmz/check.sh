#!/usr/bin/env bash
# Check the DMZ hub from the runner, with curl and openssl only (UAT.3a).
#
# Usage:
#   check.sh --endpoints FILE --ca-file FILE [--kubeconfig FILE]
#            [--connect ADDRESS] [--refill-wait SECONDS] [--max-burst N]
#            [--diagnostics DIR]
#
# --endpoints    the same endpoints file install.sh took (README.md)
# --ca-file      the UAT CA certificate (PEM) UAT.2 writes; the only trust
#                anchor used, the system store is switched off
# --kubeconfig   the DMZ cluster: D13 to D16 read the bus pods, the trust
#                ConfigMap and the Envoys' admin interface with it (skipped
#                without it), and pod and Service state is printed when a
#                check fails
# --connect      where to connect instead of dmz.public_ip (or dmz.fqdn),
#                e.g. the address of a LoadBalancer (install.sh --expose
#                loadbalancer writes it to dmz.json); the DMZ FQDN is still
#                sent and verified
# --refill-wait  seconds after D9's burst before D11 checks that every
#                Envoy's /v1/enroll bucket has refilled (default 75; above
#                the 60s fill interval, so every Envoy has had a refill tick;
#                0 skips, and then enrolment through a drained Envoy is
#                refused for up to 60s)
# --max-burst    /v1/enroll requests D9 sends (default 41 per Envoy: two
#                buckets of 20, in case a refill lands mid-burst, plus one.
#                An HA DMZ runs one Envoy per node behind a load balancer,
#                each with its own bucket, so 121 for three nodes). Sent 24
#                at a time, each on a new connection, so the burst ends well
#                inside one fill interval
# --diagnostics  directory for the Envoys' rate-limit diagnostics (D16:
#                per Envoy pod the local_rate_limit filter and /v1/enroll's
#                route from its config_dump, and its rate-limit stats); a
#                temporary one, removed at the end, without it
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
#   D9  /v1/enroll is rate limited: a burst of --max-burst requests, done
#       well inside one fill interval, draws Envoy's 429 local_rate_limited
#       (bucket: 20 per 60s per Envoy); the burst's duration is reported
#   D10 /v1/refresh has its own bucket and no JWT gate: with /v1/enroll's
#       bucket empty it still reaches farmer (401 enrollment_failed)
#   D11 every Envoy's /v1/enroll bucket refills: --refill-wait after the
#       burst, two probes per Envoy all reach farmer (skipped with
#       --refill-wait 0)
#   D12 the same certificate verifies for the DMZ private name sprouts use
#       (dmz.<private_dns_zone>, their farmerinterface), sent as SNI over the
#       same connection, since the runner cannot resolve that name
#   D13 (T5) the bus's farmerbus container has no trust chain seed: no
#       IMAS_NATS_*_SEED[_FILE] but the clustered fence user's
#   D14 (T5) ... and no OpenBao signing access (no IMAS_NATSSIGN_* or
#       IMAS_NATSBOOT_*), and mounts the trust ConfigMap at exactly the
#       directory IMAS_NATS_TRUST_DIR names
#   D15 (T5) the trust ConfigMap here is a complete, public trust (no seed,
#       the chain hangs together) and every bus pod is Ready: the bus
#       started from the published operator JWT alone
#   D16 every Envoy (one per DMZ node) carries /v1/enroll's local_rate_limit
#       filter and bucket (20 max, 20 per fill, 60s) in its config_dump,
#       read through kubectl port-forward to its admin port
# D8 to D11 need farmer running on the core hub (UAT.3b); the others
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

endpoints="" ca_file="" kubeconfig="" connect="" refill_wait=75 max_burst="" diag_dir=""
while (($#)); do
	case $1 in
	--endpoints | --ca-file | --kubeconfig | --connect | --refill-wait | --max-burst | --diagnostics)
		(($# >= 2)) || dmz_die "$1 needs a value"
		case $1 in
		--endpoints) endpoints=$2 ;;
		--ca-file) ca_file=$2 ;;
		--kubeconfig) kubeconfig=$2 ;;
		--connect) connect=$2 ;;
		--refill-wait) refill_wait=$2 ;;
		--max-burst) max_burst=$2 ;;
		--diagnostics) diag_dir=$2 ;;
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
[[ -z $max_burst || $max_burst =~ ^[1-9][0-9]*$ ]] || dmz_die "--max-burst must be a whole number of 1 or more"
[[ -z $kubeconfig || -r $kubeconfig ]] || dmz_die "kubeconfig '$kubeconfig' is not readable"

dmz_need jq curl openssl timeout xargs seq
openssl version | grep -q '^OpenSSL 3' || dmz_die "OpenSSL 3 is required (-no-CAstore, pkeyutl -rawin)"
openssl x509 -in "$ca_file" -noout 2>/dev/null || dmz_die "'$ca_file' is not a PEM certificate"
dmz_load_endpoints "$endpoints"
# One Envoy per DMZ node (values-ha.yaml on an HA hub), one bucket each.
envoys=$DMZ_NODE_COUNT
max_burst=${max_burst:-$((40 * envoys + 1))}
# D9 sends its burst burst_parallel requests at a time; a burst that takes
# longer than burst_slow seconds cannot show the limit (see D9).
burst_parallel=24
burst_slow=30
if [[ -n $connect ]]; then
	_dmz_is_ipv4 "$connect" || _dmz_is_fqdn "$connect" || dmz_die "--connect '$connect' is not an IPv4 address or a DNS name"
	DMZ_CONNECT_ADDR=$connect
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/uat-dmz-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/capath"
if [[ -n $diag_dir ]]; then
	mkdir -p "$diag_dir" || dmz_die "cannot create the diagnostics directory '$diag_dir'"
else
	diag_dir=$tmp/diagnostics
fi

host=$DMZ_FQDN port=$DMZ_ENVOY_PORT
base="https://$host:$port"
# Connect to the public address while sending the FQDN as SNI and Host, so
# the check needs no public DNS and still verifies the name. Never through a
# proxy: the runner's own connection is the one the DMZ NSG is set for
# (uat/tofu public_ingress).
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

# now_ms: the wall clock in milliseconds. ms_secs MS: MS as seconds, one
# decimal.
now_ms() { date +%s%3N; }
ms_secs() { printf '%d.%d' $(($1 / 1000)) $(($1 % 1000 / 100)); }

# burst DIR N: N POST /v1/enroll, burst_parallel in flight, each its own
# curl: a new TCP and TLS connection per request, as sprouts enrol, so the
# load balancer spreads them over the Envoys. Each request writes its own
# files, DIR/<i>.head (the status line first), DIR/<i>.body and DIR/<i>.err,
# so nothing is counted in a shared variable while they run.
burst() {
	local d=$1 n=$2
	mkdir -p "$d"
	seq 1 "$n" | xargs -P "$burst_parallel" -I '{}' \
		curl "${curl_args[@]}" -o "$d/{}.body" -D "$d/{}.head" --stderr "$d/{}.err" \
		-X POST -H 'Content-Type: application/json' --data '{}' "$base/v1/enroll" >/dev/null 2>&1 || true
}

# tally DIR N: count burst DIR's N answers. Sets n_answered (farmer's 401;
# any HTTP answer but a 429 when D8 failed), n_limited (429s),
# n_limited_body (429s with Envoy's local_rate_limited body), n_other
# (anything else, 000 for no HTTP answer), and the first of each:
# first_limited, first_bad_limited, first_other.
tally() {
	local d=$1 n=$2 i c b
	n_answered=0 n_limited=0 n_limited_body=0 n_other=0
	first_limited="" first_bad_limited="" first_other=""
	for ((i = 1; i <= n; i++)); do
		c=$(head -n 1 "$d/$i.head" 2>/dev/null | awk '{print $2}')
		[[ $c =~ ^[0-9]{3}$ ]] || c=000
		b=$(head -c 200 "$d/$i.body" 2>/dev/null | tr -s '\r\n' ' ')
		b=${b% }
		if [[ $c == 429 ]]; then
			n_limited=$((n_limited + 1))
			if [[ $b == *local_rate_limited* ]]; then
				n_limited_body=$((n_limited_body + 1))
				first_limited=${first_limited:-$b}
			else
				first_bad_limited=${first_bad_limited:-$b}
			fi
		elif [[ $c != 000 ]] && { [[ -z $enroll_ok ]] || [[ $c == 401 && $b == *'"error":"enrollment_failed"'* ]]; }; then
			n_answered=$((n_answered + 1))
		else
			n_other=$((n_other + 1))
			if [[ -z $first_other ]]; then
				[[ $c != 000 ]] || b="no HTTP answer: $(head -c 200 "$d/$i.err" 2>/dev/null | tr -s '\r\n' ' ')"
				first_other="$c \"$b\""
			fi
		fi
	done
}

# envoy_rate_limit DIAG: for every Envoy pod, through kubectl port-forward
# to its admin port (Envoy binds it to 127.0.0.1 in the pod; nothing is
# asked of the image, no shell or curl), the local_rate_limit pieces of its
# config_dump (the HTTP filter and /v1/enroll's route; the rest of the dump
# is not kept) and its rate-limit stats (enabled, enforced, rate_limited, ok)
# into DIAG/envoy/<pod>/, with one line per pod on stderr. Sets
# envoy_problem to why not every one of the $envoys Envoys carries
# /v1/enroll's bucket, empty when they all do. Never asserts on the stats:
# the load balancer's spread does not promise each Envoy a 429.
envoy_rate_limit() {
	local diag=$1/envoy pods pod d pf lport tries stats
	envoy_problem=""
	mkdir -p "$diag"
	pods=$(kubectl --kubeconfig "$kubeconfig" -n "$DMZ_NAMESPACE" get pods \
		-l "app.kubernetes.io/instance=$DMZ_RELEASE,app.kubernetes.io/component=envoy" \
		--field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>"$diag/kubectl.err") || {
		envoy_problem="cannot list the Envoy pods: $(head -c 200 "$diag/kubectl.err" | tr -s '\r\n' ' ')"
		return
	}
	local n=0 ok=0 missing=""
	for pod in $pods; do
		n=$((n + 1))
		d=$diag/$pod
		mkdir -p "$d"
		kubectl --kubeconfig "$kubeconfig" -n "$DMZ_NAMESPACE" port-forward --address 127.0.0.1 \
			"pod/$pod" ":$DMZ_ENVOY_ADMIN_PORT" >"$d/port-forward.out" 2>"$d/port-forward.err" &
		pf=$!
		lport=""
		for ((tries = 0; tries < 80; tries++)); do
			lport=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$d/port-forward.out" | head -n 1)
			[[ -z $lport ]] || break
			kill -0 "$pf" 2>/dev/null || break
			sleep 0.25
		done
		if [[ -n $lport ]] &&
			curl -sS --noproxy '*' --max-time 15 -o "$d/config_dump.full" "http://127.0.0.1:$lport/config_dump" 2>"$d/admin.err" &&
			jq '{
				http_filters: [.. | objects | select(.name? == "envoy.filters.http.local_ratelimit" and has("typed_config"))],
				enroll_routes: [.. | objects | select((.match? | objects | .prefix?) == "/v1/enroll")
					| {match, local_ratelimit: .typed_per_filter_config?["envoy.filters.http.local_ratelimit"]}]
			}' "$d/config_dump.full" >"$d/rate-limit.json" 2>>"$d/admin.err"; then
			curl -sS --noproxy '*' --max-time 15 -o "$d/stats.txt" "http://127.0.0.1:$lport/stats?filter=rate_limit" 2>>"$d/admin.err" || true
			if jq -e '(.http_filters | length > 0) and (.enroll_routes | length > 0) and all(.enroll_routes[]; .local_ratelimit as $l
				| $l.stat_prefix == "enroll_rate_limiter"
				and ($l.token_bucket.max_tokens | tonumber) == 20
				and ($l.token_bucket.tokens_per_fill | tonumber) == 20
				and $l.token_bucket.fill_interval == "60s"
				and ($l.filter_enabled.default_value.numerator // 0) == 100
				and ($l.filter_enforced.default_value.numerator // 0) == 100)' "$d/rate-limit.json" >/dev/null 2>&1; then
				ok=$((ok + 1))
			else
				missing+=" $pod"
			fi
			stats=$(awk -F': ' '$1 ~ /^enroll_rate_limiter\.http_local_rate_limit\./ {sub(/.*\./, "", $1); printf "%s=%s ", $1, $2}' "$d/stats.txt" 2>/dev/null)
			dmz_log "Envoy $pod: /v1/enroll ${stats:-(no enroll_rate_limiter stats)}"
		else
			missing+=" $pod(admin port $DMZ_ENVOY_ADMIN_PORT not reachable: $(cat "$d/port-forward.err" "$d/admin.err" 2>/dev/null | head -c 200 | tr -s '\r\n' ' '))"
			dmz_log "Envoy $pod: admin interface not reachable through kubectl port-forward"
		fi
		rm -f "$d/config_dump.full"
		kill "$pf" 2>/dev/null
		wait "$pf" 2>/dev/null
	done
	if ((n != envoys)); then
		envoy_problem="$n Envoy pod(s) Running, want $envoys"
	elif [[ -n $missing ]]; then
		envoy_problem="$ok of $n carry it; not:$missing"
	fi
}

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

# D9's burst: every request at once (burst_parallel in flight), so it ends
# well inside one fill interval. Each Envoy's bucket holds 20 and gets 20 per
# 60s: continuously, one token every 3s, with Envoy's timer-less token bucket
# (the default since Envoy 1.31, so the chart's v1.35.3), or all at once on a
# timer with the older one. Either way one Envoy serves at most 40 requests
# in any window shorter than 60s, so 2*20*Envoys+1 must draw a 429 whatever
# the load balancer's spread. Sent one after the other (0.6s each from the
# runner, a new TLS connection each), 121 took 74s, in which three Envoys
# earn about 3 x (20 + 74/3) = 134 tokens: no 429 (UAT run 41277641220). A
# burst slower than burst_slow seconds is reported as too slow to test the
# limit, not as a missing limit.
t0_ms=$(now_ms)
burst "$tmp/burst" "$max_burst"
burst_end_ms=$(now_ms)
burst_secs=$(ms_secs $((burst_end_ms - t0_ms)))
tally "$tmp/burst" "$max_burst"
limited=""
if ((n_other)); then
	fail D9 "POST /v1/enroll: $n_other of $max_burst request(s) got $first_other during the burst, want farmer's 401 or Envoy's 429 (burst took ${burst_secs}s)"
elif ((n_limited && n_limited_body == n_limited)); then
	limited=1
	note=""
	((n_answered <= 20 * envoys)) || note=" (more than $((20 * envoys)): a refill tick landed mid-burst)"
	pass D9 "POST /v1/enroll is rate limited: $n_limited of $max_burst answered 429 \"$first_limited\", $n_answered reached farmer$note; burst took ${burst_secs}s ($burst_parallel in flight, $envoys Envoy(s))"
elif ((n_limited)); then
	fail D9 "POST /v1/enroll: $((n_limited - n_limited_body)) 429(s) without Envoy's local_rate_limited body: \"$first_bad_limited\" (burst took ${burst_secs}s)"
elif ((burst_end_ms - t0_ms > burst_slow * 1000)); then
	fail D9 "POST /v1/enroll: burst too slow to test the limit: $max_burst requests took ${burst_secs}s (more than ${burst_slow}s; each Envoy refills 20 every 60s, so only a burst well inside that interval must see a 429), no 429"
else
	fail D9 "POST /v1/enroll: no 429 after $max_burst requests in ${burst_secs}s (bucket should be 20 per 60s per Envoy, $envoys Envoy(s): at most $((40 * envoys)) answers inside one fill interval)"
fi

http POST /v1/refresh -H 'Content-Type: application/json' --data '{}'
if farmer_failed; then
	pass D10 "POST /v1/refresh with /v1/enroll's bucket empty reaches farmer: 401 $body"
else
	fail D10 "POST /v1/refresh: got $code \"$body\", want farmer's 401 enrollment_failed (own bucket, no JWT gate)"
fi

# D16 and the Envoys' rate-limit diagnostics (config_dump and stats per
# Envoy pod), after the burst so the stats count it.
if [[ -z $kubeconfig ]]; then
	skip D16 "no --kubeconfig: the Envoys' config_dump is not read"
elif ! command -v kubectl >/dev/null 2>&1; then
	skip D16 "kubectl not found on PATH"
else
	envoy_rate_limit "$diag_dir"
	if [[ -n $envoy_problem ]]; then
		fail D16 "/v1/enroll's bucket in the Envoys' config_dump: $envoy_problem (diagnostics in $diag_dir/envoy)"
	else
		pass D16 "all $envoys Envoy(s) carry /v1/enroll's local_rate_limit filter and bucket (20 per fill, 20 max, 60s) in their config_dump"
	fi
fi

# D11: every Envoy's bucket has refilled before enrolment, which goes through
# any of them. Once a whole fill interval (60s) has passed since the burst
# ended every Envoy holds 20 again (20 earned one per 3s, or a timer tick),
# not only the one a probe happens to reach: wait --refill-wait seconds from
# the end of the burst, then send 2 probes per Envoy at once; every one must
# reach farmer.
if ((refill_wait == 0)); then
	skip D11 "not waiting for /v1/enroll's buckets: enrolment through a drained Envoy is refused (429) for up to 60s"
elif [[ -n $limited ]]; then
	left_ms=$((burst_end_ms + refill_wait * 1000 - $(now_ms)))
	if ((left_ms > 0)); then
		dmz_log "waiting $(ms_secs "$left_ms")s for every Envoy's /v1/enroll bucket to refill"
		sleep "$(ms_secs "$left_ms")"
	fi
	probes=$((2 * envoys))
	burst "$tmp/refill" "$probes"
	waited=$(ms_secs $(($(now_ms) - burst_end_ms)))
	tally "$tmp/refill" "$probes"
	if ((n_limited)); then
		fail D11 "$n_limited of $probes POST /v1/enroll still answered 429 ${waited}s after the burst: not every Envoy's bucket refilled (enrolment through it would be refused)"
	elif ((n_other)); then
		fail D11 "after the refill POST /v1/enroll got $first_other ($n_other of $probes)"
	elif [[ -z $enroll_ok ]]; then
		fail D11 "after the refill POST /v1/enroll answered, but not with farmer's 401 (D8 failed)"
	else
		pass D11 "every Envoy's /v1/enroll bucket refilled: $probes of $probes probes reached farmer ${waited}s after the burst"
	fi
else
	skip D11 "the buckets were never drained (D9 failed)"
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
		# Each pod: the farmerbus container mounts the trust ConfigMap's
		# volume at exactly the directory IMAS_NATS_TRUST_DIR names.
		elif jq -e --arg cm "$DMZ_TRUST_CONFIGMAP" '
			all(.items[];
				.spec as $spec
				| ($spec.containers[] | select(.name == "farmerbus")) as $bus
				| ([$bus.env[]? | select(.name == "IMAS_NATS_TRUST_DIR") | .value][0]) as $dir
				| $dir != null and any($spec.volumes[]?; .configMap.name? == $cm and
					(.name as $v | any($bus.volumeMounts[]?; .name == $v and .mountPath == $dir))))' <<<"$pods" >/dev/null; then
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
