#!/usr/bin/env bash
# runner-cidr.sh: the runner's public IPv4 address as one /32, the runner_cidr
# of the Shared contract (section 4h): the only source the UAT network rules
# let in from the internet (Envoy on the DMZ, 443 on core, 443 on the Bastion).
#
#   runner-cidr.sh         print A.B.C.D/32
#
# It asks several independent "what is my address" services over IPv4 and
# accepts the answer only when at least RUNNER_IP_MIN_AGREE of them answered,
# every answer is the same address, and that address is a public unicast one.
# A single service could be wrong or lie; opening the NSGs to a wrong address
# would either lock the run out or let someone else in, so any disagreement
# fails the run instead of picking one.
#
# Environment:
#   RUNNER_IP_SOURCES    space separated URLs (default: three services below)
#   RUNNER_IP_MIN_AGREE  how many must answer (default 2)
#   RUNNER_IP_TIMEOUT    seconds per request (default 10)
#
# Exit status: 0 with the /32 on stdout; 1 when no trustworthy address was
# found (the reason on stderr).
set -euo pipefail

prog=$(basename "$0")
sources=${RUNNER_IP_SOURCES:-https://api.ipify.org https://checkip.amazonaws.com https://icanhazip.com}
min_agree=${RUNNER_IP_MIN_AGREE:-2}
req_timeout=${RUNNER_IP_TIMEOUT:-10}

log() { echo "$prog: $*" >&2; }

[[ "$min_agree" =~ ^[1-9][0-9]*$ ]] || { log "RUNNER_IP_MIN_AGREE must be a positive number"; exit 1; }
[[ "$req_timeout" =~ ^[1-9][0-9]*$ ]] || { log "RUNNER_IP_TIMEOUT must be a positive number"; exit 1; }

# is_ipv4 ADDR: dotted quad, each octet 0 to 255, no leading zeros.
is_ipv4() {
  local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
  [[ "$1" =~ ^$octet\.$octet\.$octet\.$octet$ ]]
}

# not_public ADDR: prints why ADDR is not a public unicast address, or nothing.
not_public() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  : "$d"
  if [ "$a" -eq 0 ]; then echo "in 0.0.0.0/8 ('this network')"
  elif [ "$a" -eq 10 ]; then echo "private (10.0.0.0/8)"
  elif [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ]; then echo "carrier-grade NAT (100.64.0.0/10)"
  elif [ "$a" -eq 127 ]; then echo "loopback (127.0.0.0/8)"
  elif [ "$a" -eq 169 ] && [ "$b" -eq 254 ]; then echo "link local (169.254.0.0/16)"
  elif [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; then echo "private (172.16.0.0/12)"
  elif [ "$a" -eq 192 ] && [ "$b" -eq 0 ] && [ "$c" -eq 0 ]; then echo "IETF protocol assignments (192.0.0.0/24)"
  elif [ "$a" -eq 192 ] && [ "$b" -eq 0 ] && [ "$c" -eq 2 ]; then echo "documentation (192.0.2.0/24)"
  elif [ "$a" -eq 192 ] && [ "$b" -eq 168 ]; then echo "private (192.168.0.0/16)"
  elif [ "$a" -eq 198 ] && { [ "$b" -eq 18 ] || [ "$b" -eq 19 ]; }; then echo "benchmarking (198.18.0.0/15)"
  elif [ "$a" -eq 198 ] && [ "$b" -eq 51 ] && [ "$c" -eq 100 ]; then echo "documentation (198.51.100.0/24)"
  elif [ "$a" -eq 203 ] && [ "$b" -eq 0 ] && [ "$c" -eq 113 ]; then echo "documentation (203.0.113.0/24)"
  elif [ "$a" -ge 224 ]; then echo "multicast or reserved (224.0.0.0/3)"
  fi
}

answers=()
for url in $sources; do
  case "$url" in
    https://*) ;;
    *) log "refusing $url: only https sources are used"; continue ;;
  esac
  if ! body=$(curl -4 -fsS --max-time "$req_timeout" --proto '=https' "$url" 2>/dev/null); then
    log "$url did not answer"
    continue
  fi
  # One line, surrounding white space trimmed. Anything else is not an address.
  addr=$(printf '%s' "$body" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  if [ "$(printf '%s\n' "$addr" | wc -l)" -ne 1 ] || ! is_ipv4 "$addr"; then
    log "$url answered something that is not one IPv4 address; ignoring it"
    continue
  fi
  log "$url says $addr"
  answers+=("$addr")
done

if [ "${#answers[@]}" -lt "$min_agree" ]; then
  log "only ${#answers[@]} of the address services answered with an address; need $min_agree"
  exit 1
fi

first=${answers[0]}
for a in "${answers[@]}"; do
  if [ "$a" != "$first" ]; then
    log "the address services disagree (${answers[*]}): the runner has no single public address; refusing to guess"
    exit 1
  fi
done

why=$(not_public "$first")
if [ -n "$why" ]; then
  log "$first is not a public address: $why"
  exit 1
fi

echo "$first/32"
