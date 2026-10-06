#!/usr/bin/env bash
# run-id.sh: the run_id of one UAT run (UAT.6; Shared contract, section 4h of
# docs/claude-code-parallel-build-plan.md: 6 to 10 lowercase letters and
# digits).
#
#   run-id.sh              print a new run_id: 8 characters, a letter then
#                          7 letters or digits, from /dev/urandom
#   run-id.sh --check ID   exit 0 when ID is a valid run_id, 2 otherwise
#
# The first character is a letter so the id never reads as a number to a tool
# that guesses types (a tag value, a YAML scalar). 36^7 ids is enough that two
# runs never meet; the resource group name imas-uat-<run_id> would collide
# loudly in tofu apply anyway.
set -euo pipefail

prog=$(basename "$0")
RANDOM_SOURCE=${RUN_ID_RANDOM_SOURCE:-/dev/urandom}

valid() { [[ "$1" =~ ^[a-z0-9]{6,10}$ ]]; }

# pick ALPHABET COUNT: COUNT characters of ALPHABET, unbiased (bytes at or
# above the largest multiple of the alphabet's length are thrown away).
pick() {
  local alphabet=$1 count=$2 n=${#1} out="" limit byte
  limit=$((256 - 256 % n))
  while [ "${#out}" -lt "$count" ]; do
    for byte in $(od -An -N64 -tu1 "$RANDOM_SOURCE"); do
      [ "$byte" -lt "$limit" ] || continue
      out+=${alphabet:byte % n:1}
      [ "${#out}" -lt "$count" ] || break
    done
  done
  printf '%s' "$out"
}

case "${1:-}" in
  "")
    id="$(pick abcdefghijklmnopqrstuvwxyz 1)$(pick abcdefghijklmnopqrstuvwxyz0123456789 7)"
    valid "$id" || { echo "$prog: generated an invalid run_id '$id'" >&2; exit 1; }
    echo "$id"
    ;;
  --check)
    [ $# -eq 2 ] || { echo "usage: $prog [--check ID]" >&2; exit 2; }
    if valid "$2"; then exit 0; fi
    echo "$prog: '$2' is not a run_id (6 to 10 lowercase letters and digits)" >&2
    exit 2
    ;;
  *)
    echo "usage: $prog [--check ID]" >&2
    exit 2
    ;;
esac
