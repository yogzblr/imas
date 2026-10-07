#!/usr/bin/env bash
# janitor.sh: delete expired UAT resource groups (.github/workflows/uat-janitor.yml).
#
#   janitor.sh run [--dry-run]            list, select, delete, report
#   janitor.sh select <groups.json> [--now TIME]
#                                         print the selection as JSON, no Azure
#
# A resource group is deleted only when ALL of these hold:
#   - its tag purpose is exactly imas-uat (the bootstrap group is tagged
#     imas-uat-state and never matches; an untagged group is never looked at);
#   - its name is imas-uat-<run_id> and its tag run_id is that same run_id
#     (6 to 10 lowercase letters and digits), as uat/tofu creates it;
#   - its tag expires_at is an RFC 3339 time (UTC "Z" or an offset, optional
#     fraction of a second) that has passed;
#   - Azure does not already report it as Deleting.
# A group tagged purpose=imas-uat that fails any other check is kept and
# reported as a problem, never deleted. Right before deleting, the group is
# read again and must still be selected.
#
# select prints {"delete": [{name, run_id, expires_at}], "keep": [{name,
# expires_at, reason}], "problems": [{name, reason}]}, listing only groups
# tagged purpose=imas-uat. TIME is epoch seconds or an RFC 3339 time
# (default: now).
#
# run lists the groups with az group list --tag purpose=imas-uat, deletes the
# selected ones one by one (az group delete, VMs force-deleted), and prints
# what it deleted, what failed, what it kept and why. It writes the same to
# GITHUB_STEP_SUMMARY when that is set.
#
# Environment: AZ (default az); JANITOR_NOW (epoch seconds or RFC 3339) stands
# in for the current time in run, for tests only.
#
# Exit status: 0 when every selected group was deleted (or none was due);
# 1 when listing or any deletion failed; 2 on a usage error.
set -euo pipefail

prog=$(basename "$0")
AZ=${AZ:-az}

usage() {
  cat >&2 <<EOF
usage: $prog run [--dry-run]
       $prog select <groups.json> [--now TIME]
EOF
  exit 2
}

# RFC 3339 to epoch seconds, or null when it is not one (jq).
read -r -d '' RFC3339 <<'JQ' || true
def rfc3339:
  if type != "string" then null
  else
    (capture("^(?<d>[0-9]{4}-[0-9]{2}-[0-9]{2})[Tt](?<t>[0-9]{2}:[0-9]{2}:[0-9]{2})(\\.[0-9]+)?(?<z>[Zz]|[+-][0-9]{2}:[0-9]{2})$") // null) as $m
    | if $m == null then null
      else
        (try (($m.d + "T" + $m.t + "Z") | fromdateiso8601) catch null) as $base
        | if $base == null then null
          elif ($m.z | ascii_downcase) == "z" then $base
          else
            ($m.z[0:1]) as $sign
            | (($m.z[1:3] | tonumber) * 3600 + ($m.z[4:6] | tonumber) * 60) as $off
            | if $sign == "+" then $base - $off else $base + $off end
          end
      end
  end;
JQ

# The whole selection rule, as one jq program over an az group list -o json
# array. $now is epoch seconds.
read -r -d '' SELECT_BODY <<'JQ' || true
[ .[] | select((.tags // {}) | type == "object" and .purpose == "imas-uat") ]
| map(
    . as $g
    | ($g.tags.run_id // "") as $rid
    | ($g.tags.expires_at // null) as $exp
    | ($exp | rfc3339) as $at
    | if ($g.name | test("^imas-uat-[a-z0-9]{6,10}$") | not) then
        {kind: "problems", name: $g.name, reason: "tagged purpose=imas-uat but the name is not imas-uat-<run_id>"}
      elif ($rid | type) != "string" or ("imas-uat-" + $rid) != $g.name then
        {kind: "problems", name: $g.name, reason: ("tag run_id '" + ($rid | tostring) + "' does not match the name")}
      elif $exp == null then
        {kind: "problems", name: $g.name, reason: "no expires_at tag"}
      elif $at == null then
        {kind: "problems", name: $g.name, reason: ("expires_at '" + ($exp | tostring) + "' is not an RFC 3339 time")}
      elif (($g.properties // {}).provisioningState // "") == "Deleting" then
        {kind: "keep", name: $g.name, expires_at: $exp, reason: "already being deleted"}
      elif $at > $now then
        {kind: "keep", name: $g.name, expires_at: $exp, reason: "not expired"}
      else
        {kind: "delete", name: $g.name, run_id: $rid, expires_at: $exp}
      end
  )
| {
    delete: [ .[] | select(.kind == "delete") | del(.kind) ],
    keep: [ .[] | select(.kind == "keep") | del(.kind) ],
    problems: [ .[] | select(.kind == "problems") | del(.kind) ]
  }
JQ
SELECT="$RFC3339
$SELECT_BODY"

# to_epoch TIME: epoch seconds from epoch seconds or an RFC 3339 time.
to_epoch() {
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "$1"
  else
    jq -rn --arg t "$1" "$RFC3339"' $t | rfc3339 // error("not a time: " + $t)'
  fi
}

# select_groups FILE NOW
select_groups() {
  jq -e 'type == "array"' "$1" >/dev/null 2>&1 || { echo "$prog: $1 is not a JSON array of resource groups" >&2; return 1; }
  jq --argjson now "$2" "$SELECT" "$1"
}

# summary LINE...: each argument is one line, on stdout and in the step summary.
summary() {
  printf '%s\n' "$@"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n' "$@" >>"$GITHUB_STEP_SUMMARY"; fi
}

cmd_select() {
  [ $# -ge 1 ] || usage
  local file=$1 now
  now=$(date -u +%s)
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --now) [ $# -ge 2 ] || usage; now=$(to_epoch "$2") || exit 2; shift 2 ;;
      *) usage ;;
    esac
  done
  select_groups "$file" "$now"
}

cmd_run() {
  local dry=0 work listing sel now name exp again deleted=() failed=() status=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) dry=1; shift ;;
      *) usage ;;
    esac
  done
  work=$(mktemp -d)
  # shellcheck disable=SC2064 # expand $work now
  trap "rm -rf '$work'" EXIT
  listing="$work/groups.json"
  if ! $AZ group list --tag purpose=imas-uat -o json >"$listing"; then
    echo "::error::$prog: az group list failed; nothing was deleted"
    return 1
  fi
  now=$(date -u +%s)
  if [ -n "${JANITOR_NOW:-}" ]; then now=$(to_epoch "$JANITOR_NOW") || return 2; fi
  sel=$(select_groups "$listing" "$now") || return 1

  summary "## UAT janitor, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ "$dry" -eq 0 ] || summary "Dry run: nothing is deleted."

  while IFS=$'\t' read -r name exp; do
    [ -n "$name" ] || continue
    # Read the group again: its tags may have changed since the listing.
    if ! $AZ group show --name "$name" -o json >"$work/one.json" 2>/dev/null; then
      echo "$prog: $name is gone already" >&2
      continue
    fi
    again=$(jq -s '.' "$work/one.json" | jq --argjson now "$now" "$SELECT" | jq -r '.delete[0].name // empty')
    if [ "$again" != "$name" ]; then
      echo "$prog: $name no longer qualifies on a second read; left alone" >&2
      continue
    fi
    if [ "$dry" -eq 1 ]; then
      deleted+=("$name (expired $exp; dry run, not deleted)")
      continue
    fi
    echo "$prog: deleting $name (expired $exp)" >&2
    if $AZ group delete --name "$name" --yes --force-deletion-types Microsoft.Compute/virtualMachines >&2; then
      deleted+=("$name (expired $exp)")
    else
      failed+=("$name (expired $exp)")
      status=1
    fi
  done < <(jq -r '.delete[] | [.name, .expires_at] | @tsv' <<<"$sel")

  summary "" "Deleted: ${#deleted[@]}"
  for d in "${deleted[@]}"; do summary "- $d"; done
  if [ "${#failed[@]}" -gt 0 ]; then
    summary "" "Failed to delete: ${#failed[@]}"
    for d in "${failed[@]}"; do
      summary "- $d"
      echo "::error::$prog: could not delete $d"
    done
  fi
  summary "" "Kept: $(jq '.keep | length' <<<"$sel")"
  while IFS= read -r line; do [ -z "$line" ] || summary "- $line"; done < <(jq -r '.keep[] | "\(.name): \(.reason) (expires_at \(.expires_at))"' <<<"$sel")
  if [ "$(jq '.problems | length' <<<"$sel")" -gt 0 ]; then
    summary "" "Tagged purpose=imas-uat but left alone (fix or delete by hand):"
    while IFS= read -r line; do
      summary "- $line"
      echo "::warning::$prog: $line"
    done < <(jq -r '.problems[] | "\(.name): \(.reason)"' <<<"$sel")
  fi
  return "$status"
}

case "${1:-}" in
  run) shift; cmd_run "$@" ;;
  select) shift; cmd_select "$@" ;;
  *) usage ;;
esac
