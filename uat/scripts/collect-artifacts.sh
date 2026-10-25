#!/usr/bin/env bash
# collect-artifacts.sh: copy what a UAT run may upload, and nothing else.
#
#   collect-artifacts.sh <state-dir> <out-dir>
#
# The run's state directory holds credentials: the per-run SSH key and WinRM
# password, the kubeconfigs, OpenBao's unseal keys and root token, the NKey
# seeds, the bootstrap admin's keys, the Keycloak passwords and the
# enrolment keys. None of them may leave the runner. So this copies by an
# allowlist of known non-secret files (missing ones are skipped):
#
#   <out-dir>/report/    the test report: summary.txt, junit.xml, events.json,
#                        build.log (uat/tests/run.sh), and every regular
#                        file under report/diagnostics/ (uat/scripts/
#                        diagnostics.sh and vmctl.sh's channel captures,
#                        which redact them first); and, under
#                        report/diagnostics/channel/, the Bastion tunnels'
#                        own logs (access/logs/<vm>-<kind>.log, as tunnels/)
#                        and session.sh's supervisor log (W10)
#   <out-dir>/outputs/   run.json (this run's inputs), uat.json (tofu output
#                        uat, no credentials), ha_node_names.json and
#                        object_store.json (tofu outputs ha_node_names and
#                        object_store, no key), k0s/endpoints.json,
#                        k0s/uat-ca.crt, k0s/k0sctl-{dmz,core}.yaml,
#                        hub/core/out/{core,admin}.json and uat-ca.crt,
#                        hub/harness.json, dmz/dmz.json,
#                        enroll/{run,tenants,keys,sprouts,sprouts-detail}.json
#
# build.log, the tunnel logs and the supervisor log are text logs of
# everything that ran, so they go through redact (uat/scripts/redact.sh) on
# the way: UAT Run 2 #6's build.log held a login token (az-relogin.sh's
# ::add-mask:: line, which GitHub masks in the job log but not in a file)
# and was deleted below, leaving no build.log. There is always a build.log:
# when the run wrote none, one that says so (W10).
#
# and then scans every copied file for anything that looks like a secret (a
# private key, kubeconfig credentials, a Bearer or Basic credential, a JWT,
# an NKey seed, a JSON password, secret, token or unseal key). A file that
# matches is deleted from <out-dir>, named, and the script exits 1, so a
# leak is a failed step rather than an uploaded artifact. Fix the allowlist
# or the file that grew a secret.
set -euo pipefail

prog=$(basename "$0")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=redact.sh
. "$here/redact.sh"
[ $# -eq 2 ] || { echo "usage: $prog <state-dir> <out-dir>" >&2; exit 2; }
state=$1 out=$2
[ -d "$state" ] || { echo "$prog: not a directory: $state" >&2; exit 2; }

report_files=(
  report/summary.txt
  report/junit.xml
  report/events.json
)
output_files=(
  run.json
  uat.json
  ha_node_names.json
  object_store.json
  k0s/endpoints.json
  k0s/uat-ca.crt
  k0s/k0sctl-dmz.yaml
  k0s/k0sctl-core.yaml
  hub/core/out/core.json
  hub/core/out/admin.json
  hub/core/out/uat-ca.crt
  hub/harness.json
  dmz/dmz.json
  enroll/run.json
  enroll/tenants.json
  enroll/keys.json
  enroll/sprouts.json
  enroll/sprouts-detail.json
)

mkdir -p "$out/report" "$out/outputs"

# copy SRC-REL DEST-DIR: copies a regular file (never a symlink, which could
# point anywhere) keeping its relative path.
copied=0
copy() {
  local rel=$1 dest=$2 src="$state/$1"
  [ -f "$src" ] && [ ! -L "$src" ] || return 0
  mkdir -p "$dest/$(dirname "$rel")"
  cp "$src" "$dest/$rel"
  copied=$((copied + 1))
}
for f in "${report_files[@]}"; do copy "$f" "$out"; done

# copy_redacted SRC-REL DEST-PATH: a text log through redact.
copy_redacted() {
  local src="$state/$1" dest=$2
  [ -f "$src" ] && [ ! -L "$src" ] || return 1
  mkdir -p "$(dirname "$dest")"
  redact <"$src" >"$dest"
  copied=$((copied + 1))
}
if ! copy_redacted report/build.log "$out/report/build.log"; then
  mkdir -p "$out/report"
  echo "$prog: the run wrote no report/build.log (the Tests step did not run, or failed before uat/tests/run.sh started); see the job log" >"$out/report/build.log"
fi
if [ -d "$state/access/logs" ] && [ ! -L "$state/access/logs" ]; then
  for f in "$state"/access/logs/*.log; do
    [ -f "$f" ] || continue
    case ${f##*/} in
      supervisor.log) copy_redacted "access/logs/supervisor.log" "$out/report/diagnostics/channel/supervisor.log" || true ;;
      *) copy_redacted "access/logs/${f##*/}" "$out/report/diagnostics/channel/tunnels/${f##*/}" || true ;;
    esac
  done
fi
if [ -d "$state/report/diagnostics" ] && [ ! -L "$state/report/diagnostics" ]; then
  while IFS= read -r -d '' f; do
    copy "${f#"$state"/}" "$out"
  done < <(find "$state/report/diagnostics" -type f -print0)
fi
for f in "${output_files[@]}"; do copy "$f" "$out/outputs"; done

# Patterns of things that must never be uploaded (extended regular
# expressions). The first list is matched ignoring case, the second exactly.
patterns_ci=(
  'BEGIN [A-Z ]*PRIVATE KEY'
  # A Bearer credential of any shape (an opaque token, not only a JWT).
  'Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{8,}'
  # A Basic Authorization header's credential (base64 of user:password).
  # base64 of user:password is 4 characters or more ("u:p" is dTpw).
  'Authorization"?[[:space:]]*[:=][[:space:]]*"?Basic[[:space:]]+[A-Za-z0-9+/]{2,}={0,2}'
  'client-key-data:'
  'client-certificate-data:'
  '"[a-z_]*password"[[:space:]]*:[[:space:]]*"[^"]+'
  '"[a-z_]*secret"[[:space:]]*:[[:space:]]*"[^"]+'
  '"(root_)?token"[[:space:]]*:[[:space:]]*"[^"]+'
  '"unseal_keys[a-z0-9_]*"'
  '"registration_key"[[:space:]]*:'
)
patterns_cs=(
  # A JWT (header and payload are base64url JSON, so both start with eyJ).
  '(^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.'
  # An NKey seed: S, the key type, then base32 (58 characters in all).
  '(^|[^A-Z0-9])S[OAUNCX][A-Z2-7]{56}([^A-Z2-7]|$)'
)

leaks=()
while IFS= read -r -d '' f; do
  hit=""
  for p in "${patterns_ci[@]}"; do
    if grep -Eiq -- "$p" "$f"; then hit=$p && break; fi
  done
  if [ -z "$hit" ]; then
    for p in "${patterns_cs[@]}"; do
      if grep -Eq -- "$p" "$f"; then hit=$p && break; fi
    done
  fi
  if [ -n "$hit" ]; then
    leaks+=("${f#"$out"/} (matches: $hit)")
    rm -f "$f"
  fi
done < <(find "$out" -type f -print0)

if [ "${#leaks[@]}" -gt 0 ]; then
  for l in "${leaks[@]}"; do
    echo "::error::$prog: removed $l; it looks like a secret and is not uploaded"
  done
  exit 1
fi

echo "$prog: $copied file(s) in $out, none looks secret" >&2
