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
#                        build.log (uat/tests/run.sh)
#   <out-dir>/outputs/   run.json (this run's inputs), uat.json (tofu output
#                        uat, no credentials), k0s/endpoints.json,
#                        k0s/uat-ca.crt, k0s/k0sctl-{dmz,core}.yaml,
#                        hub/core/out/{core,admin}.json and uat-ca.crt,
#                        hub/harness.json, dmz/dmz.json,
#                        enroll/{run,tenants,keys,sprouts,sprouts-detail}.json
#
# and then scans every copied file for anything that looks like a secret (a
# private key, kubeconfig credentials, a JWT, an NKey seed, a JSON password,
# secret, token or unseal key). A file that matches is deleted from <out-dir>,
# named, and the script exits 1, so a leak is a failed step rather than an
# uploaded artifact. Fix the allowlist or the file that grew a secret.
set -euo pipefail

prog=$(basename "$0")
[ $# -eq 2 ] || { echo "usage: $prog <state-dir> <out-dir>" >&2; exit 2; }
state=$1 out=$2
[ -d "$state" ] || { echo "$prog: not a directory: $state" >&2; exit 2; }

report_files=(
  report/summary.txt
  report/junit.xml
  report/events.json
  report/build.log
)
output_files=(
  run.json
  uat.json
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
for f in "${output_files[@]}"; do copy "$f" "$out/outputs"; done

# Patterns of things that must never be uploaded (extended regular
# expressions). The first list is matched ignoring case, the second exactly.
patterns_ci=(
  'BEGIN [A-Z ]*PRIVATE KEY'
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
