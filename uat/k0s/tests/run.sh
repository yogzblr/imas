#!/usr/bin/env bash
# uat/k0s/tests/run.sh: every static check and test for uat/k0s.
#   ShellCheck on the scripts and stubs, yamllint on the templates and the
#   golden rendered files, then tests/test-k0s.sh.
# A missing shellcheck or yamllint is reported as skipped, never as passed;
# REQUIRE_LINTERS=1 makes a missing one a failure.
set -uo pipefail

K0S="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rc=0

skip() {
  if [[ ${REQUIRE_LINTERS:-} == 1 ]]; then
    echo "FAIL: $1 not installed"
    rc=1
  else
    echo "SKIPPED: $1 not installed"
  fi
}

if command -v shellcheck >/dev/null 2>&1; then
  echo "== shellcheck"
  (cd "$K0S" && shellcheck -x -P SCRIPTDIR ./*.sh tests/*.sh tests/stubs/*) && echo ok || rc=1
else
  skip shellcheck
fi

if command -v yamllint >/dev/null 2>&1; then
  echo "== yamllint"
  yamllint -s -c "$K0S/.yamllint.yaml" "$K0S/.yamllint.yaml" "$K0S/templates" \
    "$K0S"/testdata/expected/*.yaml "$K0S"/testdata/downloads/*.yaml && echo ok || rc=1
else
  skip yamllint
fi

echo "== test-k0s.sh"
"$K0S/tests/test-k0s.sh" || rc=1

exit "$rc"
