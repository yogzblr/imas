#!/usr/bin/env bash
# Run the UAT gate's acceptance tests against a deployed stack
# (docs/claude-code-parallel-build-plan.md, section 4h; uat/tests/README.md).
#
# Usage: uat/tests/run.sh <tier> [scenario id ...]
#   tier  smoke, core, resilience, ingredients, lifecycle, ha or all
#   ids   catalogue ids of that tier (T1 C2 ...), or ingredient ids
#         (I.file.managed ...) on their own
#
# Environment:
#   IMAS_UAT_DIR          required: the material directory (README.md)
#   IMAS_UAT_VMCTL        the vmctl.sh to use (default: harness.json's vmctl,
#                         else uat/access/vmctl.sh)
#   IMAS_UAT_REPORT_DIR   where the report goes (default $IMAS_UAT_DIR/report)
#   IMAS_UAT_TIMEOUT      go test -timeout (default by tier: smoke 45m,
#                         core 4h, resilience and ha 3h, others 8h)
#   IMAS_UAT_RELEASE_TAG  optional: the release the sprouts must run (S1)
#   IMAS_UAT_CORE_KUBECONFIG, IMAS_UAT_ENDPOINTS
#                         the core kubeconfig and endpoints file: with them,
#                         T1, T4 and T5 make users for the tenants they create
#                         with uat/hub/core/bind-tenant.sh --scratch-user
#                         (IMAS_UAT_BIND_TENANT overrides the script)
#   IMAS_UAT_DMZ_KUBECONFIG, IMAS_UAT_DMZ_CHART, IMAS_UAT_CORE_CHART,
#   IMAS_UAT_CORE_CHECK   the ha tier: the DMZ kubeconfig, the charts the
#                         hubs were installed from (HA3's helm upgrade; the
#                         core one defaults to the state directory's) and
#                         uat/hub/core/check.sh (default; HA3 runs it)
#   UAT_SESSION_HOOK      optional (W6): uat/access/session.sh. With it each
#                         top-level test runs in its own test process, and
#                         `$UAT_SESSION_HOOK phase "tests: <Test>"` runs
#                         before each one, so the Azure login and the
#                         Bastion tunnels are refreshed between tests, never
#                         during one. IMAS_UAT_TIMEOUT is then the budget of
#                         all of them together. A failed hook stops the run
#                         (the rest are reported missing).
#   IMAS_UAT_DIAG_HOOK    optional (W8; the UAT workflow sets
#                         uat/scripts/diagnostics.sh): after a top-level test
#                         (with UAT_SESSION_HOOK) or a package (without)
#                         fails, `$IMAS_UAT_DIAG_HOOK kube
#                         <report>/diagnostics/<name>` collects the hubs'
#                         state while it is fresh, bounded by
#                         IMAS_UAT_DIAG_SECONDS (default 300). Its time
#                         counts against IMAS_UAT_TIMEOUT.
#
# The test channel (W10): run.sh exports IMAS_UAT_REPORT_DIR (the report
# directory, for the harness's per-VM diagnostics) and VMCTL_DIAG_DIR
# (<report>/diagnostics, where vmctl.sh captures a failed channel), and
# AZ_RELOGIN_ADD_MASK=0: a login made under it prints no ::add-mask:: line
# with its token, as everything printed here is kept in build.log. Everything
# that goes into build.log goes through redact (uat/scripts/redact.sh).
#
# It builds the report tool and one test binary per package under
# uat/tests with the uat tag, runs them with the tier's -run pattern, and
# prints one line per scenario id, OS and tenant. The report directory
# gets events.json (test2json), summary.txt, junit.xml and build.log: the
# packages' compile errors, everything the tests printed (as shown while
# they ran), run.sh's own messages and the summary, in order.
#
# Exit status 0 only when every selected scenario passed or was skipped
# with a written reason, at least one test of the tier ran, every
# catalogue scenario of the tier ran or was skipped with a reason, and
# nothing failed outside a test (the no silent green rule). 1 on any
# failure (a test, a package that doesn't build, the rule), 2 on a usage
# error or an unknown scenario id.
set -euo pipefail

usage() {
	sed -n '5,9p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

[ $# -ge 1 ] || usage
tier=$1
shift
case "$tier" in
smoke | core | resilience | ingredients | lifecycle | ha | all) ;;
-h | --help) usage ;;
*)
	echo "run.sh: unknown tier '$tier'" >&2
	usage
	;;
esac

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
if [ -z "${IMAS_UAT_DIR:-}" ]; then
	echo "run.sh: set IMAS_UAT_DIR to the material directory (uat/tests/README.md)" >&2
	exit 2
fi
if [ ! -d "$IMAS_UAT_DIR" ]; then
	echo "run.sh: IMAS_UAT_DIR=$IMAS_UAT_DIR is not a directory" >&2
	exit 2
fi
IMAS_UAT_DIR=$(cd "$IMAS_UAT_DIR" && pwd)
export IMAS_UAT_DIR
# shellcheck source-path=SCRIPTDIR source=../scripts/redact.sh
. "$repo/uat/scripts/redact.sh"
export IMAS_UAT_VMCTL_DEFAULT="$repo/uat/access/vmctl.sh"
export IMAS_UAT_BIND_TENANT_DEFAULT="$repo/uat/hub/core/bind-tenant.sh"
export IMAS_UAT_CORE_CHECK_DEFAULT="$repo/uat/hub/core/check.sh"
report="${IMAS_UAT_REPORT_DIR:-$IMAS_UAT_DIR/report}"
case "$tier" in
smoke) default_timeout=45m ;;
core) default_timeout=4h ;;
resilience | ha) default_timeout=3h ;;
*) default_timeout=8h ;;
esac
timeout="${IMAS_UAT_TIMEOUT:-$default_timeout}"
catalogue="$here/catalogue.tsv"

mkdir -p "$report/bin"
report=$(cd "$report" && pwd)
events="$report/events.json"
: >"$events"
build_log="$report/build.log"
: >"$build_log"
export IMAS_UAT_REPORT_DIR="$report"
export VMCTL_DIAG_DIR="$report/diagnostics"
export AZ_RELOGIN_ADD_MASK=0

# say TEXT: a message of run.sh's, on stderr and in build.log.
say() {
	echo "run.sh: $*" >&2
	echo "run.sh: $*" >>"$build_log"
}

cd "$repo"
say "tier $tier${*:+, scenarios $*}; report in $report"
go build -o "$report/bin/uatreport" ./uat/tests/uatreport
uatreport="$report/bin/uatreport"
pattern=$("$uatreport" pattern -catalogue "$catalogue" -tier "$tier" "$@")
say "go test -run '$pattern'"

# Every package under uat/tests with tests under the uat tag, except the
# harness and the report tool, whose own unit tests aren't scenarios.
pkgs=()
while IFS= read -r line; do
	[ -n "$line" ] && pkgs+=("$line")
done < <(go list -tags uat -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}|{{.Dir}}{{end}}' ./uat/tests/... |
	grep -v -e '/uat/tests/harness|' -e '/uat/tests/uatreport|' || true)
if [ ${#pkgs[@]} -eq 0 ]; then
	echo "run.sh: no test packages under uat/tests" >&2
	exit 2
fi

# dur_seconds 1h30m: a go duration of h, m and s, in seconds.
dur_seconds() {
	local d=$1 n=0 v u
	[[ "$d" =~ ^([0-9]+[hms])+$ ]] || return 1
	while [[ "$d" =~ ^([0-9]+)([hms])(.*)$ ]]; do
		v=${BASH_REMATCH[1]} u=${BASH_REMATCH[2]} d=${BASH_REMATCH[3]}
		case $u in h) n=$((n + 10#$v * 3600)) ;; m) n=$((n + 10#$v * 60)) ;; s) n=$((n + 10#$v)) ;; esac
	done
	echo "$n"
}

# fail_event PKG TEXT: a package-level failure in the events, so the
# summary reports it.
fail_event() {
	jq -cn --arg p "$1" --arg o "$2"$'\n' '{Action: "output", Package: $p, Output: $o}, {Action: "fail", Package: $p}' >>"$events"
}

# run_bin PKG DIR BIN PATTERN TIMEOUT: one test process, its events into the
# report and its output into build.log as well.
run_bin() {
	(cd "$2" && go tool test2json -t -p "$1" "$3" -test.v=test2json \
		-test.run "$4" -test.timeout "$5" -test.count=1) |
		tee -a "$events" | "$uatreport" follow | redact | tee -a "$build_log"
}

# diagnose NAME: runs IMAS_UAT_DIAG_HOOK after a failure, if set, bounded.
diagnose() {
	[ -n "${IMAS_UAT_DIAG_HOOK:-}" ] || return 0
	local dir="$report/diagnostics/$1" started=$SECONDS
	say "$1 failed; collecting the hubs' state into $dir"
	timeout -k 10 "${IMAS_UAT_DIAG_SECONDS:-300}" "$IMAS_UAT_DIAG_HOOK" kube "$dir" 2>&1 | redact >>"$build_log" ||
		say "the diagnostics for $1 exited $? (see build.log)"
	say "diagnostics for $1 took $((SECONDS - started))s"
}

if [ -n "${UAT_SESSION_HOOK:-}" ]; then
	budget=$(dur_seconds "$timeout") || {
		echo "run.sh: IMAS_UAT_TIMEOUT '$timeout' must be h, m and s (like 165m) with UAT_SESSION_HOOK" >&2
		exit 2
	}
	# The top-level part of the pattern selects the tests; the rest (the
	# ingredient ids after TestIngredients$/) goes along to each.
	top=${pattern%%/*}
	sub=""
	[ "$top" = "$pattern" ] || sub=/${pattern#*/}
	say "one test process per top-level test, the session refreshed between them (UAT_SESSION_HOOK); budget ${budget}s"
fi
started=$SECONDS
stopped=""

status=0
for entry in "${pkgs[@]}"; do
	pkg=${entry%%|*}
	dir=${entry#*|}
	bin="$report/bin/$(echo "${pkg#*/uat/}" | tr '/' '-').test"
	if ! go test -tags uat -c -o "$bin" "$pkg" 2>"$report/compile.log"; then
		cat "$report/compile.log" >&2
		{
			echo "run.sh: $pkg did not build with the uat tag:"
			cat "$report/compile.log"
		} >>"$build_log"
		# A package that doesn't build fails the run through the summary.
		printf '{"Action":"output","Package":"%s","Output":"the package did not build with the uat tag; see build.log\\n"}\n{"Action":"fail","Package":"%s"}\n' \
			"$pkg" "$pkg" >>"$events"
		status=1
		continue
	fi
	say "running $pkg"
	if [ -z "${UAT_SESSION_HOOK:-}" ]; then
		if ! run_bin "$pkg" "$dir" "$bin" "$pattern" "$timeout"; then
			status=1
			diagnose "$(echo "${pkg#*/uat/}" | tr '/' '-')"
		fi
		continue
	fi
	[ -z "$stopped" ] || continue
	# -test.list runs TestMain too, which only reads (the tenants' claims).
	if ! tests=$(cd "$dir" && "$bin" -test.list "$top" 2>"$report/list.log"); then
		cat "$report/list.log" >&2
		fail_event "$pkg" "listing the tests failed: $(tail -n 5 "$report/list.log")"
		status=1
		continue
	fi
	while IFS= read -r test; do
		[[ "$test" =~ ^Test[A-Za-z0-9_]*$ ]] || continue
		left=$((budget - (SECONDS - started)))
		if [ "$left" -le 0 ]; then
			stopped="the tests' time budget ($timeout) ran out before $test"
		elif ! "$UAT_SESSION_HOOK" phase "tests: $test" 2>&1 | redact | tee -a "$build_log" >&2; then
			stopped="the session refresh before $test failed (see the log above)"
		else
			# A refresh can take minutes: the test gets what is left after it.
			left=$((budget - (SECONDS - started)))
			[ "$left" -gt 0 ] || stopped="the tests' time budget ($timeout) ran out before $test"
		fi
		if [ -n "$stopped" ]; then
			say "$stopped; not running the rest"
			fail_event "$pkg" "$stopped; the tests after it did not run"
			status=1
			break
		fi
		say "$test: ${left}s of the budget left"
		if ! run_bin "$pkg" "$dir" "$bin" "^$test\$$sub" "${left}s"; then
			status=1
			diagnose "$test"
		fi
	done <<<"$tests"
done

set +e
"$uatreport" summarize -catalogue "$catalogue" -tier "$tier" -junit "$report/junit.xml" "$@" <"$events" |
	tee "$report/summary.txt" | tee -a "$build_log"
summary=${PIPESTATUS[0]}
set -e
if [ "$summary" -ne 0 ]; then
	exit "$summary"
fi
if [ "$status" -ne 0 ]; then
	say "a test binary exited non-zero although the summary passed; failing the run"
	exit 1
fi
exit 0
