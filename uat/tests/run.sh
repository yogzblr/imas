#!/usr/bin/env bash
# Run the UAT gate's acceptance tests against a deployed stack
# (docs/claude-code-parallel-build-plan.md, section 4h; uat/tests/README.md).
#
# Usage: uat/tests/run.sh <tier> [scenario id ...]
#   tier  smoke, core, resilience, ingredients, lifecycle or all
#   ids   catalogue ids of that tier (T1 C2 ...), or ingredient ids
#         (I.file.managed ...) on their own
#
# Environment:
#   IMAS_UAT_DIR          required: the material directory (README.md)
#   IMAS_UAT_VMCTL        the vmctl.sh to use (default: harness.json's vmctl,
#                         else uat/access/vmctl.sh)
#   IMAS_UAT_REPORT_DIR   where the report goes (default $IMAS_UAT_DIR/report)
#   IMAS_UAT_TIMEOUT      go test -timeout (default by tier: smoke 45m,
#                         core 4h, resilience 3h, others 8h)
#   IMAS_UAT_RELEASE_TAG  optional: the release the sprouts must run (S1)
#
# It builds the report tool and one test binary per package under
# uat/tests with the uat tag, runs them with the tier's -run pattern, and
# prints one line per scenario id, OS and tenant. The report directory
# gets events.json (test2json), summary.txt and junit.xml.
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
smoke | core | resilience | ingredients | lifecycle | all) ;;
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
export IMAS_UAT_VMCTL_DEFAULT="$repo/uat/access/vmctl.sh"
report="${IMAS_UAT_REPORT_DIR:-$IMAS_UAT_DIR/report}"
case "$tier" in
smoke) default_timeout=45m ;;
core) default_timeout=4h ;;
resilience) default_timeout=3h ;;
*) default_timeout=8h ;;
esac
timeout="${IMAS_UAT_TIMEOUT:-$default_timeout}"
catalogue="$here/catalogue.tsv"

mkdir -p "$report/bin"
report=$(cd "$report" && pwd)
events="$report/events.json"
: >"$events"

cd "$repo"
echo "run.sh: tier $tier${*:+, scenarios $*}; report in $report" >&2
go build -o "$report/bin/uatreport" ./uat/tests/uatreport
uatreport="$report/bin/uatreport"
pattern=$("$uatreport" pattern -catalogue "$catalogue" -tier "$tier" "$@")
echo "run.sh: go test -run '$pattern'" >&2

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

status=0
for entry in "${pkgs[@]}"; do
	pkg=${entry%%|*}
	dir=${entry#*|}
	bin="$report/bin/$(echo "${pkg#*/uat/}" | tr '/' '-').test"
	if ! go test -tags uat -c -o "$bin" "$pkg" 2>"$report/build.log"; then
		cat "$report/build.log" >&2
		# A package that doesn't build fails the run through the summary.
		printf '{"Action":"output","Package":"%s","Output":"the package did not build with the uat tag; see build.log\\n"}\n{"Action":"fail","Package":"%s"}\n' \
			"$pkg" "$pkg" >>"$events"
		status=1
		continue
	fi
	echo "run.sh: running $pkg" >&2
	if ! (cd "$dir" && go tool test2json -t -p "$pkg" "$bin" -test.v=test2json \
		-test.run "$pattern" -test.timeout "$timeout" -test.count=1) |
		tee -a "$events" | "$uatreport" follow; then
		status=1
	fi
done

set +e
"$uatreport" summarize -catalogue "$catalogue" -tier "$tier" -junit "$report/junit.xml" "$@" <"$events" |
	tee "$report/summary.txt"
summary=${PIPESTATUS[0]}
set -e
if [ "$summary" -ne 0 ]; then
	exit "$summary"
fi
if [ "$status" -ne 0 ]; then
	echo "run.sh: a test binary exited non-zero although the summary passed; failing the run" >&2
	exit 1
fi
exit 0
