#!/usr/bin/env bash
# run.sh: run the UAT acceptance tests on the local rig (UAT.8; README.md).
#
# Usage: run.sh [--state DIR] [--release-tag TAG] [--no-up] [--with-x3]
#               smoke|core|all [scenario id ...]
#
#   --state DIR       the rig's state (default LITE_STATE in config.env)
#   --release-tag TAG the release under test; needed when the rig is not up
#                     yet (default: the release the rig was brought up with)
#   --no-up           fail instead of bringing the rig up
#   --with-x3         also run X3 (a sprout cannot reach core), which the rig
#                     cannot pass: it has no network separation
#   ids               catalogue ids of the tier, passed to uat/tests/run.sh
#
# It brings the rig up with up.sh when it is not up for the release, then
# runs uat/tests/run.sh unchanged, with the rig's material directory, its
# vmctl.sh and the core kubeconfig and endpoints for bind-tenant.sh. Tier
# all is two runs of uat/tests/run.sh, because ingredient ids cannot share a
# run with the others: the static scenarios, then the ingredients tier.
#
# No silent green: the rig has no Windows sprouts and no network
# separation. Every scenario that ran on a Linux sprout gets a SKIP line for
# Windows with that reason, per tenant, and X3 (unless --with-x3) a SKIP
# line too; none of them is ever counted as passed. They are printed under
# each run's summary and written to <report>/lite-summary.txt.
#
# Exit status: uat/tests/run.sh's (0 only when every run passed), 2 on a
# usage error.
set -euo pipefail
LITE_PROG=run.sh
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

cli_state="" release_tag="" no_up=0 with_x3=0
while (($#)); do
	case $1 in
	--state | --release-tag)
		(($# >= 2)) || lite_usage_die "$1 needs a value"
		if [[ $1 == --state ]]; then cli_state=$2; else release_tag=$2; fi
		shift 2
		;;
	--no-up) no_up=1 && shift ;;
	--with-x3) with_x3=1 && shift ;;
	-h | --help) usage ;;
	-*) lite_usage_die "unknown option '$1' (see --help)" ;;
	*) break ;;
	esac
done
(($# >= 1)) || lite_usage_die "give a tier: smoke, core or all"
tier=$1
shift
case $tier in
smoke | core | all) ;;
*) lite_usage_die "tier '$tier' is not smoke, core or all (the rig runs these; README.md)" ;;
esac
ids=("$@")
[[ -z $release_tag ]] || lite_is_release_tag "$release_tag" ||
	lite_usage_die "--release-tag '$release_tag' is not vX.Y.Z or vX.Y.Z-rc.N"

lite_need jq awk
lite_load_settings
[[ -z $cli_state ]] || LITE_STATE=$cli_state
if [[ -d $LITE_STATE ]]; then
	LITE_STATE=$(cd "$LITE_STATE" && pwd)
	lite_restore_settings || true
fi
lite_check_settings

UP=${LITE_UP:-$LITE_DIR/up.sh}
TESTS_RUN=${LITE_TESTS_RUN:-$REPO_DIR/uat/tests/run.sh}
CATALOGUE=${LITE_CATALOGUE:-$REPO_DIR/uat/tests/catalogue.tsv}
[[ -n $release_tag ]] || release_tag=$(lite_rig_get '.release_tag')

# rig_is_up: built for this release, enrolled, every container running and
# the material written.
rig_is_up() {
	local vm f
	[[ -s $(lite_rig_file) ]] || return 1
	[[ -n $release_tag ]] && lite_stage_done enroll "$release_tag" || return 1
	lite_container_running "$DMZ_NODE" && lite_container_running "$CORE_NODE" || return 1
	for vm in $LITE_SPROUTS; do
		lite_is_host_sprout "$vm" || lite_container_running "$(lite_sprout_container "$vm")" || return 1
	done
	for f in uat.json harness.json endpoints.json sprouts.json tenants.json; do
		[[ -s $LITE_STATE/$f ]] || return 1
	done
}

if ! rig_is_up; then
	((!no_up)) || lite_die "the rig in $LITE_STATE is not up${release_tag:+ for $release_tag} (--no-up)"
	[[ -n $release_tag ]] || lite_usage_die "the rig is not up: give --release-tag to bring it up"
	lite_log "bringing the rig up for $release_tag"
	"$UP" --release-tag "$release_tag" --state "$LITE_STATE"
	LITE_STATE=$(cd "$LITE_STATE" && pwd)
	lite_restore_settings || lite_die "up.sh wrote no rig.json in $LITE_STATE"
	lite_check_settings
	rig_is_up || lite_die "up.sh finished but the rig is not up (see above)"
fi

# catalogue_ids TIER: the static ids of a tier (I.* left out).
catalogue_ids() {
	awk -F'\t' -v tier="$1" '
		/^#/ || NF < 2 || $1 ~ /^I\./ { next }
		{ n = split($2, t, ","); for (i = 1; i <= n; i++) if (tier == "all" || t[i] == tier) { print $1; break } }' "$CATALOGUE"
}

# The runs: a label, the tier, the ids.
runs=()
excluded=()
if ((${#ids[@]} > 0)); then
	runs+=("$tier|$tier|${ids[*]}")
elif ((with_x3)) || [[ $tier == smoke ]]; then
	runs+=("$tier|$tier|")
else
	mapfile -t static < <(catalogue_ids "$tier" | grep -vx X3)
	((${#static[@]} > 0)) || lite_die "no scenario of tier $tier in $CATALOGUE"
	excluded+=(X3)
	if [[ $tier == all ]]; then
		runs+=("all-static|all|${static[*]}" "ingredients|ingredients|")
	else
		runs+=("$tier|$tier|${static[*]}")
	fi
fi

export IMAS_UAT_DIR=$LITE_STATE
export IMAS_UAT_VMCTL=$LITE_DIR/vmctl.sh
export IMAS_UAT_RELEASE_TAG=$release_tag
IMAS_UAT_CORE_KUBECONFIG=$(lite_kubeconfig core)
export IMAS_UAT_CORE_KUBECONFIG
export IMAS_UAT_ENDPOINTS=$LITE_STATE/endpoints.json

windows_reason="not run: the local rig has no Windows sprouts (Linux containers only); the Azure gate runs this on Windows Server 2022 Core"
x3_reason="not run: the local rig puts the hubs and the sprouts on one Docker network with no network separation, so a sprout can always reach core; the Azure gate's NSGs are what X3 tests (uat/lite/README.md)"

# rig_lines SUMMARY: the rig's own SKIP lines, in uatreport's format. For
# every id that has a line on a Linux sprout (ubuntu or alma) and no line
# for windows in the same tenant, one SKIP line for windows.
rig_lines() {
	awk -v reason="$windows_reason" '
		/^(PASS|FAIL|SKIP|MISS) / {
			id = $2; os = $3; tn = $4
			seen[id SUBSEP os SUBSEP tn] = 1
			if (os == "ubuntu" || os == "alma") {
				if (!(id in pos)) { pos[id] = ++n; order[n] = id }
				linux[id SUBSEP tn] = 1
			}
		}
		END {
			split("- 1 2", tenants, " ")
			for (i = 1; i <= n; i++) {
				id = order[i]
				for (j = 1; j <= 3; j++) {
					tn = tenants[j]
					if ((id SUBSEP tn) in linux && !((id SUBSEP "windows" SUBSEP tn) in seen))
						printf "%-6s %-22s %-8s %-6s %8s  %s\n", "SKIP", id, "windows", tn, "0.0", reason
				}
			}
		}' "$1"
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
status=0
total_rig=0
for r in "${runs[@]}"; do
	IFS='|' read -r label run_tier run_ids <<<"$r"
	report="$LITE_STATE/report/$stamp-$label"
	mkdir -p "$report"
	export IMAS_UAT_REPORT_DIR=$report
	read -r -a args <<<"$run_ids"
	lite_log "uat/tests/run.sh $run_tier${run_ids:+ (${#args[@]} ids)}; report in $report"
	set +e
	"$TESTS_RUN" "$run_tier" "${args[@]}"
	rc=$?
	set -e
	if ((rc != 0)); then
		if ((rc == 2 || status == 0)); then status=$rc; fi
	fi
	{
		echo "== uat/lite: $label (uat/tests/run.sh $run_tier) on the local rig, release $release_tag =="
		if [[ -s $report/summary.txt ]]; then
			cat "$report/summary.txt"
		else
			echo "(uat/tests/run.sh wrote no summary.txt; exit $rc)"
		fi
		echo
		echo "Added by the local rig: not run here, never counted as passed:"
		n=0
		if [[ $label != ingredients ]]; then
			for x in "${excluded[@]}"; do
				printf '%-6s %-22s %-8s %-6s %8s  %s\n' SKIP "$x" - - 0.0 "$x3_reason"
				n=$((n + 1))
			done
		fi
		if [[ -s $report/summary.txt ]]; then
			lines=$(rig_lines "$report/summary.txt")
			if [[ -n $lines ]]; then
				printf '%s\n' "$lines"
				n=$((n + $(wc -l <<<"$lines")))
			fi
		fi
		((n > 0)) || echo "(none)"
		echo "uat/tests/run.sh exit status: $rc"
	} | tee "$report/lite-summary.txt"
	total_rig=$((total_rig + $(grep -c '^SKIP .*not run: the local rig' "$report/lite-summary.txt" || true)))
	echo
done

if ((status == 0)); then
	echo "RIG RESULT: PASS on the Linux sprouts only; $total_rig lines not run on the rig (Windows, X3) are listed above as SKIP, and only the Azure gate can pass them"
else
	echo "RIG RESULT: FAIL (exit $status); see the summaries above"
fi
exit "$status"
