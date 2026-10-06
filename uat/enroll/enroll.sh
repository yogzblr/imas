#!/usr/bin/env bash
# Enrolls the UAT sprouts: creates the two tenants and their one-time keys,
# writes the inventory, runs ansible/site.yml (which installs the published
# package and runs imas_verify), checks the sprout IDs, and waits until farmer
# sees every sprout connected.
#
#   enroll.sh --uat uat.json --access access.json --state DIR \
#     --release-tag vX.Y.Z[-rc.N] [--ca-file uat-ca.pem] \
#     (--core-state DIR --core-kubeconfig FILE --endpoints FILE [--core-scripts DIR]
#      | --internal-auth-file FILE (--token-cmd EXE | --token-t1 FILE --token-t2 FILE)) \
#     [--ssh-key FILE] [--winrm-password-file FILE | --winrm-password-dir DIR] \
#     [--saasapi-url URL] [--envoy-host NAME] [--envoy-port 8443] [--bus-url URL]... \
#     [--buildkite-org ORG] [--windows-msi-url URL --windows-msi-sha256 HEX] \
#     [--key-hours 6] [--verify-timeout 600] [--connect-timeout 600] \
#     [--skip-tenants] [--no-seed-sproutid] [--ansible-dir DIR]
#     [-- ANSIBLE-PLAYBOOK ARGS...]
#
# Steps, each safe to repeat:
#   1. create-tenants.sh        tenants 1 and 2, one key per sprout (skip: --skip-tenants)
#   2. gen-inventory.py         DIR/inventory
#   3. seed-sproutid.yml        the same sprout ID per OS in both tenants (skip: --no-seed-sproutid)
#   4. ansible/site.yml         install, enroll, imas_verify (the role includes it)
#   5. collect.yml              imas_verify again, then the enrolled sprout IDs
#   6. wait-connected.sh        farmer's view, through saasapi; writes DIR/sprouts.json
#
# --core-state, --core-kubeconfig and --endpoints are the <state-dir>,
# <kubeconfig> and <endpoints.json> the core hub's scripts took (--core-scripts,
# default uat/hub/core).
# They select core-token.sh as the token command, which binds each new tenant
# with uat/hub/core/bind-tenant.sh, and they default --internal-auth-file,
# --saasapi-url and --ca-file from the core hub's core.json and sensitive
# directory (see README.md, "Tokens and the tenant id").
# Sprouts are reached over SSH or WinRM only, the local rig's (UAT.8) too:
# its containers run sshd (owner decision, 2026-10-06). farmerinterface is the
# DMZ's private name, dmz.uat.imas.internal, unless --envoy-host says otherwise.
# Nothing secret is printed: keys, tokens, the shared secret and the WinRM
# password stay in their files and reach Ansible through lookups.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME=enroll.sh
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() {
	usage_text "${BASH_SOURCE[0]}" >&2
	exit 2
}

UAT="" ACCESS="" STATE="" RELEASE_TAG="" CA="" SSH_KEY="" WINRM_FILE="" WINRM_DIR=""
SAAS_URL="" ENVOY_HOST="" ENVOY_PORT=8443 BUILDKITE_ORG="" MSI_URL="" MSI_SHA=""
CORE_STATE="" CORE_SCRIPTS="" CORE_KUBECONFIG="" ENDPOINTS="" KEY_HOURS=6 VERIFY_TIMEOUT=600 CONNECT_TIMEOUT=600 SKIP_TENANTS=0 SEED=1
ANSIBLE_DIR=""
if [[ -d "$here/../../ansible" ]]; then ANSIBLE_DIR="$(cd "$here/../../ansible" && pwd)"; fi
auth=() bus=() playbook_args=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--uat) UAT="${2:?}"; shift 2 ;;
	--access) ACCESS="${2:?}"; shift 2 ;;
	--state) STATE="${2:?}"; shift 2 ;;
	--release-tag) RELEASE_TAG="${2:?}"; shift 2 ;;
	--ca-file) CA="${2:?}"; shift 2 ;;
	--ssh-key) SSH_KEY="${2:?}"; shift 2 ;;
	--winrm-password-file) WINRM_FILE="${2:?}"; shift 2 ;;
	--winrm-password-dir) WINRM_DIR="${2:?}"; shift 2 ;;
	--internal-auth-file | --token-cmd | --token-t1 | --token-t2) auth+=("$1" "${2:?}"); shift 2 ;;
	--core-state) CORE_STATE="${2:?}"; shift 2 ;;
	--core-kubeconfig) CORE_KUBECONFIG="${2:?}"; shift 2 ;;
	--endpoints) ENDPOINTS="${2:?}"; shift 2 ;;
	--core-scripts) CORE_SCRIPTS="${2:?}"; shift 2 ;;
	--saasapi-url) SAAS_URL="${2:?}"; shift 2 ;;
	--envoy-host) ENVOY_HOST="${2:?}"; shift 2 ;;
	--envoy-port) ENVOY_PORT="${2:?}"; shift 2 ;;
	--bus-url) bus+=(--bus-url "${2:?}"); shift 2 ;;
	--buildkite-org) BUILDKITE_ORG="${2:?}"; shift 2 ;;
	--windows-msi-url) MSI_URL="${2:?}"; shift 2 ;;
	--windows-msi-sha256) MSI_SHA="${2:?}"; shift 2 ;;
	--key-hours) KEY_HOURS="${2:?}"; shift 2 ;;
	--verify-timeout) VERIFY_TIMEOUT="${2:?}"; shift 2 ;;
	--connect-timeout) CONNECT_TIMEOUT="${2:?}"; shift 2 ;;
	--skip-tenants) SKIP_TENANTS=1; shift ;;
	--no-seed-sproutid) SEED=0; shift ;;
	--ansible-dir) ANSIBLE_DIR="${2:?}"; shift 2 ;;
	--) shift; playbook_args=("$@"); break ;;
	-h | --help) usage ;;
	*) echo "enroll.sh: unknown argument: $1" >&2; usage ;;
	esac
done
[[ -n "$UAT" && -n "$STATE" && -n "$RELEASE_TAG" ]] || usage
abspath() { printf '%s/%s' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"; }
if [[ -n "$CORE_STATE" ]]; then
	need jq
	core_json="$CORE_STATE/core/out/core.json"
	[[ -s "$core_json" ]] || die "no $core_json: run uat/hub/core/install.sh first"
	[[ -n "$CORE_KUBECONFIG" && -n "$ENDPOINTS" ]] || die "--core-state needs --core-kubeconfig and --endpoints (for bind-tenant.sh)"
	export UAT_CORE_STATE UAT_CORE_KUBECONFIG UAT_CORE_ENDPOINTS
	UAT_CORE_STATE="$(cd "$CORE_STATE" && pwd)"
	UAT_CORE_KUBECONFIG="$(abspath "$CORE_KUBECONFIG")"
	UAT_CORE_ENDPOINTS="$(abspath "$ENDPOINTS")"
	if [[ -n "$CORE_SCRIPTS" ]]; then export UAT_CORE_SCRIPTS; UAT_CORE_SCRIPTS="$(cd "$CORE_SCRIPTS" && pwd)"; fi
	auth+=(--token-cmd "$here/core-token.sh")
	[[ " ${auth[*]} " == *" --internal-auth-file "* ]] ||
		auth+=(--internal-auth-file "$UAT_CORE_STATE/core/sensitive/internal-auth-secret")
	[[ -n "$SAAS_URL" ]] || SAAS_URL="$(jq -r '.saasapi_url // empty' "$core_json")"
	[[ -n "$CA" ]] || CA="$(jq -r '.ca_file // empty' "$core_json")"
fi
[[ -n "$CA" ]] || die "--ca-file is required (or --core-state, whose core.json names it)"
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] ||
	die "--release-tag must be vX.Y.Z or vX.Y.Z-rc.N, never latest: $RELEASE_TAG"
[[ -r "$UAT" ]] || die "uat JSON not readable: $UAT"
[[ -r "$CA" ]] || die "UAT CA file not readable: $CA"
[[ -n "$ANSIBLE_DIR" && -f "$ANSIBLE_DIR/site.yml" && -d "$ANSIBLE_DIR/roles/imas_sprout" ]] ||
	die "ansible/site.yml not found (pass --ansible-dir)"
need jq python3 ansible-playbook
[[ -n "$ACCESS" && -r "$ACCESS" ]] || die "--access is required (uat/access/tunnels.sh, or the local rig, writes it)"
if jq -e '[.sprouts[] | .connection] | any(. == "winrm")' "$UAT" >/dev/null; then
	ansible-galaxy collection list ansible.windows 2>/dev/null | grep -q '^ansible\.windows ' ||
		log "warning: collection ansible.windows not found: ansible-galaxy collection install -r $here/requirements.yml"
fi

umask 077
mkdir -p "$STATE"
chmod 700 "$STATE"
STATE="$(cd "$STATE" && pwd)"
saas=("${auth[@]}")
[[ -n "$SAAS_URL" ]] && saas+=(--saasapi-url "$SAAS_URL")
saas+=(--ca-file "$CA")

step() { log "== $*"; }

if ((SKIP_TENANTS)); then
	step "1/6 tenants and keys: skipped, reusing $STATE"
	[[ -s "$STATE/tenants.json" ]] || die "--skip-tenants but no $STATE/tenants.json"
else
	step "1/6 tenants and keys"
	"$here/create-tenants.sh" --uat "$UAT" --state "$STATE" --key-hours "$KEY_HOURS" "${saas[@]}"
fi

step "2/6 inventory"
gen=(--uat "$UAT" --keys-dir "$STATE/keys" --release-tag "$RELEASE_TAG" --ca-file "$CA"
	--out "$STATE/inventory" --known-hosts "$STATE/ssh/known_hosts"
	--envoy-port "$ENVOY_PORT" --verify-timeout "$VERIFY_TIMEOUT" "${bus[@]}")
gen+=(--access "$ACCESS")
[[ -n "$SSH_KEY" ]] && gen+=(--ssh-key "$SSH_KEY")
[[ -n "$WINRM_FILE" ]] && gen+=(--winrm-password-file "$WINRM_FILE")
[[ -n "$WINRM_DIR" ]] && gen+=(--winrm-password-dir "$WINRM_DIR")
[[ -n "$ENVOY_HOST" ]] && gen+=(--envoy-host "$ENVOY_HOST")
[[ -n "$BUILDKITE_ORG" ]] && gen+=(--buildkite-org "$BUILDKITE_ORG")
[[ -n "$MSI_URL" ]] && gen+=(--windows-msi-url "$MSI_URL" --windows-msi-sha256 "$MSI_SHA")
python3 "$here/gen-inventory.py" "${gen[@]}"
inventory="$STATE/inventory/hosts.yml"

# The repository's ansible.cfg (forks, interpreter discovery) and roles, from
# wherever this runs. Host key checking is off for the tunnels; see README.md.
export ANSIBLE_CONFIG="$ANSIBLE_DIR/ansible.cfg"
export ANSIBLE_ROLES_PATH="$ANSIBLE_DIR/roles"
export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_RETRY_FILES_ENABLED=False
run_playbook() { ansible-playbook -i "$inventory" "$@" "${playbook_args[@]}"; }

if ((SEED)); then
	step "3/6 seed the sprout IDs"
	run_playbook "$here/playbooks/seed-sproutid.yml"
else
	step "3/6 seed the sprout IDs: skipped (sprout IDs default to host names)"
fi

step "4/6 ansible/site.yml with $RELEASE_TAG"
run_playbook "$ANSIBLE_DIR/site.yml"

step "5/6 imas_verify and the enrolled sprout IDs"
collect=(-e "uat_out_dir=$STATE")
((SEED)) || collect+=(-e uat_skip_sprout_id_check=true)
run_playbook "$here/playbooks/collect.yml" "${collect[@]}"

step "6/6 farmer's view"
"$here/wait-connected.sh" --state "$STATE" --timeout "$CONNECT_TIMEOUT" "${saas[@]}"
