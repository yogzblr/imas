#!/usr/bin/env bash
# Enrolls the UAT sprouts: creates the two tenants and their one-time keys,
# writes the inventory, runs ansible/site.yml (which installs the published
# package and runs imas_verify), checks the sprout IDs, and waits until farmer
# sees every sprout connected.
#
#   enroll.sh --uat uat.json --access access.json --state DIR \
#     --release-tag vX.Y.Z[-rc.N] --ca-file uat-ca.pem \
#     --internal-auth-file FILE \
#     (--keycloak-json FILE | --token-cmd EXE | --token-t1 FILE --token-t2 FILE) \
#     [--ssh-key FILE] [--winrm-password-file FILE | --winrm-password-dir DIR] \
#     [--saasapi-url URL] [--envoy-host NAME] [--envoy-port 8443] [--bus-url URL]... \
#     [--buildkite-org ORG] [--windows-msi-url URL --windows-msi-sha256 HEX] \
#     [--key-hours 6] [--verify-timeout 600] [--connect-timeout 600] \
#     [--skip-tenants] [--no-seed-sproutid] [--ansible-dir DIR] [-- ANSIBLE-PLAYBOOK ARGS...]
#
# Steps, each safe to repeat:
#   1. create-tenants.sh        tenants 1 and 2, one key per sprout (skip: --skip-tenants)
#   2. gen-inventory.py         DIR/inventory
#   3. seed-sproutid.yml        the same sprout ID per OS in both tenants (skip: --no-seed-sproutid)
#   4. ansible/site.yml         install, enroll, imas_verify (the role includes it)
#   5. collect.yml              imas_verify again, then the enrolled sprout IDs
#   6. wait-connected.sh        farmer's view, through saasapi; writes DIR/sprouts.json
#
# --keycloak-json FILE is short for --token-cmd keycloak-token.sh with that
# keycloak.json (see keycloak-token.sh and README.md, "Tokens and the tenant id").
# --access is not needed when every sprout's connection is docker (the local
# rig, UAT.8). Nothing secret is printed: keys, tokens, the shared secret and
# the WinRM password stay in their files and reach Ansible through lookups.
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
KEYCLOAK_JSON="" KEY_HOURS=6 VERIFY_TIMEOUT=600 CONNECT_TIMEOUT=600 SKIP_TENANTS=0 SEED=1
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
	--keycloak-json) KEYCLOAK_JSON="${2:?}"; shift 2 ;;
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
[[ -n "$UAT" && -n "$STATE" && -n "$RELEASE_TAG" && -n "$CA" ]] || usage
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] ||
	die "--release-tag must be vX.Y.Z or vX.Y.Z-rc.N, never latest: $RELEASE_TAG"
[[ -r "$UAT" ]] || die "uat JSON not readable: $UAT"
[[ -r "$CA" ]] || die "UAT CA file not readable: $CA"
[[ -n "$ANSIBLE_DIR" && -f "$ANSIBLE_DIR/site.yml" && -d "$ANSIBLE_DIR/roles/imas_sprout" ]] ||
	die "ansible/site.yml not found (pass --ansible-dir)"
need jq python3 ansible-playbook
if jq -e '[.sprouts[] | .connection] | any(. != "docker")' "$UAT" >/dev/null; then
	[[ -n "$ACCESS" && -r "$ACCESS" ]] || die "--access is required for ssh and winrm sprouts (uat/access/tunnels.sh writes it)"
fi
if jq -e '[.sprouts[] | .connection] | any(. == "winrm")' "$UAT" >/dev/null; then
	ansible-galaxy collection list ansible.windows 2>/dev/null | grep -q '^ansible\.windows ' ||
		log "warning: collection ansible.windows not found: ansible-galaxy collection install -r $here/requirements.yml"
fi
if jq -e '[.sprouts[] | .connection] | any(. == "docker")' "$UAT" >/dev/null; then
	ansible-galaxy collection list community.docker 2>/dev/null | grep -q '^community\.docker ' ||
		log "warning: collection community.docker not found: ansible-galaxy collection install -r $here/requirements.yml"
fi

umask 077
mkdir -p "$STATE"
chmod 700 "$STATE"
STATE="$(cd "$STATE" && pwd)"
if [[ -n "$KEYCLOAK_JSON" ]]; then
	[[ -r "$KEYCLOAK_JSON" ]] || die "keycloak.json not readable: $KEYCLOAK_JSON"
	export UAT_KEYCLOAK_JSON UAT_KEYCLOAK_CA
	UAT_KEYCLOAK_JSON="$(cd "$(dirname "$KEYCLOAK_JSON")" && pwd)/$(basename "$KEYCLOAK_JSON")"
	UAT_KEYCLOAK_CA="$(cd "$(dirname "$CA")" && pwd)/$(basename "$CA")"
	auth+=(--token-cmd "$here/keycloak-token.sh")
fi
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
[[ -n "$ACCESS" ]] && gen+=(--access "$ACCESS")
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
