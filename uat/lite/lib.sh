# shellcheck shell=bash
# shellcheck disable=SC2034 # the names set here are used by the scripts sourcing this
# Shared by the uat/lite scripts (UAT.8, the local rig). Sourced, never run.
#
# The rig runs the UAT hub scripts (uat/hub/core, uat/hub/dmz), the enrolment
# wrapper (uat/enroll) and the test runner (uat/tests/run.sh) unchanged, on
# two kind clusters and four systemd containers on one Docker host. This file
# holds the names, the checks and the small Docker, kind and kubectl helpers.

LITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LITE_DIR/../.." && pwd)"

lite_log() { printf '[%s] %s\n' "${LITE_PROG:-uat-lite}" "$*" >&2; }
lite_die() {
	printf '[%s] error: %s\n' "${LITE_PROG:-uat-lite}" "$*" >&2
	exit 1
}
# lite_usage_die MESSAGE: a usage error, exit 2 (as uat/access's scripts).
lite_usage_die() {
	printf '[%s] error: %s\n' "${LITE_PROG:-uat-lite}" "$*" >&2
	exit 2
}

lite_need() {
	local c
	for c in "$@"; do
		command -v "$c" >/dev/null 2>&1 || lite_die "required command not found: $c (README.md, Prerequisites)"
	done
}

# lite_load_settings sources UAT.2's versions.env (the cert-manager pin) and
# config.env (ports, the ClusterIssuer and CA Secret names), then this
# directory's versions.env and config.env. LITE_K0S_VERSIONS and
# LITE_K0S_CONFIG point elsewhere in the tests.
lite_load_settings() {
	local f
	for f in "${LITE_K0S_VERSIONS:-$REPO_DIR/uat/k0s/versions.env}" \
		"${LITE_K0S_CONFIG:-$REPO_DIR/uat/k0s/config.env}" \
		"$LITE_DIR/versions.env" "$LITE_DIR/config.env"; do
		[[ -r $f ]] || lite_die "settings file not readable: $f"
		# shellcheck source=/dev/null
		source "$f"
	done
}

# --- checks ----------------------------------------------------------------

lite_is_run_id() { [[ $1 =~ ^[a-z0-9]{6,10}$ ]]; }
lite_is_release_tag() { [[ $1 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.(0|[1-9][0-9]*))?$ ]]; }
lite_is_ipv4() {
	local o
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	for o in "${BASH_REMATCH[@]:1}"; do
		[[ $o =~ ^(0|[1-9][0-9]*)$ ]] && ((o <= 255)) || return 1
	done
}
lite_is_fqdn() {
	((${#1} <= 253)) && [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}
lite_is_name() { [[ $1 =~ ^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$ ]]; }
lite_is_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535)); }

# lite_check_settings fails on settings that would build a broken rig, and
# sets the derived names:
#   LITE_SUBNET_PREFIX (a.b.c), LITE_GATEWAY, LITE_IP_RANGE
#   DMZ_NODE CORE_NODE         the kind node containers
#   DMZ_FQDN CORE_FQDN         the public names (the Keycloak issuer is on CORE_FQDN)
#   DMZ_PRIVATE_NAME CORE_PRIVATE_NAME   dmz.<zone>, core.<zone>
lite_check_settings() {
	lite_is_run_id "$LITE_RUN_ID" || lite_usage_die "run id '$LITE_RUN_ID' must be 6 to 10 lowercase letters and digits"
	if [[ ! $LITE_SUBNET =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.0/24$ ]] || ! lite_is_ipv4 "${BASH_REMATCH[1]}.0"; then
		lite_usage_die "LITE_SUBNET '$LITE_SUBNET' must be a /24 written a.b.c.0/24"
	fi
	LITE_SUBNET_PREFIX=${LITE_SUBNET%.0/24}
	LITE_GATEWAY="$LITE_SUBNET_PREFIX.1"
	LITE_IP_RANGE="$LITE_SUBNET_PREFIX.128/25"
	lite_is_name "$LITE_NETWORK" || lite_usage_die "bad LITE_NETWORK '$LITE_NETWORK'"
	if ! lite_is_name "$LITE_DMZ_CLUSTER" || ! lite_is_name "$LITE_CORE_CLUSTER"; then
		lite_usage_die "bad cluster names '$LITE_DMZ_CLUSTER', '$LITE_CORE_CLUSTER'"
	fi
	[[ $LITE_DMZ_CLUSTER != "$LITE_CORE_CLUSTER" ]] || lite_usage_die "the two clusters need different names"
	lite_is_fqdn "$LITE_DOMAIN" || lite_usage_die "bad LITE_DOMAIN '$LITE_DOMAIN'"
	lite_is_fqdn "$LITE_PRIVATE_DNS_ZONE" || lite_usage_die "bad LITE_PRIVATE_DNS_ZONE '$LITE_PRIVATE_DNS_ZONE'"
	case $LITE_HOST_ACCESS in auto | direct | published) ;; *) lite_usage_die "LITE_HOST_ACCESS must be auto, direct or published" ;; esac
	lite_is_ipv4 "$LITE_PUBLISH_ADDRESS" || lite_usage_die "LITE_PUBLISH_ADDRESS must be an IPv4 address"
	lite_is_port "$LITE_SSH_PORT_BASE" || lite_usage_die "bad LITE_SSH_PORT_BASE"
	[[ $LITE_CA_DAYS =~ ^[1-9][0-9]*$ ]] || lite_usage_die "bad LITE_CA_DAYS"
	[[ $LITE_WAIT_TIMEOUT =~ ^[1-9][0-9]*$ ]] || lite_usage_die "bad LITE_WAIT_TIMEOUT"
	[[ $LITE_POLL_SECONDS =~ ^[0-9]+$ ]] || lite_usage_die "bad LITE_POLL_SECONDS"
	[[ $LITE_CONTAINER_PREFIX =~ ^[a-z0-9][a-z0-9_.-]*$ ]] || lite_usage_die "bad LITE_CONTAINER_PREFIX"

	local vm seen=" " n=0
	for vm in $LITE_SPROUTS; do
		[[ $vm =~ ^t[12]-(ubuntu|alma)$ ]] || lite_usage_die "sprout '$vm' is not t1|t2-ubuntu|alma (the rig has no Windows)"
		[[ $seen != *" $vm "* ]] || lite_usage_die "sprout '$vm' listed twice"
		seen+="$vm "
		n=$((n + 1))
	done
	((n > 0)) || lite_usage_die "LITE_SPROUTS is empty"
	((n <= 8)) || lite_usage_die "at most 8 sprouts"
	if [[ -n $LITE_HOST_SPROUT ]]; then
		[[ $seen == *" $LITE_HOST_SPROUT "* ]] || lite_usage_die "LITE_HOST_SPROUT '$LITE_HOST_SPROUT' is not in LITE_SPROUTS"
		[[ $LITE_HOST_SPROUT == *-ubuntu ]] || lite_usage_die "LITE_HOST_SPROUT must be an Ubuntu sprout (the host stands in for one)"
		lite_is_port "$LITE_HOST_SPROUT_PORT" || lite_usage_die "bad LITE_HOST_SPROUT_PORT"
		[[ $LITE_HOST_SPROUT_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || lite_usage_die "bad LITE_HOST_SPROUT_USER"
	fi

	DMZ_NODE="${LITE_DMZ_CLUSTER}-control-plane"
	CORE_NODE="${LITE_CORE_CLUSTER}-control-plane"
	DMZ_FQDN="uat${LITE_RUN_ID}-dmz.${LITE_DOMAIN}"
	CORE_FQDN="uat${LITE_RUN_ID}-core.${LITE_DOMAIN}"
	DMZ_PRIVATE_NAME="dmz.${LITE_PRIVATE_DNS_ZONE}"
	CORE_PRIVATE_NAME="core.${LITE_PRIVATE_DNS_ZONE}"
}

# --- sprouts ---------------------------------------------------------------

lite_sprout_os() { printf '%s\n' "${1#t[12]-}"; }
lite_sprout_tenant() {
	local t=${1%%-*}
	printf '%s\n' "${t#t}"
}
lite_sprout_index() {
	local vm i=0
	for vm in $LITE_SPROUTS; do
		if [[ $vm == "$1" ]]; then
			printf '%s\n' "$i"
			return 0
		fi
		i=$((i + 1))
	done
	return 1
}
lite_sprout_ip() { printf '%s.%s\n' "$LITE_SUBNET_PREFIX" "$((21 + $(lite_sprout_index "$1")))"; }
lite_sprout_ssh_port() { printf '%s\n' "$((LITE_SSH_PORT_BASE + $(lite_sprout_index "$1")))"; }
lite_sprout_container() { printf '%s%s\n' "$LITE_CONTAINER_PREFIX" "$1"; }
lite_sprout_image() { printf 'imas-uat-lite/sprout-%s:%s\n' "$1" "$LITE_SPROUT_IMAGE_TAG"; }
lite_is_host_sprout() { [[ -n $LITE_HOST_SPROUT && $1 == "$LITE_HOST_SPROUT" ]]; }

# --- docker ----------------------------------------------------------------

# lite_inspect NAME prints the container's docker inspect object, or
# nothing when there is no such container.
lite_inspect() { docker inspect --type container "$1" 2>/dev/null | jq -c '.[0] // empty' 2>/dev/null || true; }
lite_container_exists() { [[ -n $(lite_inspect "$1") ]]; }
lite_container_running() { [[ $(lite_inspect "$1" | jq -r '.State.Running // false') == true ]]; }
# lite_container_ip NAME prints the container's address on the rig network.
lite_container_ip() {
	lite_inspect "$1" | jq -r --arg n "$LITE_NETWORK" '.NetworkSettings.Networks[$n].IPAddress // empty'
}

# lite_resolve_host_access sets LITE_ACCESS_MODE to direct or published.
lite_resolve_host_access() {
	LITE_ACCESS_MODE=$LITE_HOST_ACCESS
	if [[ $LITE_ACCESS_MODE == auto ]]; then
		local os
		os=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)
		if grep -qi 'docker desktop' <<<"$os"; then
			LITE_ACCESS_MODE=published
		else
			LITE_ACCESS_MODE=direct
		fi
	fi
}

# --- kubectl ---------------------------------------------------------------

lite_kubeconfig() { printf '%s/kube/%s.kubeconfig\n' "$LITE_STATE" "$1"; }
# lite_kc HUB ARGS... runs kubectl against one hub (dmz or core).
lite_kc() {
	local hub=$1
	shift
	kubectl --kubeconfig "$(lite_kubeconfig "$hub")" "$@"
}

# --- waiting and downloads -------------------------------------------------

# lite_wait_until SECONDS DESCRIPTION COMMAND...: polls COMMAND until it
# succeeds, or fails naming DESCRIPTION.
lite_wait_until() {
	local limit=$1 what=$2 deadline
	shift 2
	deadline=$((SECONDS + limit))
	until "$@"; do
		((SECONDS < deadline)) || lite_die "$what: not done after ${limit}s"
		sleep "$LITE_POLL_SECONDS"
	done
}

lite_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# lite_fetch_pinned URL SHA256 OUT: download once, refuse another checksum.
lite_fetch_pinned() {
	local url=$1 want=$2 out=$3 got
	if [[ ! -s $out ]]; then
		lite_log "downloading $url"
		curl -fsSL --retry 3 --retry-delay 2 -o "$out.part" "$url" || lite_die "download failed: $url"
		mv -f "$out.part" "$out"
	fi
	got=$(lite_sha256 "$out")
	if [[ $got != "$want" ]]; then
		rm -f "$out"
		lite_die "checksum mismatch for $url: got $got, pinned $want"
	fi
}

# --- the hosts file --------------------------------------------------------

lite_hosts_begin() { printf '# BEGIN imas-uat-lite %s (uat/lite/up.sh; uat/lite/down.sh removes it)\n' "$LITE_RUN_ID"; }
lite_hosts_end() { printf '# END imas-uat-lite %s\n' "$LITE_RUN_ID"; }

# lite_hosts_update FILE CONTENT: replaces this rig's block in FILE with
# CONTENT (lines "address names..."), or removes the block when CONTENT is
# empty. Every other line is kept as it was. sudo (LITE_SUDO) only when the
# file is not writable; the file is rewritten in place (tee), never moved,
# so a bind-mounted or WSL-managed hosts file keeps its inode.
lite_hosts_update() {
	local file=$1 content=$2 begin end tmp
	begin=$(lite_hosts_begin)
	end=$(lite_hosts_end)
	tmp=$(mktemp)
	if [[ -e $file ]]; then
		awk -v b="${begin%% (*}" -v e="$end" '
			index($0, b) == 1 { skip = 1; next }
			skip && $0 == e { skip = 0; next }
			!skip' "$file" >"$tmp"
	fi
	if [[ -n $content ]]; then
		printf '%s\n%s\n%s\n' "$begin" "$content" "$end" >>"$tmp"
	fi
	if [[ -e $file ]] && cmp -s "$tmp" "$file"; then
		rm -f "$tmp"
		return 0
	fi
	if [[ -w $file ]] || { [[ ! -e $file ]] && [[ -w $(dirname "$file") ]]; }; then
		cat "$tmp" >"$file"
	else
		lite_log "writing the hub names to $file with $LITE_SUDO"
		# shellcheck disable=SC2086 # LITE_SUDO may carry options
		$LITE_SUDO tee "$file" >/dev/null <"$tmp" || {
			rm -f "$tmp"
			lite_die "could not write $file (set LITE_HOSTS_FILE=none to add the lines by hand)"
		}
	fi
	rm -f "$tmp"
}

# --- rig.json --------------------------------------------------------------
# rig.json in the state directory records what up.sh resolved and created,
# so down.sh, write-material.sh and run.sh act on that rig and nothing else.

lite_rig_file() { printf '%s/rig.json\n' "$LITE_STATE"; }
lite_rig_get() { jq -r "($1) // empty" "$(lite_rig_file)" 2>/dev/null || true; }
# lite_rig_update JQ_FILTER [jq args...]: rewrite rig.json through a filter.
lite_rig_update() {
	local f tmp filter=$1
	shift
	f=$(lite_rig_file)
	[[ -s $f ]] || printf '{}\n' >"$f"
	tmp=$(mktemp "$f.XXXXXX")
	jq "$@" "$filter" "$f" >"$tmp" && mv -f "$tmp" "$f"
}
lite_stage_done() { [[ $(lite_rig_get ".stages[\"$1\"]") == "$2" ]]; }
lite_stage_mark() { lite_rig_update '.stages[$s] = $v' --arg s "$1" --arg v "$2"; }

# The settings up.sh resolved, kept in rig.json: down.sh, write-material.sh
# and run.sh read them back, so a changed environment cannot make them act
# on another rig than the one that was built.
LITE_SAVED_SETTINGS=(LITE_RUN_ID LITE_NETWORK LITE_SUBNET LITE_DMZ_CLUSTER LITE_CORE_CLUSTER
	LITE_DOMAIN LITE_PRIVATE_DNS_ZONE LITE_PUBLISH_ADDRESS LITE_HOSTS_FILE LITE_SPROUTS
	LITE_SSH_PORT_BASE LITE_CONTAINER_PREFIX LITE_HOST_SPROUT LITE_HOST_SPROUT_PORT
	LITE_HOST_SPROUT_USER LITE_ACCESS_MODE)

lite_save_settings() {
	local v args=() keys=()
	for v in "${LITE_SAVED_SETTINGS[@]}"; do
		args+=(--arg "$v" "${!v-}")
		keys+=("$v: \$$v")
	done
	lite_rig_update ".settings = {$(
		IFS=,
		echo "${keys[*]}"
	)}" "${args[@]}"
}

# lite_restore_settings: the saved settings win over the environment.
# Returns 1 when the state directory has no rig.json.
lite_restore_settings() {
	local f v val
	f=$(lite_rig_file)
	[[ -s $f ]] || return 1
	jq -e '.settings | type == "object"' "$f" >/dev/null 2>&1 || return 1
	for v in "${LITE_SAVED_SETTINGS[@]}"; do
		if jq -e --arg k "$v" '.settings | has($k)' "$f" >/dev/null; then
			val=$(jq -r --arg k "$v" '.settings[$k]' "$f")
			printf -v "$v" '%s' "$val"
		fi
	done
	return 0
}
