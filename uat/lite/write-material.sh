#!/usr/bin/env bash
# write-material.sh: write the files the shared UAT scripts read, in the
# Shared contract's shapes, for the local rig (UAT.8):
#
#   <state>/uat.json       the tofu output "uat" object: run_id, dmz, core and
#                          sprouts (connection ssh; id is the container name)
#   <state>/access.json    the Access interface's file: each sprout's host and
#                          ssh_port (127.0.0.1 and its published port), each
#                          hub's kube_port (kind's API server port)
#   <state>/endpoints.json the hubs' names, private addresses, ports and the
#                          ClusterIssuer, read by uat/hub/core and uat/hub/dmz
#   <state>/harness.json   uat/tests overrides: Envoy's port, the rig's
#                          vmctl.sh, how to run bind-tenant.sh
#
# Usage: write-material.sh [--state DIR]
#
# It reads the settings up.sh saved in <state>/rig.json and the addresses
# Docker gave the kind nodes. up.sh runs it; run it again by hand after a
# node's address changed. Nothing secret is written.
set -euo pipefail
LITE_PROG=write-material.sh
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

state=""
while (($#)); do
	case $1 in
	--state)
		(($# >= 2)) || lite_usage_die "--state needs a value"
		state=$2
		shift 2
		;;
	-h | --help) usage ;;
	*) lite_usage_die "unknown argument '$1'" ;;
	esac
done

lite_need jq docker
lite_load_settings
[[ -z $state ]] || LITE_STATE=$state
[[ -d $LITE_STATE ]] || lite_die "no state directory $LITE_STATE: run up.sh first"
LITE_STATE=$(cd "$LITE_STATE" && pwd)
lite_restore_settings || lite_die "$LITE_STATE has no rig.json: run up.sh first"
lite_check_settings

# kube_port_of HUB: the API server port in kind's kubeconfig (127.0.0.1:<port>).
kube_port_of() {
	local k p
	k=$(lite_kubeconfig "$1")
	[[ -r $k ]] || lite_die "no kubeconfig $k: run up.sh first"
	p=$(sed -nE 's#^[[:space:]]*server:[[:space:]]*https://[^:/]+:([0-9]+)/?[[:space:]]*$#\1#p' "$k" | head -n 1)
	lite_is_port "$p" || lite_die "no API server port in $k"
	printf '%s\n' "$p"
}

dmz_ip=$(lite_container_ip "$DMZ_NODE")
core_ip=$(lite_container_ip "$CORE_NODE")
lite_is_ipv4 "$dmz_ip" || lite_die "the DMZ node $DMZ_NODE has no address on $LITE_NETWORK: is the cluster up?"
lite_is_ipv4 "$core_ip" || lite_die "the core node $CORE_NODE has no address on $LITE_NETWORK: is the cluster up?"
dmz_kube=$(kube_port_of dmz)
core_kube=$(kube_port_of core)

# The sprouts: tenant, OS, container, address and SSH port.
sprouts='{}'
access=$(jq -n --argjson d "$dmz_kube" --argjson c "$core_kube" \
	'{"uat-dmz": {host: "127.0.0.1", kube_port: $d}, "uat-core": {host: "127.0.0.1", kube_port: $c}}')
for vm in $LITE_SPROUTS; do
	if lite_is_host_sprout "$vm"; then
		id=host ip=$LITE_GATEWAY port=$LITE_HOST_SPROUT_PORT user=$LITE_HOST_SPROUT_USER
	else
		id=$(lite_sprout_container "$vm")
		ip=$(lite_container_ip "$id")
		[[ $ip == "$(lite_sprout_ip "$vm")" ]] ||
			lite_die "sprout container $id has address '${ip:-none}', expected $(lite_sprout_ip "$vm"): run up.sh"
		port=$(lite_sprout_ssh_port "$vm") user=root
	fi
	sprouts=$(jq --arg vm "$vm" --argjson t "$(lite_sprout_tenant "$vm")" --arg os "$(lite_sprout_os "$vm")" \
		--arg id "$id" --arg ip "$ip" --arg user "$user" \
		'.[$vm] = {tenant: $t, os: $os, connection: "ssh", id: $id, private_ip: $ip, admin_user: $user}' <<<"$sprouts")
	access=$(jq --arg vm "$vm" --argjson p "$port" '.[$vm] = {host: "127.0.0.1", ssh_port: $p}' <<<"$access")
done

# uat.json: the contract's object. No public_ip anywhere: nothing on the
# rig has one, and scenario X3 must not probe a made-up address. id is the
# Docker container (the Azure resource id's place), which vmctl.sh uses.
jq -n --arg run_id "$LITE_RUN_ID" --arg zone "$LITE_PRIVATE_DNS_ZONE" \
	--arg dn "$DMZ_NODE" --arg dip "$dmz_ip" --arg dfq "$DMZ_FQDN" \
	--arg cn "$CORE_NODE" --arg cip "$core_ip" --arg cfq "$CORE_FQDN" \
	--arg net "$LITE_NETWORK" --argjson sprouts "$sprouts" '{
	run_id: $run_id,
	region: "local",
	resource_group: ("docker network " + $net),
	private_dns_zone: $zone,
	dmz: {name: "uat-dmz", id: $dn, private_ip: $dip, fqdn: $dfq, admin_user: "root"},
	core: {name: "uat-core", id: $cn, private_ip: $cip, fqdn: $cfq, admin_user: "root"},
	sprouts: $sprouts
}' >"$LITE_STATE/uat.json"

printf '%s\n' "$access" | jq . >"$LITE_STATE/access.json"

# endpoints.json: what uat/hub/core (lib/common.sh load_endpoints) and
# uat/hub/dmz (lib.sh dmz_load_endpoints) read, with UAT.2's extra keys.
# core.exposure is "hostPort", the only value uat/hub/core accepts.
jq -n --arg run_id "$LITE_RUN_ID" --arg zone "$LITE_PRIVATE_DNS_ZONE" \
	--arg dip "$dmz_ip" --arg dfq "$DMZ_FQDN" --arg dpn "$DMZ_PRIVATE_NAME" \
	--arg cip "$core_ip" --arg cfq "$CORE_FQDN" --arg cpn "$CORE_PRIVATE_NAME" \
	--argjson envoy "$UAT_DMZ_ENVOY_PORT" --argjson bus "$UAT_DMZ_BUS_PORT" \
	--argjson https "$UAT_CORE_HTTPS_PORT" --argjson api "$UAT_CORE_FARMER_API_PORT" \
	--arg drange "$UAT_DMZ_NODE_PORT_RANGE" --arg crange "$UAT_CORE_NODE_PORT_RANGE" \
	--arg issuer "$UAT_CLUSTER_ISSUER" --arg mode "$LITE_ACCESS_MODE" '{
	run_id: $run_id,
	private_dns_zone: $zone,
	cluster_issuer: $issuer,
	ca: {cluster_issuer: $issuer},
	ca_file: "uat-ca.pem",
	kubeconfigs: {dmz: "kube/dmz.kubeconfig", core: "kube/core.kubeconfig"},
	cluster_tool: "kind",
	host_access: $mode,
	dmz: {name: "uat-dmz", private_ip: $dip, fqdn: $dfq, private_fqdn: $dpn,
	      ports: {envoy: $envoy, bus: $bus}, envoy_service_type: "NodePort",
	      exposure: "node ports, Services owned by uat/hub/dmz", node_port_range: $drange},
	core: {name: "uat-core", private_ip: $cip, fqdn: $cfq, private_fqdn: $cpn,
	       ports: {https: $https, farmer_api: $api}, exposure: "hostPort",
	       node_port_range: $crange}
}' >"$LITE_STATE/endpoints.json"

# harness.json: only fields uat/tests/harness knows (it reads the file
# strictly). Envoy listens on 8443, not the default 443; sprouts reach it
# by the private name. The farmer, bus and Envoy restarts keep their
# defaults: vmctl.sh runs them on the kind node, whose kubectl works.
saas_url="https://$CORE_FQDN"
[[ $UAT_CORE_HTTPS_PORT == 443 ]] || saas_url+=":$UAT_CORE_HTTPS_PORT"
jq -n --arg saas "$saas_url" --arg envoy "https://$DMZ_FQDN:$UAT_DMZ_ENVOY_PORT" \
	--arg sprout_envoy "$DMZ_PRIVATE_NAME:$UAT_DMZ_ENVOY_PORT" \
	--arg vmctl "$LITE_DIR/vmctl.sh" --arg bind "$REPO_DIR/uat/hub/core/bind-tenant.sh" \
	--arg kube "$(lite_kubeconfig core)" --arg ep "$LITE_STATE/endpoints.json" --arg st "$LITE_STATE" '{
	saasapi_url: $saas,
	envoy_url: $envoy,
	sprout_envoy_address: $sprout_envoy,
	ca_file: "uat-ca.pem",
	vmctl: $vmctl,
	bind_tenant: {script: $bind, kubeconfig: $kube, endpoints: $ep, state_dir: $st}
}' >"$LITE_STATE/harness.json"

lite_log "wrote uat.json, access.json, endpoints.json and harness.json in $LITE_STATE"
