#!/usr/bin/env bash
# up.sh: bring the local UAT rig up (UAT.8; README.md). On one Docker host:
#
#   1. the shared Docker network, and two kind clusters on it, dmz and core,
#      with cert-manager, a default StorageClass (kind's local-path) and the
#      DMZ's NodePort range 8442-8443;
#   2. the per-run UAT CA as the ClusterIssuer imas-uat-ca on both;
#   3. the hub names resolving the same way everywhere: a CoreDNS hosts
#      block in both clusters, --add-host in the sprout containers, and a
#      block in the host's hosts file (sudo when it is not writable);
#   4. the sprout containers (systemd, sshd), one Ubuntu 24.04 and one
#      AlmaLinux 9 per tenant, built from sprouts/*.Dockerfile;
#   5. uat.json, access.json, endpoints.json and harness.json
#      (write-material.sh);
#   6. uat/hub/core/install.sh, then uat/hub/dmz/install.sh and check.sh,
#      from the release named by --release-tag (core first: the bus needs
#      core's seeds);
#   7. uat/enroll/enroll.sh: tenants 1 and 2, and the published imas-sprout
#      package on every sprout over SSH.
#
# Usage: up.sh --release-tag vX.Y.Z[-rc.N] [--state DIR] [--run-id ID]
#              [--host-access auto|direct|published] [--hosts-file FILE|none]
#              [--skip-hubs] [--skip-enroll] [--skip-checks] [--reinstall]
#              [--rebuild-images]
#
#   --release-tag   the release under test (chart, images and packages)
#   --state DIR     the rig's state (default LITE_STATE in config.env)
#   --run-id ID     6 to 10 lowercase letters and digits (default lite01)
#   --host-access   how the host reaches the hubs (config.env, LITE_HOST_ACCESS)
#   --hosts-file    where the hub names go on the host (default /etc/hosts);
#                   none prints the lines instead
#   --skip-hubs     stop before the hub installs (and enrolment)
#   --skip-enroll   stop before enrolment
#   --skip-checks   do not run uat/hub/dmz/check.sh
#   --reinstall     run the hub installs and enrolment again even when this
#                   release is already installed
#   --rebuild-images  rebuild the sprout images
#
# Every step is safe to repeat: what exists is reused. Exit 2 on a usage
# error, 1 on any failure.
set -euo pipefail
LITE_PROG=up.sh
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

release_tag="" skip_hubs=0 skip_enroll=0 skip_checks=0 reinstall=0 rebuild_images=0
cli_state="" cli_run_id="" cli_access="" cli_hosts=""
while (($#)); do
	case $1 in
	--release-tag | --state | --run-id | --host-access | --hosts-file)
		(($# >= 2)) || lite_usage_die "$1 needs a value"
		case $1 in
		--release-tag) release_tag=$2 ;;
		--state) cli_state=$2 ;;
		--run-id) cli_run_id=$2 ;;
		--host-access) cli_access=$2 ;;
		--hosts-file) cli_hosts=$2 ;;
		esac
		shift 2
		;;
	--skip-hubs) skip_hubs=1 && shift ;;
	--skip-enroll) skip_enroll=1 && shift ;;
	--skip-checks) skip_checks=1 && shift ;;
	--reinstall) reinstall=1 && shift ;;
	--rebuild-images) rebuild_images=1 && shift ;;
	-h | --help) usage ;;
	*) lite_usage_die "unknown argument '$1' (see --help)" ;;
	esac
done
[[ -n $release_tag ]] || lite_usage_die "--release-tag is required"
lite_is_release_tag "$release_tag" || lite_usage_die "--release-tag '$release_tag' is not vX.Y.Z or vX.Y.Z-rc.N (never latest)"
[[ -z $cli_run_id ]] || LITE_RUN_ID=$cli_run_id
# A run id given on purpose (flag or environment) must match a saved rig's.
explicit_run_id=${LITE_RUN_ID:-}
[[ -z $cli_state ]] || LITE_STATE=$cli_state
[[ -z $cli_access ]] || LITE_HOST_ACCESS=$cli_access
[[ -z $cli_hosts ]] || LITE_HOSTS_FILE=$cli_hosts
lite_load_settings
lite_check_settings

# The scripts the rig runs unchanged. The overrides exist for the tests.
CORE_INSTALL=${LITE_CORE_INSTALL:-$REPO_DIR/uat/hub/core/install.sh}
DMZ_INSTALL=${LITE_DMZ_INSTALL:-$REPO_DIR/uat/hub/dmz/install.sh}
DMZ_CHECK=${LITE_DMZ_CHECK:-$REPO_DIR/uat/hub/dmz/check.sh}
ENROLL=${LITE_ENROLL:-$REPO_DIR/uat/enroll/enroll.sh}

# --- 0. preflight and state ------------------------------------------------

preflight() {
	lite_need docker kind kubectl helm jq curl openssl ssh-keygen awk sed grep
	((skip_hubs)) || lite_need go tar sha256sum base64
	((skip_hubs || skip_enroll)) || lite_need python3 ansible-playbook ssh
	docker info >/dev/null 2>&1 || lite_die "the Docker daemon is not reachable (docker info failed)"

	local have
	have=$(kind version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
	if [[ -z $have ]]; then
		lite_log "warning: cannot read kind's version; $LITE_KIND_MIN_VERSION or later is expected"
	elif [[ $(printf '%s\n%s\n' "$LITE_KIND_MIN_VERSION" "$have" | sort -V | head -n 1) != "$LITE_KIND_MIN_VERSION" ]]; then
		lite_log "warning: kind $have is older than $LITE_KIND_MIN_VERSION, which this rig was written for"
	fi
	local f v
	for f in max_user_instances:512 max_user_watches:524288; do
		v=$(cat "/proc/sys/fs/inotify/${f%%:*}" 2>/dev/null || echo "")
		if [[ -n $v ]] && ((v < ${f#*:})); then
			lite_log "warning: fs.inotify.${f%%:*} is $v; two kind clusters want ${f#*:} (README.md, Prerequisites)"
		fi
	done
	v=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
	if [[ $v =~ ^[0-9]+$ ]] && ((v > 0 && v < 12 * 1024 * 1024 * 1024)); then
		lite_log "warning: Docker has $((v / 1024 / 1024)) MiB of memory; the rig wants about 16 GiB (README.md)"
	fi
}

prepare_state() {
	mkdir -p "$LITE_STATE"
	chmod 700 "$LITE_STATE"
	LITE_STATE=$(cd "$LITE_STATE" && pwd)
	mkdir -p "$LITE_STATE/kind" "$LITE_STATE/kube" "$LITE_STATE/cache" "$LITE_STATE/ssh"
	(umask 077 && mkdir -p "$LITE_STATE/sensitive/ca")

	local saved_mode=""
	if [[ -s $(lite_rig_file) ]]; then
		saved_mode=$(lite_rig_get '.settings.LITE_ACCESS_MODE')
		PREV_HOSTS_FILE=$(lite_rig_get '.settings.LITE_HOSTS_FILE')
		lite_restore_settings || true
		[[ -z $cli_hosts ]] || LITE_HOSTS_FILE=$cli_hosts
		[[ -z $explicit_run_id || $LITE_RUN_ID == "$explicit_run_id" ]] ||
			lite_usage_die "$LITE_STATE holds the rig of run $LITE_RUN_ID, not $explicit_run_id (another --state, or down.sh first)"
		lite_check_settings
		lite_log "reusing the rig in $LITE_STATE"
	fi
	lite_resolve_host_access
	if [[ -n $saved_mode && $LITE_HOST_ACCESS != auto && $LITE_HOST_ACCESS != "$saved_mode" ]]; then
		lite_usage_die "the rig was built with host access '$saved_mode'; run down.sh before switching to '$LITE_HOST_ACCESS'"
	fi
	[[ -z $saved_mode ]] || LITE_ACCESS_MODE=$saved_mode
	lite_save_settings
	lite_log "rig $LITE_RUN_ID, state $LITE_STATE, host access $LITE_ACCESS_MODE, release $release_tag"
}

# --- 1. network and clusters -----------------------------------------------

ensure_network() {
	local net
	if net=$(docker network inspect "$LITE_NETWORK" 2>/dev/null) && [[ -n $net && $net != "[]" ]]; then
		jq -e --arg s "$LITE_SUBNET" '.[0].IPAM.Config // [] | any(.Subnet == $s)' <<<"$net" >/dev/null ||
			lite_die "Docker network $LITE_NETWORK exists without subnet $LITE_SUBNET: remove it or set LITE_NETWORK"
		jq -e '.[0].Labels["imas.io/purpose"] == "imas-uat-lite"' <<<"$net" >/dev/null ||
			lite_die "Docker network $LITE_NETWORK exists but is not the rig's (no imas.io/purpose label)"
		return 0
	fi
	lite_log "creating Docker network $LITE_NETWORK ($LITE_SUBNET; kind nodes from $LITE_IP_RANGE)"
	docker network create --driver bridge --subnet "$LITE_SUBNET" --ip-range "$LITE_IP_RANGE" \
		--gateway "$LITE_GATEWAY" --label imas.io/purpose=imas-uat-lite --label "imas.io/run-id=$LITE_RUN_ID" \
		"$LITE_NETWORK" >/dev/null || lite_die "could not create Docker network $LITE_NETWORK"
}

cluster_name() { if [[ $1 == dmz ]]; then echo "$LITE_DMZ_CLUSTER"; else echo "$LITE_CORE_CLUSTER"; fi; }
node_of() { if [[ $1 == dmz ]]; then echo "$DMZ_NODE"; else echo "$CORE_NODE"; fi; }

# kind_config HUB: the kind cluster file. The DMZ's NodePort range is set
# through a kubeadm patch, written for both kubeadm API versions kind may
# generate (each patch names its apiVersion, so only the matching one
# applies); up.sh checks the API server got it. In published mode the
# hub's outside port (core 443, DMZ 8443) is published on the host.
kind_config() {
	local hub=$1 pod svc range port
	if [[ $hub == dmz ]]; then
		pod=$LITE_DMZ_POD_SUBNET svc=$LITE_DMZ_SERVICE_SUBNET range=$UAT_DMZ_NODE_PORT_RANGE port=$UAT_DMZ_ENVOY_PORT
	else
		pod=$LITE_CORE_POD_SUBNET svc=$LITE_CORE_SERVICE_SUBNET range=$UAT_CORE_NODE_PORT_RANGE port=$UAT_CORE_HTTPS_PORT
	fi
	cat <<EOF
---
# kind cluster for the $hub hub of the uat/lite rig (UAT.8), written by up.sh.
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $(cluster_name "$hub")
networking:
  apiServerAddress: 127.0.0.1
  podSubnet: "$pod"
  serviceSubnet: "$svc"
nodes:
  - role: control-plane
    image: $LITE_KIND_NODE_IMAGE
    labels:
      imas.io/hub: $hub
EOF
	if [[ $LITE_ACCESS_MODE == published ]]; then
		cat <<EOF
    extraPortMappings:
      - containerPort: $port
        hostPort: $port
        listenAddress: "$LITE_PUBLISH_ADDRESS"
        protocol: TCP
EOF
	fi
	cat <<EOF
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta3
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-node-port-range: "$range"
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: service-node-port-range
          value: "$range"
EOF
}

node_ready() { lite_kc "$1" wait --for=condition=Ready node --all --timeout=10s >/dev/null 2>&1; }

ensure_cluster() {
	local hub=$1 name node cfg kube tmp
	name=$(cluster_name "$hub")
	node=$(node_of "$hub")
	cfg="$LITE_STATE/kind/$hub.yaml"
	kube=$(lite_kubeconfig "$hub")
	kind_config "$hub" >"$cfg"
	local existing
	existing=$(kind get clusters 2>/dev/null || true)
	if grep -qx "$name" <<<"$existing"; then
		lite_container_running "$node" || docker start "$node" >/dev/null || lite_die "could not start $node"
		[[ -n $(lite_container_ip "$node") ]] ||
			lite_die "a kind cluster named $name exists but is not on $LITE_NETWORK: not this rig's (delete it, or set LITE_${hub^^}_CLUSTER)"
		# kind always publishes the API server; published mode needs the
		# hub's own port too, which only a cluster created that way has.
		local want=$UAT_DMZ_ENVOY_PORT
		[[ $hub == dmz ]] || want=$UAT_CORE_HTTPS_PORT
		if [[ $LITE_ACCESS_MODE == published ]] &&
			! lite_inspect "$node" | jq -e --arg p "$want/tcp" '.HostConfig.PortBindings // {} | has($p)' >/dev/null; then
			lite_die "cluster $name does not publish port $want but host access is published: run down.sh, then up.sh"
		fi
		lite_log "$hub: reusing kind cluster $name"
	else
		lite_log "$hub: creating kind cluster $name on $LITE_NETWORK ($LITE_KIND_NODE_IMAGE)"
		KIND_EXPERIMENTAL_DOCKER_NETWORK=$LITE_NETWORK kind create cluster --name "$name" --config "$cfg" \
			--kubeconfig "$kube" --wait "${LITE_WAIT_TIMEOUT}s" >&2 || lite_die "$hub: kind create cluster failed"
	fi
	lite_rig_update '.clusters[$h] = {name: $n, node: $c}' --arg h "$hub" --arg n "$name" --arg c "$node"
	tmp=$(mktemp "$kube.XXXXXX")
	kind get kubeconfig --name "$name" >"$tmp" || lite_die "$hub: kind get kubeconfig failed"
	chmod 600 "$tmp"
	mv -f "$tmp" "$kube"
	lite_wait_until "$LITE_WAIT_TIMEOUT" "$hub: node Ready" node_ready "$hub"
}

# The DMZ's node ports 8442 and 8443 need its NodePort range; a kubeadm
# patch kind ignored would only show when uat/hub/dmz creates the Services.
check_node_port_range() {
	lite_kc dmz -n kube-system get pods -l component=kube-apiserver -o json |
		jq -e --arg a "--service-node-port-range=$UAT_DMZ_NODE_PORT_RANGE" \
			'[.items[].spec.containers[].command[]?] | index($a) != null' >/dev/null ||
		lite_die "dmz: the API server has no --service-node-port-range=$UAT_DMZ_NODE_PORT_RANGE (kind ignored the kubeadm patch; see README.md, Known gaps)"
}

# --- 2. add-ons and the UAT CA ---------------------------------------------

ensure_addons() {
	local hub=$1 n d manifest="$LITE_STATE/cache/cert-manager.yaml"
	n=$(lite_kc "$hub" get storageclass -o json |
		jq '[.items[] | select(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true")] | length')
	[[ $n == 1 ]] || lite_die "$hub: expected one default StorageClass (kind's standard), found ${n:-none}"
	lite_kc "$hub" -n local-path-storage rollout status deployment/local-path-provisioner \
		--timeout="${LITE_WAIT_TIMEOUT}s" >&2 || lite_die "$hub: local-path-provisioner not available"
	lite_fetch_pinned "$CERT_MANAGER_URL" "$CERT_MANAGER_SHA256" "$manifest"
	lite_log "$hub: cert-manager $CERT_MANAGER_VERSION"
	lite_kc "$hub" apply --server-side --force-conflicts -f "$manifest" >&2 || lite_die "$hub: cert-manager apply failed"
	for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
		lite_kc "$hub" -n "$UAT_CERT_MANAGER_NAMESPACE" rollout status "deployment/$d" \
			--timeout="${LITE_WAIT_TIMEOUT}s" >&2 || lite_die "$hub: $d not available"
	done
}

# ensure_ca: one self-signed root for the rig (ECDSA P-256, as UAT.2's), in
# the Secret cert-manager/imas-uat-ca and as the CA ClusterIssuer
# imas-uat-ca on both hubs. Its key stays in <state>/sensitive/ca (0600) so
# a re-run keeps the CA the sprouts pin.
ensure_ca() {
	local dir="$LITE_STATE/sensitive/ca" hub i issuer
	if [[ ! -s $dir/tls.key || ! -s $dir/tls.crt ]]; then
		lite_log "creating the rig's UAT CA (valid $LITE_CA_DAYS days)"
		cat >"$dir/ca.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
O = imas UAT
CN = imas UAT CA $LITE_RUN_ID (local rig)
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
		(umask 077 && openssl req -x509 -new -config "$dir/ca.cnf" \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-keyout "$dir/tls.key" -out "$dir/tls.crt" -days "$LITE_CA_DAYS" 2>/dev/null) ||
			lite_die "openssl could not create the UAT CA"
	fi
	openssl x509 -in "$dir/tls.crt" -noout -checkend 86400 >/dev/null ||
		lite_die "the rig's UAT CA expires within a day: run down.sh, then up.sh"
	issuer="$LITE_STATE/kind/cluster-issuer.yaml"
	sed -e "s/__CLUSTER_ISSUER__/$UAT_CLUSTER_ISSUER/g" -e "s/__CA_SECRET__/$UAT_CA_SECRET/g" \
		"$REPO_DIR/uat/k0s/templates/cluster-issuer.yaml.tmpl" >"$issuer"
	for hub in core dmz; do
		lite_kc "$hub" -n "$UAT_CERT_MANAGER_NAMESPACE" create secret tls "$UAT_CA_SECRET" \
			--cert="$dir/tls.crt" --key="$dir/tls.key" --dry-run=client -o json |
			lite_kc "$hub" apply -f - >&2 || lite_die "$hub: could not store the CA Secret"
		# cert-manager's webhook can lag its rollout by a few seconds.
		for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
			lite_kc "$hub" apply -f "$issuer" >&2 && break
			((i < 12)) || lite_die "$hub: could not create ClusterIssuer $UAT_CLUSTER_ISSUER"
			sleep 5
		done
		lite_kc "$hub" wait --for=condition=Ready "clusterissuer/$UAT_CLUSTER_ISSUER" \
			--timeout="${LITE_WAIT_TIMEOUT}s" >&2 || lite_die "$hub: ClusterIssuer $UAT_CLUSTER_ISSUER not Ready"
	done
	cp "$dir/tls.crt" "$LITE_STATE/uat-ca.pem"
	chmod 644 "$LITE_STATE/uat-ca.pem"
}

# --- 3. names --------------------------------------------------------------

# coredns_hosts HUB: a hosts block in the cluster's Corefile, after "ready",
# mapping the hub names to the node addresses, as UAT.2 does on k0s. kind
# does not reconcile the CoreDNS ConfigMap, so an edit stays.
coredns_hosts() {
	local hub=$1 cm corefile block new
	cm=$(lite_kc "$hub" -n kube-system get configmap coredns -o json) || lite_die "$hub: no coredns ConfigMap"
	corefile=$(jq -r '.data.Corefile // empty' <<<"$cm")
	[[ -n $corefile ]] || lite_die "$hub: the coredns ConfigMap has no Corefile"
	block=$(printf '    # BEGIN imas-uat-lite\n    hosts {\n        %s %s %s\n        %s %s %s\n        fallthrough\n    }\n    # END imas-uat-lite' \
		"$CORE_IP" "$CORE_FQDN" "$CORE_PRIVATE_NAME" "$DMZ_IP" "$DMZ_FQDN" "$DMZ_PRIVATE_NAME")
	new=$(awk -v block="$block" '
		/# BEGIN imas-uat-lite/ { skip = 1; next }
		skip && /# END imas-uat-lite/ { skip = 0; next }
		skip { next }
		{ print }
		!done && /^[[:space:]]*ready[[:space:]]*$/ { print block; done = 1 }
		END { if (!done) exit 3 }' <<<"$corefile") ||
		lite_die "$hub: the Corefile has no 'ready' line to put the hosts block after"
	if [[ $new == "$corefile" ]]; then
		return 0
	fi
	lite_log "$hub: CoreDNS resolves $CORE_FQDN, $CORE_PRIVATE_NAME, $DMZ_FQDN and $DMZ_PRIVATE_NAME"
	jq --arg c "$new" '.data.Corefile = $c' <<<"$cm" | lite_kc "$hub" replace -f - >&2 ||
		lite_die "$hub: could not update the coredns ConfigMap"
	lite_kc "$hub" -n kube-system rollout restart deployment/coredns >&2
	lite_kc "$hub" -n kube-system rollout status deployment/coredns --timeout="${LITE_WAIT_TIMEOUT}s" >&2 ||
		lite_die "$hub: CoreDNS did not come back"
}

host_names() {
	local d=$DMZ_IP c=$CORE_IP
	if [[ $LITE_ACCESS_MODE == published ]]; then
		d=$LITE_PUBLISH_ADDRESS c=$LITE_PUBLISH_ADDRESS
	fi
	printf '%s %s %s\n%s %s %s\n' "$c" "$CORE_FQDN" "$CORE_PRIVATE_NAME" "$d" "$DMZ_FQDN" "$DMZ_PRIVATE_NAME"
}

PREV_HOSTS_FILE=""
ensure_host_names() {
	local lines
	lines=$(host_names)
	# The rig moved to another hosts file (or to none): take its block out
	# of the old one, so down.sh's single file is the only place left.
	if [[ -n $PREV_HOSTS_FILE && $PREV_HOSTS_FILE != none && $PREV_HOSTS_FILE != "$LITE_HOSTS_FILE" && -e $PREV_HOSTS_FILE ]]; then
		lite_hosts_update "$PREV_HOSTS_FILE" ""
	fi
	if [[ $LITE_HOSTS_FILE == none ]]; then
		lite_log "LITE_HOSTS_FILE=none: add these lines to the host's hosts file yourself:"
		printf '%s\n' "$lines" >&2
		return 0
	fi
	lite_hosts_update "$LITE_HOSTS_FILE" "$lines"
	lite_log "host: $LITE_HOSTS_FILE resolves the hub names ($LITE_ACCESS_MODE)"
}

# --- 4. sprouts ------------------------------------------------------------

sprout_booted() {
	local s
	s=$(docker exec "$1" systemctl is-system-running 2>/dev/null || true)
	[[ $s == running || $s == degraded ]]
}
sshd_up() { docker exec "$1" sh -c 'systemctl is-active --quiet ssh || systemctl is-active --quiet sshd' 2>/dev/null; }

ensure_sprouts() {
	local key="$LITE_STATE/ssh/id_ed25519" vm os c ip port img hosts_ok built=" "
	if [[ ! -s $key ]]; then
		ssh-keygen -q -t ed25519 -N '' -C "imas-uat-lite-$LITE_RUN_ID" -f "$key" || lite_die "ssh-keygen failed"
	fi
	chmod 600 "$key"
	for vm in $LITE_SPROUTS; do
		if lite_is_host_sprout "$vm"; then
			lite_log "$vm is this host (LITE_HOST_SPROUT): authorise $key.pub for $LITE_HOST_SPROUT_USER on 127.0.0.1:$LITE_HOST_SPROUT_PORT (README.md, WSL2)"
			continue
		fi
		os=$(lite_sprout_os "$vm")
		img=$(lite_sprout_image "$os")
		if [[ $built != *" $os "* ]] && { ((rebuild_images)) || ! docker image inspect "$img" >/dev/null 2>&1; }; then
			local base=$LITE_UBUNTU_BASE_IMAGE
			[[ $os == ubuntu ]] || base=$LITE_ALMA_BASE_IMAGE
			lite_log "building $img from $base"
			docker build -t "$img" -f "$LITE_DIR/sprouts/$os.Dockerfile" --build-arg "BASE_IMAGE=$base" \
				"$LITE_DIR/sprouts" >&2 || lite_die "could not build $img"
		fi
		built+="$os "
		c=$(lite_sprout_container "$vm")
		ip=$(lite_sprout_ip "$vm")
		port=$(lite_sprout_ssh_port "$vm")
		if lite_container_exists "$c"; then
			hosts_ok=$(lite_inspect "$c" | jq -r --arg a "$DMZ_PRIVATE_NAME" --arg ip "$DMZ_IP" \
				'[.HostConfig.ExtraHosts[]? | select(. == ($a + ":" + $ip) or . == ($a + "=" + $ip))] | length')
			[[ $hosts_ok == 1 ]] ||
				lite_die "$c resolves $DMZ_PRIVATE_NAME to an old address (the DMZ node is now $DMZ_IP): run down.sh, then up.sh"
			lite_container_running "$c" || docker start "$c" >/dev/null || lite_die "could not start $c"
			[[ $(lite_container_ip "$c") == "$ip" ]] || lite_die "$c is not at $ip on $LITE_NETWORK"
			continue
		fi
		lite_log "$vm: starting $c ($img) at $ip, SSH on 127.0.0.1:$port"
		docker run -d --name "$c" --hostname "$vm" \
			--network "$LITE_NETWORK" --ip "$ip" \
			--privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
			-p "127.0.0.1:$port:22" \
			--add-host "$DMZ_PRIVATE_NAME:$DMZ_IP" --add-host "$DMZ_FQDN:$DMZ_IP" \
			--add-host "$CORE_PRIVATE_NAME:$CORE_IP" --add-host "$CORE_FQDN:$CORE_IP" \
			--label imas.io/purpose=imas-uat-lite --label "imas.io/run-id=$LITE_RUN_ID" --label "imas.io/vm=$vm" \
			"$img" >/dev/null || lite_die "could not start $c"
	done
	for vm in $LITE_SPROUTS; do
		lite_is_host_sprout "$vm" && continue
		c=$(lite_sprout_container "$vm")
		lite_wait_until "$LITE_WAIT_TIMEOUT" "$c: systemd boot" sprout_booted "$c"
		docker exec -i "$c" sh -c 'umask 077 && mkdir -p /root/.ssh && cat >/root/.ssh/authorized_keys' \
			<"$key.pub" || lite_die "$c: could not authorise the rig's SSH key"
		lite_wait_until "$LITE_WAIT_TIMEOUT" "$c: sshd" sshd_up "$c"
	done
	lite_rig_update '.sprouts_up = true'
}

# --- 6. and 7. the hubs and enrolment --------------------------------------

install_core() {
	if ((!reinstall)) && lite_stage_done core "$release_tag"; then
		lite_log "core: $release_tag already installed (--reinstall to run it again)"
		return 1
	fi
	lite_log "core: uat/hub/core/install.sh $release_tag"
	"$CORE_INSTALL" "$(lite_kubeconfig core)" "$LITE_STATE/endpoints.json" "$LITE_STATE" "$release_tag" ||
		lite_die "core: uat/hub/core/install.sh failed"
	lite_stage_mark core "$release_tag"
}

install_dmz() {
	if ((!reinstall)) && lite_stage_done dmz "$release_tag"; then
		lite_log "dmz: $release_tag already installed (--reinstall to run it again)"
		return 1
	fi
	lite_log "dmz: uat/hub/dmz/install.sh $release_tag"
	"$DMZ_INSTALL" --kubeconfig "$(lite_kubeconfig dmz)" --endpoints "$LITE_STATE/endpoints.json" \
		--release-tag "$release_tag" --seeds-from-kubeconfig "$(lite_kubeconfig core)" \
		--workdir "$LITE_STATE/dmz" || lite_die "dmz: uat/hub/dmz/install.sh failed"
	lite_stage_mark dmz "$release_tag"
}

check_dmz() {
	local connect=$DMZ_IP
	[[ $LITE_ACCESS_MODE != published ]] || connect=$LITE_PUBLISH_ADDRESS
	lite_log "dmz: uat/hub/dmz/check.sh (connecting to $connect)"
	"$DMZ_CHECK" --endpoints "$LITE_STATE/endpoints.json" --ca-file "$LITE_STATE/uat-ca.pem" \
		--kubeconfig "$(lite_kubeconfig dmz)" --connect "$connect" || lite_die "dmz: uat/hub/dmz/check.sh failed"
}

enroll() {
	if ((!reinstall)) && lite_stage_done enroll "$release_tag"; then
		lite_log "enrolment: $release_tag already enrolled (--reinstall to run it again)"
	else
		lite_log "enrolment: uat/enroll/enroll.sh $release_tag"
		"$ENROLL" --uat "$LITE_STATE/uat.json" --access "$LITE_STATE/access.json" \
			--state "$LITE_STATE/enroll" --release-tag "$release_tag" \
			--ssh-key "$LITE_STATE/ssh/id_ed25519" \
			--core-state "$LITE_STATE" --core-kubeconfig "$(lite_kubeconfig core)" \
			--endpoints "$LITE_STATE/endpoints.json" || lite_die "uat/enroll/enroll.sh failed"
		lite_stage_mark enroll "$release_tag"
	fi
	# The hand-off files uat/tests reads from the material directory.
	local f
	for f in tenants.json sprouts.json; do
		[[ -s $LITE_STATE/enroll/$f ]] || lite_die "uat/enroll wrote no $f"
		ln -sfn "enroll/$f" "$LITE_STATE/$f"
	done
}

main() {
	preflight
	prepare_state
	ensure_network
	local hub
	for hub in core dmz; do
		ensure_cluster "$hub"
	done
	check_node_port_range
	DMZ_IP=$(lite_container_ip "$DMZ_NODE")
	CORE_IP=$(lite_container_ip "$CORE_NODE")
	if ! lite_is_ipv4 "$DMZ_IP" || ! lite_is_ipv4 "$CORE_IP"; then
		lite_die "the kind nodes have no address on $LITE_NETWORK"
	fi
	lite_log "nodes: core $CORE_NODE at $CORE_IP, dmz $DMZ_NODE at $DMZ_IP"
	for hub in core dmz; do
		ensure_addons "$hub"
	done
	ensure_ca
	for hub in core dmz; do
		coredns_hosts "$hub"
	done
	ensure_host_names
	ensure_sprouts
	"$LITE_DIR/write-material.sh" --state "$LITE_STATE"
	lite_rig_update '.release_tag = $t' --arg t "$release_tag"

	if ((skip_hubs)); then
		lite_log "--skip-hubs: stopping before the hub installs"
		return 0
	fi
	install_core || true
	local dmz_ran=0
	if install_dmz; then dmz_ran=1; fi
	# check.sh drains /v1/enroll's bucket (then waits for the refill), so it
	# runs once after an install, before enrolment, as its README says.
	if ((dmz_ran && !skip_checks)); then
		check_dmz
	fi
	if ((skip_enroll)); then
		lite_log "--skip-enroll: stopping before enrolment"
		return 0
	fi
	enroll
	lite_log "the rig is up: uat/lite/run.sh smoke --state $LITE_STATE"
}

main
