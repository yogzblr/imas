# shellcheck shell=bash
# shellcheck disable=SC2034 # the constants are used by the scripts sourcing this
# Shared by install.sh and check.sh (UAT.3a). Sourced, never run.
#
# Nothing here is Azure specific: the inputs are an endpoints file and a
# kubeconfig, so the local rig (UAT.8) runs the same code.

# Fixed names (values-uat.yaml sets fullnameOverride to match). The core
# side relies on them: deploy/helm/farmer's bus.serviceName and
# bus.namespace.
DMZ_RELEASE=imas-dmz
DMZ_NAMESPACE=imas-dmz
DMZ_FULLNAME=imas-dmz-nats
DMZ_BUS_NAME="${DMZ_FULLNAME}-bus"
DMZ_ENVOY_NAME="${DMZ_FULLNAME}-envoy"
DMZ_BUS_FQDN="${DMZ_BUS_NAME}.${DMZ_NAMESPACE}.svc.cluster.local"
DMZ_ENVOY_TLS_SECRET=imas-envoy-dmz-tls
DMZ_BUS_TLS_SECRET=imas-farmerbus-tls
DMZ_SEEDS_SECRET=imas-farmer-nats-seeds
# The five seeds the bus mounts (values-uat.yaml natsSeeds.seeds).
DMZ_SEED_KEYS=(operator.nk operator-signing.nk sys-account.nk tenant.nk tenant-signing.nk)
# The bus client pod port from values-uat.yaml (NetworkPolicy rules name
# pod ports), which is also the farmer chart's bus.port.
DMZ_BUS_CLIENT_POD_PORT=5406
# The published farmerbus image (deploy/helm/nats values.yaml).
DMZ_BUS_IMAGE_REPO=ghcr.io/yogzblr/imas-farmerbus

# Defaults when the endpoints file names no port. The DMZ node ports are the
# owner's decisions of 2026-10-06: Envoy on node port 8443, the bus on node
# port 8442, so the DMZ NodePort range is 8442-8443 and holds no reserved
# port. farmer's API port is the farmer chart's.
DMZ_DEFAULT_ENVOY_PORT=8443
DMZ_DEFAULT_BUS_PORT=8442
DMZ_DEFAULT_FARMER_API_PORT=5405
DMZ_DEFAULT_CLUSTER_ISSUER=imas-uat-ca
# The private DNS zone of the run (UAT.1's private_dns_zone): dmz.<zone> and
# core.<zone> resolve to the hubs' private addresses inside the VNet. Owner's
# decision, 2026-10-06: the SANs, farmerinterface and farmerbusurl use them.
DMZ_DEFAULT_PRIVATE_DNS_ZONE=uat.imas.internal

dmz_log() { printf '%s: %s\n' "${DMZ_PROG:-uat-dmz}" "$*" >&2; }
dmz_die() {
	dmz_log "error: $*"
	exit 1
}

dmz_need() {
	local t
	for t in "$@"; do
		command -v "$t" >/dev/null 2>&1 || dmz_die "$t not found on PATH"
	done
}

# dmz_chart_version TAG: print the chart version (and image tag) for a
# release tag, the tag without its leading v. Only vX.Y.Z and vX.Y.Z-rc.N
# are accepted (section 4h, Shared contract), so "latest" never gets in.
dmz_chart_version() {
	local tag=$1
	[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.(0|[1-9][0-9]*))?$ ]] ||
		dmz_die "release tag '$tag' is not vX.Y.Z or vX.Y.Z-rc.N"
	printf '%s\n' "${tag#v}"
}

_dmz_is_ipv4() {
	local ip=$1 o
	[[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	for o in "${BASH_REMATCH[@]:1}"; do
		((10#$o <= 255)) || return 1
	done
}

_dmz_is_fqdn() {
	[[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] &&
		((${#1} <= 253))
}

_dmz_is_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535)); }

# _dmz_jq FILE FILTER: one scalar, empty when null or absent.
_dmz_jq() { jq -r "($2) // empty | tostring" "$1"; }

# dmz_load_endpoints FILE: read and check the endpoints file, setting
#   DMZ_FQDN DMZ_PRIVATE_IP DMZ_PUBLIC_IP (may be empty) DMZ_ENVOY_PORT
#   DMZ_BUS_PORT CORE_FQDN CORE_PRIVATE_IP CORE_FARMER_API_PORT
#   DMZ_CLUSTER_ISSUER DMZ_CONNECT_ADDR DMZ_PRIVATE_DNS_ZONE
#   DMZ_PRIVATE_NAME CORE_PRIVATE_NAME
# The shape is the tofu output "uat" object's dmz and core entries (name,
# private_ip, public_ip, fqdn), plus optional ports; see README.md,
# "Endpoints file". A tofu "uat" JSON is a valid endpoints file as is.
dmz_load_endpoints() {
	local f=$1
	[[ -r $f ]] || dmz_die "endpoints file '$f' is not readable"
	jq -e 'type == "object" and (.dmz | type == "object") and (.core | type == "object")' "$f" >/dev/null 2>&1 ||
		dmz_die "endpoints file '$f' is not a JSON object with dmz and core objects"

	DMZ_FQDN=$(_dmz_jq "$f" '.dmz.fqdn')
	DMZ_PRIVATE_IP=$(_dmz_jq "$f" '.dmz.private_ip')
	DMZ_PUBLIC_IP=$(_dmz_jq "$f" '.dmz.public_ip')
	DMZ_ENVOY_PORT=$(_dmz_jq "$f" ".dmz.ports.envoy // $DMZ_DEFAULT_ENVOY_PORT")
	# bus_client is the name UAT.2's endpoints file (PR #130) uses.
	DMZ_BUS_PORT=$(_dmz_jq "$f" ".dmz.ports.bus // .dmz.ports.bus_client // $DMZ_DEFAULT_BUS_PORT")
	CORE_FQDN=$(_dmz_jq "$f" '.core.fqdn')
	CORE_PRIVATE_IP=$(_dmz_jq "$f" '.core.private_ip')
	CORE_FARMER_API_PORT=$(_dmz_jq "$f" ".core.ports.farmer_api // $DMZ_DEFAULT_FARMER_API_PORT")
	DMZ_CLUSTER_ISSUER=$(_dmz_jq "$f" ".cluster_issuer // \"$DMZ_DEFAULT_CLUSTER_ISSUER\"")
	# The names are a convention on the zone, not keys of the tofu output.
	DMZ_PRIVATE_DNS_ZONE=$(_dmz_jq "$f" ".private_dns_zone // \"$DMZ_DEFAULT_PRIVATE_DNS_ZONE\"")
	_dmz_is_fqdn "$DMZ_PRIVATE_DNS_ZONE" || dmz_die "endpoints: private_dns_zone '$DMZ_PRIVATE_DNS_ZONE' is not a DNS name"
	DMZ_PRIVATE_NAME="dmz.${DMZ_PRIVATE_DNS_ZONE}"
	CORE_PRIVATE_NAME="core.${DMZ_PRIVATE_DNS_ZONE}"
	# How Envoy is exposed, when the file says (UAT.2's PR #130 writes it);
	# install.sh --expose overrides it.
	DMZ_ENVOY_SERVICE_TYPE=$(_dmz_jq "$f" '.dmz.envoy_service_type')
	case $DMZ_ENVOY_SERVICE_TYPE in
	"" | NodePort | LoadBalancer) ;;
	*) dmz_die "endpoints: dmz.envoy_service_type '$DMZ_ENVOY_SERVICE_TYPE' is not NodePort or LoadBalancer" ;;
	esac

	_dmz_is_fqdn "$DMZ_FQDN" || dmz_die "endpoints: dmz.fqdn '$DMZ_FQDN' is not a DNS name"
	_dmz_is_fqdn "$CORE_FQDN" || dmz_die "endpoints: core.fqdn '$CORE_FQDN' is not a DNS name"
	_dmz_is_ipv4 "$DMZ_PRIVATE_IP" || dmz_die "endpoints: dmz.private_ip '$DMZ_PRIVATE_IP' is not an IPv4 address"
	_dmz_is_ipv4 "$CORE_PRIVATE_IP" || dmz_die "endpoints: core.private_ip '$CORE_PRIVATE_IP' is not an IPv4 address"
	if [[ -n $DMZ_PUBLIC_IP ]]; then
		_dmz_is_ipv4 "$DMZ_PUBLIC_IP" || dmz_die "endpoints: dmz.public_ip '$DMZ_PUBLIC_IP' is not an IPv4 address"
	fi
	_dmz_is_port "$DMZ_ENVOY_PORT" || dmz_die "endpoints: dmz.ports.envoy '$DMZ_ENVOY_PORT' is not a port"
	_dmz_is_port "$DMZ_BUS_PORT" || dmz_die "endpoints: dmz.ports.bus '$DMZ_BUS_PORT' is not a port"
	_dmz_is_port "$CORE_FARMER_API_PORT" || dmz_die "endpoints: core.ports.farmer_api '$CORE_FARMER_API_PORT' is not a port"
	[[ $DMZ_ENVOY_PORT != "$DMZ_BUS_PORT" ]] || dmz_die "endpoints: dmz.ports.envoy and dmz.ports.bus are both $DMZ_ENVOY_PORT"
	[[ $DMZ_CLUSTER_ISSUER =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] ||
		dmz_die "endpoints: cluster_issuer '$DMZ_CLUSTER_ISSUER' is not a Kubernetes name"
	# Where the runner (and a sprout) connects: the public address when
	# there is one, so the check does not depend on public DNS.
	DMZ_CONNECT_ADDR=${DMZ_PUBLIC_IP:-$DMZ_FQDN}
}

# dmz_write_run_values OUT VERSION: the run-specific values, passed after
# values-uat.yaml.
dmz_write_run_values() {
	local out=$1 version=$2
	cat >"$out" <<EOF
# Written by uat/hub/dmz/install.sh for one run. Do not commit.
---
bus:
  image:
    repository: ${DMZ_BUS_IMAGE_REPO}
    # The release under test: chart version and image tag are both the
    # release tag without its leading v. Never latest.
    tag: "${version}"
envoy:
  upstreams:
    # farmer's API on the core hub, reached on the core private IP. sni is
    # core's private DNS name (${CORE_PRIVATE_NAME}); upstream TLS is not
    # verified.
    farmerAPI:
      host: "${CORE_PRIVATE_IP}"
      port: ${CORE_FARMER_API_PORT}
      sni: "${CORE_PRIVATE_NAME}"
    recipeService:
      host: "${CORE_PRIVATE_IP}"
      port: ${CORE_FARMER_API_PORT}
      sni: "${CORE_PRIVATE_NAME}"
networkPolicy:
  # The chart's core rule selects pods in this cluster, which core is
  # not. Envoy's egress to farmer goes to the core private IP.
  envoyExtraEgress:
    - to:
        - ipBlock:
            cidr: ${CORE_PRIVATE_IP}/32
      ports:
        - protocol: TCP
          port: ${CORE_FARMER_API_PORT}
EOF
}

# _dmz_expose_service NAME COMPONENT PORT TARGETPORT TYPE
# TYPE is NodePort or LoadBalancer (PORT on the load balancer's address).
# The node port is PORT in both: pinned, so the DMZ's NodePort range
# (8442-8443) is never left to allocation.
_dmz_expose_service() {
	local name=$1 component=$2 port=$3 target=$4 type=$5
	cat <<EOF
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${DMZ_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: imas
    app.kubernetes.io/managed-by: uat-hub-dmz
    imas.io/purpose: imas-uat
spec:
  type: ${type}
  # Local: no source NAT, so the bus policy below sees core's own address
  # and Envoy sees the client's (its enroll rate limit and logs).
  externalTrafficPolicy: Local
  selector:
    app.kubernetes.io/name: nats
    app.kubernetes.io/instance: ${DMZ_RELEASE}
    app.kubernetes.io/component: ${component}
  ports:
    - name: ${target}
      port: ${port}
      targetPort: ${target}
      protocol: TCP
      nodePort: ${port}
EOF
}

# dmz_write_manifests OUT MODE: what the chart does not render. The two
# certificates, the two Services that expose Envoy and the bus, and the bus
# ingress rule for core. MODE is nodeport (Envoy on node port
# dmz.ports.envoy, 8443 by default) or loadbalancer (Envoy behind a
# LoadBalancer Service on that port, node port pinned to it too). The bus
# is a NodePort on dmz.ports.bus (8442 by default) either way: only core
# dials it. These Services are this script's, not UAT.2's (owner's
# decisions, 2026-10-06). README.md, "Exposure".
dmz_write_manifests() {
	local out=$1 mode=$2
	{
		cat <<EOF
# Written by uat/hub/dmz/install.sh for one run. Do not commit.
---
# DMZ edge certificate, verified against the UAT CA: sprouts connect to the
# private name (their farmerinterface), the runner's check.sh to the public
# FQDN.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${DMZ_ENVOY_TLS_SECRET}
  namespace: ${DMZ_NAMESPACE}
  labels:
    imas.io/purpose: imas-uat
spec:
  secretName: ${DMZ_ENVOY_TLS_SECRET}
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: ${DMZ_CLUSTER_ISSUER}
  dnsNames:
    - ${DMZ_PRIVATE_NAME}
    - ${DMZ_FQDN}
  duration: 168h
  renewBefore: 24h
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  usages:
    - server auth
    - digital signature
---
# Bus certificate (bus.tls.mode=secret): tls.crt, tls.key and ca.crt.
# Covers the bus Service names Envoy dials, the private name farmer dials
# and verifies (farmerbusurl tls://${DMZ_PRIVATE_NAME}:<bus node port>), and
# the DMZ private IP.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${DMZ_BUS_TLS_SECRET}
  namespace: ${DMZ_NAMESPACE}
  labels:
    imas.io/purpose: imas-uat
spec:
  secretName: ${DMZ_BUS_TLS_SECRET}
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: ${DMZ_CLUSTER_ISSUER}
  dnsNames:
    - ${DMZ_BUS_NAME}
    - ${DMZ_BUS_NAME}.${DMZ_NAMESPACE}
    - ${DMZ_BUS_NAME}.${DMZ_NAMESPACE}.svc
    - ${DMZ_BUS_FQDN}
    - ${DMZ_BUS_NAME}-0.${DMZ_BUS_NAME}-headless.${DMZ_NAMESPACE}.svc.cluster.local
    - ${DMZ_PRIVATE_NAME}
  ipAddresses:
    - ${DMZ_PRIVATE_IP}
  duration: 168h
  renewBefore: 24h
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  usages:
    - server auth
    - client auth
    - digital signature
EOF
		local envoy_type=NodePort
		[[ $mode != loadbalancer ]] || envoy_type=LoadBalancer
		_dmz_expose_service "${DMZ_FULLNAME}-envoy-edge" envoy "$DMZ_ENVOY_PORT" https "$envoy_type"
		_dmz_expose_service "${DMZ_FULLNAME}-bus-core" bus "$DMZ_BUS_PORT" client NodePort
		cat <<EOF
---
# Core (cmd/farmer and saasapi) dials the bus client port from the core
# hub, which no pod selector can name. NetworkPolicies are additive: this
# adds one source to the chart's bus policy and opens nothing else.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${DMZ_BUS_NAME}-uat-core
  namespace: ${DMZ_NAMESPACE}
  labels:
    imas.io/purpose: imas-uat
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: nats
      app.kubernetes.io/instance: ${DMZ_RELEASE}
      app.kubernetes.io/component: bus
  policyTypes:
    - Ingress
  ingress:
    - from:
        - ipBlock:
            cidr: ${CORE_PRIVATE_IP}/32
      ports:
        - protocol: TCP
          port: ${DMZ_BUS_CLIENT_POD_PORT}
EOF
	} >"$out"
}

# dmz_write_outputs OUT VERSION MODE [LB_ADDRESS]: what the core side and the
# enrolment need from this hub, nothing secret. envoy.host is what sprouts
# use (farmerinterface); bus.farmerbusurl is what farmer dials, verifying
# bus.tls_server_name; bus.in_cluster is the bus Service inside the DMZ
# cluster, for reference (README.md, "What is assumed about the core side").
dmz_write_outputs() {
	local out=$1 version=$2 mode=$3 lb_address=${4:-}
	jq -n \
		--arg version "$version" \
		--arg mode "$mode" \
		--arg lb "$lb_address" \
		--arg image "${DMZ_BUS_IMAGE_REPO}:${version}" \
		--arg private_name "$DMZ_PRIVATE_NAME" \
		--arg public_fqdn "$DMZ_FQDN" \
		--arg envoy_port "$DMZ_ENVOY_PORT" \
		--arg bus_ip "$DMZ_PRIVATE_IP" \
		--arg bus_port "$DMZ_BUS_PORT" \
		--arg bus_fqdn "$DMZ_BUS_FQDN" \
		--arg bus_name "$DMZ_BUS_NAME" \
		--arg bus_svc_port "$DMZ_BUS_CLIENT_POD_PORT" \
		--arg ns "$DMZ_NAMESPACE" \
		'{
			chart_version: $version,
			farmerbus_image: $image,
			envoy: {
				host: $private_name,
				public_host: $public_fqdn,
				port: ($envoy_port | tonumber),
				sprout_bus_url: "wss://\($private_name):\($envoy_port)/",
				exposure: $mode,
				load_balancer_address: (if $lb == "" then null else $lb end)
			},
			bus: {
				farmerbusurl: "tls://\($private_name):\($bus_port)",
				tls_server_name: $private_name,
				address: $bus_ip,
				port: ($bus_port | tonumber),
				in_cluster: {
					service_name: $bus_name,
					namespace: $ns,
					port: ($bus_svc_port | tonumber),
					fqdn: $bus_fqdn
				}
			}
		}' >"$out"
}
