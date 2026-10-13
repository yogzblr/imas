#!/usr/bin/env bash
# uat/k0s/bootstrap.sh: install a k0s cluster on each UAT hub (dmz and core,
# two separate clusters) and the add-ons the charts need, then set up the
# per-run UAT CA. See README.md.
#
# A hub of one node (the single-node run) gets a single-node cluster (role
# single, kine). A hub of 3 or 5 nodes (the HA run, P24) gets every node as
# controller+worker on etcd, with node-local load balancing and kube-router's
# FOU overlay (README.md, "HA hubs").
#
# Every node is reached only through its Azure Bastion tunnels on the runner,
# as access.json (uat/access/tunnels.sh open) describes: k0sctl over SSH on
# each node's ssh_port, kubectl over the hub's API tunnel (the node's
# kube_port on a single node, the <hub>-api entry's on an HA hub). Nothing
# here calls Azure.
set -euo pipefail
umask 077

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<'EOF'
Usage: bootstrap.sh --uat FILE --access FILE --ssh-key FILE --out DIR
                    [--nodes N] [--timeout SECONDS] [--render-only] [--skip-check]

  --uat FILE        the uat JSON (tofu output -json uat)
  --access FILE     access.json written by uat/access/tunnels.sh open
  --ssh-key FILE    the per-run SSH private key for the hubs' admin_user
  --out DIR         where to write (created if missing):
                      dmz.kubeconfig, core.kubeconfig   admin kubeconfigs (secret)
                      uat-ca.crt                         the UAT CA certificate
                      endpoints.json                     hub names, addresses, ports
                      k0sctl-dmz.yaml, k0sctl-core.yaml  rendered k0sctl files
                      known_hosts                        the hubs' SSH host keys
  --nodes N         every hub must have N nodes in the uat JSON (the
                    workflow's hub_nodes input); without it any count
                    config.env allows is taken
  --timeout SECONDS how long to wait for the nodes, etcd, each rollout and
                    the issuer (900)
  --render-only     write the k0sctl files and endpoints.json, then stop
                    (no k0sctl, kubectl or network)
  --skip-check      do not run check.sh at the end
  -h, --help        this text

Versions are pinned in versions.env, ports and the CA settings in config.env.
EOF
}

usage_error() {
  printf '[uat-k0s] error: %s\n' "$*" >&2
  usage >&2
  exit 2
}

UAT_JSON=""
ACCESS_JSON=""
SSH_KEY=""
OUT_DIR=""
TIMEOUT=900
WANT_NODES=""
RENDER_ONLY=0
SKIP_CHECK=0

parse_args() {
  while (($#)); do
    case $1 in
      --uat | --access | --ssh-key | --out | --timeout | --nodes)
        (($# >= 2)) || usage_error "$1 needs a value"
        case $1 in
          --uat) UAT_JSON=$2 ;;
          --access) ACCESS_JSON=$2 ;;
          --ssh-key) SSH_KEY=$2 ;;
          --out) OUT_DIR=$2 ;;
          --timeout) TIMEOUT=$2 ;;
          --nodes) WANT_NODES=$2 ;;
        esac
        shift 2
        ;;
      --render-only) RENDER_ONLY=1 && shift ;;
      --skip-check) SKIP_CHECK=1 && shift ;;
      -h | --help) usage && exit 0 ;;
      *) usage_error "unknown argument: $1" ;;
    esac
  done

  [[ -n $UAT_JSON ]] || usage_error "--uat is required"
  [[ -n $ACCESS_JSON ]] || usage_error "--access is required"
  [[ -n $SSH_KEY ]] || usage_error "--ssh-key is required"
  [[ -n $OUT_DIR ]] || usage_error "--out is required"
  [[ $TIMEOUT =~ ^[1-9][0-9]*$ ]] || usage_error "--timeout must be a positive number of seconds"
  [[ -z $WANT_NODES || $WANT_NODES =~ ^[1-9][0-9]*$ ]] || usage_error "--nodes must be a positive number"

  local f
  for f in "$UAT_JSON" "$ACCESS_JSON"; do
    [[ -f $f && -r $f ]] || usage_error "not a readable file: $f"
    jq -e 'type == "object"' "$f" >/dev/null 2>&1 || usage_error "not a JSON object: $f"
  done
  [[ -f $SSH_KEY && -r $SSH_KEY ]] || usage_error "SSH key not readable: $SSH_KEY"
  SSH_KEY=$(abs_path "$SSH_KEY") || usage_error "cannot resolve --ssh-key"
  is_safe_abs_path "$SSH_KEY" || usage_error "--ssh-key path has unsupported characters: $SSH_KEY"

  mkdir -p -- "$OUT_DIR" || usage_error "cannot create --out $OUT_DIR"
  OUT_DIR=$(abs_path "$OUT_DIR") || usage_error "cannot resolve --out"
  is_safe_abs_path "$OUT_DIR" || usage_error "--out path has unsupported characters: $OUT_DIR"
}

# check_settings fails on a settings file that would render a broken cluster.
check_settings() {
  [[ $K0S_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k0s\.[0-9]+$ ]] || die "versions.env: bad K0S_VERSION: $K0S_VERSION"
  is_port "$UAT_KUBE_API_PORT" || die "config.env: bad UAT_KUBE_API_PORT"
  local hub range lo hi p r reserved_in
  for r in $UAT_RESERVED_NODE_PORTS; do
    is_port "$r" || die "config.env: bad port in UAT_RESERVED_NODE_PORTS: $r"
  done
  [[ " $UAT_RESERVED_NODE_PORTS " == *" $UAT_KUBE_API_PORT "* ]] ||
    die "config.env: UAT_RESERVED_NODE_PORTS must list the API port $UAT_KUBE_API_PORT"
  for hub in "${HUBS[@]}"; do
    range=$(hub_node_port_range "$hub")
    [[ $range =~ ^[1-9][0-9]*-[1-9][0-9]*$ ]] || die "config.env: bad $hub NodePort range: $range"
    lo=${range%-*}
    hi=${range#*-}
    ((lo < hi && hi <= 65535)) || die "config.env: bad $hub NodePort range: $range"
    while read -r p; do
      is_port "$p" || die "config.env: bad $hub port: $p"
      port_in_range "$p" "$range" || die "config.env: $hub port $p is outside its NodePort range $range"
      [[ " $UAT_RESERVED_NODE_PORTS " != *" $p "* ]] ||
        die "config.env: $hub port $p is a port k0s or the node uses (UAT_RESERVED_NODE_PORTS)"
    done < <(hub_allowed_node_ports "$hub")
    while read -r p; do
      [[ -n $p ]] || continue
      is_port "$p" || die "config.env: bad $hub hostPort: $p"
      [[ " $UAT_RESERVED_NODE_PORTS " != *" $p "* ]] ||
        die "config.env: $hub hostPort $p is a port k0s or the node uses (UAT_RESERVED_NODE_PORTS)"
      if port_in_range "$p" "$range"; then
        die "config.env: $hub hostPort $p is inside its NodePort range $range (a node port could take it)"
      fi
    done < <(hub_allowed_host_ports "$hub")
    reserved_in=""
    for r in $UAT_RESERVED_NODE_PORTS; do
      if port_in_range "$r" "$range"; then reserved_in+=" $r"; fi
    done
    if [[ -n $reserved_in ]]; then
      log "warning: the $hub NodePort range $range contains ports k0s or the node uses:$reserved_in." \
        "A node port Kubernetes picks by itself could land on one (README.md, Exposure)."
    fi
  done
  [[ $UAT_CLUSTER_ISSUER =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "config.env: bad UAT_CLUSTER_ISSUER"
  is_fqdn "$UAT_PRIVATE_DNS_ZONE" || die "config.env: bad UAT_PRIVATE_DNS_ZONE"
  [[ $UAT_CA_SECRET =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "config.env: bad UAT_CA_SECRET"
  [[ $UAT_CA_DAYS =~ ^[1-9][0-9]*$ ]] || die "config.env: bad UAT_CA_DAYS"
  is_port "$UAT_KUBE_ROUTER_FOU_PORT" || die "config.env: bad UAT_KUBE_ROUTER_FOU_PORT"
  [[ " $UAT_RESERVED_NODE_PORTS " == *" $UAT_KUBE_ROUTER_FOU_PORT "* ]] ||
    die "config.env: UAT_RESERVED_NODE_PORTS must list the FOU port $UAT_KUBE_ROUTER_FOU_PORT"
  [[ $UAT_HUB_NODE_COUNTS =~ ^[1-9][0-9]*( [1-9][0-9]*)*$ ]] || die "config.env: bad UAT_HUB_NODE_COUNTS"
}

# read_inputs fills the per-hub and per-node values from the uat JSON and
# access.json, checking each one.
#   per hub:  NAME PRIV_IP PUB_IP FQDN ADMIN (the contract's hub fields, the
#             first node on an HA hub), NODES and NODE_IPS (space-separated,
#             in node order), NODE_COUNT, API_ADDR and API_FQDN (the hub's
#             stable API address and name), HOST and KUBE_PORT (the API
#             tunnel kubectl uses)
#   per node: NODE_HOST NODE_SSH_PORT (the node's SSH tunnel)
declare -A NAME PRIV_IP PUB_IP FQDN ADMIN HOST KUBE_PORT NODES NODE_IPS NODE_COUNT API_ADDR API_FQDN
declare -A NODE_HOST NODE_SSH_PORT
RUN_ID=""

# check_list HUB FIELD fails unless a hub's field is absent or a list of
# strings; read_list HUB FIELD then prints its items, one per line.
check_list() {
  jq -e --arg h "$1" --arg f "$2" '.[$h][$f] | . == null or (type == "array" and all(.[]; type == "string"))' \
    "$UAT_JSON" >/dev/null 2>&1 || die "uat JSON: $1.$2 must be a list of strings"
}
read_list() { jq -r --arg h "$1" --arg f "$2" '.[$h][$f] // [] | .[]' "$UAT_JSON"; }

read_inputs() {
  RUN_ID=$(uat_get "$UAT_JSON" .run_id)
  is_run_id "$RUN_ID" || die "uat JSON: run_id must be 6 to 10 lowercase letters and digits: $RUN_ID"

  local hub v n i api_entry
  local -a names ips
  declare -A seen=()
  for hub in "${HUBS[@]}"; do
    NAME[$hub]=$(uat_get "$UAT_JSON" ".$hub.name")
    is_vm_name "${NAME[$hub]}" || die "uat JSON: bad $hub.name: ${NAME[$hub]}"
    PRIV_IP[$hub]=$(uat_get "$UAT_JSON" ".$hub.private_ip")
    is_ipv4 "${PRIV_IP[$hub]}" || die "uat JSON: bad $hub.private_ip: ${PRIV_IP[$hub]}"
    PUB_IP[$hub]=$(jq -r ".$hub.public_ip // \"\"" "$UAT_JSON")
    [[ -z ${PUB_IP[$hub]} ]] || is_ipv4 "${PUB_IP[$hub]}" || die "uat JSON: bad $hub.public_ip: ${PUB_IP[$hub]}"
    FQDN[$hub]=$(uat_get "$UAT_JSON" ".$hub.fqdn")
    is_fqdn "${FQDN[$hub]}" || die "uat JSON: bad $hub.fqdn: ${FQDN[$hub]}"
    ADMIN[$hub]=$(uat_get "$UAT_JSON" ".$hub.admin_user")
    is_user "${ADMIN[$hub]}" || die "uat JSON: bad $hub.admin_user: ${ADMIN[$hub]}"

    # The nodes (uat/tofu, P24): node_names and node_private_ips, or the
    # hub's own name and address where the file has no node lists. The
    # first node is the hub's name and private_ip.
    check_list "$hub" node_names
    check_list "$hub" node_private_ips
    mapfile -t names < <(read_list "$hub" node_names)
    mapfile -t ips < <(read_list "$hub" node_private_ips)
    if ((${#names[@]} == 0 && ${#ips[@]} == 0)); then
      names=("${NAME[$hub]}")
      ips=("${PRIV_IP[$hub]}")
    fi
    n=${#names[@]}
    ((n == ${#ips[@]})) || die "uat JSON: $hub.node_names and $hub.node_private_ips differ in length"
    [[ " $UAT_HUB_NODE_COUNTS " == *" $n "* ]] ||
      die "uat JSON: $hub has $n nodes; a hub has one of: $UAT_HUB_NODE_COUNTS (etcd needs an odd number)"
    [[ -z $WANT_NODES || $n == "$WANT_NODES" ]] ||
      die "uat JSON: $hub has $n nodes, --nodes asks for $WANT_NODES (is uat.json from this run's tofu apply?)"
    [[ ${names[0]} == "${NAME[$hub]}" && ${ips[0]} == "${PRIV_IP[$hub]}" ]] ||
      die "uat JSON: $hub.name and $hub.private_ip must be the first node's"
    for ((i = 0; i < n; i++)); do
      is_vm_name "${names[i]}" || die "uat JSON: bad $hub node name: ${names[i]}"
      is_ipv4 "${ips[i]}" || die "uat JSON: bad $hub node address: ${ips[i]}"
      [[ -z ${seen[${names[i]}]:-} ]] || die "uat JSON: node ${names[i]} appears twice"
      [[ -z ${seen[ip-${ips[i]}]:-} ]] || die "uat JSON: node address ${ips[i]} appears twice"
      seen[${names[i]}]=1
      seen[ip-${ips[i]}]=1
    done
    NODES[$hub]=${names[*]}
    NODE_IPS[$hub]=${ips[*]}
    NODE_COUNT[$hub]=$n

    # The hub's stable API address and its private name (uat/tofu H1): the
    # internal load balancer on an HA hub, the node itself on a single node.
    API_ADDR[$hub]=$(jq -r ".$hub.api_address // empty" "$UAT_JSON")
    API_FQDN[$hub]=$(jq -r ".$hub.api_fqdn // empty" "$UAT_JSON")
    if ((n == 1)); then
      [[ -n ${API_ADDR[$hub]} ]] || API_ADDR[$hub]=${PRIV_IP[$hub]}
    else
      [[ -n ${API_ADDR[$hub]} ]] || die "uat JSON: $hub has $n nodes but no api_address"
      [[ -n ${API_FQDN[$hub]} ]] || die "uat JSON: $hub has $n nodes but no api_fqdn"
      [[ " ${NODE_IPS[$hub]} " != *" ${API_ADDR[$hub]} "* ]] ||
        die "uat JSON: $hub.api_address must be the load balancer's, not a node's: ${API_ADDR[$hub]}"
    fi
    is_ipv4 "${API_ADDR[$hub]}" || die "uat JSON: bad $hub.api_address: ${API_ADDR[$hub]}"
    [[ -z ${API_FQDN[$hub]} ]] || is_fqdn "${API_FQDN[$hub]}" || die "uat JSON: bad $hub.api_fqdn: ${API_FQDN[$hub]}"

    # Each node's SSH tunnel.
    for v in ${NODES[$hub]}; do
      NODE_HOST[$v]=$(access_get "$ACCESS_JSON" "$v" host)
      is_tunnel_host "${NODE_HOST[$v]}" || die "access.json: bad host for $v: ${NODE_HOST[$v]}"
      NODE_SSH_PORT[$v]=$(access_get "$ACCESS_JSON" "$v" ssh_port)
      is_port "${NODE_SSH_PORT[$v]}" || die "access.json: bad ssh_port for $v: ${NODE_SSH_PORT[$v]}"
    done
    # The API tunnel: the node's own kube tunnel on a single node, the
    # tunnel to the hub's API address (access.json "<hub>-api",
    # uat/access/tunnels.sh) on an HA hub.
    if ((n == 1)); then api_entry=${NAME[$hub]}; else api_entry="$hub-api"; fi
    HOST[$hub]=$(access_get "$ACCESS_JSON" "$api_entry" host)
    is_tunnel_host "${HOST[$hub]}" || die "access.json: bad host for $api_entry: ${HOST[$hub]}"
    KUBE_PORT[$hub]=$(access_get "$ACCESS_JSON" "$api_entry" kube_port)
    is_port "${KUBE_PORT[$hub]}" || die "access.json: bad kube_port for $api_entry: ${KUBE_PORT[$hub]}"
  done
  [[ ${NAME[dmz]} != "${NAME[core]}" ]] || die "uat JSON: dmz and core have the same name"
}

is_tunnel_host() { is_ipv4 "$1" || is_fqdn "$1" || [[ $1 == localhost ]]; }

# is_ha HUB: the hub has more than one node.
is_ha() { ((NODE_COUNT[$1] > 1)); }

cluster_name() { printf 'imas-uat-%s-%s\n' "$RUN_ID" "$1"; }

# render_hub HUB writes OUT/k0sctl-HUB.yaml: one host per node (role single
# for one node, controller+worker for an HA hub) and the hub's ClusterConfig.
render_hub() {
  local hub=$1 extra_san=${HOST[$1]} tmp hosts="" sans="" dns="" role ha_host="" node i other
  local api_address="" storage="" kube_router=""
  local -a names ips list
  read -ra names <<<"${NODES[$hub]}"
  read -ra ips <<<"${NODE_IPS[$hub]}"
  tmp=$(mktemp "$OUT_DIR/.render.XXXXXX")

  if is_ha "$hub"; then
    role=controller+worker
    ha_host=$(read_block "$K0S_DIR/templates/ha/host.yaml.tmpl")
    storage=$(read_block "$K0S_DIR/templates/ha/storage.yaml.tmpl")
    render_template "$K0S_DIR/templates/ha/network.yaml.tmpl" "$tmp" "FOU_PORT=$UAT_KUBE_ROUTER_FOU_PORT"
    kube_router=$(read_block "$tmp")
  else
    role=single
    api_address="          address: ${PRIV_IP[$hub]}"
  fi

  for ((i = 0; i < ${#names[@]}; i++)); do
    node=${names[i]}
    render_template "$K0S_DIR/templates/k0sctl-host.yaml.tmpl" "$tmp" \
      "ROLE=$role" \
      "HA_HOST=$ha_host" \
      "ACCESS_HOST=${NODE_HOST[$node]}" \
      "SSH_PORT=${NODE_SSH_PORT[$node]}" \
      "ADMIN_USER=${ADMIN[$hub]}" \
      "SSH_KEY=$SSH_KEY" \
      "HOST_ALIAS=$node" \
      "KNOWN_HOSTS=$OUT_DIR/known_hosts" \
      "PRIVATE_IP=${ips[i]}"
    hosts+="${hosts:+$'\n'}$(read_block "$tmp")"
  done

  # 127.0.0.1 is always in the SANs; a different tunnel host is added too.
  # A single node: its private IP and the hub's FQDN, as before P24. An HA
  # hub: the internal load balancer's address and private name, then every
  # node's private IP and the hub's FQDN.
  [[ $extra_san != 127.0.0.1 ]] || extra_san=localhost
  list=(127.0.0.1 "$extra_san")
  if is_ha "$hub"; then list+=("${API_ADDR[$hub]}" "${API_FQDN[$hub]}"); fi
  list+=("${ips[@]}" "${FQDN[$hub]}")
  declare -A dup=()
  for i in "${list[@]}"; do
    [[ -z ${dup[$i]:-} ]] || continue
    dup[$i]=1
    sans+="${sans:+$'\n'}            - $i"
  done

  # CoreDNS: core's line(s) first, then the DMZ's. This hub's FQDN maps to
  # each of its nodes (a pod never dials its own hub's internal load
  # balancer, which drops a node's flow to itself); the other hub's FQDN to
  # that hub's stable private address.
  for other in core dmz; do
    if [[ $other == "$hub" ]]; then
      for i in ${NODE_IPS[$other]}; do
        dns+="${dns:+$'\n'}                                $i ${FQDN[$other]}"
      done
    else
      dns+="${dns:+$'\n'}                                ${API_ADDR[$other]} ${FQDN[$other]}"
    fi
  done

  render_template "$K0S_DIR/templates/k0sctl.yaml.tmpl" "$OUT_DIR/k0sctl-$hub.yaml" \
    "CLUSTER_NAME=$(cluster_name "$hub")" \
    "HOSTS=$hosts" \
    "API_ADDRESS=$api_address" \
    "SANS=$sans" \
    "STORAGE=$storage" \
    "KUBE_ROUTER=$kube_router" \
    "COREDNS_HOSTS=$dns" \
    "K0S_VERSION=$K0S_VERSION" \
    "KUBE_API_PORT=$UAT_KUBE_API_PORT" \
    "NODE_PORT_RANGE=$(hub_node_port_range "$hub")"
  rm -f "$tmp"
  chmod 600 "$OUT_DIR/k0sctl-$hub.yaml"
  log "rendered $OUT_DIR/k0sctl-$hub.yaml (${#names[@]} node(s), role $role)"
}

# write_endpoints writes the hubs' names, addresses and exposed ports for the
# hub scripts and the tests: the uat JSON's dmz and core objects plus ports
# (the keys uat/hub/dmz reads: dmz.ports.envoy, dmz.ports.bus,
# core.ports.farmer_api, cluster_issuer, private_dns_zone). The two hub
# readers use different spellings for the issuer and the private names
# (uat/hub/dmz: cluster_issuer, private_dns_zone; uat/hub/core:
# ca.cluster_issuer, dmz.private_fqdn, core.private_fqdn), so both forms are
# written, with the same values. Each hub also carries its nodes (names and
# private IPs), its API address and name, and its datastore (kine for one
# node, etcd for an HA hub); check.sh reads the node count and the datastore.
write_endpoints() {
  local zone
  zone=$(jq -r '.private_dns_zone // empty' "$UAT_JSON")
  [[ -n $zone ]] || zone=$UAT_PRIVATE_DNS_ZONE
  is_fqdn "$zone" || die "uat JSON: bad private_dns_zone: $zone"
  jq -n \
    --arg zone "$zone" \
    --arg run_id "$RUN_ID" \
    --arg dn "${NAME[dmz]}" --arg dp "${PRIV_IP[dmz]}" --arg dq "${PUB_IP[dmz]}" --arg df "${FQDN[dmz]}" \
    --arg cn "${NAME[core]}" --arg cp "${PRIV_IP[core]}" --arg cq "${PUB_IP[core]}" --arg cf "${FQDN[core]}" \
    --argjson envoy "$UAT_DMZ_ENVOY_PORT" --argjson bus "$UAT_DMZ_BUS_PORT" \
    --argjson https "$UAT_CORE_HTTPS_PORT" --argjson api "$UAT_CORE_FARMER_API_PORT" \
    --arg drange "$UAT_DMZ_NODE_PORT_RANGE" --arg crange "$UAT_CORE_NODE_PORT_RANGE" \
    --arg issuer "$UAT_CLUSTER_ISSUER" \
    --arg k0s "$K0S_VERSION" \
    --arg dnodes "${NODES[dmz]}" --arg dips "${NODE_IPS[dmz]}" --arg dapi "${API_ADDR[dmz]}" --arg dapif "${API_FQDN[dmz]}" \
    --arg cnodes "${NODES[core]}" --arg cips "${NODE_IPS[core]}" --arg capi "${API_ADDR[core]}" --arg capif "${API_FQDN[core]}" '
    def nodes($names; $ips; $api; $apif):
      ($names | split(" ")) as $n
      | {nodes: $n, node_private_ips: ($ips | split(" ")), api_address: $api, api_fqdn: $apif,
         datastore: (if ($n | length) > 1 then "etcd" else "kine" end)};
    {
      run_id: $run_id,
      dmz: ({name: $dn, private_ip: $dp, public_ip: $dq, fqdn: $df,
            private_fqdn: ("dmz." + $zone),
            ports: {envoy: $envoy, bus: $bus},
            exposure: "node ports, Services owned by uat/hub/dmz",
            node_port_range: $drange} + nodes($dnodes; $dips; $dapi; $dapif)),
      core: ({name: $cn, private_ip: $cp, public_ip: $cq, fqdn: $cf,
             private_fqdn: ("core." + $zone),
             ports: {https: $https, farmer_api: $api},
             # Exactly "hostPort": uat/hub/core/lib/common.sh accepts
             # nothing else (owner decision, 2026-10-06: no core node ports).
             exposure: "hostPort",
             node_port_range: $crange} + nodes($cnodes; $cips; $capi; $capif)),
      private_dns_zone: $zone,
      cluster_issuer: $issuer,
      ca: {cluster_issuer: $issuer},
      ca_file: "uat-ca.crt",
      kubeconfigs: {dmz: "dmz.kubeconfig", core: "core.kubeconfig"},
      k0s_version: $k0s
    }' >"$OUT_DIR/endpoints.json"
  chmod 644 "$OUT_DIR/endpoints.json"
  log "wrote $OUT_DIR/endpoints.json"
}

check_k0sctl_version() {
  local have
  # awk reads to the end: exiting at the first match could leave k0sctl
  # writing to a closed pipe, and pipefail would end the script with 141.
  have=$(k0sctl version 2>/dev/null | awk '$1 == "version:" && v == "" {v = $2} END {print v}')
  [[ $have == "$K0SCTL_VERSION" ]] ||
    die "k0sctl ${have:-unknown} found, versions.env pins $K0SCTL_VERSION (uat/k0s/install-tools.sh installs it)"
}

kubeconfig_of() { printf '%s/%s.kubeconfig\n' "$OUT_DIR" "$1"; }

# wait_nodes_ready HUB waits until every node of the hub has registered and
# is Ready, and on an HA hub until etcd has a joined member per node.
wait_nodes_ready() {
  local hub=$1 k deadline n want=${NODE_COUNT[$1]}
  k=$(kubeconfig_of "$hub")
  deadline=$((SECONDS + TIMEOUT))
  until n=$(kc "$k" get nodes -o json 2>/dev/null | jq '.items | length') && ((n >= want)); do
    ((SECONDS < deadline)) || die "$hub: ${n:-0} of $want node(s) registered within ${TIMEOUT}s"
    sleep 5
  done
  kc "$k" wait --for=condition=Ready node --all --timeout="$((deadline - SECONDS > 0 ? deadline - SECONDS : 1))s" >&2 ||
    die "$hub: nodes not Ready within ${TIMEOUT}s"
  log "$hub: $want node(s) Ready"
  is_ha "$hub" || return 0
  # k0s's EtcdMember objects (etcd.k0sproject.io), one per controller that
  # joined etcd.
  until n=$(kc "$k" get etcdmembers.etcd.k0sproject.io -o json 2>/dev/null | jq "$ETCD_JOINED") && ((n >= want)); do
    ((SECONDS < deadline)) || die "$hub: etcd has ${n:-0} of $want members joined after ${TIMEOUT}s"
    sleep 5
  done
  log "$hub: etcd has $want members"
}

install_cluster() {
  local hub=$1 cfg="$OUT_DIR/k0sctl-$1.yaml" tmp
  log "$hub: installing k0s $K0S_VERSION on ${NODES[$hub]// /, } (${NODE_COUNT[$hub]} node(s))"
  k0sctl apply --config "$cfg" >&2 || die "$hub: k0sctl apply failed"

  tmp=$(mktemp "$OUT_DIR/.kubeconfig.XXXXXX")
  if ! k0sctl kubeconfig --config "$cfg" --cluster "$(cluster_name "$hub")" \
    --address "https://${HOST[$hub]}:${KUBE_PORT[$hub]}" >"$tmp"; then
    rm -f "$tmp"
    die "$hub: k0sctl kubeconfig failed"
  fi
  if ! grep -q '^apiVersion: v1' "$tmp"; then
    rm -f "$tmp"
    die "$hub: k0sctl kubeconfig printed no kubeconfig"
  fi
  chmod 600 "$tmp"
  mv -f "$tmp" "$(kubeconfig_of "$hub")"
  log "$hub: kubeconfig at $(kubeconfig_of "$hub") (server https://${HOST[$hub]}:${KUBE_PORT[$hub]})"
  wait_nodes_ready "$hub"
}

# pin_helper_image SRC DST rewrites the local-path helper pod's untagged
# busybox image to LOCAL_PATH_HELPER_IMAGE, and fails if the manifest no
# longer has exactly one such line.
pin_helper_image() {
  local src=$1 dst=$2 n
  n=$(grep -cE '^[[:space:]]*image: docker\.io/library/busybox[[:space:]]*$' "$src" || true)
  [[ $n == 1 ]] || die "local-path manifest: expected one untagged busybox image line, found $n"
  sed -E "s#^([[:space:]]*image: )docker\.io/library/busybox[[:space:]]*\$#\\1${LOCAL_PATH_HELPER_IMAGE}#" "$src" >"$dst"
}

install_local_path() {
  local hub=$1 k src="$CACHE_DIR/local-path-storage.yaml" dst="$CACHE_DIR/local-path-storage.pinned.yaml"
  k=$(kubeconfig_of "$hub")
  fetch_pinned "$LOCAL_PATH_PROVISIONER_URL" "$LOCAL_PATH_PROVISIONER_SHA256" "$src"
  pin_helper_image "$src" "$dst"
  log "$hub: local-path-provisioner $LOCAL_PATH_PROVISIONER_VERSION"
  kc "$k" apply -f "$dst" >&2
  kc "$k" annotate storageclass local-path storageclass.kubernetes.io/is-default-class=true --overwrite >&2
  kc "$k" -n local-path-storage rollout status deployment/local-path-provisioner --timeout="${TIMEOUT}s" >&2 ||
    die "$hub: local-path-provisioner not available"
}

install_cert_manager() {
  local hub=$1 k src="$CACHE_DIR/cert-manager.yaml" d
  k=$(kubeconfig_of "$hub")
  fetch_pinned "$CERT_MANAGER_URL" "$CERT_MANAGER_SHA256" "$src"
  log "$hub: cert-manager $CERT_MANAGER_VERSION"
  # Server-side: the CRDs are too large for client-side apply's annotation.
  kc "$k" apply --server-side --force-conflicts -f "$src" >&2
  for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
    kc "$k" -n "$UAT_CERT_MANAGER_NAMESPACE" rollout status "deployment/$d" --timeout="${TIMEOUT}s" >&2 ||
      die "$hub: $d not available"
  done
}

# ca_secret_field HUB KEY prints a base64 field of the CA Secret on a hub,
# or nothing when the Secret does not exist.
ca_secret_field() {
  local k
  k=$(kubeconfig_of "$1")
  kc "$k" -n "$UAT_CERT_MANAGER_NAMESPACE" get secret "$UAT_CA_SECRET" --ignore-not-found -o json |
    jq -r --arg key "$2" 'if . == null then "" else (.data[$key] // "") end'
}

# generate_ca DIR writes a fresh self-signed root (ECDSA P-256) to DIR/tls.crt
# and DIR/tls.key.
generate_ca() {
  local dir=$1
  cat >"$dir/ca.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
O = imas UAT
CN = imas UAT CA $RUN_ID
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl req -x509 -new -config "$dir/ca.cnf" \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$dir/tls.key" -out "$dir/tls.crt" -days "$UAT_CA_DAYS" 2>/dev/null ||
    die "openssl could not create the UAT CA"
}

# setup_ca makes sure both hubs hold the same CA Secret and a Ready
# ClusterIssuer on it, and writes the CA certificate to OUT/uat-ca.crt. A CA
# already on a hub (a re-run) is reused, never replaced: sprouts may pin it.
setup_ca() {
  local hub k src="" crt key first="" i
  declare -A have=()
  CA_TMP=$(mktemp -d "$OUT_DIR/.ca.XXXXXX")

  for hub in "${HUBS[@]}"; do
    have[$hub]=$(ca_secret_field "$hub" tls.crt) || die "$hub: cannot read Secret $UAT_CERT_MANAGER_NAMESPACE/$UAT_CA_SECRET"
    if [[ -n ${have[$hub]} ]]; then
      if [[ -z $first ]]; then
        first=$hub
      elif [[ ${have[$hub]} != "${have[$first]}" ]]; then
        die "the two hubs hold different UAT CAs in $UAT_CERT_MANAGER_NAMESPACE/$UAT_CA_SECRET; delete one by hand"
      fi
    fi
  done

  if [[ -n $first ]]; then
    log "reusing the UAT CA already on $first"
    printf '%s' "${have[$first]}" | base64 -d >"$CA_TMP/tls.crt"
    key=$(ca_secret_field "$first" tls.key) || die "$first: cannot read the CA Secret"
    [[ -n $key ]] || die "$first: CA Secret has no tls.key"
    printf '%s' "$key" | base64 -d >"$CA_TMP/tls.key"
    src=$first
  else
    log "creating a new UAT CA for run $RUN_ID (valid $UAT_CA_DAYS days)"
    generate_ca "$CA_TMP"
  fi

  for hub in "${HUBS[@]}"; do
    k=$(kubeconfig_of "$hub")
    if [[ -z ${have[$hub]} ]]; then
      log "$hub: storing the UAT CA in $UAT_CERT_MANAGER_NAMESPACE/$UAT_CA_SECRET"
      kc "$k" -n "$UAT_CERT_MANAGER_NAMESPACE" create secret tls "$UAT_CA_SECRET" \
        --cert="$CA_TMP/tls.crt" --key="$CA_TMP/tls.key" --dry-run=client -o json |
        kc "$k" apply -f - >&2 || die "$hub: could not store the CA Secret"
    fi
    render_template "$K0S_DIR/templates/cluster-issuer.yaml.tmpl" "$CA_TMP/issuer-$hub.yaml" \
      "CLUSTER_ISSUER=$UAT_CLUSTER_ISSUER" "CA_SECRET=$UAT_CA_SECRET"
    # cert-manager's webhook can lag its rollout by a few seconds.
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
      kc "$k" apply -f "$CA_TMP/issuer-$hub.yaml" >&2 && break
      ((i < 12)) || die "$hub: could not create ClusterIssuer $UAT_CLUSTER_ISSUER"
      sleep 5
    done
    kc "$k" wait --for=condition=Ready "clusterissuer/$UAT_CLUSTER_ISSUER" --timeout="${TIMEOUT}s" >&2 ||
      die "$hub: ClusterIssuer $UAT_CLUSTER_ISSUER not Ready"
  done

  crt="$OUT_DIR/uat-ca.crt"
  cp "$CA_TMP/tls.crt" "$crt"
  chmod 644 "$crt"
  rm -rf "$CA_TMP"
  CA_TMP=""
  log "UAT CA certificate at $crt${src:+ (from $src)}"
}

CA_TMP=""
CACHE_DIR=""
cleanup() {
  [[ -z $CA_TMP ]] || rm -rf "$CA_TMP"
}

main() {
  need_cmd jq
  parse_args "$@"
  load_settings
  check_settings
  read_inputs
  trap cleanup EXIT

  : >>"$OUT_DIR/known_hosts"
  chmod 600 "$OUT_DIR/known_hosts"
  local hub
  for hub in "${HUBS[@]}"; do
    render_hub "$hub"
  done
  write_endpoints
  if ((RENDER_ONLY)); then
    log "render only: stopping before k0sctl"
    return 0
  fi

  need_cmd k0sctl kubectl curl openssl base64 awk sed grep
  check_k0sctl_version
  CACHE_DIR="$OUT_DIR/cache"
  mkdir -p "$CACHE_DIR"

  for hub in "${HUBS[@]}"; do
    install_cluster "$hub"
  done
  for hub in "${HUBS[@]}"; do
    install_local_path "$hub"
    install_cert_manager "$hub"
  done
  setup_ca

  if ((!SKIP_CHECK)); then
    "$K0S_DIR/check.sh" --out "$OUT_DIR"
  fi
  log "done: kubeconfigs, uat-ca.crt and endpoints.json are in $OUT_DIR"
}

main "$@"
