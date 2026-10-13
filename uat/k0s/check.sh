#!/usr/bin/env bash
# uat/k0s/check.sh: print the state of both UAT hub clusters and fail if
# either is not fit for the hub charts. It fails when:
#   - a node is not Ready (or there is none), or fewer nodes are Ready than
#     the hub has (endpoints.json, the hub's nodes),
#   - an HA hub's etcd has fewer joined members than the hub has nodes,
#   - there is no default StorageClass,
#   - cert-manager is not available (its three Deployments),
#   - the UAT ClusterIssuer is not Ready,
#   - CoreDNS does not map the core FQDN (and the DMZ FQDN) to the private
#     addresses bootstrap.sh set (only with an endpoints file, which names
#     them): a hub's own FQDN to each of its nodes, the other hub's to that
#     hub's api_address,
#   - a NodePort or LoadBalancer Service uses a node port the hub does not
#     expose (config.env),
#     (Envoy's and the bus's on the DMZ, none on core),
#   - a pod off the host network, on any node, uses a hostPort the hub does
#     not expose (none on the DMZ; the edge's 443 and 5405 and RustFS's 9000
#     on core).
# It reads the clusters only; it changes nothing.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<'EOF'
Usage: check.sh [--out DIR] [--dmz-kubeconfig FILE] [--core-kubeconfig FILE]
                [--endpoints FILE]

  --out DIR               bootstrap.sh's output directory: uses DIR/dmz.kubeconfig,
                          DIR/core.kubeconfig and DIR/endpoints.json
  --dmz-kubeconfig FILE   kubeconfig of the DMZ hub (overrides --out)
  --core-kubeconfig FILE  kubeconfig of the core hub (overrides --out)
  --endpoints FILE        endpoints.json, for the node count, the etcd and the
                          CoreDNS checks (overrides --out)
  -h, --help              this text

Exit status: 0 when both hubs pass, 1 when a check fails, 2 on bad usage.
EOF
}

usage_error() {
  printf '[uat-k0s] error: %s\n' "$*" >&2
  usage >&2
  exit 2
}

declare -A KUBECONFIG_OF=()
ENDPOINTS=""
OUT_DIR=""

parse_args() {
  while (($#)); do
    case $1 in
      --out | --dmz-kubeconfig | --core-kubeconfig | --endpoints)
        (($# >= 2)) || usage_error "$1 needs a value"
        case $1 in
          --out) OUT_DIR=$2 ;;
          --dmz-kubeconfig) KUBECONFIG_OF[dmz]=$2 ;;
          --core-kubeconfig) KUBECONFIG_OF[core]=$2 ;;
          --endpoints) ENDPOINTS=$2 ;;
        esac
        shift 2
        ;;
      -h | --help) usage && exit 0 ;;
      *) usage_error "unknown argument: $1" ;;
    esac
  done
  local hub
  if [[ -n $OUT_DIR ]]; then
    [[ -d $OUT_DIR ]] || usage_error "not a directory: $OUT_DIR"
    for hub in "${HUBS[@]}"; do
      [[ -n ${KUBECONFIG_OF[$hub]:-} ]] || KUBECONFIG_OF[$hub]="$OUT_DIR/$hub.kubeconfig"
    done
    if [[ -z $ENDPOINTS && -f "$OUT_DIR/endpoints.json" ]]; then
      ENDPOINTS="$OUT_DIR/endpoints.json"
    fi
  fi
  for hub in "${HUBS[@]}"; do
    [[ -n ${KUBECONFIG_OF[$hub]:-} ]] || usage_error "no kubeconfig for the $hub hub (--out or --$hub-kubeconfig)"
    [[ -r ${KUBECONFIG_OF[$hub]} ]] || usage_error "kubeconfig not readable: ${KUBECONFIG_OF[$hub]}"
  done
  if [[ -n $ENDPOINTS ]]; then
    jq -e '.core.fqdn and .core.private_ip and .dmz.fqdn and .dmz.private_ip' "$ENDPOINTS" >/dev/null 2>&1 ||
      usage_error "endpoints file lacks dmz/core fqdn and private_ip: $ENDPOINTS"
  fi
}

FAILURES=()
fail() {
  FAILURES+=("$1: $2")
  printf '  FAIL  %s\n' "$2"
}
ok() { printf '  ok    %s\n' "$1"; }

# expected_nodes HUB prints how many nodes the hub has (endpoints.json), or
# 1 without an endpoints file.
expected_nodes() {
  if [[ -n $ENDPOINTS ]]; then
    jq -r --arg h "$1" '.[$h].nodes // [] | length | if . == 0 then 1 else . end' "$ENDPOINTS"
  else
    echo 1
  fi
}

# hub_datastore HUB prints kine or etcd (endpoints.json), or kine without one.
hub_datastore() {
  if [[ -n $ENDPOINTS ]]; then
    jq -r --arg h "$1" '.[$h].datastore // "kine"' "$ENDPOINTS"
  else
    echo kine
  fi
}

get_json() {
  local k=$1
  shift
  kc "$k" --request-timeout=30s get "$@" -o json 2>/dev/null
}

check_nodes() {
  local hub=$1 k=$2 json n bad ready want
  if ! json=$(get_json "$k" nodes); then
    fail "$hub" "cannot list nodes (API unreachable through the kube tunnel?)"
    return
  fi
  jq -r '.items[] | "  node  \(.metadata.name)  Ready=\((.status.conditions // [] | map(select(.type == "Ready"))[0].status) // "Unknown")  \(.status.nodeInfo.kubeletVersion // "?")"' <<<"$json"
  n=$(jq '.items | length' <<<"$json")
  bad=$(jq -r '[.items[] | select(((.status.conditions // []) | map(select(.type == "Ready" and .status == "True")) | length) == 0) | .metadata.name] | join(" ")' <<<"$json")
  ready=$(jq '[.items[] | select((.status.conditions // []) | any(.type == "Ready" and .status == "True"))] | length' <<<"$json")
  want=$(expected_nodes "$hub")
  if ((n == 0)); then
    fail "$hub" "no node registered"
    return
  fi
  [[ -z $bad ]] || fail "$hub" "node not Ready: $bad"
  if ((ready < want)); then
    fail "$hub" "$ready of $want nodes Ready"
  elif [[ -z $bad ]]; then
    ok "$n node(s) Ready, the hub has $want"
  fi
}

# check_etcd: on a hub whose datastore is etcd (an HA hub), every node must be
# a joined etcd member (k0s's EtcdMember objects).
check_etcd() {
  local hub=$1 k=$2 json joined want
  [[ $(hub_datastore "$hub") == etcd ]] || return 0
  want=$(expected_nodes "$hub")
  if ! json=$(get_json "$k" etcdmembers.etcd.k0sproject.io); then
    fail "$hub" "cannot list etcd members (etcdmembers.etcd.k0sproject.io)"
    return
  fi
  jq -r '.items[] | "  etcd  \(.metadata.name)  \(.status.peerAddress // "?")  Joined=\((.status.conditions // [] | map(select(.type == "Joined"))[0].status) // "Unknown")"' <<<"$json"
  joined=$(jq "$ETCD_JOINED" <<<"$json")
  if ((joined < want)); then
    fail "$hub" "etcd has $joined of $want members joined"
  else
    ok "etcd: $joined members joined"
  fi
}

check_storage() {
  local hub=$1 k=$2 json defaults
  if ! json=$(get_json "$k" storageclasses); then
    fail "$hub" "cannot list StorageClasses"
    return
  fi
  jq -r '.items[] | "  sc    \(.metadata.name)  provisioner=\(.provisioner)  default=\(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] // "false")"' <<<"$json"
  defaults=$(jq -r '[.items[] | select(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true") | .metadata.name] | join(" ")' <<<"$json")
  if [[ -z $defaults ]]; then
    fail "$hub" "no default StorageClass"
  elif [[ $defaults == *" "* ]]; then
    fail "$hub" "more than one default StorageClass: $defaults"
  else
    ok "default StorageClass: $defaults"
  fi
}

check_cert_manager() {
  local hub=$1 k=$2 json d avail
  if ! json=$(get_json "$k" -n "$UAT_CERT_MANAGER_NAMESPACE" deployments); then
    fail "$hub" "cannot list Deployments in $UAT_CERT_MANAGER_NAMESPACE"
    return
  fi
  jq -r '.items[] | "  deploy \(.metadata.name)  ready=\(.status.readyReplicas // 0)/\(.spec.replicas // 0)"' <<<"$json"
  for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
    avail=$(jq -r --arg d "$d" '.items[] | select(.metadata.name == $d) | (.status.conditions // [] | map(select(.type == "Available"))[0].status) // "False"' <<<"$json")
    if [[ $avail == True ]]; then
      ok "cert-manager: $d Available"
    else
      fail "$hub" "cert-manager not available: $d ${avail:-missing}"
    fi
  done
}

check_issuer() {
  local hub=$1 k=$2 json ready
  if ! json=$(get_json "$k" clusterissuers); then
    fail "$hub" "cannot list ClusterIssuers (cert-manager CRDs missing?)"
    return
  fi
  ready=$(jq -r --arg n "$UAT_CLUSTER_ISSUER" '.items[] | select(.metadata.name == $n) | (.status.conditions // [] | map(select(.type == "Ready"))[0].status) // "Unknown"' <<<"$json")
  if [[ $ready == True ]]; then
    ok "ClusterIssuer $UAT_CLUSTER_ISSUER Ready"
  else
    fail "$hub" "ClusterIssuer $UAT_CLUSTER_ISSUER not Ready: ${ready:-missing}"
  fi
}

# check_dns: the hosts block bootstrap.sh set. In the hub's own cluster its
# FQDN maps to each of its nodes; the other hub's FQDN maps to that hub's
# api_address. For a single node both are its private_ip.
check_dns() {
  local hub=$1 k=$2 json corefile role ip fqdn ips
  [[ -n $ENDPOINTS ]] || return 0
  if ! json=$(get_json "$k" -n kube-system configmap coredns); then
    fail "$hub" "cannot read kube-system/coredns"
    return
  fi
  corefile=$(jq -r '.data.Corefile // ""' <<<"$json")
  for role in core dmz; do
    fqdn=$(jq -r ".$role.fqdn" "$ENDPOINTS")
    if [[ $role == "$hub" ]]; then
      ips=$(jq -r ".$role | (.node_private_ips // [.private_ip]) | .[]" "$ENDPOINTS")
    else
      ips=$(jq -r ".$role | .api_address // .private_ip" "$ENDPOINTS")
    fi
    for ip in $ips; do
      if grep -qE "^[[:space:]]*${ip//./\\.}[[:space:]]+${fqdn//./\\.}[[:space:]]*$" <<<"$corefile"; then
        ok "CoreDNS: $fqdn -> $ip"
      else
        fail "$hub" "CoreDNS does not map $fqdn to $ip"
      fi
    done
  done
}

check_node_ports() {
  local hub=$1 k=$2 json allowed bad shown
  if ! json=$(get_json "$k" services -A); then
    fail "$hub" "cannot list Services"
    return
  fi
  allowed=$(hub_allowed_node_ports "$hub" | jq -R 'select(length > 0) | tonumber' | jq -sc .)
  shown=$(hub_allowed_node_ports "$hub" | paste -sd' ' -)
  jq -r '.items[] | select(.spec.type == "NodePort" or .spec.type == "LoadBalancer")
    | .metadata as $m | .spec.type as $t
    | (if $t == "LoadBalancer" then "  external=\((.status.loadBalancer.ingress // []) | map(.ip // .hostname) | if length == 0 then "pending" else join(",") end)" else "" end) as $lb
    | .spec.ports[] | select(.nodePort)
    | "  svc   \($m.namespace)/\($m.name)  \($t)  \(.port) -> node port \(.nodePort)\($lb)"' <<<"$json"
  bad=$(jq -r --argjson allowed "$allowed" '[.items[] | .metadata as $m | (.spec.ports // [])[] | select(.nodePort and ((.nodePort as $p | $allowed | index($p)) | not)) | "\($m.namespace)/\($m.name):\(.nodePort)"] | join(" ")' <<<"$json")
  if [[ -n $bad ]]; then
    fail "$hub" "node ports outside the hub's exposed ports (${shown:-none}): $bad"
  else
    ok "node ports within ${shown:-none}"
  fi
}

check_host_ports() {
  local hub=$1 k=$2 json allowed bad shown
  if ! json=$(get_json "$k" pods -A); then
    fail "$hub" "cannot list Pods"
    return
  fi
  allowed=$(hub_allowed_host_ports "$hub" | jq -R 'select(length > 0) | tonumber' | jq -sc .)
  # Pods on the host network report hostPort for every port; they are k0s's
  # own (kube-router, kube-proxy) and not exposures, so they are left out.
  jq -r '.items[] | select(.spec.hostNetwork != true) | .metadata as $m | (.spec.nodeName // "?") as $node
    | [(.spec.containers // [])[] | (.ports // [])[] | select(.hostPort)][]
    | "  pod   \($m.namespace)/\($m.name)  node \($node)  hostPort \(.hostPort) -> \(.containerPort)"' <<<"$json"
  bad=$(jq -r --argjson allowed "$allowed" '[.items[] | select(.spec.hostNetwork != true) | .metadata as $m
    | (.spec.containers // [])[] | (.ports // [])[] | select(.hostPort and ((.hostPort as $p | $allowed | index($p)) | not))
    | "\($m.namespace)/\($m.name):\(.hostPort)"] | join(" ")' <<<"$json")
  shown=$(hub_allowed_host_ports "$hub" | paste -sd' ' -)
  if [[ -n $bad ]]; then
    fail "$hub" "hostPorts outside the hub's exposed ports (${shown:-none}): $bad"
  else
    ok "hostPorts within ${shown:-none}"
  fi
}

main() {
  need_cmd jq kubectl
  parse_args "$@"
  load_settings
  local hub k
  for hub in "${HUBS[@]}"; do
    k=${KUBECONFIG_OF[$hub]}
    printf '== %s hub (%s)\n' "$hub" "$k"
    check_nodes "$hub" "$k"
    check_etcd "$hub" "$k"
    check_storage "$hub" "$k"
    check_cert_manager "$hub" "$k"
    check_issuer "$hub" "$k"
    check_dns "$hub" "$k"
    check_node_ports "$hub" "$k"
    check_host_ports "$hub" "$k"
  done
  if ((${#FAILURES[@]})); then
    printf '\n%d check(s) failed:\n' "${#FAILURES[@]}"
    printf '  %s\n' "${FAILURES[@]}"
    exit 1
  fi
  printf '\nboth hubs pass\n'
}

main "$@"
