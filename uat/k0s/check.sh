#!/usr/bin/env bash
# uat/k0s/check.sh: print the state of both UAT hub clusters and fail if
# either is not fit for the hub charts. It fails when:
#   - a node is not Ready (or there is none),
#   - there is no default StorageClass,
#   - cert-manager is not available (its three Deployments),
#   - the UAT ClusterIssuer is not Ready,
#   - CoreDNS does not map the core FQDN (and the DMZ FQDN) to the private IP
#     (only with an endpoints file, which names them),
#   - a NodePort Service uses a node port the hub does not expose (config.env).
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
  --endpoints FILE        endpoints.json, for the CoreDNS check (overrides --out)
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

get_json() {
  local k=$1
  shift
  kc "$k" --request-timeout=30s get "$@" -o json 2>/dev/null
}

check_nodes() {
  local hub=$1 k=$2 json n bad
  if ! json=$(get_json "$k" nodes); then
    fail "$hub" "cannot list nodes (API unreachable through the kube tunnel?)"
    return
  fi
  jq -r '.items[] | "  node  \(.metadata.name)  Ready=\((.status.conditions // [] | map(select(.type == "Ready"))[0].status) // "Unknown")  \(.status.nodeInfo.kubeletVersion // "?")"' <<<"$json"
  n=$(jq '.items | length' <<<"$json")
  bad=$(jq -r '[.items[] | select(((.status.conditions // []) | map(select(.type == "Ready" and .status == "True")) | length) == 0) | .metadata.name] | join(" ")' <<<"$json")
  if ((n == 0)); then
    fail "$hub" "no node registered"
  elif [[ -n $bad ]]; then
    fail "$hub" "node not Ready: $bad"
  else
    ok "$n node(s) Ready"
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

check_dns() {
  local hub=$1 k=$2 json corefile role ip fqdn
  [[ -n $ENDPOINTS ]] || return 0
  if ! json=$(get_json "$k" -n kube-system configmap coredns); then
    fail "$hub" "cannot read kube-system/coredns"
    return
  fi
  corefile=$(jq -r '.data.Corefile // ""' <<<"$json")
  for role in core dmz; do
    ip=$(jq -r ".$role.private_ip" "$ENDPOINTS")
    fqdn=$(jq -r ".$role.fqdn" "$ENDPOINTS")
    if grep -qE "^[[:space:]]*${ip//./\\.}[[:space:]]+${fqdn//./\\.}[[:space:]]*$" <<<"$corefile"; then
      ok "CoreDNS: $fqdn -> $ip"
    else
      fail "$hub" "CoreDNS does not map $fqdn to $ip"
    fi
  done
}

check_node_ports() {
  local hub=$1 k=$2 json allowed bad
  if ! json=$(get_json "$k" services -A); then
    fail "$hub" "cannot list Services"
    return
  fi
  allowed=$(hub_allowed_node_ports "$hub" | jq -R 'tonumber' | jq -sc .)
  jq -r '.items[] | select(.spec.type == "NodePort" or .spec.type == "LoadBalancer") | .metadata as $m | .spec.ports[] | select(.nodePort) | "  svc   \($m.namespace)/\($m.name)  \(.port) -> node port \(.nodePort)"' <<<"$json"
  bad=$(jq -r --argjson allowed "$allowed" '[.items[] | .metadata as $m | (.spec.ports // [])[] | select(.nodePort and ((.nodePort as $p | $allowed | index($p)) | not)) | "\($m.namespace)/\($m.name):\(.nodePort)"] | join(" ")' <<<"$json")
  if [[ -n $bad ]]; then
    fail "$hub" "node ports outside the hub's exposed ports ($(hub_allowed_node_ports "$hub" | paste -sd' ' -)): $bad"
  else
    ok "node ports within $(hub_allowed_node_ports "$hub" | paste -sd' ' -)"
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
    check_storage "$hub" "$k"
    check_cert_manager "$hub" "$k"
    check_issuer "$hub" "$k"
    check_dns "$hub" "$k"
    check_node_ports "$hub" "$k"
  done
  if ((${#FAILURES[@]})); then
    printf '\n%d check(s) failed:\n' "${#FAILURES[@]}"
    printf '  %s\n' "${FAILURES[@]}"
    exit 1
  fi
  printf '\nboth hubs pass\n'
}

main "$@"
