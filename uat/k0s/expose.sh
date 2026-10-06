#!/usr/bin/env bash
# uat/k0s/expose.sh: expose one port of a chart's Service on a UAT hub through
# a node port that is the port the network rules open (config.env).
#
# It adds a sibling Service, <service>-np, of type NodePort (the default) or
# LoadBalancer, with the same selector and only the chosen port; either type
# gets the pinned node port. The chart's own Service is not touched:
# no chart value or Helm drift, and its other ports (the bus websocket port,
# for one) get no node port. It refuses any node port the hub does not
# expose, so nothing else can be opened by mistake. Re-running it is safe.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<'EOF'
Usage: expose.sh --kubeconfig FILE --hub dmz|core --namespace NS --service NAME
                 --port NAME|NUMBER --node-port N [--local] [--name NAME]
                 [--type NodePort|LoadBalancer] [--lb-source-range CIDR]...

  --kubeconfig FILE  the hub's kubeconfig (bootstrap.sh writes OUT/<hub>.kubeconfig)
  --hub dmz|core     which hub; selects the node ports allowed (config.env)
  --namespace NS     the chart Service's namespace
  --service NAME     the chart Service whose selector and port are used
  --port NAME|NUMBER the Service port to expose, by name or port number
  --node-port N      the node port; must be one the hub exposes:
                       dmz:  UAT_DMZ_ENVOY_PORT, UAT_DMZ_BUS_PORT
                       core: UAT_CORE_HTTPS_PORT, UAT_CORE_FARMER_API_PORT
  --local            externalTrafficPolicy Local: keep the client's source
                     address (Envoy's rate limit and logs need it)
  --name NAME        the new Service's name (default: <service>-np)
  --type TYPE        NodePort (default) or LoadBalancer. A LoadBalancer Service
                     also gets the pinned node port; its external address
                     stays pending on k0s unless a load balancer controller
                     (or a gateway in front) provides one.
                     For Envoy, pass config.env's UAT_DMZ_ENVOY_SERVICE_TYPE.
  --lb-source-range CIDR
                     loadBalancerSourceRanges entry (LoadBalancer only;
                     repeatable)
  -h, --help         this text
EOF
}

usage_error() {
  printf '[uat-k0s] error: %s\n' "$*" >&2
  usage >&2
  exit 2
}

KUBECONFIG_FILE=""
HUB=""
NAMESPACE=""
SERVICE=""
PORT=""
NODE_PORT=""
NAME=""
LOCAL=0
TYPE=NodePort
LB_RANGES=()

dns_label() { [[ $1 =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }

parse_args() {
  while (($#)); do
    case $1 in
      --kubeconfig | --hub | --namespace | --service | --port | --node-port | --name | --type | --lb-source-range)
        (($# >= 2)) || usage_error "$1 needs a value"
        case $1 in
          --kubeconfig) KUBECONFIG_FILE=$2 ;;
          --hub) HUB=$2 ;;
          --namespace) NAMESPACE=$2 ;;
          --service) SERVICE=$2 ;;
          --port) PORT=$2 ;;
          --node-port) NODE_PORT=$2 ;;
          --name) NAME=$2 ;;
          --type) TYPE=$2 ;;
          --lb-source-range) LB_RANGES+=("$2") ;;
        esac
        shift 2
        ;;
      --local) LOCAL=1 && shift ;;
      -h | --help) usage && exit 0 ;;
      *) usage_error "unknown argument: $1" ;;
    esac
  done
  [[ -n $KUBECONFIG_FILE ]] || usage_error "--kubeconfig is required"
  [[ -r $KUBECONFIG_FILE ]] || usage_error "kubeconfig not readable: $KUBECONFIG_FILE"
  [[ $HUB == dmz || $HUB == core ]] || usage_error "--hub must be dmz or core"
  [[ $NAMESPACE =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || usage_error "bad --namespace: $NAMESPACE"
  dns_label "$SERVICE" || usage_error "bad --service: $SERVICE"
  [[ $PORT =~ ^([a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?|[1-9][0-9]{0,4})$ ]] || usage_error "bad --port: $PORT"
  is_port "$NODE_PORT" || usage_error "bad --node-port: $NODE_PORT"
  [[ -n $NAME ]] || NAME="$SERVICE-np"
  dns_label "$NAME" || usage_error "bad or too long NodePort Service name: $NAME (use --name)"
  [[ $NAME != "$SERVICE" ]] || usage_error "--name must differ from --service"
  [[ $TYPE == NodePort || $TYPE == LoadBalancer ]] || usage_error "--type must be NodePort or LoadBalancer"
  local c
  for c in "${LB_RANGES[@]}"; do
    [[ $TYPE == LoadBalancer ]] || usage_error "--lb-source-range needs --type LoadBalancer"
    if ! [[ $c =~ ^[0-9.]+/([0-9]|[12][0-9]|3[0-2])$ ]] || ! is_ipv4 "${c%/*}"; then
      usage_error "bad --lb-source-range: $c"
    fi
  done
}

main() {
  need_cmd jq kubectl
  parse_args "$@"
  load_settings

  if ! grep -qx -- "$NODE_PORT" < <(hub_allowed_node_ports "$HUB"); then
    die "node port $NODE_PORT is not one the $HUB hub exposes ($(hub_allowed_node_ports "$HUB" | paste -sd' ' -))"
  fi

  local src svc got ranges
  ranges=$(printf '%s\n' "${LB_RANGES[@]}" | jq -R 'select(length > 0)' | jq -sc .)
  src=$(kc "$KUBECONFIG_FILE" -n "$NAMESPACE" get service "$SERVICE" -o json) ||
    die "cannot read Service $NAMESPACE/$SERVICE"
  svc=$(jq -c --arg p "$PORT" --arg name "$NAME" --arg svc "$SERVICE" \
    --argjson np "$NODE_PORT" --argjson local "$LOCAL" --arg type "$TYPE" --argjson ranges "$ranges" '
      ([.spec.ports // [] | .[] | select(.name == $p or ((.port | tostring) == $p))]) as $m
      | if ($m | length) != 1 then error("port") else . end
      | if ((.spec.selector // {}) | length) == 0 then error("selector") else . end
      | {
          apiVersion: "v1",
          kind: "Service",
          metadata: {
            name: $name,
            namespace: .metadata.namespace,
            labels: {"app.kubernetes.io/part-of": "imas-uat",
                     "app.kubernetes.io/managed-by": "uat-k0s-expose"},
            annotations: {"imas-uat/exposes": "\($svc):\($p)"}
          },
          spec: ({
            type: $type,
            selector: .spec.selector,
            ports: [$m[0] | {name: (.name // "port"), protocol: (.protocol // "TCP"),
                             port: .port, targetPort: (.targetPort // .port),
                             nodePort: $np}]
          }
          + (if $local == 1 then {externalTrafficPolicy: "Local"} else {} end)
          + (if ($ranges | length) > 0 then {loadBalancerSourceRanges: $ranges} else {} end))
        }' <<<"$src" 2>/dev/null) ||
    die "Service $NAMESPACE/$SERVICE needs exactly one port named or numbered $PORT and a selector"

  log "$HUB: exposing $NAMESPACE/$SERVICE port $PORT on node port $NODE_PORT as $TYPE $NAMESPACE/$NAME"
  kc "$KUBECONFIG_FILE" -n "$NAMESPACE" apply -f - <<<"$svc" >&2 ||
    die "could not apply Service $NAMESPACE/$NAME"

  got=$(kc "$KUBECONFIG_FILE" -n "$NAMESPACE" get service "$NAME" -o json |
    jq -r '"\(.spec.type) \(.spec.ports | map(.nodePort) | join(","))"')
  [[ $got == "$TYPE $NODE_PORT" ]] || die "Service $NAMESPACE/$NAME reads back as '$got', not $TYPE $NODE_PORT"
  printf '%s/%s port %s -> node port %s (%s Service %s)\n' "$NAMESPACE" "$SERVICE" "$PORT" "$NODE_PORT" "$TYPE" "$NAME"
}

main "$@"
