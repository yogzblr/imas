#!/usr/bin/env bash
# uat/k0s/bootstrap.sh: install a single-node k0s cluster on each UAT hub
# (uat-dmz and uat-core, two separate clusters) and the add-ons the charts
# need, then set up the per-run UAT CA. See README.md.
#
# Every hub is reached only through its Azure Bastion tunnel on the runner, as
# access.json (uat/access/tunnels.sh open) describes: k0sctl over SSH on the
# tunnel's ssh_port, kubectl over the kube tunnel's kube_port. Nothing here
# calls Azure.
set -euo pipefail
umask 077

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<'EOF'
Usage: bootstrap.sh --uat FILE --access FILE --ssh-key FILE --out DIR
                    [--timeout SECONDS] [--render-only] [--skip-check]

  --uat FILE        the uat JSON (tofu output -json uat)
  --access FILE     access.json written by uat/access/tunnels.sh open
  --ssh-key FILE    the per-run SSH private key for the hubs' admin_user
  --out DIR         where to write (created if missing):
                      dmz.kubeconfig, core.kubeconfig   admin kubeconfigs (secret)
                      uat-ca.crt                         the UAT CA certificate
                      endpoints.json                     hub names, addresses, ports
                      k0sctl-dmz.yaml, k0sctl-core.yaml  rendered k0sctl files
                      known_hosts                        the hubs' SSH host keys
  --timeout SECONDS how long to wait for each node, rollout and issuer (900)
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
RENDER_ONLY=0
SKIP_CHECK=0

parse_args() {
  while (($#)); do
    case $1 in
      --uat | --access | --ssh-key | --out | --timeout)
        (($# >= 2)) || usage_error "$1 needs a value"
        case $1 in
          --uat) UAT_JSON=$2 ;;
          --access) ACCESS_JSON=$2 ;;
          --ssh-key) SSH_KEY=$2 ;;
          --out) OUT_DIR=$2 ;;
          --timeout) TIMEOUT=$2 ;;
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
  [[ $UAT_CA_SECRET =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "config.env: bad UAT_CA_SECRET"
  [[ $UAT_CA_DAYS =~ ^[1-9][0-9]*$ ]] || die "config.env: bad UAT_CA_DAYS"
}

# read_inputs fills the per-hub values from the uat JSON and access.json,
# checking each one.
declare -A NAME PRIV_IP PUB_IP FQDN ADMIN HOST SSH_PORT KUBE_PORT
RUN_ID=""
read_inputs() {
  RUN_ID=$(uat_get "$UAT_JSON" .run_id)
  is_run_id "$RUN_ID" || die "uat JSON: run_id must be 6 to 10 lowercase letters and digits: $RUN_ID"

  local hub v
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

    v=$(access_get "$ACCESS_JSON" "${NAME[$hub]}" host)
    is_ipv4 "$v" || is_fqdn "$v" || [[ $v == localhost ]] || die "access.json: bad host for ${NAME[$hub]}: $v"
    HOST[$hub]=$v
    SSH_PORT[$hub]=$(access_get "$ACCESS_JSON" "${NAME[$hub]}" ssh_port)
    is_port "${SSH_PORT[$hub]}" || die "access.json: bad ssh_port for ${NAME[$hub]}: ${SSH_PORT[$hub]}"
    KUBE_PORT[$hub]=$(access_get "$ACCESS_JSON" "${NAME[$hub]}" kube_port)
    is_port "${KUBE_PORT[$hub]}" || die "access.json: bad kube_port for ${NAME[$hub]}: ${KUBE_PORT[$hub]}"
  done
  [[ ${NAME[dmz]} != "${NAME[core]}" ]] || die "uat JSON: dmz and core have the same name"
}

cluster_name() { printf 'imas-uat-%s-%s\n' "$RUN_ID" "$1"; }

render_hub() {
  local hub=$1 extra_san=${HOST[$1]}
  # 127.0.0.1 is always in the SANs; a different tunnel host is added too.
  [[ $extra_san != 127.0.0.1 ]] || extra_san=localhost
  render_template "$K0S_DIR/templates/k0sctl.yaml.tmpl" "$OUT_DIR/k0sctl-$hub.yaml" \
    "CLUSTER_NAME=$(cluster_name "$hub")" \
    "ACCESS_HOST=${HOST[$hub]}" \
    "SSH_PORT=${SSH_PORT[$hub]}" \
    "ADMIN_USER=${ADMIN[$hub]}" \
    "SSH_KEY=$SSH_KEY" \
    "HOST_ALIAS=${NAME[$hub]}" \
    "KNOWN_HOSTS=$OUT_DIR/known_hosts" \
    "PRIVATE_IP=${PRIV_IP[$hub]}" \
    "FQDN=${FQDN[$hub]}" \
    "EXTRA_SAN=$extra_san" \
    "K0S_VERSION=$K0S_VERSION" \
    "KUBE_API_PORT=$UAT_KUBE_API_PORT" \
    "NODE_PORT_RANGE=$(hub_node_port_range "$hub")" \
    "CORE_PRIVATE_IP=${PRIV_IP[core]}" \
    "CORE_FQDN=${FQDN[core]}" \
    "DMZ_PRIVATE_IP=${PRIV_IP[dmz]}" \
    "DMZ_FQDN=${FQDN[dmz]}"
  chmod 600 "$OUT_DIR/k0sctl-$hub.yaml"
  log "rendered $OUT_DIR/k0sctl-$hub.yaml"
}

# write_endpoints writes the hubs' names, addresses and exposed ports for the
# hub scripts and the tests: the uat JSON's dmz and core objects plus ports
# (the keys uat/hub/dmz reads: dmz.ports.envoy, dmz.ports.bus,
# core.ports.farmer_api, cluster_issuer).
write_endpoints() {
  jq -n \
    --arg run_id "$RUN_ID" \
    --arg dn "${NAME[dmz]}" --arg dp "${PRIV_IP[dmz]}" --arg dq "${PUB_IP[dmz]}" --arg df "${FQDN[dmz]}" \
    --arg cn "${NAME[core]}" --arg cp "${PRIV_IP[core]}" --arg cq "${PUB_IP[core]}" --arg cf "${FQDN[core]}" \
    --argjson envoy "$UAT_DMZ_ENVOY_PORT" --argjson bus "$UAT_DMZ_BUS_PORT" \
    --argjson https "$UAT_CORE_HTTPS_PORT" --argjson api "$UAT_CORE_FARMER_API_PORT" \
    --arg drange "$UAT_DMZ_NODE_PORT_RANGE" --arg crange "$UAT_CORE_NODE_PORT_RANGE" \
    --arg issuer "$UAT_CLUSTER_ISSUER" \
    --arg k0s "$K0S_VERSION" '
    {
      run_id: $run_id,
      dmz: {name: $dn, private_ip: $dp, public_ip: $dq, fqdn: $df,
            ports: {envoy: $envoy, bus: $bus},
            exposure: "node ports, Services owned by uat/hub/dmz",
            node_port_range: $drange},
      core: {name: $cn, private_ip: $cp, public_ip: $cq, fqdn: $cf,
             ports: {https: $https, farmer_api: $api},
             # Exactly "hostPort": uat/hub/core/lib/common.sh accepts
             # nothing else (owner decision, 2026-10-06: no core node ports).
             exposure: "hostPort",
             node_port_range: $crange},
      cluster_issuer: $issuer,
      ca_file: "uat-ca.crt",
      kubeconfigs: {dmz: "dmz.kubeconfig", core: "core.kubeconfig"},
      k0s_version: $k0s
    }' >"$OUT_DIR/endpoints.json"
  chmod 644 "$OUT_DIR/endpoints.json"
  log "wrote $OUT_DIR/endpoints.json"
}

check_k0sctl_version() {
  local have
  have=$(k0sctl version 2>/dev/null | awk '$1 == "version:" {print $2; exit}')
  [[ $have == "$K0SCTL_VERSION" ]] ||
    die "k0sctl ${have:-unknown} found, versions.env pins $K0SCTL_VERSION (uat/k0s/install-tools.sh installs it)"
}

kubeconfig_of() { printf '%s/%s.kubeconfig\n' "$OUT_DIR" "$1"; }

wait_node_ready() {
  local hub=$1 k deadline n
  k=$(kubeconfig_of "$hub")
  deadline=$((SECONDS + TIMEOUT))
  until n=$(kc "$k" get nodes -o json 2>/dev/null | jq '.items | length') && ((n > 0)); do
    ((SECONDS < deadline)) || die "$hub: no node registered within ${TIMEOUT}s"
    sleep 5
  done
  kc "$k" wait --for=condition=Ready node --all --timeout="$((deadline - SECONDS > 0 ? deadline - SECONDS : 1))s" >&2 ||
    die "$hub: node not Ready within ${TIMEOUT}s"
  log "$hub: node Ready"
}

install_cluster() {
  local hub=$1 cfg="$OUT_DIR/k0sctl-$1.yaml" tmp
  log "$hub: installing k0s $K0S_VERSION on ${NAME[$hub]} through ${HOST[$hub]}:${SSH_PORT[$hub]}"
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
  wait_node_ready "$hub"
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
