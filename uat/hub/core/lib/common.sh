# shellcheck shell=bash
# Constants and derived values here are used by the scripts that source it.
# shellcheck disable=SC2034
# Shared by the uat/hub/core scripts. Source it; it defines functions and
# constants and runs nothing. Everything here is UAT only.
#
# FLAG FOR SECURITY REVIEW: this file decides where generated secrets are
# written (sensitive_dir, mode 0700, files 0600) and how they reach the
# cluster (kubectl apply of Secrets built from files, never from argv).
#
# Inputs every script takes, in this order:
#   <kubeconfig>  path to the core cluster's kubeconfig
#   <endpoints>   endpoints JSON (README.md, "The endpoints file")
#   <state-dir>   per-run directory this brief writes under (state_root)
# Nothing in here calls Azure: the same scripts run on UAT.8's local rig.

# --- names (one place; core_test.go checks values/farmer-uat.yaml agrees) ---
CORE_NS=imas-core                 # farmer chart namespace
CORE_RELEASE=imas-core            # farmer chart release name
UAT_NS=imas-uat                   # MinIO, Keycloak, the edge proxy
EXTRAS_RELEASE=imas-uat-core      # release of uat/hub/core/chart
FARMER_FULLNAME=imas-core-farmer  # chart fullname for release imas-core
SAASAPI_FULLNAME=imas-core-farmer-saasapi
OPENBAO_STS=imas-core-openbao
OPENBAO_POD=imas-core-openbao-0
PXC_CLUSTER=imas-core-pxc         # StatefulSets <cluster>-pxc, <cluster>-haproxy
PXC_ROOT_SECRET=imas-core-pxc-secrets
VALKEY_DEPLOY=imas-core-valkey
SEEDS_SECRET=imas-farmer-nats-seeds
INTERNAL_AUTH_SECRET=imas-saasapi-internal-auth
SAASAPI_NATS_SECRET=imas-saasapi-nats
SAASAPI_BOX_SECRET=imas-saasapi-box
OPENBAO_ROOT_SECRET=imas-uat-openbao-root     # openbaoBootstrap.tokenSecretName
OPENBAO_UNSEAL_SECRET=imas-uat-openbao-unseal # UAT ONLY: unseal keys in a Secret
S3_FARMER_SECRET=imas-uat-s3-farmer           # objectStore.credentialsSecret
S3_SAASAPI_SECRET=imas-uat-s3-saasapi         # saasapi.recipes.credentialsSecret
MINIO_ROOT_SECRET=imas-uat-minio-root
KEYCLOAK_ADMIN_SECRET=imas-uat-keycloak-admin
KEYCLOAK_REALM_SECRET=imas-uat-keycloak-realm
UAT_CA_CONFIGMAP=imas-uat-ca
FARMER_TLS_SECRET=imas-farmer-tls             # tls.secretName
MINIO_SVC=imas-uat-minio
KEYCLOAK_DEPLOY=imas-uat-keycloak
EDGE_DEPLOY=imas-uat-edge
RECIPE_BUCKET=imas-recipes                    # objectStore.bucket
JOB_BUCKET=imas-jobs                          # objectStore.jobBucket
S3_FARMER_USER=imas-farmer
S3_SAASAPI_USER=imas-saasapi
REALM=imas-uat
SAASAPI_AUDIENCE=imas-saasapi                 # saasapi.jwt.audience
TESTS_CLIENT=imas-uat-tests
OTHER_CLIENT=imas-uat-other-audience        # tokens without saasapi's audience (X1)
TENANT_ATTRIBUTE=organization_id              # user attribute mapped to organization.id
READ_ROLE=imas-recipes-read                   # saasapi.recipes.readRole
WRITE_ROLE=imas-recipes-write                 # saasapi.recipes.writeRole
UAT_USERS=(t1-admin t1-reader t2-admin t2-reader)
BOOTSTRAP_ADMIN_NAME=uat-admin
GATEWAY_KEY=imas-gateway-jwt                  # farmer.openbao.gateway.keyName
REPO_OWNER=yogzblr
REPO_NAME=imas

# Where the published farmer chart comes from (README.md, "Release
# inputs"). A public Buildkite Helm registry: no credentials.
IMAS_HELM_REPO_URL="${IMAS_HELM_REPO_URL:-https://packages.buildkite.com/yogzblr/imashelm/helm}"
IMAS_RELEASE_BASE_URL="${IMAS_RELEASE_BASE_URL:-https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download}"

log() { printf '[uat/hub/core] %s\n' "$*" >&2; }
die() { printf '[uat/hub/core] ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
	local c
	for c in "$@"; do
		command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
	done
}

# parse_common_args <script-usage> <kubeconfig> <endpoints> <state-dir>
# Sets KUBECONFIG_PATH, ENDPOINTS, STATE_ROOT and the derived dirs.
parse_common_args() {
	local usage="$1"
	shift
	[[ $# -ge 3 ]] || die "usage: $usage"
	KUBECONFIG_PATH="$1"
	ENDPOINTS="$2"
	STATE_ROOT="$3"
	[[ -f "$KUBECONFIG_PATH" ]] || die "kubeconfig not found: $KUBECONFIG_PATH"
	[[ -f "$ENDPOINTS" ]] || die "endpoints file not found: $ENDPOINTS"
	jq -e 'type == "object"' "$ENDPOINTS" >/dev/null 2>&1 || die "endpoints file is not a JSON object: $ENDPOINTS"
	mkdir -p "$STATE_ROOT"
	STATE_ROOT=$(cd "$STATE_ROOT" && pwd)
	KUBECONFIG_PATH=$(cd "$(dirname "$KUBECONFIG_PATH")" && pwd)/$(basename "$KUBECONFIG_PATH")
	ENDPOINTS=$(cd "$(dirname "$ENDPOINTS")" && pwd)/$(basename "$ENDPOINTS")
	STATE_DIR="$STATE_ROOT/core"
	OUT_DIR="$STATE_DIR/out"
	SENSITIVE_DIR="$STATE_DIR/sensitive"
	mkdir -p "$STATE_DIR" "$OUT_DIR"
	(umask 077 && mkdir -p "$SENSITIVE_DIR")
	chmod 700 "$SENSITIVE_DIR"
	SEEDS_DIR="${UAT_SEEDS_DIR:-$SENSITIVE_DIR/seeds}"
	load_endpoints
}

# ep <jq path> [default]: a string from the endpoints file.
ep() {
	local v
	v=$(jq -r "($1) // empty | tostring" "$ENDPOINTS")
	if [[ -z "$v" ]]; then
		[[ $# -ge 2 ]] || die "endpoints file has no $1"
		v="$2"
	fi
	printf '%s' "$v"
}

valid_fqdn() { [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }
valid_ipv4() {
	[[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	local i
	for i in 1 2 3 4; do ((BASH_REMATCH[i] <= 255)) || return 1; done
}
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (($1 >= 1 && $1 <= 65535)); }
valid_dns_label() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }

# load_endpoints: reads and validates every field this brief uses. The
# required ones are the contract's hub fields (tofu output uat shape);
# the rest have defaults and are documented in README.md.
load_endpoints() {
	CORE_FQDN=$(ep '.core.fqdn')
	CORE_IP=$(ep '.core.private_ip')
	DMZ_FQDN=$(ep '.dmz.fqdn')
	DMZ_IP=$(ep '.dmz.private_ip')
	CORE_HTTPS_PORT=$(ep '.core.ports.https' 443)
	CORE_FARMER_PORT=$(ep '.core.ports.farmer_api' 5405)
	CORE_EXPOSURE=$(ep '.core.exposure' hostPort)
	DMZ_ENVOY_PORT=$(ep '.dmz.ports.envoy' 8443)
	DMZ_BUS_PORT=$(ep '.dmz.ports.bus' 8442)
	BUS_SERVICE=$(ep '.dmz.bus_service' imas-dmz-nats-bus)
	BUS_NAMESPACE=$(ep '.dmz.bus_namespace' imas-dmz)
	CA_ISSUER=$(ep '.ca.cluster_issuer' imas-uat-ca)
	CLUSTER_DOMAIN=$(ep '.cluster_domain' cluster.local)

	valid_fqdn "$CORE_FQDN" || die "core.fqdn is not a DNS name: $CORE_FQDN"
	valid_fqdn "$DMZ_FQDN" || die "dmz.fqdn is not a DNS name: $DMZ_FQDN"
	valid_ipv4 "$CORE_IP" || die "core.private_ip is not an IPv4 address: $CORE_IP"
	valid_ipv4 "$DMZ_IP" || die "dmz.private_ip is not an IPv4 address: $DMZ_IP"
	local p
	for p in "$CORE_HTTPS_PORT" "$CORE_FARMER_PORT" "$DMZ_ENVOY_PORT" "$DMZ_BUS_PORT"; do
		valid_port "$p" || die "not a port: $p"
	done
	[[ "$CORE_EXPOSURE" == hostPort || "$CORE_EXPOSURE" == nodePort ]] ||
		die "core.exposure must be hostPort or nodePort, not $CORE_EXPOSURE"
	valid_dns_label "$BUS_SERVICE" || die "dmz.bus_service is not a DNS label: $BUS_SERVICE"
	valid_dns_label "$BUS_NAMESPACE" || die "dmz.bus_namespace is not a DNS label: $BUS_NAMESPACE"
	valid_dns_label "$CA_ISSUER" || die "ca.cluster_issuer is not a valid name: $CA_ISSUER"
	valid_fqdn "$CLUSTER_DOMAIN" || die "cluster_domain is not a DNS name: $CLUSTER_DOMAIN"

	# The contract: the Keycloak issuer, SAASAPI_KEYCLOAK_JWKS_URL and the
	# token iss are built on the core FQDN, as one string.
	CORE_BASE_URL="https://$CORE_FQDN"
	[[ "$CORE_HTTPS_PORT" == 443 ]] || CORE_BASE_URL="$CORE_BASE_URL:$CORE_HTTPS_PORT"
	KEYCLOAK_ISSUER="$CORE_BASE_URL/realms/$REALM"
	KEYCLOAK_JWKS_URL="$KEYCLOAK_ISSUER/protocol/openid-connect/certs"
	KEYCLOAK_TOKEN_URL="$KEYCLOAK_ISSUER/protocol/openid-connect/token"
	SAASAPI_URL="$CORE_BASE_URL"
	SPROUT_BUS_URL="wss://$DMZ_FQDN:$DMZ_ENVOY_PORT/"
}

# extras_set_args: the --set flags (one per line) that give uat/hub/core/chart
# this run's endpoints. install.sh passes them; core_test.go renders the
# chart with them.
extras_set_args() {
	printf '%s\n' \
		--set-string "core.fqdn=$CORE_FQDN" \
		--set-string "core.privateIP=$CORE_IP" \
		--set-string "core.exposure=$CORE_EXPOSURE" \
		--set "core.httpsPort=$CORE_HTTPS_PORT" \
		--set "core.farmerAPIPort=$CORE_FARMER_PORT" \
		--set-string "dmz.privateIP=$DMZ_IP" \
		--set-string "bus.serviceName=$BUS_SERVICE" \
		--set-string "bus.namespace=$BUS_NAMESPACE" \
		--set "bus.remotePort=$DMZ_BUS_PORT" \
		--set-string "caIssuer.name=$CA_ISSUER" \
		--set-string "clusterDomain=$CLUSTER_DOMAIN"
}

# release_version <tag>: vX.Y.Z or vX.Y.Z-rc.N (the contract) -> X.Y.Z[-rc.N].
release_version() {
	[[ "$1" =~ ^v([0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)$ ]] ||
		die "release_tag must be vX.Y.Z or vX.Y.Z-rc.N (never latest), got: $1"
	printf '%s' "${BASH_REMATCH[1]}"
}

kc() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }
hc() { helm --kubeconfig "$KUBECONFIG_PATH" "$@"; }

# gen_secret_file <path> [hex bytes]: writes a random hex string (mode 0600)
# unless the file already exists, so a re-run keeps what the cluster has.
gen_secret_file() {
	local path="$1" bytes="${2:-24}"
	[[ -s "$path" ]] && return 0
	(umask 077 && openssl rand -hex "$bytes" | tr -d '\n' >"$path")
}

# apply_secret <ns> <name> <key>=<file> ...: creates or updates a generic
# Secret from files. Values never pass through argv or the log.
apply_secret() {
	local ns="$1" name="$2"
	shift 2
	local args=() kv
	for kv in "$@"; do
		[[ -f "${kv#*=}" ]] || die "apply_secret $ns/$name: missing file for ${kv%%=*}"
		args+=("--from-file=$kv")
	done
	kc -n "$ns" create secret generic "$name" "${args[@]}" --dry-run=client -o yaml |
		kc apply -f - >/dev/null
	log "secret $ns/$name applied (${#args[@]} key(s))"
}

ensure_ns() {
	local ns
	for ns in "$@"; do
		kc create namespace "$ns" --dry-run=client -o yaml | kc apply -f - >/dev/null
	done
}

# wait_for <seconds> <description> <command...>: polls until it succeeds.
wait_for() {
	local timeout="$1" what="$2"
	shift 2
	local start=$SECONDS
	until "$@" >/dev/null 2>&1; do
		((SECONDS - start < timeout)) || die "timed out after ${timeout}s waiting for $what"
		sleep 5
	done
	log "ready: $what"
}

# rollout <kind/name> <ns> [timeout]
rollout() {
	kc -n "$2" rollout status "$1" --timeout="${3:-600s}" >&2 ||
		die "$1 in $2 did not become ready"
}

# sts_ready <name> <ns>: every replica of a StatefulSet is Ready. (kubectl
# rollout status refuses OnDelete StatefulSets, which OpenBao's and the
# Percona operator's are.)
sts_ready() {
	kc -n "$2" get statefulset "$1" -o json |
		jq -e '(.spec.replicas // 0) > 0 and (.status.readyReplicas // 0) == .spec.replicas' >/dev/null
}

# pxc_ready <cluster> <ns>: the PerconaXtraDBCluster reports state ready.
pxc_ready() {
	[[ "$(kc -n "$2" get perconaxtradbcluster "$1" -o jsonpath='{.status.state}')" == ready ]]
}

# write_keycloak_json <keycloak creds dir> <out file>: the sensitive
# keycloak.json uat/tests and uat/enroll read. Keeps tenant_ids already
# bound in <out file>; bind-tenant.sh adds them.
write_keycloak_json() {
	local prev_kc_tenants
	prev_kc_tenants=$(jq -c '[.tenants // {} | to_entries[] | select(.value.tenant_id) | {key, value: .value.tenant_id}] | from_entries' \
		"$2" 2>/dev/null || echo '{}')
	(umask 077 && jq -n --arg issuer "$KEYCLOAK_ISSUER" --arg client "$TESTS_CLIENT" --arg other "$OTHER_CLIENT" \
		--arg attr "$TENANT_ATTRIBUTE" --argjson bound "$prev_kc_tenants" \
		--rawfile cs "$1/tests-client-secret" --rawfile os "$1/other-client-secret" \
		--rawfile p1 "$1/t1-admin.password" --rawfile p2 "$1/t1-reader.password" \
		--rawfile p3 "$1/t2-admin.password" --rawfile p4 "$1/t2-reader.password" '
		def tenant($n; $a; $ap; $r; $rp):
		  {admin: {username: $a, password: $ap}, readonly: {username: $r, password: $rp}}
		  + (if $bound[$n] then {tenant_id: $bound[$n]} else {} end);
		{
		  issuer: $issuer, client_id: $client, client_secret: $cs, tenant_attribute: $attr,
		  other_audience_client: {client_id: $other, client_secret: $os},
		  tenants: {
		    "1": tenant("1"; "t1-admin"; $p1; "t1-reader"; $p2),
		    "2": tenant("2"; "t2-admin"; $p3; "t2-reader"; $p4)
		  }
		}' >"$2")
}

# jwt_payload <token>: the decoded payload JSON (no verification; the
# check script uses it to compare claims, saasapi does the verifying).
jwt_payload() {
	local p
	p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
	case $((${#p} % 4)) in
	2) p="$p==" ;;
	3) p="$p=" ;;
	esac
	printf '%s' "$p" | base64 -d 2>/dev/null
}
