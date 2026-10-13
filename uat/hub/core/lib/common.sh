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
UAT_NS=imas-uat                   # RustFS, Keycloak, the edge proxy
EXTRAS_RELEASE=imas-uat-core      # release of uat/hub/core/chart
FARMER_FULLNAME=imas-core-farmer  # chart fullname for release imas-core
SAASAPI_FULLNAME=imas-core-farmer-saasapi
OPENBAO_STS=imas-core-openbao
OPENBAO_POD=imas-core-openbao-0   # the only pod, or the HA run's first raft node (init runs here)
OPENBAO_INTERNAL_SVC=imas-core-openbao-internal # the subchart's headless Service (raft peers' names)
PXC_CLUSTER=imas-core-pxc         # StatefulSets <cluster>-pxc, <cluster>-haproxy
PXC_ROOT_SECRET=imas-core-pxc-secrets
VALKEY_NAME=imas-core-valkey      # a Deployment (single node) or, replicated, a StatefulSet whose pod 0 is the primary
SEEDS_SECRET=imas-farmer-nats-seeds        # natsSeeds.secretName: SYS_USER, SAASAPI_USER
FARMER_NKEY_SECRET=imas-farmer-nkey         # farmer.nkeySecret.secretName (the chart default)
FARMER_NKEY_KEY=farmer.nk                    # farmer.nkeySecret.key (the chart default)
LOADER_SEED_FILE=bus-loader-user.nk          # the DMZ bus loader's SYS user seed: a file in SEEDS_DIR, never a core Secret
LOADER_PUB_FILE=bus-loader-user.pub          # its public key in OUT_DIR: natsTrust.busLoaderUserPub (gen-values.sh)
FENCE_SEED_FILE=bus-fence-user.nk            # a clustered DMZ bus's fence user seed (HA run): a file in SEEDS_DIR, never a core Secret
FENCE_PUB_FILE=bus-fence-user.pub            # its public key in OUT_DIR: natsTrust.busFenceUserPub (gen-values.sh)
NATS_TRUST_CONFIGMAP=imas-nats-trust          # natsTrust.configMapName (public; the DMZ copies it)
INTERNAL_AUTH_SECRET=imas-saasapi-internal-auth
SAASAPI_NATS_SECRET=imas-saasapi-nats
SAASAPI_BOX_SECRET=imas-saasapi-box
SAASAPI_OPERATOR_FULLNAME=imas-core-farmer-saasapi-operator  # saasapi's operator Service (<saasapi fullname>-operator)
SAASAPI_OPERATOR_PORT=8443                    # saasapi.operator.port (the chart default)
OPERATOR_TLS_SECRET=imas-saasapi-operator-tls # saasapi.operator.tls.secretName: cert-manager, from the UAT CA (chart/)
OPERATOR_TOKEN_SECRET=imas-saasapi-operator-token # saasapi.operator.token.secretName (key current; saasapi-secrets.sh)
OPERATOR_TOKEN_FILE=saasapi-operator-token    # its copy in SENSITIVE_DIR (finish.sh, operator-release.sh)
SPROUT_RELEASE_CONFIGMAP=imas-core-farmer-sprout-release # the registration hook's request body (request.json)
OPENBAO_ROOT_SECRET=imas-uat-openbao-root     # openbaoBootstrap.tokenSecretName (a per-run bootstrap token, not the root token)
OPENBAO_UNSEAL_SECRET=imas-uat-openbao-unseal # UAT ONLY: unseal (HA: recovery) keys and root token in a Secret
OPENBAO_SEAL_SECRET=imas-uat-openbao-seal     # UAT ONLY, HA run: the static seal key every OpenBao pod unseals itself with
OPENBAO_SEAL_KEY_ID=imas-uat-1                # its key ID (seal "static" current_key_id, values/values-ha.yaml)
S3_FARMER_SECRET=imas-uat-s3-farmer           # objectStore.credentialsSecret
S3_SAASAPI_SECRET=imas-uat-s3-saasapi         # saasapi.recipes.credentialsSecret
S3_ACCOUNTS_READER_SECRET=imas-uat-s3-accounts-reader # versity.accountsReader.credentialsSecret (HA run; the DMZ holds the same pair)
VERSITY_FULLNAME=imas-core-farmer-versity     # the farmer chart's Versity Gateway Deployment and Service (versity.enabled, HA run)
VERSITY_PORT=7070                             # versity.port (the chart default)
VERSITY_AZURE_SECRET=imas-uat-versity-azure   # versity.azure.credentialsSecret: account-name, account-key (uat/tofu object_store)
VERSITY_ROOT_SECRET=imas-uat-versity-root     # versity.rootCredentials.secretName (generated per run)
RUSTFS_ROOT_SECRET=imas-uat-rustfs-root
KEYCLOAK_ADMIN_SECRET=imas-uat-keycloak-admin
KEYCLOAK_REALM_SECRET=imas-uat-keycloak-realm
UAT_CA_CONFIGMAP=imas-uat-ca
FARMER_TLS_SECRET=imas-farmer-tls             # tls.secretName
RUSTFS_SVC=imas-uat-rustfs
KEYCLOAK_DEPLOY=imas-uat-keycloak
EDGE_DEPLOY=imas-uat-edge
RECIPE_BUCKET=imas-recipes                    # objectStore.bucket
JOB_BUCKET=imas-jobs                          # objectStore.jobBucket
SPROUT_JWT_BUCKET=imas-sprout-jwts            # objectStore.sproutJWTBucket
ACCOUNTS_BUCKET=imas-accounts                 # accountStore.bucket (the farmer and nats chart default)
S3_ACCOUNTS_WRITER_SECRET=imas-farmer-accounts-writer # accountStore.credentialsSecret (the chart default)
S3_FARMER_USER=imas-farmer                    # the S3 users' access key IDs (RustFS and Versity Gateway alike)
S3_SAASAPI_USER=imas-saasapi
S3_ACCOUNTS_WRITER_USER=imas-farmer-accounts  # the accounts bucket's writer (farmer's accountStore)
S3_ACCOUNTS_READER_USER=imas-bus-accounts-reader # ... and its reader (the DMZ bus's loader)
VERSITY_ROOT_USER=imas-uat-versity-root       # Versity Gateway's root access key ID (HA run)
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
# inputs"): OCI charts on GHCR, pulled anonymously (the owner makes each
# chart package public once). docs/RELEASING.md. Replaces IMAS_HELM_REPO_URL
# and the Buildkite imashelm registry.
IMAS_HELM_OCI_BASE="${IMAS_HELM_OCI_BASE:-oci://ghcr.io/yogzblr/charts}"
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
	# The private names of the Shared contract (UAT.1's Azure Private DNS
	# zone, owner decision 2026-10-06); overridable for the local rig.
	# uat/hub/dmz spells them as the zone (private_dns_zone: dmz.<zone>,
	# core.<zone>); both forms are read, an explicit *.private_fqdn first.
	PRIVATE_ZONE=$(ep '.private_dns_zone' uat.imas.internal)
	CORE_PRIVATE_FQDN=$(ep '.core.private_fqdn' "core.$PRIVATE_ZONE")
	DMZ_PRIVATE_FQDN=$(ep '.dmz.private_fqdn' "dmz.$PRIVATE_ZONE")
	CORE_EXPOSURE=$(ep '.core.exposure' hostPort)
	DMZ_ENVOY_PORT=$(ep '.dmz.ports.envoy' 8443)
	DMZ_BUS_PORT=$(ep '.dmz.ports.bus' 8442)
	# uat/hub/dmz spells the issuer cluster_issuer; both forms are read.
	CA_ISSUER=$(ep '(.ca? | objects | .cluster_issuer) // .cluster_issuer' imas-uat-ca)
	CLUSTER_DOMAIN=$(ep '.cluster_domain' cluster.local)
	# The S3 object store farmer and saasapi use. "rustfs" (default): the
	# chart deploys RustFS in imas-uat and rustfs-setup.sh provisions it.
	# "external": an S3 endpoint you run (e.g. Versity Gateway in front of
	# Azure Blob); nothing is deployed or provisioned, see README.md.
	S3_MODE=$(ep '.object_store.mode' rustfs)
	S3_ENDPOINT=$(ep '.object_store.endpoint' "$RUSTFS_SVC.$UAT_NS.svc.cluster.local:9000")
	S3_USE_SSL=$(ep '.object_store.use_ssl' false)
	S3_EGRESS_CIDRS=$(jq -c '(.object_store.egress_cidrs // [])' "$ENDPOINTS")

	# The hubs' layout (uat/k0s endpoints.json, from tofu's uat output):
	# every node's private address, and the hub's private address, which
	# <hub>.<private_dns_zone> resolves to (api_address: the node's own on a
	# single node, the internal load balancer's on an HA hub). Traffic the
	# other hub sends arrives from one of its nodes' addresses; traffic sent to
	# the other hub goes to its private address. A file without the fields
	# (one node, written before P24) means one node at private_ip.
	CORE_NODE_IPS=$(jq -c '(.core.node_private_ips // [.core.private_ip]) | map(tostring)' "$ENDPOINTS")
	DMZ_NODE_IPS=$(jq -c '(.dmz.node_private_ips // [.dmz.private_ip]) | map(tostring)' "$ENDPOINTS")
	CORE_NODE_COUNT=$(jq -r '((.core.nodes // .core.node_names // [.core.name]) | length)' "$ENDPOINTS")
	DMZ_NODE_COUNT=$(jq -r '((.dmz.nodes // .dmz.node_names // [.dmz.name]) | length)' "$ENDPOINTS")
	CORE_ADDR=$(ep '.core.api_address' "$CORE_IP")
	DMZ_ADDR=$(ep '.dmz.api_address' "$DMZ_IP")
	# The accounts store's port on the core hub's private address (the DMZ
	# bus's loader reads the accounts bucket there; uat/tofu
	# accounts_store_port).
	CORE_ACCOUNTS_STORE_PORT=$(ep '.core.ports.accounts_store' 9000)

	valid_fqdn "$CORE_FQDN" || die "core.fqdn is not a DNS name: $CORE_FQDN"
	valid_fqdn "$DMZ_FQDN" || die "dmz.fqdn is not a DNS name: $DMZ_FQDN"
	valid_ipv4 "$CORE_IP" || die "core.private_ip is not an IPv4 address: $CORE_IP"
	valid_ipv4 "$DMZ_IP" || die "dmz.private_ip is not an IPv4 address: $DMZ_IP"
	local n
	for n in "$CORE_NODE_COUNT" "$DMZ_NODE_COUNT"; do
		[[ "$n" == 1 || "$n" == 3 || "$n" == 5 ]] || die "a hub has 1, 3 or 5 nodes (uat/tofu), the endpoints file says $n"
	done
	[[ "$(jq -r 'length' <<<"$CORE_NODE_IPS")" == "$CORE_NODE_COUNT" ]] || die "core.node_private_ips does not list every core node"
	[[ "$(jq -r 'length' <<<"$DMZ_NODE_IPS")" == "$DMZ_NODE_COUNT" ]] || die "dmz.node_private_ips does not list every DMZ node"
	local ip
	for ip in $(jq -r '.[]' <<<"$CORE_NODE_IPS") $(jq -r '.[]' <<<"$DMZ_NODE_IPS") "$CORE_ADDR" "$DMZ_ADDR"; do
		valid_ipv4 "$ip" || die "a hub node or API address is not an IPv4 address: $ip"
	done
	# HA_CORE: the core hub has several nodes, so install.sh adds the HA
	# overlay (values/values-ha.yaml) and the object store is Versity Gateway
	# in front of the run's Azure Blob account (design D18; brief H4).
	HA_CORE=false
	((CORE_NODE_COUNT > 1)) && HA_CORE=true
	if [[ $HA_CORE == true ]]; then
		jq -e '.object_store.mode | . == null or . == "versity"' "$ENDPOINTS" >/dev/null ||
			die "the core hub has $CORE_NODE_COUNT nodes: its object store is Versity Gateway (object_store.mode versity or unset), not $S3_MODE"
		S3_MODE=versity
		S3_ENDPOINT="$VERSITY_FULLNAME.$CORE_NS.svc.$CLUSTER_DOMAIN:$VERSITY_PORT"
		S3_USE_SSL=false
	fi
	case "$S3_MODE" in
	rustfs) ;;
	versity)
		[[ $HA_CORE == true ]] || die "object_store.mode versity is the HA run's (a core hub of several nodes)" ;;
	external)
		jq -e '.object_store.endpoint | strings | length > 0' "$ENDPOINTS" >/dev/null ||
			die "object_store.mode is external: object_store.endpoint (host[:port]) is required"
		# farmer writes the accounts bucket on that external store; without
		# this the DMZ loader would read <core private IP>:9000, where no
		# RustFS runs in this mode (uat/hub/dmz, dmz.account_store).
		jq -e '.dmz.account_store.endpoint | strings | length > 0' "$ENDPOINTS" >/dev/null ||
			die "object_store.mode is external: dmz.account_store.endpoint (the accounts bucket's host:port as the DMZ reaches it) is required" ;;
	*) die "object_store.mode must be rustfs or external (versity on an HA core hub), got: $S3_MODE" ;;
	esac
	[[ "$S3_ENDPOINT" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$ ]] ||
		die "object_store.endpoint is not host[:port] (no scheme, no path): $S3_ENDPOINT"
	[[ "$S3_USE_SSL" == true || "$S3_USE_SSL" == false ]] || die "object_store.use_ssl must be true or false"
	jq -e 'type == "array" and all(.[]; type == "string" and test("^[0-9.]+/[0-9]{1,2}$"))' <<<"$S3_EGRESS_CIDRS" >/dev/null ||
		die "object_store.egress_cidrs must be a list of IPv4 CIDRs"
	local p
	for p in "$CORE_HTTPS_PORT" "$CORE_FARMER_PORT" "$DMZ_ENVOY_PORT" "$DMZ_BUS_PORT" "$CORE_ACCOUNTS_STORE_PORT"; do
		valid_port "$p" || die "not a port: $p"
	done
	# Owner decision 2026-10-06: no node port mode on core (its node port
	# range is 30000-32767); the edge always takes hostPorts.
	[[ "$CORE_EXPOSURE" == hostPort ]] ||
		die "core.exposure must be hostPort (the core node port mode was dropped), not $CORE_EXPOSURE"
	valid_fqdn "$CORE_PRIVATE_FQDN" || die "core.private_fqdn is not a DNS name: $CORE_PRIVATE_FQDN"
	valid_fqdn "$DMZ_PRIVATE_FQDN" || die "dmz.private_fqdn is not a DNS name: $DMZ_PRIVATE_FQDN"
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
	# saasapi's operator listener, in-cluster only (the name on its
	# certificate, chart/templates/certificates.yaml).
	OPERATOR_FQDN="$SAASAPI_OPERATOR_FULLNAME.$CORE_NS.svc.$CLUSTER_DOMAIN"
	# Sprouts sit in the tenants subnet, which may reach the DMZ private range only
	# (the NSG denies its DMZ public IP), so they get the private name, as the
	# enrolment does for farmerinterface. The first Azure run (2026-10-10) timed
	# out dialling the public name.
	SPROUT_BUS_URL="wss://$DMZ_PRIVATE_FQDN:$DMZ_ENVOY_PORT/"
}

# extras_set_args: the --set flags (one per line) that give uat/hub/core/chart
# this run's endpoints. install.sh passes them; core_test.go renders the
# chart with them.
extras_set_args() {
	printf '%s\n' \
		--set-string "core.fqdn=$CORE_FQDN" \
		--set-string "core.privateIP=$CORE_ADDR" \
		--set-json "core.nodeIPs=$CORE_NODE_IPS" \
		--set "core.accountsStorePort=$CORE_ACCOUNTS_STORE_PORT" \
		--set-string "core.privateFQDN=$CORE_PRIVATE_FQDN" \
		--set "core.httpsPort=$CORE_HTTPS_PORT" \
		--set "core.farmerAPIPort=$CORE_FARMER_PORT" \
		--set-string "dmz.privateIP=$DMZ_ADDR" \
		--set-json "dmz.nodeIPs=$DMZ_NODE_IPS" \
		--set-string "dmz.privateFQDN=$DMZ_PRIVATE_FQDN" \
		--set "bus.port=$DMZ_BUS_PORT" \
		--set-string "caIssuer.name=$CA_ISSUER" \
		--set-string "clusterDomain=$CLUSTER_DOMAIN" \
		--set "rustfs.enabled=$([[ $S3_MODE == rustfs ]] && echo true || echo false)" \
		--set "versity.enabled=$([[ $S3_MODE == versity ]] && echo true || echo false)" \
		--set "edge.replicas=$CORE_NODE_COUNT" \
		--set "loadBalancerProbe.enabled=$HA_CORE"
}

# farmer_values_files: the -f arguments (one per line) of the farmer chart:
# values/farmer-uat.yaml, then on an HA core hub values/values-ha.yaml. The
# run's own values (gen-values.sh) come after these.
farmer_values_files() {
	local here_dir
	here_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
	printf '%s\n' -f "$here_dir/values/farmer-uat.yaml"
	[[ $HA_CORE == true ]] && printf '%s\n' -f "$here_dir/values/values-ha.yaml"
	return 0
}

# valkey_ready: Valkey is a Deployment on one node and
# a StatefulSet replicated: every replica of whichever exists is Ready.
valkey_ready() {
	if kc -n "$CORE_NS" get statefulset "$VALKEY_NAME" >/dev/null 2>&1; then
		sts_ready "$VALKEY_NAME" "$CORE_NS"
	else
		kc -n "$CORE_NS" get deployment "$VALKEY_NAME" -o json |
			jq -e '(.spec.replicas // 0) > 0 and (.status.readyReplicas // 0) == .spec.replicas' >/dev/null
	fi
}

# release_version <tag>: vX.Y.Z or vX.Y.Z-rc.N (the contract) -> X.Y.Z[-rc.N].
release_version() {
	[[ "$1" =~ ^v([0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)$ ]] ||
		die "release_tag must be vX.Y.Z or vX.Y.Z-rc.N (never latest), got: $1"
	printf '%s' "${BASH_REMATCH[1]}"
}

# helm_pull_chart <name> <version> <dest-dir>: pulls
# $IMAS_HELM_OCI_BASE/<name> at exactly <version> into <dest-dir>, with no
# credentials: an empty registry config keeps a runner's own login out of
# it, and no --devel or range is ever used. Needs a Helm that pulls oci://
# (Helm 3.8 or later, and 4).
helm_pull_chart() {
	local name="$1" version="$2" dest="$3" base cfg
	base="${IMAS_HELM_OCI_BASE%/}"
	[[ "$base" == oci://?* ]] || die "IMAS_HELM_OCI_BASE must be oci://HOST/PATH, got: $IMAS_HELM_OCI_BASE"
	mkdir -p "$dest" "$STATE_DIR/helm"
	cfg="$STATE_DIR/helm/anonymous-registry.json"
	printf '{}\n' >"$cfg"
	helm pull "$base/$name" --version "$version" --destination "$dest" --registry-config "$cfg" ||
		die "can't pull chart $base/$name:$version. Was release v$version published? The chart package may still be private: the owner makes each chart package public once, in its GHCR package settings, after the first push (docs/RELEASING.md)"
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

# Design T4 (docs/design/imas-openbao-signing-design.md section 11), as the
# check script reads it: the keys the trust ConfigMap must carry, and the
# Transit keys the chart's bootstrap Job creates. bus-loader-user.jwt is
# there because the UAT sets natsTrust.busLoaderUserPub (seeds.sh,
# gen-values.sh): the DMZ bus's loader connects with it.
NATS_TRUST_KEYS=(operator.jwt operator.pub operator-signing.pub sys-account.pub sys-account.jwt bus-loader-user.jwt)
NATS_PLATFORM_KEYS=(nats-operator nats-operator-signing nats-sys-account)

# openbao_t4 <root token file> <bootstrap token file>: the OpenBao half of
# design T4, run in the OpenBao pod. Prints one "PASS <what>" or
# "FAIL <what>" line per check:
#   - the token the chart's bootstrap Job was handed is revoked;
#   - the ephemeral policy imas-nats-bootstrap is gone;
#   - farmer's and the publish Job's policies, each alone, cannot sign with
#     the operator identity key, nor update or soft-delete it;
#   - the three platform keys are ed25519, not exportable, no plaintext
#     backup, not imported, not derived, not soft-deleted.
# Both tokens go over stdin, never argv. A short-lived probe token per
# policy is minted and revoked again.
openbao_t4() {
	{ cat "$1"; echo; cat "$2" 2>/dev/null; echo; } |
		kc -n "$CORE_NS" exec -i "$OPENBAO_POD" -c openbao -- /bin/sh -c '
		IFS= read -r BAO_TOKEN; IFS= read -r boot || true
		export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200
		r() { printf "%s %s
" "$1" "$2"; }
		if [ -z "$boot" ]; then
			r FAIL "T4: no bootstrap token recorded to check"
		elif BAO_TOKEN="$boot" bao token lookup >/dev/null 2>&1; then
			r FAIL "T4: the token handed to the bootstrap Job is still valid"
		else
			r PASS "T4: the token handed to the bootstrap Job is revoked"
		fi
		if bao policy read imas-nats-bootstrap >/dev/null 2>&1; then
			r FAIL "T4: policy imas-nats-bootstrap still exists"
		else
			r PASS "T4: policy imas-nats-bootstrap is deleted"
		fi
		# One probe per policy: an explicit deny in one must not hide a
		# grant in the other (each runs with its own policy alone).
		for pol in imas-farmer-natssign imas-nats-sys-signer; do
			if probe=$(bao token create -orphan -no-default-policy -policy="$pol" \
				-ttl=2m -explicit-max-ttl=2m -renewable=false -field=token 2>/dev/null); then
				for pc in transit/sign/nats-operator=deny transit/keys/nats-operator=read transit/keys/nats-operator/soft-delete=deny; do
					got=$(bao token capabilities "$probe" "${pc%%=*}" 2>/dev/null || echo error)
					if [ "$got" = "${pc#*=}" ]; then
						r PASS "T4: $pol on ${pc%%=*}: $got"
					else
						r FAIL "T4: $pol on ${pc%%=*}: $got, want ${pc#*=}"
					fi
				done
				bao token revoke "$probe" >/dev/null 2>&1 || r FAIL "T4: could not revoke the $pol probe token"
			else
				r FAIL "T4: could not mint a probe token with $pol (policy missing?)"
			fi
		done
		for k in '"${NATS_PLATFORM_KEYS[*]}"'; do
			hard=yes
			[ "$(bao read -field=type "transit/keys/$k" 2>/dev/null)" = ed25519 ] || hard=no
			for f in exportable allow_plaintext_backup imported_key derived soft_deleted; do
				[ "$(bao read -field=$f "transit/keys/$k" 2>/dev/null)" = false ] || hard=no
			done
			if [ $hard = yes ]; then
				r PASS "T4: transit/keys/$k is a hardened ed25519 key"
			else
				r FAIL "T4: transit/keys/$k is missing or not hardened (ed25519, no export, no backup, not imported, not derived, not soft-deleted)"
			fi
		done' 2>/dev/null || printf 'FAIL T4: could not run the checks in %s\n' "$OPENBAO_POD"
}

# trust_snapshot: the trust ConfigMap's data and resourceVersion, sorted
# JSON (public data). install.sh keeps the first one; check.sh compares.
trust_snapshot() {
	kc -n "$CORE_NS" get configmap "$NATS_TRUST_CONFIGMAP" -o json |
		jq -S '{data: .data, resourceVersion: .metadata.resourceVersion}'
}

# status_line <http code> <body file>: the code, and after a space the error
# code of saasapi's JSON error body ({"error": "...", "message": "..."}) when
# the body is one: "401 unauthorized", "403 forbidden", "200". check.sh's
# "must refuse" checks compare it whole, so a refusal from anything but
# saasapi (an HTML 401 from a proxy, an empty body) does not pass.
status_line() {
	local err
	err=$(jq -r 'if type == "object" and (.error | type == "string") and (.error | test("^[a-z_]{1,64}$")) then .error else empty end' "$2" 2>/dev/null || true)
	printf '%s%s' "$1" "${err:+ $err}"
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
