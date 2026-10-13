#!/usr/bin/env bash
# Install the published DMZ chart (deploy/helm/nats: farmerbus and Envoy)
# on the uat-dmz cluster, wait until both are Ready, and expose Envoy (a
# NodePort, 8443 by default, or a LoadBalancer) and the bus client port
# (UAT.3a; docs/claude-code-parallel-build-plan.md, 4h).
#
# Usage:
#   install.sh --kubeconfig FILE --endpoints FILE --release-tag vX.Y.Z[-rc.N]
#              [--trust-dir DIR | --seeds-from-kubeconfig FILE
#                                 [--seeds-from-namespace NS]]
#              [--accounts-reader-dir DIR] [--loader-seed FILE]
#              [--fence-seed FILE]
#              [--workdir DIR] [--expose nodeport|loadbalancer]
#              [--timeout DURATION] [--chart-registry OCI_BASE]
#   install.sh --render-only --endpoints FILE --release-tag TAG
#              [--chart DIR|TGZ] [--workdir DIR] [--expose MODE]
#
# --kubeconfig            the DMZ cluster (UAT.2 writes it; on Azure it points
#                         at the Bastion kube tunnel on 127.0.0.1)
# --endpoints             hub names, addresses and ports (README.md,
#                         "Endpoints file"); a tofu "uat" JSON works as is
# --release-tag           the release under test. Chart version and farmerbus
#                         image tag are both the tag without its leading v.
# --trust-dir             a directory with core's public NATS trust files:
#                         operator.jwt, operator.pub, operator-signing.pub,
#                         sys-account.pub, sys-account.jwt and, when core
#                         minted them, bus-fence-user.jwt and
#                         bus-loader-user.jwt (P21 slice 1)
# --seeds-from-kubeconfig copy those keys from the core cluster's trust
#                         ConfigMap (imas-nats-trust in --seeds-from-
#                         namespace, default imas-core) instead. The name
#                         predates P21: no seed is copied any more
#                         With neither, the ConfigMap must already exist
#                         here. Nothing secret crosses: the bus holds no
#                         trust chain seed
# --accounts-reader-dir   a directory with access-key-id and
#                         secret-access-key: the read-only accounts bucket
#                         credential the bus's loader sidecar uses (uat/hub/
#                         core/rustfs-setup.sh writes it to <core state-dir>/
#                         core/sensitive/s3/accounts-reader). Without it,
#                         Secret imas-bus-accounts-reader must exist here
# --loader-seed           the loader's SYS user NKey seed file (SU...;
#                         uat/hub/core/seeds.sh writes it to <core state-dir>/
#                         core/sensitive/seeds/bus-loader-user.nk); its
#                         public key is core's natsTrust.busLoaderUserPub.
#                         Without it, Secret imas-bus-loader-sys-user must
#                         exist here
# --fence-seed            a clustered bus's fence user NKey seed file (SU...;
#                         uat/hub/core/seeds.sh writes it to <core state-dir>/
#                         core/sensitive/seeds/bus-fence-user.nk when the DMZ
#                         has several nodes); its public key is core's
#                         natsTrust.busFenceUserPub. Read only on an HA DMZ
#                         (endpoints dmz.nodes longer than one), where
#                         without it Secret imas-bus-fence-user must exist
#                         here; a single-node bus has no fence user and the
#                         option is ignored
# --workdir               where the pulled chart, the generated values and
#                         manifests, the render and dmz.json go (default: a
#                         new temporary directory, printed at the end)
# --expose                how Envoy is exposed on dmz.ports.envoy (default
#                         8443): nodeport or loadbalancer (needs a load
#                         balancer controller; production puts Envoy behind
#                         an application gateway). Default: the endpoints
#                         file's dmz.envoy_service_type, else nodeport. The
#                         bus is a NodePort on dmz.ports.bus (default 8442)
#                         either way. README.md, "Exposure"
# --timeout               how long each wait may take (default 10m)
# --chart-registry        OCI base the chart is pulled from, default
#                         oci://ghcr.io/yogzblr/charts (the chart is
#                         <base>/nats). Replaces --chart-repo-url, which is
#                         gone
# --render-only           pull (or take --chart), write the values and
#                         manifests and run helm template; touch no cluster
# --chart                 a local chart, only with --render-only (tests)
#
# The chart is pulled anonymously (no login, no token): the owner makes the
# chart package public once in its GHCR package settings after the first
# push (docs/RELEASING.md). The Buildkite imashelm registry is superseded
# for charts.
#
# HA DMZ hub (the endpoints file lists several DMZ nodes; the workflow's
# hub_nodes 3; brief H4): values-ha.yaml goes after values-uat.yaml (a
# three-node bus cluster and three Envoys, one of each per node), the bus
# certificate names every bus pod, core's traffic is admitted from every
# core node, and two more Secrets are made: the fence user's seed
# (--fence-seed) and the cluster's route password (generated here once,
# kept in the cluster only).
#
# Nothing here is Azure specific, so the local rig (UAT.8) runs it as is.
set -euo pipefail

DMZ_PROG=install.sh
# The loader's Secrets (values-uat.yaml accountStore.credentialsSecret and
# loader.sysUserSecret).
DMZ_ACCOUNTS_READER_SECRET=imas-bus-accounts-reader
DMZ_LOADER_SECRET=imas-bus-loader-sys-user
# A clustered bus's (values-ha.yaml natsSeeds.secretName and
# bus.cluster.auth.secretName).
DMZ_FENCE_SECRET=imas-bus-fence-user
DMZ_ROUTE_SECRET=imas-bus-route-auth
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

kubeconfig="" endpoints="" release_tag="" trust_dir="" seeds_kubeconfig=""
seeds_namespace=imas-core workdir="" expose="" timeout=10m
chart_registry="" render_only="" chart="" reader_dir="" loader_seed="" fence_seed=""

while (($#)); do
	case $1 in
	--kubeconfig | --endpoints | --release-tag | --trust-dir | --seeds-from-kubeconfig | \
		--seeds-from-namespace | --workdir | --expose | --timeout | --chart-registry | --chart | \
		--accounts-reader-dir | --loader-seed | --fence-seed)
		(($# >= 2)) || dmz_die "$1 needs a value"
		case $1 in
		--kubeconfig) kubeconfig=$2 ;;
		--endpoints) endpoints=$2 ;;
		--release-tag) release_tag=$2 ;;
		--trust-dir) trust_dir=$2 ;;
		--seeds-from-kubeconfig) seeds_kubeconfig=$2 ;;
		--seeds-from-namespace) seeds_namespace=$2 ;;
		--accounts-reader-dir) reader_dir=$2 ;;
		--loader-seed) loader_seed=$2 ;;
		--fence-seed) fence_seed=$2 ;;
		--workdir) workdir=$2 ;;
		--expose) expose=$2 ;;
		--timeout) timeout=$2 ;;
		--chart-registry) chart_registry=$2 ;;
		--chart) chart=$2 ;;
		esac
		shift 2
		;;
	--render-only)
		render_only=1
		shift
		;;
	-h | --help) usage ;;
	*) dmz_die "unknown argument '$1' (see --help)" ;;
	esac
done

[[ -n $endpoints ]] || dmz_die "--endpoints is required"
[[ -n $release_tag ]] || dmz_die "--release-tag is required"
version=$(dmz_chart_version "$release_tag")
[[ -z $expose || $expose == nodeport || $expose == loadbalancer ]] || dmz_die "--expose must be nodeport or loadbalancer, not '$expose'"
[[ $timeout =~ ^[1-9][0-9]*[smh]$ ]] || dmz_die "--timeout '$timeout' is not a duration like 10m"
if [[ -n $render_only ]]; then
	[[ -z $kubeconfig && -z $trust_dir && -z $seeds_kubeconfig && -z $reader_dir && -z $loader_seed && -z $fence_seed ]] ||
		dmz_die "--render-only touches no cluster: drop --kubeconfig, the trust and the loader credential options"
else
	[[ -n $kubeconfig ]] || dmz_die "--kubeconfig is required"
	[[ -r $kubeconfig ]] || dmz_die "kubeconfig '$kubeconfig' is not readable"
	[[ -z $chart ]] || dmz_die "--chart is only for --render-only: an install always pulls the published chart"
	[[ -z $trust_dir || -z $seeds_kubeconfig ]] || dmz_die "give --trust-dir or --seeds-from-kubeconfig, not both"
	[[ -z $trust_dir || -d $trust_dir ]] || dmz_die "--trust-dir '$trust_dir' is not a directory"
	[[ -z $seeds_kubeconfig || -r $seeds_kubeconfig ]] || dmz_die "kubeconfig '$seeds_kubeconfig' is not readable"
	[[ $seeds_namespace =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || dmz_die "bad namespace '$seeds_namespace'"
	[[ -z $reader_dir || -d $reader_dir ]] || dmz_die "--accounts-reader-dir '$reader_dir' is not a directory"
	[[ -z $loader_seed || -r $loader_seed ]] || dmz_die "--loader-seed '$loader_seed' is not readable"
fi

dmz_need jq helm
[[ -n $render_only ]] || dmz_need kubectl base64 openssl
dmz_load_endpoints "$endpoints"
if [[ -z $render_only && $DMZ_HA == true ]]; then
	[[ -z $fence_seed || -r $fence_seed ]] || dmz_die "--fence-seed '$fence_seed' is not readable (the DMZ hub has $DMZ_NODE_COUNT nodes: a clustered bus needs its fence user's seed)"
fi
if [[ -z $expose ]]; then
	expose=nodeport
	[[ $DMZ_ENVOY_SERVICE_TYPE != LoadBalancer ]] || expose=loadbalancer
fi

if [[ -z $workdir ]]; then
	workdir=$(mktemp -d "${TMPDIR:-/tmp}/uat-dmz.XXXXXX")
else
	mkdir -p "$workdir"
fi
workdir=$(cd "$workdir" && pwd)
dmz_log "release $release_tag: chart and farmerbus image $version; work directory $workdir"

# Temporary directories, removed on exit whatever happens.
cleanup_dirs=()
cleanup() { ((${#cleanup_dirs[@]} == 0)) || rm -rf "${cleanup_dirs[@]}"; }
trap cleanup EXIT

# Helm state of its own, so nothing leaks into or out of the runner's; a
# temporary directory, so the work directory holds only this run's files.
helm_home=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/uat-dmz-helm.XXXXXX")
cleanup_dirs+=("$helm_home")
export HELM_CONFIG_HOME="$helm_home/config" HELM_CACHE_HOME="$helm_home/cache" \
	HELM_DATA_HOME="$helm_home/data"
export HELM_REPOSITORY_CONFIG="$HELM_CONFIG_HOME/repositories.yaml" \
	HELM_REPOSITORY_CACHE="$HELM_CACHE_HOME/repository"

# chart_field CHART KEY: a top-level scalar of the chart's Chart.yaml.
chart_field() {
	helm show chart "$1" | sed -n "s/^$2:[[:space:]]*//p" | head -n1 | tr -d "\"'"
}

# The accounts bucket the bus's loader reads (P21 slice 2): the core hub's
# object store, reached on dmz.account_store.endpoint (default the core
# hub's private address, port 9000: RustFS, or on an HA core hub Versity
# Gateway through core's edge proxy), and the bus egress to exactly that
# address.
# write_accounts_values OUT: passed after values-run.yaml.
write_accounts_values() {
	local out=$1 endpoint use_ssl cidr host port
	endpoint=$(jq -r --arg d "${CORE_ADDR}:9000" '.dmz.account_store.endpoint // $d' "$endpoints")
	use_ssl=$(jq -r '.dmz.account_store.use_ssl // false' "$endpoints")
	[[ $endpoint =~ ^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?):([0-9]{1,5})$ ]] ||
		dmz_die "endpoints: dmz.account_store.endpoint '$endpoint' is not host:port (no scheme)"
	host=${BASH_REMATCH[1]} port=${BASH_REMATCH[3]}
	((port >= 1 && port <= 65535)) || dmz_die "endpoints: dmz.account_store.endpoint port $port is not a port"
	[[ $use_ssl == true || $use_ssl == false ]] || dmz_die "endpoints: dmz.account_store.use_ssl must be true or false"
	if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		cidr=$(jq -r --arg d "$host/32" '.dmz.account_store.egress_cidr // $d' "$endpoints")
	else
		cidr=$(jq -r '.dmz.account_store.egress_cidr // empty' "$endpoints")
		[[ -n $cidr ]] || dmz_die "endpoints: dmz.account_store.endpoint '$endpoint' is a name: set dmz.account_store.egress_cidr to its address"
	fi
	[[ $cidr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}$ ]] || dmz_die "endpoints: dmz.account_store.egress_cidr '$cidr' is not an IPv4 CIDR"
	cat >"$out" <<EOF
# Written by uat/hub/dmz/install.sh for one run. Do not commit.
---
accountStore:
  endpoint: "${endpoint}"
  useSSL: ${use_ssl}
networkPolicy:
  accountStoreEgress:
    cidr: "${cidr}"
    port: ${port}
EOF
}

# --- 1. The chart, from the release's OCI registry --------------------------
if [[ -n $chart ]]; then
	[[ -e $chart ]] || dmz_die "chart '$chart' not found"
	chart_ref=$chart
	dmz_log "using the local chart $chart (render only)"
else
	chart_registry=${chart_registry:-oci://ghcr.io/yogzblr/charts}
	chart_registry=${chart_registry%/}
	[[ $chart_registry == oci://?* ]] || dmz_die "--chart-registry must be oci://HOST/PATH, not '$chart_registry'"
	mkdir -p "$workdir/chart"
	rm -f "$workdir/chart/nats-$version.tgz"
	# Anonymous: an empty registry config keeps any login of the runner's
	# out of it. An exact --version selects a pre-release (0.1.0-rc.5) too.
	# No --devel, no range, so nothing but this version can be pulled.
	printf '{}\n' >"$helm_home/anonymous-registry.json"
	dmz_log "helm pull $chart_registry/nats --version $version"
	helm pull "$chart_registry/nats" --version "$version" --destination "$workdir/chart" \
		--registry-config "$helm_home/anonymous-registry.json" ||
		dmz_die "could not pull chart $chart_registry/nats:$version (was release $release_tag published? The chart package may still be private: the owner makes each chart package public once, in its GHCR package settings, after the first push; docs/RELEASING.md)"
	chart_ref="$workdir/chart/nats-$version.tgz"
	[[ -f $chart_ref ]] || dmz_die "helm pull did not write $chart_ref"
fi
got_version=$(chart_field "$chart_ref" version)
got_app=$(chart_field "$chart_ref" appVersion)
[[ $got_version == "$version" ]] || dmz_die "chart version is '$got_version', want $version"
[[ $got_app == "$version" ]] || dmz_die "chart appVersion is '$got_app', want $version"

# --- 2. Values, manifests, render ----------------------------------------
dmz_write_run_values "$workdir/values-run.yaml" "$version"
write_accounts_values "$workdir/values-accounts.yaml"
dmz_write_manifests "$workdir/manifests.yaml" "$expose"
values=(-f "$here/values-uat.yaml")
[[ $DMZ_HA != true ]] || values+=(-f "$here/values-ha.yaml")
values+=(-f "$workdir/values-run.yaml" -f "$workdir/values-accounts.yaml")

# An offline render of exactly what step 6 installs, kept for the record and
# checked below. The Kubernetes version only satisfies the chart's
# kubeVersion (>=1.25) offline; the install itself uses the cluster's.
helm template "$DMZ_RELEASE" "$chart_ref" --namespace "$DMZ_NAMESPACE" "${values[@]}" \
	--kube-version "${DMZ_RENDER_KUBE_VERSION:-1.30.0}" \
	>"$workdir/rendered.yaml" || dmz_die "helm template failed"
grep -q "image: \"${DMZ_BUS_IMAGE_REPO}:${version}\"" "$workdir/rendered.yaml" ||
	dmz_die "the render does not run ${DMZ_BUS_IMAGE_REPO}:${version}"
if grep -Eq 'image: "?[^"[:space:]]+:latest"?$' "$workdir/rendered.yaml"; then
	dmz_die "the render pulls a :latest image"
fi
dmz_write_outputs "$workdir/dmz.json" "$version" "$expose"

if [[ -n $render_only ]]; then
	dmz_log "render only: $workdir/{values-run.yaml,manifests.yaml,rendered.yaml,dmz.json}"
	exit 0
fi

# --- 3. Cluster preconditions (UAT.2) -------------------------------------
kc() { kubectl --kubeconfig "$kubeconfig" "$@"; }
kc version --request-timeout=30s >/dev/null || dmz_die "cannot reach the cluster in $kubeconfig"
kc get crd certificates.cert-manager.io >/dev/null 2>&1 ||
	dmz_die "cert-manager is not installed (UAT.2 installs it)"
kc get clusterissuer "$DMZ_CLUSTER_ISSUER" >/dev/null 2>&1 ||
	dmz_die "ClusterIssuer '$DMZ_CLUSTER_ISSUER' not found (UAT.2 creates the UAT CA issuer; set cluster_issuer in the endpoints file)"
kc wait --for=condition=Ready "clusterissuer/$DMZ_CLUSTER_ISSUER" --timeout="$timeout" >/dev/null ||
	dmz_die "ClusterIssuer '$DMZ_CLUSTER_ISSUER' is not Ready"

kc create namespace "$DMZ_NAMESPACE" --dry-run=client -o yaml | kc apply -f - >/dev/null
kc label namespace "$DMZ_NAMESPACE" imas.io/purpose=imas-uat --overwrite >/dev/null

# --- 4. The public NATS trust ----------------------------------------------
# P21 slice 1: the bus holds no trust chain seed. It starts from the public
# trust ConfigMap core's OpenBao bootstrap Job wrote (imas-core/
# imas-nats-trust), copied here by hand or pipeline (owner decision c);
# this is that copy. Only the named public keys are copied, after
# dmz_trust_problem has checked them.
# trust_from_json JSON DIR: the ConfigMap's known keys as files in DIR.
trust_from_json() {
	local json=$1 dir=$2 key
	for key in "${DMZ_TRUST_KEYS[@]}" "${DMZ_TRUST_OPTIONAL_KEYS[@]}"; do
		jq -j --arg k "$key" '.data[$k] // empty' <<<"$json" >"$dir/$key" ||
			dmz_die "ConfigMap $DMZ_TRUST_CONFIGMAP: could not read $key"
	done
}
# apply_trust_dir DIR: the trust files into the DMZ ConfigMap.
apply_trust_dir() {
	local dir=$1 key problem args=()
	problem=$(dmz_trust_problem "$dir")
	[[ -z $problem ]] || dmz_die "the NATS trust from $2: $problem"
	for key in "${DMZ_TRUST_KEYS[@]}" "${DMZ_TRUST_OPTIONAL_KEYS[@]}"; do
		[[ ! -s $dir/$key ]] || args+=("--from-file=$key=$dir/$key")
	done
	kc -n "$DMZ_NAMESPACE" create configmap "$DMZ_TRUST_CONFIGMAP" "${args[@]}" \
		--dry-run=client -o yaml | kc apply -f - >/dev/null
	kc -n "$DMZ_NAMESPACE" label configmap "$DMZ_TRUST_CONFIGMAP" imas.io/purpose=imas-uat --overwrite >/dev/null
}

trust_tmp=$(mktemp -d "${TMPDIR:-/tmp}/uat-dmz-trust.XXXXXX")
cleanup_dirs+=("$trust_tmp")
if [[ -n $trust_dir ]]; then
	dmz_log "NATS trust: from $trust_dir"
	apply_trust_dir "$trust_dir" "$trust_dir"
elif [[ -n $seeds_kubeconfig ]]; then
	dmz_log "NATS trust: copying ConfigMap $seeds_namespace/$DMZ_TRUST_CONFIGMAP from the core cluster"
	cm=$(kubectl --kubeconfig "$seeds_kubeconfig" -n "$seeds_namespace" get configmap "$DMZ_TRUST_CONFIGMAP" -o json) ||
		dmz_die "could not read ConfigMap $seeds_namespace/$DMZ_TRUST_CONFIGMAP on the core cluster (core's OpenBao bootstrap Job writes it: run uat/hub/core/install.sh first)"
	trust_from_json "$cm" "$trust_tmp"
	apply_trust_dir "$trust_tmp" "$seeds_namespace/$DMZ_TRUST_CONFIGMAP on the core cluster"
else
	cm=$(kc -n "$DMZ_NAMESPACE" get configmap "$DMZ_TRUST_CONFIGMAP" -o json 2>/dev/null) ||
		dmz_die "ConfigMap $DMZ_NAMESPACE/$DMZ_TRUST_CONFIGMAP not found: pass --trust-dir or --seeds-from-kubeconfig (core's public NATS trust; deploy/helm/nats/README.md, \"NATS trust\")"
	trust_from_json "$cm" "$trust_tmp"
	problem=$(dmz_trust_problem "$trust_tmp")
	[[ -z $problem ]] || dmz_die "ConfigMap $DMZ_NAMESPACE/$DMZ_TRUST_CONFIGMAP: $problem (copy core's again: --seeds-from-kubeconfig)"
	dmz_log "NATS trust: using the existing ConfigMap $DMZ_NAMESPACE/$DMZ_TRUST_CONFIGMAP"
fi
rm -rf "$trust_tmp"

# --- 4b. The loader's Secrets ----------------------------------------------
# apply_loader_secret NAME KEY=FILE...: one Secret from files; contents
# travel only through kubectl's stdin.
apply_loader_secret() {
	local name=$1 kv args=()
	shift
	for kv in "$@"; do
		[[ -s ${kv#*=} ]] || dmz_die "${kv#*=} is missing or empty"
		args+=("--from-file=$kv")
	done
	kc -n "$DMZ_NAMESPACE" create secret generic "$name" "${args[@]}" \
		--dry-run=client -o yaml | kc apply -f - >/dev/null
	kc -n "$DMZ_NAMESPACE" label secret "$name" imas.io/purpose=imas-uat --overwrite >/dev/null
}
# need_secret_keys NAME KEY...: an existing Secret with every key.
need_secret_keys() {
	local name=$1 key
	shift
	for key in "$@"; do
		[[ -n $(kc -n "$DMZ_NAMESPACE" get secret "$name" -o "jsonpath={.data.${key//./\\.}}" 2>/dev/null) ]] ||
			dmz_die "Secret $DMZ_NAMESPACE/$name lacks $key: pass --accounts-reader-dir and --loader-seed (and --fence-seed on an HA DMZ) (README.md, \"Accounts bucket and loader\")"
	done
}
if [[ -n $reader_dir ]]; then
	dmz_log "accounts reader credential: from $reader_dir"
	apply_loader_secret "$DMZ_ACCOUNTS_READER_SECRET" \
		"access-key-id=$reader_dir/access-key-id" "secret-access-key=$reader_dir/secret-access-key"
else
	need_secret_keys "$DMZ_ACCOUNTS_READER_SECRET" access-key-id secret-access-key
	dmz_log "accounts reader credential: using the existing Secret $DMZ_NAMESPACE/$DMZ_ACCOUNTS_READER_SECRET"
fi
if [[ -n $loader_seed ]]; then
	# The whole file: one seed and at most one final newline, nothing else
	# (the Secret carries the file byte for byte).
	seed=$(<"$loader_seed")
	size=$(wc -c <"$loader_seed")
	{ [[ $seed =~ ^SU[A-Z2-7]{50,}$ ]] && ((size == ${#seed} || size == ${#seed} + 1)); } ||
		dmz_die "--loader-seed $loader_seed is not one NKey user seed"
	unset seed
	dmz_log "loader SYS user seed: from $loader_seed"
	apply_loader_secret "$DMZ_LOADER_SECRET" "user.nk=$loader_seed"
else
	need_secret_keys "$DMZ_LOADER_SECRET" user.nk
	dmz_log "loader SYS user seed: using the existing Secret $DMZ_NAMESPACE/$DMZ_LOADER_SECRET"
fi
# A clustered bus (HA DMZ): the fence user's seed and the route password.
if [[ $DMZ_HA == true ]]; then
	[[ -n $(kc -n "$DMZ_NAMESPACE" get configmap "$DMZ_TRUST_CONFIGMAP" -o 'jsonpath={.data.bus-fence-user\.jwt}' 2>/dev/null) ]] ||
		dmz_die "the DMZ hub has $DMZ_NODE_COUNT nodes, but the NATS trust has no bus-fence-user.jwt: core's install must set natsTrust.busFenceUserPub (uat/hub/core/seeds.sh and gen-values.sh do for an HA DMZ)"
	if [[ -n $fence_seed ]]; then
		seed=$(<"$fence_seed")
		size=$(wc -c <"$fence_seed")
		{ [[ $seed =~ ^SU[A-Z2-7]{50,}$ ]] && ((size == ${#seed} || size == ${#seed} + 1)); } ||
			dmz_die "--fence-seed $fence_seed is not one NKey user seed"
		unset seed
		dmz_log "bus fence user seed: from $fence_seed"
		apply_loader_secret "$DMZ_FENCE_SECRET" "bus-fence-user.nk=$fence_seed"
	else
		need_secret_keys "$DMZ_FENCE_SECRET" bus-fence-user.nk
		dmz_log "bus fence user seed: using the existing Secret $DMZ_NAMESPACE/$DMZ_FENCE_SECRET"
	fi
	if [[ -z $(kc -n "$DMZ_NAMESPACE" get secret "$DMZ_ROUTE_SECRET" -o 'jsonpath={.data.route-password}' 2>/dev/null) ]]; then
		route_tmp=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/uat-dmz-route.XXXXXX")
		cleanup_dirs+=("$route_tmp")
		(umask 077 && openssl rand -hex 32 | tr -d '\n' >"$route_tmp/route-password")
		apply_loader_secret "$DMZ_ROUTE_SECRET" "route-password=$route_tmp/route-password"
		rm -rf "$route_tmp"
		dmz_log "bus route password: generated into Secret $DMZ_NAMESPACE/$DMZ_ROUTE_SECRET"
	else
		dmz_log "bus route password: keeping the existing Secret $DMZ_NAMESPACE/$DMZ_ROUTE_SECRET"
	fi
fi

# --- 5. Certificates, exposure, the core rule -----------------------------
kc apply -f "$workdir/manifests.yaml" >/dev/null ||
	dmz_die "applying $workdir/manifests.yaml failed (a node port must lie in the API server's --service-node-port-range, which UAT.2 sets)"
for cert in "$DMZ_ENVOY_TLS_SECRET" "$DMZ_BUS_TLS_SECRET"; do
	kc -n "$DMZ_NAMESPACE" wait --for=condition=Ready "certificate/$cert" --timeout="$timeout" >/dev/null ||
		dmz_die "certificate $cert is not Ready (kubectl -n $DMZ_NAMESPACE describe certificate $cert)"
done
[[ -n $(kc -n "$DMZ_NAMESPACE" get secret "$DMZ_BUS_TLS_SECRET" -o 'jsonpath={.data.ca\.crt}') ]] ||
	dmz_die "secret $DMZ_BUS_TLS_SECRET has no ca.crt: the ClusterIssuer must be a CA issuer"

# --- 6. The chart -----------------------------------------------------------
dmz_log "helm upgrade --install $DMZ_RELEASE nats $version"
helm upgrade --install "$DMZ_RELEASE" "$chart_ref" --kubeconfig "$kubeconfig" \
	--namespace "$DMZ_NAMESPACE" "${values[@]}" --timeout "$timeout" >/dev/null ||
	dmz_die "helm upgrade --install failed"

kc -n "$DMZ_NAMESPACE" rollout status "statefulset/$DMZ_BUS_NAME" --timeout="$timeout" ||
	dmz_die "farmerbus did not roll out"
kc -n "$DMZ_NAMESPACE" rollout status "deployment/$DMZ_ENVOY_NAME" --timeout="$timeout" ||
	dmz_die "Envoy did not roll out"
for component in bus envoy; do
	kc -n "$DMZ_NAMESPACE" wait --for=condition=Ready pod \
		-l "app.kubernetes.io/instance=$DMZ_RELEASE,app.kubernetes.io/component=$component" \
		--timeout="$timeout" >/dev/null || dmz_die "the $component pod is not Ready"
done

for svc in "${DMZ_FULLNAME}-envoy-edge" "${DMZ_FULLNAME}-bus-core"; do
	ready=$(kc -n "$DMZ_NAMESPACE" get endpointslices -l "kubernetes.io/service-name=$svc" \
		-o 'jsonpath={.items[*].endpoints[?(@.conditions.ready==true)].addresses[*]}')
	[[ -n $ready ]] || dmz_die "Service $svc has no ready endpoint"
done

# A LoadBalancer is usable only once its controller has given it an address.
if [[ $expose == loadbalancer ]]; then
	case $timeout in
	*s) wait_s=${timeout%s} ;;
	*m) wait_s=$((${timeout%m} * 60)) ;;
	*h) wait_s=$((${timeout%h} * 3600)) ;;
	esac
	lb_address="" waited=0
	while :; do
		lb_address=$(kc -n "$DMZ_NAMESPACE" get service "${DMZ_FULLNAME}-envoy-edge" \
			-o 'jsonpath={.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}')
		[[ -z $lb_address && $waited -lt $wait_s ]] || break
		sleep 5
		waited=$((waited + 5))
	done
	[[ -n $lb_address ]] ||
		dmz_die "Service ${DMZ_FULLNAME}-envoy-edge got no load balancer address within $timeout (is a load balancer controller installed? --expose nodeport needs none)"
	dmz_write_outputs "$workdir/dmz.json" "$version" "$expose" "$lb_address"
	where="LoadBalancer $lb_address:$DMZ_ENVOY_PORT"
else
	where="node port $DMZ_ENVOY_PORT on $DMZ_NODE_COUNT node(s), private address $DMZ_ADDR"
fi

kc -n "$DMZ_NAMESPACE" get pods,svc -o wide >&2 || true
dmz_log "Ready. Envoy for $DMZ_PRIVATE_NAME (sprouts) and $DMZ_FQDN (runner): $where; bus for core: tls://$DMZ_PRIVATE_NAME:$DMZ_BUS_PORT ($DMZ_ADDR)"
dmz_log "outputs for the core side and enrolment: $workdir/dmz.json"
