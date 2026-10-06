#!/usr/bin/env bash
# Install the published DMZ chart (deploy/helm/nats: farmerbus and Envoy)
# on the uat-dmz cluster, wait until both are Ready, and expose Envoy (a
# NodePort, 8443 by default, or a LoadBalancer) and the bus client port
# (UAT.3a; docs/claude-code-parallel-build-plan.md, 4h).
#
# Usage:
#   install.sh --kubeconfig FILE --endpoints FILE --release-tag vX.Y.Z[-rc.N]
#              [--seeds-dir DIR | --seeds-from-kubeconfig FILE
#                                 [--seeds-from-namespace NS]]
#              [--workdir DIR] [--expose nodeport|loadbalancer]
#              [--timeout DURATION] [--chart-repo-url URL]
#   install.sh --render-only --endpoints FILE --release-tag TAG
#              [--chart DIR|TGZ] [--workdir DIR] [--expose MODE]
#
# --kubeconfig            the DMZ cluster (UAT.2 writes it; on Azure it points
#                         at the Bastion kube tunnel on 127.0.0.1)
# --endpoints             hub names, addresses and ports (README.md,
#                         "Endpoints file"); a tofu "uat" JSON works as is
# --release-tag           the release under test. Chart version and farmerbus
#                         image tag are both the tag without its leading v.
# --seeds-dir             a directory with core's operator.nk,
#                         operator-signing.nk, sys-account.nk, tenant.nk and
#                         tenant-signing.nk (saasapi-user.nk is ignored)
# --seeds-from-kubeconfig copy those five keys from the core cluster's seed
#                         Secret (imas-farmer-nats-seeds in --seeds-from-
#                         namespace, default imas-core) instead
#                         With neither, the Secret must already exist here.
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
# --chart-repo-url        default https://packages.buildkite.com/
#                         $BUILDKITE_ORGANIZATION_SLUG (default yogzblr)/
#                         imashelm/helm
# --render-only           pull (or take --chart), write the values and
#                         manifests and run helm template; touch no cluster
# --chart                 a local chart, only with --render-only (tests)
#
# The imashelm registry is public (owner's decision, 2026-10-06): no token
# is taken or sent.
#
# Nothing here is Azure specific, so the local rig (UAT.8) runs it as is.
set -euo pipefail

DMZ_PROG=install.sh
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" >&2
	exit 2
}

kubeconfig="" endpoints="" release_tag="" seeds_dir="" seeds_kubeconfig=""
seeds_namespace=imas-core workdir="" expose="" timeout=10m
chart_repo_url="" render_only="" chart=""

while (($#)); do
	case $1 in
	--kubeconfig | --endpoints | --release-tag | --seeds-dir | --seeds-from-kubeconfig | \
		--seeds-from-namespace | --workdir | --expose | --timeout | --chart-repo-url | --chart)
		(($# >= 2)) || dmz_die "$1 needs a value"
		case $1 in
		--kubeconfig) kubeconfig=$2 ;;
		--endpoints) endpoints=$2 ;;
		--release-tag) release_tag=$2 ;;
		--seeds-dir) seeds_dir=$2 ;;
		--seeds-from-kubeconfig) seeds_kubeconfig=$2 ;;
		--seeds-from-namespace) seeds_namespace=$2 ;;
		--workdir) workdir=$2 ;;
		--expose) expose=$2 ;;
		--timeout) timeout=$2 ;;
		--chart-repo-url) chart_repo_url=$2 ;;
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
	[[ -z $kubeconfig && -z $seeds_dir && -z $seeds_kubeconfig ]] ||
		dmz_die "--render-only touches no cluster: drop --kubeconfig and the seed options"
else
	[[ -n $kubeconfig ]] || dmz_die "--kubeconfig is required"
	[[ -r $kubeconfig ]] || dmz_die "kubeconfig '$kubeconfig' is not readable"
	[[ -z $chart ]] || dmz_die "--chart is only for --render-only: an install always pulls the published chart"
	[[ -z $seeds_dir || -z $seeds_kubeconfig ]] || dmz_die "give --seeds-dir or --seeds-from-kubeconfig, not both"
	[[ -z $seeds_kubeconfig || -r $seeds_kubeconfig ]] || dmz_die "kubeconfig '$seeds_kubeconfig' is not readable"
	[[ $seeds_namespace =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || dmz_die "bad namespace '$seeds_namespace'"
fi

dmz_need jq helm
[[ -n $render_only ]] || dmz_need kubectl base64
dmz_load_endpoints "$endpoints"
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

# --- 1. The chart, from the release's registry --------------------------
if [[ -n $chart ]]; then
	[[ -e $chart ]] || dmz_die "chart '$chart' not found"
	chart_ref=$chart
	dmz_log "using the local chart $chart (render only)"
else
	org=${BUILDKITE_ORGANIZATION_SLUG:-yogzblr}
	[[ $org =~ ^[a-z0-9][a-z0-9-]*$ ]] || dmz_die "bad BUILDKITE_ORGANIZATION_SLUG '$org'"
	chart_repo_url=${chart_repo_url:-https://packages.buildkite.com/$org/imashelm/helm}
	[[ $chart_repo_url == https://* ]] || dmz_die "--chart-repo-url must be https"
	dmz_log "helm repo add imas-uat-imashelm $chart_repo_url"
	helm repo add --force-update imas-uat-imashelm "$chart_repo_url" >/dev/null ||
		dmz_die "could not add the chart repository $chart_repo_url"
	mkdir -p "$workdir/chart"
	rm -f "$workdir/chart/nats-$version.tgz"
	# An exact --version selects a pre-release (0.1.0-rc.4) too: Helm skips
	# pre-releases only when resolving a range or the newest version. No
	# --devel, no range, so nothing but this version can be pulled.
	helm pull imas-uat-imashelm/nats --version "$version" --destination "$workdir/chart" ||
		dmz_die "chart nats $version is not in $chart_repo_url (was release $release_tag published?)"
	chart_ref="$workdir/chart/nats-$version.tgz"
	[[ -f $chart_ref ]] || dmz_die "helm pull did not write $chart_ref"
fi
got_version=$(chart_field "$chart_ref" version)
got_app=$(chart_field "$chart_ref" appVersion)
[[ $got_version == "$version" ]] || dmz_die "chart version is '$got_version', want $version"
[[ $got_app == "$version" ]] || dmz_die "chart appVersion is '$got_app', want $version"

# --- 2. Values, manifests, render ----------------------------------------
dmz_write_run_values "$workdir/values-run.yaml" "$version"
dmz_write_manifests "$workdir/manifests.yaml" "$expose"
values=(-f "$here/values-uat.yaml" -f "$workdir/values-run.yaml")

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

# --- 4. Seeds ---------------------------------------------------------------
# apply_seed_dir DIR: the five seeds into the DMZ Secret. Contents travel
# through a pipe only; nothing is printed.
apply_seed_dir() {
	local dir=$1 key args=()
	for key in "${DMZ_SEED_KEYS[@]}"; do
		[[ -s $dir/$key ]] || dmz_die "seed $key missing or empty in $dir"
		if (($(wc -l <"$dir/$key") > 1)) || ! grep -Eq '^S[OAU][A-Z2-7]{50,}$' "$dir/$key"; then
			dmz_die "seed $key in $dir is not one NKey seed"
		fi
		args+=("--from-file=$key=$dir/$key")
	done
	kc -n "$DMZ_NAMESPACE" create secret generic "$DMZ_SEEDS_SECRET" "${args[@]}" \
		--dry-run=client -o yaml | kc apply -f - >/dev/null
	kc -n "$DMZ_NAMESPACE" label secret "$DMZ_SEEDS_SECRET" imas.io/purpose=imas-uat --overwrite >/dev/null
}

if [[ -n $seeds_dir ]]; then
	dmz_log "seeds: from $seeds_dir"
	apply_seed_dir "$seeds_dir"
elif [[ -n $seeds_kubeconfig ]]; then
	dmz_log "seeds: copying the five bus seeds from $seeds_namespace/$DMZ_SEEDS_SECRET on the core cluster"
	seed_tmp=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/uat-dmz-seeds.XXXXXX")
	cleanup_dirs+=("$seed_tmp")
	for key in "${DMZ_SEED_KEYS[@]}"; do
		(umask 077 && kubectl --kubeconfig "$seeds_kubeconfig" -n "$seeds_namespace" \
			get secret "$DMZ_SEEDS_SECRET" -o "jsonpath={.data.${key//./\\.}}" | base64 -d >"$seed_tmp/$key") ||
			dmz_die "could not read $key from $seeds_namespace/$DMZ_SEEDS_SECRET on the core cluster"
	done
	apply_seed_dir "$seed_tmp"
	rm -rf "$seed_tmp"
else
	for key in "${DMZ_SEED_KEYS[@]}"; do
		[[ -n $(kc -n "$DMZ_NAMESPACE" get secret "$DMZ_SEEDS_SECRET" -o "jsonpath={.data.${key//./\\.}}" 2>/dev/null) ]] ||
			dmz_die "Secret $DMZ_NAMESPACE/$DMZ_SEEDS_SECRET lacks $key: pass --seeds-dir or --seeds-from-kubeconfig (core's seeds; README.md, \"Seeds\")"
	done
	dmz_log "seeds: using the existing Secret $DMZ_NAMESPACE/$DMZ_SEEDS_SECRET"
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
	where="node port $DMZ_ENVOY_PORT on $DMZ_PRIVATE_IP"
fi

kc -n "$DMZ_NAMESPACE" get pods,svc -o wide >&2 || true
dmz_log "Ready. Envoy for $DMZ_PRIVATE_NAME (sprouts) and $DMZ_FQDN (runner): $where; bus for core: tls://$DMZ_PRIVATE_NAME:$DMZ_BUS_PORT ($DMZ_PRIVATE_IP)"
dmz_log "outputs for the core side and enrolment: $workdir/dmz.json"
