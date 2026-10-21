#!/usr/bin/env bash
# install.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>
#
# Installs the core side of the UAT gate on the uat-core cluster, in order
# (README.md, "What install.sh does"):
#    1. namespaces and the generated credentials (Kubernetes Secrets, and
#       files under <state>/core/sensitive)
#    2. the NATS user seeds and farmer's NKey, with their Secrets, and the
#       DMZ bus loader's seed (seeds.sh), and the bootstrap admin keys
#       (admin-keys.sh, the release's own imas CLI)
#    3. the published farmer chart of release_tag, pulled and checked: its
#       version, and the stamped sprout release it carries
#       (files/sprout-release.json, which finish.sh registers)
#    4. the UAT-only pieces (chart/): RustFS, Keycloak with the imas-uat
#       realm, the edge proxy, certificates (farmer's, the edge's and
#       saasapi's operator listener's), policies
#    5. RustFS buckets, users and policies (rustfs-setup.sh): recipes, jobs,
#       sprout JWTs, the accounts bucket with its writer and reader, and the
#       log bucket with its writer and retention users (logShipping), then
#       validate-object-store.sh proves each scoped credential's reach. On an
#       HA core hub, Versity Gateway's Secrets instead (below)
#    6. the farmer chart, with OpenBao initialised and unsealed while the
#       install runs (openbao-bootstrap.sh); its bootstrap Job writes the
#       public NATS trust (ConfigMap imas-nats-trust, which the DMZ copies)
#       and revokes the token it was handed, whose Secret then goes
#    7. saasapi's hand-made Secrets (saasapi-secrets.sh), the operator
#       token's and Valkey's password (imas-valkey-auth, which Valkey,
#       farmer and saasapi wait for) among them
#    8. waits for the workloads core owns and writes the outputs
# HA core hub (the endpoints file lists several core nodes; the workflow's
# hub_nodes 3; brief H4): the farmer chart also gets values/values-ha.yaml
# (three replicas of farmer, saasapi and Versity Gateway spread over the
# nodes, PXC 3, OpenBao 3-node raft with the static seal, Valkey replicated,
# all on the nodes' local volumes) and the UAT-only chart runs one edge per
# node. Before the chart, step 1 also makes OpenBao's static seal key
# (Secret imas-uat-openbao-seal; <state>/core/sensitive/openbao-seal.key)
# and step 5 Versity Gateway's Secrets instead of provisioning RustFS: the
# Azure Blob account's name and key (from <state>/core/sensitive/
# azure-blob/, which the workflow writes from uat/tofu's object_store
# outputs), the gateway's root credential and the six users' pairs (the
# accounts reader's for the DMZ too, at sensitive/s3/accounts-reader as
# before). After the chart (its createBuckets Job has made the buckets and
# their policies), validate-object-store.sh proves each credential through
# the gateway. FLAG FOR SECURITY REVIEW: the seal key and the Azure key are
# UAT-only Secrets in the core namespace.
# It does NOT wait for farmer or saasapi, register the sprout release, or run
# check.sh: farmer's /ready and saasapi's startup both need the DMZ's NATS bus,
# which the DMZ install (uat/hub/dmz/install.sh) creates after this script.
# finish.sh does those three things once the DMZ is up. It does raise both
# Deployments' progress deadline to FIRST_START_SECONDS (1200 s) as helm
# creates them, as a clean first start of farmer takes about ten minutes
# (W7; lib/common.sh).
# IMAS_UAT_DISPATCH_FLAGS (on or off, default off; the workflow input
# dispatch_flags) sets the fleet update flags in the chart values
# (gen-values.sh) and is recorded in core.json, which check.sh compares.
# Chart and images are the release's version (release_tag without the v),
# never latest. Calls nothing Azure specific: UAT.8 runs it on a local
# cluster. Re-running it upgrades in place and keeps every generated
# secret. FLAG FOR SECURITY REVIEW.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
usage="install.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>"
parse_common_args "$usage" "$@"
[[ $# -ge 4 ]] || die "usage: $usage"
release_tag="$4"
version=$(release_version "$release_tag")
need_cmd kubectl helm jq curl openssl go tar sha256sum base64 awk sed
HELM_TIMEOUT="${HELM_TIMEOUT:-45m}"
common=("$KUBECONFIG_PATH" "$ENDPOINTS" "$STATE_ROOT")

case "${IMAS_UAT_DISPATCH_FLAGS:-off}" in
on | true | yes | 1) dispatch_flags=on ;;
off | false | no | 0) dispatch_flags=off ;;
*) die "IMAS_UAT_DISPATCH_FLAGS must be on or off, got: ${IMAS_UAT_DISPATCH_FLAGS}" ;;
esac
log "release $release_tag (chart and images $version); core $CORE_FQDN ($CORE_ADDR, $CORE_NODE_COUNT node(s)), DMZ $DMZ_FQDN ($DMZ_ADDR, $DMZ_NODE_COUNT node(s)); object store $S3_MODE; fleet update dispatch flags $dispatch_flags"
log "issuer $KEYCLOAK_ISSUER; sprout bus URL $SPROUT_BUS_URL"
kc version >/dev/null 2>&1 || die "can't reach the cluster with $KUBECONFIG_PATH"
kc get clusterissuer "$CA_ISSUER" >/dev/null 2>&1 ||
	die "ClusterIssuer $CA_ISSUER not found: the UAT CA (UAT.2) must exist first"

# --- 1. namespaces and generated credentials --------------------------------
ensure_ns "$CORE_NS" "$UAT_NS"

kcdir="$SENSITIVE_DIR/keycloak"
mdir="$SENSITIVE_DIR/rustfs"
(umask 077 && mkdir -p "$kcdir" "$mdir")
printf '%s' imas-uat-kc-admin >"$kcdir/admin-username"
gen_secret_file "$kcdir/admin-password"
gen_secret_file "$kcdir/tests-client-secret" 32
gen_secret_file "$kcdir/other-client-secret" 32
for u in "${UAT_USERS[@]}"; do gen_secret_file "$kcdir/$u.password"; done
printf '%s' imas-uat-root >"$mdir/root-user"
gen_secret_file "$mdir/root-password" 32
gen_secret_file "$SENSITIVE_DIR/internal-auth-secret" 32

apply_secret "$UAT_NS" "$RUSTFS_ROOT_SECRET" "user=$mdir/root-user" "password=$mdir/root-password"
apply_secret "$UAT_NS" "$KEYCLOAK_ADMIN_SECRET" "username=$kcdir/admin-username" "password=$kcdir/admin-password"
apply_secret "$UAT_NS" "$KEYCLOAK_REALM_SECRET" \
	"UAT_TESTS_CLIENT_SECRET=$kcdir/tests-client-secret" \
	"UAT_OTHER_CLIENT_SECRET=$kcdir/other-client-secret" \
	"UAT_T1_ADMIN_PASSWORD=$kcdir/t1-admin.password" \
	"UAT_T1_READER_PASSWORD=$kcdir/t1-reader.password" \
	"UAT_T2_ADMIN_PASSWORD=$kcdir/t2-admin.password" \
	"UAT_T2_READER_PASSWORD=$kcdir/t2-reader.password"
# The BFF's shared secret (saasapi.internalAuthSecret): the tests stand in
# for the BFF, so they get it too (sensitive outputs).
apply_secret "$CORE_NS" "$INTERNAL_AUTH_SECRET" "current=$SENSITIVE_DIR/internal-auth-secret"

if [[ $HA_CORE == true ]]; then
	# OpenBao's static seal key (values/values-ha.yaml): 32 random bytes,
	# made once and kept, as every raft pod unseals itself with it. UAT ONLY.
	seal_key="$SENSITIVE_DIR/openbao-seal.key"
	[[ -s "$seal_key" ]] || (umask 077 && openssl rand 32 >"$seal_key")
	[[ "$(wc -c <"$seal_key")" -eq 32 ]] || die "$seal_key is not a 32-byte key"
	apply_secret "$CORE_NS" "$OPENBAO_SEAL_SECRET" "seal.key=$seal_key"
	# Versity Gateway's Azure Blob account (uat/tofu object_store; the
	# workflow writes the files, the key masked) and its root credential.
	blob="$SENSITIVE_DIR/azure-blob"
	for f in account-name account-key; do
		[[ -s "$blob/$f" ]] || die "an HA core hub's object store is Versity Gateway over Azure Blob: $blob/$f is missing (uat/tofu outputs object_store and object_store_account_key; README.md, \"HA run\")"
	done
	[[ "$(cat "$blob/account-name")" =~ ^[a-z0-9]{3,24}$ ]] || die "$blob/account-name is not an Azure storage account name"
	apply_secret "$CORE_NS" "$VERSITY_AZURE_SECRET" "account-name=$blob/account-name" "account-key=$blob/account-key"
	vroot="$SENSITIVE_DIR/s3/versity-root"
	(umask 077 && mkdir -p "$vroot")
	printf '%s' "$VERSITY_ROOT_USER" >"$vroot/access-key-id"
	gen_secret_file "$vroot/secret-access-key" 32
	apply_secret "$CORE_NS" "$VERSITY_ROOT_SECRET" \
		"access-key-id=$vroot/access-key-id" "secret-access-key=$vroot/secret-access-key"
fi

# --- 2. seeds and bootstrap admin -------------------------------------------
"$here/seeds.sh" "${common[@]}"
"$here/admin-keys.sh" "${common[@]}" "$release_tag"

# --- 3. the published farmer chart ------------------------------------------
chart_dir="$STATE_DIR/chart"
chart_tgz="$chart_dir/farmer-$version.tgz"
if [[ ! -s "$chart_tgz" ]]; then
	# Exact version, anonymous, no --devel (helm_pull_chart, lib/common.sh).
	helm_pull_chart farmer "$version" "$chart_dir"
fi
chart_meta=$(tar -xzf "$chart_tgz" -O farmer/Chart.yaml)
grep -qx "version: $version" <<<"$chart_meta" || die "$chart_tgz is not chart version $version"
grep -Eqx "appVersion: \"?$version\"?" <<<"$chart_meta" || die "$chart_tgz appVersion is not $version"
# The release's own object store policies: saasapi's recipe user, and the
# log shipper's two users (rustfs-setup.sh reads them side by side).
for p in saasapi-recipes logs-writer logs-retention; do
	tar -xzf "$chart_tgz" -O "farmer/files/objectstore-policies/$p.json" >"$chart_dir/$p.json" ||
		die "$chart_tgz has no files/objectstore-policies/$p.json"
done
# The published chart carries the sprout release finish.sh registers
# (files/sprout-release.json, stamped at release time with the GPG-signed
# checksums.txt and its signature); a chart without it would register
# nothing, so stop here rather than after the whole install.
tar -xzf "$chart_tgz" -O farmer/files/sprout-release.json >"$chart_dir/sprout-release.json" 2>/dev/null ||
	die "$chart_tgz has no files/sprout-release.json: it is not a release-stamped chart (packaging/helm/stamp-sprout-release.sh)"
jq -e --arg v "$release_tag" '.version == $v and (.checksums_txt | type == "string" and length > 0) and (.checksums_sig | type == "string" and length > 0)' \
	"$chart_dir/sprout-release.json" >/dev/null ||
	die "$chart_tgz files/sprout-release.json is not release $release_tag with checksums_txt and checksums_sig"

# --- 4. the UAT-only pieces --------------------------------------------------
log "installing $EXTRAS_RELEASE (RustFS unless external S3, Keycloak, edge proxy, certificates)"
mapfile -t extras_args < <(extras_set_args)
hc upgrade --install "$EXTRAS_RELEASE" "$here/chart" -n "$UAT_NS" --wait --timeout 20m "${extras_args[@]}" >&2 ||
	die "the UAT-only chart did not become ready (kubectl -n $UAT_NS get pods)"
kc -n "$CORE_NS" wait certificate "$FARMER_TLS_SECRET" --for=condition=Ready --timeout=300s >&2
kc -n "$CORE_NS" wait certificate "$OPERATOR_TLS_SECRET" --for=condition=Ready --timeout=300s >&2
kc -n "$UAT_NS" wait certificate imas-uat-edge-tls --for=condition=Ready --timeout=300s >&2

# The UAT CA, from the issued Secret's ca.crt (a public certificate).
kc -n "$CORE_NS" get secret "$FARMER_TLS_SECRET" -o jsonpath='{.data.ca\.crt}' | base64 -d >"$OUT_DIR/uat-ca.crt"
grep -q 'BEGIN CERTIFICATE' "$OUT_DIR/uat-ca.crt" || die "Secret $FARMER_TLS_SECRET has no ca.crt: is $CA_ISSUER a CA issuer?"
cp "$OUT_DIR/uat-ca.crt" "$OUT_DIR/uat-ca.pem" # the name uat/tests reads
kc -n "$CORE_NS" create configmap "$UAT_CA_CONFIGMAP" --from-file="ca.crt=$OUT_DIR/uat-ca.crt" \
	--dry-run=client -o yaml | kc apply -f - >/dev/null

# --- 5. the object store -----------------------------------------------------
if [[ "$S3_MODE" == rustfs ]]; then
	"$here/rustfs-setup.sh" "${common[@]}" "$chart_dir/saasapi-recipes.json"
	"$here/validate-object-store.sh" "${common[@]}"
elif [[ "$S3_MODE" == versity ]]; then
	# Versity Gateway (HA run): the six users' credentials, generated once
	# and kept, in the same files rustfs-setup.sh writes (the accounts
	# reader's at accounts-reader/, for uat/hub/dmz/install.sh
	# --accounts-reader-dir), as the Secrets the farmer chart names. The
	# gateway's init container writes them into its IAM file; its
	# createBuckets Job makes the buckets and the policies that scope each
	# user (design D22). validate-object-store.sh runs after the chart.
	s3dir="$SENSITIVE_DIR/s3"
	(umask 077 && mkdir -p "$s3dir/accounts-reader")
	printf '%s' "$S3_FARMER_USER" >"$s3dir/farmer-access-key-id"
	printf '%s' "$S3_SAASAPI_USER" >"$s3dir/saasapi-access-key-id"
	printf '%s' "$S3_ACCOUNTS_WRITER_USER" >"$s3dir/accounts-writer-access-key-id"
	printf '%s' "$S3_ACCOUNTS_READER_USER" >"$s3dir/accounts-reader/access-key-id"
	printf '%s' "$S3_LOGS_WRITER_USER" >"$s3dir/logs-writer-access-key-id"
	printf '%s' "$S3_LOGS_RETENTION_USER" >"$s3dir/logs-retention-access-key-id"
	for f in farmer-secret-access-key saasapi-secret-access-key accounts-writer-secret-access-key accounts-reader/secret-access-key \
		logs-writer-secret-access-key logs-retention-secret-access-key; do
		gen_secret_file "$s3dir/$f" 24
	done
	apply_secret "$CORE_NS" "$S3_FARMER_SECRET" \
		"access-key-id=$s3dir/farmer-access-key-id" "secret-access-key=$s3dir/farmer-secret-access-key"
	apply_secret "$CORE_NS" "$S3_SAASAPI_SECRET" \
		"access-key-id=$s3dir/saasapi-access-key-id" "secret-access-key=$s3dir/saasapi-secret-access-key"
	apply_secret "$CORE_NS" "$S3_ACCOUNTS_WRITER_SECRET" \
		"access-key-id=$s3dir/accounts-writer-access-key-id" "secret-access-key=$s3dir/accounts-writer-secret-access-key"
	apply_secret "$CORE_NS" "$S3_ACCOUNTS_READER_SECRET" \
		"access-key-id=$s3dir/accounts-reader/access-key-id" "secret-access-key=$s3dir/accounts-reader/secret-access-key"
	apply_secret "$CORE_NS" "$S3_LOGS_WRITER_SECRET" \
		"access-key-id=$s3dir/logs-writer-access-key-id" "secret-access-key=$s3dir/logs-writer-secret-access-key"
	apply_secret "$CORE_NS" "$S3_LOGS_RETENTION_SECRET" \
		"access-key-id=$s3dir/logs-retention-access-key-id" "secret-access-key=$s3dir/logs-retention-secret-access-key"
	log "Versity Gateway users' Secrets applied; accounts reader credential for the DMZ bus: $s3dir/accounts-reader"
else
	# External S3 (object_store.mode external): buckets, users and policies
	# are the operator's. The credential files below are theirs too; they
	# become the five Secrets the farmer chart names. The accounts reader's
	# pair (accounts-reader/) is for the DMZ (uat/hub/dmz/install.sh
	# --accounts-reader-dir) and is only checked here.
	s3dir="$SENSITIVE_DIR/s3"
	for f in farmer- saasapi- accounts-writer- accounts-reader/ logs-writer- logs-retention-; do
		for k in access-key-id secret-access-key; do
			[[ -s "$s3dir/$f$k" ]] || die "object_store.mode is external: $s3dir/$f$k is missing (README.md, \"External S3\")"
		done
	done
	apply_secret "$CORE_NS" "$S3_FARMER_SECRET" \
		"access-key-id=$s3dir/farmer-access-key-id" "secret-access-key=$s3dir/farmer-secret-access-key"
	apply_secret "$CORE_NS" "$S3_SAASAPI_SECRET" \
		"access-key-id=$s3dir/saasapi-access-key-id" "secret-access-key=$s3dir/saasapi-secret-access-key"
	apply_secret "$CORE_NS" "$S3_ACCOUNTS_WRITER_SECRET" \
		"access-key-id=$s3dir/accounts-writer-access-key-id" "secret-access-key=$s3dir/accounts-writer-secret-access-key"
	apply_secret "$CORE_NS" "$S3_LOGS_WRITER_SECRET" \
		"access-key-id=$s3dir/logs-writer-access-key-id" "secret-access-key=$s3dir/logs-writer-secret-access-key"
	apply_secret "$CORE_NS" "$S3_LOGS_RETENTION_SECRET" \
		"access-key-id=$s3dir/logs-retention-access-key-id" "secret-access-key=$s3dir/logs-retention-secret-access-key"
	log "external S3 at $S3_ENDPOINT: Secrets $S3_FARMER_SECRET, $S3_SAASAPI_SECRET, $S3_ACCOUNTS_WRITER_SECRET, $S3_LOGS_WRITER_SECRET and $S3_LOGS_RETENTION_SECRET applied from $s3dir"
fi

# --- 6. the farmer chart, with OpenBao bootstrapped alongside ----------------
gv_args=("$ENDPOINTS" "$OUT_DIR/admin.json" "$release_tag" "$OUT_DIR/$LOADER_PUB_FILE")
((DMZ_NODE_COUNT > 1)) && gv_args+=("$OUT_DIR/$FENCE_PUB_FILE")
"$here/gen-values.sh" "${gv_args[@]}" >"$STATE_DIR/values-run.json"
mapfile -t farmer_values < <(farmer_values_files)
helm_log="$STATE_DIR/helm-install.log"
log "installing $CORE_RELEASE from $chart_tgz (timeout $HELM_TIMEOUT; log $helm_log)"
# No --wait: saasapi starts only once step 7's Secrets exist, and those
# come from this install's own hooks (chart README, "Eval install").
# sproutRelease.register=false: the registration hook POSTs to saasapi, which
# is not Ready until the DMZ bus exists, so finish.sh turns it on afterwards.
hc upgrade --install "$CORE_RELEASE" "$chart_tgz" -n "$CORE_NS" --timeout "$HELM_TIMEOUT" \
	--set sproutRelease.register=false \
	"${farmer_values[@]}" -f "$STATE_DIR/values-run.json" >"$helm_log" 2>&1 &
helm_pid=$!
# farmer's and saasapi's progress deadline, raised to FIRST_START_SECONDS as
# soon as helm creates them (W7, lib/common.sh): a clean first start of
# farmer takes about ten minutes, past the API default of 600 s.
raise_progress_deadlines_as_created "$FIRST_START_SECONDS" &
deadline_pid=$!
trap 'kill "$helm_pid" "$deadline_pid" 2>/dev/null || true' EXIT
if ! "$here/openbao-bootstrap.sh" "${common[@]}"; then
	die "OpenBao bootstrap failed; the farmer install ($helm_log) will time out"
fi
if ! wait "$helm_pid"; then
	kill "$deadline_pid" 2>/dev/null || true
	trap - EXIT
	cat "$helm_log" >&2
	kc -n "$CORE_NS" get jobs,pods >&2 || true
	for j in $(kc -n "$CORE_NS" get jobs -o name 2>/dev/null); do
		log "logs of $j"
		kc -n "$CORE_NS" logs "$j" --all-containers --tail=50 >&2 || true
	done
	die "helm install of $CORE_RELEASE failed (its hooks include the migration, the OpenBao bootstrap, the box keygen and the credential publisher)"
fi
wait "$deadline_pid" || die "could not raise the progress deadline of $FARMER_FULLNAME and $SAASAPI_FULLNAME (see above)"
trap - EXIT
log "helm: $(tail -n 3 "$helm_log" | tr '\n' ' ')"

# The bootstrap hook has run: it wrote the public NATS trust (which the DMZ
# install copies next) and revoked the token it was handed, so the Secret
# holding that token goes (owner decision a: no standing admin). A later
# run without it only checks the trust; install.sh mints a fresh one.
kc -n "$CORE_NS" get configmap "$NATS_TRUST_CONFIGMAP" >/dev/null 2>&1 ||
	die "the farmer install left no ConfigMap $CORE_NS/$NATS_TRUST_CONFIGMAP (the OpenBao bootstrap Job's nats-trust step writes it)"
# Design T4: the first trust is kept, and check.sh fails if a re-run changed it.
if [[ ! -s "$OUT_DIR/nats-trust.json" ]]; then
	trust_snapshot >"$OUT_DIR/nats-trust.json" || die "could not read ConfigMap $CORE_NS/$NATS_TRUST_CONFIGMAP"
fi
kc -n "$CORE_NS" delete secret "$OPENBAO_ROOT_SECRET" --ignore-not-found >/dev/null

# Versity Gateway's buckets and policies exist now (the createBuckets hook
# ran with the install): prove each user's reach through the gateway.
if [[ "$S3_MODE" == versity ]]; then
	rollout "deployment/$VERSITY_FULLNAME" "$CORE_NS"
	"$here/validate-object-store.sh" "${common[@]}"
fi

# --- 7. saasapi's Secrets, and Valkey's password ----------------------------
"$here/saasapi-secrets.sh" "${common[@]}"

# --- 8. wait for every workload ---------------------------------------------
wait_for 600 "OpenBao ($OPENBAO_STS) Ready (unsealed)" sts_ready "$OPENBAO_STS" "$CORE_NS"
wait_for 900 "PXC cluster $PXC_CLUSTER ready" pxc_ready "$PXC_CLUSTER" "$CORE_NS"
wait_for 300 "PXC statefulset $PXC_CLUSTER-pxc" sts_ready "$PXC_CLUSTER-pxc" "$CORE_NS"
wait_for 300 "HAProxy statefulset $PXC_CLUSTER-haproxy" sts_ready "$PXC_CLUSTER-haproxy" "$CORE_NS"
wait_for 600 "Valkey ($VALKEY_NAME) Ready" valkey_ready
# farmer and saasapi are waited for in finish.sh, after the DMZ install.
[[ "$S3_MODE" == rustfs ]] && rollout "deployment/$RUSTFS_SVC" "$UAT_NS"
rollout "deployment/$KEYCLOAK_DEPLOY" "$UAT_NS"
rollout "deployment/$EDGE_DEPLOY" "$UAT_NS"

# --- outputs ---------------------------------------------------------------
# Not secret: names, URLs, the CA certificate, public keys.
prev_tenants=$(jq -c '.tenants // {}' "$OUT_DIR/core.json" 2>/dev/null || echo '{}')
prev_scratch=$(jq -c '.scratch_users // {}' "$OUT_DIR/core.json" 2>/dev/null || echo '{}')
jq -n --arg tag "$release_tag" --arg version "$version" --arg ns "$CORE_NS" --arg rel "$CORE_RELEASE" \
	--arg url "$SAASAPI_URL" --arg ca "$OUT_DIR/uat-ca.crt" --arg issuer "$KEYCLOAK_ISSUER" \
	--arg jwks "$KEYCLOAK_JWKS_URL" --arg token "$KEYCLOAK_TOKEN_URL" --arg realm "$REALM" \
	--arg aud "$SAASAPI_AUDIENCE" --arg client "$TESTS_CLIENT" --arg rr "$READ_ROLE" --arg wr "$WRITE_ROLE" \
	--arg attr "$TENANT_ATTRIBUTE" --arg other "$OTHER_CLIENT" \
	--arg cpn "$CORE_PRIVATE_FQDN" --arg dpn "$DMZ_PRIVATE_FQDN" \
	--arg sens "$SENSITIVE_DIR" --arg bus "$SPROUT_BUS_URL" --argjson tenants "$prev_tenants" \
	--argjson scratch "$prev_scratch" --arg dispatch "$dispatch_flags" \
	--argjson cn "$CORE_NODE_COUNT" --argjson dn "$DMZ_NODE_COUNT" --arg s3 "$S3_MODE" \
	--arg caddr "$CORE_ADDR" --arg daddr "$DMZ_ADDR" --argjson ha "$HA_CORE" --arg valkey "$VALKEY_NAME" \
	--slurpfile admin "$OUT_DIR/admin.json" '{
	  release_tag: $tag, version: $version, namespace: $ns, release: $rel,
	  dispatch_flags: $dispatch,
	  topology: {
	    ha: $ha, core_nodes: $cn, dmz_nodes: $dn,
	    core_address: $caddr, dmz_address: $daddr, object_store: $s3,
	    valkey_primary: (if $ha then ($valkey + "-0") else $valkey end)
	  },
	  saasapi_url: $url, internal_auth_header: "X-Internal-Auth", ca_file: $ca,
	  sprout_bus_url: $bus,
	  private_names: {core: $cpn, dmz: $dpn},
	  keycloak: {issuer: $issuer, jwks_url: $jwks, token_url: $token, realm: $realm,
	             audience: $aud, client_id: $client, read_role: $rr, write_role: $wr,
	             tenant_claim: "organization.id", tenant_attribute: $attr,
	             other_audience_client_id: $other},
	  users: {
	    "t1-admin":  {tenant: "1", roles: [$rr, $wr]},
	    "t1-reader": {tenant: "1", roles: [$rr]},
	    "t2-admin":  {tenant: "2", roles: [$rr, $wr]},
	    "t2-reader": {tenant: "2", roles: [$rr]}
	  },
	  tenants: $tenants,
	  scratch_users: $scratch,
	  bootstrap_admin: $admin[0],
	  sensitive_dir: $sens
	}' >"$OUT_DIR/core.json"

# SENSITIVE: keycloak.json, the shape uat/tests (UAT.5) and uat/enroll
# (UAT.4) read (owner decision 2026-10-06): the issuer, the test client and
# its secret, tenant_attribute (the user attribute the realm maps to
# organization.id), the client whose tokens lack saasapi's audience, and
# each tenant's admin and read-only users. tenants.<n>.tenant_id appears
# once bind-tenant.sh has bound that tenant. No `admin` block: Keycloak's
# admin REST API is not reachable from outside the cluster (README.md,
# "Keycloak, tokens and tenants").
write_keycloak_json "$kcdir" "$SENSITIVE_DIR/keycloak.json"

# SENSITIVE: everything the tests need to act as the BFF, the users and the
# CLI admin, in one file (mode 0600) next to the files it points at.
(umask 077 && jq -n \
	--rawfile ias "$SENSITIVE_DIR/internal-auth-secret" --rawfile cs "$kcdir/tests-client-secret" \
	--rawfile ocs "$kcdir/other-client-secret" \
	--rawfile p1 "$kcdir/t1-admin.password" --rawfile p2 "$kcdir/t1-reader.password" \
	--rawfile p3 "$kcdir/t2-admin.password" --rawfile p4 "$kcdir/t2-reader.password" \
	--rawfile kau "$kcdir/admin-username" --rawfile kap "$kcdir/admin-password" \
	--slurpfile admin "$SENSITIVE_DIR/admin.json" --arg obao "$SENSITIVE_DIR/openbao-init.json" '{
	  note: "SENSITIVE. UAT only, generated for this run. Never commit or upload outside the run.",
	  internal_auth_secret: $ias,
	  keycloak: {client_secret: $cs, other_audience_client_secret: $ocs,
	             passwords: {"t1-admin": $p1, "t1-reader": $p2, "t2-admin": $p3, "t2-reader": $p4},
	             master_admin: {username: $kau, password: $kap}},
	  bootstrap_admin: $admin[0],
	  openbao_init_file: $obao
	}' >"$SENSITIVE_DIR/credentials.json")

log "outputs: $OUT_DIR/core.json (not secret), $SENSITIVE_DIR/keycloak.json and credentials.json and the rest of $SENSITIVE_DIR (SENSITIVE: keep as a sensitive artifact, never upload)"
log "core installed. Next: the DMZ hub, then finish.sh (waits for farmer and saasapi, registers the sprout release, runs check.sh)"

