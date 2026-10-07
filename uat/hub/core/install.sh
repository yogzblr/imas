#!/usr/bin/env bash
# install.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>
#
# Installs the core side of the UAT gate on the uat-core cluster, in order
# (README.md, "What install.sh does"):
#    1. namespaces and the generated credentials (Kubernetes Secrets, and
#       files under <state>/core/sensitive)
#    2. the NATS seeds (seeds.sh) and the bootstrap admin keys
#       (admin-keys.sh, the release's own imas CLI)
#    3. the published farmer chart of release_tag, pulled and checked
#    4. the UAT-only pieces (chart/): MinIO, Keycloak with the imas-uat
#       realm, the edge proxy, certificates, policies
#    5. MinIO buckets, users and policies (minio-setup.sh)
#    6. the farmer chart, with OpenBao initialised and unsealed while the
#       install runs (openbao-bootstrap.sh)
#    7. saasapi's two hand-made Secrets (saasapi-secrets.sh)
#    8. waits for every workload, writes the outputs, runs check.sh
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

log "release $release_tag (chart and images $version); core $CORE_FQDN ($CORE_IP), DMZ $DMZ_FQDN ($DMZ_IP)"
log "issuer $KEYCLOAK_ISSUER; sprout bus URL $SPROUT_BUS_URL"
kc version >/dev/null 2>&1 || die "can't reach the cluster with $KUBECONFIG_PATH"
kc get clusterissuer "$CA_ISSUER" >/dev/null 2>&1 ||
	die "ClusterIssuer $CA_ISSUER not found: the UAT CA (UAT.2) must exist first"

# --- 1. namespaces and generated credentials --------------------------------
ensure_ns "$CORE_NS" "$UAT_NS"

kcdir="$SENSITIVE_DIR/keycloak"
mdir="$SENSITIVE_DIR/minio"
(umask 077 && mkdir -p "$kcdir" "$mdir")
printf '%s' imas-uat-kc-admin >"$kcdir/admin-username"
gen_secret_file "$kcdir/admin-password"
gen_secret_file "$kcdir/tests-client-secret" 32
gen_secret_file "$kcdir/other-client-secret" 32
for u in "${UAT_USERS[@]}"; do gen_secret_file "$kcdir/$u.password"; done
printf '%s' imas-uat-root >"$mdir/root-user"
gen_secret_file "$mdir/root-password" 32
gen_secret_file "$SENSITIVE_DIR/internal-auth-secret" 32

apply_secret "$UAT_NS" "$MINIO_ROOT_SECRET" "user=$mdir/root-user" "password=$mdir/root-password"
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
tar -xzf "$chart_tgz" -O farmer/files/objectstore-policies/saasapi-recipes.json >"$chart_dir/saasapi-recipes.json" ||
	die "$chart_tgz has no files/objectstore-policies/saasapi-recipes.json"

# --- 4. the UAT-only pieces --------------------------------------------------
log "installing $EXTRAS_RELEASE (MinIO, Keycloak, edge proxy, certificates)"
mapfile -t extras_args < <(extras_set_args)
hc upgrade --install "$EXTRAS_RELEASE" "$here/chart" -n "$UAT_NS" --wait --timeout 20m "${extras_args[@]}" >&2 ||
	die "the UAT-only chart did not become ready (kubectl -n $UAT_NS get pods)"
kc -n "$CORE_NS" wait certificate "$FARMER_TLS_SECRET" --for=condition=Ready --timeout=300s >&2
kc -n "$UAT_NS" wait certificate imas-uat-edge-tls --for=condition=Ready --timeout=300s >&2

# The UAT CA, from the issued Secret's ca.crt (a public certificate).
kc -n "$CORE_NS" get secret "$FARMER_TLS_SECRET" -o jsonpath='{.data.ca\.crt}' | base64 -d >"$OUT_DIR/uat-ca.crt"
grep -q 'BEGIN CERTIFICATE' "$OUT_DIR/uat-ca.crt" || die "Secret $FARMER_TLS_SECRET has no ca.crt: is $CA_ISSUER a CA issuer?"
cp "$OUT_DIR/uat-ca.crt" "$OUT_DIR/uat-ca.pem" # the name uat/tests reads
kc -n "$CORE_NS" create configmap "$UAT_CA_CONFIGMAP" --from-file="ca.crt=$OUT_DIR/uat-ca.crt" \
	--dry-run=client -o yaml | kc apply -f - >/dev/null

# --- 5. MinIO ----------------------------------------------------------------
"$here/minio-setup.sh" "${common[@]}" "$chart_dir/saasapi-recipes.json"

# --- 6. the farmer chart, with OpenBao bootstrapped alongside ----------------
"$here/gen-values.sh" "$ENDPOINTS" "$OUT_DIR/admin.json" "$release_tag" >"$STATE_DIR/values-run.json"
helm_log="$STATE_DIR/helm-install.log"
log "installing $CORE_RELEASE from $chart_tgz (timeout $HELM_TIMEOUT; log $helm_log)"
# No --wait: saasapi starts only once step 7's Secrets exist, and those
# come from this install's own hooks (chart README, "Eval install").
hc upgrade --install "$CORE_RELEASE" "$chart_tgz" -n "$CORE_NS" --timeout "$HELM_TIMEOUT" \
	-f "$here/values/farmer-uat.yaml" -f "$STATE_DIR/values-run.json" >"$helm_log" 2>&1 &
helm_pid=$!
trap 'kill "$helm_pid" 2>/dev/null || true' EXIT
if ! "$here/openbao-bootstrap.sh" "${common[@]}"; then
	die "OpenBao bootstrap failed; the farmer install ($helm_log) will time out"
fi
if ! wait "$helm_pid"; then
	trap - EXIT
	cat "$helm_log" >&2
	kc -n "$CORE_NS" get jobs,pods >&2 || true
	for j in $(kc -n "$CORE_NS" get jobs -o name 2>/dev/null); do
		log "logs of $j"
		kc -n "$CORE_NS" logs "$j" --all-containers --tail=50 >&2 || true
	done
	die "helm install of $CORE_RELEASE failed (its hooks include the migration, the OpenBao bootstrap, the box keygen and the credential publisher)"
fi
trap - EXIT
log "helm: $(tail -n 3 "$helm_log" | tr '\n' ' ')"

# --- 7. saasapi's Secrets ----------------------------------------------------
"$here/saasapi-secrets.sh" "${common[@]}"

# --- 8. wait for every workload ---------------------------------------------
wait_for 600 "OpenBao ($OPENBAO_STS) Ready (unsealed)" sts_ready "$OPENBAO_STS" "$CORE_NS"
wait_for 900 "PXC cluster $PXC_CLUSTER ready" pxc_ready "$PXC_CLUSTER" "$CORE_NS"
wait_for 300 "PXC statefulset $PXC_CLUSTER-pxc" sts_ready "$PXC_CLUSTER-pxc" "$CORE_NS"
wait_for 300 "HAProxy statefulset $PXC_CLUSTER-haproxy" sts_ready "$PXC_CLUSTER-haproxy" "$CORE_NS"
rollout "deployment/$VALKEY_DEPLOY" "$CORE_NS"
rollout "deployment/$FARMER_FULLNAME" "$CORE_NS" 900s
rollout "deployment/$SAASAPI_FULLNAME" "$CORE_NS" 900s
rollout "deployment/$MINIO_SVC" "$UAT_NS"
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
	--argjson scratch "$prev_scratch" \
	--slurpfile admin "$OUT_DIR/admin.json" '{
	  release_tag: $tag, version: $version, namespace: $ns, release: $rel,
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
if [[ "${SKIP_CHECK:-}" != 1 ]]; then
	"$here/check.sh" "${common[@]}"
fi
