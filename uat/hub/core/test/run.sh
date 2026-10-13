#!/usr/bin/env bash
# test/run.sh: the static checks and script tests for uat/hub/core. No
# cluster, registry or cloud is needed.
#   1. shellcheck on every script and stub
#   2. yamllint on the values files, the chart metadata and the rendered
#      UAT chart
#   3. the realm file's jq checks (check-realm.sh)
#   4. gen-values.sh and lib/common.sh input handling
#   5. seeds.sh against a stub kubectl (real nk, built from go.mod): the
#      user seeds SYS_USER and SAASAPI_USER (Secret imas-farmer-nats-seeds),
#      farmer's NKey (Secret imas-farmer-nkey) and the DMZ bus loader's
#      seed (a file only) with its public key; with three DMZ nodes also the
#      clustered bus's fence user seed
#   6. admin-keys.sh against a stub curl and a fake imas CLI (checksum
#      check, key reuse, file modes)
#   7. bind-tenant.sh, token.sh and install.sh argument checks
#      (7c: helm_pull_chart, the oci:// chart pull, against a stub helm)
#   8. openbao-bootstrap.sh, saasapi-secrets.sh and the T4 probe
#      (openbao_t4) against a real local OpenBao server, when a bao binary
#      is on PATH or in $BAO_BIN (skipped, and said so, otherwise)
#   8a. openbao-bootstrap.sh on an HA core hub (static seal, three raft
#      pods) against three real local OpenBao servers, when bao is there
#   8b. finish.sh and operator-release.sh against stub kubectl, helm and
#      curl (test/finish_test.sh): a failed registration Job fails it, and
#      the operator API's answer decides; validate-object-store.sh against a
#      curl that answers with the UAT policies, for RustFS and for Versity
#      Gateway (test/object_store_test.sh)
#   9. go test ./uat/hub/core/ (helm template and lint of the farmer chart
#      with values/farmer-uat.yaml, and of chart/)
# A tool that isn't installed is reported as SKIPPED, never as passed.
# The checks below use `test && ok || bad` on purpose: ok and bad always
# return 0, so bad runs only when the test fails.
# shellcheck disable=SC2015
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
core=$(cd "$here/.." && pwd)
repo=$(cd "$core/../../.." && pwd)
tmp=$(mktemp -d)
bao_pid=""
cleanup() {
	[[ -z "$bao_pid" ]] || kill "$bao_pid" 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT

failed=0 skipped=()
ok() { printf 'ok    %s\n' "$1"; }
bad() {
	printf 'FAIL  %s\n' "$1"
	failed=$((failed + 1))
}
skip() {
	printf 'SKIP  %s\n' "$1"
	skipped+=("$1")
}
# expect <description> <command...>: must succeed.
expect() {
	local d="$1"
	shift
	if "$@" >"$tmp/out" 2>&1; then ok "$d"; else
		bad "$d"
		sed 's/^/      /' "$tmp/out" | tail -n 20
	fi
}
# refuse <description> <message regex> <command...>: must fail, saying so.
refuse() {
	local d="$1" re="$2"
	shift 2
	if "$@" >"$tmp/out" 2>&1; then
		bad "$d (succeeded)"
	elif grep -Eq -- "$re" "$tmp/out"; then ok "$d"; else
		bad "$d (wrong message)"
		sed 's/^/      /' "$tmp/out" | tail -n 5
	fi
}

stubs="$here/stubs"
export STUB_STATE="$tmp/stub"
mkdir -p "$STUB_STATE"
kubeconfig="$tmp/kubeconfig"
echo "apiVersion: v1" >"$kubeconfig"
ep="$core/testdata/endpoints.json"
ep2="$core/testdata/endpoints-overrides.json"

# --- 1. shellcheck --------------------------------------------------------------
if command -v shellcheck >/dev/null; then
	expect "shellcheck" bash -c 'cd "$1" && shellcheck -x ./*.sh lib/common.sh test/*.sh test/stubs/* test/finish-stubs/* test/object-store-stubs/*' _ "$core"
else
	skip "shellcheck (not installed)"
fi

# --- 2. yamllint ----------------------------------------------------------------
if command -v yamllint >/dev/null; then
	expect "yamllint values and chart metadata" yamllint -c "$here/yamllint.yaml" \
		"$core/values/farmer-uat.yaml" "$core/values/values-ha.yaml" "$core/chart/Chart.yaml" "$core/chart/values.yaml"
	if command -v helm >/dev/null; then
		helm template imas-uat-core "$core/chart" -n imas-uat --kube-version 1.31.0 >"$tmp/extras.yaml" 2>"$tmp/out" &&
			expect "yamllint rendered UAT chart" yamllint -c "$here/yamllint.yaml" "$tmp/extras.yaml" ||
			bad "helm template chart/"
		# The HA render (one edge per node, the accounts store through the
		# edge to Versity Gateway), with lib/common.sh's flags for it.
		mapfile -t ha_set < <(bash -c '. "$1/lib/common.sh"; ENDPOINTS="$2"; load_endpoints; extras_set_args' _ "$core" "$repo/uat/k0s/testdata/expected/endpoints-ha.json")
		helm template imas-uat-core "$core/chart" -n imas-uat --kube-version 1.31.0 "${ha_set[@]}" >"$tmp/extras-ha.yaml" 2>"$tmp/out" &&
			expect "yamllint rendered UAT chart (HA)" yamllint -c "$here/yamllint.yaml" "$tmp/extras-ha.yaml" ||
			bad "helm template chart/ (HA)"
	fi
else
	skip "yamllint (not installed)"
fi

# --- 3. realm --------------------------------------------------------------------
expect "realm jq checks" "$here/check-realm.sh"

# --- 4. gen-values and endpoints --------------------------------------------------
admin="$core/testdata/admin.json"
loader_pub="$core/testdata/bus-loader-user.pub"
gv() { "$core/gen-values.sh" "$@" "$loader_pub"; }
if gv "$ep" "$admin" v0.1.0-rc.4 >"$tmp/v1.json" 2>"$tmp/out"; then
	ok "gen-values.sh renders the contract's endpoints"
	jq -e '
	  .saasapi.jwt.issuer == "https://uatabc123-core.centralindia.cloudapp.azure.com/realms/imas-uat"
	  and .saasapi.jwt.keycloakJWKSURL == .saasapi.jwt.issuer + "/protocol/openid-connect/certs"
	  and .saasapi.jwt.audience == "imas-saasapi"
	  and .bus.sproutBusURLs == ["wss://dmz.uat.imas.internal:8443/"]
	  and .bus.host == "dmz.uat.imas.internal" and .bus.egressCIDRs == ["10.60.1.4/32"] and .bus.port == 8442
	  and (.bus | has("serviceName") | not)
	  and .farmer.image.tag == "0.1.0-rc.4" and .saasapi.image.tag == "0.1.0-rc.4"
	  and .database.migrate.image.tag == "0.1.0-rc.4"
	  and .farmer.bootstrapAdmin.pubkey == "AC4LMP7I2FYLWGY5GIB52A4XCFFFSB2QTZ65B3A4G6OK5GYWRJSKH74C"
	  and .farmer.bootstrapAdmin.username == "uat-admin"
	  and .natsTrust.busLoaderUserPub == $lp' --arg lp "$(cat "$loader_pub")" "$tmp/v1.json" >/dev/null &&
		ok "gen-values.sh: issuer, JWKS, audience, bus, tags, admin and loader key" ||
		bad "gen-values.sh: issuer, JWKS, audience, bus, tags, admin and loader key"
else
	bad "gen-values.sh renders the contract's endpoints"
fi
gv "$ep2" "$admin" v1.2.3 >"$tmp/v2.json" 2>/dev/null &&
	jq -e '.saasapi.jwt.issuer == "https://core.imas-uat.test:30444/realms/imas-uat"
	  and .bus.sproutBusURLs == ["wss://dmz.rig.test:30443/"] and .bus.host == "dmz.rig.test" and .bus.egressCIDRs == ["172.18.0.2/32"] and .bus.port == 30406
	  and .farmer.image.tag == "1.2.3"' "$tmp/v2.json" >/dev/null &&
	ok "gen-values.sh: port and name overrides, non-443 issuer keeps the port" ||
	bad "gen-values.sh: port and name overrides"
jq -e '.farmer.selfUpdate.enabled == false and .saasapi.fleetUpdateDispatch.enabled == false' "$tmp/v1.json" >/dev/null &&
	ok "gen-values.sh: dispatch flags off by default" || bad "gen-values.sh: dispatch flags off by default"
IMAS_UAT_DISPATCH_FLAGS=on gv "$ep" "$admin" v1.2.3 2>/dev/null |
	jq -e '.farmer.selfUpdate.enabled == true and .saasapi.fleetUpdateDispatch.enabled == true' >/dev/null &&
	ok "gen-values.sh: IMAS_UAT_DISPATCH_FLAGS=on turns both flags on" || bad "gen-values.sh: IMAS_UAT_DISPATCH_FLAGS=on"
IMAS_UAT_DISPATCH_FLAGS=off gv "$ep" "$admin" v1.2.3 2>/dev/null |
	jq -e '.farmer.selfUpdate.enabled == false and .saasapi.fleetUpdateDispatch.enabled == false' >/dev/null &&
	ok "gen-values.sh: IMAS_UAT_DISPATCH_FLAGS=off keeps both off" || bad "gen-values.sh: IMAS_UAT_DISPATCH_FLAGS=off"
refuse "gen-values.sh: an unknown IMAS_UAT_DISPATCH_FLAGS is refused" "must be on or off" \
	env IMAS_UAT_DISPATCH_FLAGS=maybe "$core/gen-values.sh" "$ep" "$admin" v1.2.3 "$loader_pub"
# status_line: check.sh's "must refuse" checks compare status and error code.
sl() { printf '%s' "$2" >"$tmp/body"; bash -c '. "$1/lib/common.sh"; status_line "$2" "$3"' _ "$core" "$1" "$tmp/body"; }
[[ "$(sl 401 '{"error":"unauthorized","message":"unauthorized"}')" == "401 unauthorized" ]] &&
	[[ "$(sl 403 '{"error":"forbidden","message":"forbidden"}')" == "403 forbidden" ]] &&
	[[ "$(sl 200 '{"versions":[]}')" == 200 ]] &&
	[[ "$(sl 401 '<html>401 Authorization Required</html>')" == 401 ]] &&
	[[ "$(sl 401 '')" == 401 ]] &&
	[[ "$(sl 401 '{"error":"Bad Thing; rm -rf"}')" == 401 ]] &&
	ok "status_line: saasapi's error code after the status, nothing for any other body" || bad "status_line"
# The two readers spell the issuer and the private names differently
# (uat/hub/dmz: cluster_issuer, private_dns_zone; uat/hub/core: ca.cluster_issuer,
# *.private_fqdn). An endpoints file with only one form must give the same
# values here, and the bus host is the DMZ private name in every case.
readvals() { bash -c '. "$1/lib/common.sh"; ENDPOINTS="$2"; load_endpoints; printf "%s %s %s" "$CA_ISSUER" "$DMZ_PRIVATE_FQDN" "$CORE_PRIVATE_FQDN"' _ "$core" "$1"; }
jq '. + {cluster_issuer: "dmz-form-ca", private_dns_zone: "zone.test"}' "$ep" >"$tmp/form-dmz.json"
[[ "$(readvals "$tmp/form-dmz.json" 2>&1)" == "dmz-form-ca dmz.zone.test core.zone.test" ]] &&
	ok "endpoints with only cluster_issuer and private_dns_zone are read" || bad "endpoints with only the dmz-form keys"
jq '. + {ca: {cluster_issuer: "core-form-ca"}} | .dmz.private_fqdn = "dmz.core-form.test" | .core.private_fqdn = "core.core-form.test"' "$ep" >"$tmp/form-core.json"
[[ "$(readvals "$tmp/form-core.json" 2>&1)" == "core-form-ca dmz.core-form.test core.core-form.test" ]] &&
	ok "endpoints with only ca.cluster_issuer and *.private_fqdn are read" || bad "endpoints with only the core-form keys"
jq '. + {cluster_issuer: "dmz-form-ca", ca: {cluster_issuer: "core-form-ca"}, private_dns_zone: "zone.test"} | .dmz.private_fqdn = "dmz.explicit.test"' "$ep" >"$tmp/form-both.json"
[[ "$(readvals "$tmp/form-both.json" 2>&1)" == "core-form-ca dmz.explicit.test core.zone.test" ]] &&
	ok "ca.cluster_issuer and an explicit private_fqdn win over the other form" || bad "endpoints with both forms"
[[ "$(readvals "$ep" 2>&1)" == "imas-uat-ca dmz.uat.imas.internal core.uat.imas.internal" ]] &&
	ok "endpoints with neither form get the defaults" || bad "endpoints with neither form"
gv "$tmp/form-dmz.json" "$admin" v0.1.0 2>/dev/null | jq -e '.bus.host == "dmz.zone.test"' >/dev/null &&
	ok "gen-values.sh: bus.host follows the zone form" || bad "gen-values.sh: bus.host with the zone form"
refuse "release_tag latest is refused" "never latest" gv "$ep" "$admin" latest
refuse "release_tag without v is refused" "vX.Y.Z" gv "$ep" "$admin" 0.1.0
refuse "release_tag with a build suffix is refused" "vX.Y.Z" gv "$ep" "$admin" v0.1.0-beta.1
jq '.core.fqdn = "bad_name"' "$ep" >"$tmp/bad-fqdn.json"
refuse "a malformed core FQDN is refused" "core.fqdn" gv "$tmp/bad-fqdn.json" "$admin" v0.1.0
jq '.dmz.private_ip = "10.60.1.400"' "$ep" >"$tmp/bad-ip.json"
refuse "a malformed DMZ IP is refused" "dmz.private_ip" gv "$tmp/bad-ip.json" "$admin" v0.1.0
jq 'del(.core.fqdn)' "$ep" >"$tmp/no-fqdn.json"
refuse "a missing core FQDN is refused" "no .core.fqdn" gv "$tmp/no-fqdn.json" "$admin" v0.1.0
jq '.core.exposure = "nodePort"' "$ep" >"$tmp/bad-exp.json"
refuse "the dropped core node port mode is refused" "core.exposure must be hostPort" gv "$tmp/bad-exp.json" "$admin" v0.1.0
jq '.dmz.private_fqdn = "-bad-"' "$ep" >"$tmp/bad-pfqdn.json"
refuse "a malformed private name is refused" "dmz.private_fqdn" gv "$tmp/bad-pfqdn.json" "$admin" v0.1.0
jq '.boxpub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="' "$admin" >"$tmp/zero-admin.json"
refuse "the chart's all-zero placeholder admin key is refused" "placeholder" gv "$ep" "$tmp/zero-admin.json" v0.1.0
jq '.pubkey = "not-a-key"' "$admin" >"$tmp/bad-admin.json"
refuse "a malformed admin pubkey is refused" "NKey" gv "$ep" "$tmp/bad-admin.json" v0.1.0
printf 'SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >"$tmp/seed-as-pub"
refuse "a loader key that is not a user public key is refused" "not an NKey user public key" \
	"$core/gen-values.sh" "$ep" "$admin" v0.1.0 "$tmp/seed-as-pub"
refuse "gen-values.sh needs the loader key file" "usage: gen-values.sh" "$core/gen-values.sh" "$ep" "$admin" v0.1.0

# keycloak.json: the shape uat/tests and uat/enroll read (owner decision
# 2026-10-06), mode 0600, bound tenant_ids kept on a rewrite.
kcd="$tmp/kc"
(umask 077 && mkdir -p "$kcd")
for f in tests-client-secret other-client-secret t1-admin.password t1-reader.password t2-admin.password t2-reader.password; do
	printf 'secret-%s' "$f" >"$kcd/$f"
done
wkj() { bash -c '. "$1/lib/common.sh"; ENDPOINTS="$2"; load_endpoints; write_keycloak_json "$3" "$4"' _ "$core" "$ep" "$kcd" "$tmp/keycloak.json"; }
if wkj 2>"$tmp/out"; then
	jq -e '.issuer == "https://uatabc123-core.centralindia.cloudapp.azure.com/realms/imas-uat"
	  and .client_id == "imas-uat-tests" and .client_secret == "secret-tests-client-secret"
	  and .tenant_attribute == "organization_id"
	  and .other_audience_client == {client_id: "imas-uat-other-audience", client_secret: "secret-other-client-secret"}
	  and .tenants["1"] == {admin: {username: "t1-admin", password: "secret-t1-admin.password"}, readonly: {username: "t1-reader", password: "secret-t1-reader.password"}}
	  and .tenants["2"].admin.username == "t2-admin" and .tenants["2"].readonly.username == "t2-reader"
	  and (has("admin") | not)' "$tmp/keycloak.json" >/dev/null &&
		ok "keycloak.json: issuer, clients, tenant_attribute, users, no admin block" || bad "keycloak.json shape"
	[[ "$(stat -c %a "$tmp/keycloak.json")" == 600 ]] && ok "keycloak.json is 0600" || bad "keycloak.json mode"
	jq '.tenants["2"].tenant_id = "t_abcdefghijklmnop"' "$tmp/keycloak.json" >"$tmp/kj" && cp "$tmp/kj" "$tmp/keycloak.json"
	wkj && jq -e '.tenants["2"].tenant_id == "t_abcdefghijklmnop" and (.tenants["1"] | has("tenant_id") | not)' "$tmp/keycloak.json" >/dev/null &&
		ok "keycloak.json: a rewrite keeps the bound tenant_id" || bad "keycloak.json: rewrite lost tenant_id"
else
	bad "write_keycloak_json"
	sed 's/^/      /' "$tmp/out"
fi
refuse "token.sh refuses an unknown client" "tests or other" \
	"$core/token.sh" "$kubeconfig" "$ep" "$tmp/s" t1-admin admin-cli

# --- 5. seeds.sh --------------------------------------------------------------------
state="$tmp/state"
seeds() { PATH="$stubs:$PATH" "$core/seeds.sh" "$kubeconfig" "$ep" "$state"; }
if command -v go >/dev/null; then
	if seeds >"$tmp/out" 2>&1; then
		ok "seeds.sh generates the user seeds with nk"
		sd="$state/core/sensitive/seeds"
		all_seeds=(sys-user.nk saasapi-user.nk farmer.nk bus-loader-user.nk)
		good=1
		for k in "${all_seeds[@]}"; do
			[[ "$(cat "$sd/$k")" =~ ^SU[A-Z2-7]{56}$ ]] || good=0
			[[ "$(stat -c %a "$sd/$k")" == 600 ]] || good=0
		done
		[[ "$(for f in "$sd"/*.nk; do cat "$f"; echo; done | sort -u | wc -l)" -eq 4 ]] || good=0
		[[ "$(wc -c <"$sd/sys-user.nk")" -eq 58 ]] || good=0
		((good)) && ok "seeds: four user seeds, distinct, mode 0600, no newline" || bad "seeds: types, distinctness or modes"
		[[ -z "$(find "$sd" -name '*.nk' ! -name sys-user.nk ! -name saasapi-user.nk ! -name farmer.nk ! -name bus-loader-user.nk)" ]] &&
			ok "seeds: no trust chain seed generated (P21 slice 1: those are Transit keys)" || bad "seeds: a removed seed was generated"
		[[ "$(stat -c %a "$state/core/sensitive")" == 700 ]] && ok "sensitive dir is 0700" || bad "sensitive dir is 0700"
		sec="$STUB_STATE/imas-core/Secret/imas-farmer-nats-seeds.json"
		jq -e --arg su "$(base64 -w0 <"$sd/sys-user.nk")" '(.data | keys | sort) == ["saasapi-user.nk","sys-user.nk"] and .data["sys-user.nk"] == $su' "$sec" >/dev/null &&
			ok "seeds: Secret imas-core/imas-farmer-nats-seeds holds exactly the two files" || bad "seeds: Secret content"
		nksec="$STUB_STATE/imas-core/Secret/imas-farmer-nkey.json"
		jq -e --arg fk "$(base64 -w0 <"$sd/farmer.nk")" '(.data | keys) == ["farmer.nk"] and .data["farmer.nk"] == $fk' "$nksec" >/dev/null &&
			ok "seeds: Secret imas-core/imas-farmer-nkey holds farmer.nk only (farmer.nkeySecret)" || bad "seeds: farmer NKey Secret content"
		! grep -rqF "$(base64 -w0 <"$sd/bus-loader-user.nk")" "$STUB_STATE/imas-core" &&
			ok "seeds: the loader seed is in no core Secret (it goes to the DMZ)" || bad "seeds: the loader seed reached a core Secret"
		lpub="$state/core/out/bus-loader-user.pub"
		[[ -s "$lpub" && "$(cat "$lpub")" == "$("$state/core/bin/nk" -inkey "$sd/bus-loader-user.nk" -pubout)" && "$(cat "$lpub")" =~ ^U[A-Z2-7]{55}$ ]] &&
			ok "seeds: out/bus-loader-user.pub is the loader seed's public key" || bad "seeds: loader public key file"
		! grep -q 'S[OAU][A-Z2-7]\{56\}' "$STUB_STATE/calls.log" && ok "seeds: no seed in any kubectl argument" || bad "seeds: a seed reached argv"
		expect "seeds.sh again: existing Secrets match, nothing replaced" seeds
		cp "$sd/sys-user.nk" "$tmp/sys-user.nk"
		rm "$sd/sys-user.nk"
		expect "seeds.sh restores a missing local seed from the Secret" seeds
		cmp -s "$sd/sys-user.nk" "$tmp/sys-user.nk" && ok "seeds: restored seed is byte-identical" || bad "seeds: restored seed differs"
		cp "$sd/farmer.nk" "$tmp/farmer.nk"
		rm "$sd/farmer.nk"
		expect "seeds.sh restores farmer.nk from imas-farmer-nkey" seeds
		cmp -s "$sd/farmer.nk" "$tmp/farmer.nk" && ok "seeds: restored farmer.nk is byte-identical" || bad "seeds: restored farmer.nk differs"
		printf 'SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >"$sd/sys-user.nk"
		refuse "seeds.sh refuses to replace an existing install's seeds" "refusing to replace" seeds
		cp "$tmp/sys-user.nk" "$sd/sys-user.nk"
		printf 'SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >"$sd/farmer.nk"
		refuse "seeds.sh refuses to replace an existing farmer NKey" "farmer.nk in .* differs from Secret imas-core/imas-farmer-nkey" seeds
		cp "$tmp/farmer.nk" "$sd/farmer.nk"
		# A cluster installed before imas-farmer-nkey existed: the seeds
		# Secret is kept as is and the farmer NKey Secret is created.
		rm "$nksec" "$sd/farmer.nk"
		cp "$sec" "$tmp/seeds-secret.json"
		expect "seeds.sh adds imas-farmer-nkey to an install that has only the seeds Secret" seeds
		[[ -s "$nksec" ]] && cmp -s "$sec" "$tmp/seeds-secret.json" &&
			ok "seeds: imas-farmer-nkey created, imas-farmer-nats-seeds untouched" || bad "seeds: adding imas-farmer-nkey"
		# The loader seed once the trust names it (bus-loader-user.jwt):
		# kept, a missing one refused, one for another key refused.
		b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
		ljwt="$(printf '{"alg":"ed25519-nkey"}' | b64url).$(jq -nc --arg s "$(cat "$lpub")" '{sub: $s}' | b64url).c2ln"
		mkdir -p "$STUB_STATE/imas-core/ConfigMap"
		jq -n --arg j "$ljwt" '{kind:"ConfigMap",metadata:{name:"imas-nats-trust",namespace:"imas-core"},data:{"bus-loader-user.jwt":$j}}' \
			>"$STUB_STATE/imas-core/ConfigMap/imas-nats-trust.json"
		expect "seeds.sh with a trust naming this loader: seed kept" seeds
		cp "$sd/bus-loader-user.nk" "$tmp/loader.nk"
		rm "$sd/bus-loader-user.nk"
		refuse "seeds.sh refuses to regenerate a loader seed the trust already names" "restore the seed .*never regenerate" seeds
		[[ ! -e "$sd/bus-loader-user.nk" ]] && ok "seeds: no new loader seed written" || bad "seeds: a new loader seed was written"
		"$state/core/bin/nk" -gen user | tr -d '\n' >"$sd/bus-loader-user.nk"
		chmod 600 "$sd/bus-loader-user.nk"
		refuse "seeds.sh refuses a loader seed for another key than the trust's" "refusing a seed the bus would not accept" seeds
		cp "$tmp/loader.nk" "$sd/bus-loader-user.nk"
		expect "seeds.sh with the restored loader seed" seeds
		rm "$STUB_STATE/imas-core/ConfigMap/imas-nats-trust.json"
		# A seed directory that already holds one seed: it is kept, the
		# others generated.
		state2="$tmp/state2" shared="$tmp/shared-seeds"
		(umask 077 && mkdir -p "$shared" && cp "$sd/sys-user.nk" "$shared/")
		rm -rf "$STUB_STATE/imas-core"
		if UAT_SEEDS_DIR="$shared" PATH="$stubs:$PATH" "$core/seeds.sh" "$kubeconfig" "$ep" "$state2" >"$tmp/out" 2>&1 &&
			cmp -s "$shared/sys-user.nk" "$sd/sys-user.nk" && [[ $(find "$shared" -name '*.nk' | wc -l) -eq 4 ]]; then
			ok "seeds: UAT_SEEDS_DIR seeds are reused, missing ones generated"
		else
			bad "seeds: UAT_SEEDS_DIR reuse"
		fi
		[[ ! -e "$state/core/out/bus-fence-user.pub" && ! -e "$sd/bus-fence-user.nk" ]] &&
			ok "seeds: one DMZ node, no fence user seed" || bad "seeds: a fence user seed for a single-node bus"
		# Three DMZ nodes (uat/k0s's HA endpoints): a clustered bus's fence
		# user, a file only, its public key next to the loader's.
		rm -rf "$STUB_STATE/imas-core"
		state3="$tmp/state3"
		if PATH="$stubs:$PATH" "$core/seeds.sh" "$kubeconfig" "$repo/uat/k0s/testdata/expected/endpoints-ha.json" "$state3" >"$tmp/out" 2>&1; then
			sd3="$state3/core/sensitive/seeds"
			fpub="$state3/core/out/bus-fence-user.pub"
			[[ -s "$sd3/bus-fence-user.nk" && "$(stat -c %a "$sd3/bus-fence-user.nk")" == 600 &&
				"$(cat "$fpub")" == "$("$state3/core/bin/nk" -inkey "$sd3/bus-fence-user.nk" -pubout)" &&
				"$(cat "$fpub")" != "$(cat "$state3/core/out/bus-loader-user.pub")" ]] &&
				ok "seeds: three DMZ nodes, a fence user seed (0600) and its own public key" || bad "seeds: fence user seed"
			! grep -rqF "$(base64 -w0 <"$sd3/bus-fence-user.nk")" "$STUB_STATE/imas-core" &&
				ok "seeds: the fence seed is in no core Secret (it goes to the DMZ)" || bad "seeds: the fence seed reached a core Secret"
			IMAS_FENCE_PUB=$(cat "$fpub")
			"$core/gen-values.sh" "$repo/uat/k0s/testdata/expected/endpoints-ha.json" "$admin" v0.1.0 \
				"$state3/core/out/bus-loader-user.pub" "$fpub" 2>/dev/null |
				jq -e --arg f "$IMAS_FENCE_PUB" '.natsTrust.busFenceUserPub == $f and .bus.expectedNodes == 3' >/dev/null &&
				ok "gen-values.sh (HA): the fence user's key and three expected bus nodes" || bad "gen-values.sh (HA) with seeds.sh's keys"
		else
			bad "seeds.sh with three DMZ nodes"
			sed 's/^/      /' "$tmp/out" | tail -n 10
		fi
	else
		bad "seeds.sh generates the user seeds with nk"
		sed 's/^/      /' "$tmp/out" | tail -n 10
	fi
else
	skip "seeds.sh (go not installed: nk is built from go.mod)"
fi

# --- 6. admin-keys.sh ----------------------------------------------------------------
rel="$tmp/release"
mkdir -p "$rel/pack"
cp "$stubs/fake-imas" "$rel/pack/imas-0.9.9-linux-amd64"
case "$(uname -m)" in aarch64 | arm64) cp "$stubs/fake-imas" "$rel/pack/imas-0.9.9-linux-arm64" ;; esac
arch=amd64
[[ "$(uname -m)" == aarch64 || "$(uname -m)" == arm64 ]] && arch=arm64
tar -czf "$rel/imas-0.9.9-linux-$arch.tar.gz" -C "$rel/pack" "imas-0.9.9-linux-$arch"
(cd "$rel" && sha256sum "imas-0.9.9-linux-$arch.tar.gz" >checksums.txt)
akeys() { FAKE_RELEASE_DIR="$rel" PATH="$stubs:$PATH" "$core/admin-keys.sh" "$kubeconfig" "$ep" "$1" v0.9.9; }
if akeys "$tmp/a1" >"$tmp/out" 2>&1; then
	ok "admin-keys.sh: downloads, verifies and runs the release CLI"
	jq -e '.pubkey == "AC4LMP7I2FYLWGY5GIB52A4XCFFFSB2QTZ65B3A4G6OK5GYWRJSKH74C" and .boxpub == "Go0DiL9Y7s+Dp1mSizpp9n5xXuotDZzeqF6iGfIyt1c=" and .username == "uat-admin" and .cli_release == "v0.9.9"' \
		"$tmp/a1/core/out/admin.json" >/dev/null && ok "admin-keys.sh: public admin.json" || bad "admin-keys.sh: public admin.json"
	! grep -q SUFAKEPRIVATE "$tmp/a1/core/out/admin.json" "$tmp/a1/core/sensitive/admin.json" && ok "admin-keys.sh: no private key in either admin.json" || bad "admin-keys.sh: private key leaked into admin.json"
	h="$tmp/a1/core/sensitive/admin-home/.config/imas"
	[[ "$(stat -c %a "$h/imas")" == 600 && "$(stat -c %a "$h/cli-box.key")" == 600 && "$(stat -c %a "$tmp/a1/core/sensitive/admin.json")" == 600 ]] &&
		ok "admin-keys.sh: CLI config, box key and sensitive admin.json are 0600" || bad "admin-keys.sh: file modes"
	expect "admin-keys.sh again reuses the keys" akeys "$tmp/a1"
	[[ $(grep -c privkey "$h/imas") -eq 1 ]] && ok "admin-keys.sh: no second privkey on a re-run" || bad "admin-keys.sh: re-run made a new key"
else
	bad "admin-keys.sh: downloads, verifies and runs the release CLI"
	sed 's/^/      /' "$tmp/out" | tail -n 10
fi
printf '%s  imas-0.9.9-linux-%s.tar.gz\n' "$(printf '0%.0s' {1..64})" "$arch" >"$rel/checksums.txt"
refuse "admin-keys.sh refuses an archive that doesn't match checksums.txt" "does not match checksums.txt" akeys "$tmp/a2"
: >"$rel/checksums.txt"
refuse "admin-keys.sh refuses a release with no checksum for the archive" "no entry" akeys "$tmp/a3"
refuse "admin-keys.sh refuses release_tag latest" "never latest" \
	env FAKE_RELEASE_DIR="$rel" PATH="$stubs:$PATH" "$core/admin-keys.sh" "$kubeconfig" "$ep" "$tmp/a4" latest

# --- 7. argument checks ----------------------------------------------------------------
refuse "every script needs its three common inputs" "usage" "$core/install.sh" "$kubeconfig"
refuse "a missing kubeconfig is refused" "kubeconfig not found" "$core/check.sh" "$tmp/nope" "$ep" "$tmp/s"
refuse "a missing endpoints file is refused" "endpoints file not found" "$core/check.sh" "$kubeconfig" "$tmp/nope" "$tmp/s"
echo '[1,2]' >"$tmp/array.json"
refuse "an endpoints file that is not an object is refused" "not a JSON object" "$core/check.sh" "$kubeconfig" "$tmp/array.json" "$tmp/s"
refuse "install.sh needs release_tag" "usage" "$core/install.sh" "$kubeconfig" "$ep" "$tmp/s"
refuse "install.sh refuses release_tag latest" "never latest" "$core/install.sh" "$kubeconfig" "$ep" "$tmp/s" latest
refuse "bind-tenant.sh refuses a malformed tenant_id" "not a saasapi tenant_id" \
	"$core/bind-tenant.sh" "$kubeconfig" "$ep" "$tmp/s" 1 "t_UPPERCASE123456"
refuse "bind-tenant.sh refuses tenant 3" "must be 1 or 2" \
	"$core/bind-tenant.sh" "$kubeconfig" "$ep" "$tmp/s" 3 t_abcdefghijklmnop
refuse "token.sh refuses an unknown user" "unknown UAT user" \
	"$core/token.sh" "$kubeconfig" "$ep" "$tmp/s" root

# --- 7b. bind-tenant.sh against a fake kcadm.sh ------------------------------------
bstate="$tmp/bstate"
bsens="$bstate/core/sensitive"
(umask 077 && mkdir -p "$bsens/keycloak" "$bstate/core/out")
printf 'imas-uat-kc-admin' >"$bsens/keycloak/admin-username"
printf 'KCADMINPASSWORD0123' >"$bsens/keycloak/admin-password"
echo '{"tenants": {}}' >"$bstate/core/out/core.json"
(umask 077 && jq -n '{tenants: {"1": {admin: {username: "t1-admin"}}, "2": {admin: {username: "t2-admin"}}}}' >"$bsens/keycloak.json")
jq -n '{users: [ "t1-admin", "t1-reader", "t2-admin", "t2-reader" | {id: ("id-" + .), username: ., attributes: {}, roles: []}]}' >"$STUB_STATE/kc-users.json"
: >"$STUB_STATE/kcadm-argv.log"
bt() { UAT_KCADM="$stubs/fake-kcadm" PATH="$stubs:$PATH" "$core/bind-tenant.sh" "$kubeconfig" "$ep" "$bstate" "$@"; }
users() { jq -c "$1" "$STUB_STATE/kc-users.json"; }
T1=t_aaaaaaaaaaaaaaaa T2=t_bbbbbbbbbbbbbbbb T9=t_cccccccccccccccc
expect "bind-tenant.sh binds tenant 1" bt 1 "$T1"
[[ "$(users '[.users[] | select(.username | startswith("t1-")) | .attributes.organization_id[0]] | unique')" == "[\"$T1\"]" ]] &&
	[[ "$(users '[.users[] | select(.username | startswith("t2-")) | .attributes.organization_id] | unique')" == "[null]" ]] &&
	ok "tenant mode: t1-admin and t1-reader carry organization_id, tenant 2 untouched" || bad "tenant mode: attributes"
jq -e --arg t "$T1" '.tenants["1"] == $t' "$bstate/core/out/core.json" >/dev/null &&
	jq -e --arg t "$T1" '.tenants["1"].tenant_id == $t and .tenants["1"].admin.username == "t1-admin"' "$bsens/keycloak.json" >/dev/null &&
	[[ "$(stat -c %a "$bsens/keycloak.json")" == 600 ]] &&
	ok "tenant mode: recorded in core.json and keycloak.json (still 0600)" || bad "tenant mode: records"
grep -qF 'users/id-t1-admin?userProfileMetadata=true' "$STUB_STATE/kcadm-argv.log" &&
	ok "tenant mode: the read-back asks for userProfileMetadata=true (Keycloak 26.4 hides admin-only attributes from a plain GET)" ||
	bad "tenant mode: the read-back must use userProfileMetadata=true"
refuse "bind-tenant.sh refuses tenant 1's id for tenant 2" "already bound to tenant 1" bt 2 "$T1"
expect "bind-tenant.sh binds tenant 2" bt 2 "$T2"
if bt --scratch-user scratch-t1-new admin "$T9" >"$tmp/scratch.json" 2>"$tmp/out"; then
	ok "scratch mode creates and binds a user"
	pwf=$(jq -r .password_file "$tmp/scratch.json")
	jq -e --arg t "$T9" '.username == "scratch-t1-new" and .tenant_id == $t and .role == "admin" and (has("password") | not)' "$tmp/scratch.json" >/dev/null &&
		[[ "$(stat -c %a "$pwf")" == 600 ]] && ok "scratch mode: prints username, tenant, role and a 0600 password file, never the password" ||
		bad "scratch mode: output"
	users '.users[] | select(.username == "scratch-t1-new")' >"$tmp/su.json"
	jq -e --arg t "$T9" --arg p "$(cat "$pwf")" '.attributes.organization_id == [$t] and (.roles | sort) == ["imas-recipes-read", "imas-recipes-write"] and .password == $p' "$tmp/su.json" >/dev/null &&
		ok "scratch mode: both roles, organization_id and the password from its file" || bad "scratch mode: user in Keycloak"
	! grep -qF "$(cat "$pwf")" "$STUB_STATE/kcadm-argv.log" "$STUB_STATE/calls.log" "$tmp/scratch.json" "$tmp/out" &&
		! grep -qF KCADMINPASSWORD0123 "$STUB_STATE/calls.log" &&
		ok "scratch mode: no password in kubectl's argv, kcadm's (user) or the output" || bad "scratch mode: a password leaked"
	jq -e --arg t "$T9" '.scratch_users["scratch-t1-new"] == {tenant_id: $t, role: "admin"}' "$bstate/core/out/core.json" >/dev/null &&
		ok "scratch mode: recorded in core.json scratch_users" || bad "scratch mode: core.json"
	expect "scratch mode again for the same user and tenant" bt --scratch-user scratch-t1-new admin "$T9"
	[[ "$(users '[.users[] | select(.username == "scratch-t1-new")] | length')" == 1 ]] && ok "scratch mode: a re-run creates no second user" || bad "scratch mode: duplicate user"
else
	bad "scratch mode creates and binds a user"
	sed 's/^/      /' "$tmp/out" | tail -n 10
fi
expect "scratch mode: a read-only user" bt --scratch-user scratch-t1-ro readonly "$T9"
[[ "$(users '.users[] | select(.username == "scratch-t1-ro") | .roles')" == '["imas-recipes-read"]' ]] && ok "scratch mode: readonly gets the read role only" || bad "scratch mode: readonly roles"
refuse "scratch mode refuses to move a scratch user to another tenant" "already bound to" bt --scratch-user scratch-t1-new admin t_dddddddddddddddd
refuse "scratch mode refuses tenant 1 or 2" "scratch users are for tenants created during a run" bt --scratch-user scratch-x admin "$T1"
refuse "scratch mode refuses a realm user's name" "scratch user names" bt --scratch-user t1-admin admin "$T9"
refuse "scratch mode refuses an unknown role" "admin or readonly" bt --scratch-user scratch-x owner "$T9"

# --- 7c. helm_pull_chart (the OCI chart pull of install.sh) ----------------------
# A stub helm that records its argv and writes the chart into --destination,
# or fails like GHCR does for a package that is still private.
mkdir -p "$tmp/helmbin"
cat >"$tmp/helmbin/helm" <<'STUB'
#!/usr/bin/env bash
printf 'helm %s\n' "$*" >>"$HELM_STUB_LOG"
[[ "${HELM_STUB_FAIL:-}" != 1 ]] || { echo "Error: unauthorized: authentication required" >&2; exit 1; }
while (($#)); do
	[[ "$1" != --destination ]] || : >"$2/farmer-fake.tgz"
	shift
done
STUB
chmod +x "$tmp/helmbin/helm"
export HELM_STUB_LOG="$tmp/helm.log"
# pull: helm_pull_chart farmer 0.1.0-rc.5 in a subshell, so die only ends that.
pull() {
	(
		STATE_DIR="$tmp/pullstate"
		# shellcheck source=../lib/common.sh
		. "$core/lib/common.sh"
		PATH="$tmp/helmbin:$PATH" helm_pull_chart farmer 0.1.0-rc.5 "$tmp/pulled"
	)
}
: >"$HELM_STUB_LOG"
expect "helm_pull_chart: pulls the default OCI chart" pull
grep -qxF "helm pull oci://ghcr.io/yogzblr/charts/farmer --version 0.1.0-rc.5 --destination $tmp/pulled --registry-config $tmp/pullstate/helm/anonymous-registry.json" "$HELM_STUB_LOG" &&
	ok "helm_pull_chart: exact version, OCI reference, anonymous registry config" || bad "helm_pull_chart: unexpected helm call ($(cat "$HELM_STUB_LOG"))"
! grep -qE -- '--devel|helm repo|registry login|--password|--username' "$HELM_STUB_LOG" &&
	ok "helm_pull_chart: no --devel, no repo add, no login" || bad "helm_pull_chart: forbidden helm option"
[[ -f "$tmp/pulled/farmer-fake.tgz" ]] && ok "helm_pull_chart: the chart lands in the destination" || bad "helm_pull_chart: no chart written"
: >"$HELM_STUB_LOG"
IMAS_HELM_OCI_BASE=oci://registry.example/x/charts/ expect "helm_pull_chart: IMAS_HELM_OCI_BASE is honoured (trailing slash dropped)" pull
grep -qF "helm pull oci://registry.example/x/charts/farmer --version 0.1.0-rc.5 " "$HELM_STUB_LOG" &&
	ok "helm_pull_chart: custom base used" || bad "helm_pull_chart: custom base ignored ($(cat "$HELM_STUB_LOG"))"
IMAS_HELM_OCI_BASE=https://packages.buildkite.com/yogzblr/imashelm/helm refuse "helm_pull_chart: a non-OCI base is refused" 'must be oci://' pull
HELM_STUB_FAIL=1 refuse "helm_pull_chart: a failed pull says the package may still be private" \
	'may still be private.*owner makes each chart package public.*GHCR package settings' pull

# --- 8. OpenBao ------------------------------------------------------------------------
bao_bin="${BAO_BIN:-$(command -v bao || true)}"
if [[ -n "$bao_bin" && -x "$bao_bin" ]] && ! (exec 3<>/dev/tcp/127.0.0.1/8200) 2>/dev/null; then
	mkdir -p "$tmp/baobin" "$tmp/baodata"
	ln -s "$bao_bin" "$tmp/baobin/bao"
	# Single-node raft: OpenBao 2.7.1 (the version the repo pins) has no
	# "file" storage backend.
	cat >"$tmp/bao.hcl" <<-EOF
		storage "raft" {
		  path    = "$tmp/baodata"
		  node_id = "uat-core-test"
		}
		listener "tcp" { address = "127.0.0.1:8200" tls_disable = 1 }
		api_addr     = "http://127.0.0.1:8200"
		cluster_addr = "http://127.0.0.1:8201"
		disable_mlock = true
	EOF
	start_bao() {
		"$bao_bin" server -config="$tmp/bao.hcl" >>"$tmp/bao.log" 2>&1 &
		bao_pid=$!
		local rc
		for _ in $(seq 1 50); do
			rc=0
			BAO_ADDR=http://127.0.0.1:8200 "$bao_bin" status >/dev/null 2>&1 || rc=$?
			[[ $rc -ne 1 ]] && return 0
			sleep 0.2
		done
		return 1
	}
	stop_bao() { kill "$bao_pid" && wait "$bao_pid" 2>/dev/null || true; bao_pid=""; }
	ostate="$tmp/ostate"
	obao() { PATH="$stubs:$tmp/baobin:$PATH" "$core/openbao-bootstrap.sh" "$kubeconfig" "$ep" "$ostate"; }
	start_bao || bad "local OpenBao server starts"
	rm -rf "$STUB_STATE/imas-core"
	if obao >"$tmp/out" 2>&1; then
		ok "openbao-bootstrap.sh: initialise, unseal, Transit, gateway key"
		sens="$ostate/core/sensitive"
		jq -e '(.unseal_keys_b64 | length) == 3 and .unseal_threshold == 2' "$sens/openbao-init.json" >/dev/null &&
			ok "openbao: 3 key shares, threshold 2, kept in openbao-init.json" || bad "openbao: init file"
		[[ "$(stat -c %a "$sens/openbao-init.json")" == 600 && "$(stat -c %a "$sens/openbao-root-token")" == 600 ]] &&
			ok "openbao: init file and root token are 0600" || bad "openbao: file modes"
		root=$(cat "$sens/openbao-root-token")
		ty=$(BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root" "$bao_bin" read -field=type transit/keys/imas-gateway-jwt 2>/dev/null || true)
		[[ "$ty" == ed25519 ]] && ok "openbao: transit/keys/imas-gateway-jwt is ed25519" || bad "openbao: gateway key type ($ty)"
		# The chart's Job revokes the token it is handed, so it gets a
		# per-run root-policy token, never the root token.
		boot=$(jq -r '.data.token | @base64d' "$STUB_STATE/imas-core/Secret/imas-uat-openbao-root.json")
		[[ -n "$boot" && "$boot" != "$root" && "$boot" == "$(cat "$sens/openbao-bootstrap-token")" && "$(stat -c %a "$sens/openbao-bootstrap-token")" == 600 ]] &&
			ok "openbao: Secret imas-uat-openbao-root holds a bootstrap token (0600 copy kept), not the root token" || bad "openbao: bootstrap token Secret"
		blook=$(BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root" "$bao_bin" token lookup -format=json "$boot" 2>/dev/null || echo '{}')
		jq -e '.data.policies == ["root"] and .data.orphan == true and .data.renewable == false and .data.ttl > 0 and .data.ttl <= 3600' <<<"$blook" >/dev/null &&
			ok "openbao: the bootstrap token is an orphan root-policy token, one hour, not renewable" || bad "openbao: bootstrap token properties ($blook)"
		jq -e --arg t "$(printf '%s' "$root" | base64 -w0)" '(.data["unseal-keys.json"] | @base64d | fromjson | (.keys | length) == 3 and .threshold == 2) and .data["root-token"] == $t' \
			"$STUB_STATE/imas-core/Secret/imas-uat-openbao-unseal.json" >/dev/null &&
			ok "openbao: UAT ONLY unseal keys and root token in Secret imas-uat-openbao-unseal" || bad "openbao: unseal Secret"
		! grep -qF "$root" "$STUB_STATE/calls.log" "$tmp/out" && ok "openbao: root token never in argv or output" || bad "openbao: root token leaked"
		! grep -qF "$boot" "$STUB_STATE/calls.log" "$tmp/out" && ok "openbao: bootstrap token never in argv or output" || bad "openbao: bootstrap token leaked"
		for k in $(jq -r '.unseal_keys_b64[]' "$sens/openbao-init.json"); do
			grep -qF "$k" "$STUB_STATE/calls.log" "$tmp/out" && { bad "openbao: an unseal key leaked"; break; }
		done
		expect "openbao-bootstrap.sh again on an unsealed OpenBao changes nothing" obao
		[[ "$(cat "$sens/openbao-bootstrap-token")" != "$boot" ]] &&
			ok "openbao: a re-run hands the Job a fresh bootstrap token" || bad "openbao: the bootstrap token was reused"
		# A restart seals OpenBao: the script unseals it with the stored keys.
		stop_bao
		start_bao
		expect "openbao-bootstrap.sh unseals after a restart" obao
		BAO_ADDR=http://127.0.0.1:8200 "$bao_bin" status >/dev/null 2>&1 && ok "openbao: unsealed again" || bad "openbao: still sealed"
		# The same, from a runner that never saw the init: keys from the Secrets.
		stop_bao
		start_bao
		mv "$sens/openbao-init.json" "$tmp/init.json"
		rm -f "$sens/openbao-root-token" "$sens/openbao-unseal-keys.json"
		expect "openbao-bootstrap.sh unseals from the cluster Secrets without local files" obao
		BAO_ADDR=http://127.0.0.1:8200 "$bao_bin" status >/dev/null 2>&1 && ok "openbao: unsealed from the Secrets" || bad "openbao: not unsealed from the Secrets"
		mv "$tmp/init.json" "$sens/openbao-init.json"
		[[ "$(cat "$sens/openbao-root-token")" == "$root" ]] &&
			ok "openbao: the root token is restored from Secret imas-uat-openbao-unseal" || bad "openbao: root token not restored"

		# Design T4 (openbao_t4, check.sh): stand in for the chart's Job with
		# its own policy files, then check before and after its clean-up.
		t4() { (
			# shellcheck source=../lib/common.sh
			. "$core/lib/common.sh"
			KUBECONFIG_PATH="$kubeconfig"
			PATH="$stubs:$tmp/baobin:$PATH" openbao_t4 "$sens/openbao-root-token" "$sens/openbao-bootstrap-token"
		); }
		bt() { BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$(cat "$sens/openbao-bootstrap-token")" "$bao_bin" "$@" >/dev/null; }
		pols="$repo/deploy/helm/farmer/files/openbao-policies"
		for f in imas-farmer-natssign imas-nats-sys-signer imas-nats-bootstrap; do bt policy write "$f" "$pols/$f.hcl"; done
		bt write -f transit/keys/nats-operator type=ed25519
		bt write -f transit/keys/nats-operator-signing type=ed25519
		bt write -f transit/keys/nats-sys-account type=ed25519 exportable=true
		t4 >"$tmp/t4" 2>&1
		grep -qx 'FAIL T4: the token handed to the bootstrap Job is still valid' "$tmp/t4" &&
			grep -qx 'FAIL T4: policy imas-nats-bootstrap still exists' "$tmp/t4" &&
			grep -qx 'FAIL T4: transit/keys/nats-sys-account is missing or not hardened (ed25519, no export, no backup, not imported, not derived, not soft-deleted)' "$tmp/t4" &&
			grep -qx 'PASS T4: transit/keys/nats-operator is a hardened ed25519 key' "$tmp/t4" &&
			ok "T4 probe: a live bootstrap token, the ephemeral policy and an exportable key all fail" ||
			{ bad "T4 probe before the clean-up"; sed 's/^/      /' "$tmp/t4"; }
		good=1
		for pol in imas-farmer-natssign imas-nats-sys-signer; do
			grep -qx "PASS T4: $pol on transit/sign/nats-operator: deny" "$tmp/t4" &&
				grep -qx "PASS T4: $pol on transit/keys/nats-operator: read" "$tmp/t4" &&
				grep -qx "PASS T4: $pol on transit/keys/nats-operator/soft-delete: deny" "$tmp/t4" || good=0
		done
		((good)) &&
			ok "T4 probe: the chart's farmer and publisher policies cannot sign with, update or retire the operator key" ||
			{ bad "T4 probe: policy capabilities"; sed 's/^/      /' "$tmp/t4"; }
		# The Job's clean-up: the ephemeral policy, then its own token.
		bt policy delete imas-nats-bootstrap
		bt token revoke -self
		t4 >"$tmp/t4" 2>&1
		grep -qx 'PASS T4: the token handed to the bootstrap Job is revoked' "$tmp/t4" &&
			grep -qx 'PASS T4: policy imas-nats-bootstrap is deleted' "$tmp/t4" &&
			[[ $(grep -c '^FAIL' "$tmp/t4") -eq 1 ]] && grep -q '^FAIL T4: transit/keys/nats-sys-account' "$tmp/t4" &&
			ok "T4 probe: after the clean-up only the exportable key fails" ||
			{ bad "T4 probe after the clean-up"; sed 's/^/      /' "$tmp/t4"; }
		! grep -qF "$root" "$STUB_STATE/calls.log" "$tmp/t4" && ok "T4 probe: no token in argv or output" || bad "T4 probe: a token leaked"
		# A grant in one policy is caught even where the other denies it.
		{ cat "$pols/imas-nats-sys-signer.hcl"; printf '\npath "transit/keys/nats-operator/soft-delete" {\n  capabilities = ["delete"]\n}\n'; } >"$tmp/loose.hcl"
		BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root" "$bao_bin" policy write imas-nats-sys-signer "$tmp/loose.hcl" >/dev/null
		t4 >"$tmp/t4" 2>&1
		grep -qx 'FAIL T4: imas-nats-sys-signer on transit/keys/nats-operator/soft-delete: delete, want deny' "$tmp/t4" &&
			grep -qx 'PASS T4: imas-farmer-natssign on transit/keys/nats-operator/soft-delete: deny' "$tmp/t4" &&
			ok "T4 probe: a grant in the publisher policy is not hidden by the farmer policy's deny" ||
			{ bad "T4 probe: per-policy probes"; sed 's/^/      /' "$tmp/t4"; }

		# saasapi-secrets.sh: the KV entries the chart's hook Jobs would have
		# written, then the two Secrets and the operator token's.
		b() { BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root" "$bao_bin" "$@" >/dev/null; }
		b secrets enable -path=secret -version=2 kv
		b kv put secret/platform/imas/saasapi-nats-user jwt=eyJ.fake.jwt public_key=UFAKE
		b kv put secret/imas/tenant-x25519/saasapi-box pub=PUB priv=PRIVBOX
		b kv put secret/imas/tenant-x25519/controlplane-pub platform_pub=PLATPUB saasapi_box_pub=PUB
		b kv put secret/imas/tenant-x25519/platform pub=P priv=PLATFORM_PRIVATE origin=x
		mkdir -p "$ostate/core/sensitive/seeds"
		printf 'SUFAKESAASAPIUSERSEED' >"$ostate/core/sensitive/seeds/saasapi-user.nk"
		if PATH="$stubs:$tmp/baobin:$PATH" "$core/saasapi-secrets.sh" "$kubeconfig" "$ep" "$ostate" >"$tmp/out" 2>&1; then
			ok "saasapi-secrets.sh runs"
			nats="$STUB_STATE/imas-core/Secret/imas-saasapi-nats.json"
			box="$STUB_STATE/imas-core/Secret/imas-saasapi-box.json"
			jq -e '(.data | keys | sort) == ["SAASAPI_NATS_USER_JWT", "nats-user.nk"] and (.data.SAASAPI_NATS_USER_JWT | @base64d) == "eyJ.fake.jwt" and (.data["nats-user.nk"] | @base64d) == "SUFAKESAASAPIUSERSEED"' "$nats" >/dev/null &&
				ok "saasapi-secrets: imas-saasapi-nats has the seed and the published JWT" || bad "saasapi-secrets: imas-saasapi-nats"
			jq -e '(.data | keys | sort) == ["SAASAPI_PLATFORM_BOX_PUB", "saasapi-box.key"] and (.data["saasapi-box.key"] | @base64d) == "PRIVBOX" and (.data.SAASAPI_PLATFORM_BOX_PUB | @base64d) == "PLATPUB"' "$box" >/dev/null &&
				ok "saasapi-secrets: imas-saasapi-box has exactly priv and platform_pub" || bad "saasapi-secrets: imas-saasapi-box"
			! grep -rq PLATFORM_PRIVATE "$STUB_STATE" "$ostate" && ok "saasapi-secrets: the platform private key is never read" || bad "saasapi-secrets: platform key read"
			[[ -z "$(find "$ostate/core/sensitive" -name 'saasapi-secrets.*')" ]] && ok "saasapi-secrets: temporary files removed" || bad "saasapi-secrets: temporary files left"
			opt="$ostate/core/sensitive/saasapi-operator-token"
			optok="$STUB_STATE/imas-core/Secret/imas-saasapi-operator-token.json"
			[[ "$(cat "$opt" 2>/dev/null)" =~ ^[0-9a-f]{64}$ && "$(stat -c %a "$opt")" == 600 ]] &&
				jq -e --arg t "$(cat "$opt")" '(.data | keys) == ["current"] and (.data.current | @base64d) == $t' "$optok" >/dev/null &&
				ok "saasapi-secrets: the operator token (64 hex, 0600) is Secret imas-saasapi-operator-token key current" ||
				bad "saasapi-secrets: the operator token Secret"
			first=$(cat "$opt" 2>/dev/null)
			PATH="$stubs:$tmp/baobin:$PATH" "$core/saasapi-secrets.sh" "$kubeconfig" "$ep" "$ostate" >/dev/null 2>&1 &&
				[[ "$(cat "$opt")" == "$first" ]] && ok "saasapi-secrets: a re-run keeps the operator token" ||
				bad "saasapi-secrets: a re-run changed the operator token"
			cp "$opt" "$ostate/core/sensitive/internal-auth-secret"
			refuse "saasapi-secrets: an operator token equal to the BFF secret is refused" "equals the BFF secret" \
				env PATH="$stubs:$tmp/baobin:$PATH" "$core/saasapi-secrets.sh" "$kubeconfig" "$ep" "$ostate"
			rm -f "$ostate/core/sensitive/internal-auth-secret"
		else
			bad "saasapi-secrets.sh runs"
			sed 's/^/      /' "$tmp/out" | tail -n 10
		fi
	else
		bad "openbao-bootstrap.sh: initialise, unseal, Transit, gateway key"
		sed 's/^/      /' "$tmp/out" | tail -n 15
	fi
	stop_bao
else
	skip "openbao-bootstrap.sh and saasapi-secrets.sh against a real OpenBao (no bao binary in BAO_BIN or PATH, or 127.0.0.1:8200 is taken)"
fi

# --- 8a. OpenBao on an HA core hub ---------------------------------------------------
# Three local raft servers with the static seal of values/values-ha.yaml
# (retry_join, a seal key file) stand in for imas-core-openbao-0 to -2
# (STUB_BAO_PORTS); the endpoints file is uat/k0s's HA output (3 + 3 nodes).
ep_ha="$repo/uat/k0s/testdata/expected/endpoints-ha.json"
if [[ -n "$bao_bin" && -x "$bao_bin" ]] && ! (exec 3<>/dev/tcp/127.0.0.1/8300) 2>/dev/null &&
	! (exec 3<>/dev/tcp/127.0.0.1/8310) 2>/dev/null && ! (exec 3<>/dev/tcp/127.0.0.1/8320) 2>/dev/null; then
	mkdir -p "$tmp/baobin"
	[[ -e "$tmp/baobin/bao" ]] || ln -s "$bao_bin" "$tmp/baobin/bao"
	(umask 077 && openssl rand 32 >"$tmp/seal.key")
	ha_pids=()
	start_ha() { # <index>
		local i=$1
		mkdir -p "$tmp/ha$i"
		cat >"$tmp/ha$i.hcl" <<-EOF
			storage "raft" {
			  path    = "$tmp/ha$i"
			  node_id = "imas-core-openbao-$i"
			  retry_join { leader_api_addr = "http://127.0.0.1:8300" }
			  retry_join { leader_api_addr = "http://127.0.0.1:8310" }
			  retry_join { leader_api_addr = "http://127.0.0.1:8320" }
			}
			seal "static" {
			  current_key_id = "imas-uat-1"
			  current_key    = "file://$tmp/seal.key"
			}
			listener "tcp" {
			  address         = "127.0.0.1:83${i}0"
			  cluster_address = "127.0.0.1:83${i}1"
			  tls_disable     = 1
			}
			api_addr      = "http://127.0.0.1:83${i}0"
			cluster_addr  = "http://127.0.0.1:83${i}1"
			disable_mlock = true
		EOF
		"$bao_bin" server -config="$tmp/ha$i.hcl" >>"$tmp/ha$i.log" 2>&1 &
		ha_pids[i]=$!
	}
	stop_ha() { kill "${ha_pids[$1]}" && wait "${ha_pids[$1]}" 2>/dev/null || true; }
	for i in 0 1 2; do start_ha "$i"; done
	export STUB_BAO_PORTS="imas-core-openbao-0=8300 imas-core-openbao-1=8310 imas-core-openbao-2=8320"
	rm -rf "$STUB_STATE/imas-core"
	mkdir -p "$STUB_STATE/imas-core/StatefulSet" "$STUB_STATE/imas-core/Secret"
	echo '{"kind":"StatefulSet","metadata":{"name":"imas-core-openbao"},"spec":{"replicas":3}}' >"$STUB_STATE/imas-core/StatefulSet/imas-core-openbao.json"
	hstate="$tmp/hstate"
	hbao() { PATH="$stubs:$tmp/baobin:$PATH" "$core/openbao-bootstrap.sh" "$kubeconfig" "$ep_ha" "$hstate"; }
	refuse "openbao-bootstrap.sh (HA) refuses to start without the seal key Secret" "imas-uat-openbao-seal.*missing" hbao
	echo '{"kind":"Secret","metadata":{"name":"imas-uat-openbao-seal"},"data":{}}' >"$STUB_STATE/imas-core/Secret/imas-uat-openbao-seal.json"
	if hbao >"$tmp/out" 2>&1; then
		ok "openbao-bootstrap.sh (HA): initialise pod 0, three pods unseal themselves and join, Transit, gateway key"
		hs="$hstate/core/sensitive"
		jq -e '(.recovery_keys_b64 | length) == 3 and .recovery_keys_threshold == 2 and ((.unseal_keys_b64 // []) | length) == 0' "$hs/openbao-init.json" >/dev/null &&
			ok "openbao (HA): 3 recovery key shares, threshold 2, no unseal keys (static seal)" || bad "openbao (HA): init file"
		hroot=$(cat "$hs/openbao-root-token")
		peers=$(BAO_ADDR=http://127.0.0.1:8310 BAO_TOKEN="$hroot" "$bao_bin" operator raft list-peers -format=json 2>/dev/null || echo '{}')
		jq -e '[.data.config.servers[] | select(.voter)] | length == 3' <<<"$peers" >/dev/null &&
			ok "openbao (HA): three raft voters" || bad "openbao (HA): raft peers ($peers)"
		for p in 8300 8310 8320; do
			[[ "$(BAO_ADDR=http://127.0.0.1:$p BAO_TOKEN="$hroot" "$bao_bin" read -field=type transit/keys/imas-gateway-jwt 2>/dev/null)" == ed25519 ]] ||
				{ bad "openbao (HA): transit/keys/imas-gateway-jwt through 127.0.0.1:$p"; continue; }
		done
		ok "openbao (HA): the gateway key is ed25519, read through every pod"
		jq -e --arg t "$(printf '%s' "$hroot" | base64 -w0)" '(.data["recovery-keys.json"] | @base64d | fromjson | (.keys | length) == 3 and .threshold == 2) and .data["root-token"] == $t and (.data | has("unseal-keys.json") | not)' \
			"$STUB_STATE/imas-core/Secret/imas-uat-openbao-unseal.json" >/dev/null &&
			ok "openbao (HA): UAT ONLY recovery keys and root token in Secret imas-uat-openbao-unseal" || bad "openbao (HA): unseal Secret"
		hboot=$(jq -r '.data.token | @base64d' "$STUB_STATE/imas-core/Secret/imas-uat-openbao-root.json")
		[[ -n "$hboot" && "$hboot" != "$hroot" ]] && ok "openbao (HA): the chart's Job gets a bootstrap token, not the root token" || bad "openbao (HA): bootstrap token"
		! grep -qF "$hroot" "$STUB_STATE/calls.log" "$tmp/out" && ! grep -qF "$hboot" "$STUB_STATE/calls.log" "$tmp/out" &&
			ok "openbao (HA): no token in argv or output" || bad "openbao (HA): a token leaked"
		expect "openbao-bootstrap.sh (HA) again changes nothing" hbao
		# A pod restart: it unseals itself (no script) and rejoins.
		stop_ha 0
		start_ha 0
		up=""
		for _ in $(seq 1 50); do
			if BAO_ADDR=http://127.0.0.1:8300 "$bao_bin" status >/dev/null 2>&1; then up=1 && break; fi
			sleep 0.3
		done
		[[ -n "$up" ]] && ok "openbao (HA): a restarted pod unseals itself (static seal)" || bad "openbao (HA): pod 0 still sealed after a restart"
		expect "openbao-bootstrap.sh (HA) after a pod restart" hbao
		# From a runner that never saw the init: the Secret has them.
		mv "$hs/openbao-init.json" "$tmp/hinit.json"
		rm -f "$hs/openbao-root-token" "$hs/openbao-recovery-keys.json"
		expect "openbao-bootstrap.sh (HA) restores the root token from the cluster Secret" hbao
		[[ "$(cat "$hs/openbao-root-token")" == "$hroot" ]] && ok "openbao (HA): root token restored" || bad "openbao (HA): root token not restored"
	else
		bad "openbao-bootstrap.sh (HA): initialise pod 0, three pods unseal themselves and join, Transit, gateway key"
		sed 's/^/      /' "$tmp/out" | tail -n 15
	fi
	for i in 0 1 2; do stop_ha "$i"; done
	unset STUB_BAO_PORTS
else
	skip "openbao-bootstrap.sh on an HA core hub against three real OpenBao servers (no bao binary, or 127.0.0.1:8300, 8310 or 8320 is taken)"
fi

# --- 8b. finish.sh ------------------------------------------------------------------
expect "finish.sh and operator-release.sh (test/finish_test.sh)" bash "$here/finish_test.sh"
expect "validate-object-store.sh (test/object_store_test.sh)" bash "$here/object_store_test.sh"

# --- 9. go test ---------------------------------------------------------------------
if command -v go >/dev/null; then
	expect "go test ./uat/hub/core/ (helm template checks; see its output for skips)" \
		bash -c 'cd "$1" && go test -count=1 -v ./uat/hub/core/ 2>&1 | tee "$2"; exit "${PIPESTATUS[0]}"' _ "$repo" "$tmp/gotest"
	grep -E '^\s+--- SKIP|SKIP:' "$tmp/gotest" | sed 's/^/      /' || true
else
	skip "go test (go not installed)"
fi

echo
if ((${#skipped[@]})); then
	printf 'skipped (not passed): %s\n' "${skipped[@]}"
fi
if ((failed)); then
	printf '%d test(s) failed\n' "$failed"
	exit 1
fi
echo "all run tests passed"
