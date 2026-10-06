#!/usr/bin/env bash
# test/run.sh: the static checks and script tests for uat/hub/core. No
# cluster, registry or cloud is needed.
#   1. shellcheck on every script and stub
#   2. yamllint on the values files, the chart metadata and the rendered
#      UAT chart
#   3. the realm file's jq checks (check-realm.sh)
#   4. gen-values.sh and lib/common.sh input handling
#   5. seeds.sh against a stub kubectl (real nk, built from go.mod)
#   6. admin-keys.sh against a stub curl and a fake imas CLI (checksum
#      check, key reuse, file modes)
#   7. bind-tenant.sh, token.sh and install.sh argument checks
#   8. openbao-bootstrap.sh and saasapi-secrets.sh against a real local
#      OpenBao server, when a bao binary is on PATH or in $BAO_BIN (skipped,
#      and said so, otherwise)
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
	expect "shellcheck" bash -c 'cd "$1" && shellcheck -x ./*.sh lib/common.sh test/*.sh test/stubs/*' _ "$core"
else
	skip "shellcheck (not installed)"
fi

# --- 2. yamllint ----------------------------------------------------------------
if command -v yamllint >/dev/null; then
	expect "yamllint values and chart metadata" yamllint -c "$here/yamllint.yaml" \
		"$core/values/farmer-uat.yaml" "$core/chart/Chart.yaml" "$core/chart/values.yaml"
	if command -v helm >/dev/null; then
		helm template imas-uat-core "$core/chart" -n imas-uat --kube-version 1.31.0 >"$tmp/extras.yaml" 2>"$tmp/out" &&
			expect "yamllint rendered UAT chart" yamllint -c "$here/yamllint.yaml" "$tmp/extras.yaml" ||
			bad "helm template chart/"
	fi
else
	skip "yamllint (not installed)"
fi

# --- 3. realm --------------------------------------------------------------------
expect "realm jq checks" "$here/check-realm.sh"

# --- 4. gen-values and endpoints --------------------------------------------------
admin="$core/testdata/admin.json"
gv() { "$core/gen-values.sh" "$@"; }
if gv "$ep" "$admin" v0.1.0-rc.4 >"$tmp/v1.json" 2>"$tmp/out"; then
	ok "gen-values.sh renders the contract's endpoints"
	jq -e '
	  .saasapi.jwt.issuer == "https://uatabc123-core.centralindia.cloudapp.azure.com/realms/imas-uat"
	  and .saasapi.jwt.keycloakJWKSURL == .saasapi.jwt.issuer + "/protocol/openid-connect/certs"
	  and .saasapi.jwt.audience == "imas-saasapi"
	  and .bus.sproutBusURLs == ["wss://uatabc123-dmz.centralindia.cloudapp.azure.com:8443/"]
	  and .bus.serviceName == "imas-dmz-nats-bus" and .bus.namespace == "imas-dmz"
	  and .farmer.image.tag == "0.1.0-rc.4" and .saasapi.image.tag == "0.1.0-rc.4"
	  and .database.migrate.image.tag == "0.1.0-rc.4"
	  and .farmer.bootstrapAdmin.pubkey == "AC4LMP7I2FYLWGY5GIB52A4XCFFFSB2QTZ65B3A4G6OK5GYWRJSKH74C"
	  and .farmer.bootstrapAdmin.username == "uat-admin"' "$tmp/v1.json" >/dev/null &&
		ok "gen-values.sh: issuer, JWKS, audience, bus, tags and admin" ||
		bad "gen-values.sh: issuer, JWKS, audience, bus, tags and admin"
else
	bad "gen-values.sh renders the contract's endpoints"
fi
gv "$ep2" "$admin" v1.2.3 >"$tmp/v2.json" 2>/dev/null &&
	jq -e '.saasapi.jwt.issuer == "https://core.imas-uat.test:30444/realms/imas-uat"
	  and .bus.sproutBusURLs == ["wss://dmz.imas-uat.test:30443/"] and .bus.serviceName == "uat-dmz-nats-bus"
	  and .farmer.image.tag == "1.2.3"' "$tmp/v2.json" >/dev/null &&
	ok "gen-values.sh: port and name overrides, non-443 issuer keeps the port" ||
	bad "gen-values.sh: port and name overrides"
refuse "release_tag latest is refused" "never latest" gv "$ep" "$admin" latest
refuse "release_tag without v is refused" "vX.Y.Z" gv "$ep" "$admin" 0.1.0
refuse "release_tag with a build suffix is refused" "vX.Y.Z" gv "$ep" "$admin" v0.1.0-beta.1
jq '.core.fqdn = "bad_name"' "$ep" >"$tmp/bad-fqdn.json"
refuse "a malformed core FQDN is refused" "core.fqdn" gv "$tmp/bad-fqdn.json" "$admin" v0.1.0
jq '.dmz.private_ip = "10.60.1.400"' "$ep" >"$tmp/bad-ip.json"
refuse "a malformed DMZ IP is refused" "dmz.private_ip" gv "$tmp/bad-ip.json" "$admin" v0.1.0
jq 'del(.core.fqdn)' "$ep" >"$tmp/no-fqdn.json"
refuse "a missing core FQDN is refused" "no .core.fqdn" gv "$tmp/no-fqdn.json" "$admin" v0.1.0
jq '.core.exposure = "LoadBalancer"' "$ep" >"$tmp/bad-exp.json"
refuse "an unknown exposure is refused" "core.exposure" gv "$tmp/bad-exp.json" "$admin" v0.1.0
jq '.boxpub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="' "$admin" >"$tmp/zero-admin.json"
refuse "the chart's all-zero placeholder admin key is refused" "placeholder" gv "$ep" "$tmp/zero-admin.json" v0.1.0
jq '.pubkey = "not-a-key"' "$admin" >"$tmp/bad-admin.json"
refuse "a malformed admin pubkey is refused" "NKey" gv "$ep" "$tmp/bad-admin.json" v0.1.0

# --- 5. seeds.sh --------------------------------------------------------------------
state="$tmp/state"
seeds() { PATH="$stubs:$PATH" "$core/seeds.sh" "$kubeconfig" "$ep" "$state"; }
if command -v go >/dev/null; then
	if seeds >"$tmp/out" 2>&1; then
		ok "seeds.sh generates the six seeds with nk"
		sd="$state/core/sensitive/seeds"
		declare -A pfx=([operator.nk]=SO [operator-signing.nk]=SO [sys-account.nk]=SA [tenant.nk]=SA [tenant-signing.nk]=SA [saasapi-user.nk]=SU)
		good=1
		for k in "${!pfx[@]}"; do
			[[ "$(cat "$sd/$k")" =~ ^${pfx[$k]}[A-Z2-7]{56}$ ]] || good=0
			[[ "$(stat -c %a "$sd/$k")" == 600 ]] || good=0
		done
		[[ "$(for f in "$sd"/*.nk; do cat "$f"; echo; done | sort -u | wc -l)" -eq 6 ]] || good=0
		[[ "$(wc -c <"$sd/operator.nk")" -eq 58 ]] || good=0
		((good)) && ok "seeds: right types, distinct, mode 0600, no newline" || bad "seeds: types, distinctness or modes"
		[[ "$(stat -c %a "$state/core/sensitive")" == 700 ]] && ok "sensitive dir is 0700" || bad "sensitive dir is 0700"
		sec="$STUB_STATE/imas-core/Secret/imas-farmer-nats-seeds.json"
		jq -e --arg op "$(base64 -w0 <"$sd/operator.nk")" '(.data | keys | sort) == ["operator-signing.nk","operator.nk","saasapi-user.nk","sys-account.nk","tenant-signing.nk","tenant.nk"] and .data["operator.nk"] == $op' "$sec" >/dev/null &&
			ok "seeds: Secret imas-core/imas-farmer-nats-seeds holds the six files" || bad "seeds: Secret content"
		! grep -q 'S[OAU][A-Z2-7]\{56\}' "$STUB_STATE/calls.log" && ok "seeds: no seed in any kubectl argument" || bad "seeds: a seed reached argv"
		expect "seeds.sh again: existing Secret matches, nothing replaced" seeds
		cp "$sd/tenant.nk" "$tmp/tenant.nk"
		rm "$sd/tenant.nk"
		expect "seeds.sh restores a missing local seed from the Secret" seeds
		cmp -s "$sd/tenant.nk" "$tmp/tenant.nk" && ok "seeds: restored seed is byte-identical" || bad "seeds: restored seed differs"
		printf 'SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >"$sd/tenant.nk"
		refuse "seeds.sh refuses to replace an existing install's seeds" "refusing to replace" seeds
		cp "$tmp/tenant.nk" "$sd/tenant.nk"
		# A seed directory shared with the DMZ install that already holds
		# some seeds: they are kept, the rest generated.
		state2="$tmp/state2" shared="$tmp/shared-seeds"
		(umask 077 && mkdir -p "$shared" && cp "$sd/operator.nk" "$shared/")
		rm -rf "$STUB_STATE/imas-core"
		if UAT_SEEDS_DIR="$shared" PATH="$stubs:$PATH" "$core/seeds.sh" "$kubeconfig" "$ep" "$state2" >"$tmp/out" 2>&1 &&
			cmp -s "$shared/operator.nk" "$sd/operator.nk" && [[ $(find "$shared" -name '*.nk' | wc -l) -eq 6 ]]; then
			ok "seeds: UAT_SEEDS_DIR seeds are reused, missing ones generated"
		else
			bad "seeds: UAT_SEEDS_DIR reuse"
		fi
	else
		bad "seeds.sh generates the six seeds with nk"
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

# --- 8. OpenBao ------------------------------------------------------------------------
bao_bin="${BAO_BIN:-$(command -v bao || true)}"
if [[ -n "$bao_bin" && -x "$bao_bin" ]] && ! (exec 3<>/dev/tcp/127.0.0.1/8200) 2>/dev/null; then
	mkdir -p "$tmp/baobin" "$tmp/baodata"
	ln -s "$bao_bin" "$tmp/baobin/bao"
	cat >"$tmp/bao.hcl" <<-EOF
		storage "file" { path = "$tmp/baodata" }
		listener "tcp" { address = "127.0.0.1:8200" tls_disable = 1 }
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
		jq -e --arg t "$(printf '%s' "$root" | base64 -w0)" '.data.token == $t' \
			"$STUB_STATE/imas-core/Secret/imas-uat-openbao-root.json" >/dev/null &&
			ok "openbao: root token in Secret imas-uat-openbao-root (openbaoBootstrap.tokenSecretName)" || bad "openbao: root token Secret"
		jq -e '.data["unseal-keys.json"] | @base64d | fromjson | (.keys | length) == 3 and .threshold == 2' \
			"$STUB_STATE/imas-core/Secret/imas-uat-openbao-unseal.json" >/dev/null &&
			ok "openbao: UAT ONLY unseal keys in Secret imas-uat-openbao-unseal" || bad "openbao: unseal Secret"
		! grep -qF "$root" "$STUB_STATE/calls.log" "$tmp/out" && ok "openbao: root token never in argv or output" || bad "openbao: root token leaked"
		for k in $(jq -r '.unseal_keys_b64[]' "$sens/openbao-init.json"); do
			grep -qF "$k" "$STUB_STATE/calls.log" "$tmp/out" && { bad "openbao: an unseal key leaked"; break; }
		done
		expect "openbao-bootstrap.sh again on an unsealed OpenBao changes nothing" obao
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

		# saasapi-secrets.sh: the KV entries the chart's hook Jobs would have
		# written, then the two Secrets.
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
