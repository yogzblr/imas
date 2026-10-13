#!/usr/bin/env bash
# test/object_store_test.sh: validate-object-store.sh against the repo's stub
# kubectl (its exec runs here; its port-forward stands in for the one to
# Versity Gateway) and a curl that answers with the UAT policies
# (test/object-store-stubs/curl). No cluster, no RustFS, no gateway. Run by
# test/run.sh and by core_test.go's TestValidateObjectStore. (The RustFS
# probes also passed 32 of 32 against a real RustFS 1.0.1 container
# provisioned by rustfs-setup.sh.)
# The checks use `test && ok || bad` on purpose: ok and bad always return 0.
# shellcheck disable=SC2015
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
core=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0
ok() { printf 'ok    %s\n' "$1"; }
bad() {
	printf 'FAIL  %s\n' "$1"
	failed=$((failed + 1))
}

export PATH="$here/object-store-stubs:$here/stubs:$PATH"
# The RustFS pod's root credential (its exec runs here), and the stub
# store's root key.
export RUSTFS_ACCESS_KEY=imas-uat-root RUSTFS_SECRET_KEY=root-secret-never-printed STUB_S3_ROOT_KEY=imas-uat-root
kubeconfig="$tmp/kubeconfig"
echo "apiVersion: v1" >"$kubeconfig"
ep="$core/testdata/endpoints.json"

# setup <name>: a state directory holding the credentials rustfs-setup.sh
# (or, for Versity Gateway, install.sh) writes.
setup() {
	state="$tmp/$1"
	export STUB_STATE="$state/stub"
	mkdir -p "$STUB_STATE"
	local s3="$state/core/sensitive/s3"
	(umask 077 && mkdir -p "$s3/accounts-reader")
	printf imas-farmer >"$s3/farmer-access-key-id"
	printf imas-saasapi >"$s3/saasapi-access-key-id"
	printf imas-farmer-accounts >"$s3/accounts-writer-access-key-id"
	printf imas-bus-accounts-reader >"$s3/accounts-reader/access-key-id"
	for f in farmer-secret-access-key saasapi-secret-access-key accounts-writer-secret-access-key accounts-reader/secret-access-key; do
		printf 'secret-%s-never-printed' "${f%%/*}" >"$s3/$f"
	done
	(umask 077 && mkdir -p "$s3/versity-root")
	printf imas-uat-root >"$s3/versity-root/access-key-id"
	printf root-secret-never-printed >"$s3/versity-root/secret-access-key"
}
vr() { "$core/validate-object-store.sh" "$kubeconfig" "$1" "$state" >"$state/out" 2>&1; }

setup good
if vr "$ep"; then
	grep -q 'validate-object-store (rustfs): 32 of 32 checks passed' "$state/out" && ok "the UAT policies pass all 32 checks" ||
		{ bad "the pass count"; tail -n 3 "$state/out"; }
else
	bad "the UAT policies fail validate-object-store.sh"
	grep FAIL "$state/out" | head -n 5
fi
[[ "$(grep -Ec '^(imas-farmer|imas-saasapi|imas-farmer-accounts|imas-bus-accounts-reader) ' "$STUB_STATE/s3-curl.log")" -eq 32 ]] &&
	ok "each call is signed with its user's own access key" || bad "calls per user ($(wc -l <"$STUB_STATE/s3-curl.log"))"
grep -Eq '^imas-saasapi PUT http://127.0.0.1:9000/imas-recipes/tenants/uat-validate-[0-9a-f]{8}/recipes/recipe$' "$STUB_STATE/s3-curl.log" &&
	ok "saasapi's probes are under tenants/<prefix>/recipes/" || bad "saasapi's probe path"
[[ "$(grep -c '^imas-uat-root DELETE ' "$STUB_STATE/s3-curl.log")" -eq 11 ]] &&
	ok "every probe object is deleted with the root credential" || bad "cleanup deletes"
! grep -rq 'never-printed' "$STUB_STATE/calls.log" "$state/out" && ok "no secret key in kubectl's argv or the output" || bad "a secret key leaked"

setup reader-put
FAKE_S3_BREAK=reader-put vr "$ep" && bad "a reader that can write passes" ||
	{ grep -qF 'FAIL  accounts reader: put on imas-accounts: http 200, want deny' "$state/out" && grep -q '1 of 32 checks failed' "$state/out" &&
		ok "an accounts reader that can write fails, named" || { bad "reader-put: wrong output"; tail -n 3 "$state/out"; }; }
setup farmer-accounts
FAKE_S3_BREAK=farmer-accounts vr "$ep" && bad "farmer reading the accounts bucket passes" ||
	{ grep -qF 'FAIL  farmer: list on imas-accounts: http 200, want deny' "$state/out" &&
		ok "farmer listing the accounts bucket fails, named" || { bad "farmer-accounts: wrong output"; tail -n 3 "$state/out"; }; }

setup root-delete
FAKE_S3_BREAK=root-delete vr "$ep" && bad "probe objects left behind pass" ||
	{ grep -qF 'FAIL  root cleanup: delete imas-recipes/' "$state/out" && grep -q '11 of 43 checks failed' "$state/out" &&
		ok "a cleanup DELETE that fails is reported and fails the script" || { bad "root-delete: wrong output"; tail -n 3 "$state/out"; }; }

setup nocreds
rm "$state/core/sensitive/s3/accounts-reader/secret-access-key"
vr "$ep" && bad "missing credentials pass" ||
	{ grep -q 'run rustfs-setup.sh (or, for Versity Gateway, install.sh) first' "$state/out" && ok "a missing credential file is refused" || bad "missing credential: wrong message"; }
setup external
jq '.object_store = {mode: "external", endpoint: "s3.example:443"} | .dmz.account_store = {endpoint: "s3.example:443"}' "$ep" >"$tmp/external.json"
vr "$tmp/external.json" && bad "external mode is validated as RustFS" ||
	{ grep -q "checks the UAT's own store only" "$state/out" && ok "external S3 mode is refused" || bad "external: wrong message"; }

# Versity Gateway (an HA core hub, uat/k0s's HA endpoints): the same probes,
# here through the port-forward, cleaned up with the gateway's root key.
ep_ha="$core/../../k0s/testdata/expected/endpoints-ha.json"
setup versity
export STUB_PF_PORT=17071
if vr "$ep_ha"; then
	grep -q 'validate-object-store (versity): 32 of 32 checks passed' "$state/out" && ok "Versity Gateway: the UAT policies pass all 32 checks" ||
		{ bad "Versity Gateway: the pass count"; tail -n 3 "$state/out"; }
else
	bad "Versity Gateway: the UAT policies fail validate-object-store.sh"
	grep -E 'FAIL|ERROR' "$state/out" | head -n 5
fi
grep -q 'port-forward svc/imas-core-farmer-versity :7070' "$STUB_STATE/calls.log" &&
	ok "Versity Gateway: reached through kubectl port-forward to its Service" || bad "Versity Gateway: no port-forward"
! grep -q ' exec ' "$STUB_STATE/calls.log" && ok "Versity Gateway: nothing runs in a pod" || bad "Versity Gateway: a probe ran in a pod"
[[ "$(grep -Ec '^imas-uat-root DELETE http://127.0.0.1:17071/' "$STUB_STATE/s3-curl.log")" -eq 11 ]] &&
	ok "Versity Gateway: every probe object is deleted with the gateway's root credential" || bad "Versity Gateway: cleanup deletes"
! grep -rq 'never-printed' "$STUB_STATE/calls.log" "$state/out" && ok "Versity Gateway: no secret key in argv or the output" || bad "Versity Gateway: a secret key leaked"
setup versity-reader-put
FAKE_S3_BREAK=reader-put vr "$ep_ha" && bad "Versity Gateway: a reader that can write passes" ||
	{ grep -qF 'FAIL  accounts reader: put on imas-accounts: http 200, want deny' "$state/out" &&
		ok "Versity Gateway: an accounts reader that can write fails, named" || { bad "versity reader-put: wrong output"; tail -n 3 "$state/out"; }; }
setup versity-noroot
rm "$state/core/sensitive/s3/versity-root/secret-access-key"
vr "$ep_ha" && bad "Versity Gateway without its root credential passes" ||
	{ grep -q "install.sh makes the gateway's root credential" "$state/out" && ok "Versity Gateway: a missing root credential is refused" || bad "versity-noroot: wrong message"; }

if ((failed)); then
	printf '%d validate-object-store check(s) failed\n' "$failed"
	exit 1
fi
printf 'all validate-object-store checks passed\n'
