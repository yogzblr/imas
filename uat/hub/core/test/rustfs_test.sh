#!/usr/bin/env bash
# test/rustfs_test.sh: validate-rustfs.sh against the repo's stub kubectl
# (its exec runs here) and a curl that answers with the UAT policies
# (test/rustfs-stubs/curl). No cluster and no RustFS. Run by test/run.sh and
# by core_test.go's TestValidateRustFS. (The same script also passed 32 of 32
# against a real RustFS 1.0.1 container provisioned by rustfs-setup.sh.)
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

export PATH="$here/rustfs-stubs:$here/stubs:$PATH"
export RUSTFS_ACCESS_KEY=imas-uat-root RUSTFS_SECRET_KEY=root-secret-never-printed
kubeconfig="$tmp/kubeconfig"
echo "apiVersion: v1" >"$kubeconfig"
ep="$core/testdata/endpoints.json"

# setup <name>: a state directory holding the credentials rustfs-setup.sh writes.
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
}
vr() { "$core/validate-rustfs.sh" "$kubeconfig" "$1" "$state" >"$state/out" 2>&1; }

setup good
if vr "$ep"; then
	grep -q 'validate-rustfs: 32 of 32 checks passed' "$state/out" && ok "the UAT policies pass all 32 checks" ||
		{ bad "the pass count"; tail -n 3 "$state/out"; }
else
	bad "the UAT policies fail validate-rustfs.sh"
	grep FAIL "$state/out" | head -n 5
fi
[[ "$(grep -Ec '^(imas-farmer|imas-saasapi|imas-farmer-accounts|imas-bus-accounts-reader) ' "$STUB_STATE/rustfs-curl.log")" -eq 32 ]] &&
	ok "each call is signed with its user's own access key" || bad "calls per user ($(wc -l <"$STUB_STATE/rustfs-curl.log"))"
grep -Eq '^imas-saasapi PUT http://127.0.0.1:9000/imas-recipes/tenants/uat-validate-[0-9a-f]{8}/recipes/recipe$' "$STUB_STATE/rustfs-curl.log" &&
	ok "saasapi's probes are under tenants/<prefix>/recipes/" || bad "saasapi's probe path"
[[ "$(grep -c '^imas-uat-root DELETE ' "$STUB_STATE/rustfs-curl.log")" -eq 11 ]] &&
	ok "every probe object is deleted with the root credential" || bad "cleanup deletes"
! grep -rq 'never-printed' "$STUB_STATE/calls.log" "$state/out" && ok "no secret key in kubectl's argv or the output" || bad "a secret key leaked"

setup reader-put
FAKE_RUSTFS_BREAK=reader-put vr "$ep" && bad "a reader that can write passes" ||
	{ grep -qF 'FAIL  accounts reader: put on imas-accounts: http 200, want deny' "$state/out" && grep -q '1 of 32 checks failed' "$state/out" &&
		ok "an accounts reader that can write fails, named" || { bad "reader-put: wrong output"; tail -n 3 "$state/out"; }; }
setup farmer-accounts
FAKE_RUSTFS_BREAK=farmer-accounts vr "$ep" && bad "farmer reading the accounts bucket passes" ||
	{ grep -qF 'FAIL  farmer: list on imas-accounts: http 200, want deny' "$state/out" &&
		ok "farmer listing the accounts bucket fails, named" || { bad "farmer-accounts: wrong output"; tail -n 3 "$state/out"; }; }

setup nocreds
rm "$state/core/sensitive/s3/accounts-reader/secret-access-key"
vr "$ep" && bad "missing credentials pass" ||
	{ grep -q 'run rustfs-setup.sh first' "$state/out" && ok "a missing credential file is refused" || bad "missing credential: wrong message"; }
setup external
jq '.object_store = {mode: "external", endpoint: "s3.example:443"} | .dmz.account_store = {endpoint: "s3.example:443"}' "$ep" >"$tmp/external.json"
vr "$tmp/external.json" && bad "external mode is validated as RustFS" ||
	{ grep -q 'checks the UAT RustFS only' "$state/out" && ok "external S3 mode is refused" || bad "external: wrong message"; }

if ((failed)); then
	printf '%d validate-rustfs check(s) failed\n' "$failed"
	exit 1
fi
printf 'all validate-rustfs checks passed\n'
