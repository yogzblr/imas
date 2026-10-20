#!/usr/bin/env bash
# Tests the logic of uat/scripts against stubbed az, gh and tofu
# (tests/stubs). Nothing reaches Azure or GitHub.
# Run: bash uat/scripts/tests/scripts_test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
scripts=$(cd "$here/.." && pwd)
stubs="$here/stubs"
testdata="$scripts/testdata"

pass=0
fail=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ok() { pass=$((pass + 1)); echo "ok   - $1"; }
nok() {
  fail=$((fail + 1))
  echo "FAIL - $1"
  [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /'
}
# check NAME COMMAND...: passes when COMMAND succeeds.
check() {
  local name=$1
  shift
  if "$@"; then ok "$name"; else nok "$name" "${out:-}"; fi
}

new_state() {
  STUB_STATE="$work/$1"
  rm -rf "$STUB_STATE"
  mkdir -p "$STUB_STATE"
  : >"$STUB_STATE/calls.log"
  export STUB_STATE
}
calls() { cat "$STUB_STATE/calls.log"; }

# run SCRIPT ARGS...: runs a script with the stubs first on PATH; sets rc and out.
run() {
  out=$(PATH="$stubs:$PATH" bash "$scripts/$1" "${@:2}" 2>&1)
  rc=$?
}

###############################################################################
echo "# run-id.sh"
ids=()
bad=""
for _ in $(seq 1 50); do
  id=$(bash "$scripts/run-id.sh") || bad="exit $?"
  [[ "$id" =~ ^[a-z][a-z0-9]{7}$ ]] || bad="$bad '$id'"
  ids+=("$id")
done
check "50 generated ids are 8 characters, a letter then letters or digits" test -z "$bad"
check "50 generated ids are all different" test "$(printf '%s\n' "${ids[@]}" | sort -u | wc -l)" -eq 50
for id in "${ids[@]:0:5}"; do
  check "generated id $id passes run-id.sh --check" bash "$scripts/run-id.sh" --check "$id"
done
# The same rule as uat/tofu (variables.tf) and destroy.sh.
for id in abc123 a1b2c3d4e5 999999; do
  check "--check accepts $id" bash "$scripts/run-id.sh" --check "$id"
done
for id in abc12 abcdefghijk ABC123 abc-123 'abc 123' '' 'abc123;x'; do
  if bash "$scripts/run-id.sh" --check "$id" 2>/dev/null; then nok "--check refuses '$id'"; else ok "--check refuses '$id'"; fi
done
# Deterministic source: byte 255 is above the unbiased limit and skipped.
printf '\377\001\002\003\004\005\006\007\010\011\012' >"$work/bytes"
id=$(RUN_ID_RANDOM_SOURCE="$work/bytes" bash "$scripts/run-id.sh")
check "biased bytes are skipped and bytes map to the alphabet (got $id)" test "$id" = bbcdefgh
if bash "$scripts/run-id.sh" extra 2>/dev/null; then nok "an unknown argument is a usage error"; else ok "an unknown argument is a usage error"; fi

###############################################################################
echo "# check-inputs.sh"
GUID1=11111111-2222-3333-4444-555555555555
GUID2=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
GUID3=01234567-89ab-cdef-0123-456789abcdef
inputs_state() {
  new_state "inputs-$1"
  printf '%s\n' v0.1.0-rc.3 v0.1.0-rc.4 v0.1.0-rc.5 >"$STUB_STATE/tags"
  printf '%s\n' "v0.1.0-rc.3 false" "v0.1.0-rc.4 false checksums.txt,checksums.txt.sig,imas-sprout_0.1.0-rc.4_linux_amd64.deb" \
    "v0.1.0-rc.5 true checksums.txt,checksums.txt.sig" >"$STUB_STATE/releases"
}
# run_inputs VAR=VALUE...: check-inputs.sh with a full, valid environment, the
# given variables overriding it.
run_inputs() {
  out=$(env AZURE_CLIENT_ID=$GUID1 AZURE_TENANT_ID=$GUID2 AZURE_SUBSCRIPTION_ID=$GUID3 \
    GITHUB_REPOSITORY=yogzblr/imas RELEASE_TAG=v0.1.0-rc.4 REGION=centralindia KEEP_HOURS=0 TIER=all \
    UPGRADE_FROM_TAG= SCENARIOS= GITHUB_OUTPUT="$STUB_STATE/github_output" PATH="$stubs:$PATH" \
    "$@" bash "$scripts/check-inputs.sh" 2>&1)
  rc=$?
}
has() { grep -qF -- "$1" <<<"$out"; }

inputs_state ok
run_inputs
check "valid inputs pass" test "$rc" -eq 0
check "the tag is looked up" grep -q "gh api repos/yogzblr/imas/git/ref/tags/v0.1.0-rc.4" "$STUB_STATE/calls.log"
check "the release is looked up" grep -q "gh api repos/yogzblr/imas/releases/tags/v0.1.0-rc.4" "$STUB_STATE/calls.log"
check "outputs: destroy=true with keep_hours 0" grep -qx "destroy=true" "$STUB_STATE/github_output"
check "outputs: run_budget_hours=7 for tier all" grep -qx "run_budget_hours=7" "$STUB_STATE/github_output"
check "outputs: release_tag" grep -qx "release_tag=v0.1.0-rc.4" "$STUB_STATE/github_output"

check "outputs: one node per hub by default" grep -qx "core_node_count=1" "$STUB_STATE/github_output"
check "outputs: dmz_node_count=1 by default" grep -qx "dmz_node_count=1" "$STUB_STATE/github_output"
check "outputs: no core_node_size for one node (the tofu default stays)" grep -qx "core_node_size=" "$STUB_STATE/github_output"

inputs_state ha
run_inputs HUB_NODES=3
check "hub_nodes 3 passes" test "$rc" -eq 0
check "outputs: 3 core nodes" grep -qx "core_node_count=3" "$STUB_STATE/github_output"
check "outputs: 3 DMZ nodes" grep -qx "dmz_node_count=3" "$STUB_STATE/github_output"
check "outputs: core nodes of Standard_D4s_v5 for the HA run" grep -qx "core_node_size=Standard_D4s_v5" "$STUB_STATE/github_output"
check "outputs: hub_nodes=3" grep -qx "hub_nodes=3" "$STUB_STATE/github_output"

inputs_state badnodes
run_inputs HUB_NODES=2
check "hub_nodes 2 fails, named" test "$rc" -eq 1 -a -n "$(grep -F "input hub_nodes '2' must be 1" <<<"$out")"

inputs_state vars
run_inputs AZURE_CLIENT_ID= AZURE_TENANT_ID= AZURE_SUBSCRIPTION_ID=
check "missing Azure variables fail" test "$rc" -eq 1
check "... naming AZURE_CLIENT_ID" has "::error::variable AZURE_CLIENT_ID is not set"
check "... naming AZURE_TENANT_ID" has "::error::variable AZURE_TENANT_ID is not set"
check "... naming AZURE_SUBSCRIPTION_ID" has "::error::variable AZURE_SUBSCRIPTION_ID is not set"
check "... and writes no outputs" test ! -s "$STUB_STATE/github_output"

inputs_state guid
run_inputs AZURE_TENANT_ID=not-a-guid
check "a malformed variable fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'AZURE_TENANT_ID is not a GUID' <<<"$out")"

inputs_state notag
run_inputs RELEASE_TAG=v0.1.0-rc.9
check "a tag that does not exist fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'tag v0.1.0-rc.9 does not exist' <<<"$out")"

inputs_state norelease
echo v0.1.0-rc.6 >>"$STUB_STATE/tags"
run_inputs RELEASE_TAG=v0.1.0-rc.6
check "a tag without a release fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'v0.1.0-rc.6 has no published release' <<<"$out")"

inputs_state unsigned
echo v0.1.0-rc.7 >>"$STUB_STATE/tags"
echo "v0.1.0-rc.7 false checksums.txt" >>"$STUB_STATE/releases"
run_inputs RELEASE_TAG=v0.1.0-rc.7
check "a release without checksums.txt.sig fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'v0.1.0-rc.7 is not GPG signed' <<<"$out")"
inputs_state nosums
echo v0.1.0-rc.7 >>"$STUB_STATE/tags"
echo "v0.1.0-rc.7 false checksums.txt.sig" >>"$STUB_STATE/releases"
run_inputs RELEASE_TAG=v0.1.0-rc.7
check "a release without checksums.txt fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'v0.1.0-rc.7 is not GPG signed' <<<"$out")"
inputs_state upgrade-unsigned
run_inputs UPGRADE_FROM_TAG=v0.1.0-rc.3
check "upgrade_from_tag need not be signed (it is installed from the repository, never registered)" test "$rc" -eq 0

inputs_state dispatch-default
run_inputs
check "outputs: dispatch_flags=off by default" grep -qx "dispatch_flags=off" "$STUB_STATE/github_output"
inputs_state dispatch-on
run_inputs DISPATCH_FLAGS=true
check "outputs: dispatch_flags=on for true" test "$rc" -eq 0 -a -n "$(grep -x 'dispatch_flags=on' "$STUB_STATE/github_output")"
inputs_state dispatch-off
run_inputs DISPATCH_FLAGS=false
check "outputs: dispatch_flags=off for false" test "$rc" -eq 0 -a -n "$(grep -x 'dispatch_flags=off' "$STUB_STATE/github_output")"
inputs_state dispatch-bad
run_inputs DISPATCH_FLAGS=yes
check "dispatch_flags yes fails, named" test "$rc" -eq 1 -a -n "$(grep -F "input dispatch_flags 'yes' must be true or false" <<<"$out")"

# ingress_cidrs (W5): empty opens the internet-facing ports to the Internet;
# ranges are the hardened mode, checked by uat/tofu's rule.
inputs_state ingress-default
run_inputs
check "outputs: public_ingress=internet by default" grep -qx "public_ingress=internet" "$STUB_STATE/github_output"
check "outputs: public_ingress_cidrs=[] by default" grep -qxF "public_ingress_cidrs=[]" "$STUB_STATE/github_output"
inputs_state ingress-cidrs
run_inputs INGRESS_CIDRS="203.0.113.0/24, 198.51.100.7/32 4.0.0.0/8"
check "ingress ranges pass" test "$rc" -eq 0
check "outputs: public_ingress=cidrs with ranges" grep -qx "public_ingress=cidrs" "$STUB_STATE/github_output"
check "outputs: the ranges as a JSON list, in order" grep -qxF 'public_ingress_cidrs=["203.0.113.0/24","198.51.100.7/32","4.0.0.0/8"]' "$STUB_STATE/github_output"
for c in 203.0.113.7/24 0.0.0.0/0 4.0.0.0/08 10.0.0.0/7 1.2.3.4/33 256.1.2.3/32 020.1.2.3/32 1.2.3/24 203.0.113.7 'Internet' '1.2.3.4/32;id' '::1/128'; do
  inputs_state ingress-bad
  run_inputs INGRESS_CIDRS="$c"
  check "ingress_cidrs '$c' fails, named" test "$rc" -eq 1 -a -n "$(grep -F "input ingress_cidrs: '$c'" <<<"$out")"
done
inputs_state ingress-repeated
run_inputs INGRESS_CIDRS="203.0.113.7/32 203.0.113.7/32"
check "a repeated ingress range fails, named" test "$rc" -eq 1 -a -n "$(grep -F "'203.0.113.7/32' is repeated" <<<"$out")"
inputs_state ingress-many
run_inputs INGRESS_CIDRS="$(for i in $(seq 1 51); do printf '20.0.%d.0/24 ' "$i"; done)"
check "more than 50 ingress ranges fail, named" test "$rc" -eq 1 -a -n "$(grep -F "51 ranges is more than 50" <<<"$out")"

inputs_state draft
run_inputs RELEASE_TAG=v0.1.0-rc.5
check "a draft release fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'still a draft' <<<"$out")"

for t in latest 0.1.0 v0.1 v0.1.0-beta.1 'v0.1.0;id' v0.1.0-rc.4x; do
  inputs_state badtag
  run_inputs RELEASE_TAG="$t"
  check "release_tag '$t' is refused before any lookup" test "$rc" -eq 1 -a "$(grep -c "gh api" "$STUB_STATE/calls.log")" -eq 0
done
inputs_state emptytag
run_inputs RELEASE_TAG=
check "an empty release_tag fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'input release_tag is empty' <<<"$out")"

inputs_state upgrade
run_inputs UPGRADE_FROM_TAG=v0.1.0-rc.3
check "a valid upgrade_from_tag passes" test "$rc" -eq 0 -a -n "$(grep -x 'upgrade_from_tag=v0.1.0-rc.3' "$STUB_STATE/github_output")"
check "... and is looked up too" grep -q "releases/tags/v0.1.0-rc.3" "$STUB_STATE/calls.log"
inputs_state upgrade-same
run_inputs UPGRADE_FROM_TAG=v0.1.0-rc.4
check "upgrade_from_tag equal to release_tag fails" test "$rc" -eq 1 -a -n "$(grep -F 'equals release_tag' <<<"$out")"
inputs_state upgrade-missing
run_inputs UPGRADE_FROM_TAG=v0.0.9
check "an upgrade_from_tag that does not exist fails, named" test "$rc" -eq 1 -a -n "$(grep -F 'input upgrade_from_tag: tag v0.0.9 does not exist' <<<"$out")"

for k in 169 -1 1.5 abc 1000; do
  inputs_state keep
  run_inputs KEEP_HOURS="$k"
  check "keep_hours '$k' is refused" test "$rc" -eq 1 -a -n "$(grep -F 'keep_hours' <<<"$out")"
done
inputs_state keep-ok
run_inputs KEEP_HOURS=2.0
check "keep_hours 2.0 is 2, and turns the final destroy off" test "$rc" -eq 0 -a -n "$(grep -x 'keep_hours=2' "$STUB_STATE/github_output")" -a -n "$(grep -x 'destroy=false' "$STUB_STATE/github_output")"
inputs_state keep-168
run_inputs KEEP_HOURS=168
check "keep_hours 168 is the most allowed" test "$rc" -eq 0

for t in smoke core resilience ingredients lifecycle all; do
  inputs_state tier
  run_inputs TIER="$t"
  check "tier $t is accepted" test "$rc" -eq 0
done
inputs_state tier-ha
run_inputs TIER=ha HUB_NODES=3
check "tier ha is accepted on the HA run, with a 7 hour budget" test "$rc" -eq 0 -a -n "$(grep -x 'tier=ha' "$STUB_STATE/github_output")" -a -n "$(grep -x 'run_budget_hours=7' "$STUB_STATE/github_output")"
inputs_state tier-ha-1
run_inputs TIER=ha
check "tier ha on one node per hub is refused, saying why" test "$rc" -eq 1 -a -n "$(grep -F 'input tier ha needs hub_nodes 3' <<<"$out")"
inputs_state tier-smoke
run_inputs TIER=smoke
check "a smoke run gets a 3 hour budget" grep -qx "run_budget_hours=3" "$STUB_STATE/github_output"
inputs_state tier-bad
run_inputs TIER=everything
check "an unknown tier is refused" test "$rc" -eq 1 -a -n "$(grep -F "input tier 'everything'" <<<"$out")"

inputs_state region
run_inputs REGION='central india'
check "a malformed region is refused" test "$rc" -eq 1

inputs_state scen
run_inputs SCENARIOS='C1, X4  I.file.managed,S1'
check "scenario ids split on commas and spaces" test "$rc" -eq 0 -a -n "$(grep -x 'scenarios=C1 X4 I.file.managed S1' "$STUB_STATE/github_output")"
# shellcheck disable=SC2016 # the expansions are the point: they must not run
for s in 'C1;rm' '$(id)' 'C1 `id`' '-run' 'C1 ../x' 'a|b'; do
  inputs_state scen-bad
  run_inputs SCENARIOS="$s"
  check "scenario list '$s' is refused" test "$rc" -eq 1
done

inputs_state many
run_inputs AZURE_CLIENT_ID= RELEASE_TAG=latest TIER=x KEEP_HOURS=999
check "every problem is reported in one run (4 here)" test "$rc" -eq 1 -a "$(grep -c '^::error::' <<<"$out")" -eq 4

###############################################################################
echo "# material.sh"
new_state material
m="$STUB_STATE/hub" e="$STUB_STATE/enroll"
mkdir -p "$m/core/out" "$e"
echo '{"saasapi_url":"https://uatabc123-core.centralindia.cloudapp.azure.com"}' >"$m/core/out/core.json"
echo '{"1":{"tenant_id":"t_aaaaaaaaaaaaaaaa"},"2":{"tenant_id":"t_bbbbbbbbbbbbbbbb"}}' >"$e/tenants.json"
echo '{"t1-ubuntu":{"sprout_id":"ubuntu-01","asset_id":"uat-abc123-t1-ubuntu"}}' >"$e/sprouts.json"
run material.sh "$testdata/uat.json" "$testdata/endpoints.json" "$e" "$m"
check "material.sh succeeds" test "$rc" -eq 0
check "uat.json, tenants.json and sprouts.json are copied" cmp -s "$e/sprouts.json" "$m/sprouts.json"
check "... tenants.json" cmp -s "$e/tenants.json" "$m/tenants.json"
check "... uat.json" cmp -s "$testdata/uat.json" "$m/uat.json"
check "harness.json: envoy_url is the DMZ FQDN on Envoy's node port" \
  test "$(jq -r .envoy_url "$m/harness.json")" = "https://uatabc123-dmz.centralindia.cloudapp.azure.com:8443"
check "harness.json: sprouts reach Envoy by the private name" \
  test "$(jq -r .sprout_envoy_address "$m/harness.json")" = "dmz.uat.imas.internal:8443"
echo '{"vmctl":"/x/vmctl.sh","envoy_url":"https://old"}' >"$m/harness.json"
jq '.private_dns_zone = "lite.test" | .dmz.ports.envoy = 9443' "$testdata/endpoints.json" >"$STUB_STATE/ep.json"
run material.sh "$testdata/uat.json" "$STUB_STATE/ep.json" "$e" "$m"
check "an existing harness.json keeps its other keys" test "$rc" -eq 0 -a "$(jq -r .vmctl "$m/harness.json")" = /x/vmctl.sh
check "the endpoints file's port and private zone are used" \
  test "$(jq -r '.envoy_url + " " + .sprout_envoy_address' "$m/harness.json")" = "https://uatabc123-dmz.centralindia.cloudapp.azure.com:9443 dmz.lite.test:9443"
rm "$m/core/out/core.json"
run material.sh "$testdata/uat.json" "$testdata/endpoints.json" "$e" "$m"
check "a directory without core.json is refused" test "$rc" -eq 1 -a -n "$(grep -F 'no core.json' <<<"$out")"
echo '{}' >"$m/core/out/core.json"
jq '.dmz.fqdn = "bad name;x"' "$testdata/endpoints.json" >"$STUB_STATE/ep.json"
run material.sh "$testdata/uat.json" "$STUB_STATE/ep.json" "$e" "$m"
check "a malformed FQDN is refused" test "$rc" -eq 1
rm "$e/sprouts.json"
run material.sh "$testdata/uat.json" "$testdata/endpoints.json" "$e" "$m"
check "a missing sprouts.json is refused" test "$rc" -eq 1
run material.sh only two
check "wrong argument count is a usage error" test "$rc" -eq 2

###############################################################################
echo "# collect-artifacts.sh"
# Fake credentials, assembled at run time so no secret-shaped literal sits in
# this file (gitleaks scans it): each has the shape the scanner must catch and
# a body of repeated letters, nothing else.
rep() { local r="" i; for ((i = 0; i < $2; i++)); do r+=$1; done; printf '%s' "$r"; }
PRIV="PRIV""ATE KEY"
fake_pem() { printf -- '-----BEGIN %s-----\n%s\n-----END %s-----\n' "$1$PRIV" "$(rep A 4)" "$1$PRIV"; }
fake_nkey() { printf '%s%s' "$1" "$(rep A 56)"; }               # 2 letters + 56: 58, like an NKey
fake_jwt() { printf '%s.%s.%s' "ey""J$(rep A 12)" "ey""J$(rep B 12)" "$(rep C 4)"; }
new_state collect
s="$STUB_STATE/state" o="$STUB_STATE/out"
mkdir -p "$s"/{report,k0s,hub/core/out,hub/core/sensitive/seeds,dmz,enroll/keys,secrets,access}
echo "PASS C1 ubuntu 1" >"$s/report/summary.txt"
echo '<testsuites/>' >"$s/report/junit.xml"
echo '{"Action":"pass","Test":"TestSmokeC1_CmdRunEverySprout","Output":"token minted for t1-admin (password grant)"}' >"$s/report/events.json"
cp "$testdata/uat.json" "$s/uat.json"
echo '{"core":["uat-core-1","uat-core-2","uat-core-3"],"dmz":["uat-dmz-1","uat-dmz-2","uat-dmz-3"]}' >"$s/ha_node_names.json"
echo '{"account_name":"imasuatabc123","blob_endpoint":"https://imasuatabc123.blob.core.windows.net/"}' >"$s/object_store.json"
cp "$testdata/endpoints.json" "$s/k0s/endpoints.json"
printf -- '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n' >"$s/k0s/uat-ca.crt"
echo 'hosts: [{ssh: {keyPath: /tmp/x/ssh_key}}]' >"$s/k0s/k0sctl-dmz.yaml"
cat >"$s/hub/core/out/core.json" <<EOF
{"saasapi_url":"https://x","internal_auth_header":"X-Internal-Auth","keycloak":{"token_url":"https://x/token","client_id":"imas-uat-tests","other_audience_client_id":"o"},
 "users":{"t1-admin":{"tenant":"1","roles":["imas-recipes-read"]}},"bootstrap_admin":{"pubkey":"$(fake_nkey UA)"},"sensitive_dir":"/s"}
EOF
echo '{"t1-ubuntu":{"tenant":1,"tenant_id":"t_a","key_id":"k_1","expires_at":"2026-10-06T18:00:00Z","key_file":"keys/t1-ubuntu.key"}}' >"$s/enroll/keys.json"
echo '{"t1-ubuntu":{"sprout_id":"ubuntu-01","asset_id":"a"}}' >"$s/enroll/sprouts.json"
echo '{"envoy":{"sprout_bus_url":"wss://dmz.uat.imas.internal:8443/"}}' >"$s/dmz/dmz.json"
echo '{"run_id":"abc123","release_tag":"v0.1.0-rc.4"}' >"$s/run.json"
# Things that must never be copied.
fake_pem "OPENSSH " >"$s/secrets/ssh_key"
echo 'users: [{user: {client-key-data: QUJD}}]' >"$s/k0s/dmz.kubeconfig"
echo '{"unseal_keys_b64":["placeholder"],"root_token":"placeholder"}' >"$s/hub/core/sensitive/openbao-init.json"
mkdir -p "$s/hub/core/sensitive/azure-blob" && echo 'bW9jay1henVyZS1rZXk=' >"$s/hub/core/sensitive/azure-blob/account-key"
fake_nkey SU >"$s/hub/core/sensitive/seeds/sys-user.nk"
echo 'k_1.secret' >"$s/enroll/keys/t1-ubuntu.key"
echo '{"t1-ubuntu":{"host":"127.0.0.1"}}' >"$s/access/access.json"
ln -s "$s/secrets/ssh_key" "$s/enroll/tenants.json"
run collect-artifacts.sh "$s" "$o"
check "collect succeeds on a run's state" test "$rc" -eq 0
listing=$(cd "$o" && find . -type f | sort)
expected=$(printf '%s\n' ./outputs/dmz/dmz.json ./outputs/enroll/keys.json ./outputs/enroll/sprouts.json \
  ./outputs/hub/core/out/core.json ./outputs/k0s/endpoints.json ./outputs/k0s/k0sctl-dmz.yaml ./outputs/k0s/uat-ca.crt \
  ./outputs/ha_node_names.json ./outputs/object_store.json ./outputs/run.json ./outputs/uat.json ./report/events.json ./report/junit.xml ./report/summary.txt | sort)
check "exactly the allowlisted, present, regular files are copied" test "$listing" = "$expected"
[ "$listing" = "$expected" ] || diff <(echo "$expected") <(echo "$listing")
check "no private key, kubeconfig, unseal key, seed or enrolment key in the output" \
  test -z "$(grep -rlE 'PRIVATE KEY|client-key-data|unseal|SUAAAA|k_1\.secret|bW9jay1henVyZS1rZXk' "$o")"
check "a symlink in the allowlist (to the SSH key) is not followed" test ! -e "$o/outputs/enroll/tenants.json"

leak_case() { # leak_case NAME STATE-REL OUT-REL CONTENT
  new_state "leak-$1"
  mkdir -p "$STUB_STATE/state/report" "$STUB_STATE/state/$(dirname "$2")"
  echo ok >"$STUB_STATE/state/report/summary.txt"
  printf '%s\n' "$4" >"$STUB_STATE/state/$2"
  run collect-artifacts.sh "$STUB_STATE/state" "$STUB_STATE/out"
  check "a $1 in $2 fails the step" test "$rc" -eq 1
  check "... is removed from the output" test ! -e "$STUB_STATE/out/$3"
  check "... and named in an error" grep -qF "::error::collect-artifacts.sh: removed $3" <<<"$out"
  check "... while clean files are kept" test -s "$STUB_STATE/out/report/summary.txt"
}
leak_case "JWT" report/events.json report/events.json "{\"Output\":\"Authorization: Bearer $(fake_jwt)\"}"
leak_case "JSON password" enroll/run.json outputs/enroll/run.json '{"password": "placeholder"}'
leak_case "client secret" hub/core/out/core.json outputs/hub/core/out/core.json '{"keycloak":{"client_secret":"placeholder"}}'
leak_case "NKey seed" uat.json outputs/uat.json "{\"x\":\"$(fake_nkey SO)\"}"
leak_case "private key" k0s/uat-ca.crt outputs/k0s/uat-ca.crt "$(fake_pem "EC ")"
leak_case "root token" dmz/dmz.json outputs/dmz/dmz.json '{"root_token": "placeholder"}'
leak_case "kubeconfig credential" k0s/k0sctl-core.yaml outputs/k0s/k0sctl-core.yaml 'client-key-data: QUJD'
run collect-artifacts.sh /nonexistent "$work/x"
check "a missing state directory is a usage error" test "$rc" -eq 2

###############################################################################
echo "# verify-teardown.sh"
vt() { VERIFY_ATTEMPTS=${VA:-3} VERIFY_INTERVAL=0 run verify-teardown.sh "$@"; }

new_state vt-clean
echo false >"$STUB_STATE/group_exists"
vt abc123
check "nothing left: exit 0" test "$rc" -eq 0
check "checks the group by name" grep -q "az group exists --name imas-uat-abc123" "$STUB_STATE/calls.log"
check "checks groups tagged with the run_id" grep -q "az group list --tag run_id=abc123" "$STUB_STATE/calls.log"
check "checks resources tagged with the run_id" grep -q "az resource list --tag run_id=abc123" "$STUB_STATE/calls.log"
check "deletes nothing" test -z "$(grep -E 'delete' "$STUB_STATE/calls.log")"

new_state vt-group
echo true >"$STUB_STATE/group_exists"
vt abc123
check "the group still there: exit 1, named" test "$rc" -eq 1 -a -n "$(grep -F 'resource group imas-uat-abc123' <<<"$out")"
check "... after every attempt (3)" test "$(grep -c 'az group exists' "$STUB_STATE/calls.log")" -eq 3

new_state vt-resource
echo false >"$STUB_STATE/group_exists"
echo "/subscriptions/x/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/publicIPAddresses/stray" >"$STUB_STATE/leftovers"
vt abc123
check "a resource tagged run_id elsewhere: exit 1, listed" test "$rc" -eq 1 -a -n "$(grep -F 'publicIPAddresses/stray' <<<"$out")"

# The HA topology's own resources (P24, uat/tofu/lb.tf): load balancers and
# their public IP, each tagged with the run_id, are listed like any other.
new_state vt-ha
echo false >"$STUB_STATE/group_exists"
printf '%s\n' \
  "/subscriptions/x/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/loadBalancers/uat-core-ilb" \
  "/subscriptions/x/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/loadBalancers/uat-dmz-lb" \
  "/subscriptions/x/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/publicIPAddresses/uat-dmz-lb-pip" >"$STUB_STATE/leftovers"
vt abc123
check "HA leftovers (load balancers, their public IP): exit 1, each listed" test "$rc" -eq 1 -a \
  -n "$(grep -F 'loadBalancers/uat-core-ilb' <<<"$out")" -a -n "$(grep -F 'loadBalancers/uat-dmz-lb' <<<"$out")" -a \
  -n "$(grep -F 'publicIPAddresses/uat-dmz-lb-pip' <<<"$out")"

new_state vt-taggedgroup
echo false >"$STUB_STATE/group_exists"
echo "some-other-rg" >"$STUB_STATE/tagged_groups"
vt abc123
check "another group tagged run_id: exit 1, listed" test "$rc" -eq 1 -a -n "$(grep -F 'some-other-rg' <<<"$out")"

new_state vt-error
echo error >"$STUB_STATE/group_exists"
vt abc123
check "az group exists failing counts as remaining (fail closed)" test "$rc" -eq 1
new_state vt-listerror
echo false >"$STUB_STATE/group_exists"
touch "$STUB_STATE/resource_list_fail"
vt abc123
check "az resource list failing counts as remaining (fail closed)" test "$rc" -eq 1

new_state vt-eventually
printf 'true\ntrue\nfalse\n' >"$STUB_STATE/group_exists"
VA=5 vt abc123
check "a group that goes away on the third check passes" test "$rc" -eq 0 -a "$(grep -c 'az group exists' "$STUB_STATE/calls.log")" -eq 3

new_state vt-usage
vt 'ABC;x'
check "a malformed run_id is a usage error, with no az call" test "$rc" -eq 2 -a ! -s "$STUB_STATE/calls.log"

###############################################################################
echo "# janitor.sh select (the tag and expiry filter)"
sel=$(bash "$scripts/janitor.sh" select "$testdata/groups.json" --now 2026-10-06T12:00:00Z)
rc=$?
check "select on the sample listing succeeds" test "$rc" -eq 0
del=$(jq -r '.delete[].name' <<<"$sel" | sort | tr '\n' ' ')
check "deletes exactly the expired, tagged, consistent groups (got: $del)" \
  test "$del" = "imas-uat-abc123 imas-uat-edge0001 imas-uat-frac0001 imas-uat-offset1 "
all=$(jq -r '[.delete[], .keep[], .problems[]] | .[].name' <<<"$sel")
for g in imas-uat-state production-rg imas-uat-nontag1 imas-uat-upper01 imas-uat-keycase; do
  if grep -qx "$g" <<<"$all"; then nok "$g (not tagged purpose=imas-uat exactly) is not even considered"; else ok "$g (not tagged purpose=imas-uat exactly) is not even considered"; fi
done
reason() { jq -r --arg n "$1" '[.keep[], .problems[]] | .[] | select(.name == $n) | .reason' <<<"$sel"; }
check "not expired yet: kept" test "$(reason imas-uat-keep01)" = "not expired"
check "an offset time still in the future (13:00-01:00 = 14:00Z): kept" test "$(reason imas-uat-offset2)" = "not expired"
check "already Deleting: kept" test "$(reason imas-uat-deleting)" = "already being deleted"
check "no expires_at: a problem, not deleted" test "$(reason imas-uat-noexp01)" = "no expires_at tag"
check "a malformed expires_at: a problem, not deleted" grep -q "not an RFC 3339 time" <<<"$(reason imas-uat-badexp01)"
check "run_id tag differing from the name: a problem, not deleted" grep -q "does not match the name" <<<"$(reason imas-uat-mism01)"
check "a name that is not imas-uat-<run_id>: a problem, not deleted" grep -q "name is not" <<<"$(reason team-imas-uat-x)"
sel2=$(bash "$scripts/janitor.sh" select "$testdata/groups.json" --now 2026-10-06T09:00:00Z)
check "at 09:00Z nothing in the sample has expired yet" test "$(jq '.delete | length' <<<"$sel2")" -eq 0
sel3=$(bash "$scripts/janitor.sh" select "$testdata/groups.json" --now 2030-01-01T00:00:00Z)
check "years later, every consistent tagged group but the Deleting one is due" test "$(jq '.delete | length' <<<"$sel3")" -eq 6
check "... and the problems are still never due" test "$(jq '.problems | length' <<<"$sel3")" -eq 4
sel4=$(bash "$scripts/janitor.sh" select "$testdata/groups.json" --now 1791288000)
check "--now accepts epoch seconds (2026-10-06T12:00:00Z)" test "$(jq -c '[.delete[].name] | sort' <<<"$sel4")" = "$(jq -c '[.delete[].name] | sort' <<<"$sel")"
echo '{"not":"an array"}' >"$work/notarray.json"
if bash "$scripts/janitor.sh" select "$work/notarray.json" 2>/dev/null; then nok "a listing that is not an array fails"; else ok "a listing that is not an array fails"; fi
if bash "$scripts/janitor.sh" select "$testdata/groups.json" --now tomorrow 2>/dev/null; then nok "--now tomorrow is a usage error"; else ok "--now tomorrow is a usage error"; fi

echo "# janitor.sh run"
janitor_state() {
  new_state "janitor-$1"
  cp "$testdata/groups.json" "$STUB_STATE/groups.json"
  mkdir -p "$STUB_STATE/delete_fail" "$STUB_STATE/show"
}
jrun() { JANITOR_NOW=2026-10-06T12:00:00Z GITHUB_STEP_SUMMARY="$STUB_STATE/summary.md" run janitor.sh run "$@"; }
deleted_names() { grep -oE 'az group delete --name [^ ]+' "$STUB_STATE/calls.log" | awk '{print $5}' | sort | tr '\n' ' '; }

janitor_state run
jrun
check "run exits 0 when every due group is deleted" test "$rc" -eq 0
check "lists only groups tagged purpose=imas-uat" grep -q "az group list --tag purpose=imas-uat -o json" "$STUB_STATE/calls.log"
check "deletes exactly the due groups (got: $(deleted_names))" \
  test "$(deleted_names)" = "imas-uat-abc123 imas-uat-edge0001 imas-uat-frac0001 imas-uat-offset1 "
check "reads each group again before deleting it" test "$(grep -c 'az group show' "$STUB_STATE/calls.log")" -eq 4
check "force-deletes the VMs" grep -q "delete --name imas-uat-abc123 --yes --force-deletion-types Microsoft.Compute/virtualMachines" "$STUB_STATE/calls.log"
check "the summary lists what it deleted" grep -q "^- imas-uat-abc123 (expired 2026-10-06T10:00:00Z)" "$STUB_STATE/summary.md"
check "the summary counts the deletions" grep -q "^Deleted: 4" "$STUB_STATE/summary.md"
check "the summary lists what it kept and why" grep -q "^- imas-uat-keep01: not expired" "$STUB_STATE/summary.md"
check "the problems are warnings" grep -q "::warning::janitor.sh: imas-uat-noexp01: no expires_at tag" <<<"$out"
check "the untagged and differently tagged groups are still there" \
  test "$(jq -r '.[].name' "$STUB_STATE/groups.json" | grep -cE '^(imas-uat-state|production-rg|imas-uat-nontag1|imas-uat-upper01|imas-uat-keycase)$')" -eq 5

janitor_state dry
jrun --dry-run
check "--dry-run deletes nothing" test "$rc" -eq 0 -a -z "$(grep 'group delete' "$STUB_STATE/calls.log")"
check "--dry-run still lists what it would delete" grep -q "imas-uat-abc123 (expired 2026-10-06T10:00:00Z; dry run, not deleted)" "$STUB_STATE/summary.md"

janitor_state retagged
# Between the listing and the delete, someone re-tagged abc123 to live longer.
jq '.[] | select(.name == "imas-uat-abc123") | .tags.expires_at = "2026-10-07T00:00:00Z"' \
  "$STUB_STATE/groups.json" >"$STUB_STATE/show/imas-uat-abc123"
jrun
check "a group whose tags changed since the listing is left alone" \
  test "$rc" -eq 0 -a -z "$(grep 'delete --name imas-uat-abc123' "$STUB_STATE/calls.log")"

janitor_state gone
# The listing has offset1, but by the second read it is gone.
cp "$STUB_STATE/groups.json" "$STUB_STATE/listing.json"
jq 'map(select(.name != "imas-uat-offset1"))' "$STUB_STATE/listing.json" >"$STUB_STATE/groups.json"
jrun
check "a group gone by the second read is skipped, not an error" \
  test "$rc" -eq 0 -a -z "$(grep 'delete --name imas-uat-offset1' "$STUB_STATE/calls.log")"

janitor_state fail
touch "$STUB_STATE/delete_fail/imas-uat-offset1"
jrun
check "a failed deletion fails the run" test "$rc" -eq 1
check "... names it" grep -q "::error::janitor.sh: could not delete imas-uat-offset1" <<<"$out"
check "... and the others are still deleted" test "$(deleted_names)" = "imas-uat-abc123 imas-uat-edge0001 imas-uat-frac0001 imas-uat-offset1 "

janitor_state listfail
touch "$STUB_STATE/list_fail"
jrun
check "a failed listing fails the run and deletes nothing" test "$rc" -eq 1 -a -z "$(grep 'group delete' "$STUB_STATE/calls.log")"

janitor_state empty
echo '[]' >"$STUB_STATE/groups.json"
jrun
check "nothing tagged: exit 0, nothing deleted" test "$rc" -eq 0 -a -n "$(grep '^Deleted: 0' "$STUB_STATE/summary.md")"

if bash "$scripts/janitor.sh" bogus 2>/dev/null; then nok "an unknown command is a usage error"; else ok "an unknown command is a usage error"; fi

###############################################################################
echo "# azure-owner-setup.sh"
# srun ARGS...: runs the script with the stubs first on PATH and no waiting.
srun() {
  out=$(PATH="$stubs:$PATH" SETUP_RETRY_SLEEP=0 bash "$scripts/azure-owner-setup.sh" "$@" 2>&1 </dev/null)
  rc=$?
}
created() { grep -c -e 'ad app create' -e 'ad sp create' -e 'role assignment create' -e 'federated-credential create' "$STUB_STATE/calls.log" || true; }


new_state setup_fresh
srun --yes
check "a fresh subscription: exit 0" test "$rc" -eq 0
check "... creates the app registration" grep -q -- 'az ad app create --display-name imas-uat-github' "$STUB_STATE/calls.log"
check "... creates the service principal" grep -q -- 'az ad sp create --id 33333333' "$STUB_STATE/calls.log"
check "... assigns Contributor on the subscription by object id" grep -q -- 'role assignment create --assignee-object-id 44444444-4444-4444-4444-444444444444 --assignee-principal-type ServicePrincipal --role Contributor --scope /subscriptions/11111111-1111-1111-1111-111111111111' "$STUB_STATE/calls.log"
check "... registers the five resource providers" test "$(grep -c 'az provider register' "$STUB_STATE/calls.log")" -eq 5
check "... adds the federated credentials of uat and uat-janitor" test "$(sort "$STUB_STATE/fed_subjects" | tr '\n' ' ')" = "repo:yogzblr@16265408/imas@1388858987:environment:uat repo:yogzblr@16265408/imas@1388858987:environment:uat-janitor "
check "... prints the three variables" test "$(grep -c -e '^  AZURE_CLIENT_ID=33333333-3333-3333-3333-333333333333$' -e '^  AZURE_TENANT_ID=22222222-2222-2222-2222-222222222222$' -e '^  AZURE_SUBSCRIPTION_ID=11111111-1111-1111-1111-111111111111$' <<<"$out")" -eq 3
check "... and the service principal's object id" grep -q '^  44444444-4444-4444-4444-444444444444$' <<<"$out"
check "... does not accept the marketplace terms unasked" test -z "$(grep 'vm image terms' "$STUB_STATE/calls.log")"
check "... asks for no secret: no password or secret is created" test -z "$(grep -i -e 'credential reset' -e 'password' -e 'secret' "$STUB_STATE/calls.log")"

first=$(created)
srun --yes
check "the first run created five things: app, service principal, role, two credentials" test "$first" -eq 5
check "a second run: exit 0" test "$rc" -eq 0
check "... creates nothing more" test "$(created)" -eq 5
check "... says it is already done, five times" test "$(grep -c 'already there' <<<"$out")" -eq 5

new_state setup_login
touch "$STUB_STATE/not_logged_in"
srun --yes
check "logged out: it runs a device code login first" grep -q -- 'az login --use-device-code' "$STUB_STATE/calls.log"
check "... and then carries on" test "$rc" -eq 0 -a -f "$STUB_STATE/sp_exists"

new_state setup_loggedin
srun --yes
check "already logged in: no login" test -z "$(grep 'az login' "$STUB_STATE/calls.log")"

new_state setup_nojanitor
srun --yes --no-janitor --repo someone/else
check "--no-janitor and --repo: only the uat subject, with that repository's ids" test "$(cat "$STUB_STATE/fed_subjects")" = "repo:someone@16265408/else@1388858987:environment:uat"
check "... the ids came from gh api repos/someone/else" grep -q -- 'gh api repos/someone/else' "$STUB_STATE/calls.log"

new_state setup_terms
srun --yes --accept-image-terms
check "--accept-image-terms accepts the AlmaLinux terms" grep -q -- 'az vm image terms accept --publisher almalinux --offer almalinux-x86_64 --plan 9-gen2' "$STUB_STATE/calls.log"

new_state setup_sub
srun --yes --subscription 55555555-5555-5555-5555-555555555555
check "--subscription selects it and uses it for the role scope" grep -q -- '--scope /subscriptions/55555555-5555-5555-5555-555555555555' "$STUB_STATE/calls.log"

new_state setup_noconfirm
srun
check "no --yes and no answer: exit 1, nothing changed" test "$rc" -eq 1 -a "$(created)" -eq 0 -a -z "$(grep 'provider register' "$STUB_STATE/calls.log")"
check "... says it was not confirmed" grep -q 'not confirmed' <<<"$out"

new_state setup_confirm
out=$(echo y | PATH="$stubs:$PATH" SETUP_RETRY_SLEEP=0 bash "$scripts/azure-owner-setup.sh" 2>&1)
rc=$?
check "answering y proceeds" test "$rc" -eq 0 -a -f "$STUB_STATE/role_assigned"

new_state setup_retry
echo 2 >"$STUB_STATE/role_fail_times"
srun --yes
check "a role assignment that fails twice is retried and then succeeds" test "$rc" -eq 0 -a -f "$STUB_STATE/role_assigned" -a "$(grep -c 'role assignment create' "$STUB_STATE/calls.log")" -eq 3

new_state setup_retry_fail
echo 99 >"$STUB_STATE/role_fail_times"
srun --yes
check "a role assignment that never works: exit 1, six tries, no credential created" test "$rc" -eq 1 -a "$(grep -c 'role assignment create' "$STUB_STATE/calls.log")" -eq 6 -a -z "$(grep 'federated-credential create' "$STUB_STATE/calls.log")"

new_state setup_twoapps
printf '%s\n' aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >"$STUB_STATE/app_ids"
srun --yes
check "two app registrations of that name: exit 1, nothing created" test "$rc" -eq 1 -a "$(created)" -eq 0

new_state setup_badargs
srun --subscription not-a-guid
check "a malformed subscription id is refused" test "$rc" -eq 1
srun --repo 'bad repo'
check "a malformed repository is refused" test "$rc" -eq 1
srun --bogus
check "an unknown argument is refused" test "$rc" -eq 1
check "... and no az call was made" test ! -s "$STUB_STATE/calls.log"

new_state setup_ids_flags
srun --yes --owner-id 7 --repo-id 9
check "--owner-id and --repo-id: used, and gh is not called" test "$rc" -eq 0 -a "$(sort "$STUB_STATE/fed_subjects" | head -n 1)" = "repo:yogzblr@7/imas@9:environment:uat" -a -z "$(grep '^gh ' "$STUB_STATE/calls.log")"
srun --yes --owner-id x --repo-id 9
check "a non-numeric owner id is refused" test "$rc" -eq 1

new_state setup_gh_fail
touch "$STUB_STATE/gh_repo_fail"
srun --yes
check "gh cannot read the repository: exit 1, nothing changed, names the flags" test "$rc" -eq 1 -a "$(created)" -eq 0 -a -z "$(grep 'provider register' "$STUB_STATE/calls.log")" && grep -q -- '--owner-id' <<<"$out"

new_state setup_stale
printf 'imas-uat-env\trepo:yogzblr/imas:environment:uat\nimas-uat-janitor-env\trepo:yogzblr/imas:environment:uat-janitor\n' >"$STUB_STATE/fed_creds"
srun --yes
check "stale plain-subject credentials: exit 0" test "$rc" -eq 0
check "... both are deleted by name" test "$(grep -c 'federated-credential delete' "$STUB_STATE/calls.log")" -eq 2 -a "$(grep -c -e 'federated-credential-id imas-uat-env$' -e 'federated-credential-id imas-uat-janitor-env$' "$STUB_STATE/calls.log")" -eq 2
check "... and replaced by the ID-based ones" test "$(sort "$STUB_STATE/fed_subjects" | tr '\n' ' ')" = "repo:yogzblr@16265408/imas@1388858987:environment:uat repo:yogzblr@16265408/imas@1388858987:environment:uat-janitor "
srun --yes
check "... a second run deletes nothing more" test "$(grep -c 'federated-credential delete' "$STUB_STATE/calls.log")" -eq 2

new_state setup_hand_made
printf 'my-uat\trepo:yogzblr@16265408/imas@1388858987:environment:uat\nmy-janitor\trepo:yogzblr@16265408/imas@1388858987:environment:uat-janitor\nold\trepo:yogzblr/imas:environment:uat\n' >"$STUB_STATE/fed_creds"
srun --yes
check "credentials made by hand with the right subjects are kept; the plain one is deleted" test "$rc" -eq 0 -a "$(grep -c 'federated-credential create' "$STUB_STATE/calls.log")" -eq 0 -a "$(grep -c 'federated-credential delete' "$STUB_STATE/calls.log")" -eq 1

new_state setup_name_taken
printf 'imas-uat-env\trepo:other/thing:environment:uat\n' >"$STUB_STATE/fed_creds"
srun --yes
check "the name taken by an unrelated subject: exit 1, not deleted" test "$rc" -eq 1 -a -z "$(grep 'federated-credential delete' "$STUB_STATE/calls.log")"

new_state setup_fedfail
touch "$STUB_STATE/fed_fail"
srun --yes
check "a failed federated credential: exit 1" test "$rc" -eq 1

###############################################################################
echo "# tofu-outputs.sh"
# tofu_state CASE: the stub tofu's state outputs. CASE is missing (the
# single-node run: object_store is null, so OpenTofu 1.11 does not store it),
# null (a stored null) or object (the HA run).
tofu_state() {
  local os
  case "$1" in
    missing) os='{}' ;;
    null) os='{"object_store": {"sensitive": false, "type": "dynamic", "value": null}}' ;;
    object) os='{"object_store": {"sensitive": false, "type": ["object", {"account_name": "string", "blob_endpoint": "string"}], "value": {"account_name": "imasuatabc123", "blob_endpoint": "https://imasuatabc123.blob.core.windows.net/"}}}' ;;
  esac
  local key=""
  [ "$1" = object ] && key=s3cr3tAccountKey==
  jq -n --argjson os "$os" --arg key "$key" '{
    uat: {sensitive: false, type: "dynamic", value: {run_id: "abc12345", resource_group: "imas-uat-abc12345"}},
    ha_node_names: {sensitive: false, type: "dynamic", value: {core: [], dmz: []}},
    ssh_private_key: {sensitive: true, type: "string", value: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"},
    windows_admin_password: {sensitive: true, type: "string", value: "Wp4ss-word!"},
    object_store_account_key: {sensitive: true, type: "string", value: $key}
  } + $os' >"$STUB_STATE/tofu_outputs.json"
}
jqok() { jq -e "$@" >/dev/null; }
# tout ARGS...: tofu-outputs.sh with the stubs on PATH, in a TOFU_DIR of its own.
tout() {
  out=$(cd "$STUB_STATE" && PATH="$stubs:$PATH" TOFU_DIR=tofu bash "$scripts/tofu-outputs.sh" "$@" 2>&1)
  rc=$?
}
# The step the workflow had before (Run 2, hub_nodes 1, v0.1.0-rc.15): the
# direct call fails on the output tofu did not store.
new_state tofu-old
tofu_state missing
out=$(PATH="$stubs:$PATH" tofu -chdir=uat/tofu output -json object_store 2>&1)
check "the old direct read of a null object_store fails as Run 2 did" grep -q 'Output "object_store" not found' <<<"$out"

for c in missing null object; do
  new_state "tofu-$c"
  tofu_state "$c"
  mkdir -p "$STUB_STATE/state" "$STUB_STATE/secrets"
  tout outputs "$STUB_STATE/state"
  check "outputs ($c object_store): exit 0" test "$rc" -eq 0
  check "outputs ($c): uat.json is the uat output" jqok '.resource_group == "imas-uat-abc12345"' "$STUB_STATE/state/uat.json"
  check "outputs ($c): ha_node_names.json is the ha_node_names output" jqok '. == {core: [], dmz: []}' "$STUB_STATE/state/ha_node_names.json"
  if [ "$c" = object ]; then
    check "outputs (object): object_store.json is the object" jqok '. == {account_name: "imasuatabc123", blob_endpoint: "https://imasuatabc123.blob.core.windows.net/"}' "$STUB_STATE/state/object_store.json"
  else
    check "outputs ($c): object_store.json is null" test "$(cat "$STUB_STATE/state/object_store.json")" = null
  fi
  check "outputs ($c): no sensitive value in the state directory" test -z "$(grep -rlE 'OPENSSH|Wp4ss|s3cr3t' "$STUB_STATE/state")"
  check "outputs ($c): the tofu root is TOFU_DIR" test -z "$(grep -v '^tofu -chdir=tofu output' "$STUB_STATE/calls.log")"

  : >"$STUB_STATE/calls.log"
  tout credentials "$STUB_STATE/state" "$STUB_STATE/secrets"
  check "credentials ($c): exit 0" test "$rc" -eq 0
  check "credentials ($c): the SSH key, 0600" test "$(stat -c %a "$STUB_STATE/secrets/ssh_key")" = 600 -a "$(sed -n 2p "$STUB_STATE/secrets/ssh_key")" = b3BlbnNzaC1rZXktdjEAAAAA
  check "credentials ($c): the WinRM password, 0600" test "$(stat -c %a "$STUB_STATE/secrets/winrm_password")" = 600 -a "$(cat "$STUB_STATE/secrets/winrm_password")" = 'Wp4ss-word!'
  check "credentials ($c): the SSH key body is masked" grep -qx '::add-mask::b3BlbnNzaC1rZXktdjEAAAAA' <<<"$out"
  check "credentials ($c): the password is masked" grep -qx '::add-mask::Wp4ss-word!' <<<"$out"
  blob="$STUB_STATE/state/hub/core/sensitive/azure-blob"
  if [ "$c" = object ]; then
    check "credentials (object): the account key is read" grep -qx 'tofu -chdir=tofu output -raw object_store_account_key' "$STUB_STATE/calls.log"
    check "credentials (object): the account key is masked" grep -qx '::add-mask::s3cr3tAccountKey==' <<<"$out"
    check "credentials (object): account-key and account-name for Versity Gateway" test "$(cat "$blob/account-key")" = 's3cr3tAccountKey==' -a "$(cat "$blob/account-name")" = imasuatabc123
    check "credentials (object): account-key is 0600" test "$(stat -c %a "$blob/account-key")" = 600
  else
    check "credentials ($c): the account key is not read" test -z "$(grep object_store_account_key "$STUB_STATE/calls.log")"
    check "credentials ($c): no azure-blob directory" test ! -e "$blob"
  fi
done

new_state tofu-bad-object
tofu_state object
jq '.object_store.value = {blob_endpoint: "x"}' "$STUB_STATE/tofu_outputs.json" >"$STUB_STATE/o" && mv "$STUB_STATE/o" "$STUB_STATE/tofu_outputs.json"
mkdir -p "$STUB_STATE/state"
tout outputs "$STUB_STATE/state"
check "outputs: an object_store without account_name: exit 1, named" test "$rc" -eq 1 -a -n "$(grep 'neither null nor an object' <<<"$out")"
jq '.object_store.value = false' "$STUB_STATE/tofu_outputs.json" >"$STUB_STATE/o" && mv "$STUB_STATE/o" "$STUB_STATE/tofu_outputs.json"
tout outputs "$STUB_STATE/state"
check "outputs: an object_store of false is not read as null: exit 1, named" test "$rc" -eq 1 -a -n "$(grep 'neither null nor an object' <<<"$out")"

new_state tofu-no-uat
tofu_state missing
jq 'del(.uat)' "$STUB_STATE/tofu_outputs.json" >"$STUB_STATE/o" && mv "$STUB_STATE/o" "$STUB_STATE/tofu_outputs.json"
mkdir -p "$STUB_STATE/state"
tout outputs "$STUB_STATE/state"
check "outputs: a missing uat output still fails" test "$rc" -ne 0

new_state tofu-empty-key
tofu_state object
jq '.object_store_account_key.value = ""' "$STUB_STATE/tofu_outputs.json" >"$STUB_STATE/o" && mv "$STUB_STATE/o" "$STUB_STATE/tofu_outputs.json"
mkdir -p "$STUB_STATE/state" "$STUB_STATE/secrets"
tout outputs "$STUB_STATE/state"
tout credentials "$STUB_STATE/state" "$STUB_STATE/secrets"
check "credentials: an object_store with an empty account key: exit 1, named" test "$rc" -eq 1 -a -n "$(grep 'object_store_account_key is empty' <<<"$out")"

tout bogus
check "an unknown subcommand is a usage error" test "$rc" -eq 1 -a -n "$(grep usage <<<"$out")"

###############################################################################
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
