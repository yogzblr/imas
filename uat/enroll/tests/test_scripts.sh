#!/usr/bin/env bash
# Tests for the uat/enroll shell scripts, against a fake saasapi (tests/fake/curl,
# a curl stand-in) and fake ansible-playbook/ansible-galaxy:
#   - create-tenants.sh: both tenants, one one-time key per sprout in its own
#     tenant, files and modes, re-runs, the token/tenant mismatch, rate limits,
#     a failed tenant, argument errors, and that no secret is printed or put
#     on a command line;
#   - wait-connected.sh: asset links, waiting for farmer's "connected", the
#     link conflict and the timeout, and sprouts.json;
#   - enroll.sh: the order of the steps, the inventory it hands Ansible, and a
#     failing playbook stopping the run;
#   - playbooks/seed-sproutid.yml and collect.yml, run for real against
#     localhost with temporary paths, when ansible-playbook is installed and
#     this runs as root (the seed play writes root-owned files).
#
#   bash uat/enroll/tests/test_scripts.sh
#
# Needs: bash, jq, python3, base64. Optional: ansible-playbook (the real one).
#
# The single-quoted $names below belong to bash -c scripts and jq programs.
# shellcheck disable=SC2016
set -euo pipefail

tests="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
enroll="$(dirname "$tests")"
repo="$(cd "$enroll/../.." && pwd)"
for tool in jq python3 base64; do
	command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
real_playbook="$(command -v ansible-playbook || true)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export PATH="$tests/fake:$PATH" UAT_ENROLL_POLL_SECONDS=0 FAKE_SECRET="shared-SHHH-secret"

fails=0
pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; fails=$((fails + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null; then pass "$d"; else fail "$d"; fi; }
# no_secret FILE...: none of the secrets the fakes hand out appear.
no_secret() { ! grep -q -E 'SEKRIT|SHHH|TOKSIGNATURE|PWSECRET|KCADMINSIG|kcadmin-pw' "$@"; }

testdata="$enroll/testdata"
printf '%s\n' "$FAKE_SECRET" >"$work/internal-auth"

# fresh NAME: a new fake saasapi and state directory, as $FAKE_DIR and $state.
fresh() {
	export FAKE_DIR="$work/$1/fake"
	state="$work/$1/state"
	mkdir -p "$FAKE_DIR"
	unset FAKE_PENDING_POLLS FAKE_TENANT_FAILS FAKE_429 FAKE_CONNECT_AFTER FAKE_LINK_CONFLICT FAKE_PLAYBOOK_FAIL
}
ct() {
	"$enroll/create-tenants.sh" --uat "$testdata/uat.json" --state "$state" \
		--saasapi-url https://saas.uat.test --internal-auth-file "$work/internal-auth" "$@"
}

echo "# create-tenants.sh"
fresh happy
rc=0
ct --token-cmd "$tests/fake/token-cmd" >"$work/out" 2>"$work/err" || rc=$?
check "creates both tenants and exits 0" [ "$rc" -eq 0 ]
check "two POST /v1/tenants" [ "$(grep -c '^POST /v1/tenants$' "$FAKE_DIR/log")" -eq 2 ]
check "tenants.json has tenant 1 and 2, active" \
	jq -e 'keys == ["1","2"] and ([.[].status] | all(. == "active"))' "$state/tenants.json"
check "run.json records the run and saasapi" jq -e '. == {run_id: "abc123", saasapi_url: "https://saas.uat.test"}' "$state/run.json"
t1="$(jq -r '.["1"].tenant_id' "$state/tenants.json")"
t2="$(jq -r '.["2"].tenant_id' "$state/tenants.json")"
check "the two tenants differ" [ "$t1" != "$t2" ]
check "tenant names carry the run id" jq -e '.["1"].name == "uat-abc123-t1" and .["2"].name == "uat-abc123-t2"' "$state/tenants.json"
check "six keys minted, each one use" \
	jq -e '(.keys | length) == 6 and ([.keys[].request.max_uses] | all(. == 1)) and ([.keys[].request.expires_in_hours] | all(. == 6))' "$FAKE_DIR/state.json"
check "three keys in each tenant" \
	jq -e --arg a "$t1" --arg b "$t2" '([.keys[] | select(.tenant_id == $a)] | length) == 3 and ([.keys[] | select(.tenant_id == $b)] | length) == 3' "$FAKE_DIR/state.json"
check "each sprout's key is from its own tenant" \
	jq -e --arg a "$t1" --arg b "$t2" 'to_entries | all(if (.key | startswith("t1-")) then .value.tenant_id == $a and .value.tenant == 1 else .value.tenant_id == $b and .value.tenant == 2 end)' "$state/keys.json"
check "a key file per sprout holding the registration key" \
	bash -c 'for v in t1-ubuntu t1-alma t1-win t2-ubuntu t2-alma t2-win; do grep -qE "^ek_[0-9]{4}\.SEKRIT[0-9]{4}xyz$" "$1/keys/$v.key" || exit 1; done' _ "$state"
check "key files are mode 600, the state dir 700" \
	bash -c '[ "$(stat -c %a "$1")" = 700 ] && for f in "$1"/keys/*.key; do [ "$(stat -c %a "$f")" = 600 ] || exit 1; done' _ "$state"
check "key id matches the key file" \
	bash -c 'kid="$(jq -r ".[\"t2-win\"].key_id" "$1/keys.json")"; grep -q "^$kid\." "$1/keys/t2-win.key"' _ "$state"
check "the hook got the tenant id for tenant-scoped calls" grep -q "^1 $t1$" "$FAKE_DIR/token-cmd.log"
check "prints tenant and key ids" grep -q "t2-alma: tenant 2 key ek_" "$work/out"
check "prints no secret (stdout, stderr)" no_secret "$work/out" "$work/err"
check "no secret on any curl command line" no_secret "$FAKE_DIR/argv"
check "no secret left in work files" bash -c '! ls -A "$1" | grep -q "^\.work"' _ "$state"

: >"$FAKE_DIR/log"
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>"$work/err"
check "a re-run creates no tenant and mints no key" bash -c '! grep -qE "^POST /v1/tenants$|enrollment-keys" "$1"' _ "$FAKE_DIR/log"
check "a re-run says it reuses" grep -q "reusing $t1" "$work/err"
ct --token-cmd "$tests/fake/token-cmd" --new-keys >/dev/null 2>&1
check "--new-keys mints six more" jq -e '(.keys | length) == 12' "$FAKE_DIR/state.json"

fresh mismatch
b64url() { base64 | tr -d '=\n' | tr '/+' '_-'; }
for n in 1 2; do
	printf '%s.%s.TOKSIGNATURE\n' "$(printf '{"alg":"none"}' | b64url)" \
		"$(printf '{"organization":{"id":"kc-org-%s"}}' "$n" | b64url)" >"$work/static-t$n"
done
rc=0
ct --token-t1 "$work/static-t1" --token-t2 "$work/static-t2" >"$work/out" 2>"$work/err" || rc=$?
check "a token for another organization: exit 3" [ "$rc" -eq 3 ]
check "it names the tenant id and the token's organization" grep -q "organization.id is 'kc-org-1'" "$work/err"
check "the tenant was created and recorded before stopping" jq -e '.["1"].tenant_id | startswith("t_")' "$state/tenants.json"
check "prints no secret on the error path" no_secret "$work/out" "$work/err"
rc=0
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1 || rc=$?
check "a re-run with a matching token completes" [ "$rc" -eq 0 ]
check "and reuses the tenant created before" [ "$(grep -c '^POST /v1/tenants$' "$FAKE_DIR/log")" -eq 2 ]

fresh ratelimit
export FAKE_429=3
rc=0
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1 || rc=$?
check "rate limited mints are retried" [ "$rc" -eq 0 ]
check "and all six keys exist" jq -e '(.keys | length) == 6' "$FAKE_DIR/state.json"

fresh failed
export FAKE_TENANT_FAILS=1
rc=0
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>"$work/err" || rc=$?
check "a failed tenant stops the run" [ "$rc" -eq 1 ]
check "with its last_error" grep -q "farmer refused the account" "$work/err"
check "and no key is minted" bash -c '! grep -q enrollment-keys "$1"' _ "$FAKE_DIR/log"

fresh badauth
printf 'wrong\n' >"$work/wrong-auth"
rc=0
"$enroll/create-tenants.sh" --uat "$testdata/uat.json" --state "$state" --saasapi-url https://saas.uat.test \
	--internal-auth-file "$work/wrong-auth" --token-cmd "$tests/fake/token-cmd" >/dev/null 2>"$work/err" || rc=$?
check "a wrong shared secret: 401 reported" bash -c '[ "$1" -eq 1 ] && grep -q "HTTP 401" "$2"' _ "$rc" "$work/err"

fresh args
rc=0; "$enroll/create-tenants.sh" >/dev/null 2>&1 || rc=$?
check "no arguments: usage, exit 2" [ "$rc" -eq 2 ]
rc=0; ct >/dev/null 2>"$work/err" || rc=$?
check "no token source: refused" bash -c '[ "$1" -ne 0 ] && grep -q "no token for tenant 1" "$2"' _ "$rc" "$work/err"
rc=0; ct --token-cmd "$tests/fake/token-cmd" --key-hours 0 >/dev/null 2>&1 || rc=$?
check "--key-hours 0 refused" [ "$rc" -eq 1 ]
rc=0; "$enroll/create-tenants.sh" --uat "$testdata/uat.json" --state "$state" --internal-auth-file "$work/internal-auth" \
	--token-cmd "$tests/fake/token-cmd" --saasapi-url https://saas.uat.test/v1 >/dev/null 2>&1 || rc=$?
check "a saasapi URL with a path refused" [ "$rc" -eq 1 ]
jq '.sprouts["t1-alma"].tenant = 3' "$testdata/uat.json" >"$work/bad-uat.json"
rc=0; "$enroll/create-tenants.sh" --uat "$work/bad-uat.json" --state "$state" --internal-auth-file "$work/internal-auth" \
	--token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1 || rc=$?
check "a sprout in tenant 3 refused" [ "$rc" -eq 1 ]
fresh defaulturl
"$enroll/create-tenants.sh" --uat "$testdata/uat.json" --state "$state" --internal-auth-file "$work/internal-auth" \
	--token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1
check "saasapi URL defaults to https://<core.fqdn>" \
	grep -q '"https://uatabc123-core.centralindia.cloudapp.azure.com/v1/tenants"' "$FAKE_DIR/argv"

echo "# keycloak-token.sh"
kc_setup() {
	cat >"$FAKE_DIR/kc-users.json" <<'JSON'
{"t1admin": {"password": "PWSECRET-1a"}, "t1ro": {"password": "PWSECRET-1r"},
 "t2admin": {"password": "PWSECRET-2a"}, "t2ro": {"password": "PWSECRET-2r"}}
JSON
	jq -n '{issuer: "https://kc.uat.test/realms/imas-uat", client_id: "uat-tests", tenant_attribute: "tenant_id",
		admin: {realm: "master", client_id: "admin-cli", username: "kcadmin", password: "kcadmin-pw"},
		tenants: {"1": {admin: {username: "t1admin", password: "PWSECRET-1a"}, readonly: {username: "t1ro", password: "PWSECRET-1r"}},
		          "2": {admin: {username: "t2admin", password: "PWSECRET-2a"}, readonly: {username: "t2ro", password: "PWSECRET-2r"}}}}' \
		>"$work/keycloak.json"
	export UAT_KEYCLOAK_JSON="$work/keycloak.json" FAKE_KC_ATTR=tenant_id
}
fresh hook
kc_setup
rc=0
ct --token-cmd "$tests/../keycloak-token.sh" >"$work/out" 2>"$work/err" || rc=$?
check "create-tenants with the Keycloak hook exits 0" [ "$rc" -eq 0 ]
t1="$(jq -r '.["1"].tenant_id' "$state/tenants.json")"
t2="$(jq -r '.["2"].tenant_id' "$state/tenants.json")"
check "each tenant's admin and read-only users carry its tenant id" \
	jq -e --arg a "$t1" --arg b "$t2" '.kc_users.t1admin.attributes.tenant_id == [$a] and .kc_users.t1ro.attributes.tenant_id == [$a]
		and .kc_users.t2admin.attributes.tenant_id == [$b] and .kc_users.t2ro.attributes.tenant_id == [$b]' "$FAKE_DIR/state.json"
check "each user is updated once, not on every call" jq -e '(.kc_puts | length) == 4' "$FAKE_DIR/state.json"
check "six keys minted with the hook's tokens" jq -e '(.keys | length) == 6' "$FAKE_DIR/state.json"
check "no password or token printed" no_secret "$work/out" "$work/err"
check "no password or token on a curl command line" no_secret "$FAKE_DIR/argv"
rc=0; UAT_KEYCLOAK_JSON="$work/nowhere.json" "$enroll/keycloak-token.sh" 1 >/dev/null 2>&1 || rc=$?
check "the hook without keycloak.json fails" [ "$rc" -ne 0 ]
rc=0; "$enroll/keycloak-token.sh" 3 >/dev/null 2>&1 || rc=$?
check "the hook refuses tenant 3" [ "$rc" -eq 2 ]
jq '.kc_users.t1admin.password = "changed"' "$FAKE_DIR/state.json" >"$work/s" && mv "$work/s" "$FAKE_DIR/state.json"
rc=0; "$enroll/keycloak-token.sh" 1 "$t1" >/dev/null 2>"$work/err" || rc=$?
check "a refused password grant is an error, saying so" bash -c '[ "$1" -ne 0 ] && grep -q "HTTP 401 invalid_grant" "$2"' _ "$rc" "$work/err"
unset UAT_KEYCLOAK_JSON FAKE_KC_ATTR

echo "# wait-connected.sh"
# enrolled.json as collect.yml writes it, from gen-inventory's choices.
enrolled() {
	jq '{run_id: "abc123", sprouts: (.sprouts | to_entries | map({key, value: {
		tenant: (.value.tenant | tonumber),
		os: (if .value.os == "windows" then "windows" else .value.os end),
		sprout_id: ({"ubuntu": "ubuntu-01", "alma": "alma-01", "windows": "win-01"}[.value.os]),
		expected_sprout_id: ({"ubuntu": "ubuntu-01", "alma": "alma-01", "windows": "win-01"}[.value.os]),
		asset_id: ("uat-abc123-" + .key)}}) | from_entries)}' "$testdata/uat.json" >"$state/enrolled.json"
}
wc_run() { "$enroll/wait-connected.sh" --state "$state" --internal-auth-file "$work/internal-auth" "$@"; }

fresh wait
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1
enrolled
export FAKE_CONNECT_AFTER=4
rc=0
wc_run --token-cmd "$tests/fake/token-cmd" --timeout 60 >"$work/out" 2>"$work/err" || rc=$?
check "waits until every sprout is connected" [ "$rc" -eq 0 ]
check "six asset links, each in the sprout's own tenant" \
	jq -e --slurpfile t "$state/tenants.json" '(.links | length) == 6 and (.links | to_entries | all(
		.value[0] == (if (.key | startswith("uat-abc123-t1-")) then $t[0]["1"].tenant_id else $t[0]["2"].tenant_id end)))' \
	"$FAKE_DIR/state.json"
check "the same sprout id linked in both tenants" \
	jq -e '.links["uat-abc123-t1-ubuntu"][1] == "ubuntu-01" and .links["uat-abc123-t2-ubuntu"][1] == "ubuntu-01" and .links["uat-abc123-t1-ubuntu"][0] != .links["uat-abc123-t2-ubuntu"][0]' \
	"$FAKE_DIR/state.json"
check "polled more than once" [ "$(grep -c 'GET /v1/tenants/.*/sprouts?asset_ids=' "$FAKE_DIR/log")" -gt 2 ]
check "sprouts.json in the shape uat/tests/harness reads" \
	jq -e 'length == 6 and .["t2-win"] == {sprout_id: "win-01", asset_id: "uat-abc123-t2-win"}
		and ([.[] | keys] | all(. == ["asset_id", "sprout_id"]))' "$state/sprouts.json"
check "sprouts-detail.json with tenant ids" \
	jq -e --slurpfile t "$state/tenants.json" '.run_id == "abc123" and (.sprouts | length) == 6
		and .sprouts["t2-win"] == {tenant: 2, tenant_id: $t[0]["2"].tenant_id, os: "windows", sprout_id: "win-01", asset_id: "uat-abc123-t2-win"}' \
	"$state/sprouts-detail.json"
check "prints no secret" no_secret "$work/out" "$work/err" "$state/sprouts.json" "$state/sprouts-detail.json"
: >"$FAKE_DIR/log"
wc_run --token-cmd "$tests/fake/token-cmd" >/dev/null 2>"$work/err"
check "a re-run finds the links already there (200)" grep -q "already linked" "$work/err"

fresh conflict
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1
enrolled
export FAKE_LINK_CONFLICT=uat-abc123-t2-alma
rc=0
wc_run --token-cmd "$tests/fake/token-cmd" >/dev/null 2>"$work/err" || rc=$?
check "an asset link conflict fails" bash -c '[ "$1" -eq 1 ] && grep -q "asset_link_conflict" "$2"' _ "$rc" "$work/err"

fresh timeout
ct --token-cmd "$tests/fake/token-cmd" >/dev/null 2>&1
enrolled
export FAKE_CONNECT_AFTER=1000
rc=0
wc_run --token-cmd "$tests/fake/token-cmd" --timeout 0 >/dev/null 2>"$work/err" || rc=$?
check "a sprout never connected: timeout names it" bash -c '[ "$1" -eq 1 ] && grep -q "t1-win(key accepted, connected false)" "$2"' _ "$rc" "$work/err"
rc=0; "$enroll/wait-connected.sh" --state "$work/nowhere" --internal-auth-file "$work/internal-auth" >/dev/null 2>&1 || rc=$?
check "no tenants.json: refused" [ "$rc" -eq 1 ]

echo "# enroll.sh"
fresh enroll
printf 'KEY\n' >"$work/id_uat"
printf 'pw\n' >"$work/winrm"
er() {
	"$enroll/enroll.sh" --uat "$testdata/uat.json" --access "$testdata/access.json" --state "$state" \
		--release-tag v0.1.0-rc.4 --ca-file "$testdata/uat-ca.pem" --ssh-key "$work/id_uat" \
		--winrm-password-file "$work/winrm" --internal-auth-file "$work/internal-auth" \
		--token-cmd "$tests/fake/token-cmd" --saasapi-url https://saas.uat.test "$@"
}
rc=0
er -- -v >"$work/out" 2>"$work/err" || rc=$?
check "the whole run exits 0" [ "$rc" -eq 0 ]
check "playbooks in order: seed, site, collect" \
	bash -c '[ "$(cut -d" " -f1 "$1" | tr "\n" " ")" = "seed-sproutid.yml site.yml collect.yml " ]' _ "$FAKE_DIR/ansible.log"
check "site.yml is the repository's" grep -q "^site.yml -i $state/inventory/hosts.yml $repo/ansible/site.yml -v " "$FAKE_DIR/ansible.log"
check "roles from ansible/roles, host key checking off" \
	grep -q "ANSIBLE_ROLES_PATH=$repo/ansible/roles ANSIBLE_HOST_KEY_CHECKING=False" "$FAKE_DIR/ansible.log"
check "collect gets the state directory" grep -q "^collect.yml .*-e uat_out_dir=$state" "$FAKE_DIR/ansible.log"
check "the inventory pins the release" grep -q '"0.1.0~rc.4+git"' "$state/inventory/group_vars/linux_sprouts.yml"
check "sprouts.json written" jq -e 'length == 6 and .["t1-alma"].sprout_id == "alma-01"' "$state/sprouts.json"
check "prints no secret" no_secret "$work/out" "$work/err"
check "the inventory holds no secret" bash -c '! grep -rqE "SEKRIT|SHHH|TOKSIGNATURE|^KEY" "$1/inventory"' _ "$state"

fresh enrollkc
kc_setup
unset UAT_KEYCLOAK_JSON
rc=0
"$enroll/enroll.sh" --uat "$testdata/uat.json" --access "$testdata/access.json" --state "$state" \
	--release-tag v0.1.0-rc.4 --ca-file "$testdata/uat-ca.pem" --ssh-key "$work/id_uat" \
	--winrm-password-file "$work/winrm" --internal-auth-file "$work/internal-auth" \
	--keycloak-json "$work/keycloak.json" --saasapi-url https://saas.uat.test >"$work/out" 2>"$work/err" || rc=$?
check "enroll.sh --keycloak-json runs through" bash -c '[ "$1" -eq 0 ] && jq -e "length == 6" "$2/sprouts.json"' _ "$rc" "$state"
check "and prints no secret" no_secret "$work/out" "$work/err"
unset FAKE_KC_ATTR

fresh enrollfail
export FAKE_PLAYBOOK_FAIL=site.yml
rc=0
er >/dev/null 2>&1 || rc=$?
check "a failing site.yml stops the run" bash -c '[ "$1" -ne 0 ] && ! grep -q "^collect.yml" "$2" && [ ! -e "$3/sprouts.json" ]' _ "$rc" "$FAKE_DIR/ansible.log" "$state"

fresh enrollnoseed
rc=0
er --no-seed-sproutid >/dev/null 2>&1 || rc=$?
check "--no-seed-sproutid skips the seed and relaxes the check" \
	bash -c '[ "$1" -eq 0 ] && ! grep -q "^seed-sproutid.yml" "$2" && grep -q "uat_skip_sprout_id_check=true" "$2"' _ "$rc" "$FAKE_DIR/ansible.log"

fresh enrollargs
rc=0; er --release-tag latest >/dev/null 2>"$work/err" || rc=$?
check "release tag latest refused" bash -c '[ "$1" -ne 0 ] && grep -q "never latest" "$2"' _ "$rc" "$work/err"
rc=0
"$enroll/enroll.sh" --uat "$testdata/uat.json" --state "$state" --release-tag v0.1.0-rc.4 --ca-file "$testdata/uat-ca.pem" \
	--internal-auth-file "$work/internal-auth" --token-cmd "$tests/fake/token-cmd" >/dev/null 2>"$work/err" || rc=$?
check "ssh/winrm sprouts without access.json refused" bash -c '[ "$1" -ne 0 ] && grep -q -- "--access is required" "$2"' _ "$rc" "$work/err"

fresh enrolllite
printf '{"vms":{}}' >"$work/empty-access.json"
rc=0
"$enroll/enroll.sh" --uat "$testdata/uat-lite.json" --state "$state" --release-tag v0.1.0-rc.4 --ca-file "$testdata/uat-ca.pem" \
	--internal-auth-file "$work/internal-auth" --token-cmd "$tests/fake/token-cmd" --saasapi-url https://saas.uat.test >/dev/null 2>"$work/err" || rc=$?
check "the docker rig needs no access.json, SSH key or WinRM password" [ "$rc" -eq 0 ]
check "docker connection in its inventory" grep -q '"community.docker.docker"' "$state/inventory/group_vars/conn_docker.yml"

echo "# playbooks, for real against localhost"
if [[ -z "$real_playbook" ]]; then
	echo "skip - ansible-playbook not installed"
elif [[ "$(id -u)" != 0 ]]; then
	echo "skip - not root (seed-sproutid.yml writes root-owned files)"
else
	pb="$work/pb"
	mkdir -p "$pb/a" "$pb/b" "$pb/c"
	py="$(head -1 "$real_playbook" | sed 's/^#!//')"
	cat >"$pb/inv.yml" <<EOF
all:
  children:
    sprouts:
      vars: {uat_run_id: abc123}
      children:
        linux_sprouts:
          hosts:
            t1-ubuntu: {ansible_connection: local, ansible_python_interpreter: "$py", uat_tenant: 1, uat_os: ubuntu, uat_sprout_id: ubuntu-01, uat_asset_id: uat-abc123-t1-ubuntu}
EOF
	export ANSIBLE_ROLES_PATH="$repo/ansible/roles"
	seed() { "$real_playbook" -i "$pb/inv.yml" "$enroll/playbooks/seed-sproutid.yml" -e "uat_linux_config_file=$1" -e "uat_linux_jwt_file=$2" </dev/null >"$work/pbout" 2>&1; }
	printf 'farmerinterface: placeholder\njointoken: ek_1.SEKRIT\n' >"$pb/a/sprout"
	rc=0; seed "$pb/a/sprout" "$pb/a/sprout.jwt" || rc=$?
	check "seed: merges sproutid into an existing config file, mode 600" \
		bash -c '[ "$1" -eq 0 ] && grep -qx "sproutid: ubuntu-01" "$2" && grep -qx "farmerinterface: placeholder" "$2" && [ "$(stat -c %a "$2")" = 600 ]' _ "$rc" "$pb/a/sprout"
	seed "$pb/a/sprout" "$pb/a/sprout.jwt"
	check "seed: a second run changes nothing" grep -q "changed=0" "$work/pbout"
	check "seed: the play log shows no secret" no_secret "$work/pbout"
	seed "$pb/b/etc/imas/sprout" "$pb/b/sprout.jwt"
	check "seed: creates the directory and file on a fresh host" grep -qx "sproutid: ubuntu-01" "$pb/b/etc/imas/sprout"
	printf 'sproutid: t1-ubuntu\n' >"$pb/c/sprout"
	: >"$pb/c/sprout.jwt"
	seed "$pb/c/sprout" "$pb/c/sprout.jwt"
	check "seed: an enrolled sprout keeps its ID" grep -qx "sproutid: t1-ubuntu" "$pb/c/sprout"
	collect() { "$real_playbook" -i "$pb/inv.yml" "$enroll/playbooks/collect.yml" --skip-tags uat_verify -e "uat_linux_config_file=$1" -e "uat_out_dir=$pb" </dev/null >"$work/pbout" 2>&1; }
	rc=0; collect "$pb/a/sprout" || rc=$?
	check "collect: writes enrolled.json" bash -c '[ "$1" -eq 0 ] && jq -e ".run_id == \"abc123\" and .sprouts[\"t1-ubuntu\"] == {tenant: 1, os: \"ubuntu\", sprout_id: \"ubuntu-01\", expected_sprout_id: \"ubuntu-01\", asset_id: \"uat-abc123-t1-ubuntu\"}" "$2/enrolled.json" >/dev/null' _ "$rc" "$pb"
	rc=0; collect "$pb/c/sprout" || rc=$?
	check "collect: a sprout enrolled under another ID fails, saying so" bash -c '[ "$1" -ne 0 ] && grep -q "enrolled as .t1-ubuntu., not" "$2"' _ "$rc" "$work/pbout"
fi

echo
if ((fails)); then
	echo "$fails test(s) failed"
	exit 1
fi
echo "all tests passed"
