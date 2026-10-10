#!/usr/bin/env bash
# Tests for uat/lite (UAT.8) with stubbed docker, kind, kubectl, helm,
# ssh-keygen, ssh, sudo and curl (tests/stubs) and stand-ins for the hub
# scripts, enrolment and the test runner (tests/fake). Nothing here starts a
# container or a cluster: the stubs keep their "state" as files. Each test
# runs in a subshell with its own temporary directory.
#
# Also checks the files the rig writes against the real readers, unchanged:
# uat/hub/dmz/lib.sh (dmz_load_endpoints), uat/hub/core/lib/common.sh
# (load_endpoints) and uat/enroll/gen-inventory.py.
#
# LITE_TEST_KEEP=DIR copies the material one stubbed up.sh wrote (uat.json,
# access.json, endpoints.json, harness.json, the kind configs) to DIR, for
# lite_test.go's checks with the harness's own parser.
set -uo pipefail

LITE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO=$(cd "$LITE/../.." && pwd)
RESULTS=$(mktemp -d "${TMPDIR:-/tmp}/lite-results.XXXXXX")
trap 'rm -rf "$RESULTS"' EXIT
TAG=v0.1.0-rc.4

ok() { echo x >>"$RESULTS/ok"; }
bad() {
	echo "  FAIL [$CURRENT]: $*"
	echo x >>"$RESULTS/fail"
}
check() {
	local what=$1
	shift
	if "$@"; then ok; else bad "$what"; fi
}
has() { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }
jqt() { jq -e "$2" "$1" >/dev/null 2>&1; }
# rc_is WANT CMD...: runs CMD, keeps its stdout and stderr in $T/out, $T/err.
rc_is() {
	local want=$1 got
	shift
	"$@" >"$T/out" 2>"$T/err"
	got=$?
	if [[ $got == "$want" ]]; then ok; else
		bad "$* exited $got, want $want: $(tail -n 3 "$T/err")"
	fi
}
# log_order A B: the first line matching A comes before the first matching B.
log_order() {
	local a b
	a=$(grep -nF -- "$1" "$STUB_LOG" | head -n 1 | cut -d: -f1)
	b=$(grep -nF -- "$2" "$STUB_LOG" | head -n 1 | cut -d: -f1)
	[[ -n $a && -n $b ]] && ((a < b))
}
count() { grep -cF -- "$2" "$1" || true; }

setup() {
	T=$(mktemp -d "${TMPDIR:-/tmp}/lite-test.XXXXXX")
	export STUB_STATE=$T/stub STUB_LOG=$T/log STUB_FIX=$T/fix
	mkdir -p "$STUB_STATE" "$STUB_FIX" "$T/home"
	: >"$STUB_LOG"
	printf 'apiVersion: v1\nkind: List\nitems: []\n' >"$STUB_FIX/download"
	cat >"$T/k0s-versions.env" <<EOF
CERT_MANAGER_VERSION=v1.21.2
CERT_MANAGER_URL=https://example.invalid/cert-manager.yaml
CERT_MANAGER_SHA256=$(sha256sum "$STUB_FIX/download" | awk '{print $1}')
EOF
	printf '127.0.0.1 localhost\n::1 localhost\n' >"$T/hosts"
	cp "$T/hosts" "$T/hosts.orig"
	export PATH="$LITE/tests/stubs:$PATH" HOME=$T/home
	unset XDG_STATE_HOME LITE_RUN_ID LITE_HOST_ACCESS LITE_HOST_SPROUT LITE_SPROUTS LITE_NETWORK \
		LITE_SUBNET STUB_DOCKER_OS STUB_APISERVER_ARGS STUB_NO_DEFAULT_SC STUB_TESTS_RC STUB_SUMMARY
	export LITE_STATE=$T/state LITE_HOSTS_FILE=$T/hosts LITE_POLL_SECONDS=0 LITE_SUDO=sudo \
		LITE_K0S_VERSIONS=$T/k0s-versions.env VMCTL_POLL_SECONDS=0 \
		LITE_CORE_INSTALL=$LITE/tests/fake/core-install LITE_CORE_FINISH=$LITE/tests/fake/core-finish LITE_DMZ_INSTALL=$LITE/tests/fake/dmz-install \
		LITE_DMZ_CHECK=$LITE/tests/fake/dmz-check LITE_ENROLL=$LITE/tests/fake/enroll \
		LITE_TESTS_RUN=$LITE/tests/fake/tests-run
	S=$T/state
}

up() { "$LITE/up.sh" --release-tag "$TAG" "$@"; }

run_test() {
	CURRENT=$1
	echo "== $1"
	(
		setup
		"$1"
		rm -rf "$T"
	)
}

# --- argument handling -----------------------------------------------------

t_usage() {
	rc_is 2 "$LITE/up.sh"
	rc_is 2 up --bogus
	rc_is 2 "$LITE/up.sh" --release-tag latest
	rc_is 2 "$LITE/up.sh" --release-tag 0.1.0
	rc_is 2 "$LITE/up.sh" --release-tag v0.1.0-beta.1
	rc_is 2 up --state
	rc_is 2 up --host-access sometimes
	rc_is 2 env LITE_SUBNET=10.0.0.0/16 "$LITE/up.sh" --release-tag "$TAG"
	rc_is 2 env LITE_SPROUTS="t1-ubuntu t1-win" "$LITE/up.sh" --release-tag "$TAG"
	rc_is 2 env LITE_SPROUTS="t1-ubuntu t1-ubuntu" "$LITE/up.sh" --release-tag "$TAG"
	rc_is 2 up --run-id UP
	rc_is 2 env LITE_HOST_SPROUT=t1-alma "$LITE/up.sh" --release-tag "$TAG"
	rc_is 2 env LITE_HOST_SPROUT=t9-ubuntu "$LITE/up.sh" --release-tag "$TAG"
	check "nothing was created by a usage error" test ! -e "$S"
	check "no docker call on a usage error" hasnt "$STUB_LOG" "docker network"
	rc_is 2 "$LITE/run.sh"
	rc_is 2 "$LITE/run.sh" resilience
	rc_is 2 "$LITE/run.sh" --release-tag latest core
	rc_is 2 "$LITE/run.sh" --bogus core
	rc_is 2 "$LITE/run.sh" core
	check "run.sh says how to bring the rig up" has "$T/err" "--release-tag"
	rc_is 2 "$LITE/down.sh" --bogus
	rc_is 1 "$LITE/write-material.sh" --state "$T/nowhere"
	rc_is 2 "$LITE/write-material.sh" --what
	rc_is 2 "$LITE/up.sh" --help
	check "--help prints the usage" has "$T/err" "Usage: up.sh --release-tag"
}

# --- up.sh -----------------------------------------------------------------

t_up_direct() {
	rc_is 0 up
	local net=$STUB_STATE/docker/networks/imas-uat-lite.json
	check "network subnet" jqt "$net" '.IPAM.Config[0] == {Subnet: "172.29.88.0/24", IPRange: "172.29.88.128/25", Gateway: "172.29.88.1"}'
	check "network label" jqt "$net" '.Labels["imas.io/purpose"] == "imas-uat-lite"'
	check "kind creates core on the rig network" has "$STUB_LOG" "kind create cluster --name core --config $S/kind/core.yaml --kubeconfig $S/kube/core.kubeconfig --wait 600s [KIND_EXPERIMENTAL_DOCKER_NETWORK=imas-uat-lite]"
	check "kind creates dmz on the rig network" has "$STUB_LOG" "kind create cluster --name dmz --config $S/kind/dmz.yaml"
	check "core cluster first" log_order "kind create cluster --name core" "kind create cluster --name dmz"
	check "dmz NodePort range, v1beta3" grep -q 'service-node-port-range: "8442-8443"' "$S/kind/dmz.yaml"
	check "dmz NodePort range, v1beta4" grep -A1 -- '- name: service-node-port-range' "$S/kind/dmz.yaml" | grep -q 'value: "8442-8443"'
	check "core keeps the default range" grep -q 'service-node-port-range: "30000-32767"' "$S/kind/core.yaml"
	check "distinct pod subnets" bash -c "grep -q 'podSubnet: \"10.244.0.0/16\"' '$S/kind/dmz.yaml' && grep -q 'podSubnet: \"10.245.0.0/16\"' '$S/kind/core.yaml'"
	check "no published ports in direct mode" bash -c "! grep -q extraPortMappings '$S/kind/dmz.yaml' '$S/kind/core.yaml'"
	check "kind node image pinned" grep -q 'image: docker.io/kindest/node:v' "$S/kind/dmz.yaml"
	check "kubeconfig mode 600" test "$(stat -c %a "$S/kube/dmz.kubeconfig")" = 600
	check "state mode 700" test "$(stat -c %a "$S")" = 700
	for hub in core dmz; do
		check "$hub: cert-manager applied server side" has "$STUB_LOG" "kubectl $hub apply --server-side --force-conflicts -f $S/cache/cert-manager.yaml"
		check "$hub: cert-manager rolled out" has "$STUB_LOG" "kubectl $hub rollout status deployment/cert-manager-webhook"
		check "$hub: issuer Ready" has "$STUB_LOG" "kubectl $hub wait --for=condition=Ready clusterissuer/imas-uat-ca"
		check "$hub: CA Secret stored" bash -c "grep -l '\"kind\": \"Secret\"' '$STUB_STATE'/kube/$hub-applied-* >/dev/null"
		check "$hub: ClusterIssuer on the CA Secret" bash -c "grep -l 'secretName: imas-uat-ca' '$STUB_STATE'/kube/$hub-applied-* >/dev/null"
	done
	check "UAT CA is a CA" bash -c "openssl x509 -in '$S/uat-ca.pem' -noout -text | grep -q 'CA:TRUE'"
	check "UAT CA names the run" bash -c "openssl x509 -in '$S/uat-ca.pem' -noout -subject | grep -q 'imas UAT CA lite01'"
	check "CA key mode 600" test "$(stat -c %a "$S/sensitive/ca/tls.key")" = 600

	local cf
	cf=$(jq -r '.data.Corefile' "$STUB_STATE/kube/core-coredns.json")
	check "core CoreDNS: core names" grep -q '172.29.88.130 uatlite01-core.imas-lite.test core.uat.imas.internal' <<<"$cf"
	check "core CoreDNS: dmz names" grep -q '172.29.88.131 uatlite01-dmz.imas-lite.test dmz.uat.imas.internal' <<<"$cf"
	check "core CoreDNS: hosts after ready, with fallthrough" bash -c "grep -A3 '^    ready\$' <<<'$cf' | grep -q 'hosts {' && grep -q fallthrough <<<'$cf'"
	cf=$(jq -r '.data.Corefile' "$STUB_STATE/kube/dmz-coredns.json")
	check "dmz CoreDNS: core names" grep -q '172.29.88.130 uatlite01-core.imas-lite.test core.uat.imas.internal' <<<"$cf"
	check "CoreDNS restarted" has "$STUB_LOG" "kubectl dmz rollout restart deployment/coredns"

	check "hosts file keeps its lines" bash -c "head -n 2 '$T/hosts' | cmp -s - '$T/hosts.orig'"
	check "hosts file: core names to the node" has "$T/hosts" "172.29.88.130 uatlite01-core.imas-lite.test core.uat.imas.internal"
	check "hosts file: dmz names to the node" has "$T/hosts" "172.29.88.131 uatlite01-dmz.imas-lite.test dmz.uat.imas.internal"

	check "two images built" test "$(count "$STUB_LOG" "docker build")" = 2
	check "ubuntu image from the official base" has "$STUB_LOG" "docker build -t imas-uat-lite/sprout-ubuntu:1 -f $LITE/sprouts/ubuntu.Dockerfile --build-arg BASE_IMAGE=docker.io/library/ubuntu:24.04 $LITE/sprouts"
	check "alma image from the official base" has "$STUB_LOG" "--build-arg BASE_IMAGE=docker.io/library/almalinux:9"
	check "four sprout containers" test "$(count "$STUB_LOG" "docker run -d")" = 4
	local run
	run=$(grep -F "docker run -d --name imas-lite-t1-ubuntu " "$STUB_LOG")
	for want in "--hostname t1-ubuntu" "--network imas-uat-lite --ip 172.29.88.21" "--privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock" \
		"-p 127.0.0.1:22221:22" "--add-host dmz.uat.imas.internal:172.29.88.131" "--add-host uatlite01-dmz.imas-lite.test:172.29.88.131" \
		"--add-host uatlite01-core.imas-lite.test:172.29.88.130" "--label imas.io/run-id=lite01" "imas-uat-lite/sprout-ubuntu:1"; do
		check "t1-ubuntu run has $want" grep -qF -- "$want" <<<"$run"
	done
	check "t2-alma at .24, SSH 22224" has "$STUB_LOG" "--name imas-lite-t2-alma --hostname t2-alma --network imas-uat-lite --ip 172.29.88.24 --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock -p 127.0.0.1:22224:22"
	check "rig key authorised in each sprout" cmp -s "$STUB_STATE/docker/authorized_keys-imas-lite-t2-alma" "$S/ssh/id_ed25519.pub"

	local u=$S/uat.json
	check "uat.json run and hubs" jqt "$u" '.run_id == "lite01" and .dmz.name == "uat-dmz" and .dmz.id == "dmz-control-plane" and .dmz.private_ip == "172.29.88.131" and .core.name == "uat-core" and .core.id == "core-control-plane" and .core.private_ip == "172.29.88.130" and .core.fqdn == "uatlite01-core.imas-lite.test" and .core.admin_user == "root"'
	check "uat.json sprouts" jqt "$u" '(.sprouts | keys) == ["t1-alma", "t1-ubuntu", "t2-alma", "t2-ubuntu"]'
	check "uat.json t2-alma" jqt "$u" '.sprouts["t2-alma"] == {tenant: 2, os: "alma", connection: "ssh", id: "imas-lite-t2-alma", private_ip: "172.29.88.24", admin_user: "root"}'
	check "uat.json every connection ssh" jqt "$u" '[.sprouts[].connection] | all(. == "ssh")'
	check "uat.json has no public_ip" jqt "$u" '[.. | objects | has("public_ip")] | any | not'
	check "uat.json private zone" jqt "$u" '.private_dns_zone == "uat.imas.internal"'
	local a=$S/access.json
	check "access.json sprouts" jqt "$a" '.["t1-ubuntu"] == {host: "127.0.0.1", ssh_port: 22221} and .["t2-alma"] == {host: "127.0.0.1", ssh_port: 22224}'
	check "access.json hubs" jqt "$a" '.["uat-core"].kube_port == 40001 and .["uat-dmz"].kube_port == 40002 and .["uat-dmz"].host == "127.0.0.1"'
	local e=$S/endpoints.json
	check "endpoints core" jqt "$e" '.core == {name: "uat-core", private_ip: "172.29.88.130", fqdn: "uatlite01-core.imas-lite.test", private_fqdn: "core.uat.imas.internal", ports: {https: 443, farmer_api: 5405}, exposure: "hostPort", node_port_range: "30000-32767"}'
	check "endpoints dmz" jqt "$e" '.dmz.ports == {envoy: 8443, bus: 8442} and .dmz.private_fqdn == "dmz.uat.imas.internal" and .dmz.envoy_service_type == "NodePort"'
	check "endpoints issuer, both keys" jqt "$e" '.cluster_issuer == "imas-uat-ca" and .ca.cluster_issuer == "imas-uat-ca" and .private_dns_zone == "uat.imas.internal" and .host_access == "direct"'
	local h=$S/harness.json
	check "harness.json Envoy" jqt "$h" '.envoy_url == "https://uatlite01-dmz.imas-lite.test:8443" and .sprout_envoy_address == "dmz.uat.imas.internal:8443" and .saasapi_url == "https://uatlite01-core.imas-lite.test"'
	check "harness.json vmctl" jqt "$h" ".vmctl == \"$LITE/vmctl.sh\" and .ca_file == \"uat-ca.pem\""
	check "harness.json bind_tenant" jqt "$h" ".bind_tenant == {script: \"$REPO/uat/hub/core/bind-tenant.sh\", kubeconfig: \"$S/kube/core.kubeconfig\", endpoints: \"$S/endpoints.json\", state_dir: \"$S\"}"

	check "core install args" has "$STUB_LOG" "core-install $S/kube/core.kubeconfig $S/endpoints.json $S $TAG"
	check "dmz install args" has "$STUB_LOG" "dmz-install --kubeconfig $S/kube/dmz.kubeconfig --endpoints $S/endpoints.json --release-tag $TAG --seeds-from-kubeconfig $S/kube/core.kubeconfig --workdir $S/dmz"
	check "dmz check args" has "$STUB_LOG" "dmz-check --endpoints $S/endpoints.json --ca-file $S/uat-ca.pem --kubeconfig $S/kube/dmz.kubeconfig --connect 172.29.88.131"
	check "enroll args" has "$STUB_LOG" "enroll --uat $S/uat.json --access $S/access.json --state $S/enroll --release-tag $TAG --ssh-key $S/ssh/id_ed25519 --core-state $S --core-kubeconfig $S/kube/core.kubeconfig --endpoints $S/endpoints.json"
	check "core before dmz" log_order "core-install" "dmz-install"
	check "core finish args" has "$STUB_LOG" "core-finish $S/kube/core.kubeconfig $S/endpoints.json $S $TAG SKIP_CHECK=0"
	check "core finish after the dmz install" log_order "dmz-install" "core-finish"
	check "core finish before enrolment" log_order "core-finish" "enroll --uat"
	check "ubuntu sprouts refresh apt" has "$STUB_LOG" "docker-exec imas-lite-t1-ubuntu env=[] sh -c apt-get update -qq"
	check "alma sprouts refresh dnf" has "$STUB_LOG" "docker-exec imas-lite-t2-alma env=[] sh -c dnf clean all -q && dnf makecache -q"
	check "package index refreshed before enrolment" log_order "apt-get update -qq" "enroll --uat"
	check "every sprout refreshed once" test "$(count "$STUB_LOG" 'env=[] sh -c apt-get update -qq')" = 2 -a "$(count "$STUB_LOG" 'env=[] sh -c dnf clean all -q')" = 2
	check "dmz install before its check" log_order "dmz-install" "dmz-check"
	check "check before enrolment" log_order "dmz-check" "enroll --uat"
	check "material before the hubs" log_order "docker run -d --name imas-lite-t2-alma" "core-install"
	check "tenants.json linked" test "$(readlink "$S/tenants.json")" = enroll/tenants.json
	check "sprouts.json linked" test "$(readlink "$S/sprouts.json")" = enroll/sprouts.json
	check "stages recorded" jqt "$S/rig.json" ".stages == {core: \"$TAG\", dmz: \"$TAG\", enroll: \"$TAG\"} and .release_tag == \"$TAG\""
	check "settings recorded" jqt "$S/rig.json" '.settings.LITE_ACCESS_MODE == "direct" and .settings.LITE_RUN_ID == "lite01"'

	if command -v yamllint >/dev/null 2>&1; then
		check "kind configs pass yamllint" yamllint -s -c "$LITE/.yamllint.yaml" "$S/kind/dmz.yaml" "$S/kind/core.yaml" "$S/kind/cluster-issuer.yaml"
	fi
	if [[ -n ${LITE_TEST_KEEP:-} ]]; then
		mkdir -p "$LITE_TEST_KEEP"
		cp "$S"/uat.json "$S"/access.json "$S"/endpoints.json "$S"/harness.json "$S"/kind/*.yaml "$LITE_TEST_KEEP/"
	fi
}

t_up_rerun() {
	rc_is 0 up
	: >"$STUB_LOG"
	rc_is 0 up
	check "no second cluster" hasnt "$STUB_LOG" "kind create"
	check "no second container" hasnt "$STUB_LOG" "docker run"
	check "no second image build" hasnt "$STUB_LOG" "docker build"
	check "no second core install" hasnt "$STUB_LOG" "core-install"
	check "no second core finish" hasnt "$STUB_LOG" "core-finish"
	check "no second dmz check" hasnt "$STUB_LOG" "dmz-check"
	check "no second enrolment" hasnt "$STUB_LOG" "enroll --uat"
	check "one hosts block" test "$(count "$T/hosts" "# BEGIN imas-uat-lite")" = 1
	check "one CoreDNS block" test "$(jq -r '.data.Corefile' "$STUB_STATE/kube/core-coredns.json" | grep -c 'BEGIN imas-uat-lite')" = 1
	check "CoreDNS untouched when unchanged" hasnt "$STUB_LOG" "replace -f"
	check "same CA kept" test "$(count "$STUB_LOG" "openssl")" = 0
	: >"$STUB_LOG"
	rc_is 0 up --reinstall
	check "--reinstall runs the installs" bash -c "grep -q core-install '$STUB_LOG' && grep -q dmz-install '$STUB_LOG' && grep -q 'enroll --uat' '$STUB_LOG'"
	: >"$STUB_LOG"
	rc_is 0 "$LITE/up.sh" --release-tag v0.1.0-rc.5
	check "a new release installs again" bash -c "grep -q 'core-install.* v0.1.0-rc.5' '$STUB_LOG'"
	# A stopped sprout is started again, not replaced.
	jq '.State.Running = false' "$STUB_STATE/docker/containers/imas-lite-t1-alma.json" >"$T/c" &&
		mv "$T/c" "$STUB_STATE/docker/containers/imas-lite-t1-alma.json"
	: >"$STUB_LOG"
	rc_is 0 up
	check "stopped sprout started" has "$STUB_LOG" "docker start imas-lite-t1-alma"
	rc_is 2 up --run-id other01
	check "another run id in the same state is refused" has "$T/err" "holds the rig of run lite01"
	# A state directory of another run id, named with --state only.
	mv "$S" "$T/elsewhere"
	jq '.settings.LITE_RUN_ID = "abc123"' "$T/elsewhere/rig.json" >"$T/r" && mv "$T/r" "$T/elsewhere/rig.json"
	rc_is 0 up --state "$T/elsewhere" --skip-hubs
	check "the saved run id is used" jqt "$T/elsewhere/uat.json" '.run_id == "abc123"'
	mv "$T/elsewhere" "$S"
}

t_up_published() {
	export STUB_DOCKER_OS="Docker Desktop"
	rc_is 0 up
	check "auto picks published on Docker Desktop" jqt "$S/endpoints.json" '.host_access == "published"'
	check "core publishes 443" grep -A3 extraPortMappings "$S/kind/core.yaml" | grep -q 'containerPort: 443'
	check "dmz publishes 8443 on 127.0.0.1" bash -c "grep -A4 extraPortMappings '$S/kind/dmz.yaml' | grep -q 'hostPort: 8443' && grep -q 'listenAddress: \"127.0.0.1\"' '$S/kind/dmz.yaml'"
	check "hosts file: names to 127.0.0.1" has "$T/hosts" "127.0.0.1 uatlite01-core.imas-lite.test core.uat.imas.internal"
	check "hosts file: dmz to 127.0.0.1" has "$T/hosts" "127.0.0.1 uatlite01-dmz.imas-lite.test dmz.uat.imas.internal"
	check "CoreDNS still maps to the node" bash -c "jq -r .data.Corefile '$STUB_STATE/kube/core-coredns.json' | grep -q '172.29.88.130 uatlite01-core'"
	check "sprouts still get the node address" has "$STUB_LOG" "--add-host dmz.uat.imas.internal:172.29.88.131"
	check "dmz check through the published port" has "$STUB_LOG" "--connect 127.0.0.1"
	rc_is 2 up --host-access direct
	check "switching mode on a built rig is refused" has "$T/err" "run down.sh before switching"
	# Clusters made in direct mode, state lost, then published: refused.
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE"
	rc_is 0 up --host-access direct --skip-hubs
	rm -rf "$S"
	rc_is 1 up --host-access published --skip-hubs
	check "a cluster without the published port is refused" has "$T/err" "does not publish port 443"
}

t_up_failures() {
	STUB_APISERVER_ARGS="" rc_is 1 up
	check "an ignored kubeadm patch is caught" has "$T/err" "no --service-node-port-range=8442-8443"
	check "and nothing is installed" hasnt "$STUB_LOG" "core-install"
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE"
	STUB_NO_DEFAULT_SC=1 rc_is 1 up
	check "no default StorageClass" has "$T/err" "expected one default StorageClass"
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE"
	echo tampered >>"$STUB_FIX/download"
	rc_is 1 up
	check "cert-manager checksum refused" has "$T/err" "checksum mismatch"
	sed -i '$d' "$STUB_FIX/download"
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE"
	: >"$STUB_LOG"
	STUB_FAIL_CORE_INSTALL=1 rc_is 1 up
	check "core failure stops before the dmz" hasnt "$STUB_LOG" "dmz-install"
	check "core failure named" has "$T/err" "uat/hub/core/install.sh failed"
	STUB_FAIL_ENROLL=1 rc_is 1 up
	check "enrolment failure named" has "$T/err" "uat/enroll/enroll.sh failed"
	: >"$STUB_LOG"
	rc_is 0 up
	check "core not reinstalled after its success" hasnt "$STUB_LOG" "core-install"
	check "enrolment retried" has "$STUB_LOG" "enroll --uat"
	# A network of the same name but another subnet is not the rig's.
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE/docker/networks"
	echo '{"Name": "imas-uat-lite", "IPAM": {"Config": [{"Subnet": "10.9.0.0/24"}]}, "Labels": {}}' >"$STUB_STATE/docker/networks/imas-uat-lite.json"
	rc_is 1 up
	check "foreign network refused" has "$T/err" "exists without subnet"
	# A kind cluster named core that is not on the rig's network.
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE/kind" "$STUB_STATE/docker/containers"
	echo 40999 >"$STUB_STATE/kind/core"
	echo '{"Name": "/core-control-plane", "State": {"Running": true}, "NetworkSettings": {"Networks": {"kind": {"IPAddress": "172.18.0.2"}}}}' \
		>"$STUB_STATE/docker/containers/core-control-plane.json"
	: >"$STUB_LOG"
	rc_is 1 up
	check "foreign cluster refused" has "$T/err" "not this rig's"
	check "foreign cluster not recreated" hasnt "$STUB_LOG" "kind create cluster --name core"
}

t_up_options() {
	rc_is 0 up --skip-hubs
	check "--skip-hubs writes the material" test -s "$S/endpoints.json"
	check "--skip-hubs installs nothing" hasnt "$STUB_LOG" "core-install"
	rc_is 0 up --skip-enroll --skip-checks
	check "--skip-checks" hasnt "$STUB_LOG" "dmz-check"
	check "--skip-checks reaches core finish" has "$STUB_LOG" "SKIP_CHECK=1"
	check "--skip-enroll" hasnt "$STUB_LOG" "enroll --uat"
	check "hubs installed" has "$STUB_LOG" "dmz-install"
	: >"$STUB_LOG"
	rc_is 0 up --rebuild-images
	check "--rebuild-images" test "$(count "$STUB_LOG" "docker build")" = 2
	rc_is 0 up --hosts-file none
	check "hosts-file none takes the block out of the old file" cmp -s "$T/hosts" "$T/hosts.orig"
	check "hosts-file none prints the lines" has "$T/err" "172.29.88.130 uatlite01-core.imas-lite.test core.uat.imas.internal"
}

t_up_host_sprout() {
	export LITE_SPROUTS="t1-ubuntu t2-ubuntu" LITE_HOST_SPROUT=t1-ubuntu LITE_HOST_SPROUT_PORT=2222 LITE_HOST_SPROUT_USER=imas
	rc_is 0 up
	check "no container for the host sprout" hasnt "$STUB_LOG" "--name imas-lite-t1-ubuntu"
	check "t2-ubuntu container at .22" has "$STUB_LOG" "--name imas-lite-t2-ubuntu --hostname t2-ubuntu --network imas-uat-lite --ip 172.29.88.22"
	check "only the ubuntu image" test "$(count "$STUB_LOG" "docker build")" = 1
	check "host sprout in uat.json" jqt "$S/uat.json" '.sprouts["t1-ubuntu"] == {tenant: 1, os: "ubuntu", connection: "ssh", id: "host", private_ip: "172.29.88.1", admin_user: "imas"}'
	check "host sprout in access.json" jqt "$S/access.json" '.["t1-ubuntu"] == {host: "127.0.0.1", ssh_port: 2222}'
	check "up.sh says what to authorise" has "$T/err" "authorise $S/ssh/id_ed25519.pub for imas"
}

# --- the files, read by the real readers -----------------------------------

t_readers() {
	rc_is 0 up --skip-hubs
	local got
	got=$(
		# shellcheck source=../../hub/dmz/lib.sh
		. "$REPO/uat/hub/dmz/lib.sh"
		dmz_load_endpoints "$S/endpoints.json"
		echo "$DMZ_FQDN|$DMZ_PRIVATE_IP|$DMZ_ENVOY_PORT|$DMZ_BUS_PORT|$CORE_PRIVATE_IP|$CORE_FARMER_API_PORT|$DMZ_CLUSTER_ISSUER|$DMZ_PRIVATE_NAME|$CORE_PRIVATE_NAME|$DMZ_CONNECT_ADDR|$DMZ_ENVOY_SERVICE_TYPE"
	)
	check "uat/hub/dmz reads endpoints.json" test "$got" = "uatlite01-dmz.imas-lite.test|172.29.88.131|8443|8442|172.29.88.130|5405|imas-uat-ca|dmz.uat.imas.internal|core.uat.imas.internal|uatlite01-dmz.imas-lite.test|NodePort"
	got=$(
		# shellcheck source=../../hub/core/lib/common.sh
		. "$REPO/uat/hub/core/lib/common.sh"
		parse_common_args usage "$S/kube/core.kubeconfig" "$S/endpoints.json" "$T/corestate"
		echo "$KEYCLOAK_ISSUER|$SAASAPI_URL|$SPROUT_BUS_URL|$CORE_IP|$DMZ_IP|$CORE_PRIVATE_FQDN|$DMZ_PRIVATE_FQDN|$CA_ISSUER|$DMZ_BUS_PORT|$CORE_EXPOSURE"
	)
	check "uat/hub/core reads endpoints.json: $got" test "$got" = "https://uatlite01-core.imas-lite.test/realms/imas-uat|https://uatlite01-core.imas-lite.test|wss://dmz.uat.imas.internal:8443/|172.29.88.130|172.29.88.131|core.uat.imas.internal|dmz.uat.imas.internal|imas-uat-ca|8442|hostPort"
	if command -v python3 >/dev/null 2>&1; then
		mkdir -p "$T/keys"
		for vm in t1-ubuntu t1-alma t2-ubuntu t2-alma; do printf 'key-%s\n' "$vm" >"$T/keys/$vm.key"; done
		rc_is 0 python3 "$REPO/uat/enroll/gen-inventory.py" --uat "$S/uat.json" --access "$S/access.json" \
			--keys-dir "$T/keys" --release-tag "$TAG" --ca-file "$S/uat-ca.pem" --out "$T/inv" \
			--ssh-key "$S/ssh/id_ed25519"
		check "gen-inventory: same sprout ID in both tenants" jqt "$T/inv/plan.json" \
			'.sprouts["t1-ubuntu"].sprout_id == "ubuntu-01" and .sprouts["t2-ubuntu"].sprout_id == "ubuntu-01" and .sprouts["t2-alma"].sprout_id == "alma-01"'
		check "gen-inventory: SSH port from access.json" grep -q 'ansible_port: 22224' "$T/inv/hosts.yml"
		check "gen-inventory: root login" grep -q 'ansible_user: "root"' "$T/inv/hosts.yml"
		check "gen-inventory: Envoy's private name" grep -rq 'imas_farmer_host: "dmz.uat.imas.internal"' "$T/inv/group_vars"
	else
		echo "  SKIPPED: python3 not installed (gen-inventory check)"
	fi
}

# --- vmctl.sh --------------------------------------------------------------

t_vmctl() {
	rc_is 0 up --skip-hubs
	local v=$LITE/vmctl.sh u=$S/uat.json
	rc_is 2 "$v"
	rc_is 2 "$v" "$u" reboot t1-ubuntu
	rc_is 2 "$v" "$u" run t1-ubuntu
	rc_is 2 "$v" "$u" restart t1-ubuntu extra
	rc_is 2 "$v" "$u" run t9-ubuntu true
	check "unknown VM named" has "$T/err" "no VM named 't9-ubuntu'"
	rc_is 2 "$v" "$T/missing.json" run t1-ubuntu true
	jq '.sprouts["t1-win"] = {tenant: 1, os: "windows", connection: "winrm", id: "imas-lite-t1-win"}' "$u" >"$T/win.json"
	rc_is 2 "$v" "$T/win.json" run t1-win hostname
	check "Windows refused with the reason" has "$T/err" "the local rig has none"

	rc_is 7 "$v" "$u" run t1-ubuntu 'echo out; echo err >&2; exit 7'
	check "run stdout" test "$(cat "$T/out")" = out
	check "run stderr" has "$T/err" "err"
	check "run exit marker" has "$T/err" "vmctl.sh: exit_code=7"
	rc_is 0 "$v" "$u" run t1-ubuntu "x='a \"b\" \$c | d'; printf '%s\n' \"\$x\""
	check "quoting survives" test "$(cat "$T/out")" = 'a "b" $c | d'
	rc_is 0 "$v" "$u" run t1-ubuntu echo a b
	check "arguments joined with spaces" test "$(cat "$T/out")" = "a b"
	check "sprout run without KUBECONFIG" has "$STUB_LOG" "docker-exec imas-lite-t1-ubuntu env=[] bash -c"
	rc_is 0 "$v" "$u" run uat-core 'echo "$KUBECONFIG"'
	check "hub run gets the node kubeconfig" test "$(cat "$T/out")" = /etc/kubernetes/admin.conf

	rc_is 0 "$v" "$u" stop-sprout t1-alma
	check "stop-sprout" has "$STUB_LOG" "systemctl stop imas-sprout"
	STUB_SYSTEMCTL_RC=5 rc_is 5 "$v" "$u" start-sprout t2-alma
	check "start-sprout passes the exit code" has "$STUB_LOG" "systemctl start imas-sprout"
	rc_is 2 "$v" "$u" stop-sprout uat-dmz
	check "hub refused for stop-sprout" has "$T/err" "works on sprout VMs only"

	echo 2 >"$STUB_STATE/docker/boot-imas-lite-t1-ubuntu"
	: >"$STUB_LOG"
	rc_is 0 "$v" "$u" restart t1-ubuntu
	check "restart is a container restart" has "$STUB_LOG" "docker restart -t 30 imas-lite-t1-ubuntu"
	check "restart waits for systemd" test "$(count "$STUB_LOG" "docker-exec imas-lite-t1-ubuntu env=[] systemctl is-system-running")" = 3
	echo 999 >"$STUB_STATE/docker/boot-imas-lite-t1-ubuntu"
	VMCTL_WAIT_SECONDS=0 rc_is 255 "$v" "$u" restart t1-ubuntu
	check "restart timeout" has "$T/err" "not back after 0s"
	rm -f "$STUB_STATE/docker/boot-imas-lite-t1-ubuntu"
	touch "$STUB_STATE/docker/restart-fail"
	rc_is 255 "$v" "$u" restart t1-ubuntu
	rm -f "$STUB_STATE/docker/restart-fail"
	rc_is 0 "$v" "$u" restart uat-core
	check "hub restart waits for the API server" has "$STUB_LOG" "docker-exec core-control-plane env=[KUBECONFIG=/etc/kubernetes/admin.conf] kubectl get --raw /readyz"
	echo 172.29.88.199 >"$STUB_STATE/docker/restart-ip-dmz-control-plane"
	rc_is 255 "$v" "$u" restart uat-dmz
	check "a hub that moved is reported" has "$T/err" "came back at 172.29.88.199, not 172.29.88.131"

	jq '.State.Running = false' "$STUB_STATE/docker/containers/imas-lite-t2-ubuntu.json" >"$T/c" &&
		mv "$T/c" "$STUB_STATE/docker/containers/imas-lite-t2-ubuntu.json"
	rc_is 255 "$v" "$u" run t2-ubuntu true
	check "stopped container: 255" has "$T/err" "is not running"
}

t_vmctl_host_sprout() {
	export LITE_SPROUTS="t1-ubuntu t2-ubuntu" LITE_HOST_SPROUT=t1-ubuntu LITE_HOST_SPROUT_PORT=2222
	rc_is 0 up --skip-hubs
	local v=$LITE/vmctl.sh u=$S/uat.json
	rc_is 3 "$v" "$u" run t1-ubuntu 'echo hi; exit 3'
	check "host sprout over SSH" test "$(cat "$T/out")" = hi
	check "ssh to the access.json port, pinned by VM name" has "$STUB_LOG" "-p 2222 -o BatchMode=yes"
	check "ssh HostKeyAlias" has "$STUB_LOG" "HostKeyAlias=t1-ubuntu"
	check "ssh as the uat.json admin_user" has "$STUB_LOG" "root@127.0.0.1"
	rc_is 0 "$v" "$u" stop-sprout t1-ubuntu
	check "host stop-sprout" has "$STUB_LOG" "systemctl stop imas-sprout"
	rc_is 255 "$v" "$u" restart t1-ubuntu
	check "host cannot be rebooted" has "$T/err" "cannot reboot it"
	STUB_SSH_FAIL=1 rc_is 255 "$v" "$u" run t1-ubuntu true
}

# --- down.sh ---------------------------------------------------------------

t_down() {
	rc_is 0 up
	echo "10.1.1.1 added-after-up" >>"$T/hosts"
	# Someone else's container and image on the same host.
	echo '{"Name": "/other", "Config": {"Labels": {}}, "State": {"Running": true}, "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}}}' \
		>"$STUB_STATE/docker/containers/other.json"
	: >"$STUB_LOG"
	rc_is 0 "$LITE/down.sh"
	check "sprout containers removed" test ! -e "$STUB_STATE/docker/containers/imas-lite-t1-ubuntu.json"
	check "other container left" test -e "$STUB_STATE/docker/containers/other.json"
	check "clusters deleted" bash -c "grep -q 'kind delete cluster --name core' '$STUB_LOG' && grep -q 'kind delete cluster --name dmz' '$STUB_LOG'"
	check "network removed" test ! -e "$STUB_STATE/docker/networks/imas-uat-lite.json"
	check "hosts block removed, other lines kept" bash -c "printf '127.0.0.1 localhost\n::1 localhost\n10.1.1.1 added-after-up\n' | cmp -s - '$T/hosts'"
	check "state removed" test ! -e "$S"
	check "images kept by default" hasnt "$STUB_LOG" "docker image rm"
	rc_is 0 "$LITE/down.sh"
	check "down twice is fine" has "$T/err" "the rig is down"

	rc_is 0 up
	rc_is 0 "$LITE/down.sh" --keep-state --images
	check "--keep-state" test -s "$S/rig.json"
	check "--images" has "$STUB_LOG" "docker image rm imas-uat-lite/sprout-alma:1"

	# A cluster named core that is not on the rig's network is not touched,
	# and neither is a state directory up.sh did not make.
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE/kind" "$STUB_STATE/docker/containers" "$S"
	echo 40999 >"$STUB_STATE/kind/core"
	echo '{"Name": "/core-control-plane", "State": {"Running": true}, "NetworkSettings": {"Networks": {"kind": {"IPAddress": "172.18.0.2"}}}}' \
		>"$STUB_STATE/docker/containers/core-control-plane.json"
	touch "$S/precious"
	: >"$STUB_LOG"
	rc_is 0 "$LITE/down.sh"
	check "foreign cluster left" hasnt "$STUB_LOG" "kind delete"
	check "foreign state directory left" test -e "$S/precious"

	# A network still used by someone else's container: reported, exit 1.
	rm -rf "$S" "$STUB_STATE" && mkdir -p "$STUB_STATE"
	rc_is 0 up --skip-hubs
	echo '{"Name": "/squatter", "Config": {"Labels": {}}, "State": {"Running": true}, "NetworkSettings": {"Networks": {"imas-uat-lite": {"IPAddress": "172.29.88.99"}}}}' \
		>"$STUB_STATE/docker/containers/squatter.json"
	rc_is 1 "$LITE/down.sh" --keep-state
	check "network in use reported" has "$T/err" "still in use"
}

# --- run.sh ----------------------------------------------------------------

core_ids() { awk -F'\t' '!/^#/ && NF >= 2 && $1 !~ /^I\./ && $2 ~ /(^|,)core(,|$)/ {print $1}' "$REPO/uat/tests/catalogue.tsv"; }

t_run() {
	rc_is 0 up
	: >"$STUB_LOG"
	rc_is 0 "$LITE/run.sh" core
	local args want
	args=$(grep '^tests-run ' "$STUB_LOG")
	want="tests-run core $(core_ids | grep -vx X3 | tr '\n' ' ' | sed 's/ $//')"
	check "core runs every core id but X3" test "$args" = "$want"
	check "the rig did not come up again" hasnt "$STUB_LOG" "kind create"
	check "the test env" has "$STUB_LOG" "tests-env dir=$S vmctl=$LITE/vmctl.sh release=$TAG kube=$S/kube/core.kubeconfig endpoints=$S/endpoints.json"
	local sum
	sum=$(find "$S/report" -name lite-summary.txt | head -n 1)
	check "lite summary written" test -s "$sum"
	check "X3 skipped with the reason" grep -qE '^SKIP +X3 +- +- +0.0  not run: the local rig puts the hubs' "$sum"
	check "C1 Windows tenant 1 skipped" grep -qE '^SKIP +C1 +windows +1 +0.0  not run: the local rig has no Windows sprouts' "$sum"
	check "C1 Windows tenant 2 skipped" grep -qE '^SKIP +C1 +windows +2 ' "$sum"
	check "S2 Windows skipped (no tenant)" grep -qE '^SKIP +S2 +windows +- ' "$sum"
	check "no Windows line for an OS-free scenario" bash -c "! grep -qE '^SKIP +T1 +windows' '$sum'"
	check "upstream summary kept" grep -q '^RESULT: PASS' "$sum"
	check "rig result" has "$T/out" "RIG RESULT: PASS on the Linux sprouts only; 4 lines not run on the rig"

	: >"$STUB_LOG"
	rc_is 0 "$LITE/run.sh" smoke
	check "smoke runs the tier as is" test "$(grep '^tests-run ' "$STUB_LOG")" = "tests-run smoke"
	check "no X3 line for smoke" bash -c "! grep -q 'SKIP   X3' '$T/out'"

	: >"$STUB_LOG"
	rc_is 0 "$LITE/run.sh" all
	check "all: two runs" test "$(count "$STUB_LOG" "tests-run ")" = 2
	args=$(grep '^tests-run all ' "$STUB_LOG")
	check "all: static ids without X3" bash -c "[[ '$args' == *' L1 '* && '$args' == *' R6 '* && '$args' != *' X3 '* && '$args' != *'I.'* ]]"
	check "all: then the ingredients tier" grep -qx 'tests-run ingredients' "$STUB_LOG"

	: >"$STUB_LOG"
	rc_is 0 "$LITE/run.sh" --with-x3 core
	check "--with-x3 runs the tier as is" test "$(grep '^tests-run ' "$STUB_LOG")" = "tests-run core"
	: >"$STUB_LOG"
	rc_is 0 "$LITE/run.sh" core C1 X3
	check "ids pass through" test "$(grep '^tests-run ' "$STUB_LOG")" = "tests-run core C1 X3"

	STUB_TESTS_RC=1 rc_is 1 "$LITE/run.sh" core
	check "a failure fails the rig" has "$T/out" "RIG RESULT: FAIL (exit 1)"

	# A Windows line already in the summary is not doubled.
	printf '%s\n' "UAT summary, tier core" "STATUS ID OS TENANT SECONDS DETAIL" \
		"PASS   C1                     ubuntu   1           4.2  " \
		"FAIL   C1                     windows  1           4.2  odd" "" "RESULT: FAIL" >"$T/sum"
	STUB_SUMMARY=$T/sum rc_is 0 "$LITE/run.sh" core C1
	check "no Windows skip where a Windows line exists" bash -c "! grep -qE '^SKIP +C1 +windows +1' '$T/out'"
}

t_run_brings_up() {
	rc_is 2 "$LITE/run.sh" core
	rc_is 1 "$LITE/run.sh" --no-up --release-tag "$TAG" core
	check "--no-up refuses" has "$T/err" "is not up"
	rc_is 0 "$LITE/run.sh" --release-tag "$TAG" smoke
	check "run.sh brought the rig up" has "$STUB_LOG" "kind create cluster --name core"
	check "then ran the tests" has "$STUB_LOG" "tests-run smoke"
	jq '.State.Running = false' "$STUB_STATE/docker/containers/imas-lite-t2-alma.json" >"$T/c" &&
		mv "$T/c" "$STUB_STATE/docker/containers/imas-lite-t2-alma.json"
	: >"$STUB_LOG"
	rc_is 0 "$LITE/run.sh" smoke
	check "a stopped sprout brings the rig up again, with the saved release" has "$STUB_LOG" "docker start imas-lite-t2-alma"
}

for t in t_usage t_up_direct t_up_rerun t_up_published t_up_failures t_up_options t_up_host_sprout \
	t_readers t_vmctl t_vmctl_host_sprout t_down t_run t_run_brings_up; do
	run_test "$t"
done
passed=0 failed=0
[[ ! -e $RESULTS/ok ]] || passed=$(wc -l <"$RESULTS/ok")
[[ ! -e $RESULTS/fail ]] || failed=$(wc -l <"$RESULTS/fail")
echo "uat/lite tests: $passed passed, $failed failed"
((failed == 0))
