#!/usr/bin/env bash
# "cond && pass || fail" is safe here: pass only increments a counter.
# shellcheck disable=SC2015
# uat/k0s/tests/test-k0s.sh: bash tests for bootstrap.sh and check.sh.
# Nothing here reaches a cluster or the network: k0sctl, kubectl,
# curl and sleep are stubs (tests/stubs), the clusters' answers are JSON
# fixtures (testdata/kube), and the add-on downloads are stand-ins
# (testdata/downloads) pinned by a test copy of versions.env.
#
# Run: uat/k0s/tests/test-k0s.sh            (UPDATE_GOLDEN=1 rewrites
#      testdata/expected from the current templates; review the diff.)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K0S="$(cd "$HERE/.." && pwd)"
DATA="$K0S/testdata"

for c in jq openssl base64; do
  command -v "$c" >/dev/null 2>&1 || {
    echo "test-k0s: $c is required" >&2
    exit 1
  }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
CURRENT=""

t() { CURRENT=$1; }
pass() { PASS=$((PASS + 1)); }
fail() {
  FAIL=$((FAIL + 1))
  printf 'FAIL [%s] %s\n' "$CURRENT" "$*"
}

# run CMD... runs a command capturing RC, OUT (stdout) and ERR (stderr).
RC=0
OUT=""
ERR=""
run() {
  local o="$WORK/.out" e="$WORK/.err"
  "$@" >"$o" 2>"$e"
  RC=$?
  OUT=$(<"$o")
  ERR=$(<"$e")
}

expect_rc() {
  if [[ $RC == "$1" ]]; then pass; else fail "exit $RC, want $1; stderr: ${ERR:0:400}"; fi
}
expect_err() {
  if [[ $ERR == *"$1"* ]]; then pass; else fail "stderr lacks '$1': ${ERR:0:400}"; fi
}
expect_out() {
  if [[ $OUT == *"$1"* ]]; then pass; else fail "stdout lacks '$1': ${OUT:0:600}"; fi
}
expect_file_has() {
  if grep -qF -- "$2" "$1" 2>/dev/null; then pass; else fail "$1 lacks '$2'"; fi
}
expect_file_lacks() {
  if ! grep -qF -- "$2" "$1" 2>/dev/null; then pass; else fail "$1 has '$2'"; fi
}
expect_log_order() { # expect_log_order LOG PATTERN... (fixed strings, in order)
  local log=$1 line=0 p n
  shift
  for p in "$@"; do
    n=$(grep -nF -- "$p" "$log" | awk -F: -v after="$line" '$1 > after {print $1; exit}')
    if [[ -z $n ]]; then
      fail "log lacks, in order: '$p'"
      return
    fi
    line=$n
  done
  pass
}

# fresh_case NAME makes an isolated directory with a fixture copy, a stub
# PATH and a test versions file pinning the stand-in downloads.
fresh_case() {
  CASE="$WORK/$1"
  mkdir -p "$CASE/fix/dmz" "$CASE/fix/core" "$CASE/state"
  cp -r "$DATA/kube/." "$CASE/fix/"
  cp -r "$DATA/downloads" "$CASE/fix/downloads"
  : >"$CASE/log"
  : >"$CASE/id_test"
  export STUB_LOG="$CASE/log" STUB_FIX="$CASE/fix" STUB_STATE="$CASE/state"
  unset STUB_K0SCTL_VERSION STUB_K0SCTL_FAIL_APPLY
  export PATH="$HERE/stubs:$ORIG_PATH"
  local lp cm
  lp=$(sha256sum "$CASE/fix/downloads/local-path-storage.yaml" | awk '{print $1}')
  cm=$(sha256sum "$CASE/fix/downloads/cert-manager.yaml" | awk '{print $1}')
  sed -e "s#^LOCAL_PATH_PROVISIONER_SHA256=.*#LOCAL_PATH_PROVISIONER_SHA256=$lp#" \
    -e "s#^CERT_MANAGER_SHA256=.*#CERT_MANAGER_SHA256=$cm#" \
    "$K0S/versions.env" >"$CASE/versions.env"
  export UAT_K0S_VERSIONS="$CASE/versions.env"
  unset UAT_K0S_CONFIG
}
ORIG_PATH=$PATH

# jq_edit IN OUT FILTER writes a modified copy of a JSON file.
jq_edit() { jq "$3" "$1" >"$2"; }

boot() { run "$K0S/bootstrap.sh" "$@"; }
boot_render() { # boot_render UAT ACCESS
  boot --uat "$1" --access "$2" --ssh-key "$CASE/id_test" --out "$CASE/out" --render-only
}

###############################################################################
# bootstrap.sh: argument handling
###############################################################################
fresh_case args
t "bootstrap: no arguments"
boot
expect_rc 2
expect_err "--uat is required"

t "bootstrap: --help"
boot --help
expect_rc 0
expect_out "Usage: bootstrap.sh"

t "bootstrap: unknown argument"
boot --uat "$DATA/uat.json" --bogus
expect_rc 2
expect_err "unknown argument: --bogus"

t "bootstrap: flag without value"
boot --uat
expect_rc 2
expect_err "--uat needs a value"

t "bootstrap: each required flag"
boot --uat "$DATA/uat.json" --ssh-key "$CASE/id_test" --out "$CASE/out"
expect_rc 2
expect_err "--access is required"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --out "$CASE/out"
expect_rc 2
expect_err "--ssh-key is required"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test"
expect_rc 2
expect_err "--out is required"

t "bootstrap: missing uat file"
boot --uat "$CASE/nope.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/out"
expect_rc 2
expect_err "not a readable file"

t "bootstrap: uat file is not a JSON object"
echo '[1,2]' >"$CASE/list.json"
boot --uat "$CASE/list.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/out"
expect_rc 2
expect_err "not a JSON object"

t "bootstrap: missing ssh key"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/no-key" --out "$CASE/out"
expect_rc 2
expect_err "SSH key not readable"

t "bootstrap: bad timeout"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/out" --timeout 0
expect_rc 2
expect_err "--timeout must be"

t "bootstrap: bad --nodes"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/out" --nodes three
expect_rc 2
expect_err "--nodes must be a positive number"

t "bootstrap: out path with a space"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/o u t"
expect_rc 2
expect_err "unsupported characters"

###############################################################################
# bootstrap.sh: building the k0sctl files from the sample uat JSON
###############################################################################
fresh_case render
t "render: sample uat JSON and access.json"
boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 0
for f in k0sctl-dmz.yaml k0sctl-core.yaml endpoints.json; do
  if [[ -f "$CASE/out/$f" ]]; then pass; else fail "missing $f"; fi
done

# Compare against the golden files with this run's temp paths normalised.
normalise() { sed "s#$CASE#/RUN#g" "$1"; }
for f in k0sctl-dmz.yaml k0sctl-core.yaml endpoints.json; do
  t "render: golden $f"
  if [[ ${UPDATE_GOLDEN:-} == 1 ]]; then
    normalise "$CASE/out/$f" >"$DATA/expected/$f"
  fi
  if diff -u "$DATA/expected/$f" <(normalise "$CASE/out/$f") >"$CASE/diff"; then
    pass
  else
    fail "differs from testdata/expected/$f:
$(head -40 "$CASE/diff")"
  fi
done

t "render: dmz file, values from uat JSON and access.json"
D="$CASE/out/k0sctl-dmz.yaml"
expect_file_has "$D" "    - role: single"
expect_file_has "$D" "        address: 127.0.0.1"
expect_file_has "$D" "        port: 50022"
expect_file_has "$D" "        user: imasadmin"
expect_file_has "$D" "        keyPath: $CASE/id_test"
expect_file_has "$D" "          HostKeyAlias: uat-dmz"
expect_file_has "$D" "          UserKnownHostsFile: $CASE/out/known_hosts"
expect_file_has "$D" "      privateAddress: 10.60.1.4"
expect_file_has "$D" "  name: imas-uat-ab12cd34-dmz"

t "render: k0s version comes from versions.env"
v=$(sed -n 's/^K0S_VERSION=//p' "$K0S/versions.env")
expect_file_has "$D" "    version: $v"
expect_file_has "$CASE/out/k0sctl-core.yaml" "    version: $v"
# ...and is written nowhere else under uat/k0s (outside test data).
others=$(grep -rlF --exclude-dir=testdata --exclude-dir=tests -e "$v" "$K0S" | grep -v '/versions.env$' || true)
if [[ -z $others ]]; then pass; else fail "k0s version also written in: $others"; fi

t "render: API certificate names 127.0.0.1"
sans=$(sed -n '/^          sans:/,/^          extraArgs:/p' "$D")
for s in "- 127.0.0.1" "- 10.60.1.4" "- uatab12cd34-dmz.centralindia.cloudapp.azure.com"; do
  if [[ $sans == *"$s"* ]]; then pass; else fail "dmz SANs lack $s: $sans"; fi
done
expect_file_has "$CASE/out/k0sctl-core.yaml" "            - 10.60.2.4"

t "render: node port range"
expect_file_has "$D" "            service-node-port-range: 8442-8443"
expect_file_has "$CASE/out/k0sctl-core.yaml" "            service-node-port-range: 30000-32767"

t "render: CoreDNS maps both FQDNs on both hubs"
for h in dmz core; do
  expect_file_has "$CASE/out/k0sctl-$h.yaml" "10.60.2.4 uatab12cd34-core.centralindia.cloudapp.azure.com"
  expect_file_has "$CASE/out/k0sctl-$h.yaml" "10.60.1.4 uatab12cd34-dmz.centralindia.cloudapp.azure.com"
done

t "render: core file uses core's tunnel"
C="$CASE/out/k0sctl-core.yaml"
expect_file_has "$C" "        port: 50122"
expect_file_has "$C" "          HostKeyAlias: uat-core"

t "render: no k0sctl expansion or leftover token"
for h in dmz core; do
  # shellcheck disable=SC2016 # a literal dollar sign
  expect_file_lacks "$CASE/out/k0sctl-$h.yaml" '$'
  if grep -qE '__[A-Z0-9_]+__' "$CASE/out/k0sctl-$h.yaml"; then fail "token left in $h"; else pass; fi
done

t "render: rendered files are valid YAML"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
  for h in dmz core; do
    if python3 - "$CASE/out/k0sctl-$h.yaml" "$h" <<'PY'; then pass; else fail "$h: not valid YAML or wrong shape"; fi
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
host = d["spec"]["hosts"][0]
assert host["role"] == "single"
assert isinstance(host["openSSH"]["port"], int)
cfg = d["spec"]["k0s"]["config"]["spec"]
assert "127.0.0.1" in cfg["api"]["sans"]
assert cfg["api"]["extraArgs"]["service-node-port-range"] == {"dmz": "8442-8443", "core": "30000-32767"}[sys.argv[2]]
patch = yaml.safe_load(cfg["network"]["coreDNS"]["patches"][0]["patch"]["content"])
assert "hosts {" in patch["data"]["Corefile"]
PY
  done
else
  echo "skip: python3 yaml module not available (YAML parse check)"
fi

t "render: endpoints.json"
E="$CASE/out/endpoints.json"
[[ $(jq -r '.core.fqdn' "$E") == uatab12cd34-core.centralindia.cloudapp.azure.com ]] && pass || fail "core fqdn"
[[ $(jq -r '.dmz.ports.envoy' "$E") == 8443 ]] && pass || fail "envoy port"
[[ $(jq -r '.dmz.node_port_range' "$E") == 8442-8443 ]] && pass || fail "dmz range"
[[ $(jq -r '.dmz.exposure' "$E") == *"uat/hub/dmz"* ]] && pass || fail "dmz exposure owner"
[[ $(jq -r '.core.exposure' "$E") == hostPort ]] && pass || fail "core.exposure is not exactly hostPort"
[[ $(jq -r '.core.node_port_range' "$E") == 30000-32767 ]] && pass || fail "core range"
[[ $(jq -r '.dmz.ports.bus' "$E") == 8442 ]] && pass || fail "bus port"
[[ $(jq -r '.core.ports.farmer_api' "$E") == 5405 ]] && pass || fail "farmer api port"
[[ $(jq -r '.cluster_issuer' "$E") == imas-uat-ca ]] && pass || fail "issuer"
# Both readers' spellings (uat/hub/dmz and uat/hub/core), same values.
[[ $(jq -r '.ca.cluster_issuer' "$E") == imas-uat-ca ]] && pass || fail "ca.cluster_issuer"
[[ $(jq -r '.private_dns_zone' "$E") == uat.imas.internal ]] && pass || fail "private_dns_zone"
[[ $(jq -r '.dmz.private_fqdn' "$E") == dmz.uat.imas.internal ]] && pass || fail "dmz.private_fqdn"
[[ $(jq -r '.core.private_fqdn' "$E") == core.uat.imas.internal ]] && pass || fail "core.private_fqdn"

# The hub briefs' own endpoint loaders, read only, against what bootstrap.sh
# writes: they must accept it and read the same values.
t "render: uat/hub/core's endpoint loader accepts endpoints.json"
CORE_LIB="$K0S/../hub/core/lib/common.sh"
if [[ -r $CORE_LIB ]]; then
  if got=$(bash -c 'set -euo pipefail; source "$1"; ENDPOINTS=$2; load_endpoints
      printf "%s %s %s %s %s %s %s" "$CORE_EXPOSURE" "$CORE_FQDN" "$CORE_IP" \
        "$CORE_HTTPS_PORT" "$CORE_FARMER_PORT" "$DMZ_ENVOY_PORT" "$DMZ_BUS_PORT"' _ "$CORE_LIB" "$E" 2>&1); then
    want="hostPort uatab12cd34-core.centralindia.cloudapp.azure.com 10.60.2.4 443 5405 8443 8442"
    [[ $got == "$want" ]] && pass || fail "uat/hub/core read '$got', want '$want'"
  else
    fail "uat/hub/core's load_endpoints refused endpoints.json: $got"
  fi
else
  echo "skip: $CORE_LIB not present (uat/hub/core loader check)"
fi

t "render: uat/hub/dmz's endpoint loader accepts endpoints.json"
DMZ_LIB="$K0S/../hub/dmz/lib.sh"
if [[ -r $DMZ_LIB ]]; then
  if got=$(bash -c 'set -euo pipefail; source "$1"; dmz_load_endpoints "$2"
      printf "%s %s %s %s %s" "$DMZ_FQDN" "$DMZ_ENVOY_PORT" "$DMZ_BUS_PORT" "$CORE_FARMER_API_PORT" "$DMZ_CLUSTER_ISSUER"' \
      _ "$DMZ_LIB" "$E" 2>&1); then
    want="uatab12cd34-dmz.centralindia.cloudapp.azure.com 8443 8442 5405 imas-uat-ca"
    [[ $got == "$want" ]] && pass || fail "uat/hub/dmz read '$got', want '$want'"
  else
    fail "uat/hub/dmz's dmz_load_endpoints refused endpoints.json: $got"
  fi
else
  echo "skip: $DMZ_LIB not present (uat/hub/dmz loader check)"
fi

t "render: a private_dns_zone in the uat JSON names both private forms"
jq_edit "$DATA/uat.json" "$CASE/uat-zone.json" '.private_dns_zone = "run7.example.internal"'
boot_render "$CASE/uat-zone.json" "$DATA/access.json"
expect_rc 0
[[ $(jq -r '[.private_dns_zone, .dmz.private_fqdn, .core.private_fqdn] | join(" ")' "$CASE/out/endpoints.json") == \
  "run7.example.internal dmz.run7.example.internal core.run7.example.internal" ]] && pass || fail "zone from the uat JSON"
boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 0

t "render: file modes"
[[ $(stat -c %a "$D") == 600 ]] && pass || fail "k0sctl file mode $(stat -c %a "$D")"
[[ $(stat -c %a "$CASE/out/known_hosts") == 600 ]] && pass || fail "known_hosts mode"

t "render: a tunnel host other than 127.0.0.1 is added to the SANs"
jq_edit "$DATA/access.json" "$CASE/access-host.json" '.["uat-dmz"].host = "10.9.9.9"'
boot_render "$DATA/uat.json" "$CASE/access-host.json"
expect_rc 0
expect_file_has "$CASE/out/k0sctl-dmz.yaml" "            - 10.9.9.9"
expect_file_has "$CASE/out/k0sctl-dmz.yaml" "            - 127.0.0.1"
expect_file_has "$CASE/out/k0sctl-dmz.yaml" "        address: 10.9.9.9"

t "render: access.json entries under a vms object"
jq '{vms: .}' "$DATA/access.json" >"$CASE/access-vms.json"
boot_render "$DATA/uat.json" "$CASE/access-vms.json"
expect_rc 0
expect_file_has "$CASE/out/k0sctl-core.yaml" "        port: 50122"

# Each bad input is refused before anything is written for it.
bad_uat() { # bad_uat LABEL JQ_FILTER EXPECTED_ERROR
  t "render refuses: $1"
  jq_edit "$DATA/uat.json" "$CASE/bad.json" "$2"
  boot_render "$CASE/bad.json" "$DATA/access.json"
  expect_rc 1
  expect_err "$3"
}
bad_uat "private IP out of range" '.dmz.private_ip = "10.60.1.300"' "bad dmz.private_ip"
bad_uat "private IP with leading zero" '.core.private_ip = "10.060.2.4"' "bad core.private_ip"
bad_uat "FQDN carrying YAML" '.core.fqdn = "x.example.com\n    evil: 1"' "bad core.fqdn"
# shellcheck disable=SC2016 # a literal ${HOME} in the jq filter
bad_uat "FQDN carrying a k0sctl expansion" '.dmz.fqdn = "${HOME}.example.com"' "bad dmz.fqdn"
bad_uat "FQDN carrying a Corefile directive" '.core.fqdn = "a.com }"' "bad core.fqdn"
bad_uat "admin user" '.dmz.admin_user = "root;id"' "bad dmz.admin_user"
bad_uat "run_id too short" '.run_id = "ab1"' "run_id must be"
bad_uat "run_id upper case" '.run_id = "AB12CD34"' "run_id must be"
bad_uat "missing core" 'del(.core)' "missing or not a scalar: .core.name"
bad_uat "same name for both hubs" '.core.name = "uat-dmz" | .core.node_names = ["uat-dmz"]' "node uat-dmz appears twice"
bad_uat "public IP not an address" '.dmz.public_ip = "nope"' "bad dmz.public_ip"

bad_access() { # bad_access LABEL JQ_FILTER EXPECTED_ERROR
  t "render refuses: $1"
  jq_edit "$DATA/access.json" "$CASE/bad-access.json" "$2"
  boot_render "$DATA/uat.json" "$CASE/bad-access.json"
  expect_rc 1
  expect_err "$3"
}
bad_access "no kube tunnel for core" 'del(.["uat-core"].kube_port)' "no kube_port for VM uat-core"
bad_access "no entry for dmz" 'del(.["uat-dmz"])' "no host for VM uat-dmz"
bad_access "ssh port not a number" '.["uat-dmz"].ssh_port = "22x"' "bad ssh_port"
bad_access "ssh port 0" '.["uat-dmz"].ssh_port = 0' "bad ssh_port"
bad_access "host with a space" '.["uat-dmz"].host = "1.2.3.4 x"' "bad host"

t "render: the owner's ranges hold no port k0s uses"
boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 0
if [[ $ERR == *warning* ]]; then fail "unexpected warning: $ERR"; else pass; fi

t "render warns: a range holding ports k0s uses"
sed 's/^UAT_DMZ_NODE_PORT_RANGE=.*/UAT_DMZ_NODE_PORT_RANGE=5406-8443/' "$K0S/config.env" >"$CASE/config-wide.env"
UAT_K0S_CONFIG="$CASE/config-wide.env" boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 0
expect_err "warning: the dmz NodePort range 5406-8443 contains ports k0s or the node uses: 5555 6443 7132 7443 8080 8132 8133"
if [[ $ERR == *"the core NodePort range"* ]]; then fail "core range should hold no reserved port"; else pass; fi

t "render refuses: exposing a port k0s uses"
sed -e 's/^UAT_DMZ_ENVOY_PORT=.*/UAT_DMZ_ENVOY_PORT=6443/' -e 's/^UAT_DMZ_NODE_PORT_RANGE=.*/UAT_DMZ_NODE_PORT_RANGE=6443-8443/' \
  "$K0S/config.env" >"$CASE/config-api.env"
UAT_K0S_CONFIG="$CASE/config-api.env" boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 1
expect_err "dmz port 6443 is a port k0s or the node uses"

t "render refuses: an exposed port outside its hub's range"
sed 's/^UAT_DMZ_BUS_PORT=.*/UAT_DMZ_BUS_PORT=9000/' "$K0S/config.env" >"$CASE/config-port.env"
UAT_K0S_CONFIG="$CASE/config-port.env" boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 1
expect_err "dmz port 9000 is outside its NodePort range 8442-8443"

t "render refuses: a core hostPort inside the core NodePort range"
sed 's/^UAT_CORE_NODE_PORT_RANGE=.*/UAT_CORE_NODE_PORT_RANGE=443-5405/' "$K0S/config.env" >"$CASE/config-hp.env"
UAT_K0S_CONFIG="$CASE/config-hp.env" boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 1
expect_err "core hostPort 443 is inside its NodePort range 443-5405"

t "render refuses: a reserved list without the API port"
sed 's/^UAT_RESERVED_NODE_PORTS=.*/UAT_RESERVED_NODE_PORTS="8080"/' "$K0S/config.env" >"$CASE/config-res.env"
UAT_K0S_CONFIG="$CASE/config-res.env" boot_render "$DATA/uat.json" "$DATA/access.json"
expect_rc 1
expect_err "must list the API port 6443"

###############################################################################
# bootstrap.sh: the install flow against stubs
###############################################################################
full() { boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/out" "$@"; }

fresh_case flow
t "flow: fresh run on both hubs"
full --skip-check
expect_rc 0
L="$CASE/log"
expect_log_order "$L" \
  "k0sctl version" \
  "k0sctl apply --config $CASE/out/k0sctl-dmz.yaml" \
  "k0sctl kubeconfig --config $CASE/out/k0sctl-dmz.yaml --cluster imas-uat-ab12cd34-dmz --address https://127.0.0.1:56443" \
  "kubectl dmz wait --for=condition=Ready node --all" \
  "k0sctl apply --config $CASE/out/k0sctl-core.yaml" \
  "k0sctl kubeconfig --config $CASE/out/k0sctl-core.yaml --cluster imas-uat-ab12cd34-core --address https://127.0.0.1:56543" \
  "kubectl core wait --for=condition=Ready node --all" \
  "kubectl dmz apply -f $CASE/out/cache/local-path-storage.pinned.yaml" \
  "kubectl dmz annotate storageclass local-path storageclass.kubernetes.io/is-default-class=true --overwrite" \
  "kubectl dmz apply --server-side --force-conflicts -f $CASE/out/cache/cert-manager.yaml" \
  "kubectl dmz rollout status deployment/cert-manager-webhook" \
  "kubectl core apply -f $CASE/out/cache/local-path-storage.pinned.yaml" \
  "kubectl core apply --server-side --force-conflicts -f $CASE/out/cache/cert-manager.yaml" \
  "kubectl dmz create secret tls imas-uat-ca" \
  "kubectl dmz wait --for=condition=Ready clusterissuer/imas-uat-ca" \
  "kubectl core create secret tls imas-uat-ca" \
  "kubectl core wait --for=condition=Ready clusterissuer/imas-uat-ca"

t "flow: kubeconfigs written, private"
for h in dmz core; do
  K="$CASE/out/$h.kubeconfig"
  [[ -f $K ]] && pass || fail "no $h kubeconfig"
  [[ $(stat -c %a "$K" 2>/dev/null) == 600 ]] && pass || fail "$h kubeconfig mode"
done
expect_file_has "$CASE/out/dmz.kubeconfig" "server: https://127.0.0.1:56443"
expect_file_has "$CASE/out/core.kubeconfig" "server: https://127.0.0.1:56543"

t "flow: downloads pinned and the helper image tagged"
expect_file_has "$CASE/out/cache/local-path-storage.pinned.yaml" \
  "image: $(sed -n 's/^LOCAL_PATH_HELPER_IMAGE=//p' "$K0S/versions.env")"
if grep -qE '^[[:space:]]*image: docker\.io/library/busybox[[:space:]]*$' "$CASE/out/cache/local-path-storage.pinned.yaml"; then
  fail "untagged helper image left"
else
  pass
fi
[[ $(grep -c '^curl ' "$L") == 2 ]] && pass || fail "each manifest should be downloaded once, got $(grep -c '^curl ' "$L")"

t "flow: one CA on both hubs, written for the caller"
CA="$CASE/out/uat-ca.crt"
[[ -f $CA ]] && pass || fail "no uat-ca.crt"
cmp -s "$CA" "$CASE/state/dmz-secret.crt" && pass || fail "dmz Secret holds another CA"
cmp -s "$CA" "$CASE/state/core-secret.crt" && pass || fail "core Secret holds another CA"
ext=$(openssl x509 -in "$CA" -noout -text 2>/dev/null)
[[ $ext == *"CA:TRUE"* ]] && pass || fail "CA cert is not a CA"
[[ $ext == *"Certificate Sign"* ]] && pass || fail "CA cert lacks keyCertSign"
[[ $ext == *"CN = imas UAT CA ab12cd34"* ]] && pass || fail "CA subject lacks the run id"
[[ $ext == *"prime256v1"* || $ext == *"P-256"* ]] && pass || fail "CA key is not P-256"
openssl verify -CAfile "$CA" "$CA" >/dev/null 2>&1 && pass || fail "CA cert does not verify as self-signed"
[[ $(stat -c %a "$CA") == 644 ]] && pass || fail "uat-ca.crt mode"
left=$(find "$CASE/out" -name '*.key' -o -name '.ca.*' | head -1)
[[ -z $left ]] && pass || fail "CA key material left on disk: $left"

t "flow: ClusterIssuer applied with the config.env names"
for h in dmz core; do
  f="$CASE/state/$h-applied-issuer-$h.yaml"
  expect_file_has "$f" "  name: imas-uat-ca"
  expect_file_has "$f" "    secretName: imas-uat-ca"
done

t "flow: with the check at the end (healthy fixtures)"
fresh_case flowcheck
full
expect_rc 0
expect_out "both hubs pass"

t "flow: wrong k0sctl version"
fresh_case k0sctlver
STUB_K0SCTL_VERSION=v0.30.0 full --skip-check
expect_rc 1
expect_err "k0sctl v0.30.0 found, versions.env pins"
expect_file_lacks "$CASE/log" "k0sctl apply"

t "flow: k0sctl apply fails"
fresh_case applyfail
STUB_K0SCTL_FAIL_APPLY=1 full --skip-check
expect_rc 1
expect_err "dmz: k0sctl apply failed"

t "flow: a manifest whose checksum differs is refused"
fresh_case checksum
echo "# tampered" >>"$CASE/fix/downloads/cert-manager.yaml"
full --skip-check
expect_rc 1
expect_err "checksum mismatch"
expect_file_lacks "$CASE/log" "apply --server-side"

t "flow: local-path manifest of an unexpected shape"
fresh_case lpshape
sed -i 's#image: docker.io/library/busybox#image: docker.io/library/busybox:1.0#' "$CASE/fix/downloads/local-path-storage.yaml"
lp=$(sha256sum "$CASE/fix/downloads/local-path-storage.yaml" | awk '{print $1}')
sed -i "s#^LOCAL_PATH_PROVISIONER_SHA256=.*#LOCAL_PATH_PROVISIONER_SHA256=$lp#" "$CASE/versions.env"
full --skip-check
expect_rc 1
expect_err "expected one untagged busybox image line"

# A CA Secret fixture from a real CA made here.
make_secret() { # make_secret DIR CN
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj "/CN=$2" -keyout "$1/ca.key" -out "$1/ca.crt" >/dev/null 2>&1
  jq -n --arg c "$(base64 -w0 <"$1/ca.crt")" --arg k "$(base64 -w0 <"$1/ca.key")" \
    '{apiVersion: "v1", kind: "Secret", data: {"tls.crt": $c, "tls.key": $k}}' >"$1/secret.json"
}

t "flow: a CA already on one hub is reused, not replaced"
fresh_case reuse
make_secret "$CASE/fix/dmz" "earlier run CA"
full --skip-check
expect_rc 0
expect_err "reusing the UAT CA already on dmz"
cmp -s "$CASE/out/uat-ca.crt" "$CASE/fix/dmz/ca.crt" && pass || fail "uat-ca.crt is not the existing CA"
cmp -s "$CASE/state/core-secret.crt" "$CASE/fix/dmz/ca.crt" && pass || fail "core did not get the existing CA"
expect_file_lacks "$CASE/log" "kubectl dmz create secret"

t "flow: two different CAs on the hubs are refused"
fresh_case twoca
make_secret "$CASE/fix/dmz" "ca one"
make_secret "$CASE/fix/core" "ca two"
full --skip-check
expect_rc 1
expect_err "different UAT CAs"

###############################################################################
# check.sh
###############################################################################
chk() { run "$K0S/check.sh" "$@"; }
setup_out() { # kubeconfig files the stub keys on, plus endpoints.json
  mkdir -p "$CASE/out"
  : >"$CASE/out/dmz.kubeconfig"
  : >"$CASE/out/core.kubeconfig"
  boot_render "$DATA/uat.json" "$DATA/access.json" >/dev/null
}

fresh_case check
setup_out
t "check: usage"
chk
expect_rc 2
expect_err "no kubeconfig for the dmz hub"
chk --bogus
expect_rc 2
chk --help
expect_rc 0

t "check: healthy hubs"
chk --out "$CASE/out"
expect_rc 0
expect_out "== dmz hub"
expect_out "== core hub"
expect_out "node  uat-hub  Ready=True"
expect_out "default StorageClass: local-path"
expect_out "cert-manager: cert-manager-webhook Available"
expect_out "ClusterIssuer imas-uat-ca Ready"
expect_out "CoreDNS: uatab12cd34-core.centralindia.cloudapp.azure.com -> 10.60.2.4"
expect_out "both hubs pass"

t "check: explicit kubeconfig flags, no endpoints (DNS check skipped)"
chk --dmz-kubeconfig "$CASE/out/dmz.kubeconfig" --core-kubeconfig "$CASE/out/core.kubeconfig"
expect_rc 0
if [[ $OUT == *CoreDNS* ]]; then fail "DNS checked without endpoints"; else pass; fi

t "check: a node not Ready on core"
jq_edit "$DATA/kube/nodes.json" "$CASE/fix/core/nodes.json" '.items[0].status.conditions[1].status = "False"'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: node not Ready: uat-hub"
rm -f "$CASE/fix/core/nodes.json"

t "check: no node"
jq_edit "$DATA/kube/nodes.json" "$CASE/fix/dmz/nodes.json" '.items = []'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: no node registered"
rm -f "$CASE/fix/dmz/nodes.json"

t "check: no default StorageClass"
jq_edit "$DATA/kube/storageclasses.json" "$CASE/fix/dmz/storageclasses.json" '.items[0].metadata.annotations = {}'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: no default StorageClass"
rm -f "$CASE/fix/dmz/storageclasses.json"

t "check: cert-manager webhook not available"
jq_edit "$DATA/kube/deployments.json" "$CASE/fix/core/deployments.json" '.items[2].status.conditions[0].status = "False"'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: cert-manager not available: cert-manager-webhook"
rm -f "$CASE/fix/core/deployments.json"

t "check: cert-manager missing"
jq_edit "$DATA/kube/deployments.json" "$CASE/fix/core/deployments.json" '.items = []'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: cert-manager not available: cert-manager missing"
rm -f "$CASE/fix/core/deployments.json"

t "check: ClusterIssuer not Ready"
jq_edit "$DATA/kube/clusterissuers.json" "$CASE/fix/dmz/clusterissuers.json" '.items[0].status.conditions[0].status = "False"'
chk --out "$CASE/out"
expect_rc 1
expect_out "ClusterIssuer imas-uat-ca not Ready"
rm -f "$CASE/fix/dmz/clusterissuers.json"

t "check: CoreDNS without the core mapping"
jq_edit "$DATA/kube/coredns.json" "$CASE/fix/dmz/coredns.json" '.data.Corefile |= sub("10.60.2.4 [^\n]*\n"; "")'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: CoreDNS does not map uatab12cd34-core.centralindia.cloudapp.azure.com to 10.60.2.4"
rm -f "$CASE/fix/dmz/coredns.json"

t "check: a node port the hub does not expose"
jq_edit "$DATA/kube/dmz/services.json" "$CASE/fix/dmz/services.json" '.items[2].spec.ports[0].nodePort = 5405'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: node ports outside the hub's exposed ports"
expect_out "imas-dmz/imas-dmz-nats-bus:5405"
cp "$DATA/kube/dmz/services.json" "$CASE/fix/dmz/services.json"

t "check: core exposes no node port (node-port mode dropped)"
chk --out "$CASE/out"
expect_out "node ports within none"
jq_edit "$DATA/kube/core/services.json" "$CASE/fix/core/services.json" '.items[1].spec.type = "NodePort" | .items[1].spec.ports[0].nodePort = 30405'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: node ports outside the hub's exposed ports (none): imas-core/imas-core-farmer:30405"
cp "$DATA/kube/core/services.json" "$CASE/fix/core/services.json"

t "check: hostPorts"
chk --out "$CASE/out"
expect_out "pod   imas-core/imas-uat-core-edge-0  node uat-hub  hostPort 443 -> 8443"
expect_out "hostPorts within 443 5405 9000"
expect_out "hostPorts within none"
if [[ $OUT == *"kube-router-abcde  hostPort"* ]]; then fail "host-network pod listed"; else pass; fi

t "check: a hostPort on the DMZ"
jq_edit "$DATA/kube/pods.json" "$CASE/fix/dmz/pods.json" '.items[1].spec.containers[0].ports[0].hostPort = 53'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: hostPorts outside the hub's exposed ports (none): kube-system/coredns-12345:53"
rm -f "$CASE/fix/dmz/pods.json"

t "check: a core hostPort that is not the edge's"
jq_edit "$DATA/kube/core/pods.json" "$CASE/fix/core/pods.json" '.items[1].spec.containers[0].ports[0].hostPort = 8443'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: hostPorts outside the hub's exposed ports (443 5405 9000): imas-core/imas-uat-core-edge-0:8443"
cp "$DATA/kube/core/pods.json" "$CASE/fix/core/pods.json"

t "check: API unreachable"
mv "$CASE/fix/nodes.json" "$CASE/fix/nodes.json.off"
chk --out "$CASE/out"
expect_rc 1
expect_out "cannot list nodes"
mv "$CASE/fix/nodes.json.off" "$CASE/fix/nodes.json"

###############################################################################
# HA hubs (P24, brief H2): 3 controller+worker nodes on etcd per hub
###############################################################################
HA_UAT="$DATA/uat-ha.json"
HA_ACCESS="$DATA/access-ha.json"

fresh_case harender
t "ha render: 3 + 3 nodes"
boot_render "$HA_UAT" "$HA_ACCESS"
expect_rc 0
for f in k0sctl-dmz.yaml k0sctl-core.yaml endpoints.json; do
  t "ha render: golden ${f%.*}-ha.${f##*.}"
  g="$DATA/expected/${f%.*}-ha.${f##*.}"
  if [[ ${UPDATE_GOLDEN:-} == 1 ]]; then
    normalise "$CASE/out/$f" >"$g"
  fi
  if diff -u "$g" <(normalise "$CASE/out/$f") >"$CASE/diff"; then
    pass
  else
    fail "differs from $g:
$(head -40 "$CASE/diff")"
  fi
done

HC="$CASE/out/k0sctl-core.yaml"
HD="$CASE/out/k0sctl-dmz.yaml"
t "ha render: every node is controller+worker, untainted, through its own tunnel"
[[ $(grep -c '^    - role: controller+worker$' "$HC") == 3 ]] && pass || fail "core: want 3 controller+worker hosts"
[[ $(grep -c '^      noTaints: true$' "$HC") == 3 ]] && pass || fail "core: want noTaints on 3 hosts"
expect_file_lacks "$HC" "role: single"
for p in 50122 50123 50124; do expect_file_has "$HC" "        port: $p"; done
for n in uat-core-1 uat-core-2 uat-core-3; do expect_file_has "$HC" "          HostKeyAlias: $n"; done
for ip in 10.60.2.4 10.60.2.5 10.60.2.6; do expect_file_has "$HC" "      privateAddress: $ip"; done
for n in uat-dmz-1 uat-dmz-2 uat-dmz-3; do expect_file_has "$HD" "          HostKeyAlias: $n"; done

t "ha render: etcd, no externalAddress, no shared api.address"
expect_file_has "$HC" "          type: etcd"
if grep -qE '^ *externalAddress:' "$HC"; then fail "an HA hub sets no spec.api.externalAddress"; else pass; fi
if grep -qE '^          address:' "$HC"; then fail "an HA hub must not set one spec.api.address for every node"; else pass; fi
expect_file_has "$HC" "          port: 6443"

t "ha render: the load balancer's address and name are SANs, with every node"
sans=$(sed -n '/^          sans:/,/^          extraArgs:/p' "$HC")
for s2 in "- 127.0.0.1" "- 10.60.2.250" "- core-api.uat.imas.internal" "- 10.60.2.4" "- 10.60.2.5" "- 10.60.2.6" "- uatabc123-core.centralindia.cloudapp.azure.com"; do
  if [[ $sans == *"$s2"* ]]; then pass; else fail "core SANs lack $s2: $sans"; fi
done
expect_file_has "$HD" "            - dmz-api.uat.imas.internal"

t "ha render: kube-router FOU overlay on config.env's port, which uat/tofu opens"
fou=$(sed -n 's/^UAT_KUBE_ROUTER_FOU_PORT=//p' "$K0S/config.env")
expect_file_has "$HC" "              overlay-encap: fou"
expect_file_has "$HC" "              overlay-type: full"
expect_file_has "$HC" "              overlay-encap-port: \"$fou\""
if grep -qE "k0s_node_udp_ports *= *\[\"$fou\"\]" "$K0S/../tofu/network-security.tf"; then pass; else fail "uat/tofu does not open UDP $fou between a hub's nodes"; fi
expect_file_has "$HC" "            - sudo modprobe fou"

t "ha render: node-local load balancing on"
expect_file_has "$HC" "          nodeLocalLoadBalancing:"
expect_file_has "$HC" "            type: EnvoyProxy"

t "ha render: CoreDNS maps the own FQDN to each node, the other hub's to its api_address"
for ip in 10.60.2.4 10.60.2.5 10.60.2.6; do
  expect_file_has "$HC" "$ip uatabc123-core.centralindia.cloudapp.azure.com"
  expect_file_lacks "$HD" "$ip uatabc123-core.centralindia.cloudapp.azure.com"
done
expect_file_has "$HC" "10.60.1.250 uatabc123-dmz.centralindia.cloudapp.azure.com"
expect_file_has "$HD" "10.60.2.250 uatabc123-core.centralindia.cloudapp.azure.com"
for ip in 10.60.1.4 10.60.1.5 10.60.1.6; do expect_file_has "$HD" "$ip uatabc123-dmz.centralindia.cloudapp.azure.com"; done

t "ha render: no k0sctl expansion or leftover token"
for h in dmz core; do
  # shellcheck disable=SC2016 # a literal dollar sign
  expect_file_lacks "$CASE/out/k0sctl-$h.yaml" '$'
  if grep -qE '__[A-Z0-9_]+__' "$CASE/out/k0sctl-$h.yaml"; then fail "token left in $h"; else pass; fi
done

t "ha render: rendered files are valid YAML of the right shape"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
  for h in dmz core; do
    if python3 - "$CASE/out/k0sctl-$h.yaml" "$h" <<'PY'; then pass; else fail "$h: not valid YAML or wrong shape"; fi
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
hosts = d["spec"]["hosts"]
assert len(hosts) == 3 and all(h["role"] == "controller+worker" and h["noTaints"] is True for h in hosts)
assert all(h["hooks"]["apply"]["before"] for h in hosts)
assert len({h["openSSH"]["port"] for h in hosts}) == 3
cfg = d["spec"]["k0s"]["config"]["spec"]
assert cfg["storage"] == {"type": "etcd"}
assert "address" not in cfg["api"] and "externalAddress" not in cfg["api"]
assert cfg["network"]["nodeLocalLoadBalancing"] == {"enabled": True, "type": "EnvoyProxy"}
assert cfg["network"]["kuberouter"]["extraArgs"]["overlay-encap"] == "fou"
assert {"dmz": "dmz-api.uat.imas.internal", "core": "core-api.uat.imas.internal"}[sys.argv[2]] in cfg["api"]["sans"]
PY
  done
else
  echo "skip: python3 yaml module not available (YAML parse check)"
fi

t "ha render: endpoints.json carries the nodes, API address and datastore"
E="$CASE/out/endpoints.json"
[[ $(jq -r '.core.nodes | join(" ")' "$E") == "uat-core-1 uat-core-2 uat-core-3" ]] && pass || fail "core nodes"
[[ $(jq -r '.dmz.node_private_ips | join(" ")' "$E") == "10.60.1.4 10.60.1.5 10.60.1.6" ]] && pass || fail "dmz node ips"
[[ $(jq -r '[.dmz.datastore, .core.datastore] | join(" ")' "$E") == "etcd etcd" ]] && pass || fail "datastore"
[[ $(jq -r '[.dmz.api_address, .core.api_fqdn] | join(" ")' "$E") == "10.60.1.250 core-api.uat.imas.internal" ]] && pass || fail "api address and name"
[[ $(jq -r '.core.exposure' "$E") == hostPort ]] && pass || fail "core.exposure"

t "ha render: one HA hub and one single node"
jq_edit "$HA_UAT" "$CASE/mixed.json" '.dmz = {name: "uat-dmz", id: "x", private_ip: "10.60.1.4", public_ip: "198.51.100.30",
  fqdn: "uatabc123-dmz.centralindia.cloudapp.azure.com", admin_user: "imasuat", node_names: ["uat-dmz"],
  node_ids: ["x"], node_private_ips: ["10.60.1.4"], api_address: "10.60.1.4", api_fqdn: "dmz-api.uat.imas.internal"}'
jq '. + {"uat-dmz": .["uat-dmz-1"]}' "$HA_ACCESS" >"$CASE/mixed-access.json"
boot_render "$CASE/mixed.json" "$CASE/mixed-access.json"
expect_rc 0
expect_file_has "$CASE/out/k0sctl-dmz.yaml" "    - role: single"
expect_file_has "$CASE/out/k0sctl-core.yaml" "10.60.1.4 uatabc123-dmz.centralindia.cloudapp.azure.com"
[[ $(jq -r '.dmz.datastore' "$CASE/out/endpoints.json") == kine ]] && pass || fail "single dmz keeps kine"

bad_ha() { # bad_ha LABEL JQ_FILTER EXPECTED_ERROR [ACCESS_FILTER]
  t "ha render refuses: $1"
  jq_edit "$HA_UAT" "$CASE/bad-ha.json" "$2"
  jq_edit "$HA_ACCESS" "$CASE/bad-ha-access.json" "${4:-.}"
  boot_render "$CASE/bad-ha.json" "$CASE/bad-ha-access.json"
  expect_rc 1
  expect_err "$3"
}
bad_ha "two nodes (etcd needs an odd number)" '.core.node_names |= .[:2] | .core.node_private_ips |= .[:2]' "core has 2 nodes"
bad_ha "node lists of different lengths" '.dmz.node_private_ips |= .[:2]' "differ in length"
bad_ha "no api_address" 'del(.core.api_address)' "core has 3 nodes but no api_address"
bad_ha "no api_fqdn" 'del(.dmz.api_fqdn)' "dmz has 3 nodes but no api_fqdn"
bad_ha "api_address is a node's" '.core.api_address = "10.60.2.5"' "must be the load balancer's"
bad_ha "api_fqdn carrying YAML" '.core.api_fqdn = "a.b\n  x: 1"' "bad core.api_fqdn"
bad_ha "a node address out of range" '.dmz.node_private_ips[2] = "10.60.1.256"' "bad dmz node address"
bad_ha "a bad node name" '.core.node_names[1] = "Uat_Core"' "bad core node name"
bad_ha "a node twice" '.core.node_names[2] = "uat-core-2"' "node uat-core-2 appears twice"
bad_ha "the hub's name is not the first node" '.dmz.name = "uat-dmz-2"' "must be the first node's"
bad_ha "node_names not a list of strings" '.dmz.node_names = "uat-dmz-1"' "dmz.node_names must be a list of strings"
bad_ha "no API tunnel" '.' "no host for VM core-api" 'del(.["core-api"])'
t "ha render: --nodes matches the hubs"
boot --uat "$HA_UAT" --access "$HA_ACCESS" --ssh-key "$CASE/id_test" --out "$CASE/out" --render-only --nodes 3
expect_rc 0
t "ha render refuses: --nodes differs from the uat JSON"
boot --uat "$HA_UAT" --access "$HA_ACCESS" --ssh-key "$CASE/id_test" --out "$CASE/out" --render-only --nodes 1
expect_rc 1
expect_err "dmz has 3 nodes, --nodes asks for 1"
boot --uat "$DATA/uat.json" --access "$DATA/access.json" --ssh-key "$CASE/id_test" --out "$CASE/out" --render-only --nodes 3
expect_rc 1
expect_err "dmz has 1 nodes, --nodes asks for 3"

bad_ha "a node without its SSH tunnel" '.' "no ssh_port for VM uat-dmz-3" 'del(.["uat-dmz-3"].ssh_port)'

###############################################################################
# HA hubs: the install flow against stubs
###############################################################################
ha_fix() { # 3-node answers for both hubs
  local h
  for h in dmz core; do cp "$DATA/kube/ha/$h/"*.json "$CASE/fix/$h/"; done
}
ha_full() { boot --uat "$HA_UAT" --access "$HA_ACCESS" --ssh-key "$CASE/id_test" --out "$CASE/out" "$@"; }

fresh_case haflow
ha_fix
t "ha flow: both hubs, kubeconfig through the API tunnel, waits for 3 nodes and 3 etcd members"
ha_full --skip-check
expect_rc 0
expect_log_order "$CASE/log" \
  "k0sctl apply --config $CASE/out/k0sctl-dmz.yaml" \
  "k0sctl kubeconfig --config $CASE/out/k0sctl-dmz.yaml --cluster imas-uat-abc123-dmz --address https://127.0.0.1:56450" \
  "kubectl dmz get nodes" \
  "kubectl dmz wait --for=condition=Ready node --all" \
  "kubectl dmz get etcdmembers.etcd.k0sproject.io" \
  "k0sctl apply --config $CASE/out/k0sctl-core.yaml" \
  "k0sctl kubeconfig --config $CASE/out/k0sctl-core.yaml --cluster imas-uat-abc123-core --address https://127.0.0.1:56550" \
  "kubectl core get etcdmembers.etcd.k0sproject.io"
expect_err "dmz: 3 node(s) Ready"
expect_err "core: etcd has 3 members"
expect_file_has "$CASE/out/core.kubeconfig" "server: https://127.0.0.1:56550"
[[ $(grep -c '^k0sctl apply' "$CASE/log") == 2 ]] && pass || fail "want one k0sctl apply per hub"

t "ha flow: with the check at the end"
fresh_case haflowcheck
ha_fix
ha_full
expect_rc 0
expect_out "etcd: 3 members joined"
expect_out "3 node(s) Ready, the hub has 3"
expect_out "both hubs pass"

t "ha flow: fewer nodes than the hub has"
fresh_case hafewnodes
ha_fix
jq_edit "$DATA/kube/ha/core/nodes.json" "$CASE/fix/core/nodes.json" '.items |= .[:2]'
ha_full --skip-check --timeout 1
expect_rc 1
expect_err "core: 2 of 3 node(s) registered within 1s"

t "ha flow: etcd short of a member"
fresh_case haetcd
ha_fix
jq_edit "$DATA/kube/ha/dmz/etcdmembers.json" "$CASE/fix/dmz/etcdmembers.json" '.items[2].status.conditions[0].status = "False"'
ha_full --skip-check --timeout 1
expect_rc 1
expect_err "dmz: etcd has 2 of 3 members joined after 1s"
expect_file_lacks "$CASE/log" "k0sctl apply --config $CASE/out/k0sctl-core.yaml"

###############################################################################
# HA hubs: check.sh
###############################################################################
fresh_case hacheck
ha_fix
mkdir -p "$CASE/out"
: >"$CASE/out/dmz.kubeconfig"
: >"$CASE/out/core.kubeconfig"
boot_render "$HA_UAT" "$HA_ACCESS" >/dev/null
t "ha check: healthy"
chk --out "$CASE/out"
expect_rc 0
expect_out "node  uat-core-3  Ready=True"
expect_out "etcd  uat-dmz-2  10.60.1.5  Joined=True"
expect_out "CoreDNS: uatabc123-core.centralindia.cloudapp.azure.com -> 10.60.2.6"
expect_out "CoreDNS: uatabc123-dmz.centralindia.cloudapp.azure.com -> 10.60.1.250"

t "ha check: a node not Ready"
jq_edit "$DATA/kube/ha/core/nodes.json" "$CASE/fix/core/nodes.json" '.items[1].status.conditions[1].status = "False"'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: node not Ready: uat-core-2"
expect_out "core: 2 of 3 nodes Ready"
cp "$DATA/kube/ha/core/nodes.json" "$CASE/fix/core/nodes.json"

t "ha check: a node missing"
jq_edit "$DATA/kube/ha/dmz/nodes.json" "$CASE/fix/dmz/nodes.json" '.items |= .[1:]'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: 2 of 3 nodes Ready"
cp "$DATA/kube/ha/dmz/nodes.json" "$CASE/fix/dmz/nodes.json"

t "ha check: an etcd member missing"
jq_edit "$DATA/kube/ha/core/etcdmembers.json" "$CASE/fix/core/etcdmembers.json" '.items |= .[:2]'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: etcd has 2 of 3 members joined"
cp "$DATA/kube/ha/core/etcdmembers.json" "$CASE/fix/core/etcdmembers.json"

t "ha check: an etcd member that left"
jq_edit "$DATA/kube/ha/dmz/etcdmembers.json" "$CASE/fix/dmz/etcdmembers.json" '.items[0].status.conditions[0].status = "False"'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: etcd has 2 of 3 members joined"
cp "$DATA/kube/ha/dmz/etcdmembers.json" "$CASE/fix/dmz/etcdmembers.json"

t "ha check: etcd members cannot be listed"
mv "$CASE/fix/core/etcdmembers.json" "$CASE/fix/core/etcdmembers.off"
chk --out "$CASE/out"
expect_rc 1
expect_out "core: cannot list etcd members"
mv "$CASE/fix/core/etcdmembers.off" "$CASE/fix/core/etcdmembers.json"

t "ha check: CoreDNS lacks one node of the own hub"
jq_edit "$DATA/kube/ha/core/coredns.json" "$CASE/fix/core/coredns.json" '.data.Corefile |= sub("10.60.2.5 [^\n]*\n"; "")'
chk --out "$CASE/out"
expect_rc 1
expect_out "core: CoreDNS does not map uatabc123-core.centralindia.cloudapp.azure.com to 10.60.2.5"
cp "$DATA/kube/ha/core/coredns.json" "$CASE/fix/core/coredns.json"

t "ha check: CoreDNS maps the other hub to a node instead of its api_address"
jq_edit "$DATA/kube/ha/dmz/coredns.json" "$CASE/fix/dmz/coredns.json" '.data.Corefile |= sub("10.60.2.250 "; "10.60.2.4 ")'
chk --out "$CASE/out"
expect_rc 1
expect_out "dmz: CoreDNS does not map uatabc123-core.centralindia.cloudapp.azure.com to 10.60.2.250"
cp "$DATA/kube/ha/dmz/coredns.json" "$CASE/fix/dmz/coredns.json"

t "ha check: a single-node endpoints file expects one node and no etcd"
chk --out "$CASE/out" --endpoints "$WORK/check/out/endpoints.json"
if [[ $OUT == *"etcd  "* ]]; then fail "etcd checked for a single-node hub"; else pass; fi
expect_out "3 node(s) Ready, the hub has 1"

###############################################################################
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
((FAIL == 0))
