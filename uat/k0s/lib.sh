# shellcheck shell=bash
# Shared helpers for uat/k0s: logging, input checks, reading the uat JSON and
# access.json, template rendering and pinned downloads. Sourced, never run.

# The directory holding this file, so the scripts work from any cwd.
K0S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The two hubs, in the order they are installed.
# shellcheck disable=SC2034 # used by the scripts that source this file
HUBS=(dmz core)

log() { printf '[uat-k0s] %s\n' "$*" >&2; }
die() {
  printf '[uat-k0s] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
  done
}

# load_settings sources versions.env and config.env. UAT_K0S_VERSIONS and
# UAT_K0S_CONFIG may point elsewhere (the tests use that).
load_settings() {
  local f
  for f in "${UAT_K0S_VERSIONS:-$K0S_DIR/versions.env}" "${UAT_K0S_CONFIG:-$K0S_DIR/config.env}"; do
    [[ -r "$f" ]] || die "settings file not readable: $f"
    # shellcheck source=/dev/null
    source "$f"
  done
}

# --- input checks ----------------------------------------------------------
# Every value that reaches a rendered file is checked first, so the uat JSON
# or access.json cannot inject YAML, a Corefile directive or a k0sctl
# environment expansion ($), and a typo fails here rather than on the node.

is_ipv4() {
  local ip=$1 o
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    [[ $o =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    ((o <= 255)) || return 1
  done
}

is_fqdn() {
  local n=$1
  ((${#n} <= 253)) || return 1
  [[ $n =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

is_port() {
  [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535))
}

is_run_id() { [[ $1 =~ ^[a-z0-9]{6,10}$ ]]; }

is_user() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

is_vm_name() { [[ $1 =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]]; }

# Paths end up unquoted in YAML and in k0sctl's envsubst pass: a conservative
# character set, absolute.
is_safe_abs_path() { [[ $1 =~ ^/[A-Za-z0-9._/+-]*$ ]] && [[ $1 != *..* ]]; }

# abs_path prints an absolute form of a path whose parent directory exists.
abs_path() {
  local p=$1 d b
  d=$(dirname -- "$p")
  b=$(basename -- "$p")
  d=$(cd -- "$d" 2>/dev/null && pwd -P) || return 1
  if [[ $b == "/" || $b == "." ]]; then
    printf '%s\n' "$d"
  else
    printf '%s/%s\n' "${d%/}" "$b"
  fi
}

# --- the uat JSON and access.json ------------------------------------------

# uat_get FILE JQ_PATH prints a string or number field, or fails.
uat_get() {
  local file=$1 path=$2 v
  v=$(jq -er "$path | select(type == \"string\" or type == \"number\")" "$file" 2>/dev/null) ||
    die "uat JSON $file: missing or not a scalar: $path"
  printf '%s\n' "$v"
}

# access_get FILE VM FIELD prints one field of a VM's entry in access.json.
# The Access interface gives, per VM name, host and ssh_port, winrm_port or
# kube_port. The entry is read from the top level, or from a "vms" or "hosts"
# object, so a wrapper around the entries does not break this.
access_get() {
  local file=$1 vm=$2 field=$3 v
  v=$(jq -er --arg vm "$vm" --arg f "$field" '
      (if type == "object" then (.[$vm] // .vms[$vm]? // .hosts[$vm]?) else null end)
      | if type == "object" then .[$f] else null end
      | select(type == "string" or type == "number")' "$file" 2>/dev/null) ||
    die "access.json $file: no $field for VM $vm"
  printf '%s\n' "$v"
}

# --- rendering -------------------------------------------------------------

# render_template TEMPLATE OUT KEY=VALUE... replaces each __KEY__ token with
# VALUE and fails if a token is left. Values must already be checked.
render_template() {
  local tmpl=$1 out=$2 content kv key val left
  shift 2
  [[ -r "$tmpl" ]] || die "template not readable: $tmpl"
  content=$(<"$tmpl")
  # bash 5.2 expands & in a pattern substitution's replacement; values are
  # checked and contain no &, but turn it off so that can never matter.
  shopt -u patsub_replacement 2>/dev/null || true
  for kv in "$@"; do
    key=${kv%%=*}
    val=${kv#*=}
    [[ $key =~ ^[A-Z0-9_]+$ ]] || die "bad template key: $key"
    content=${content//__${key}__/$val}
  done
  left=$(grep -oE '__[A-Z0-9_]+__' <<<"$content" | sort -u | tr '\n' ' ' || true)
  [[ -z $left ]] || die "template $tmpl: tokens left unreplaced: $left"
  printf '%s\n' "$content" >"$out"
}

# --- pinned downloads ------------------------------------------------------

# sha256_of FILE prints the file's SHA-256.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# fetch_pinned URL SHA256 OUT downloads URL to OUT (once; a cached file is
# re-checked) and fails unless its SHA-256 is the pinned one.
fetch_pinned() {
  local url=$1 want=$2 out=$3 got
  if [[ ! -s "$out" ]]; then
    log "downloading $url"
    curl -fsSL --retry 3 --retry-delay 2 -o "$out.part" "$url" || die "download failed: $url"
    mv -f "$out.part" "$out"
  fi
  got=$(sha256_of "$out")
  if [[ "$got" != "$want" ]]; then
    rm -f "$out"
    die "checksum mismatch for $url: got $got, pinned $want"
  fi
}

# --- kubectl ---------------------------------------------------------------

# kc KUBECONFIG ARGS... runs kubectl against one hub. No request timeout
# here: it would also cut the watches behind kubectl wait and rollout status.
kc() {
  local kubeconfig=$1
  shift
  kubectl --kubeconfig "$kubeconfig" "$@"
}

# hub_allowed_node_ports HUB prints the node ports a hub may expose.
hub_allowed_node_ports() {
  case $1 in
    dmz) printf '%s\n' "$UAT_DMZ_ENVOY_PORT" "$UAT_DMZ_BUS_PORT" ;;
    core) printf '%s\n' "$UAT_CORE_HTTPS_PORT" "$UAT_CORE_FARMER_API_PORT" ;;
    *) die "unknown hub: $1" ;;
  esac
}

# hub_node_port_range HUB prints the hub's NodePort range ("low-high").
hub_node_port_range() {
  case $1 in
    dmz) printf '%s\n' "$UAT_DMZ_NODE_PORT_RANGE" ;;
    core) printf '%s\n' "$UAT_CORE_NODE_PORT_RANGE" ;;
    *) die "unknown hub: $1" ;;
  esac
}

# port_in_range PORT RANGE (RANGE as "low-high").
port_in_range() {
  local p=$1 lo=${2%-*} hi=${2#*-}
  ((p >= lo && p <= hi))
}
