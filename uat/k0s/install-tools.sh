#!/usr/bin/env bash
# uat/k0s/install-tools.sh: install the k0sctl and kubectl that versions.env
# pins into DIR, checking each binary's SHA-256 before it is made executable.
# Linux amd64 and arm64 only (the GitHub runner and the local rig).
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<'USAGE'
Usage: install-tools.sh DIR

Installs the k0sctl and kubectl versions pinned in versions.env into DIR
(created if missing), checking their SHA-256. Add DIR to PATH afterwards.
USAGE
}

main() {
  case ${1:-} in
    -h | --help) usage && exit 0 ;;
    "") usage >&2 && exit 2 ;;
  esac
  (($# == 1)) || { usage >&2 && exit 2; }
  need_cmd curl uname
  load_settings

  local dir=$1 arch k0sctl_sha kubectl_sha
  case $(uname -s)/$(uname -m) in
    Linux/x86_64 | Linux/amd64)
      arch=amd64
      k0sctl_sha=$K0SCTL_SHA256_LINUX_AMD64
      kubectl_sha=$KUBECTL_SHA256_LINUX_AMD64
      ;;
    Linux/aarch64 | Linux/arm64)
      arch=arm64
      k0sctl_sha=$K0SCTL_SHA256_LINUX_ARM64
      kubectl_sha=$KUBECTL_SHA256_LINUX_ARM64
      ;;
    *) die "unsupported platform: $(uname -s)/$(uname -m)" ;;
  esac
  mkdir -p -- "$dir"

  fetch_pinned "https://github.com/k0sproject/k0sctl/releases/download/$K0SCTL_VERSION/k0sctl-linux-$arch" \
    "$k0sctl_sha" "$dir/k0sctl"
  fetch_pinned "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$arch/kubectl" \
    "$kubectl_sha" "$dir/kubectl"
  chmod 755 "$dir/k0sctl" "$dir/kubectl"
  log "installed k0sctl $K0SCTL_VERSION and kubectl $KUBECTL_VERSION in $dir"
}

main "$@"
