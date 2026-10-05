#!/usr/bin/env bash
# Assert that every deb/rpm/apk in a GoReleaser dist directory contains what
# the service needs: the unversioned binary under /usr/bin, the default
# config, the trust root, the state directories, and the unit or init script.
#
# Why this exists: an nfpms per-format `contents` list REPLACES the top-level
# list, and the package builds used to be named imas-sprout-<version>-<os>-<arch>.
# The rc.3 packages therefore shipped only a versioned binary and a unit file
# that pointed at /usr/bin/imas-sprout. Nothing failed at build time, so this
# check does.
#
# Usage: packaging/check-package-contents.sh [dist-dir]   (default: dist)
# Needs dpkg-deb and tar; rpm (or python3 with the rpmfile module) for .rpm.
set -euo pipefail

dist="${1:-dist}"

# Print the file list of a package, one normalised path per line: no leading
# "./" or "/", no trailing "/".
list_pkg() {
  local f="$1"
  case "$f" in
    *.deb) dpkg-deb -c "$f" | awk '{ $1=$2=$3=$4=$5=""; sub(/^ +/, ""); print }' ;;
    *.rpm)
      if command -v rpm >/dev/null 2>&1; then
        rpm -qlp "$f"
      elif python3 -c 'import rpmfile' 2>/dev/null; then
        # Same list as rpm -qlp: directory entries live only in the header.
        python3 -c 'import rpmfile,sys
with rpmfile.open(sys.argv[1]) as r:
    h = r.headers
    def seq(v):  # a one-file package stores scalars, not tuples
        return v if isinstance(v, (list, tuple)) else [v]
    dirs = seq(h["dirnames"])
    for b, i in zip(seq(h["basenames"]), seq(h["dirindexes"])):
        print(dirs[i].decode() + b.decode())' "$f"
      else
        echo "need rpm or python3 rpmfile to read $f" >&2
        return 1
      fi ;;
    *.apk) tar tzf "$f" 2>/dev/null | grep -v '^\.' ;;
  esac | sed -e 's|^\./||' -e 's|^/||' -e 's|/$||' | grep -v '^$' | sort -u
}

fail=0
check() { # check <pkg-file> <required path>...
  local f="$1" listing; shift
  listing="$(list_pkg "$f")"
  local p
  for p in "$@"; do
    if ! grep -qxF "$p" <<<"$listing"; then
      echo "::error::$(basename "$f") is missing /$p"
      fail=1
    fi
  done
}

shopt -s nullglob
n=0
for f in "$dist"/imas-sprout_*_linux_*.{deb,rpm,apk} \
         "$dist"/imas-farmer_*_linux_*.{deb,rpm,apk} \
         "$dist"/imas_*_linux_*.{deb,rpm,apk}; do
  n=$((n + 1))
  base="$(basename "$f")"
  case "$base" in
    imas-sprout_*) name=imas-sprout
      req=(usr/bin/imas-sprout etc/imas/sprout etc/imas/fleet-signing-keys.json var/cache/imas/sprout) ;;
    imas-farmer_*) name=imas-farmer
      req=(usr/bin/imas-farmer etc/imas/farmer etc/imas/pki/farmer var/cache/imas/farmer) ;;
    *) name=imas
      req=(usr/bin/imas) ;;
  esac
  if [ "$name" != imas ]; then
    case "$f" in
      *.deb) req+=("lib/systemd/system/$name.service") ;;
      *.rpm) req+=("usr/lib/systemd/system/$name.service") ;;
      *.apk) req+=("etc/init.d/$name") ;;
    esac
  fi
  check "$f" "${req[@]}"
  # No versioned or otherwise stray binary next to the expected one.
  stray="$(list_pkg "$f" | grep '^usr/bin/' | grep -vx "usr/bin/$name" || true)"
  if [ -n "$stray" ]; then
    echo "::error::$base has unexpected files under /usr/bin: $stray"
    fail=1
  fi
done

if [ "$n" -eq 0 ]; then
  echo "::error::no imas packages found in $dist"
  exit 1
fi
[ "$fail" -eq 0 ] && echo "checked $n packages: contents OK"
exit "$fail"
