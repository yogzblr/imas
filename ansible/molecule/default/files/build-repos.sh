#!/bin/bash
# Publishes /work/pkg/*.deb and *.rpm as signed apt and rpm repositories
# under /work/repo, laid out like the Buildkite registries the role
# installs from:
#   /work/repo/gpgkey                  the signing key (ASCII armour)
#   /work/repo/deb/any/                apt: "deb <url>/deb/any/ any main"
#   /work/repo/rpm/x86_64/             yum/zypper: "<url>/rpm/$basearch"
# Runs in a throwaway ubuntu:24.04 container (see prepare.yml), as root:
# the tree it writes is handed back to /work's owner at the end, so a
# non-root Molecule (a CI runner) can prune its ephemeral directory.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -qq -y --no-install-recommends apt-utils gnupg createrepo-c >/dev/null

export GNUPGHOME=/tmp/gnupg
mkdir -p -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key 'imas molecule repo <repo@imas.invalid>' rsa3072 sign never
rm -rf /work/repo
mkdir -p /work/repo/deb/any/pool/main /work/repo/deb/any/dists/any/main/binary-amd64 /work/repo/rpm/x86_64
gpg --armor --export > /work/repo/gpgkey

cp /work/pkg/*.deb /work/repo/deb/any/pool/main/
cd /work/repo/deb/any
apt-ftparchive packages pool > dists/any/main/binary-amd64/Packages
gzip -kf dists/any/main/binary-amd64/Packages
apt-ftparchive -o APT::FTPArchive::Release::Suite=any -o APT::FTPArchive::Release::Codename=any \
  -o APT::FTPArchive::Release::Components=main -o APT::FTPArchive::Release::Architectures=amd64 \
  release dists/any > dists/any/Release
gpg --batch --yes --clearsign -o dists/any/InRelease dists/any/Release
gpg --batch --yes --armor --detach-sign -o dists/any/Release.gpg dists/any/Release

cp /work/pkg/*.rpm /work/repo/rpm/x86_64/
createrepo_c --quiet /work/repo/rpm/x86_64
gpg --batch --yes --armor --detach-sign -o /work/repo/rpm/x86_64/repodata/repomd.xml.asc /work/repo/rpm/x86_64/repodata/repomd.xml
chmod -R a+rX /work/repo
chown -R "$(stat -c %u:%g /work)" /work/repo
