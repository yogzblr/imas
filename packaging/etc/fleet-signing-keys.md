# fleet-signing-keys.asc — the sprout's update trust root

`fleet-signing-keys.asc` is the public keyring every sprout verifies a
release's `checksums.txt` signature against before it downloads or
installs anything (`internal/ingredients/selfupdate`,
`internal/fleetsign/gpg.go`; signing design D9, D12, D20, D21). It is
built from the repository's `gpg-public-key.asc` (the release key that
SECURITY.md publishes) and installed by the sprout package, which
replaces it on every upgrade:

| Package | Installed at |
|---|---|
| deb / rpm / apk (nfpm, `.goreleaser.yaml`) | `/etc/imas/fleet-signing-keys.asc`, mode 0644, root-owned, **not** a conffile: an upgrade always replaces it |
| MSI (`packaging/windows/imas-sprout.wxs`) | `%ProgramData%\imas\fleet-signing-keys.asc`, under the SYSTEM/Administrators-only DACL, replaced on upgrade |

The sprout reads it from `sproutfleetsigningkeyring` (default: the paths
above). It refuses a keyring that is not a regular file, and on Linux one
that is group- or world-writable, since whoever can write it decides what
the sprout installs as root.

## Format

One or more ASCII-armored OpenPGP public key blocks
(`-----BEGIN PGP PUBLIC KEY BLOCK-----`), as `gpg --armor --export`
writes them. A block may hold several keys, and several blocks may be
concatenated. Parsing (`fleetsign.ParseArmoredKeyring`) is strict: any
other armor type (a private key block, a signature) is refused, and a
keyring with no key that can sign is refused, so a sprout without a
usable key refuses every `self_update` (fail closed).

## What the sprout checks

1. The detached signature `checksums.txt.sig` (binary or armored) over the
   exact bytes of `checksums.txt` verifies against any key in this keyring.
   Key expiry is not enforced (D12.2); a revoked key is refused.
2. `checksums.txt` is well formed (`<64 lowercase hex>  <file name>` per
   line, no duplicate names).
3. The line for the file name the sprout derives itself
   (`imas-sprout_<version>_linux_<arch>.<deb|rpm>`,
   `imas-sprout-<version>-windows-<x64|x86|arch>.msi`) gives the SHA-256
   the downloaded package must have.

## Rotating the release key

The shipped keyring is the trust root, so a sprout only ever learns a new
key from a package it already trusts:

1. Create the new release key. Add its public key to `gpg-public-key.asc`
   alongside the current one (review this like any trust-root change).
2. Cut a release **signed by the old key**. Sprouts verify that release
   with the key they already hold and, by installing it, receive the
   keyring that holds both keys.
3. Once the fleet runs a release whose keyring holds the new key, sign
   new releases with it. A sprout still on an older release can't verify
   those: update it through step 2's release first.
4. Remove the old key from `gpg-public-key.asc` only after no tenant's
   approved version is signed by it.

Never ship a keyring that drops the key the currently approved releases
are signed with, or the fleet can no longer update. If the old key is
compromised, revoke it (ship its revocation certificate merged into
`gpg-public-key.asc`) in a release signed by the new key; sprouts that
already hold the new key then refuse anything the old key signs.
