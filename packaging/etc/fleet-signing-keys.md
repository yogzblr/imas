# fleet-signing-keys.json — the sprout's update trust root

`fleet-signing-keys.json` is the public keyring every sprout verifies a
fleet update manifest against before it downloads or installs anything
(`internal/ingredients/selfupdate`, API design §1.8, §2.3, §2.5). It is
installed by the sprout package and replaced by every package upgrade:

| Package | Installed at |
|---|---|
| deb / rpm (nfpm, `.goreleaser.yaml`) | `/etc/imas/fleet-signing-keys.json`, mode 0644, root-owned, **not** a conffile: an upgrade always replaces it |
| MSI (`packaging/windows/imas-sprout.wxs`) | `%ProgramData%\imas\fleet-signing-keys.json`, under the SYSTEM/Administrators-only DACL, replaced on upgrade |

The sprout reads it from `sproutfleetsigningkeyring` (default: the paths
above). It refuses a keyring that is group- or world-writable on Linux,
since whoever can write it decides what the sprout installs as root.

## Format

One JSON object mapping each key id — the OpenBao Transit key version of
`imas-fleet-signing`, the `N` in a manifest signature's `vN:` prefix — to
that version's raw 32-byte Ed25519 public key in standard padded base64,
exactly as `bao read transit/keys/imas-fleet-signing` returns it under
`keys.<N>.public_key`:

```json
{"1": "<base64 public key of version 1>", "2": "<base64 public key of version 2>"}
```

Parsing is strict (`fleetsign.ParseKeyring`): duplicate ids, non-string
values, `"01"`/`"v1"` ids, weak keys and an empty object are refused.

**The file in this repository is the empty placeholder `{}`.** A sprout
shipping it refuses every `self_update` (fail closed). The release must
replace it with the current `imas-fleet-signing` public key versions
before the packages are built; never put a private key, or anything not
read back from Transit, in it.

## Rotating the signing key

The shipped keyring is the trust root, so a sprout only ever learns a new
key from a package it already trusts:

1. `bao write -f transit/keys/imas-fleet-signing/rotate` creates version
   `N+1`. Keep signing releases with version `N` for now (leave
   `min_encryption_version` at `N`).
2. Add `"N+1"` to this keyring alongside `"N"`, and cut a sprout release
   **signed by the old key `N`**. Sprouts verify that release with the key
   they already hold and, by installing it, receive the new one.
3. Once the fleet runs a release whose keyring holds `N+1`, raise
   `min_encryption_version` to `N+1` so new releases are signed by it.
   A sprout still on an older release can't verify those: update it
   through step 2's release first.
4. Remove `"N"` from the keyring only after no tenant's approved version
   is signed by it (the `vN:` prefix of `saas.fleet_versions.signature`),
   then raise `min_decryption_version` past it.

Never ship a keyring that drops the key the currently approved releases
are signed with, or the fleet can no longer update.
