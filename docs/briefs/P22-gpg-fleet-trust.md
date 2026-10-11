# P22 build brief: fleet update trust by GPG-signed checksums.txt

Decisions are in `docs/design/imas-openbao-signing-design.md` (D9, D12, D19, D20, D21).
This brief is the whole specification. If something is not written here, do not
invent it: pick the smallest option that matches the surrounding code, list it
under "Choices I made" in the PR description, and carry on. Do not ask questions
in the PR; do not leave TODOs for the reviewer to answer.

FLAG FOR SECURITY REVIEW (both slices).

Two slices, in order. Slice 2 starts only after slice 1 is merged.

## Wire contract (both slices use exactly this)

Release assets (already produced by goreleaser, see `.goreleaser.yaml` `signs: id: gpg`):
- `checksums.txt`: lines `<64 lowercase hex>  <file name>` (two spaces), one per
  release file.
- `checksums.txt.sig`: binary detached OpenPGP signature over the exact bytes of
  `checksums.txt`, made by the release key's primary key.

Farmer response to `GET /v1/sprout/update-manifest` (200), JSON, all values strings,
exactly these keys, no others:

    version             vX.Y.Z canonical semver (as today)
    os                  as today
    arch                as today
    package_type        deb | rpm | msi
    min_sprout_version  canonical semver, <= version (as today, unsigned)
    checksums_txt       the checksums.txt bytes as a UTF-8 string
    checksums_sig       base64 (standard, padded) of the checksums.txt.sig bytes

There is no file_name, checksum_sha256 or signature key any more.

Sprout verification (the only verifier, D20), in this order, every failure is a
distinct typed error and fails closed:
1. Load the keyring from `config.SproutFleetSigningKeyring` (ASCII-armored,
   one or more public keys). Zero usable keys is an error.
2. `checksums_txt` is 1 byte to 128 KiB; the decoded signature is 1 byte to 8 KiB.
3. Verify the detached signature over the exact `checksums_txt` bytes against any
   key in the keyring. Signature bytes may be binary or armored; detect armored by
   the prefix `-----BEGIN PGP`. Key expiry is NOT enforced (D12.2): construct the
   openpgp config so an expired key still verifies. A revoked key is refused.
4. Parse `checksums_txt` strictly: every non-empty line must match
   `^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._+~-]*$` (file names need the same rule as
   `reFileName` in `internal/fleetsign/manifest.go`); a duplicate file name, an
   uppercase hash, a path separator, or a malformed line refuses the whole file.
5. Derive the expected file name itself (never from farmer):
   - deb and rpm: `imas-sprout_<version without v>_linux_<arch>.<package_type>`
   - msi: `imas-sprout-<version without v>-windows-<winarch>.msi` where winarch is
     `x64` for amd64, `x86` for 386, otherwise the arch unchanged
   (this is the inverse of the mapping in `packaging/helm/stamp-sprout-release.sh`).
6. The expected SHA-256 is the hash on the single line with that exact name. No
   such line is an error (`ErrNotInChecksums`).
7. The rest of the self_update flow is unchanged: download from the sprout's own
   configured repo, compare the SHA-256 of the downloaded file with the expected
   hash, install. `min_sprout_version` is still enforced by the sprout.

Trust root file: `/etc/imas/fleet-signing-keys.asc` on Linux (packages build it from
the repo's `gpg-public-key.asc`, D21); the existing Windows default root uses the
same file name with `.asc`.

## Slice 1: library, sprout, packaging

Scope (touch only these):
- `internal/fleetsign/` : new `gpg.go`, `gpg_test.go`; edit `manifest.go`,
  `keyring.go`, `fleetsign.go`, their tests; delete `obtransit.go`,
  `transit_test.go`, `openbao_response_test.go` and `testdata/` entries only used by
  them (grep first; if another package imports them keep the file and say so)
- `internal/ingredients/selfupdate/` (all files and tests)
- `internal/config/config.go` and `config_test.go` (keyring default path only)
- `.goreleaser.yaml` (the three nfpm `fleet-signing-keys.json` entries, and the
  gpg `signs` entry), `packaging/etc/fleet-signing-keys.md`, the Windows MSI source
  that installs the keyring (grep for `fleet-signing-keys`)
- `ansible/molecule/stubfarmer/fleet.go`

Build:
1. Add `github.com/ProtonMail/go-crypto` (BSD-3-Clause, approved by the owner;
   pure Go, no CGO). Use the newest v1.x release; state the version in the PR.
2. `internal/fleetsign/gpg.go` exports:
   - `LoadArmoredKeyring(path string) (ArmoredKeyring, error)` and
     `ParseArmoredKeyring(data []byte) (ArmoredKeyring, error)`
   - `func (k ArmoredKeyring) VerifyChecksums(txt, sig []byte) error`
   - `ParseChecksums(txt []byte) (Checksums, error)` and
     `func (c Checksums) Sum(fileName string) (string, bool)`
   - `ExpectedFileName(version, os, arch, packageType string) (string, error)`
   - sentinel errors: `ErrNoKeys`, `ErrBadSignature`, `ErrBadChecksums`,
     `ErrNotInChecksums`, `ErrChecksumsTooLarge`
3. `Manifest` becomes the wire contract above: fields Version, OS, Arch,
   PackageType, MinSproutVersion, ChecksumsTxt, ChecksumsSig (decoded []byte kept
   private after parse). `ParseManifest` stays strict (flat string object, no
   unknown or duplicate keys, no trailing data) with the key set above and a 256 KiB
   input limit. Remove `Message`, `MessageDomain`, Ed25519 `KeySet`, `Keyring`
   (JSON), `EncodeSignature`, `DecodeSignature`, `PublicKey`.
4. `selfupdate.prepare`: replace `fleetsign.LoadKeyring` + `keyring.Verify` with the
   verification order above; keep every existing check (downgrade, prerelease on
   Windows, repo configured, min_sprout_version, package type). The package file
   name comes from `ExpectedFileName`; remove use of manifest `FileName` and
   `ChecksumSHA256`.
5. `config.go`: the default keyring path is `fleet-signing-keys.asc` where it was
   `fleet-signing-keys.json`; nothing else in config changes.
6. `.goreleaser.yaml`: nfpm entries copy `./gpg-public-key.asc` to
   `/etc/imas/fleet-signing-keys.asc` (all three packages that carried the json);
   add `signature: "${artifact}.sig"` to the gpg sign entry so the asset name is
   explicit. Delete `packaging/etc/fleet-signing-keys.json`; rewrite
   `fleet-signing-keys.md` to describe the armored file and key rotation (ship a
   new keyring in a package signed by the old key). Do not change cosign.
7. `ansible/molecule/stubfarmer/fleet.go`: make the stub emit the new manifest.

Tests (all in Go, no network, no checked-in private keys):
- Generate a throwaway RSA-4096 or Ed25519 key with go-crypto inside the test, sign
  a generated checksums.txt, and cover: valid; checksums.txt with one byte changed;
  signature from a different key; empty keyring; keyring with two keys where the
  second signed (rotation); expired key still verifies; revoked key refused;
  truncated signature; armored signature; oversize txt; oversize sig.
- ParseChecksums: duplicate name; uppercase hash; one-space separator; name with
  `/`, `..`, `%`, space; empty file; trailing blank lines accepted.
- ExpectedFileName: deb, rpm, msi, amd64/arm64/386; version with a prerelease
  (`v0.1.0-rc.5` gives `0.1.0-rc.5`); reject an empty or malformed input.
- selfupdate: a table test through `prepare` for: good; tampered txt; wrong key;
  file name absent from checksums; farmer sending a file_name key (must be refused
  as an unknown key); downloaded file with a different SHA-256 than the signed line.
- A test that parses the repo's own `gpg-public-key.asc` (path `../../gpg-public-key.asc`
  from `internal/fleetsign`) and requires at least one key.
- `go test ./...` and `go vet ./...` pass; no CGO (`CGO_ENABLED=0 go build ./...`).

Not in slice 1: saasapi, farmer, fleetcatalog, chart, workflows, migrations. They
will not compile against the new `Manifest` until slice 2; in slice 1 keep them
compiling by leaving the old types in a file `internal/fleetsign/legacy.go` marked
`// Deprecated: removed in P22 slice 2` containing the Ed25519 `Manifest`
(renamed `LegacyManifest`), `KeySet`, `KeySetSource`, `Keyring` and helpers, and
point those packages at the `Legacy*` names with the smallest possible edit. If this
needs a file outside the scope above, that is the exception: edit the minimum and
list the files in the PR.

## Slice 2: server side, release stamping, retire fleetreleaser

Scope:
- `internal/saasapi/` (fleet_releases.go, fleet_update_dispatch.go, model.go,
  tests), `internal/fleetcatalog/`, `internal/api/handlers/update_manifest.go`,
  `internal/natsapi/sprout_action.go`, `cmd/farmer/main.go`, `cmd/saasapi/main.go`,
  `internal/sproutrelease/`, `internal/migrations/saas/00007_fleet_release_checksums.sql`
  (+ test mirroring `outbox_sweeper_leases_test.go`)
- `packaging/helm/stamp-sprout-release.sh` (+ its test if one exists),
  `.github/workflows/publish-packages.yml`, `.github/workflows/release.yml`
  (only the fleetreleaser parts), `deploy/helm/farmer/` (templates, values,
  files, README, `chart_test.go`)
- delete `cmd/fleetreleaser/`, `deploy/fleetreleaser/`, `internal/fleetsign/legacy.go`
- `docs/design/imas-openbao-signing-design.md` section 4.1: update only to match what was built

Build:
1. Migration `00007_fleet_release_checksums.sql` (same goose conventions as 00006):
   table `fleet_release_checksums` (`version varchar(64)` primary key,
   `checksums_txt mediumtext not null`, `checksums_sig text not null` (base64),
   `created_at datetime(3) not null`). Leave `fleet_versions.signature` in place and
   write `''` to it; add a code comment that a later migration drops it.
2. Register endpoint (`fleetReleaseRequest`): add `checksums_txt` and `checksums_sig`
   (both required, same size limits as the contract). saasapi does not verify the
   GPG signature (D20). Before storing anything it parses the whole `checksums_txt` with
   the same strict rules as the sprout (contract step 4: every non-empty line must be
   well formed, no duplicate file name, no uppercase hash); any bad line is 422 naming
   the line number. It also requires, for each package, that `file_name` is a line in
   `checksums_txt` and that its hash equals `checksum_sha256`; mismatch is 422 with a
   message naming the file. Same version re-registered with identical
   content is a no-op 200; different content is the existing 409 conflict path.
   Remove `releaseSigner`, `fleetReleaserClient` and every `signRelease` call.
3. `fleetcatalog.ApprovedManifest` returns the wire manifest: it joins the
   `fleet_versions` row (version/os/arch/package_type/min_sprout_version) with
   `fleet_release_checksums`. The farmer handler serializes it exactly as in the
   contract. Remove farmer's, saasapi's and natsapi's `fleetKeys` verification and
   every `SetFleetKeySource` call; the dispatch checks that the catalog row exists
   and that the version is approved for the tenant, as today.
4. `stamp-sprout-release.sh`: before stamping, require `dist/checksums.txt` and
   `dist/checksums.txt.sig`; verify the signature with `gpg` in a temporary
   `GNUPGHOME` that has only the repo's `gpg-public-key.asc` imported (path
   argument `--keyring-asc`, default `gpg-public-key.asc` at repo root); fail the
   script on a bad signature. Add `checksums_txt` (`jq --rawfile`) and
   `checksums_sig` (`base64 -w0`) to the output JSON.
5. `internal/sproutrelease`: `Release` gains `ChecksumsTxt` and `ChecksumsSig`
   (JSON `checksums_txt`, `checksums_sig`); `readRequest` requires both; the file
   is still sent byte for byte. The chart helper that builds the request
   (`imas-farmer.sproutRelease.request`) passes them through.
6. `publish-packages.yml`: download `checksums.txt.sig` with the other assets
   (`--pattern checksums.txt.sig`) and verify it with gpg against
   `gpg-public-key.asc` in the same step that runs `sha256sum --check`. No secret
   is needed (public key only). Keep the cosign verification.
7. Retire fleetreleaser (D12.5): delete the command, its deploy directory, the
   OpenBao policies `imas-fleet-signer.hcl` and `imas-fleet-verify.hcl` (both copies),
   the bootstrap-job and policies-configmap entries, networkpolicy rules, saasapi
   deployment env and values for it, and the chart tests that assert them. Run
   `grep -rIn "fleetreleaser\|imas-fleet-signing\|fleet-signing-keys.json"` and
   remove or rewrite every remaining hit that is not history under `docs/status/` or
   `docs/archive/`. List the files in the PR.

Tests:
- Migration test; register endpoint table test (good; missing sig; hash mismatch;
  file not in checksums; a malformed extra line; a duplicate extra file name; oversize;
  replay identical; replay different = 409).
- Handler test: response has exactly the seven keys; a catalog miss is 404.
- Stamp script test: a fixture dist directory with a throwaway key signs
  `checksums.txt`; good case; tampered file; wrong key; missing sig. Skip with a
  clear message if `gpg` or `jq` is absent.
- Chart tests pass (`go test ./deploy/helm/farmer/...`) and `helm template` with
  `ci/default-values.yaml` still renders.
- `go test ./...`, `go vet ./...`, `CGO_ENABLED=0 go build ./...`.

## PR rules (both slices)

- Do not edit `docs/BUILD-STATUS.md`. Add `docs/status/days/<today>/z-p22-slice<N>.md`
  with `item: P22`, `action: update`, `next-append:` one line saying what merged.
- PR description: start with FLAG FOR SECURITY REVIEW; sections "Built",
  "Deliberately not done", "Choices I made" (every judgment call, one line each),
  "Files outside scope" (should be empty). Say "ready for review", never "done" or
  "safe to merge".
