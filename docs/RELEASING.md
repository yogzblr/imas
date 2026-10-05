# Releasing imas

> **Status (2026-10-03): this flow has never been run.** No tag or release
> exists and neither workflow has had a run. Expect the first real release to
> need fixes: follow the [First release checklist](#first-release-checklist).
> The secrets and variable it needs are listed under
> [Settings](#settings). Start with a pre-release tag such as `v0.1.0-rc.1`.
> The workflows use GoReleaser OSS (MIT), so no GoReleaser licence key is
> needed; the Windows MSI is built by `packaging/windows/build-msi.sh`
> (msitools' `wixl`) as a build hook (brief REL.1). Nothing has installed
> that MSI on a Windows host yet.

One tag releases everything: the `imas`, `imas-farmer` and `imas-sprout`
binaries and packages, the six container images, and the Helm charts. The
farmer and sprout ship in lockstep so a farmer release always carries the
sprout release it was tested with (API design §2.5).

## Tags

- Format `vMAJOR.MINOR.PATCH`, semver. Pre-1.0 releases are `v0.MINOR.PATCH`.
- Pre-releases: `vX.Y.Z-rc.N` (or `-beta.N`). goreleaser marks them
  pre-release (`prerelease: auto`); they get versioned image tags but never
  move `latest`, and `publish-packages.yml` skips them unless you dispatch it
  for that tag by hand.
- Tags are annotated and immutable. Never move or reuse one: Buildkite
  registries reject a package or chart version they already hold, and
  signatures are bound to the tag. A bad release is fixed forward with the
  next patch, and withdrawn with the revoke call (below).
- The tag is the only source of the version. Everything derives from it,
  with the leading `v` dropped except where noted:

  | Artifact | Version |
  |---|---|
  | Binaries / `-X main.Tag` | `vX.Y.Z` |
  | rpm, deb, apk, MSI, winget | `X.Y.Z` |
  | Images `ghcr.io/yogzblr/imas-*` | `X.Y.Z` (and `latest` for finals) |
  | Helm charts `farmer`, `nats` | chart `version` and `appVersion` = `X.Y.Z` |

## Settings

`release.yml` and `publish-packages.yml` run in the GitHub environment
**`goreleaser`**, so each secret or variable below can be set on the
repository or on that environment. `snapshot.yml` needs none of them: it
neither signs (`--skip=sign`) nor publishes.

| Name | Kind | Used by |
|---|---|---|
| `GPG_PRIVATE_KEY` | secret | `release.yml` (signs `checksums.txt`) |
| `GPG_PASSPHRASE` | secret | `release.yml` |
| `BUILDKITE_PACKAGES_TOKEN` | secret | `publish-packages.yml`; Buildkite API token with Read Packages and Write Packages |
| `BUILDKITE_ORGANIZATION_SLUG` | variable | `publish-packages.yml`; the org owning the registries below |

Each workflow checks its own names first and fails naming any that are
missing. The Buildkite organisation needs four registries: `imasrpm` (Red
Hat), `imasdeb` (Debian), `imasnget` (NuGet, **public**: winget downloads
the MSI from it anonymously) and `imashelm` (a **Helm** registry, not Helm OCI: `publish-helm.sh` uploads with the REST API, which only the standard Helm type accepts; the registry type cannot be changed after creation). If the `goreleaser`
environment has deployment branch or tag rules, they must allow `v*` tags
(Release, and Publish packages on a published release) and `main`
(Publish packages run by hand).

What a release carries, for version `X.Y.Z` (tag `vX.Y.Z`):

- GitHub release assets: `imas-X.Y.Z-linux-{386,amd64,arm,arm64}.tar.gz` and
  `imas-X.Y.Z-darwin-all.tar.gz` (the self-updating CLI, with farmer and
  sprout in the Linux ones),
  `imas-services-X.Y.Z-linux-{amd64,arm64}.tar.gz`,
  `{imas,imas-farmer,imas-sprout}_X.Y.Z_linux_{386,amd64,arm64,armv6}.{apk,deb,rpm}`,
  `imas-sprout-X.Y.Z-windows-x64.msi`, `checksums.txt`, its GPG signature
  `checksums.txt.sig` and its cosign bundle `checksums.txt.sigstore.json`
  (47 files).
- Images: `ghcr.io/yogzblr/imas-{farmer,sprout,saasapi,farmerbus,fleetreleaser,migrate}:X.Y.Z`,
  each a linux/amd64 + linux/arm64 manifest list, cosign-signed; `:latest`
  moves for finals only.
- The keyless cosign signer identity, which `publish-packages.yml` and
  `SECURITY.md` both verify:
  `^https://github\.com/yogzblr/imas/\.github/workflows/release\.yml@refs/tags/v[0-9].*$`
  with issuer `https://token.actions.githubusercontent.com`.

## Steps

1. `main` is green: CI, build, molecule, govulncheck, go-licenses, and
   `packaging/helm/min-sprout-version` states this release's floor (see
   [Compatibility](#compatibility)). It is read from the tagged commit, so
   change it by PR before tagging.
2. Tag the commit on `main`:
   `git tag -a v0.2.0 -m "imas v0.2.0" && git push origin v0.2.0`
   (use `git tag -s` if you sign tags).
3. Actions, **Release**, *Run workflow*, with *Use workflow from* set to the
   **tag** `v0.2.0`, not a branch. The keyless cosign identity includes the
   ref, and the publish step only accepts `refs/tags/v*`. (When the `push:
   tags` trigger in `release.yml` is re-enabled, pushing the tag does this.)
   This builds everything, pushes and cosign-signs the images, and creates a
   **draft** GitHub release with the archives, packages, `checksums.txt`, its
   GPG signature and its `.sigstore.json` bundle.
4. Review the draft (changelog, assets, the six images on GHCR).
5. **Publish the release.** `publish-packages.yml` then verifies the cosign
   signatures, uploads rpm/deb/winget to Buildkite, and last packages and
   uploads the `farmer` and `nats` charts to `imashelm`, with the sprout
   release (version, `min_sprout_version`, packages) stamped into the
   farmer chart. The stamp fails if the floor is above the tag.
6. Run the Terraform UAT gate against that tag (installs the published
   packages with the Ansible role on real hosts).
7. Roll out: `helm upgrade` the farmer chart. Its post-upgrade hook registers
   the sprout release with saasapi; tenants then approve and roll it out in
   waves (API design §1.8).

To re-run a failed publish: Actions, **Publish packages**, *Run workflow*
with the tag. If the rpm, deb and NuGet uploads already succeeded and only the
Helm step failed, tick **only_helm** so those are not uploaded again (Buildkite
rejects a version it already holds).

## First release checklist

For the first tag, `v0.1.0-rc.1`. Nothing below has been run yet; where a
step's result differs from "look for", stop and fix by PR before going on.
`TAG=v0.1.0-rc.1` and `V=0.1.0-rc.1` below.

1. **Settings.** Check every name under [Settings](#settings) exists on the
   repository or the `goreleaser` environment, the four Buildkite registries
   exist (`imasnget` public), and any environment deployment rules allow
   `v*` tags and `main`.
   *Look for:* nothing to fix. A missing name otherwise fails a later step
   with `missing ...`.
2. **The GPG public key.** Commit the public half of the key in
   `GPG_PRIVATE_KEY` to the repository and make `SECURITY.md` match it:
   today it gives fingerprint `3F62 7C68 … E4DD` and links
   `https://raw.githubusercontent.com/yogzblr/imas/master/gpg-public-key.asc`
   (no such file yet, and the branch is `main`).
   *Look for:* `gpg --show-keys <file>` on the committed key prints the
   fingerprint `SECURITY.md` gives, and the link in `SECURITY.md` downloads
   it. An rc can go out before this, but users cannot check its `.sig`
   until then.
3. **Optional pre-flight: Actions, Snapshot Build, Run workflow on `main`.**
   Builds everything the release builds, images included, without signing
   or publishing and without secrets. *Look for:* six images built (amd64
   and arm64), the MSI hook output, `release succeeded`. The GPG secrets and
   cosign signing are first exercised in step 6.
4. **`main` is green on the commit you tag**, including the `go.mod and
   go.sum are tidy` step in CI: the release's before hook fails the release
   on an untidy `go.mod` instead of tidying it. (The `go-licenses` workflow's
   `save` step is a known failure on `main`, `docs/BUILD-STATUS.md` Open
   items 5; it does not affect the release.) Check
   `packaging/helm/min-sprout-version` (`v0.0.0` today, which is fine).
5. **Tag:** `git tag -a v0.1.0-rc.1 -m "imas v0.1.0-rc.1" <commit> && git
   push origin v0.1.0-rc.1`.
   *Look for:* the tag on GitHub, and **no** workflow starting: the `push:
   tags` trigger in `release.yml` is still off.
6. **Actions, Release, Run workflow, Use workflow from: tag
   `v0.1.0-rc.1`.**
   *Look for:* `Check the ref` and `Check release secrets` pass; `Import GPG
   key` prints the fingerprint from step 2; GoReleaser
   logs `using tags ... current=v0.1.0-rc.1` (pinned from the ref through
   `GORELEASER_CURRENT_TAG`), the before hook passes, the
   `sprout-windows-pkg` hook prints the MSI it wrote, `signing` runs for
   `gpg` and `cosign`, the images and `:0.1.0-rc.1` manifests are pushed and
   signed (`docker_signs`), **no** `:latest` manifest is pushed, then 47
   `uploading to release` lines. A run on a branch fails at `Check the ref`.
7. **Check the draft release.** It is a draft and marked pre-release, with
   the 47 assets listed under [Settings](#settings). Download and verify it
   the way `publish-packages.yml` will:

   ```bash
   gh release download "$TAG" --repo yogzblr/imas --dir rc
   cd rc && sha256sum --check --strict checksums.txt
   gpg --verify checksums.txt.sig checksums.txt
   IDENTITY='^https://github\.com/yogzblr/imas/\.github/workflows/release\.yml@refs/tags/v[0-9].*$'
   ISSUER=https://token.actions.githubusercontent.com
   cosign verify-blob --bundle checksums.txt.sigstore.json \
     --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" checksums.txt
   for img in farmer sprout saasapi farmerbus fleetreleaser migrate; do
     cosign verify "ghcr.io/yogzblr/imas-$img:$V" \
       --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null &&
     docker buildx imagetools inspect "ghcr.io/yogzblr/imas-$img:$V" | grep -E 'Platform: +linux/(amd64|arm64)'
   done
   ```

   *Look for:* every line `OK`, `Good signature`, `Verified OK`, and two
   platforms per image. On GHCR, check each new `imas-*` package's
   visibility and its link to the repository: Helm installs pull these
   images, so they must be public unless every cluster has a pull secret.
   A failure here costs nothing yet: delete the draft, fix by PR, and tag
   `v0.1.0-rc.2` (never move a tag).
8. **Publish the draft**, leaving *Set as a pre-release* ticked.
   *Look for:* a **Publish packages** run that is **skipped**: pre-releases
   are not published to Buildkite automatically.
9. **Actions, Publish packages, Run workflow** (from `main`) with tag
   `v0.1.0-rc.1`. This is the deliberate publish of a pre-release.
   *Look for:* `Check publish secrets` passes; `sha256sum --check` prints
   `OK` for every package; the cosign step prints `verified imas-<img>:0.1.0-rc.1`
   six times; one MSI, the winget nupkgs built; rpm and deb uploads to
   `imasrpm` and `imasdeb`, then the NuGet pushes and the anonymous
   installer download check; `stamp-sprout-release.sh` writes
   `sprout-release.json`, `helm lint` passes for both charts, and
   `farmer-0.1.0-rc.1.tgz` and `nats-0.1.0-rc.1.tgz` go up to `imashelm`.
   Buildkite rejects a version it already holds, so if this fails part-way,
   delete what was uploaded for `0.1.0-rc.1` in Buildkite before running it
   again, or fix forward with `v0.1.0-rc.2`.
10. **Install from the registries** on a scratch host: the rpm or deb from
    `imasrpm`/`imasdeb` (package version `0.1.0~rc.1+git`, which sorts
    before the final's `0.1.0+git`), and the
    chart with an explicit `--version 0.1.0-rc.1` (Helm skips pre-release
    charts without it, or `--devel`).
    *Look for:* the packages install and the services start; the farmer
    chart's `files/sprout-release.json` names `v0.1.0-rc.1`. Then run the
    Terraform UAT gate against this tag (step 6 of [Steps](#steps)).
11. **After it went through:** re-enable the `push: tags` trigger in
    `release.yml` by PR, record the run in `docs/BUILD-STATUS.md`, and
    release `v0.1.0` the same way. It can be tagged on the rc's commit:
    the version comes from the tag the run is on, not the first tag at
    that commit. The final MSI has the same ProductVersion (`0.1.0`) as the
    rc's, which the MSI upgrades in place (`AllowSameVersionUpgrades`).

## Hotfixes

Branch from the tag (`release/0.2.x`), fix, merge via PR, tag `v0.2.1` on
that branch and release from the tag as above. Forward-merge the fix to
`main`.

## Compatibility

Each release states `min_sprout_version`, the oldest sprout that can be
updated directly to it, in `packaging/helm/min-sprout-version`: one
canonical `vX.Y.Z[-PRERELEASE]` line, at most the tag by semver precedence
(so not `v1.0.0` for `v1.0.0-rc.1`). Raise it in the PR that makes older
sprouts unable to take the release directly. It is signed into every
manifest and can't change once the version is registered (re-registering
with another floor is a 409). A sprout older than that refuses the manifest
and must step through an intermediate release first. A sprout never installs a
version lower than the one it runs. Database
migrations are forward-only and compatible with one prior version, so
`helm rollback` is safe for the farmer; it does not unregister a sprout
release. To pull a bad sprout version, revoke it:
`POST /v1/operator/fleet-releases/{version}/revoke`.
