# Releasing imas

> **Status (2026-10-03): this flow has never been run.** No tag or release
> exists and neither workflow has had a run. Expect the first real release to
> need fixes. It needs the repo secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`,
> and the Buildkite organisation variable and token
> (see the header comments of `release.yml` and `publish-packages.yml`). Start
> with a pre-release tag such as `v0.1.0-rc.1`. The workflows use GoReleaser
> OSS (MIT), so no GoReleaser licence key is needed; the Windows MSI is built
> by `packaging/windows/build-msi.sh` (msitools' `wixl`) as a build hook
> (brief REL.1). Nothing has installed that MSI on a Windows host yet.

One tag releases everything: the `imas`, `imas-farmer` and `imas-sprout`
binaries and packages, the five container images, and the Helm charts. The
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
4. Review the draft (changelog, assets, the five images on GHCR).
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
with the tag.

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
