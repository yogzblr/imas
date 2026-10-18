# Releasing imas

> **Status (2026-10-05): the flow has been run to the end.** `v0.1.0-rc.1`
> to `-rc.3` failed or shipped broken packages and stay as they are (a tag
> never moves). **`v0.1.0-rc.3`'s deb, rpm and apk packages are broken** (a
> versioned binary name the units don't match, and no config, signing keys
> or state directories): do not install them. **`v0.1.0-rc.4` is the first
> usable pre-release**: its packages passed `packaging/check-package-contents.sh`,
> installed from the `imasdeb` registry on Ubuntu (WSL2) and the service
> started. The `imas-sprout` MSI, the rpm and apk installs and enrolment
> against a backend have not been tried. Keep following the
> [First release checklist](#first-release-checklist) for the next tag. The
> secrets and variable it needs are listed under
> [Settings](#settings). Use a pre-release tag such as `v0.1.0-rc.5` for
> anything that is not final.
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
  registries reject a package version they already hold, GHCR would let a
  chart tag be pushed again (and so moved), and
  signatures are bound to the tag. The workflows refuse it too:
  `release.yml` fails when the tag already has a release built from another
  commit, and `publish-packages.yml` never pushes a chart version GHCR
  already holds (see [A tag never moves](#a-tag-never-moves)). A bad release
  is fixed forward with the next pre-release or patch, and withdrawn with the
  revoke call (below).
- The tag is the only source of the version. Everything derives from it,
  with the leading `v` dropped except where noted:

  | Artifact | Version |
  |---|---|
  | Binaries / `-X main.Tag` | `vX.Y.Z` |
  | rpm, deb, apk, MSI, winget | `X.Y.Z` |
  | Images `ghcr.io/yogzblr/imas-*` | `X.Y.Z` (and `latest` for finals) |
  | Helm charts `farmer`, `nats` (OCI, `oci://ghcr.io/yogzblr/charts/<chart>`) | chart `version` and `appVersion` = `X.Y.Z`, which is also the OCI tag |

## Settings

`release.yml` and `publish-packages.yml` run in the GitHub environment
**`goreleaser`**. **Policy (owner, 2026-10-11): the secrets below, above all
`GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, live only on the `goreleaser`
environment, never at repository level.** A repository secret is readable by
any workflow someone with write access adds on a branch, and it skips the
reviewer gate. The sprouts trust this key for updates (BUILD-STATUS P22), so
move them to the environment and delete the repository copies. Variables may
stay where they are. `snapshot.yml` needs none of them: it
neither signs (`--skip=sign`) nor publishes.

| Name | Kind | Used by |
|---|---|---|
| `GPG_PRIVATE_KEY` | secret | `release.yml` (signs `checksums.txt`) |
| `GPG_PASSPHRASE` | secret | `release.yml` |
| `BUILDKITE_PACKAGES_TOKEN` | secret | `publish-packages.yml`; Buildkite API token with Read Packages and Write Packages |
| `BUILDKITE_ORGANIZATION_SLUG` | variable | `publish-packages.yml`; the org owning the registries below |

Each workflow checks its own names first and fails naming any that are
missing (with **only_helm** the Buildkite names are not required: the charts
go to GHCR with the run's `GITHUB_TOKEN`). The Buildkite organisation needs
three registries: `imasrpm` (Red Hat), `imasdeb` (Debian) and `imasnget`
(NuGet, **public**: winget downloads the MSI from it anonymously). The Helm
charts no longer go to Buildkite: the `imashelm` registry (a standard Helm
registry that has returned HTTP 500 for its `index.yaml` for hours, so
nothing could `helm pull` from it) is **superseded for charts** and left as
it is; `packaging/buildkite/publish-helm.sh` is removed. The charts go to
GHCR; see [Helm charts on GHCR](#helm-charts-on-ghcr). If the `goreleaser`
environment has deployment branch or tag rules, they must allow `v*` tags:
Release and Publish packages run only on a tag ref (a published release,
or a run by hand with *Use workflow from* set to the tag).

**Reviewer handover.** The environment's required reviewer is the owner today (one maintainer, Prevent self-review off). When a second maintainer joins, add them as a reviewer and turn Prevent self-review on, so a person other than the one who pushed the tag approves the release. The key needs no change for that: it is held by the environment, not by a person.

**Manual gate (set 2026-10-05).** The `goreleaser` environment has the
repository owner as a **required reviewer**, with **Prevent self-review**
off (there is one maintainer) and deployment rules allowing the tag pattern
`v*` (the branch `main` may stay allowed; neither workflow runs on it any
more). Both workflows run in this environment, so every
Release run (a pushed `v*` tag, a release created in the GitHub UI, or a
manual dispatch) and every Publish packages run stops at "Waiting for
review" before any job step runs; approve it under **Review deployments**,
or reject it, which costs nothing (no images pushed, no draft created). If
you rebuild the repository settings, set this again: it is not in the repo.

What a release carries, for version `X.Y.Z` (tag `vX.Y.Z`):

- GitHub release assets: `imas-X.Y.Z-linux-{386,amd64,arm,arm64}.tar.gz` and
  `imas-X.Y.Z-darwin-all.tar.gz` (the self-updating CLI, with farmer and
  sprout in the Linux ones),
  `imas-services-X.Y.Z-linux-{amd64,arm64}.tar.gz`,
  `{imas,imas-farmer,imas-sprout}_X.Y.Z_linux_{386,amd64,arm64,armv6}.{apk,deb,rpm}`,
  `imas-sprout-X.Y.Z-windows-x64.msi`, `checksums.txt`, its GPG signature
  `checksums.txt.sig` and its cosign bundle `checksums.txt.sigstore.json`
  (47 files).
- Images: `ghcr.io/yogzblr/imas-{farmer,sprout,saasapi,farmerbus,migrate}:X.Y.Z`,
  each a linux/amd64 + linux/arm64 manifest list, cosign-signed; `:latest`
  moves for finals only.
- The keyless cosign signer identities, exact strings and never a pattern,
  pinned to the workflow and the release's own tag ref. For tag `vX.Y.Z`:
  - `checksums.txt` and the images:
    `https://github.com/yogzblr/imas/.github/workflows/release.yml@refs/tags/vX.Y.Z`
  - the Helm charts:
    `https://github.com/yogzblr/imas/.github/workflows/publish-packages.yml@refs/tags/vX.Y.Z`

  with issuer `https://token.actions.githubusercontent.com`.
  `packaging/release/cosign-identity.sh <release.yml|publish-packages.yml> vX.Y.Z`
  prints the identity (and `--issuer` the issuer); `publish-packages.yml`
  passes it to `--certificate-identity`, and so do the commands here and in
  `SECURITY.md`. A signature made by a branch run, by another workflow or
  under another tag does not verify.

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
   GPG signature and its `.sigstore.json` bundle. Two steps gate the sprout's
   update trust root (see [Fleet signing keyring](#fleet-signing-keyring)):
   *Check the fleet signing keyring* fails the run before anything is built
   if `gpg-public-key.asc` holds no release key, and *Verify
   checksums.txt.sig against the packaged keyring* fails it afterwards if the
   release's signature does not verify against that keyring the way a sprout
   verifies it. A run that failed either step leaves a draft that must not
   be published: delete it, fix the keyring by PR, tag again.
4. Review the draft (changelog, assets, the five images on GHCR) and that
   the Release run is green, both keyring steps included.
5. **Publish the release.** `publish-packages.yml` then verifies the cosign
   signatures and `checksums.txt.sig` (with `gpg`, against the repo's
   `gpg-public-key.asc`, before `sha256sum --check`), uploads rpm/deb/winget
   to Buildkite, and last packages the
   `farmer` and `nats` charts, pushes them to GHCR as OCI charts and signs
   them (see [Helm charts on GHCR](#helm-charts-on-ghcr)), then checks
   anonymously that each chart can be pulled and its package is linked to
   this repository, with the sprout
   release (version, `min_sprout_version`, packages, and `checksums.txt`
   with its signature, which the stamp verifies with `gpg` against
   `gpg-public-key.asc` and the sprout verifies again before an update)
   stamped into the farmer chart. The stamp fails if the floor is above the
   tag or the signature doesn't verify.
6. Run the Terraform UAT gate against that tag (installs the published
   packages with the Ansible role on real hosts).
7. Roll out: `helm upgrade` the farmer chart. Its post-upgrade hook registers
   the sprout release with saasapi; tenants then approve and roll it out in
   waves (API design §1.8).

To re-run a failed publish: Actions, **Publish packages**, *Run workflow*,
with *Use workflow from* set to the **tag** and the same tag as input (a run
from a branch fails at *Check publish secrets*: the charts are signed with
the identity of this workflow at `refs/tags/<tag>`). If the rpm, deb and NuGet uploads already succeeded and only the
Helm step failed, tick **only_helm** so those are not uploaded again (Buildkite
rejects a version it already holds). **only_helm** keeps its meaning: it skips
the rpm, deb, NuGet and winget uploads and publishes only the charts, now to
GHCR. A chart version already on GHCR and signed by this tag's run is not
pushed again; one that is there unsigned, or signed by anything else, fails
the run (fix forward with the next tag).

## Fleet signing keyring

Every sprout package installs the repo's `gpg-public-key.asc` as its update
trust root, `/etc/imas/fleet-signing-keys.asc` (mode 0600, root's; on
Windows `%ProgramData%\imas\fleet-signing-keys.asc`), and a sprout installs
an update only if the release's `checksums.txt.sig` verifies against it
(`packaging/etc/fleet-signing-keys.md`). A package with an empty keyring
would leave its fleet unable to self-update until every host is reinstalled
(security review L5), so a release may not ship one. The development tree
may hold an empty placeholder (`{}`, or no key) until the key is added
(owner decision T1, 2026-10-17); the release is what refuses it.

**Owner step, once, before the first release that self-updates: put the
release GPG public key in the file.** Export the public half of the key in
the `goreleaser` environment's `GPG_PRIVATE_KEY`:

```sh
gpg --armor --export <fingerprint> > gpg-public-key.asc
gpg --show-keys gpg-public-key.asc      # the fingerprint SECURITY.md gives
go test ./packaging/test                # parses as the sprout parses it
IMAS_RELEASE=1 go test -run TestPackagedKeyring ./packaging/test   # holds a key
```

and commit it by PR, reviewed like any trust-root change. Key rotation
follows `packaging/etc/fleet-signing-keys.md` ("Rotating the release key").

The Release workflow runs the same checks with the sprout's own code
(`internal/fleetsign`, through `packaging/test`):

| Step | Command | Fails when |
|---|---|---|
| Check the fleet signing keyring (before the build) | `IMAS_RELEASE=1 go test -run 'TestPackagedKeyring\|TestPackagingInstallsTheKeyring' ./packaging/test` | the keyring holds no key that can sign, does not parse, or a package does not install it mode 0600 |
| Verify checksums.txt.sig against the packaged keyring (after GoReleaser) | `IMAS_RELEASE_DIST=dist go test -run TestReleaseChecksums ./packaging/test` | `dist/checksums.txt.sig` does not verify over `dist/checksums.txt` against the keyring as a sprout verifies it, or `checksums.txt` does not parse as a sprout parses it |

To check a published release by hand, download its `checksums.txt` and
`checksums.txt.sig` into a directory and run the second command with
`IMAS_RELEASE_DIST` set to that directory.

## Helm charts on GHCR

Since UAT.10 the charts are OCI charts on GitHub Container Registry, not in
the Buildkite `imashelm` registry:

- `oci://ghcr.io/yogzblr/charts/farmer` and `oci://ghcr.io/yogzblr/charts/nats`,
  at the release version without the `v` (`0.1.0-rc.5` for `v0.1.0-rc.5`).
  `helm push` takes name and version from the package, and a pre-release
  version is an ordinary OCI tag (only `+` would be rewritten, to `_`).
- `publish-packages.yml` logs in with `helm registry login ghcr.io` (the
  run's `GITHUB_TOKEN`, password on stdin), pushes each packaged chart, and
  signs each by digest with keyless cosign (the same installation and OIDC
  issuer as the images). Only that job has `packages: write` and
  `id-token: write`. Prereleases are still published only by hand
  (`workflow_dispatch`).
- **Consumers pull anonymously, by exact version**:
  `helm pull oci://ghcr.io/yogzblr/charts/farmer --version 0.1.0-rc.5
  --destination DIR`. No `helm login`, no `--devel`, no range. `uat/hub/core`
  reads the base from `IMAS_HELM_OCI_BASE` and `uat/hub/dmz` from
  `--chart-registry OCI_BASE`, both defaulting to
  `oci://ghcr.io/yogzblr/charts`. They replace `IMAS_HELM_REPO_URL` and
  `--chart-repo-url`, which were removed rather than kept as a second way.
- **The workflow checks what consumers get.** After the push, *Check the
  charts are public and linked to the repository* runs
  `packaging/helm/ghcr-chart.sh check <chart> <version> <digest>` for each
  chart with no credential at all: it pulls the chart anonymously (registry
  token, manifest, chart layer) and requires the digest that was pushed and
  signed, requires the manifest's `org.opencontainers.image.source` to be
  `https://github.com/yogzblr/imas` (from `Chart.yaml` `sources`), and
  requires the package's page under this repository,
  `https://github.com/yogzblr/imas/pkgs/container/charts%2F<chart>`, which
  GitHub serves only for a package linked to it. It fails the run, saying
  what to do, while either is not so. The run's `GITHUB_TOKEN` cannot change
  a package's visibility or link (owner decision V2), so that is this owner
  step:
- **Owner, once per chart package, after its first push** (every release's
  notes repeat this step and the signer identities: `.goreleaser.yaml`
  `release.footer`): a package pushed
  by a workflow is **private**, and the check above fails until:
  1. *Public:* on GitHub, *Packages*, `charts/farmer` (then `charts/nats`),
     *Package settings*
     (`https://github.com/users/yogzblr/packages/container/charts%2Ffarmer/settings`),
     *Danger Zone*, *Change visibility*, **Public**. Until then an anonymous
     `helm pull` fails and the UAT install scripts say the chart package may
     still be private.
  2. *Linked:* on the same page, *Connect repository*, `yogzblr/imas` (a
     package first pushed by this workflow is usually linked already), and
     under *Manage Actions access* give `yogzblr/imas` the **Write** role, so
     later pushes by the workflow's `GITHUB_TOKEN` are accepted.
  3. Run **Publish packages** again from the tag with **only_helm**: the
     charts already pushed and signed by this tag's run are not pushed again,
     and the check passes. To check by hand, with the digest from the run's
     log: `packaging/helm/ghcr-chart.sh check farmer X.Y.Z sha256:<digest>`.
- **Verify a signature**, with the identity pinned to `publish-packages.yml`
  at the release's tag (the workflow runs on no other ref):

  ```sh
  cosign verify ghcr.io/yogzblr/charts/farmer@sha256:<digest> \
    --certificate-identity "$(packaging/release/cosign-identity.sh publish-packages.yml vX.Y.Z)" \
    --certificate-oidc-issuer "$(packaging/release/cosign-identity.sh --issuer)"
  ```

  that is, `--certificate-identity
  https://github.com/yogzblr/imas/.github/workflows/publish-packages.yml@refs/tags/vX.Y.Z`.
  The digest is in the publish run's log (`pushed and signed ...`), or
  `packaging/helm/ghcr-chart.sh digest farmer X.Y.Z`. Charts of `v0.1.0-rc.13`
  and earlier were signed by runs from `main`
  (`publish-packages.yml@refs/heads/main`) and do not verify with a tag
  identity; the pinned identity holds from the first release after it.
- GHCR does not reject a tag that exists: pushing again moves it. The
  workflow never pushes a version GHCR already holds; never push one by
  hand either. Fix forward with the next tag.

## A tag never moves

A release, its signatures and every sprout that trusts them are bound to
the commit its tag named when it was built. Moving the tag (`git tag -f`,
`git push --force`) would make a second Release run rebuild the same
version from other code. So `release.yml` refuses it: *Check the tag has not
moved* (`packaging/release/check-release-tag.sh`) looks up the tag's
release, drafts included, before anything is built, and fails when

- the release records another commit (GoReleaser writes the commit it built
  from into the release's `target_commitish`, `.goreleaser.yaml`), or
- the release records no commit (made before this check, or in the GitHub
  UI) but already has assets, so what it was built from cannot be checked.

A re-run on the same commit, and a release made in the GitHub UI that has
no assets yet, pass. If the check fails because the tag was moved by
mistake, put it back (`git push --force origin <commit>:refs/tags/vX.Y.Z`,
the commit the message names) and stop there. Otherwise, **cut a new
pre-release instead of moving the tag**:

1. Fix on `main` by PR (or on the release branch, see [Hotfixes](#hotfixes)).
2. Take the next number: if `v0.1.0-rc.14` is out, the next is
   `v0.1.0-rc.15` (`git tag --list 'v0.1.0-rc.*' --sort=-v:refname | head -1`
   shows the last one). For a final that was already released, the next
   patch, `v0.1.1`.
3. `git tag -a v0.1.0-rc.15 -m "imas v0.1.0-rc.15" <commit> && git push origin v0.1.0-rc.15`,
   and follow [Steps](#steps) from step 3.
4. Leave the old tag and its release as they are. If the old release is a
   draft that must not be published, delete the draft (not the tag). If it
   was published and is bad, withdraw its sprout release with the revoke
   call ([Compatibility](#compatibility)).

## First release checklist

For the first tag, `v0.1.0-rc.1`. Nothing below has been run yet; where a
step's result differs from "look for", stop and fix by PR before going on.
`TAG=v0.1.0-rc.1` and `V=0.1.0-rc.1` below.

1. **Settings.** Check every name under [Settings](#settings) exists where
   that section says (the GPG secrets on the `goreleaser` environment only,
   no repository copy), the three Buildkite registries
   exist (`imasnget` public), and any environment deployment rules allow
   `v*` tags and `main`.
   *Look for:* nothing to fix. A missing name otherwise fails a later step
   with `missing ...`.
2. **The GPG public key.** Commit the public half of the key in
   `GPG_PRIVATE_KEY` to the repository and make `SECURITY.md` match it:
   the committed key gives fingerprint
   `84F4 5E90 19CF D4B2 3D38 142B CCEB CDB6 41F0 41EB`, the same file every
   sprout package installs as `/etc/imas/fleet-signing-keys.asc` and that
   `publish-packages.yml` and `stamp-sprout-release.sh` verify
   `checksums.txt.sig` against, and its link is
   `https://raw.githubusercontent.com/yogzblr/imas/main/gpg-public-key.asc`.
   *Look for:* `gpg --show-keys <file>` on the committed key prints the
   fingerprint `SECURITY.md` gives, and the link in `SECURITY.md` downloads
   it. An rc can go out before this, but users cannot check its `.sig`
   until then.
3. **Optional pre-flight: Actions, Snapshot Build, Run workflow on `main`.**
   Builds everything the release builds, images included, without signing
   or publishing and without secrets. *Look for:* five images built (amd64
   and arm64), the MSI hook output, `release succeeded`. The GPG secrets and
   cosign signing are first exercised in step 6.
4. **`main` is green on the commit you tag**, including the `go.mod and
   go.sum are tidy` step in CI: the release's before hook fails the release
   on an untidy `go.mod` instead of tidying it. The `go-licenses` workflow
   (check and save) must be green too. Check
   `packaging/helm/min-sprout-version` (`v0.0.0` today, which is fine).
5. **Tag:** `git tag -a v0.1.0-rc.1 -m "imas v0.1.0-rc.1" <commit> && git
   push origin v0.1.0-rc.1`.
   *Look for:* the tag on GitHub and a **Release** run starting by itself
   (the `push: tags` trigger has been on since `v0.1.0-rc.4`, see step 11).
6. **Approve the Release run.** Its job uses the `goreleaser` environment, so
   it waits for approval: open the run, *Review deployments*, approve. (To
   run it by hand instead: Actions, Release, Run workflow, Use workflow from:
   tag `v0.1.0-rc.1`.)
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
   the way `publish-packages.yml` will (from the repository root):

   ```bash
   IDENTITY="$(packaging/release/cosign-identity.sh release.yml "$TAG")"
   ISSUER="$(packaging/release/cosign-identity.sh --issuer)"
   gh release download "$TAG" --repo yogzblr/imas --dir rc
   cd rc && sha256sum --check --strict checksums.txt
   gpg --verify checksums.txt.sig checksums.txt
   cosign verify-blob --bundle checksums.txt.sigstore.json \
     --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" checksums.txt
   for img in farmer sprout saasapi farmerbus migrate; do
     cosign verify "ghcr.io/yogzblr/imas-$img:$V" \
       --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null &&
     docker buildx imagetools inspect "ghcr.io/yogzblr/imas-$img:$V" | grep -E 'Platform: +linux/(amd64|arm64)'
   done
   ```

   *Look for:* every line `OK`, `Good signature`, `Verified OK`, and two
   platforms per image. On GHCR, check each new `imas-*` package's
   visibility and its link to the repository: Helm installs pull these
   images, so they must be public unless every cluster has a pull secret.
   A failure here costs nothing yet: delete the draft, fix by PR, and tag
   `v0.1.0-rc.2` (never move a tag: [A tag never moves](#a-tag-never-moves)).
8. **Publish the draft**, leaving *Set as a pre-release* ticked.
   *Look for:* a **Publish packages** run that is **skipped**: pre-releases
   are not published to Buildkite automatically.
9. **Actions, Publish packages, Run workflow**, *Use workflow from* the tag
   `v0.1.0-rc.1`, with tag `v0.1.0-rc.1`. This is the deliberate publish of
   a pre-release. A run from `main` fails at *Check publish secrets*.
   *Look for:* `Check publish secrets` passes; `sha256sum --check` prints
   `OK` for every package; the cosign step prints `verified imas-<img>:0.1.0-rc.1`
   five times; one MSI, the winget nupkgs built; rpm and deb uploads to
   `imasrpm` and `imasdeb`, then the NuGet pushes and the anonymous
   installer download check; `stamp-sprout-release.sh` writes
   `sprout-release.json`, `helm lint` passes for both charts, and
   `farmer-0.1.0-rc.1.tgz` and `nats-0.1.0-rc.1.tgz` are pushed to
   `oci://ghcr.io/yogzblr/charts` and signed (`pushed and signed ...`), and
   *Check the charts are public and linked to the repository* prints
   `pulled ... anonymously` and `... is public and linked to yogzblr/imas`
   for both (it fails until the owner step below is done).
   Buildkite rejects a package version it already holds, so if the rpm/deb
   upload fails part-way, delete what was uploaded for `0.1.0-rc.1` in
   Buildkite before running it again, or fix forward with `v0.1.0-rc.2`. A
   failed chart push can be repeated with **only_helm**. After the first
   push, make each chart package public and check its link once, then run
   again with **only_helm** (see [Helm charts on GHCR](#helm-charts-on-ghcr)).
10. **Install from the registries** on a scratch host: the rpm or deb from
    `imasrpm`/`imasdeb` (package version `0.1.0~rc.1+git`, which sorts
    before the final's `0.1.0+git`), and the
    chart with `helm pull oci://ghcr.io/yogzblr/charts/farmer --version
    0.1.0-rc.1` (an exact version; nothing else selects a pre-release).
    *Look for:* the packages install and the services start; the farmer
    chart's `files/sprout-release.json` names `v0.1.0-rc.1`. Then run the
    Terraform UAT gate against this tag (step 6 of [Steps](#steps)).
11. **After it went through:** the `push: tags` trigger in `release.yml` is
    on since 2026-10-05 (after `v0.1.0-rc.4`), so pushing a `v*` tag, or
    creating a release in the GitHub UI, starts a release run by itself. The
    run is recorded in `docs/BUILD-STATUS.md`. Release `v0.1.0` the same way. It can be tagged on the rc's commit:
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
