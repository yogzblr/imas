# SOP: cut a release

The short, ordered procedure. The reasons, the full "look for" lists and the
failure handling are in [RELEASING.md](RELEASING.md); this page is what you
follow on the day. Examples use `TAG=v0.1.0-rc.N` and `V=0.1.0-rc.N`; for a
final release use `v0.1.0`.

**Who:** the repository owner (the `goreleaser` environment's required
reviewer). **When:** `main` has the changes you want to ship and is green.
**Rule that never bends:** a tag never moves. A bad release is fixed forward
with the next number.

## 0. One-time setup (skip once done)

| Item | Where | Check |
|---|---|---|
| Release GPG public key in the repo | `gpg-public-key.asc` (fingerprint `84F4 5E90 19CF D4B2 3D38 142B CCEB CDB6 41F0 41EB`) | `gpg --show-keys gpg-public-key.asc` prints that fingerprint; `SECURITY.md` shows the same |
| Matching private key and passphrase | `goreleaser` environment secrets `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` (environment only, no repository copy) | the Release run's *Import GPG key* step prints the same fingerprint |
| Buildkite | secret `BUILDKITE_PACKAGES_TOKEN`, variable `BUILDKITE_ORGANIZATION_SLUG`; registries `imasrpm`, `imasdeb`, `imasnget` (public) | *Check publish secrets* passes |
| Environment rules | `goreleaser` environment: you as required reviewer; deployment rules allow `v*` tags | Release run stops at "Waiting for review" |
| GHCR packages | `charts/farmer`, `charts/nats` and the five `imas-*` images: **public** and linked to `yogzblr/imas` (Write role for the repo under *Manage Actions access*) | see step 8 |

## 1. Before tagging

1. `main` is green on the commit you will tag: CI, build, molecule,
   govulncheck, go-licenses, and *go.mod and go.sum are tidy*.
2. `packaging/helm/min-sprout-version` states this release's floor (at most
   the tag). Change it by PR first if needed.
3. Optional pre-flight: Actions, **Snapshot Build**, run on `main`. It builds
   everything without signing or publishing and needs no secrets.
4. Pick the number: `git tag --list 'v0.1.0-rc.*' --sort=-v:refname | head -1`,
   then add one.

## 2. Tag

```sh
git fetch origin && git checkout main && git pull
git tag -a "$TAG" -m "imas $TAG" <commit-on-main>
git push origin "$TAG"
```

Pushing a `v*` tag starts **Release** by itself.

## 3. Approve and watch the Release run

Open the run, *Review deployments*, approve. Look for:

- *Check the ref* and *Check release secrets* pass; *Check the tag has not
  moved* passes.
- *Check the fleet signing keyring* passes (fails if `gpg-public-key.asc`
  holds no key).
- GoReleaser signs `checksums.txt` (GPG and cosign), pushes and signs the
  five images, uploads the assets to a **draft** release.
- *Verify checksums.txt.sig against the packaged keyring* passes.

If any of these fail: do **not** publish. Delete the draft (not the tag), fix
by PR, and cut the next number.

## 4. Verify the draft

From the repository root (needs `gh`, `cosign`, `gpg`, `docker buildx`):

```sh
IDENTITY="$(packaging/release/cosign-identity.sh release.yml "$TAG")"
ISSUER="$(packaging/release/cosign-identity.sh --issuer)"
gh release download "$TAG" --repo yogzblr/imas --dir rc
(cd rc && sha256sum --check --strict checksums.txt \
  && gpg --verify checksums.txt.sig checksums.txt \
  && cosign verify-blob --bundle checksums.txt.sigstore.json \
       --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" checksums.txt)
for img in farmer sprout saasapi farmerbus migrate; do
  cosign verify "ghcr.io/yogzblr/imas-$img:$V" \
    --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" >/dev/null &&
  docker buildx imagetools inspect "ghcr.io/yogzblr/imas-$img:$V" | grep -E 'Platform: +linux/(amd64|arm64)'
done
```

Expect every check OK, two platforms per image, and 47 assets on the draft
(see RELEASING.md for the list). Check each new `imas-*` image package is
public and linked.

## 5. Publish the draft

Publish it with *Set as a pre-release* ticked for any `-rc.N`. A
**Publish packages** run for a pre-release is skipped by design.

## 6. Publish packages and charts

Actions, **Publish packages**, *Run workflow*, *Use workflow from* = the
**tag**, input tag = `$TAG`. Approve the environment. Look for:

- `sha256sum --check` OK for every package; cosign verified for the five
  images; the MSI and winget packages built.
- rpm and deb uploaded to `imasrpm` and `imasdeb`; NuGet pushed and the
  anonymous download check passes.
- `sprout-release.json` stamped (version, `min_sprout_version`, signature
  verified); `helm lint` passes; `farmer` and `nats` charts pushed to
  `oci://ghcr.io/yogzblr/charts` and signed.

If the upload fails part-way, Buildkite rejects a version it already holds:
delete what was uploaded for that version before a re-run, or fix forward.

## 7. Owner step on the first push of each chart (once per chart package)

The workflow's token cannot change package visibility, so *Check the charts
are public and linked* fails until you do this:

1. GitHub, *Packages*, `charts/farmer` (then `charts/nats`), *Package
   settings*, *Change visibility*, **Public**.
2. Same page: connect repository `yogzblr/imas` and give it **Write** under
   *Manage Actions access*.
3. Re-run **Publish packages** from the tag with **only_helm** ticked.

## 8. Verify the charts

```sh
helm pull oci://ghcr.io/yogzblr/charts/farmer --version "$V" --destination /tmp/chk
packaging/helm/ghcr-chart.sh digest farmer "$V"
cosign verify "ghcr.io/yogzblr/charts/farmer@sha256:<digest>" \
  --certificate-identity "$(packaging/release/cosign-identity.sh publish-packages.yml "$TAG")" \
  --certificate-oidc-issuer "$(packaging/release/cosign-identity.sh --issuer)"
```

An anonymous `helm pull` (no login) must work for both charts.

## 9. Prove it installs

On the local rig (Docker, WSL2 or Linux), from the repository root:

```sh
uat/lite/run.sh --release-tag "$TAG" smoke
uat/lite/run.sh core
```

It installs the published charts and the real deb/rpm of that tag, so it is
the end-to-end check of steps 4 to 8. Then the Azure runs (`uat/RUNBOOK.md`),
Run 2 and Run 3, with the same tag.

## 10. Record

- Add a status fragment (`docs/status/days/YYYY-MM-DD/release-$TAG.md`) with
  the tag, commit, and the Release and Publish run links.
- For staging or production: dispatch and self-update flags stay off until the
  OpenBao runbook launch gates are done, a release is signed end to end
  (this procedure, green) and a UAT run exercised the update path
  (`docs/security-review-2026-10.md` P3 record).

## If something is wrong after publishing

- Never move or delete-and-recreate the tag.
- Cut the next number from a fixed `main` (or from a `release/X.Y.x` branch
  for a hotfix) and follow this page again.
- Withdraw a bad sprout release so no fleet installs it:
  `POST /v1/operator/fleet-releases/{version}/revoke` (operator token).
- Key rotation: `packaging/etc/fleet-signing-keys.md`, "Rotating the release
  key". Do it by PR, reviewed as a trust-root change.

## Quick reference

| Question | Answer |
|---|---|
| Release run fails at the keyring | `gpg-public-key.asc` empty or wrong: fix by PR, next tag |
| Publish fails at chart public/linked check | step 7, then **only_helm** |
| Cosign verify fails for an old chart | charts of `v0.1.0-rc.13` and earlier were signed from `main`; the tag identity holds after |
| Draft has wrong assets | delete the draft, next tag |
| Need a final from an rc | tag the rc's commit as `v0.1.0`; the version comes from the tag |
