# Farmer: sprout update manifest

`GET /v1/sprout/update-manifest?os=&arch=&package_type=&version=` — served by farmer on
the same HTTPS listener as the sprout recipe download (`GET /files/`),
registered in [`internal/api/routers.go`](../../internal/api/routers.go),
handled by `GetSproutUpdateManifest` in
[`internal/api/handlers/update_manifest.go`](../../internal/api/handlers/update_manifest.go).
Design: [API design §2.6](../design/imas-machine-manager-api-design.md#26-update-manifest-endpoint),
with the release trust in §2.5 and the
[signing design](../design/imas-openbao-signing-design.md) §4.1 (D9, D20).

A sprout calls it to learn what to install for a `self_update`: the
manifest of the sprout version **its own tenant has approved**, for its OS,
architecture and package type, carrying that release's `checksums.txt` and
its GPG signature. Neither the package's location nor its file name is in
the response: the sprout verifies `checksums_sig` against the keyring
shipped in its package (`/etc/imas/fleet-signing-keys.asc`), derives its
package file name itself, takes that file's hash from `checksums_txt`,
downloads it from the repository configured in the sprout (requirement 20,
§1.8) and checks its SHA-256. Farmer verifies no signature; the sprout is
the only verifier. FU.2 is that client side
(`internal/ingredients/selfupdate`).

## Authentication

`Authorization: Bearer <gateway JWT>` — the sprout's gateway JWT
(`internal/gatewayjwt`), the same token it presents for `GET /files/`.
Farmer verifies it itself (`sproutIdentityAuth` in
[`internal/api/middleware.go`](../../internal/api/middleware.go)), even
behind Envoy, because farmer's API port is reachable without Envoy.

- The tenant and sprout are the token's `tenant_id` and `sprout_id`
  claims. There is no tenant parameter; any query parameter other than
  `os`, `arch`, `package_type` and `version` is ignored.
- No CLI credential is accepted (the CLI's bearer token is gone, J.3), and
  there is no development bypass: `dangerously_allow_root` was removed and
  farmer ignores it. Without a verified JWT there is no tenant to answer
  for.

| Request | Status |
|---|---|
| No `Authorization`, or not `Bearer …` | 401, empty body |
| Bearer token that fails verification (bad signature, untrusted key, expired, wrong issuer), or whose `tenant_id`/`sprout_id` is empty or contains `/`, `\`, NUL, or is `.`/`..` | 403, empty body |
| No gateway signer configured on this farmer | 403 |

## Request

| Parameter | Rule |
|---|---|
| `os` | required, exactly once, lowercase `[a-z0-9_]`, starting with a letter or digit, at most 32 characters (e.g. `linux`, `windows`) |
| `arch` | same rules as `os` (e.g. `amd64`, `arm64`) |
| `package_type` | required, exactly once, `deb`, `rpm` or `msi`: the installer the sprout uses. One linux/amd64 binary ships as both a `.deb` and an `.rpm`, registered as two rows. The sprout derives its file name from it and finds that name in the signed `checksums.txt` |
| `version` | required, exactly once, canonical semver with a leading `v` and no build metadata, at most 64 characters (e.g. `v2.4.1`, `v2.5.0-rc.1`) |

These are `fleetsign.Manifest.Validate`'s rules, so a value that could never
name a row is refused before any lookup.

## Response

**200** — `Content-Type: application/json`, `Cache-Control: no-store`.
Exactly these seven string keys of `fleetsign.Manifest`, nothing else: no
URL, no file name, no checksum, no per-row signature:

```json
{
  "version": "v2.4.1",
  "os": "linux",
  "arch": "amd64",
  "package_type": "deb",
  "min_sprout_version": "v2.0.0",
  "checksums_txt": "<checksums.txt, as a UTF-8 string>",
  "checksums_sig": "<base64 of checksums.txt.sig>"
}
```

`fleetsign.ParseManifest` accepts this body as is (it refuses unknown,
missing or duplicate keys). The GPG signature covers `checksums.txt` only;
`min_sprout_version` is unsigned farmer policy, enforced by the sprout.
The sprout's file name is `imas-sprout_<version without v>_linux_<arch>.<deb|rpm>`
or `imas-sprout-<version without v>-windows-<x64|x86|arch>.msi`.

A row is served only when all of these hold:

1. `saas.tenant_update_policy.approved_version` for the caller's tenant is
   `version`;
2. `saas.fleet_versions` has a row for (`version`, `os`, `arch`) that is
   not `revoked`;
3. `saas.fleet_release_checksums` has the version's `checksums.txt` and
   signature (an inner join: a version registered without them is never
   served);
4. the result passes `fleetsign.Manifest.Validate` and matches the request.

No signature is verified here (signing design D20). Conditions 1 to 3 are
one SQL statement with `tenant_id` in the same
`WHERE` as the caller's values (§4 "Tenant safety"), read through
farmer's existing read-only grant on `saas`.

## Errors

Bodies are `{"error": "<code>"}`, with `Cache-Control: no-store`.

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request` | a parameter is missing, repeated or malformed |
| 404 | `not_found` | **any** reason the manifest isn't served: version not approved by this tenant (approved by another, or none), revoked, unknown, no row for this OS or arch, no checksums row, no policy row, or a stored row that fails validation |
| 429 | `rate_limited` | the sprout's rate limit is spent; `Retry-After` gives seconds |
| 503 | `manifest_unavailable` | PXC read failed, or no store is configured |

The 404 is deliberately one response, byte for byte, for every reason, so
the endpoint reveals neither which versions exist nor what another tenant
approved (the same reasoning as §3.4 for enrollment). The reason is logged
on farmer, never returned.

## Rate limit and caching

Both are in farmer's memory, per replica.

- **Rate limit:** per sprout, keyed on (`tenant_id`, `sprout_id`) —
  `sprout_id` is unique per tenant only, so `web-01` in one tenant never
  spends `web-01`'s budget in another. A burst of 5, then one request per
  12 seconds. Every authenticated request counts, malformed ones
  included. Buckets idle for 10 minutes are dropped.
- **Cache:** the answer for (`tenant_id`, `os`, `arch`, `version`), so a
  rollout wave of many sprouts in one tenant costs one PXC read per
  replica rather than one per sprout. A served manifest is cached for 30
  seconds and a 404 for 10 seconds; failures (503) are not cached. So an
  approval change or a revoke reaches every replica within 30 seconds.
  Never shared between tenants. Bounded at 4096 entries.

## Deployment notes

- **Envoy:** `deploy/envoy/envoy.yaml` routes only `/v1/enroll`,
  `/v1/refresh` and `/files/` to farmer; any other path, this one
  included, falls through to the NATS websocket cluster. Sprouts that
  reach farmer through Envoy need a `/v1/sprout/update-manifest` route to
  `recipe_service`, gated by `sprout_jwt` like `/files/`. Not part of this
  change.
- **Wiring:** the PXC handle comes from `handlers.SetReadinessDB`, which
  `cmd/farmer` already calls with farmer's handle at startup. Without it
  the endpoint answers 503. Farmer reads no fleet signing key.
