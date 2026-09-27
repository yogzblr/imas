# OS packaging

What each release builds, and how it gets to hosts. Everything below is built
by goreleaser (`.goreleaser.yaml`) and published by `.github/workflows/release.yml`.

| Package | Formats | Built by | Published to |
|---|---|---|---|
| `imas`, `imas-farmer`, `imas-sprout` | apk, deb, rpm | `nfpms` | GitHub release (draft); `.deb` → Buildkite `imasdeb`, `.rpm` → Buildkite `imasrpm` |
| `imas-sprout` (Windows) | MSI | `msi` (goreleaser-pro, msitools' wixl) | GitHub release (draft) |
| `imas-sprout` (winget) | winget manifests in a `.nupkg` | `packaging/windows/winget/build-winget-nupkg.sh`, in the release workflow | Buildkite `imasnget` (NuGet) |

## Windows: MSI

`packaging/windows/imas-sprout.wxs` (WiX v3 schema) installs:

| What | Where |
|---|---|
| `imas-sprout.exe` | `%ProgramFiles%\imas\` |
| config file (from `packaging/etc/imas-sprout.conf`) | `%ProgramData%\imas\sprout` |
| cache | `%ProgramData%\imas\cache\sprout\` |
| Windows service `imas-sprout` | automatic start, LocalSystem, restarts 5s after a crash |

The service has the same name as the systemd/OpenRC unit, so one `service`
ingredient recipe covers every platform. On Windows that recipe runs through
`internal/ingredients/service/windows` (the SCM provider).

`%ProgramData%\imas` gets a protected ACL: only SYSTEM and Administrators
have access, and everything created below it inherits that. By default,
`%ProgramData%` lets any local user read its subdirectories. The sprout
keeps its join token, NKey seed and X25519 private key under this directory.
Go's `os.WriteFile(…, 0600)` sets no ACL on Windows, so the directory ACL
is what actually protects them.

Like the rpm/deb postinstall scripts, the installer enables the service but
does **not** start it: a fresh install has no farmer address or join token.
An upgrade stops the service and does not start it again. It comes back at
the next boot, or when someone starts it. The config file and state
directory survive upgrades and uninstall (the equivalent of rpm
`%config(noreplace)`).

```powershell
msiexec /i imas-sprout-<version>-windows-x64.msi /quiet /norestart
notepad $env:ProgramData\imas\sprout     # farmerinterface, jointoken, ...
Start-Service imas-sprout
```

### Known gap: the sprout can't run as a service yet

Two things outside the packaging have to change before the installed service
works. The MSI builds and installs without them, but the service won't run:

1. **The sprout never registers with the SCM.** `cmd/sprout/main.go` doesn't
   call `svc.Run` (`golang.org/x/sys/windows/svc`). Windows kills a service
   binary that doesn't check in within 30s (error 1053), and this one also
   ignores the SCM's stop requests. The fix is a `main_windows.go` that
   checks `svc.IsWindowsService()` and runs the existing main loop under a
   `svc.Handler`, with Stop/Shutdown cancelling its context.
2. **Config paths are Unix-only.** `internal/config` hard-codes `/etc/imas`
   and `/var/cache/imas/...`. Under the SCM (working directory
   `C:\Windows\System32`), those resolve to `C:\etc\imas` and so on, not to
   the `%ProgramData%\imas` paths the MSI lays out. Windows needs
   `%ProgramData%`-based defaults.

The provider in `internal/ingredients/service/windows` doesn't solve either
problem. It manages services that already exist (start/stop/enable) and
can't create them or act as one. The MSI's `ServiceInstall` table does the
registering.

### Building the MSI

goreleaser-pro's `msi` pipe templates the `.wxs` file and runs `wixl` on
Linux (`apt-get install wixl msitools`). wixl implements only part of the v3
schema and drops some attributes without warning. A goreleaser after-hook,
`packaging/windows/msi-postprocess.sh`, puts back what the `.wxs` asks for
using `msibuild`:

* `Permanent`/`NeverOverwrite` on the config and state components (wixl
  ignores both);
* `MsiLockPermissionsEx`: the `%ProgramData%\imas` ACL;
* `MsiServiceConfigFailureActions` + `MsiConfigureServices`: restart on
  failure. This is the equivalent of systemd's `Restart=always`.

Both tables need MSI 5.0 (Windows 7 / Server 2008 R2 or later).

Note that `msi.ids` in `.goreleaser.yaml` takes **build** IDs, even though
the goreleaser docs say archive IDs. With an archive ID the pipe silently
produces nothing (checked with goreleaser-pro v2.18.2).

Tests (Linux, no Windows needed): `packaging/test/test-windows-packaging.sh`
builds the MSI the way goreleaser does, then checks the service, directory,
upgrade and post-processed tables, and the winget/nupkg output. Set
`WINGET_SCHEMA_DIR` to a checkout of winget-cli's
`schemas/JSON/manifests/v1.10.0` to also validate the manifests against the
official schema.

Not tested yet, because it needs a Windows host: installing the MSI, whether
the ACL and failure actions take effect, upgrading, and uninstalling.

## Windows: winget via NuGet

`packaging/windows/winget/build-winget-nupkg.sh` runs in the release
workflow after goreleaser. It renders the three winget manifests (schema
1.10.0) from `packaging/windows/winget/templates/`:

* `PackageIdentifier`: `Imas.Sprout`, or the repo variable
  `WINGET_PACKAGE_IDENTIFIER`;
* `InstallerType: wix`, machine scope, `Silent: /quiet /norestart`,
  `SilentWithProgress: /passive /norestart`;
* `InstallerSha256`, `ProductCode` and `UpgradeCode` are read from the built
  MSI, so they can't drift from it;
* `InstallerUrl` is `$WINGET_INSTALLER_BASE_URL/<msi>`. When that repo
  variable isn't set, it falls back to the GitHub release asset URL.

The script then packs the manifests (winget-pkgs layout, under `manifests/`)
and the MSI (under `installer/`) into `<id>.<version>.nupkg` for the
`imasnget` feed. dotnet's NuGet client restores this package (tested).

The `InstallerUrl` has to be downloadable from managed hosts without
credentials. The GitHub fallback only works once someone publishes the draft
release, and only if the repo is public. Otherwise, point
`WINGET_INSTALLER_BASE_URL` at a location those hosts can reach.

## SUSE and the shared RPM scripts

SUSE uses the same RPM, and the same
`scripts/imas-{farmer,sprout}-rpm-postinstall.sh`, as RHEL. **It doesn't
need a separate postinstall script.** zypper hands the package to librpm,
which runs the same `%post` scriptlet (under `/bin/sh`) as dnf does. The
script only calls `systemctl daemon-reload` and `systemctl enable`, and both
behave identically under either tool.

Checked with `packaging/test/rpm-service-lifecycle.sh` on openSUSE Leap 15.6
(systemd 254, zypper) and Rocky Linux 9.8 (systemd 252, dnf), with systemd
booted as PID 1 in both. Every step gave the same result on both:

| Step | Result on both |
|---|---|
| install | unit enabled, not started; the script's "and start" comment is wrong |
| upgrade while running | old process keeps running (same PID); no restart |
| remove | process keeps running from the deleted binary; the `multi-user.target.wants` symlink is left dangling |
| vendor preset | `disable *` on both; `systemctl enable` overrides it on both |

The last three rows are gaps in the shared scripts, not SUSE differences:
there's no `preun`/`postun` to stop or disable the service, and no
try-restart on upgrade. SUSE's packaging guidelines prefer the
`%service_add_*`/`%service_del_*` macros, which follow presets. nfpm
can't use rpm macros, though, and that's a policy choice rather than
something that breaks.

SUSE's firewall and AppArmor, the other items the master plan asks about,
don't affect the sprout package. The sprout only makes outbound connections
(to the farmer's bus and API) and opens no listening socket, so it needs no
firewalld service definition. No AppArmor profile ships, so AppArmor
doesn't confine it.

Not covered: transactional-update systems (SLE Micro, openSUSE
MicroOS), where `%post` runs in a snapshot chroot with no running systemd.
There `daemon-reload` fails and `enable` still works. The same applies to
any offline/chroot RPM install, on RHEL too.

## Buildkite Package Registries

`packaging/buildkite/publish-packages.sh` runs in the release workflow's
`publish-buildkite` job. It uploads:

* top-level `dist/*.rpm` → `imasrpm` and `dist/*.deb` → `imasdeb`, via the
  REST API (`POST /v2/packages/organizations/{org}/registries/{registry}/packages`);
* `dist/winget/*.nupkg` → `imasnget`, via `dotnet nuget push` to
  `https://packages.buildkite.com/{org}/imasnget/nuget/package`.

It needs:

| Name | Kind | What |
|---|---|---|
| `BUILDKITE_PACKAGES_TOKEN` | secret (repo or `goreleaser` environment) | Buildkite API access token with Read Packages + Write Packages |
| `BUILDKITE_ORGANIZATION_SLUG` | variable | org that owns the three registries |

`DRY_RUN=1` lists what would be uploaded. If a package type is missing, or an
upload returns non-2xx (including a duplicate version), the job fails.
