# OS packaging

What each release builds, and how it gets to hosts:

1. `.github/workflows/release.yml` runs goreleaser (`.goreleaser.yaml`),
   which builds everything and attaches it to a **draft** GitHub release.
2. A maintainer reviews the draft and publishes it.
3. That triggers `.github/workflows/publish-packages.yml`, which downloads
   the release's packages, checks them against its `checksums.txt`, and
   uploads them to the Buildkite Package Registries. Prereleases are
   skipped unless published deliberately with `workflow_dispatch`, which also
   re-runs a failed publish for a tag.

| Package | Formats | Built by | Published to |
|---|---|---|---|
| `imas`, `imas-farmer`, `imas-sprout` | apk, deb, rpm | `nfpms` | GitHub release; `.deb` → Buildkite `imasdeb`, `.rpm` → Buildkite `imasrpm` |
| `imas-sprout` (Windows) | MSI | `packaging/windows/build-msi.sh` (msitools' wixl), a post hook of the `sprout-windows-pkg` build | GitHub release |
| `imas.sprout.windows` (winget) | installer `.nupkg` + manifests `.nupkg` | `packaging/windows/winget/build-winget-nupkg.sh`, in `publish-packages.yml` | Buildkite `imasnget` (public NuGet feed) |

## Windows: MSI

`packaging/windows/imas-sprout.wxs` (WiX v3 schema) installs:

| What | Where |
|---|---|
| `imas-sprout.exe` | `%ProgramFiles%\imas\` |
| config file (from `packaging/etc/imas-sprout.conf`) | `%ProgramData%\imas\sprout` |
| cache | `%ProgramData%\imas\cache\sprout\` |
| Windows service `imas-sprout` | automatic start, LocalSystem, restarts 5s after a crash |

The sprout creates the rest itself: `pki\sprout\`, `state\sprout\` and, when
running as a service, its log at `%ProgramData%\imas\logs\sprout.log` (the
service manager discards stderr). `internal/config/paths_windows.go` defines
these paths, and they must stay in line with the `.wxs` file.

The sprout binary runs under the Windows service manager itself
(`cmd/sprout/service_windows.go`): Stop and Shutdown cancel its main loop.
It also has service commands, `imas-sprout install|uninstall|start|stop|status`,
for a host without the MSI. `install` registers the same service with the
same recovery settings as the MSI.

The service has the same name as the systemd/OpenRC unit, so one `service`
ingredient recipe covers every platform. On Windows that recipe runs through
`internal/ingredients/service/windows` (the SCM provider).

`%ProgramData%\imas` gets a protected ACL: only SYSTEM and Administrators
have access, and everything created below it inherits that. By default,
`%ProgramData%` lets any local user read its subdirectories. The sprout
keeps its join token, NKey seed and X25519 private key under this directory.
Go's `os.WriteFile(…, 0600)` sets no ACL on Windows, so the directory ACL
is what actually protects them. The sprout re-applies the same ACL on every
start (`config.SecureSproutConfigRoot`), which covers hosts installed without
the MSI.

When the installer starts the service:

| Install | Service after the install |
|---|---|
| fresh install | stopped. Like the rpm/deb postinstall (enable, don't start): there's no farmer address or join token yet |
| fresh install with `START_SERVICE=1` | started. For hosts whose config was provisioned before the install (Ansible, a golden image) |
| upgrade, including same-version (`1.2.3-rc.1` → `1.2.3`) | started again on the new binary. The upgrade stops it first |

When the installer does start it, it waits for the service to report
Running. If it doesn't, the install fails, and an upgrade rolls back to the
previous version. The sprout reports Running as soon as its config and PKI
directories are set up. Enrollment and the bus connection come after that,
so a missing farmer address or join token doesn't block an install.

The config file and state directory survive upgrades and uninstall (the
equivalent of rpm `%config(noreplace)`).

```powershell
msiexec /i imas-sprout-<version>-windows-x64.msi /quiet /norestart
notepad $env:ProgramData\imas\sprout     # farmerinterface, jointoken, ...
imas-sprout start                         # or Start-Service imas-sprout
imas-sprout status                        # state, settings, log path

# or, config already in place:
msiexec /i imas-sprout-<version>-windows-x64.msi /quiet /norestart START_SERVICE=1
```

### Supported Windows versions

The oldest supported Windows is **Windows Server 2016** (decided
2026-10-03). Client Windows is not supported. The MSI declares Windows
Installer 5.0 (`InstallerVersion='500'`), which Server 2016 has, and must
not use anything newer. winget is not present on Server 2016: there the
Ansible role installs the MSI with `win_package`. No Server 2016 host has
installed this MSI yet.

### Building the MSI

Releases use GoReleaser OSS; there is no goreleaser-pro `msi` pipe. The
`sprout-windows-pkg` build in `.goreleaser.yaml` has a post hook that runs
`packaging/windows/build-msi.sh` with the built binary, the version and
`dist` as the output directory. The script:

1. renders the template fields of the `.wxs` (`Major`, `Minor`, `Patch`,
   `Version`, `MsiArch` as `x64`, `Binary`) and drops the non-x64 branch and
   the `.Runtime.Goos "windows"` (WiX toolset only) blocks. Any other
   template action fails the build;
2. stages `imas-sprout.exe`, `packaging/etc/imas-sprout.conf` and
   `packaging/etc/fleet-signing-keys.json` at those relative paths next to the
   rendered `.wxs`, with modification times set to the commit timestamp;
3. runs `wixl -a x64` (`apt-get install wixl msitools`), then
   `msi-postprocess.sh`;
4. writes `dist/imas-sprout-<version>-windows-x64.msi`, by an atomic rename,
   so a failed build leaves no MSI.

`checksum.extra_files` and `release.extra_files` pick the MSI up from `dist`,
so it is listed in `checksums.txt` (and covered by its GPG and cosign
signatures) and attached to the release. Checksums are computed after all
builds, so the MSI exists by then; `.github/workflows/goreleaser-check.yml`
checks that on every pull request that touches the release config or
packaging.

The MSI is not byte-for-byte reproducible: every build gets a new
ProductCode and PackageCode (`Id='*'`, which `MajorUpgrade` relies on), and
wixl stamps the build time into the summary information. With the same
inputs and timestamp the files inside it, and the cabinet holding them, are
identical.

wixl implements only part of the v3 schema and drops some attributes without
warning. `packaging/windows/msi-postprocess.sh` puts back what the `.wxs`
asks for using `msibuild`:

* `Permanent`/`NeverOverwrite` on the config and state components (wixl
  ignores both);
* the start condition on the `SproutServiceStart` component (wixl rejects
  `<Condition>` there; a WiX build on Windows gets the element instead), and
  `START_SERVICE` in `SecureCustomProperties` (wixl ignores `Secure`);
* `MsiLockPermissionsEx`: the `%ProgramData%\imas` ACL;
Not in the MSI: restart on failure (systemd's `Restart=always`). Windows
Installer was denied (error 1939, "Error: 5", status 1603) applying an
`MsiServiceConfigFailureActions` row, so the `imas_sprout` Ansible role sets it
after the install with `sc.exe failure`, and `imas-sprout install` sets it
too. An MSI-only install has no restart policy.

The ACL table needs Windows Installer 5.0, which Windows Server 2016 has.

wixl implements `AllowSameVersionUpgrades` as a separate
`WIX_SAME_VERSION_UPGRADE_DETECTED` property, which the start condition
includes. It matters because ProductVersion drops prerelease suffixes.

Tests (Linux, no Windows needed): `packaging/test/test-windows-packaging.sh`
builds the MSI with `build-msi.sh`, as the release does, then checks the
script's error handling, the service, start condition, directory, upgrade
and post-processed tables, and the two winget packages. Set
`WINGET_SCHEMA_DIR` to a checkout of winget-cli's
`schemas/JSON/manifests/v1.10.0` to also validate the manifests against the
official schema.

Not tested yet, because it needs a Windows host: installing the MSI (nothing
has installed it on any Windows host, Server 2016 included), whether the
ACL and start condition take effect, upgrading,
uninstalling, and `winget install`. The first real release tag is also the
first run of the whole release pipeline.

### Parse-checking the PowerShell by hand

No CI job has PowerShell yet. On a Windows machine, from a WSL checkout:

```sh
python3 packaging/test/extract-powershell.py /mnt/c/temp/ps
```

then, in PowerShell:

```powershell
Get-ChildItem C:\temp\ps | ForEach-Object {
  $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$e)
  if ($e) { $_.Name; $e | ForEach-Object { "  line $($_.Extent.StartLineNumber): $($_.Message)" } }
}
```

It prints nothing when every script parses. It would have caught the
`"$IndexUrl:"` mistake before the Azure run did.

## Windows: winget via NuGet

The `imasnget` Buildkite registry is a public NuGet feed. It carries two
packages per release, both built by
`packaging/windows/winget/build-winget-nupkg.sh` in `publish-packages.yml`:

| NuGet package | Contents | Role |
|---|---|---|
| `imas.sprout.windows.msi` | the MSI, at the package root | the installer: winget downloads it from the feed, with no credentials |
| `imas.sprout.windows` | the three winget manifests (schema 1.10.0), in the winget-pkgs layout under `manifests/` | the winget package, `PackageIdentifier: imas.sprout.windows` |

There are two packages because a manifest can't contain the hash of the
file it's inside. A NuGet feed only serves `.nupkg` files, so the MSI
travels in one. The manifests say `InstallerType: zip` with
`NestedInstallerType: wix`: winget downloads the installer package (a zip),
extracts it and runs the MSI.

The manifests contain:

* `InstallerUrl`: the installer package's NuGet v3 flat-container URL,
  `<PackageBaseAddress>/imas.sprout.windows.msi/<ver>/imas.sprout.windows.msi.<ver>.nupkg`.
  The workflow reads `PackageBaseAddress` from the feed's public `index.json`;
* `InstallerSha256`: the installer package's hash;
* `ProductCode`, `UpgradeCode` and the version, read from the MSI;
* machine scope, and silent switches `/quiet /norestart` and
  `/passive /norestart`.

`publish-packages.sh` pushes the installer package first. It then downloads
it back anonymously from `InstallerUrl`, retrying while the feed indexes it,
and compares the hash. Only if that passes does it push the manifests. If the
feed stopped being public, or served different bytes, the release fails
before any client sees a manifest it can't install from.

dotnet's NuGet client restores both packages (tested).

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
| remove | (as found before UAT.11) process kept running from the deleted binary and the `multi-user.target.wants` symlink was left dangling; since UAT.11 a `preremove` script (`imas-sprout-deb-prerm.sh`, `imas-sprout-rpm-preun.sh`) stops and disables the service on remove/erase but not on upgrade |
| vendor preset | `disable *` on both; `systemctl enable` overrides it on both |

The last three rows are gaps in the shared scripts, not SUSE differences:
there's no `postun`, and no try-restart on upgrade. (The missing stop/disable on remove is fixed by the sprout
remove scripts, UAT.11.) SUSE's packaging guidelines prefer the
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

`.github/workflows/publish-packages.yml` runs when a release is published
(see the top of this file). It calls `packaging/buildkite/publish-packages.sh`,
which uploads:

* the release's `*.rpm` → `imasrpm` and `*.deb` → `imasdeb`, via the REST API
  (`POST /v2/packages/organizations/{org}/registries/{registry}/packages`).
  This covers `imas`, `imas-farmer` and `imas-sprout`: `release.ids` in
  `.goreleaser.yaml` lists their nfpm IDs so they're attached to the release;
* the two winget `.nupkg` files → `imasnget`, via `dotnet nuget push` to
  `https://packages.buildkite.com/{org}/imasnget/nuget/package`. The
  installer goes first, then the check above, then the manifests.

It needs:

| Name | Kind | What |
|---|---|---|
| `BUILDKITE_PACKAGES_TOKEN` | secret (repo or `goreleaser` environment) | Buildkite API access token with Read Packages + Write Packages |
| `BUILDKITE_ORGANIZATION_SLUG` | variable | org that owns the three registries |

The Helm charts are no longer in this list. They go to GHCR as OCI charts
(`oci://ghcr.io/yogzblr/charts/{farmer,nats}`), pushed and cosign-signed by
the same workflow's last steps; `packaging/buildkite/publish-helm.sh` was
removed and the Buildkite `imashelm` registry is superseded for charts
(`docs/RELEASING.md`, "Helm charts on GHCR"). `only_helm` skips the uploads
above and publishes only the charts.

`DRY_RUN=1` lists what would be uploaded. If a package type is missing, or an
upload returns non-2xx (including a duplicate version), the job fails.
Re-running `workflow_dispatch` for a tag whose packages partly made it up will
fail on the duplicates. Delete them from the registries first.
