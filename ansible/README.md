# Bootstrapping hosts onto imas with Ansible

These playbooks install the imas sprout on your hosts, enroll each one into
your tenant with a one-time enrollment key, and wait until it is connected.
You run them from your own Ansible controller against your own inventory.

- **Linux** (systemd, with apt, dnf/yum or zypper): adds the imas package
  repository and installs `imas-sprout` from it, so later updates come
  through your normal package management.
- **Windows** (Server 2019 or later): installs the `imas-sprout` MSI from the
  imas NuGet feed and runs it as the `imas-sprout` service.

Running the playbook again is safe. A host that has already enrolled is
never enrolled again and never receives the enrollment key again.

## Before you start

On the controller:

```sh
pip install 'ansible-core>=2.15'
cd ansible/
ansible-galaxy collection install -r requirements.yml
```

`requirements.yml` installs `ansible.windows` (for Windows hosts) and
`community.general` (for SUSE hosts).

Each host needs:

- outbound HTTPS to the imas package registry (`packages.buildkite.com`)
- outbound HTTPS to the enrollment endpoint, and outbound access to the bus
  address (for example `wss://…:443`). The sprout opens no listening ports.
- a clock within 5 minutes of farmer's. Enrollment requests are signed and
  timestamped, and farmer rejects requests outside that window.
- Linux: an account Ansible can `become` root with. Windows: an administrator
  account over WinRM or PSRP.

## 1. Get an enrollment key

Enrollment keys are issued per tenant by the SaaS API
(`POST /v1/tenants/{tenant_id}/enrollment-keys`; see
[docs/api/saasapi.md](../docs/api/saasapi.md) and
[API design §1.2](../docs/design/cloudxp-machine-manager-api-design.md)).
Normally you create one from the CloudXP portal. Calling the API directly
takes the same two credentials the portal's backend sends (the
`X-Internal-Auth` shared secret and your user's bearer token):

```sh
curl -sS -X POST "https://<saas-api>/v1/tenants/<tenant_id>/enrollment-keys" \
  -H "X-Internal-Auth: $INTERNAL_SECRET" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "Content-Type: application/json" \
  -d '{"expires_in_hours": 24, "max_uses": 50}'
```

```json
{
  "key_id": "ek_…",
  "registration_key": "ek_….<secret>",
  "expires_at": "2026-09-15T10:00:00Z",
  "max_uses": 50
}
```

`registration_key` is the enrollment key: the full `{key_id}.{secret}`
string. **It is shown only once.** Choose settings that keep a leaked key as
harmless as possible:

- `max_uses`: the number of hosts in this rollout. Each first-time enrollment
  uses the key once. A retry after a dropped connection doesn't use it again.
- `expires_in_hours`: just long enough to finish the rollout.

To revoke a key you no longer need, call
`DELETE /v1/tenants/<tenant_id>/enrollment-keys/<key_id>`.

## 2. Put it in your inventory, encrypted

Copy `inventory/example/` into your own repository (not this one), and edit
it:

- `hosts.yml`: your hosts. The playbook targets the `sprouts` group.
- `group_vars/sprouts/vars.yml`: your Buildkite organization, the
  enrollment host, and optionally the bus addresses and root CA (see
  [Variables](#variables)).
- `group_vars/linux_sprouts/`, `group_vars/windows_sprouts/`: connection
  settings.

Then store the key with **ansible-vault**:

```sh
cd inventory/<yours>/group_vars/sprouts/
ansible-vault create vault.yml
# in the editor:
# vault_imas_join_token: "ek_….<secret>"
```

`vars.yml` reads it from there (`imas_join_token: "{{ vault_imas_join_token
| default('') }}"`). Commit only the encrypted file. **Never commit the key
in plain text**, not even to a private repository, and don't pass it with
`-e` on a shared machine, because the command line is visible to other
users.

If your automation runner has its own secret store (AWX/AAP credentials, a
CI secret, HashiCorp Vault), you can use that instead of ansible-vault. Have
it provide `imas_join_token`, for example:

```yaml
imas_join_token: "{{ lookup('ansible.builtin.env', 'IMAS_JOIN_TOKEN') }}"
```

Once every host has enrolled, the key isn't needed any more. You can delete
`vault.yml` and revoke the key.

## 3. Run the playbook

```sh
ansible-playbook -i inventory/<yours> site.yml --ask-vault-pass
```

For each host, the playbook:

1. **Installs the package.**
   - Linux: adds the imas repository (`imasdeb` for apt, `imasrpm` for
     dnf/yum and zypper) along with its signing key, then installs
     `imas-sprout` with the package manager. Repository metadata is signed.
     The packages themselves aren't.
   - Windows: finds the newest release (or `imas_sprout_version`) on the
     public `imasnget` NuGet feed, downloads the MSI package (the same file
     winget installs), and installs it with `win_package`. The MSI is
     identified by its ProductCode, so an installed build isn't reinstalled.
2. **Writes the enrollment settings** into the config file the sprout already
   reads (`/etc/imas/sprout`, or `%ProgramData%\imas\sprout` on Windows):
   `farmerinterface`, `farmerapiport`, `busurls` if set, and `jointoken` if
   the host isn't enrolled yet. It changes only those keys and leaves the
   rest of the file alone, including what the sprout writes itself. If you
   set `imas_sprout_root_ca`, it also writes that CA to the sprout's
   root-CA path and sets `sproutrootcatofu: false`.
3. **Starts the service** (systemd `imas-sprout`, or the Windows service
   `imas-sprout`), enables it at boot, and restarts it if its package or
   settings changed.
4. **Waits for the sprout to connect** (role `imas_verify`), and fails the
   host with the reason if it doesn't (see [If a host fails](#if-a-host-fails)).

The sprout enrolls itself when it starts. It then deletes the key from its
config file.

A host counts as enrolled when its enrollment credential
(`/etc/imas/pki/sprout/sprout.jwt`, or `…\pki\sprout\sprout.jwt`) exists.
The sprout writes that file last, after everything else from enrollment. An
enrolled host is never given `jointoken`, so later runs work with no key at
all.

## Variables

Set these in `group_vars`/`host_vars`. `roles/*/defaults/main.yml` and
`roles/*/meta/argument_specs.yml` document all of them.

| Variable | Default | |
|---|---|---|
| `imas_join_token` | `""` | The enrollment key. Needed only for hosts that aren't enrolled yet. **Secret: store it with ansible-vault.** |
| `imas_farmer_host` | required | Host the sprout enrolls with: `https://<host>:<port>/v1/enroll`. |
| `imas_farmer_api_port` | `5405` | Port of the enrollment endpoint (`443` behind the DMZ edge). |
| `imas_farmer_bus_urls` | `[]` | Bus addresses to pin, e.g. `["wss://bus.example.com:443"]`. Empty: the sprout uses the addresses farmer returns at enrollment. |
| `imas_sprout_root_ca` | `""` | PEM of the CA that issued the enrollment endpoint's certificate. **Required behind the DMZ edge.** Without it, the sprout trusts the first certificate it sees. |
| `imas_buildkite_org` | required | Buildkite organization that publishes the packages. |
| `imas_sprout_version` | `""` | Pin a version. Linux: the package version as the repository lists it (`1.2.3+git`). Windows: the release (`1.2.3`). |
| `imas_sprout_package_state` | `present` | Linux: `latest` upgrades to the newest version on every run. |
| `imas_sprout_repo_token` | `""` | Registry token, if your Linux registries are private. Stored in root-only files on the host. |
| `imas_sprout_windows_msi_url` | `""` | Install this MSI (for example from an internal mirror) instead of using the NuGet feed. |
| `imas_sprout_verify` | `true` | Wait for the bus connection after installing. |
| `imas_verify_timeout` | `300` | Seconds to wait for it. |

## If a host fails

`imas_verify` fails a host when its sprout isn't connected by
`imas_verify_timeout`. It says which stage failed and shows the sprout's last
log lines (from `journalctl -u imas-sprout`, or
`%ProgramData%\imas\logs\sprout.log` on Windows):

- **has not enrolled**: farmer returns the same `enrollment_failed` for
  every rejection, on purpose, so the log can't show why. Check that:
  - the key hasn't expired, been revoked, or run out of `max_uses`
  - the host can reach the enrollment endpoint and trusts its certificate
    (`imas_sprout_root_ca`)
  - the host's clock is within 5 minutes of farmer's

  Once you've fixed the cause, re-run the playbook. If the old key is used
  up, re-run it with a new one.
- **enrolled but its service is not running**: see the log lines.
- **no connection to its bus**: the host can't reach the bus addresses shown
  in the message, or the bus rejects it. Look for TLS or authorization
  errors in the log.

The sprout records its bus connection state in
`/var/lib/imas/sprout/bus-status.json`
(`%ProgramData%\imas\state\sprout\bus-status.json` on Windows):
`starting`, `connected`, `disconnected` (with the error) or `stopped`, the
bus server, since when, and its PID. `imas_verify` uses that state when the
running service's process wrote it, and counts the sprout as connected once
it has stayed `connected` for `imas_verify_hold` seconds. On failure it
shows the recorded state, so the message says why, for example
`disconnected since …: tls: failed to verify certificate`.

The same state is available on the host:

- Linux: `imas-sprout status`. Exit code 0 if connected, 3 if not, 4 if the
  sprout has recorded nothing yet.
- Windows: `imas-sprout status` from an elevated prompt adds a `bus:` line
  to the service status. The exit code still reflects the service state.

A sprout too old to record its state doesn't have this file. For those,
`imas_verify` falls back to checking for an established TCP connection from
the sprout's process to one of its bus addresses that stays open for
`imas_verify_hold` seconds. That check has a blind spot: when the enrollment
endpoint and the bus share the same host and port (both behind the DMZ edge
on 443), the enrollment request's own connection can look like a bus
connection for up to 90 seconds.

## Windows

The MSI comes from the public `imasnget` NuGet feed. It is the same file the
winget manifest points at. The role downloads it once per version to
`%ProgramData%\imas-installers\` and installs it with `win_package`, rather
than with `winget`, because:

- no Ansible module ships winget support (`community.windows` has none)
- winget doesn't ship with Windows Server before 2025
- winget doesn't work reliably when run as SYSTEM or over WinRM/PSRP, and
  that's how Ansible runs things
- `win_package` gives Ansible the MSI's ProductCode to check whether a
  build is already installed

The MSI leaves the service stopped on a fresh install. The role writes the
settings first and then starts the service. An upgrade restarts the service
itself.

## Development

```sh
cd ansible/
python -m pytest tests/unit              # imas_verify's Linux module
go test ./molecule/stubfarmer/           # the test farmer
molecule test                            # the Linux roles end to end, in Docker
```

The Molecule scenario (`molecule/default/`) needs Docker and Go. It works
like this:

1. It builds `imas-sprout` from this checkout and packages it with nfpm the
   way `.goreleaser.yaml` does.
2. It publishes the packages to signed apt and rpm repositories laid out
   like the Buildkite registries.
3. It starts `molecule/stubfarmer`, a stand-in for farmer's enrollment API
   plus an operator-mode nats-server.
4. It runs the role against Debian 12 (apt), Rocky 9 (dnf) and openSUSE
   Leap 15.6 (zypper) containers running systemd.
5. It checks the result: each sprout's local state, that a second run
   changes nothing and enrolls nothing, and, from the farmer side, that
   every sprout is connected and used the key exactly once.

The Windows path has no automated test yet. It needs a real Windows host.
