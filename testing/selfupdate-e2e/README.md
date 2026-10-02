# Sprout self-update, end to end

`run.sh` drives one real self-update cycle (FU.2) on a packaged sprout,
against a real package repository, with nothing on the update path
mocked:

| Piece | What stands in for production |
|---|---|
| Package repository | Sonatype Nexus Repository Community Edition: signed apt and yum hosted repositories, no anonymous access, a read-only `buildkite` user whose password is the repo token |
| Repository TLS | A proxy in front of Nexus (stub farmer `-repo-proxy-to`) with its own CA, installed in the sprout host's OS trust store |
| farmer, saasapi, fleetreleaser | The Molecule stub farmer (`ansible/molecule/stubfarmer`): enrollment, the bus, a signed manifest on `GET /v1/sprout/update-manifest`, and the `self_update` cook job sealed to the sprout as farmer seals it |
| Sprout host | systemd containers (Debian 12, Rocky 9) where `imas-sprout` v0.1.0 is installed from Nexus by apt/dnf, as the Ansible role installs it |

It checks the update to v0.2.0 (job result, installed package version,
service restart, the running binary, the sprout reconnecting with the new
version, the credentials on every repository request) and then the
refusals: downgrade, a manifest signed by a key not in the keyring, a
release whose checksum isn't in the repository, and a version with no
manifest.

```sh
NEXUS_ACCEPT_EULA=1 testing/selfupdate-e2e/run.sh     # from the repo root
```

`NEXUS_ACCEPT_EULA=1` is required: Nexus Community Edition refuses to
create repositories until its EULA
(https://links.sonatype.com/products/nxrm/ce-eula) is accepted, and the
script only accepts it, for its throwaway container, when you say so.
`DISTROS=debian` or `DISTROS=rocky` runs one; `KEEP=1` leaves the
containers up. Needs docker (privileged containers, for systemd), go, curl
and jq; about ten minutes, most of it Nexus starting and nfpm building.

What it doesn't cover: Windows (the MSI path is unit-tested with msiexec
mocked), farmer's real dispatch (`internal/natsapi`, still the pre-FU.2
shape) and saasapi's release registration (its own tests).
