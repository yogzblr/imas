# imas requirements

Numbered requirements are stable IDs; other docs cite them by number.
Status and delivery detail live in `docs/BUILD-STATUS.md`, not here.

1. Scale to 1 million endpoints.
2. DMZ and non-DMZ separation.
3. Windows and Unix support.
4. Deployment automation using Ansible.
5. Authentication to the NATS websocket is JWT-based. A one-time enrollment
   API key is used only to bootstrap; it is never used for the steady-state
   connection.
6. Each sprout holds its own JWT and presents it to connect to the bus URL.
7. Farmer is horizontally scalable.
8. Sprout supports connections via proxies.
9. Sprout downloads recipes from a dedicated HTTP endpoint configured in the
   sprout.
10. NATS response to a sprout in under 300 ms.
11. Recipe download authenticates with the same sprout credential (JWT) used
    for the bus connection.
12. Envoy with JWT validation sits in front of NATS.
13. The backend (NATS, Valkey, farmer, Percona) runs on Kubernetes.
14. NATS payloads are encrypted using a key pair per sprout and a key pair
    per tenant held on the master side.
15. Key rotation for sprout key pairs, triggered by the master side as a
    new transaction over NATS. The trigger carries no key material: the
    sprout generates the new key pair itself and submits only the new
    public key, sealed under its current key. A private key is never sent.
16. SDB support equivalent to Salt in the sprout: secrets from external
    sources as defined in the recipe.
17. Probe capability in the sprout supporting database and HTTP sequences;
    running a probe sequence is a sprout task.
18. Installers for yum (rpm), apt (deb), zypper and Windows (MSI).
19. Ansible playbook uses the installer to deploy a sprout with a one-time
    key used to download its JWT and keys.
20. Fleet (sprout) updates install from the repository configured in the
    sprout, the same per-OS package repositories the Ansible role
    `imas_sprout` configures (apt / rpm / zypper / Windows feed or MSI URL).
    An update command names a target version only; it never supplies an
    artifact URL or checksum. Repository trust (GPG / package signature)
    is the sprout's own configuration, not something the command carries.
21. Licensing: dependencies are Apache-2.0 or MIT by default. Accepted
    exceptions: Percona XtraDB Cluster (GPLv2, commercial arrangement) and
    MPL-2.0 dependencies generally, including OpenBao and its Go client
    (used unmodified, or modifications shared). UAT-only exceptions,
    run unmodified on the throwaway UAT hubs and never linked, shipped
    or a dependency of a released artifact: busybox (GPL-2.0), as
    local-path-provisioner's helper pod image on the UAT k0s hubs; and
    MinIO (AGPL-3.0), as the UAT object store on the core hub. Any other
    license is flagged before adoption.
