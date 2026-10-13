change: H6 (final gate for the next Azure runs): on main after R1 and H1 to H5, `go build`, `go vet`, `go test -race ./...` (with PXC 8.4.8-8.1, Valkey 9.1.2, Envoy 1.35.3 and OpenBao 2.7.1 behind the gated tests, as CI runs them) and `CGO_ENABLED=0 go build ./...` pass; `helm template` passes for `deploy/helm/farmer` and `deploy/helm/nats` with every ci/ values file (`versity-values.yaml` included) and for both UAT hubs single-node and with the HA overlays (`values-ha.yaml`, Versity on); `tofu validate`, and `tofu test` planning and applying `uat/tofu` for 1 and 3 nodes per hub on mocked providers, pass. Runbook `uat/RUNBOOK.md`: the owner prerequisites (GPG secrets on the `goreleaser` environment only, a `v*` tag ruleset, two signed release candidates cut after P22, the quota, the security review before the dispatch flags leave UAT), the exact dispatch inputs of Run 2 and Run 3, what each proves and how to read the report. Stale "never run" and "not merged" lines in the UAT READMEs fixed. Flagged for security review.
pr: 250
---
item: P20
action: update
rag: Amber
next-append: **H6 (2026-10-13):** the gate passes on main with R1; Run 2 of `uat/RUNBOOK.md` (`release_tag` `v0.1.0-rc.15`, `upgrade_from_tag` `v0.1.0-rc.14`, both cut from main after P22, `dispatch_flags` true, `hub_nodes` 1, tier `all`) proves the registration and L5 on the rig.
---
item: P13
action: update
rag: Amber
next: **R1 (2026-10-13) closed:** `check.sh`'s "must refuse" checks assert saasapi's error code with the status (`401 unauthorized`, `403 forbidden`); `dispatch_flags` turns the fleet update flags on (P20); the UAT's `minio` names are `rustfs` (`imas-uat-rustfs`, `rustfs-setup.sh`, values key `rustfs`); Keycloak (`docker.io/keycloak/keycloak:26.4.0`) and Envoy (`v1.35.3`, core edge and DMZ) pinned by digest; the object store credential check, now `uat/hub/core/validate-object-store.sh` (H4; put, get and list with each scoped credential in the recipe, job, sprout JWT and accounts buckets, on RustFS or Versity Gateway; `install.sh` runs it). **H6 (2026-10-13):** the runs that cover what is left are in `uat/RUNBOOK.md`: Run 2 runs the UAT.7 conformance cases and the Windows lines on Azure (tier `all`); Run 3 runs the object store through a gateway (Versity Gateway over Azure Blob, H3 and H4). **Left:** a RustFS pod-restart soak (no run restarts RustFS).
---
item: P24
action: update
title: **UAT high-availability topology: 3 k0s nodes for core and 3 for the DMZ**
rag: Amber
next-append: **Built, awaiting Run 3 (H6, 2026-10-13):** H1 to H5 merged and the gate passes on main (`tofu test` for 1 and 3 nodes, both hubs rendered with their HA overlays). Run 3 of `uat/RUNBOOK.md` (`hub_nodes` 3, tier `ha`, after Run 2, with 18 DSv5 and 12 B2ls_v2 vCPU of quota, 30 regional) is the validation.
---
item: P23
action: update
rag: Amber
next-append: **Built, awaiting Run 3 (H6, 2026-10-13):** the `ha` tier (HA1 to HA6, T1 to T8 mapped) and the HA hubs are on main; Run 3 of `uat/RUNBOOK.md` validates them against the owner's error windows.
---
item: P25
action: update
title: **Versity Gateway as an optional chart component (built); Fluent Bit log shipping**
rag: Amber
next-append: **First half built (H3, H4; H6 gate 2026-10-13):** Versity Gateway is on main, rendered with `versity.enabled` in the chart's ci values and the HA core hub, and is Run 3's object store over Azure Blob (`uat/RUNBOOK.md`). **Fluent Bit log shipping is still open.**
---
item: P1
action: update
next-append: **H6 (2026-10-13):** awaiting the runs. Owner prerequisites and the exact inputs of Run 2 (single node, fleet update path on) and Run 3 (HA) are in `uat/RUNBOOK.md`.
