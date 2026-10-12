change: Z (final gate of P26 to P28): on main after E1 to E6, `go build`, `go vet`, `CGO_ENABLED=0 go build` and `go test -race ./...` pass with MySQL (PXC 8.4.8-8.1), real Envoy 1.35.3, OpenBao 2.7.1 and Valkey 9.1.2 behind every gated test; `helm template` passes for both charts with every ci/ values file and both UAT hubs. Two end-to-end tests added: farmer's account publisher writes the accounts bucket and a loader fills an empty bus node from it (`TestEmptyBusNodeLoadsWhatFarmerPublished`); a fleet update goes through farmer's real manifest route and the sprout's GPG check (`TestApply_ThroughFarmerManifestRoute`). CI now also runs the real-Envoy and Valkey tests. Stale docs and comments from before the stateless build fixed (INSTALL.md seeds, both chart NOTES, the architecture diagram, the signing design's status). Flagged for security review.
---
item: P26
action: close
---
item: P27
action: close
---
item: P28
action: close
---
item: P21
action: update
title: **Horizontal scale of farmer and the bus: OpenBao-held signing keys**
rag: Amber
next: **Built and tested (2026-10-12):** all P21 units (B1 to B8, C1 to C7, D1 to D9, F1, E1 to E6) merged; the final gate Z passes on main (see the day's record). Evidence: Transit-held trust chain; farmer stateless with 2 replicas by default (no PVC, no local JWT or key file; `TestTwoReplicasShareMintsAndRevocations`, `TestEnrollConcurrentReplicas`: one JWT per sprout across replicas); bus stateless, an empty node loads every Account farmer published (`TestLoaderEmptyNodeReadyOnlyAfterLoadingEverything`, `TestEmptyBusNodeLoadsWhatFarmerPublished`). Not Green: the human security review (P3) and a UAT gate run on the stateless build are owed; the scale-out validation is P23.
---
item: P22
action: update
rag: Amber
next: **Built and tested (2026-10-12):** A1 #203 and A2 #205 merged; the sprout verifies `checksums.txt` and its GPG signature from the shipped keyring and takes the hash for the file name it derives (`TestPrepare_GPGChecksums`), also through farmer's real manifest route and catalog SQL, where a release signed by another key is refused before any download (`TestApply_ThroughFarmerManifestRoute`). Not Green: the human security review (P3) and the first release signed and registered end to end are owed; dispatch and self-update stay off until P3.
---
item: P23
action: update
next-append: **P27 closed (Z, 2026-10-12):** the code gaps it listed are built (E2 to E4).
