change: Owner accepted the recommended choices for the GPG fleet trust (P22, design D12) and the stateless feature (P21, D13). OpenBao image carries the AWS, Azure, GCP and KMIP seals (D14). Object storage speaks S3; Versity Gateway is optional for Azure Blob; the UAT uses RustFS (D15).
---
item: P22
action: update
next-append: **Decisions (owner, 2026-10-11, design D12):** reuse the existing release GPG key (moved to the `goreleaser` environment); no key-expiry check on the sprout; the chart stamp step verifies `checksums.txt` and its `.sig` and embeds both in `sprout-release.json`, and registration posts them (nothing is downloaded); version floor kept in saasapi and downgrade refusal kept on the sprout; retire `fleetreleaser`, `imas-fleet-signing` and its policies (chart and UAT included). Ready to build.
---
item: P21
action: update
next-append: **Decisions (owner, 2026-10-11, design D13 to D15):** separate accounts bucket; event broadcast plus timed reconcile; PXC row lease for mint-or-reuse; farmer NKey in a shared Secret; `localCooks` merged into one call (superseded the PXC row, D22); audit logs as JSON on stdout shipped by Fluent Bit to the S3 store by default with 30-day configurable retention (D16); OpenBao 2.7.1 image with the AWS, Azure, GCP and KMIP seals; S3 protocol for object storage (Versity Gateway optional for Azure Blob, RustFS in UAT). Build order: P22, then P21 in slices: Transit signer and bootstrap, accounts bucket and loader, farmer state, then drop the `replicaCount == 1` rule.
