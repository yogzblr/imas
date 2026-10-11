change: Owner decisions: Fluent Bit ships logs to the object store by default (D16); production seal is Azure Key Vault with the others supported (D17); production object store is Versity Gateway over Azure Blob, added to the Helm chart as an optional component (D18, new P25).
---
item: P21
action: update
next-append: **Logs (owner, 2026-10-11, design D16): Fluent Bit on the nodes sends to the S3 object store by default; farmer and saasapi log JSON to stdout only. Production seal Azure Key Vault (D17).**
---
item: P25
action: add
section: S1
sub: S1c
title: **Versity Gateway as an optional chart component; Fluent Bit log shipping**
rag: Red
next: Production object store is Versity Gateway in front of Azure Blob (design D18); the code only speaks S3. Add Versity Gateway to the Helm chart as an optional component, off by default, with its Azure Blob credentials from a Secret, a Service the other components use as their S3 endpoint, and readiness. Add Fluent Bit (DaemonSet or the cluster's own) with a default output to the S3 bucket, and the chart values that point farmer, saasapi and the bus at stdout only. Licences (Fluent Bit Apache-2.0; Versity Gateway Apache-2.0, D18) go in `DEPENDENCIES.md`. Log retention is 30 days by default and configurable, and the shipper's destination is set by its ConfigMap (D16); object lock is not required. Needs the same S3 endpoint settings as the accounts, sprout JWT and recipe buckets (P21).
