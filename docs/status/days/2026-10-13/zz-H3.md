change: H3 built: Versity Gateway as an optional farmer chart component (`versity.enabled`, off by default), the S3 endpoint of farmer, saasapi and the accounts bucket when on; users from the component Secrets, buckets and policies by a hook Job.
pr: 244
item: P25
action: update
rag: Amber
next-append: **H3 built (2026-10-13), ready for review, flagged for security review:** `versity.*` in `deploy/helm/farmer` (gateway Deployment pinned by digest, 2 replicas, spread, PDB, non-root, read-only root, `/_/health` probes; Service on 7070 that farmer's and saasapi's S3 endpoints and the accounts bucket default to; NetworkPolicy; IAM file written per pod by `farmer versity-iam` from the four component Secrets; `createBuckets` hook Job `farmer versity-buckets` creating the four buckets and their per-user policies, design D22). Licence in `DEPENDENCIES.md`. Checked end to end against `versitygw` v1.8.0 on Azurite. Fluent Bit log shipping is the other half and stays open.
