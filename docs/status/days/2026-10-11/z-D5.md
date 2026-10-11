change: D5 (P21 slice 3 PR 5): sprout User JWTs are kept in the private sprout JWT bucket (`IMAS_S3_SPROUT_JWT_BUCKET`), indexed by `farmer.sprout_user_jwt` on `(tenant_id, sprout_id)`, and minted at most once across replicas under that row's lease (`pki.MintOrReuseUserJWT`); enrolment and refresh serve the JWT from there, a lost lease race is `ErrSproutJWTBusy` (retryable), and enrolment grants only the enrolled NKey on the tenant Account instead of re-syncing every sprout. Flagged for security review.
pr: 212
item: P21
action: update
next-append: Slice 3 PR 5 (D5), ready for review: sprout JWT store and lease. Still open: wire the bucket env in the chart and map `ErrSproutJWTBusy` to 503 in the enroll and refresh handlers.
