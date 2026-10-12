change: F1 (P21 slice 3 follow-up, owner decision 8 of issue #197): POST /v1/enroll and POST /v1/refresh answer 503 with `Retry-After: 5` when pki fails with an error wrapping `pki.ErrSproutJWTBusy` (another farmer replica holds the sprout's User JWT mint lease), instead of the generic 401; every other failure keeps the generic 401, and the body stays `{"error":"enrollment_failed"}`. Flagged for security review.
item: P21
action: update
next-append: **Follow-up F1, ready for review:** 503 + Retry-After for a busy sprout JWT lease on /v1/enroll and /v1/refresh.
