change: V3 (P11, P14, P4, P17): findings table moved out of BUILD-STATUS into `docs/security-findings-status.md`, one row per finding of both 2026-10 reviews with its state on main and its pinning test, checked by reading the code. None is open on main: V1 (PR #286) fixed the last, L16, I1, I8, I9 and I12, and their rows name V1's tests. P11 triaged (53 follow-ups of the archive's Open item 10, table in the same document). Built: the four farmer-only `internal.sprout.action` codes moved into `internal/controlplane`; a deleted sprout's stored User JWT row and object are deleted; `imas cook` exits 1 on a failed, timed-out or incomplete cook; `props.static` can't set reserved fact names; dead `RegisterNatsConn`, `HTestPing` and hostname helpers removed; `pki.UseInMemoryJoinToken` panics outside tests; `saasapi.pdb.maxUnavailable` bounds; `credentialPublisher.extraEnv`; one shared sealed-wire test helper; `-count`-safe in-memory test databases; docs (I3 proxy note, sprout namespaces, RELEASING step 4, orchestration and API design). Issues #138, #139 and #142 verified on main and commented. Ready for security review.
item: P11
action: close
pr: 287
---
item: P14
action: close
pr: 287
---
item: P17
action: close
pr: 287
---
item: P4
action: update
next-append: **V3 (2026-10-18):** every finding's state on main is in `docs/security-findings-status.md` (the "Review findings re-checked" section moved there). No finding is open on main (V1, PR #286, fixed L16, I1, I8, I9 and I12). Every finding is fixed or accepted, with its pinning test or the reason it has none (L7, I3: documentation).
pr: 287
---
item: P3
action: update
next-append: **V3 adds to the review scope (2026-10-18):** `DeleteNKey` now also deletes the deleted sprout's stored User JWT row and object (`internal/pki` `forgetSproutUserJWT`, keyed on tenant and sprout), and `cmd/farmer` drops reserved fact names from `props.static`.
pr: 287
