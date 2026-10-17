change: S4: a cook has a render budget of its own (security review B4): every render of one cook, include discovery and step building together, is charged to total render time (`IMAS_RECIPE_COOK_RENDER_TIMEOUT`, 10s, from `renderTimeout` to 5m), total rendered bytes (`IMAS_RECIPE_COOK_MAX_RENDERED_BYTES`, 8 MiB, up to 256 MiB) and total range iterations (`IMAS_RECIPE_COOK_MAX_RANGE_ITERATIONS`, 100000, up to 100000000); a cook over it fails with `ErrCookRenderBudget` before anything is staged. The include cap is a setting, `IMAS_RECIPE_MAX_INCLUDES` (default 64, 1 to 256); saasapi gets only that one and refuses an upload whose own include list is longer (`422 recipe_too_many_includes`). Helm keys under `farmer.recipes.templateLimits`. Ready for security review.
item: P3
action: update
next-append: **S4 built (2026-10-17):** per-cook render budget and include cap (`internal/cook` `cookBudget`, `farmer.recipes.templateLimits.cook*` and `maxIncludes`, farmer README "Per-cook render budget"); flagged for security review, item 6 of 3.4 stays open until reviewed.
---
item: P4
action: update
next-append: **B4 fixed by S4 (2026-10-17):** one render budget per cook (time, bytes, range iterations) and a 64-include cap, settable up to 256; waits on the security review.
---
item: P17
action: update
next-append: The include cap and the per-cook budget are tested since S4 (`internal/cook/cook_budget_test.go`).
