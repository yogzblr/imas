change: Local rig (uat/lite, WSL2, Docker Desktop) run on v0.1.0-rc.14 from the published charts and deb/rpm: smoke 10 pass; core 58 pass, 0 fail, 3 skip (T3, S6 clean re-enrol after purge, X5), no missing scenarios, RESULT PASS. Not run: resilience, lifecycle, ingredients, ha, Windows, X3. The S3 backlog_full, S4 render budget, S6 purge, U3 sealed payloads and U4 retention fixes have no acceptance case yet (W1).
---
item: P3
action: update
next-append: **Rig run (2026-10-19):** rc.14 installs from the published charts and packages and passes core on the local rig (58 pass, 0 fail, 3 skip). The update path (dispatch and self-update flags) was not exercised; it needs a UAT run with the flags on.
