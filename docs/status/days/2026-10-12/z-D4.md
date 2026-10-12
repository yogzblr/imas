change: D4 (P21 slice 3 PR 4): farmer's NKey comes from a shared Secret. Every replica mounts `farmer.nkeySecret` (default `imas-farmer-nkey`, key `farmer.nk`) read-only and reads it from `IMAS_FARMER_NKEY_SEED_FILE`; ESO syncs it from the seed path, property `farmer_nkey`. `certs.GenNKey` is out of farmer's start path (`GenNKey(true)` refuses), farmer fails to start without the seed, and the `nkeyfarmer*file` ConfigMap keys are gone. The SYS_USER seed (B7) was already read from `IMAS_NATS_SYS_USER_SEED_FILE`; no change. UAT's `seeds.sh` must now also create the farmer NKey Secret. Flagged for security review.
pr: 228
item: P21
action: update
next-append: **Slice 3 PR 4 (D4), ready for review:** farmer NKey from a shared Secret (`farmer.nkeySecret`, `IMAS_FARMER_NKEY_SEED_FILE`); UAT seeds still to add it.
