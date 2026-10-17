change: T1: sprout update safety. L3: the keyring, the cache directory and the staging directories are checked with `Lstat` by owner (the effective uid; on Windows SYSTEM or Administrators with no write ACE for anyone else, tested with a fake ACL reader), mode (0600 keyring, 0700 staging, no group or world write on `cachedir`) and symlink, refusal code `unsafe_path`; the staging root is created fresh for every update and checked again before the installer; the packages install the keyring 0600 and `check-package-contents.sh` checks it. L5: `packaging/test` parses the packaged keyring as the sprout does (`{}` allowed in the development tree, owner decision T1), and `release.yml` fails before the build on a keyring with no key and after GoReleaser when `checksums.txt.sig` does not verify against it (the sprout's own `fleetsign` code); owner step in `docs/RELEASING.md` "Fleet signing keyring". L6: the update manifest cache holds 256 entries per tenant (4096 in all), evicts only the tenant's own, and never caches a 404. L7: the designs, SaaS API docs and farmer's dispatch comment say tenant approval is change control, not a barrier against a compromised saasapi. I4: index 16 MiB, package 512 MiB or the size its index declares, 2-minute requests, a 10-minute update budget that releases the update lock (`sproutupdatemaxindexbytes`, `sproutupdatemaxpackagebytes`, `sproutupdaterequesttimeout`, `sproutupdatebudget`). I5: the unused `no_self_update` and `self_update` build tags removed from goreleaser, CI and packaging, and the text corrected. B8: on Windows the full version (prerelease included) from the MSI's file name must equal the manifest's; zypper's downgrade skip tested with a fake `zypper`. Flagged for security review.
pr: 273
item: P18
action: close
---
item: P4
action: update
next-append: **T1 (2026-10-17):** B8 fixed (the MSI's full version from its file name, rc and final told apart; zypper's skip run against a fake `zypper`); L3, L5, L6, L7, I4 and I5, the "Before dispatch is enabled" theme, are fixed; flagged for security review.
---
item: P17
action: update
next-append: **T1 (2026-10-17):** the `no_self_update` tag is gone from CI and packaging (I5), and `packaging/test` now parses the packaged keyring and gates the release on a key and a verifying `checksums.txt.sig` (L5).
