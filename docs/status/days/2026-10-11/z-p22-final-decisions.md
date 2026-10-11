change: Owner decided the last P22 questions (design D19 to D21): min_sprout_version stays unsigned; the sprout is the only GPG verifier; the packaged trust-root file is built from gpg-public-key.asc.
---
item: P22
action: update
next-append: **Final decisions (owner, 2026-10-11, design D19 to D21):** `min_sprout_version` unsigned and farmer-served, still enforced by the sprout; saasapi and farmer do not verify the GPG signature; packages ship `/etc/imas/fleet-signing-keys.asc` built from the repo's `gpg-public-key.asc`.
