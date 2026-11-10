change: W20: the UAT gate workflow (uat.yml) runs on ubuntu-24.04 instead of ubuntu-latest (owner, 2026-11-10). ubuntu-latest moved to ubuntu-26.04 on 2026-11-09 and broke a k0s unit test on OpenSSL's subject spelling (W19, PR 334); the gate's scripts were last proven on 24.04's tools, so it moves to a new image on purpose, with a UAT run. The janitor stays on ubuntu-latest (it only calls az).
item: P24
action: update
next-append: **W20 (2026-11-10):** uat.yml pinned to ubuntu-24.04.
