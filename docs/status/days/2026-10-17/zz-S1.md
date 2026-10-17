change: S1 built: the bus loader reads its CA from a ConfigMap (loader.caConfigMap, written by the core bootstrap Job as natsTrust.busCAConfigMapName) and never mounts the bus TLS volume in either TLS mode; ready for review.
pr: 260
item: P3
action: update
next-append: **S1 (2026-10-17):** 3.3 item 1 built, ready for review (FLAG FOR SECURITY REVIEW): in `bus.tls.mode=openbao` the loader mounts `ca.crt` of ConfigMap `loader.caConfigMap` (default `imas-bus-ca`), copied from core's `natsTrust.busCAConfigMapName`, which `farmer bootstrap-nats-trust` writes from `<pki>/cert/ca`; the loader mounts no bus key in either mode. Stays open until reviewed.
