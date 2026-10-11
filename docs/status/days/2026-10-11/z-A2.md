change: P22 slice 2 (A2): saasapi registers the release's checksums.txt and checksums.txt.sig (saas.fleet_release_checksums, migration 00007), farmer serves the seven-key manifest with no signature check of its own, the stamp script and publish workflow verify checksums.txt.sig with gpg, and fleetreleaser, its OpenBao policies and the read-only fleet key clients are retired.
item: P22
action: update
next-append: Slice 2 (server side, release stamping, fleetreleaser retirement) merged.
