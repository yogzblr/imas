change: W18: the imas_sprout role's Windows install can run a second time. The installer download used win_get_url with force false and no checksum, which still sends a HEAD for Last-Modified when the file exists, and Buildkite's NuGet flat container answers HEAD with 404 (GET works). Re-running enrolment on the local HA environment for v0.1.0-rc.23 failed on both Windows sprouts at that step. The role now checks for the file first and downloads only when it is missing, or always when a checksum is given, so win_get_url verifies it. Proven by re-running enrolment on the same environment.
item: P24
action: update
next-append: **W18 (2026-11-09):** a second run of the imas_sprout role on Windows failed on Buildkite's 404 answer to HEAD for the nupkg; it now skips a download it already has.
pr: 333
