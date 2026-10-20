change: W4: the UAT enrolment no longer loses a Windows sprout to a slow first WinRM call. UAT Run 2 (rc.15, imas-uat-vp7fs3mj) ended before any test because imas_verify's Windows poll hit the 120 s WinRM read timeout on t1-win and t2-win, both connected; Ansible reports that as UNREACHABLE and `until` never retries it. `uat/enroll/gen-inventory.py` now sets the WinRM read timeout to 300 s and the operation timeout to 240 s; `imas_verify` on Windows warms WinRM up, then polls in rounds that start again after an unreachable attempt until `imas_verify_timeout`, and reports a host that never answers as "WinRM did not answer", not as a sprout that did not connect. Tested against a stub win_powershell (`ansible/tests/unit/test_imas_verify_windows.py`).
pr: 300
---
item: P1
action: update
next-append: **W4 (2026-10-20):** Run 2 (rc.15) stopped at the Windows enrolment wait on a WinRM read timeout, with both Windows sprouts connected; fixed in the inventory's WinRM timeouts and `imas_verify`'s Windows wait. Re-run Run 2.
