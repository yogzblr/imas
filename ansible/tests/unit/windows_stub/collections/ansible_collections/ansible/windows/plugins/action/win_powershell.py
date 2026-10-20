"""A stand-in for ansible.windows.win_powershell, for test_imas_verify_windows.py.

It runs on the controller and plays back, per kind of call (the role's
warm-up, its check, its log read), the outcomes listed in the JSON file
$IMAS_STUB_SCENARIO: {"warmup": [...], "check": [...], "log": [...]}. The last
outcome repeats. "unreachable" raises the error the winrm connection plugin
raised in UAT Run 2; a check outcome is "connected", "enrolled" (enrolled and
running, no bus connection) or "none" (not enrolled); "check_seconds" makes
each check take that long. Every call is appended
to $IMAS_STUB_CALLS, one kind per line.
"""

from __future__ import annotations

import json
import os
import time

from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.action import ActionBase

READ_TIMEOUT = (
    "ntlm: HTTPSConnectionPool(host='127.0.0.1', port=55986): Read timed out. (read timeout=300)"
)


def _kind(params: dict) -> str:
    if "UserJwtFile" in params:
        return "check"
    if "Log" in params:
        return "log"
    return "warmup"


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        super().run(tmp, task_vars)
        kind = _kind(self._task.args.get("parameters") or {})
        with open(os.environ["IMAS_STUB_SCENARIO"], encoding="utf-8") as f:
            scenario = json.load(f)
        outcomes = scenario.get(kind) or ["ok"]
        calls_file = os.environ["IMAS_STUB_CALLS"]
        n = 0
        if os.path.exists(calls_file):
            with open(calls_file, encoding="utf-8") as f:
                n = sum(1 for line in f if line.strip() == kind)
        with open(calls_file, "a", encoding="utf-8") as f:
            f.write(kind + "\n")
        outcome = outcomes[min(n, len(outcomes) - 1)]
        if outcome == "unreachable":
            raise AnsibleConnectionFailure(READ_TIMEOUT)
        result = {"changed": False}
        if kind == "check":
            time.sleep(scenario.get("check_seconds", 0))
            enrolled = outcome in ("enrolled", "connected")
            result["result"] = {
                "enrolled": enrolled,
                "active": enrolled,
                "pid": 4242 if enrolled else 0,
                "bus_urls": ["wss://dmz.uat.imas.internal:8443"],
                "bus_urls_source": "enrollment",
                "endpoints": [{"host": "dmz.uat.imas.internal", "port": 8443}],
                "connections": ["10.0.0.5:50000>10.0.0.9:8443"] if outcome == "connected" else [],
                "connected": outcome == "connected",
            }
        elif kind == "log":
            result["result"] = ["stub sprout log line"]
        return result
