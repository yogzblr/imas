"""Runs roles/imas_verify's Windows path with ansible-playbook, against a
stand-in ansible.windows.win_powershell (windows_stub/collections) that can
fail a call the way WinRM did in UAT Run 2: a read timeout, which Ansible
reports as UNREACHABLE and `until` never retries.

Run from ansible/: python -m pytest tests/unit (needs ansible-playbook on PATH).
"""

import json
import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(HERE, "windows_stub")
ROLES = os.path.join(HERE, "..", "..", "roles")


def run_verify(tmp_path, scenario, timeout=4, interval=1):
    ansible_playbook = shutil.which("ansible-playbook")
    assert ansible_playbook, "ansible-playbook is not on PATH (pip install ansible-core)"
    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(json.dumps(scenario))
    calls = tmp_path / "calls"
    outcome = tmp_path / "outcome.json"
    inventory = tmp_path / "hosts"
    inventory.write_text("win ansible_connection=local\n")
    # Not ansible/ansible.cfg: nothing but what is set here.
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    env = dict(
        os.environ,
        ANSIBLE_CONFIG=str(config),
        ANSIBLE_ROLES_PATH=ROLES,
        ANSIBLE_COLLECTIONS_PATH=os.path.join(STUB, "collections"),
        ANSIBLE_LOCALHOST_WARNING="false",
        ANSIBLE_INVENTORY_UNPARSED_WARNING="false",
        IMAS_STUB_SCENARIO=str(scenario_file),
        IMAS_STUB_CALLS=str(calls),
        IMAS_STUB_OUTCOME=str(outcome),
    )
    p = subprocess.run(
        [
            ansible_playbook, "-i", str(inventory), os.path.join(STUB, "verify.yml"),
            "-e", json.dumps({"imas_verify_timeout": timeout, "imas_verify_interval": interval, "imas_verify_hold": 0}),
        ],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    made = calls.read_text().split() if calls.exists() else []
    return json.loads(outcome.read_text()), made, p.stdout


def test_connected_first_time(tmp_path):
    out, calls, _ = run_verify(tmp_path, {"check": ["connected"]})
    assert out["passed"], out
    assert calls == ["warmup", "check"]


def test_slow_first_call_is_absorbed(tmp_path):
    # UAT Run 2: the first call on a fresh VM outlasts the read timeout.
    out, calls, stdout = run_verify(tmp_path, {"warmup": ["unreachable", "ok"], "check": ["connected"]})
    assert out["passed"], out
    assert calls == ["warmup", "warmup", "check"]
    assert "UNREACHABLE" in stdout


def test_unreachable_check_is_retried(tmp_path):
    out, calls, _ = run_verify(tmp_path, {"check": ["enrolled", "unreachable", "connected"]})
    assert out["passed"], out
    # A not-yet result retries within the task; the unreachable one starts a
    # new round, warm-up included.
    assert calls == ["warmup", "check", "check", "warmup", "check"]


def test_never_answers_is_reported_as_unreachable(tmp_path):
    out, calls, _ = run_verify(tmp_path, {"warmup": ["unreachable"], "log": ["unreachable"]}, timeout=3)
    assert not out["passed"], out
    assert out["task"] == "Fail with the reason the sprout isn't connected"
    assert out["msg"][0].startswith("WinRM to this host did not answer")
    assert "Read timed out" in out["msg"][1]
    assert not any("has not enrolled" in line for line in out["msg"])
    assert out["msg"][-1].startswith("(could not read the sprout log: ")
    # Rounds stop at the deadline: one at the start, then about one a second.
    assert "check" not in calls
    assert 2 <= calls.count("warmup") <= 6, calls


def test_reachable_but_not_connected_keeps_its_reason(tmp_path):
    out, calls, _ = run_verify(tmp_path, {"check": ["none"]}, timeout=2)
    assert not out["passed"], out
    assert out["msg"][0].startswith("imas-sprout has not enrolled after 2s")
    assert out["msg"][-1] == "stub sprout log line"
    # Polled with until in one round: no second warm-up.
    assert calls.count("warmup") == 1
    assert calls.count("check") >= 2


def test_enrolled_but_not_connected(tmp_path):
    out, _, _ = run_verify(tmp_path, {"check": ["enrolled"]}, timeout=2)
    assert not out["passed"], out
    assert out["msg"][0].startswith("imas-sprout is enrolled and running, but has held no connection")



def test_slow_checks_stop_at_the_deadline(tmp_path):
    # retries alone would allow ceil(2 / 1) = 2 more checks of 3 s each.
    out, calls, _ = run_verify(tmp_path, {"check": ["enrolled"], "check_seconds": 3}, timeout=2)
    assert not out["passed"], out
    assert calls.count("check") == 1, calls
