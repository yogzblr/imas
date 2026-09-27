"""Unit tests for roles/imas_verify/library/imas_sprout_bus_status.py.

Run from ansible/: python -m pytest tests/unit
"""

import ipaddress
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "roles", "imas_verify", "library"))

import imas_sprout_bus_status as m  # noqa: E402

# A /proc/net/tcp table: an established connection 10.0.0.5:40000 ->
# 10.0.0.9:5406 (inode 111), one in TIME_WAIT (06) to the same port, and a
# listening socket.
PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0500000A:9C40 0900000A:151E 01 00000000:00000000 00:00000000 00000000     0        0 111 1 0 20 4 30 10 -1
   1: 0500000A:9C41 0900000A:151E 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0
"""

# /proc/net/tcp6: an IPv4-mapped connection to 10.0.0.9:443 (inode 333) and
# a native one to 2001:db8::1:4222 (inode 444).
PROC_NET_TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000500000A:9C42 0000000000000000FFFF00000900000A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 333 1 0
   1: B80D0120000000000000000001000000:9C43 B80D0120000000000000000001000000:107E 01 00000000:00000000 00:00000000 00000000     0        0 444 1 0
"""


def test_parse_proc_net_tcp_keeps_established_only():
    assert m.parse_proc_net_tcp(PROC_NET_TCP) == {"111": (ipaddress.ip_address("10.0.0.9"), 5406)}


def test_parse_proc_net_tcp6_unmaps_ipv4():
    assert m.parse_proc_net_tcp(PROC_NET_TCP6) == {
        "333": (ipaddress.ip_address("10.0.0.9"), 443),
        "444": (ipaddress.ip_address("2001:db8::1"), 4222),
    }


@pytest.mark.parametrize("url,want", [
    ("tls://bus.example.com:5406", ("bus.example.com", 5406)),
    ("nats://bus.example.com", ("bus.example.com", 4222)),
    ("wss://bus.example.com", ("bus.example.com", 443)),
    ("WSS://bus.example.com:8443/path", ("bus.example.com", 8443)),
    ("farmer.example.com:5406", ("farmer.example.com", 5406)),
    ("tls://[2001:db8::1]:5406", ("2001:db8::1", 5406)),
    ("gopher://bus.example.com", None),
])
def test_endpoint(url, want):
    assert m.endpoint(url) == want


def test_resolve_bus_urls_prefers_the_pin(tmp_path):
    saved = tmp_path / "bus-urls.json"
    saved.write_text(json.dumps(["wss://saved:443"]))
    assert m.resolve_bus_urls([" tls://pin:5406 ", ""], str(saved), "farmer:5406") == (["tls://pin:5406"], "config")


def test_resolve_bus_urls_then_enrollment(tmp_path):
    saved = tmp_path / "bus-urls.json"
    saved.write_text(json.dumps(["wss://saved:443"]))
    assert m.resolve_bus_urls([], str(saved), "farmer:5406") == (["wss://saved:443"], "enrollment")


@pytest.mark.parametrize("content", [None, "not json", "[]", '{"a": 1}'])
def test_resolve_bus_urls_then_legacy(tmp_path, content):
    saved = tmp_path / "bus-urls.json"
    if content is not None:
        saved.write_text(content)
    assert m.resolve_bus_urls([], str(saved), "farmer:5406") == (["farmer:5406"], "legacy")


def test_resolve_bus_urls_none(tmp_path):
    assert m.resolve_bus_urls([], str(tmp_path / "missing"), ":") == ([], "none")


def test_bus_connections_matches_port_and_address():
    ip = ipaddress.ip_address
    conns = {
        "1": (ip("10.0.0.9"), 5406),   # the bus
        "2": (ip("10.0.0.9"), 5405),   # farmer's API, same host
        "3": (ip("10.9.9.9"), 5406),   # right port, another host
    }
    endpoints = [("bus.example.com", 5406)]
    assert m.bus_connections(conns, endpoints, {"bus.example.com": {ip("10.0.0.9")}}) == {"1"}
    # A host that doesn't resolve here matches on port alone.
    assert m.bus_connections(conns, endpoints, {"bus.example.com": set()}) == {"1", "3"}


def write_status(path, **status):
    path.write_text(json.dumps(status))


CONNECTED = {"state": "connected", "server": "tls://bus:443", "since": "2026-09-27T10:00:00Z", "pid": 42}


def test_read_status_file(tmp_path):
    path = tmp_path / "bus-status.json"
    assert m.read_status_file(str(path)) is None
    for bad in ("not json", "[]", '{"pid": 42}', '{"state": 1}'):
        path.write_text(bad)
        assert m.read_status_file(str(path)) is None, bad
    write_status(path, **CONNECTED)
    assert m.read_status_file(str(path)) == CONNECTED


def test_recorded_connection_connected(tmp_path):
    path = tmp_path / "bus-status.json"
    write_status(path, **CONNECTED)
    slept = []
    assert m.recorded_connection(str(path), 42, 5, sleep=slept.append) == (True, True, CONNECTED)
    assert slept == [5]


@pytest.mark.parametrize("pid", [0, 7])
def test_recorded_connection_ignores_another_process(tmp_path, pid):
    # A sprout that died (or pid 0: the service isn't running) left
    # "connected" behind: not usable, so the caller falls back.
    path = tmp_path / "bus-status.json"
    write_status(path, **CONNECTED)
    assert m.recorded_connection(str(path), pid, 5, sleep=pytest.fail) == (False, False, CONNECTED)


def test_recorded_connection_missing_file(tmp_path):
    assert m.recorded_connection(str(tmp_path / "none"), 42, 5, sleep=pytest.fail) == (False, False, None)


@pytest.mark.parametrize("state", ["starting", "disconnected", "stopped"])
def test_recorded_connection_not_connected(tmp_path, state):
    # Usable, so the caller must not fall back to the TCP check: that is
    # what would mistake the enrollment keep-alive for the bus.
    path = tmp_path / "bus-status.json"
    status = dict(CONNECTED, state=state, error="EOF")
    write_status(path, **status)
    assert m.recorded_connection(str(path), 42, 5, sleep=pytest.fail) == (True, False, status)


@pytest.mark.parametrize("later", [
    dict(CONNECTED, state="disconnected"),
    # Reconnected within hold: it didn't stay up.
    dict(CONNECTED, since="2026-09-27T10:00:03Z"),
    # The sprout restarted within hold.
    dict(CONNECTED, pid=43),
    None,
])
def test_recorded_connection_must_hold(tmp_path, later):
    path = tmp_path / "bus-status.json"
    write_status(path, **CONNECTED)

    def change(_):
        if later is None:
            path.unlink()
        else:
            write_status(path, **later)

    usable, connected, status = m.recorded_connection(str(path), 42, 5, sleep=change)
    assert (usable, connected, status) == (True, False, later)


def check_params(tmp_path, **over):
    jwt = tmp_path / "sprout.jwt"
    jwt.write_text("jwt")
    p = dict(
        status_file=str(tmp_path / "bus-status.json"),
        service="imas-sprout",
        user_jwt_file=str(jwt),
        bus_urls_file=str(tmp_path / "bus-urls.json"),
        bus_urls=["tls://127.0.0.1:443"],
        legacy_bus_url="farmer:5406",
        hold=5,
    )
    p.update(over)
    return p


# The enrollment client's HTTPS keep-alive to the same host:port as the bus:
# what the TCP check alone takes for a bus connection.
KEEPALIVE = {"9": (ipaddress.ip_address("127.0.0.1"), 443)}


def test_check_uses_the_status_file(tmp_path):
    write_status(tmp_path / "bus-status.json", **CONNECTED)
    r = m.check(check_params(tmp_path), service_state=lambda _: (True, 42),
                established=pytest.fail, sleep=lambda _: None)
    assert r["connected"] and r["status_source"] == "status_file"
    assert r["bus_status"] == CONNECTED
    assert (r["bus_urls"], r["bus_urls_source"]) == (["tls://127.0.0.1:443"], "config")


def test_check_status_file_beats_the_keepalive(tmp_path):
    # Still enrolling (starting), with the keep-alive open: not connected,
    # and the sockets aren't even looked at.
    write_status(tmp_path / "bus-status.json", **dict(CONNECTED, state="starting"))
    r = m.check(check_params(tmp_path), service_state=lambda _: (True, 42),
                established=lambda _: KEEPALIVE, sleep=lambda _: None)
    assert not r["connected"] and r["status_source"] == "status_file"
    assert r["connections"] == []


@pytest.mark.parametrize("status", [None, dict(CONNECTED, pid=7)])
def test_check_falls_back_to_tcp(tmp_path, status):
    # No status file (an older sprout), or one another process left.
    if status:
        write_status(tmp_path / "bus-status.json", **status)
    r = m.check(check_params(tmp_path), service_state=lambda _: (True, 42),
                established=lambda _: KEEPALIVE, sleep=lambda _: None)
    assert r["connected"] and r["status_source"] == "tcp"
    assert r["connections"] == [{"ip": "127.0.0.1", "port": 443}]
    assert r["bus_status"] == status


def test_check_service_not_running(tmp_path):
    write_status(tmp_path / "bus-status.json", **dict(CONNECTED, state="stopped"))
    r = m.check(check_params(tmp_path), service_state=lambda _: (False, 0),
                established=pytest.fail, sleep=pytest.fail)
    assert not r["connected"] and r["status_source"] == "none"
    assert r["bus_status"]["state"] == "stopped"


def test_check_not_enrolled(tmp_path):
    p = check_params(tmp_path, user_jwt_file=str(tmp_path / "missing"))
    write_status(tmp_path / "bus-status.json", **CONNECTED)
    r = m.check(p, service_state=lambda _: (True, 42), established=pytest.fail, sleep=pytest.fail)
    assert not r["enrolled"] and not r["connected"] and r["status_source"] == "none"
