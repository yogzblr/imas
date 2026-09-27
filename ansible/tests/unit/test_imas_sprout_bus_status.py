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
