#!/usr/bin/python
# Copyright (C) the imas contributors. SPDX-License-Identifier: 0BSD
"""Report whether a Linux imas-sprout is enrolled and connected to its bus."""

from __future__ import annotations

DOCUMENTATION = r"""
module: imas_sprout_bus_status
short_description: Report whether imas-sprout is enrolled and connected to the bus
description:
  - The sprout keeps no record of its bus connection, so this looks at what it
    leaves behind. It is enrolled when its NATS User JWT is on disk (what
    C(pki.SproutEnrolled) checks). It is connected when the service's main
    process has an established TCP connection to one of the bus addresses it
    connects to, and the same connection is still established I(hold) seconds
    later, so a connection attempt the bus then rejects doesn't count.
  - The bus addresses are resolved the way the sprout does
    (C(pki.ResolveSproutBusURLs)): the C(busurls) pin, else the C(nats_urls)
    saved at enrollment, else C(farmerinterface:farmerbusport).
  - Linux only; reads C(/proc) and C(systemctl). Never changes anything.
options:
  service:
    description: systemd unit of the sprout.
    type: str
    default: imas-sprout
  user_jwt_file:
    description: The sprout's NATS User JWT (C(sproutuserjwtfile)).
    type: path
    required: true
  bus_urls_file:
    description: The C(nats_urls) saved at enrollment (C(sproutbusurlsfile)).
    type: path
    required: true
  bus_urls:
    description: The C(busurls) pin from the sprout's config file.
    type: list
    elements: str
    default: []
  legacy_bus_url:
    description: C(farmerinterface:farmerbusport) from the sprout's config file.
    type: str
    default: ""
  hold:
    description: Seconds a connection must stay established to count.
    type: int
    default: 5
"""

RETURN = r"""
enrolled: {description: The sprout's NATS User JWT exists., type: bool, returned: always}
active: {description: The service is active., type: bool, returned: always}
pid: {description: The service's main PID (0 if not running)., type: int, returned: always}
bus_urls: {description: The bus addresses the sprout connects to., type: list, returned: always}
bus_urls_source: {description: Where they came from (config, enrollment, legacy)., type: str, returned: always}
endpoints: {description: Those addresses as host and port., type: list, returned: always}
connections: {description: The main process's established TCP connections., type: list, returned: always}
connected: {description: One of them is to a bus endpoint and stayed up for hold seconds., type: bool, returned: always}
"""

import ipaddress
import json
import os
import socket
import subprocess
import time
from urllib.parse import urlsplit

from ansible.module_utils.basic import AnsibleModule

# Ports a bus URL without one gets: nats.go's default for nats:// and
# tls://, and the scheme's own for websockets.
DEFAULT_PORTS = {"nats": 4222, "tls": 4222, "wss": 443, "ws": 80}

TCP_ESTABLISHED = "01"


def resolve_bus_urls(pin, urls_file, legacy):
    """Mirror pki.ResolveSproutBusURLs: pin, then enrollment, then legacy."""
    pin = [u.strip() for u in pin or [] if u and u.strip()]
    if pin:
        return pin, "config"
    try:
        with open(urls_file) as f:
            saved = json.load(f)
    except FileNotFoundError:
        saved = None
    except (OSError, ValueError):
        saved = None
    if isinstance(saved, list):
        saved = [u.strip() for u in saved if isinstance(u, str) and u.strip()]
        if saved:
            return saved, "enrollment"
    if legacy and legacy.strip(":"):
        return [legacy], "legacy"
    return [], "none"


def endpoint(url):
    """Split a bus URL (scheme://host[:port] or bare host:port) into (host, port)."""
    if "://" not in url:
        url = "nats://" + url
    parts = urlsplit(url)
    port = parts.port or DEFAULT_PORTS.get(parts.scheme.lower())
    if not parts.hostname or not port:
        return None
    return parts.hostname, port


def resolve_ips(host):
    """The addresses host resolves to, as ip_address objects (empty if it doesn't)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return set()
    return {ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos}


def decode_address(hex_addr):
    """Decode a /proc/net/tcp{,6} "ADDR:PORT" (hex, host byte order words)."""
    addr, port = hex_addr.split(":")
    raw = bytes.fromhex(addr)
    # Each 32-bit word is in the kernel's (little-endian) byte order.
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    ip = ipaddress.ip_address(raw)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip, int(port, 16)


def parse_proc_net_tcp(text):
    """Established sockets in a /proc/net/tcp{,6} table: {inode: (ip, port)}."""
    out = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != TCP_ESTABLISHED:
            continue
        out[fields[9]] = decode_address(fields[2])
    return out


def socket_inodes(pid):
    """Inodes of the sockets pid has open."""
    inodes = set()
    fd_dir = "/proc/%d/fd" % pid
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return inodes
    for fd in fds:
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except OSError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[len("socket:["):-1])
    return inodes


def established(pid):
    """pid's established TCP connections: {inode: (remote ip, remote port)}."""
    remote = {}
    for table in ("tcp", "tcp6"):
        try:
            with open("/proc/%d/net/%s" % (pid, table)) as f:
                remote.update(parse_proc_net_tcp(f.read()))
        except OSError:
            continue
    mine = socket_inodes(pid)
    return {inode: addr for inode, addr in remote.items() if inode in mine}


def bus_connections(conns, endpoints, ips):
    """The inodes in conns that go to a bus endpoint.

    A connection matches an endpoint on port, and on address when the
    endpoint's host resolved (it may not resolve on the host itself, e.g.
    behind a proxy); ips maps host -> set of addresses.
    """
    out = set()
    for inode, (ip, port) in conns.items():
        for host, ep_port in endpoints:
            if port == ep_port and (not ips.get(host) or ip in ips[host]):
                out.add(inode)
    return out


def service_state(service):
    """(active, main pid) of a systemd unit."""
    try:
        out = subprocess.run(
            ["systemctl", "show", "--property=ActiveState,MainPID", service],
            check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return False, 0
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return props.get("ActiveState") == "active", int(props.get("MainPID") or 0)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            service=dict(type="str", default="imas-sprout"),
            user_jwt_file=dict(type="path", required=True),
            bus_urls_file=dict(type="path", required=True),
            bus_urls=dict(type="list", elements="str", default=[]),
            legacy_bus_url=dict(type="str", default=""),
            hold=dict(type="int", default=5),
        ),
        supports_check_mode=True,
    )
    p = module.params
    enrolled = os.path.exists(p["user_jwt_file"])
    active, pid = service_state(p["service"])
    urls, source = resolve_bus_urls(p["bus_urls"], p["bus_urls_file"], p["legacy_bus_url"])
    endpoints = [e for e in (endpoint(u) for u in urls) if e]
    ips = {host: resolve_ips(host) for host, _ in endpoints}

    conns, connected = {}, False
    if enrolled and active and pid and endpoints:
        conns = established(pid)
        first = bus_connections(conns, endpoints, ips)
        if first:
            time.sleep(max(p["hold"], 0))
            later = bus_connections(established(pid), endpoints, ips)
            connected = bool(first & later)

    module.exit_json(
        changed=False,
        enrolled=enrolled,
        active=active,
        pid=pid,
        bus_urls=urls,
        bus_urls_source=source,
        endpoints=[{"host": h, "port": port} for h, port in endpoints],
        connections=[{"ip": str(ip), "port": port} for ip, port in conns.values()],
        connected=connected,
    )


if __name__ == "__main__":
    main()
