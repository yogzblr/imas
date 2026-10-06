#!/usr/bin/env python3
"""Write the Ansible inventory that enrolls the UAT sprouts with ansible/site.yml.

Input is the uat JSON of plan section 4h's Shared contract (``tofu output
-json uat``), the access.json written by ``uat/access/tunnels.sh open`` (or the
local rig's equivalent) and the key files ``create-tenants.sh`` wrote. Output,
in --out:

  hosts.yml                 the inventory: groups sprouts (linux_sprouts,
                            windows_sprouts), tenant_1/tenant_2, os_*, conn_*
  group_vars/<group>.yml    package pin, Envoy address, UAT CA, connections
  plan.json                 what each sprout should become (no secrets)

No secret is copied into the inventory: the enrollment key, the UAT CA and the
WinRM password are read on the controller at run time through
``lookup('ansible.builtin.file', <path>)``, and the SSH key by path.

Every sprout of one OS gets the same sprout ID in both tenants (ubuntu-01,
alma-01, win-01, numbered in VM name order when a tenant has several), so a
run also proves sprout_id is unique per tenant only.

Standard library only; Python 3.8 or later.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

RELEASE_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)(?:-(rc\.\d+))?$")
VM_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ORG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# OS -> (sprout ID prefix, OS family group, connections it may use).
OSES = {
    "ubuntu": ("ubuntu", "linux_sprouts", ("ssh", "docker")),
    "alma": ("alma", "linux_sprouts", ("ssh", "docker")),
    "windows": ("win", "windows_sprouts", ("winrm",)),
}



class InputError(Exception):
    """Bad input: reported as one line, exit code 1."""


def package_versions(release_tag: str, metadata: str) -> tuple[str, str]:
    """Return (Linux package version, Windows release) for a release tag.

    Linux: the version as the apt and rpm repositories list it. nfpm writes a
    prerelease after "~" and goreleaser's version_metadata after "+"
    (.goreleaser.yaml; internal/ingredients/selfupdate/pkgmeta.go), so
    v0.1.0-rc.4 is 0.1.0~rc.4+git and v1.2.3 is 1.2.3+git.

    Windows: the NuGet package version on imasnget (build-winget-nupkg.sh:
    the tag without its "v" and build metadata), 0.1.0-rc.4 or 1.2.3. The
    role fetches that version's .nupkg directly, so a prerelease installs
    even though the role's "newest" lookup would skip it.
    """
    m = RELEASE_TAG_RE.match(release_tag)
    if not m:
        raise InputError(
            f"release tag {release_tag!r} is not vX.Y.Z or vX.Y.Z-rc.N (never 'latest')"
        )
    core, pre = m.group(1), m.group(2)
    linux = core + (f"~{pre}" if pre else "") + (f"+{metadata}" if metadata else "")
    windows = core + (f"-{pre}" if pre else "")
    return linux, windows


def tenant_number(raw) -> int:
    s = str(raw).strip().lower()
    if s.startswith("t"):
        s = s[1:]
    if s not in ("1", "2"):
        raise InputError(f"tenant {raw!r} is not 1 or 2")
    return int(s)


def access_entry(access: dict, vm: str) -> dict:
    if isinstance(access.get("vms"), dict):
        access = access["vms"]
    entry = access.get(vm)
    return entry if isinstance(entry, dict) else {}


def port(entry: dict, key: str, vm: str) -> int:
    value = entry.get(key)
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise InputError(f"access.json has no {key} for {vm}: is its tunnel open?") from None
    if not 0 < p < 65536:
        raise InputError(f"access.json {key} for {vm} is out of range: {p}")
    return p


def lookup_file(path: str) -> str:
    """A template reading path on the controller when the play runs."""
    if re.search(r"['\"\\{}%\n]", path):
        raise InputError(f"path {path!r} has a quote, backslash, brace or percent sign")
    return "{{ lookup('ansible.builtin.file', '%s') }}" % path


def plan_sprouts(uat: dict) -> list[dict]:
    """Validate the sprouts of the uat JSON and assign each a sprout ID."""
    sprouts = uat.get("sprouts")
    if not isinstance(sprouts, dict) or not sprouts:
        raise InputError("the uat JSON has no sprouts map")
    run_id = uat.get("run_id")
    if not isinstance(run_id, str) or not re.match(r"^[a-z0-9]{6,10}$", run_id):
        raise InputError(f"the uat JSON's run_id {run_id!r} is not 6 to 10 lowercase letters and digits")
    planned = []
    for vm in sorted(sprouts):
        s = sprouts[vm]
        if not VM_RE.match(vm):
            raise InputError(f"VM name {vm!r} is not a plain host name")
        if not isinstance(s, dict):
            raise InputError(f"sprout {vm} is not an object")
        os_name = str(s.get("os", "")).lower()
        if os_name not in OSES:
            raise InputError(f"sprout {vm}: os {s.get('os')!r} is not one of {', '.join(OSES)}")
        conn = str(s.get("connection", "")).lower()
        allowed = OSES[os_name][2]
        if conn not in allowed:
            raise InputError(
                f"sprout {vm}: connection {s.get('connection')!r} is not supported for {os_name} "
                f"(use {' or '.join(allowed)})"
            )
        planned.append(
            {
                "vm": vm,
                "tenant": tenant_number(s.get("tenant")),
                "os": os_name,
                "connection": conn,
                "admin_user": s.get("admin_user") or "",
                # uat/tests/harness's DefaultAssetID: asset ids are global in
                # saasapi, so the run id keeps two runs' links apart.
                "asset_id": f"uat-{run_id}-{vm}",
            }
        )
    # The same sprout ID for the same OS in each tenant: per (tenant, OS), in
    # VM name order, <prefix>-01, <prefix>-02, ...
    counters: dict[tuple[int, str], int] = {}
    for p in planned:
        k = (p["tenant"], p["os"])
        counters[k] = counters.get(k, 0) + 1
        p["sprout_id"] = f"{OSES[p['os']][0]}-{counters[k]:02d}"
    return planned


def build(args) -> tuple[dict, dict, dict, str | None]:
    """Return (hosts.yml, group_vars by group, plan.json, known hosts path)."""
    with open(args.uat, encoding="utf-8") as f:
        uat = json.load(f)
    access = {}
    if args.access:
        with open(args.access, encoding="utf-8") as f:
            access = json.load(f)
    linux_version, windows_version = package_versions(args.release_tag, args.package_metadata)
    planned = plan_sprouts(uat)

    farmer_host = args.envoy_host or (uat.get("dmz") or {}).get("fqdn")
    if not farmer_host or re.search(r"://|/|\s", farmer_host):
        raise InputError("no Envoy host: pass --envoy-host or set dmz.fqdn in the uat JSON")
    keys_dir = os.path.abspath(args.keys_dir)
    ca_file = os.path.abspath(args.ca_file)
    if not os.path.isfile(ca_file):
        raise InputError(f"UAT CA file not found: {ca_file}")
    if args.buildkite_org and not ORG_RE.match(args.buildkite_org):
        raise InputError(f"bad Buildkite organization {args.buildkite_org!r}")
    if bool(args.windows_msi_url) != bool(args.windows_msi_sha256):
        raise InputError("--windows-msi-url and --windows-msi-sha256 go together")
    if args.windows_msi_url and not args.windows_msi_url.startswith("https://"):
        raise InputError("--windows-msi-url must be https://")
    if args.windows_msi_sha256 and not SHA256_RE.match(args.windows_msi_sha256):
        raise InputError("--windows-msi-sha256 must be 64 lowercase hex digits")

    conns = {p["connection"] for p in planned}
    ssh_key = known_hosts = None
    if "ssh" in conns:
        if not args.ssh_key:
            raise InputError("SSH sprouts need --ssh-key (the per run private key)")
        ssh_key = os.path.abspath(args.ssh_key)
        known_hosts = os.path.abspath(args.known_hosts or os.path.join(args.out, "..", "ssh", "known_hosts"))
    if "winrm" in conns and not (args.winrm_password_file or args.winrm_password_dir):
        raise InputError("WinRM sprouts need --winrm-password-file or --winrm-password-dir")
    if "docker" in conns and not args.docker_connection:
        # The owner dropped community.docker (2026-10-06) and no replacement
        # is chosen yet: name one, don't assume one.
        raise InputError(
            "docker sprouts need --docker-connection PLUGIN: community.docker is not used "
            "(owner decision), and which connection replaces it is open (see README.md)"
        )
    if args.docker_connection and not re.match(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$", args.docker_connection):
        raise InputError(f"--docker-connection {args.docker_connection!r} is not a connection plugin name")

    hosts: dict[str, dict] = {}
    groups: dict[str, list[str]] = {}
    summary: dict[str, dict] = {}
    for p in planned:
        vm = p["vm"]
        key_file = os.path.join(keys_dir, vm + ".key")
        if not os.path.isfile(key_file):
            raise InputError(f"no enrollment key for {vm}: {key_file} (run create-tenants.sh first)")
        entry = access_entry(access, vm)
        hv: dict = {}
        if p["connection"] == "ssh":
            hv["ansible_host"] = entry.get("host") or "127.0.0.1"
            hv["ansible_port"] = port(entry, "ssh_port", vm)
            hv["ansible_user"] = p["admin_user"] or args.default_user
            # Every tunnel is 127.0.0.1 on another port, and a port may be a
            # different VM next run: record keys under the VM name instead.
            hv["ansible_ssh_extra_args"] = f"-o HostKeyAlias={vm}"
        elif p["connection"] == "winrm":
            hv["ansible_host"] = entry.get("host") or "127.0.0.1"
            hv["ansible_port"] = port(entry, "winrm_port", vm)
            hv["ansible_user"] = p["admin_user"] or args.default_user
            if args.winrm_password_dir:
                hv["ansible_password"] = lookup_file(os.path.join(os.path.abspath(args.winrm_password_dir), vm))
        else:  # docker: the local rig's systemd containers
            hv["ansible_host"] = entry.get("container") or vm
        hv.update(
            {
                "imas_join_token": lookup_file(key_file),
                "uat_tenant": p["tenant"],
                "uat_os": p["os"],
                "uat_sprout_id": p["sprout_id"],
                "uat_asset_id": p["asset_id"],
            }
        )
        hosts[vm] = hv
        for g in (OSES[p["os"]][1], f"tenant_{p['tenant']}", f"os_{p['os']}", f"conn_{p['connection']}"):
            groups.setdefault(g, []).append(vm)
        summary[vm] = {
            k: p[k] for k in ("tenant", "os", "connection", "sprout_id", "asset_id")
        }

    def group(name: str) -> dict:
        return {"hosts": {h: hosts[h] for h in groups.get(name, [])}}

    children: dict = {}
    for fam in ("linux_sprouts", "windows_sprouts"):
        if fam in groups:
            children[fam] = group(fam)
    inventory = {"all": {"children": {"sprouts": {"children": children}}}}
    for name in sorted(groups):
        if name not in children:
            # Hosts are listed (with their vars) once, under sprouts; these
            # groups only name them.
            inventory["all"]["children"][name] = {"hosts": {h: None for h in groups[name]}}

    gv: dict[str, dict] = {}
    sprouts_vars = {
        "uat_run_id": uat["run_id"],
        "uat_release_tag": args.release_tag,
        # farmerinterface/farmerapiport: the sprout talks only to Envoy.
        "imas_farmer_host": farmer_host,
        "imas_farmer_api_port": args.envoy_port,
        # sproutrootca, and the role sets sproutrootcatofu: false with it.
        "imas_sprout_root_ca": lookup_file(ca_file),
        # A pinned version, never "latest".
        "imas_sprout_package_state": "present",
        "imas_sprout_verify": True,
        "imas_verify_timeout": args.verify_timeout,
    }
    if args.buildkite_org:
        sprouts_vars["imas_buildkite_org"] = args.buildkite_org
    if args.bus_url:
        sprouts_vars["imas_farmer_bus_urls"] = list(args.bus_url)
    gv["sprouts"] = sprouts_vars
    if "linux_sprouts" in groups:
        gv["linux_sprouts"] = {"imas_sprout_version": linux_version}
    if "windows_sprouts" in groups:
        wv = {"imas_sprout_version": windows_version}
        if args.windows_msi_url:
            wv["imas_sprout_windows_msi_url"] = args.windows_msi_url
            wv["imas_sprout_windows_checksum"] = args.windows_msi_sha256
        gv["windows_sprouts"] = wv
    if "conn_ssh" in groups:
        gv["conn_ssh"] = {
            "ansible_connection": "ssh",
            "ansible_become": True,
            "ansible_ssh_private_key_file": ssh_key,
            # Host key checking off, into a known hosts file of this run only:
            # through a tunnel every host is 127.0.0.1, and every run's VMs
            # are new.
            "ansible_host_key_checking": False,
            "ansible_ssh_common_args": (
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile={known_hosts} "
                "-o IdentitiesOnly=yes -o ServerAliveInterval=15"
            ),
        }
    if "conn_winrm" in groups:
        w = {
            "ansible_connection": "winrm",
            "ansible_become": False,
            "ansible_winrm_scheme": "https",
            "ansible_winrm_transport": "ntlm",
            # The certificate names the VM, never the 127.0.0.1 we reach it
            # by through the tunnel, and it is self-signed: not validated.
            # NTLM still encrypts the messages inside TLS.
            "ansible_winrm_server_cert_validation": "ignore",
            "ansible_winrm_read_timeout_sec": 120,
            "ansible_winrm_operation_timeout_sec": 100,
        }
        if args.winrm_password_file and not args.winrm_password_dir:
            w["ansible_password"] = lookup_file(os.path.abspath(args.winrm_password_file))
        gv["conn_winrm"] = w
    if "conn_docker" in groups:
        gv["conn_docker"] = {
            "ansible_connection": args.docker_connection,
            "ansible_user": "root",
            "ansible_become": False,
        }
    return inventory, gv, {"run_id": uat["run_id"], "sprouts": summary}, known_hosts


# --- A small YAML writer: the output is plain maps, lists and scalars. -----
# Strings are written as JSON strings, which are valid YAML double-quoted
# scalars, so nothing needs YAML-specific quoting rules.

KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _scalar(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


def to_yaml(value, indent: int = 0) -> str:
    pad = "  " * indent
    out = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not KEY_RE.match(str(k)):
                raise InputError(f"unexpected key {k!r}")
            if isinstance(v, dict) and v:
                out.append(f"{pad}{k}:\n{to_yaml(v, indent + 1)}")
            elif isinstance(v, list) and v:
                out.append(f"{pad}{k}:\n{to_yaml(v, indent + 1)}")
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                s = _scalar(v)
                out.append(f"{pad}{k}:{' ' + s if s else ''}")
        return "\n".join(out)
    if isinstance(value, list):
        for v in value:
            if isinstance(v, (dict, list)):
                raise InputError("nested lists of maps are not written by this tool")
            out.append(f"{pad}- {_scalar(v)}")
        return "\n".join(out)
    return pad + _scalar(value)


HEADER = "---\n# Written by uat/enroll/gen-inventory.py. Do not edit; re-run it.\n"


def write(path: str, text: str, mode: int = 0o644) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--uat", required=True, help="the uat JSON (tofu output -json uat)")
    ap.add_argument("--access", help="access.json from uat/access/tunnels.sh (not needed for docker sprouts)")
    ap.add_argument("--keys-dir", required=True, help="the keys/ directory create-tenants.sh wrote")
    ap.add_argument("--release-tag", required=True, help="vX.Y.Z or vX.Y.Z-rc.N")
    ap.add_argument("--ca-file", required=True, help="the UAT CA (PEM) sprouts pin as sproutrootca")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--ssh-key", help="the per run SSH private key")
    ap.add_argument("--known-hosts", help="per run known hosts file (default: OUT/../ssh/known_hosts)")
    ap.add_argument("--winrm-password-file", help="one WinRM password for every Windows sprout")
    ap.add_argument("--winrm-password-dir", help="a directory with one password file per Windows VM name")
    ap.add_argument("--default-user", default="uatadmin", help="login when the uat JSON has no admin_user")
    ap.add_argument("--envoy-host", help="Envoy's name for farmerinterface (default: dmz.fqdn)")
    ap.add_argument("--envoy-port", type=int, default=8443, help="Envoy's listener port (default 8443)")
    ap.add_argument("--bus-url", action="append", default=[], help="pin a bus URL (default: farmer's)")
    ap.add_argument("--buildkite-org", help="Buildkite organization (default: the role's, yogzblr)")
    ap.add_argument("--package-metadata", default="git", help="Linux package version metadata (default git)")
    ap.add_argument("--windows-msi-url", help="install this MSI instead of the NuGet feed's")
    ap.add_argument("--windows-msi-sha256", help="its SHA-256 (required with --windows-msi-url)")
    ap.add_argument("--docker-connection", help="connection plugin for docker sprouts (no default; see README.md)")
    ap.add_argument("--verify-timeout", type=int, default=600, help="imas_verify_timeout (default 600)")
    args = ap.parse_args(argv)
    if not 0 < args.envoy_port < 65536:
        print("gen-inventory.py: error: --envoy-port out of range", file=sys.stderr)
        return 1
    try:
        inventory, gv, summary, known_hosts = build(args)
    except (InputError, OSError, json.JSONDecodeError) as e:
        print(f"gen-inventory.py: error: {e}", file=sys.stderr)
        return 1
    os.makedirs(os.path.join(args.out, "group_vars"), exist_ok=True)
    if known_hosts:
        os.makedirs(os.path.dirname(known_hosts), mode=0o700, exist_ok=True)
    write(os.path.join(args.out, "hosts.yml"), HEADER + to_yaml(inventory) + "\n")
    for name, values in gv.items():
        write(os.path.join(args.out, "group_vars", name + ".yml"), HEADER + to_yaml(values) + "\n")
    write(os.path.join(args.out, "plan.json"), json.dumps(summary, indent=2, sort_keys=True) + "\n")
    for vm, s in summary["sprouts"].items():
        print(f"{vm}: tenant {s['tenant']} {s['os']} over {s['connection']} as sprout {s['sprout_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
