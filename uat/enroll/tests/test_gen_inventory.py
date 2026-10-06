"""Tests for uat/enroll/gen-inventory.py.

    python3 -m unittest discover -s uat/enroll/tests -p 'test_*.py'

Standard library only. PyYAML, when installed, also parses the output; and when
ansible-inventory is on PATH the inventory is loaded by Ansible itself.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENROLL = os.path.dirname(HERE)
TESTDATA = os.path.join(ENROLL, "testdata")
SCRIPT = os.path.join(ENROLL, "gen-inventory.py")

spec = importlib.util.spec_from_file_location("gen_inventory", SCRIPT)
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional
    yaml = None

SECRET = "SECRETVALUE-never-in-the-inventory"


def load(name: str) -> dict:
    with open(os.path.join(TESTDATA, name), encoding="utf-8") as f:
        return json.load(f)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gen-inventory-test-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.keys = os.path.join(self.tmp, "keys")
        os.makedirs(self.keys)
        self.ssh_key = os.path.join(self.tmp, "id_uat")
        self.winrm = os.path.join(self.tmp, "winrm-password")
        for p, content in ((self.ssh_key, "PRIVATE KEY " + SECRET), (self.winrm, "pw-" + SECRET)):
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
        self.out = os.path.join(self.tmp, "inventory")

    def write_keys(self, uat: dict):
        for vm in uat["sprouts"]:
            with open(os.path.join(self.keys, vm + ".key"), "w", encoding="utf-8") as f:
                f.write(f"ek_{vm}.{SECRET}")

    def write_json(self, name: str, data: dict) -> str:
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return p

    def run_gen(self, uat=None, access="access.json", release="v0.1.0-rc.4", extra=(), expect_ok=True):
        uat = uat if uat is not None else load("uat.json")
        self.write_keys(uat)
        args = [
            "--uat", self.write_json("uat.json", uat),
            "--keys-dir", self.keys,
            "--release-tag", release,
            "--ca-file", os.path.join(TESTDATA, "uat-ca.pem"),
            "--out", self.out,
            "--ssh-key", self.ssh_key,
            "--winrm-password-file", self.winrm,
        ]
        if access:
            args += ["--access", os.path.join(TESTDATA, access) if isinstance(access, str) else self.write_json("access.json", access)]
        args += list(extra)
        p = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
        if expect_ok:
            self.assertEqual(p.returncode, 0, p.stderr)
        else:
            self.assertNotEqual(p.returncode, 0, p.stdout)
        return p

    def read(self, rel: str) -> str:
        with open(os.path.join(self.out, rel), encoding="utf-8") as f:
            return f.read()

    def yaml(self, rel: str):
        if yaml is None:
            self.skipTest("PyYAML not installed")
        return yaml.safe_load(self.read(rel))

    def all_output(self) -> str:
        text = ""
        for root, _, files in os.walk(self.out):
            for name in files:
                with open(os.path.join(root, name), encoding="utf-8") as f:
                    text += f.read()
        return text

    def hostvars(self) -> dict:
        inv = self.yaml("hosts.yml")
        hv = {}
        for fam in inv["all"]["children"]["sprouts"]["children"].values():
            hv.update(fam["hosts"])
        return hv


class TestVersions(unittest.TestCase):
    def test_prerelease(self):
        self.assertEqual(gen.package_versions("v0.1.0-rc.4", "git"), ("0.1.0~rc.4+git", "0.1.0-rc.4"))

    def test_release(self):
        self.assertEqual(gen.package_versions("v1.2.3", "git"), ("1.2.3+git", "1.2.3"))

    def test_no_metadata(self):
        self.assertEqual(gen.package_versions("v1.2.3-rc.10", ""), ("1.2.3~rc.10", "1.2.3-rc.10"))

    def test_rejects(self):
        for tag in ("latest", "1.2.3", "v1.2", "v1.2.3-beta.1", "v1.2.3+git", "v1.2.3-rc.1 ", ""):
            with self.subTest(tag=tag), self.assertRaises(gen.InputError):
                gen.package_versions(tag, "git")


class TestSproutIDs(unittest.TestCase):
    def test_same_sprout_id_in_both_tenants(self):
        planned = {p["vm"]: p["sprout_id"] for p in gen.plan_sprouts(load("uat.json"))}
        self.assertEqual(planned["t1-ubuntu"], "ubuntu-01")
        self.assertEqual(planned["t2-ubuntu"], "ubuntu-01")
        self.assertEqual(planned["t1-alma"], "alma-01")
        self.assertEqual(planned["t2-alma"], "alma-01")
        self.assertEqual(planned["t1-win"], "win-01")
        self.assertEqual(planned["t2-win"], "win-01")

    def test_unique_within_a_tenant(self):
        uat = load("uat.json")
        uat["sprouts"]["t1-ubuntu-b"] = dict(uat["sprouts"]["t1-ubuntu"])
        planned = gen.plan_sprouts(uat)
        ids = {}
        for p in planned:
            key = (p["tenant"], p["sprout_id"])
            self.assertNotIn(key, ids, f"{p['vm']} and {ids.get(key)} share {key}")
            ids[key] = p["vm"]
        by_vm = {p["vm"]: p["sprout_id"] for p in planned}
        self.assertEqual(by_vm["t1-ubuntu"], "ubuntu-01")
        self.assertEqual(by_vm["t1-ubuntu-b"], "ubuntu-02")
        self.assertEqual(by_vm["t2-ubuntu"], "ubuntu-01")

    def test_tenant_forms(self):
        for raw, want in ((1, 1), ("2", 2), ("t1", 1), ("T2", 2)):
            self.assertEqual(gen.tenant_number(raw), want)
        for raw in (0, 3, "x", None, ""):
            with self.assertRaises(gen.InputError):
                gen.tenant_number(raw)


class TestInventory(Base):
    def test_azure_layout(self):
        p = self.run_gen()
        self.assertIn("t2-win: tenant 2 windows over winrm as sprout win-01", p.stdout)
        hv = self.hostvars()
        self.assertEqual(sorted(hv), ["t1-alma", "t1-ubuntu", "t1-win", "t2-alma", "t2-ubuntu", "t2-win"])
        # Through the tunnels: 127.0.0.1 and the port in access.json.
        self.assertEqual(hv["t1-ubuntu"]["ansible_host"], "127.0.0.1")
        self.assertEqual(hv["t1-ubuntu"]["ansible_port"], 42201)
        self.assertEqual(hv["t2-alma"]["ansible_port"], 42204)
        self.assertEqual(hv["t1-win"]["ansible_port"], 45986)
        self.assertEqual(hv["t2-win"]["ansible_port"], 45987)
        self.assertEqual(hv["t1-ubuntu"]["ansible_ssh_extra_args"], "-o HostKeyAlias=t1-ubuntu")
        # The same sprout ID per OS in both tenants.
        for os_name, sid in (("ubuntu", "ubuntu-01"), ("alma", "alma-01"), ("win", "win-01")):
            self.assertEqual(hv[f"t1-{os_name}"]["uat_sprout_id"], sid)
            self.assertEqual(hv[f"t2-{os_name}"]["uat_sprout_id"], sid)
        self.assertEqual(hv["t1-ubuntu"]["uat_tenant"], 1)
        self.assertEqual(hv["t2-ubuntu"]["uat_tenant"], 2)
        self.assertEqual(hv["t2-win"]["uat_asset_id"], "uat-abc123-t2-win")
        # The key by lookup, from the tenant's own key file.
        self.assertEqual(
            hv["t2-alma"]["imas_join_token"],
            "{{ lookup('ansible.builtin.file', '%s') }}" % os.path.join(self.keys, "t2-alma.key"),
        )

    def test_groups(self):
        self.run_gen()
        inv = self.yaml("hosts.yml")
        children = inv["all"]["children"]
        self.assertEqual(sorted(children["sprouts"]["children"]), ["linux_sprouts", "windows_sprouts"])
        self.assertEqual(sorted(children["tenant_1"]["hosts"]), ["t1-alma", "t1-ubuntu", "t1-win"])
        self.assertEqual(sorted(children["tenant_2"]["hosts"]), ["t2-alma", "t2-ubuntu", "t2-win"])
        self.assertEqual(sorted(children["os_alma"]["hosts"]), ["t1-alma", "t2-alma"])
        self.assertEqual(sorted(children["conn_winrm"]["hosts"]), ["t1-win", "t2-win"])
        self.assertEqual(sorted(children["conn_ssh"]["hosts"]), ["t1-alma", "t1-ubuntu", "t2-alma", "t2-ubuntu"])
        self.assertNotIn("conn_docker", children)

    def test_group_vars(self):
        self.run_gen()
        sv = self.yaml("group_vars/sprouts.yml")
        self.assertEqual(sv["imas_farmer_host"], "uatabc123-dmz.centralindia.cloudapp.azure.com")
        self.assertEqual(sv["imas_farmer_api_port"], 8443)
        self.assertEqual(
            sv["imas_sprout_root_ca"],
            "{{ lookup('ansible.builtin.file', '%s') }}" % os.path.join(TESTDATA, "uat-ca.pem"),
        )
        self.assertEqual(sv["imas_sprout_package_state"], "present")
        self.assertIs(sv["imas_sprout_verify"], True)
        self.assertNotIn("imas_farmer_bus_urls", sv)
        self.assertNotIn("imas_buildkite_org", sv)  # the role's default registries
        self.assertEqual(self.yaml("group_vars/linux_sprouts.yml"), {"imas_sprout_version": "0.1.0~rc.4+git"})
        self.assertEqual(self.yaml("group_vars/windows_sprouts.yml"), {"imas_sprout_version": "0.1.0-rc.4"})
        self.assertNotIn("latest", self.all_output())

    def test_ssh_and_winrm(self):
        self.run_gen()
        ssh = self.yaml("group_vars/conn_ssh.yml")
        self.assertEqual(ssh["ansible_connection"], "ssh")
        self.assertIs(ssh["ansible_become"], True)
        self.assertIs(ssh["ansible_host_key_checking"], False)
        self.assertEqual(ssh["ansible_ssh_private_key_file"], self.ssh_key)
        known = os.path.abspath(os.path.join(self.out, "..", "ssh", "known_hosts"))
        self.assertIn("-o StrictHostKeyChecking=no", ssh["ansible_ssh_common_args"])
        self.assertIn(f"-o UserKnownHostsFile={known}", ssh["ansible_ssh_common_args"])
        self.assertTrue(os.path.isdir(os.path.dirname(known)))
        win = self.yaml("group_vars/conn_winrm.yml")
        self.assertEqual(win["ansible_connection"], "winrm")
        self.assertEqual(win["ansible_winrm_scheme"], "https")
        self.assertEqual(win["ansible_winrm_server_cert_validation"], "ignore")
        self.assertEqual(win["ansible_password"], "{{ lookup('ansible.builtin.file', '%s') }}" % self.winrm)
        self.assertIs(win["ansible_become"], False)

    def test_winrm_password_dir(self):
        d = os.path.join(self.tmp, "winrm")
        os.makedirs(d)
        self.run_gen(extra=["--winrm-password-dir", d])
        hv = self.hostvars()
        self.assertEqual(hv["t1-win"]["ansible_password"], "{{ lookup('ansible.builtin.file', '%s/t1-win') }}" % d)
        self.assertNotIn("ansible_password", self.yaml("group_vars/conn_winrm.yml"))

    def test_no_secret_in_output(self):
        self.run_gen()
        text = self.all_output()
        self.assertNotIn(SECRET, text)
        self.assertNotIn("PRIVATE KEY", text)

    def test_plan_json(self):
        self.run_gen()
        with open(os.path.join(self.out, "plan.json"), encoding="utf-8") as f:
            summary = json.load(f)
        self.assertEqual(summary["run_id"], "abc123")
        self.assertEqual(
            summary["sprouts"]["t2-ubuntu"],
            {"tenant": 2, "os": "ubuntu", "connection": "ssh", "sprout_id": "ubuntu-01", "asset_id": "uat-abc123-t2-ubuntu"},
        )
        self.assertEqual(summary["sprouts"]["t1-ubuntu"]["sprout_id"], summary["sprouts"]["t2-ubuntu"]["sprout_id"])

    def test_options(self):
        self.run_gen(
            release="v1.2.3",
            extra=[
                "--envoy-host", "edge.uat.test", "--envoy-port", "30443",
                "--bus-url", "wss://edge.uat.test:30443", "--buildkite-org", "someorg",
                "--windows-msi-url", "https://example.test/imas-sprout_1.2.3_amd64.msi",
                "--windows-msi-sha256", "a" * 64,
            ],
        )
        sv = self.yaml("group_vars/sprouts.yml")
        self.assertEqual(sv["imas_farmer_host"], "edge.uat.test")
        self.assertEqual(sv["imas_farmer_api_port"], 30443)
        self.assertEqual(sv["imas_farmer_bus_urls"], ["wss://edge.uat.test:30443"])
        self.assertEqual(sv["imas_buildkite_org"], "someorg")
        self.assertEqual(self.yaml("group_vars/linux_sprouts.yml")["imas_sprout_version"], "1.2.3+git")
        wv = self.yaml("group_vars/windows_sprouts.yml")
        self.assertEqual(wv["imas_sprout_version"], "1.2.3")
        self.assertEqual(wv["imas_sprout_windows_msi_url"], "https://example.test/imas-sprout_1.2.3_amd64.msi")
        self.assertEqual(wv["imas_sprout_windows_checksum"], "a" * 64)

    def test_access_under_vms_key(self):
        self.run_gen(access={"vms": load("access.json")})
        self.assertEqual(self.hostvars()["t1-alma"]["ansible_port"], 42202)

    def test_docker_local_rig(self):
        p = self.run_gen(uat=load("uat-lite.json"), access="access-lite.json",
                         extra=["--docker-connection", "example.rig.container"])
        self.assertIn("t2-ubuntu: tenant 2 ubuntu over docker as sprout ubuntu-01", p.stdout)
        hv = self.hostvars()
        self.assertEqual(hv["t1-ubuntu"]["ansible_host"], "imas-uat-lite-t1-ubuntu")
        self.assertEqual(hv["t2-ubuntu"]["ansible_host"], "t2-ubuntu")  # no container named: the VM name
        self.assertNotIn("ansible_port", hv["t1-ubuntu"])
        self.assertEqual(hv["t1-alma"]["uat_sprout_id"], hv["t2-alma"]["uat_sprout_id"])
        docker = self.yaml("group_vars/conn_docker.yml")
        self.assertEqual(docker["ansible_connection"], "example.rig.container")
        self.assertNotIn("community.docker", self.all_output())
        self.assertEqual(docker["ansible_user"], "root")
        self.assertFalse(os.path.exists(os.path.join(self.out, "group_vars", "conn_ssh.yml")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "group_vars", "windows_sprouts.yml")))
        self.assertEqual(self.yaml("group_vars/sprouts.yml")["imas_farmer_host"], "uatlite01-dmz.uat.test")

    def test_docker_needs_no_access_file_or_credentials(self):
        uat = load("uat-lite.json")
        self.write_keys(uat)
        args = [
            sys.executable, SCRIPT, "--uat", self.write_json("u.json", uat), "--keys-dir", self.keys,
            "--release-tag", "v0.1.0-rc.4", "--ca-file", os.path.join(TESTDATA, "uat-ca.pem"), "--out", self.out,
            "--docker-connection", "example.rig.container",
        ]
        p = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_docker_needs_a_named_connection(self):
        # community.docker was dropped (owner decision); no default replaces it.
        p = self.run_gen(uat=load("uat-lite.json"), access="access-lite.json", expect_ok=False)
        self.assertIn("--docker-connection", p.stderr)
        self.assertIn("owner decision", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.out, "hosts.yml")))

    def test_docker_connection_name_checked(self):
        p = self.run_gen(uat=load("uat-lite.json"), access="access-lite.json",
                         extra=["--docker-connection", "rm -rf"], expect_ok=False)
        self.assertIn("not a connection plugin name", p.stderr)

    @unittest.skipUnless(shutil.which("ansible-inventory"), "ansible-inventory not on PATH")
    def test_ansible_loads_it(self):
        self.run_gen()
        p = subprocess.run(
            ["ansible-inventory", "-i", os.path.join(self.out, "hosts.yml"), "--list"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        hv = data["_meta"]["hostvars"]
        self.assertEqual(hv["t2-win"]["ansible_connection"], "winrm")
        self.assertEqual(hv["t2-win"]["uat_sprout_id"], "win-01")
        self.assertEqual(hv["t1-alma"]["imas_sprout_version"], "0.1.0~rc.4+git")
        self.assertEqual(hv["t1-alma"]["imas_farmer_api_port"], 8443)
        self.assertEqual(sorted(data["sprouts"]["children"]), ["linux_sprouts", "windows_sprouts"])


class TestErrors(Base):
    def assert_error(self, needle: str, **kw):
        p = self.run_gen(expect_ok=False, **kw)
        self.assertIn(needle, p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.out, "hosts.yml")))

    def test_bad_release_tag(self):
        self.assert_error("never 'latest'", release="latest")

    def test_missing_port(self):
        access = load("access.json")
        del access["t2-win"]["winrm_port"]
        self.assert_error("no winrm_port for t2-win", access=access)

    def test_missing_access(self):
        self.assert_error("no ssh_port for t1-alma", access={})

    def test_unknown_os(self):
        uat = load("uat.json")
        uat["sprouts"]["t1-alma"]["os"] = "suse"
        self.assert_error("os 'suse'", uat=uat)

    def test_windows_over_ssh(self):
        uat = load("uat.json")
        uat["sprouts"]["t1-win"]["connection"] = "ssh"
        self.assert_error("not supported for windows", uat=uat)

    def test_windows_in_docker(self):
        uat = load("uat.json")
        uat["sprouts"]["t1-win"]["connection"] = "docker"
        self.assert_error("not supported for windows", uat=uat)

    def test_tenant_three(self):
        uat = load("uat.json")
        uat["sprouts"]["t2-alma"]["tenant"] = 3
        self.assert_error("not 1 or 2", uat=uat)

    def test_bad_run_id(self):
        uat = load("uat.json")
        uat["run_id"] = "ABC"
        self.assert_error("run_id", uat=uat)

    def test_bad_vm_name(self):
        uat = load("uat.json")
        uat["sprouts"]["T1_Bad"] = uat["sprouts"].pop("t1-alma")
        self.assert_error("not a plain host name", uat=uat)

    def test_missing_key(self):
        uat = load("uat.json")
        self.write_keys(uat)
        os.remove(os.path.join(self.keys, "t2-ubuntu.key"))
        p = subprocess.run(
            [sys.executable, SCRIPT, "--uat", self.write_json("u.json", uat), "--access", os.path.join(TESTDATA, "access.json"),
             "--keys-dir", self.keys, "--release-tag", "v0.1.0-rc.4", "--ca-file", os.path.join(TESTDATA, "uat-ca.pem"),
             "--out", self.out, "--ssh-key", self.ssh_key, "--winrm-password-file", self.winrm],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("no enrollment key for t2-ubuntu", p.stderr)

    def test_ssh_without_key(self):
        uat = load("uat.json")
        self.write_keys(uat)
        p = subprocess.run(
            [sys.executable, SCRIPT, "--uat", self.write_json("u.json", uat), "--access", os.path.join(TESTDATA, "access.json"),
             "--keys-dir", self.keys, "--release-tag", "v0.1.0-rc.4", "--ca-file", os.path.join(TESTDATA, "uat-ca.pem"),
             "--out", self.out, "--winrm-password-file", self.winrm],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--ssh-key", p.stderr)

    def test_msi_url_without_checksum(self):
        self.assert_error("go together", extra=["--windows-msi-url", "https://example.test/x.msi"])

    def test_quote_in_path(self):
        bad = os.path.join(self.tmp, "it's")
        os.makedirs(bad)
        shutil.copy(os.path.join(TESTDATA, "uat-ca.pem"), bad)
        self.assert_error("has a quote", extra=["--ca-file", os.path.join(bad, "uat-ca.pem")])


class TestYamlWriter(unittest.TestCase):
    def test_round_trip(self):
        if yaml is None:
            self.skipTest("PyYAML not installed")
        data = {
            "a": {"b": [1, "two", True], "c": None, "d": {}, "e": []},
            "s": 'quote " and \\ backslash: {{ x }} # not a comment',
            "n": 0,
            "f": False,
        }
        self.assertEqual(yaml.safe_load(gen.to_yaml(copy.deepcopy(data))), data)

    def test_rejects_odd_keys(self):
        with self.assertRaises(gen.InputError):
            gen.to_yaml({"a b": 1})


if __name__ == "__main__":
    unittest.main()
