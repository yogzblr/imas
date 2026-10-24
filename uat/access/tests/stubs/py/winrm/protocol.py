"""Stub pywinrm Protocol for access_test.sh.

It checks what winrm_exec.py sends (NTLM over HTTPS, no certificate check,
powershell.exe with the stdin bootstrap), decodes the command vmctl.sh
wrapped, logs it to $STUB_STATE/calls.log as "winrm decoded: <command>"
and answers like a Windows host. Behaviour comes from files in $STUB_STATE:
win_rc (the command's exit code, default 0), winrm_open_fail (no shell can
be opened), winrm_hang (never answers), win_no_marker (no marker line),
stale.<port> (the tunnel hangs: opening a shell times out, as in UAT Run 2
#6).
"""

import base64
import os
import re
import time

STATE = os.environ["STUB_STATE"]


def _has(name):
    return os.path.exists(os.path.join(STATE, name))


def _log(line):
    with open(os.path.join(STATE, "calls.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")


class Protocol:
    def __init__(self, endpoint, transport, username, password, server_cert_validation,
                 operation_timeout_sec, read_timeout_sec):
        _log(f"winrm endpoint={endpoint} transport={transport} user={username} "
             f"password={'set' if password else 'empty'} cert={server_cert_validation}")
        self.stdin = b""
        self.port = endpoint.split(":")[2].split("/")[0]

    def open_shell(self, codepage=None):
        if _has("winrm_open_fail"):
            raise ConnectionError("stub: connection refused")
        if _has("stale." + self.port):
            raise TimeoutError(f"HTTPSConnectionPool(host='127.0.0.1', port={self.port}): Read timed out. (read timeout=30)")
        _log(f"winrm open_shell codepage={codepage}")
        return "shell-1"

    def run_command(self, shell, command, args):
        # A pooled session (winrm_exec.py --pool) runs many commands in one
        # shell; each has its own stdin. Its tunnel going stale shows here.
        self.stdin = b""
        if _has("stale." + self.port):
            raise TimeoutError(f"HTTPSConnectionPool(host='127.0.0.1', port={self.port}): Read timed out. (read timeout=30)")
        _log("winrm run_command")
        boot = base64.b64decode(args[-1]).decode("utf-16-le")
        if command != "powershell.exe" or "$input" not in boot:
            raise RuntimeError("stub: unexpected command " + command)
        return "cmd-1"

    def send_command_input(self, shell, cmd, data, end=False):
        self.stdin += data.encode() if isinstance(data, str) else data
        assert end

    def get_command_output(self, shell, cmd):
        if _has("winrm_hang"):
            time.sleep(60)
        wrapper = base64.b64decode(self.stdin.strip()).decode("utf-8")
        m = re.search(r"FromBase64String\('([^']*)'\)", wrapper)
        _log("winrm decoded: " + base64.b64decode(m.group(1)).decode("utf-8"))
        rc = "0"
        if _has("win_rc"):
            with open(os.path.join(STATE, "win_rc"), encoding="utf-8") as f:
                rc = f.read().strip()
        out = "win-out\r\n"
        if not _has("win_no_marker"):
            out += f"__IMAS_VMCTL_RC__{rc}\r\n"
        err = '#< CLIXML\r\n<Objs Version="1.1.0.1"><S S="Error">win-err_x000D__x000A_</S></Objs>'
        return out.encode(), err.encode(), 0

    def cleanup_command(self, shell, cmd):
        pass

    def close_shell(self, shell):
        _log("winrm close_shell")
