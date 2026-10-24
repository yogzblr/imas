#!/usr/bin/env python3
"""winrm_exec.py: run one PowerShell script on a Windows VM over WinRM.

    winrm_exec.py --host H --port P --user U --password-file F [--pool SOCK] < script.ps1

vmctl.sh's WinRM channel (uat/access/README.md). It connects to
https://H:P/wsman with NTLM, as uat/enroll's Ansible inventory does: through
the Bastion tunnel the host is 127.0.0.1 and the VM's certificate is
self-signed and names the VM, so the certificate is not validated; NTLM
still encrypts the messages inside TLS. The script is read from stdin and
sent to powershell.exe on its stdin (base64), so its length is not bound by
the command line's.

It prints the script's stdout on stdout and its stderr (CLIXML decoded) on
stderr. Exit status: 0 when the script ran (its own exit code is whatever
it prints; vmctl.sh's wrapper prints a marker line), 254 when no shell
could be opened (nothing ran: safe to retry), 255 on an error after the
script started, 2 on a usage error.

With --pool SOCK (W10, vmctl.sh's default) the call goes through one
pooled WinRM session per VM: a server process holding the NTLM session and
one shell, listening on the Unix socket SOCK, started on the first call and
gone after --pool-idle seconds (300) without one, so each call opens no new
connection and no new shell through the Bastion tunnel. The server runs one
script at a time; it exits when a call fails in any way (the next call
starts a fresh one) and when a script outlives --deadline (a watchdog), so a
hung command never blocks the calls after it. The exit status is the same
as without it; a server that cannot open its shell makes the call exit 254.

Needs pywinrm (MIT), which the UAT workflow installs for Ansible.
"""

import argparse
import base64
import fcntl
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

# Reads the base64 script from stdin, decodes it (UTF-8) and runs it. The
# same $input bootstrap Ansible's PowerShell shell plugin uses.
BOOTSTRAP = (
    "$ProgressPreference = 'SilentlyContinue'\n"
    "$__b = ($input | Out-String).Trim()\n"
    "$__s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__b))\n"
    "& ([ScriptBlock]::Create($__s))\n"
)

CLIXML_STRING = re.compile(r'<S S="Error">(.*?)</S>', re.S)
CLIXML_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def clean_stderr(err: bytes) -> str:
    """PowerShell sends its error stream as CLIXML; keep the text."""
    text = err.decode("utf-8", "replace")
    if not text.startswith("#< CLIXML"):
        return text
    parts = CLIXML_STRING.findall(text)
    out = "".join(CLIXML_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), p) for p in parts)
    return out.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&amp;", "&")


def open_session(args):
    """A Protocol and an open shell, or (None, rc, message) on a failure."""
    try:
        with open(args.password_file, encoding="utf-8") as f:
            password = f.read().strip()
    except OSError as e:
        return None, None, 2, f"winrm_exec.py: reading the password file: {e}"
    try:
        from winrm.protocol import Protocol  # pylint: disable=import-outside-toplevel
    except ImportError:
        return None, None, 254, "winrm_exec.py: pywinrm is not installed (pip install pywinrm)"
    proto = Protocol(
        endpoint=f"https://{args.host}:{args.port}/wsman",
        transport="ntlm",
        username=args.user,
        password=password,
        server_cert_validation="ignore",
        operation_timeout_sec=args.operation_timeout,
        read_timeout_sec=args.read_timeout,
    )
    try:
        shell = proto.open_shell(codepage=65001)
    except Exception as e:  # pylint: disable=broad-except
        return None, None, 254, f"winrm_exec.py: could not open a WinRM shell on {args.host}:{args.port}: {e}"
    return proto, shell, 0, ""


def run_script(proto, shell, script: bytes):
    """Runs one script in the shell: (rc, stdout, stderr text). rc 254: the
    command never started; 255: it failed after it started."""
    encoded = base64.b64encode(BOOTSTRAP.encode("utf-16-le")).decode("ascii")
    try:
        cmd = proto.run_command(
            shell,
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        )
    except Exception as e:  # pylint: disable=broad-except
        return 254, "", f"winrm_exec.py: starting the script over WinRM: {e}\n"
    try:
        proto.send_command_input(shell, cmd, base64.b64encode(script).decode("ascii") + "\r\n", end=True)
        out, err, _ = proto.get_command_output(shell, cmd)
        try:
            proto.cleanup_command(shell, cmd)
        except Exception:  # pylint: disable=broad-except
            pass
    except Exception as e:  # pylint: disable=broad-except
        return 255, "", f"winrm_exec.py: running the script over WinRM: {e}\n"
    return 0, out.decode("utf-8", "replace"), clean_stderr(err)


def close_session(proto, shell):
    try:
        proto.close_shell(shell)
    except Exception:  # pylint: disable=broad-except
        pass


def serve(args) -> int:
    """The pool's server: one session, one script at a time, on args.serve."""
    sock_path = args.serve
    proto, shell, rc, msg = open_session(args)
    if proto is None:
        with open(sock_path + ".err", "w", encoding="utf-8") as f:
            f.write(msg)
        return rc
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass
    old = os.umask(0o177)
    srv.bind(sock_path)
    os.umask(old)
    srv.listen(8)
    srv.settimeout(args.pool_idle)
    with open(sock_path + ".pid", "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    try:
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                return 0
            with conn:
                req = json.loads(read_line(conn) or "{}")
                if req.get("cmd") == "exit":
                    return 0
                # The watchdog: a script that outlives its caller's deadline
                # ends the server, shell and all.
                deadline = max(1, int(req.get("deadline", 120)))
                dog = threading.Timer(deadline, os._exit, args=(3,))
                dog.daemon = True
                dog.start()
                rc, out, err = run_script(proto, shell, base64.b64decode(req.get("script", "")))
                dog.cancel()
                reply = {"rc": rc, "out": out, "err": err}
                try:
                    conn.sendall((json.dumps(reply) + "\n").encode())
                except OSError:
                    return 0
                if rc != 0:
                    return 0
    finally:
        close_session(proto, shell)
        for p in (sock_path, sock_path + ".pid"):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def read_line(conn) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf.decode("utf-8", "replace")


def connect(sock_path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock_path)
        return s
    except OSError:
        s.close()
        return None


def via_pool(args, script: bytes) -> int:
    """Runs the script through the pool's server, starting it if needed."""
    sock_path = args.pool
    conn = connect(sock_path)
    lock = None
    if conn is None:
        # One starter at a time: a second caller waits, then finds the
        # first one's server.
        lock = open(sock_path + ".lock", "a", encoding="utf-8")  # pylint: disable=consider-using-with
        fcntl.flock(lock, fcntl.LOCK_EX)
        conn = connect(sock_path)
    if conn is None:
        try:
            os.unlink(sock_path + ".err")
        except FileNotFoundError:
            pass
        cmd = [sys.executable, os.path.abspath(__file__), "--serve", sock_path, "--host", args.host,
               "--port", str(args.port), "--user", args.user, "--password-file", args.password_file,
               "--operation-timeout", str(args.operation_timeout), "--read-timeout", str(args.read_timeout),
               "--pool-idle", str(args.pool_idle)]
        with open(os.devnull, "rb") as nul_in, open(os.devnull, "wb") as nul_out:
            server = subprocess.Popen(cmd, stdin=nul_in, stdout=nul_out, stderr=nul_out,
                                      start_new_session=True, close_fds=True)
        give_up = time.monotonic() + args.read_timeout + 10
        while conn is None:
            if server.poll() is not None:
                try:
                    with open(sock_path + ".err", encoding="utf-8") as f:
                        msg = f.read().strip()
                except OSError:
                    msg = f"winrm_exec.py: the WinRM pool for {args.host}:{args.port} did not start (exit {server.returncode})"
                print(msg, file=sys.stderr)
                return server.returncode if server.returncode == 2 else 254
            if time.monotonic() > give_up:
                server.kill()
                print(f"winrm_exec.py: could not open a WinRM shell on {args.host}:{args.port}: the pool did not answer", file=sys.stderr)
                return 254
            time.sleep(0.1)
            conn = connect(sock_path)
    if lock is not None:
        lock.close()
    with conn:
        req = {"script": base64.b64encode(script).decode("ascii"), "deadline": args.deadline}
        try:
            conn.sendall((json.dumps(req) + "\n").encode())
            line = read_line(conn)
        except OSError as e:
            line = ""
            print(f"winrm_exec.py: the WinRM pool: {e}", file=sys.stderr)
    if not line:
        print("winrm_exec.py: the pooled WinRM session ended during the script (it may have run)", file=sys.stderr)
        return 255
    reply = json.loads(line)
    sys.stdout.write(reply.get("out", ""))
    sys.stderr.write(reply.get("err", ""))
    return int(reply.get("rc", 255))


def close_pool(sock_path) -> int:
    """Ends the pool's server (a tunnel reopen: its session goes with it)."""
    conn = connect(sock_path)
    if conn is not None:
        with conn:
            try:
                conn.sendall(b'{"cmd": "exit"}\n')
            except OSError:
                pass
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int)
    ap.add_argument("--user")
    ap.add_argument("--password-file")
    ap.add_argument("--operation-timeout", type=int, default=20)
    ap.add_argument("--read-timeout", type=int, default=30)
    ap.add_argument("--pool", help="the pooled session's Unix socket")
    ap.add_argument("--pool-idle", type=int, default=300)
    ap.add_argument("--deadline", type=int, default=120, help="seconds the pool lets one script run")
    ap.add_argument("--close-pool", help="end the pool's server on this socket, and exit")
    ap.add_argument("--serve", help=argparse.SUPPRESS)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if args.close_pool:
        return close_pool(args.close_pool)
    if args.port is None or not args.user or not args.password_file:
        print("winrm_exec.py: --port, --user and --password-file are needed", file=sys.stderr)
        return 2
    if args.read_timeout <= args.operation_timeout:
        print("winrm_exec.py: --read-timeout must be above --operation-timeout", file=sys.stderr)
        return 2
    if args.serve:
        return serve(args)
    if not os.path.isfile(args.password_file) or not os.access(args.password_file, os.R_OK):
        print(f"winrm_exec.py: reading the password file: cannot read {args.password_file}", file=sys.stderr)
        return 2
    script = sys.stdin.buffer.read()
    if args.pool:
        return via_pool(args, script)

    proto, shell, rc, msg = open_session(args)
    if proto is None:
        print(msg, file=sys.stderr)
        return rc
    try:
        rc, out, err = run_script(proto, shell, script)
    finally:
        close_session(proto, shell)
    if rc != 0:
        sys.stderr.write(err)
        return 255 if rc == 255 else 254
    sys.stdout.write(out)
    sys.stderr.write(err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
