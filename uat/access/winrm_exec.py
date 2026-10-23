#!/usr/bin/env python3
"""winrm_exec.py: run one PowerShell script on a Windows VM over WinRM.

    winrm_exec.py --host H --port P --user U --password-file F < script.ps1

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

Needs pywinrm (MIT), which the UAT workflow installs for Ansible.
"""

import argparse
import base64
import re
import sys

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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--operation-timeout", type=int, default=20)
    ap.add_argument("--read-timeout", type=int, default=30)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if args.read_timeout <= args.operation_timeout:
        print("winrm_exec.py: --read-timeout must be above --operation-timeout", file=sys.stderr)
        return 2
    try:
        with open(args.password_file, encoding="utf-8") as f:
            password = f.read().strip()
    except OSError as e:
        print(f"winrm_exec.py: reading the password file: {e}", file=sys.stderr)
        return 2
    script = sys.stdin.buffer.read()

    try:
        from winrm.protocol import Protocol  # pylint: disable=import-outside-toplevel
    except ImportError:
        print("winrm_exec.py: pywinrm is not installed (pip install pywinrm)", file=sys.stderr)
        return 254

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
        print(f"winrm_exec.py: could not open a WinRM shell on {args.host}:{args.port}: {e}", file=sys.stderr)
        return 254
    try:
        encoded = base64.b64encode(BOOTSTRAP.encode("utf-16-le")).decode("ascii")
        cmd = proto.run_command(
            shell,
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        )
        proto.send_command_input(shell, cmd, base64.b64encode(script).decode("ascii") + "\r\n", end=True)
        out, err, _ = proto.get_command_output(shell, cmd)
        try:
            proto.cleanup_command(shell, cmd)
        except Exception:  # pylint: disable=broad-except
            pass
    except Exception as e:  # pylint: disable=broad-except
        print(f"winrm_exec.py: running the script over WinRM: {e}", file=sys.stderr)
        return 255
    finally:
        try:
            proto.close_shell(shell)
        except Exception:  # pylint: disable=broad-except
            pass
    sys.stdout.write(out.decode("utf-8", "replace"))
    sys.stderr.write(clean_stderr(err))
    return 0


if __name__ == "__main__":
    sys.exit(main())
