package harness

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// HostScript is one check written for both families. Scripts print what
// they found as "__IMAS_UAT_<KEY>=<value>" lines (see VMCtl.Run).
type HostScript struct {
	Linux   string
	Windows string
}

// For returns the script for a family.
func (h HostScript) For(family string) string {
	if family == FamilyWindows {
		return h.Windows
	}
	return h.Linux
}

// ShQuote quotes s for POSIX sh.
func ShQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// PSQuote quotes s for PowerShell (a single-quoted string).
func PSQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// FileState prints EXISTS=yes|no and, for a file that exists,
// CONTENT_B64 (base64 of its bytes), OWNER and MTIME (Unix seconds).
// Read the result with ParseFileState.
func FileState(sp Sprout, path string) HostScript {
	return HostScript{
		Linux: fmt.Sprintf(`p=%s
if [ -e "$p" ]; then
  echo "__IMAS_UAT_EXISTS=yes"
  echo "__IMAS_UAT_CONTENT_B64=$(base64 < "$p" | tr -d '\n')"
  echo "__IMAS_UAT_OWNER=$(stat -c %%U "$p")"
  echo "__IMAS_UAT_MTIME=$(stat -c %%Y "$p")"
else
  echo "__IMAS_UAT_EXISTS=no"
fi`, ShQuote(path)),
		Windows: fmt.Sprintf(`$p = %s
if (Test-Path -LiteralPath $p) {
  Write-Output '__IMAS_UAT_EXISTS=yes'
  Write-Output ('__IMAS_UAT_CONTENT_B64=' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($p)))
  Write-Output ('__IMAS_UAT_OWNER=' + (Get-Acl -LiteralPath $p).Owner)
  Write-Output ('__IMAS_UAT_MTIME=' + ([DateTimeOffset](Get-Item -LiteralPath $p).LastWriteTimeUtc).ToUnixTimeSeconds())
} else {
  Write-Output '__IMAS_UAT_EXISTS=no'
}`, PSQuote(path)),
	}
}

// FileInfo is what FileState found.
type FileInfo struct {
	Exists  bool
	Content string
	Owner   string
	MTime   int64
}

// ParseFileState reads FileState's values.
func ParseFileState(r *RunResult) (FileInfo, error) {
	var fi FileInfo
	ex, ok := r.Value("EXISTS")
	if !ok {
		return fi, fmt.Errorf("the file check printed no EXISTS line: %s", tail([]byte(r.Output), 400))
	}
	fi.Exists = ex == "yes"
	if !fi.Exists {
		return fi, nil
	}
	if b64, ok := r.Value("CONTENT_B64"); ok {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fi, fmt.Errorf("file content is not base64: %w", err)
		}
		fi.Content = string(b)
	}
	fi.Owner, _ = r.Value("OWNER")
	if m, ok := r.Value("MTIME"); ok {
		fi.MTime, _ = strconv.ParseInt(m, 10, 64)
	}
	return fi, nil
}

// MultiFileState checks several paths in one call (a vmctl.sh call
// through the Azure control plane takes tens of seconds). Values are
// EXISTS_<i> for each path, in order.
func MultiFileState(paths []string) HostScript {
	var l, w []string
	for i, p := range paths {
		l = append(l, fmt.Sprintf(`if [ -e %s ]; then echo "__IMAS_UAT_EXISTS_%d=yes"; else echo "__IMAS_UAT_EXISTS_%d=no"; fi`, ShQuote(p), i, i))
		w = append(w, fmt.Sprintf(`if (Test-Path -LiteralPath %s) { Write-Output '__IMAS_UAT_EXISTS_%d=yes' } else { Write-Output '__IMAS_UAT_EXISTS_%d=no' }`, PSQuote(p), i, i))
	}
	return HostScript{Linux: strings.Join(l, "\n"), Windows: strings.Join(w, "\n")}
}

// ParseMultiFileState returns whether each path of MultiFileState exists.
func ParseMultiFileState(r *RunResult, n int) ([]bool, error) {
	out := make([]bool, n)
	for i := range out {
		v, ok := r.Value(fmt.Sprintf("EXISTS_%d", i))
		if !ok {
			return nil, fmt.Errorf("the file check printed no EXISTS_%d line: %s", i, tail([]byte(r.Output), 400))
		}
		out[i] = v == "yes"
	}
	return out, nil
}

// Target is a TCP address a host script probes.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return t.Host + ":" + strconv.Itoa(t.Port) }

// TCPProbe tries to open each target from the host, with a 5 second
// limit each, and prints TCP_<i>=open|closed.
func TCPProbe(targets []Target) HostScript {
	var l, w []string
	for i, t := range targets {
		l = append(l, fmt.Sprintf(`if timeout 5 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null; then echo "__IMAS_UAT_TCP_%d=open"; else echo "__IMAS_UAT_TCP_%d=closed"; fi`,
			t.Host, t.Port, i, i))
		w = append(w, fmt.Sprintf(`$c = New-Object System.Net.Sockets.TcpClient
try { $a = $c.BeginConnect(%s, %d, $null, $null); if ($a.AsyncWaitHandle.WaitOne(5000) -and $c.Connected) { Write-Output '__IMAS_UAT_TCP_%d=open' } else { Write-Output '__IMAS_UAT_TCP_%d=closed' } } catch { Write-Output '__IMAS_UAT_TCP_%d=closed' } finally { $c.Close() }`,
			PSQuote(t.Host), t.Port, i, i, i))
	}
	return HostScript{Linux: strings.Join(l, "\n"), Windows: strings.Join(w, "\n")}
}

// ParseTCPProbe returns, for each target, whether it opened.
func ParseTCPProbe(r *RunResult, n int) ([]bool, error) {
	out := make([]bool, n)
	for i := range out {
		v, ok := r.Value(fmt.Sprintf("TCP_%d", i))
		if !ok {
			return nil, fmt.Errorf("the probe printed no TCP_%d line: %s", i, tail([]byte(r.Output), 400))
		}
		out[i] = v == "open"
	}
	return out, nil
}

// Sprout paths on each family (internal/config, ansible/roles/imas_verify).
const (
	LinuxSproutConfig     = "/etc/imas/sprout"
	LinuxGatewayJWTFile   = "/etc/imas/pki/sprout/gateway.jwt"
	windowsSproutConfig   = `$env:ProgramData\imas\sprout`
	windowsGatewayJWTFile = `$env:ProgramData\imas\pki\sprout\gateway.jwt`
)

// GatewayClaims prints GW_PAYLOAD: the payload segment of the sprout's
// gateway JWT (its claims: tenant_id, sprout_id, sub, exp), never the
// header or signature, so the token itself is not printed. Read it with
// DecodeSegment.
func GatewayClaims() HostScript {
	return HostScript{
		Linux: fmt.Sprintf(`f=%s
if [ -r "$f" ]; then echo "__IMAS_UAT_GW_PAYLOAD=$(cut -d. -f2 < "$f" | tr -d '\r\n')"; else echo "__IMAS_UAT_GW_PAYLOAD="; exit 3; fi`, LinuxGatewayJWTFile),
		Windows: fmt.Sprintf(`$f = "%s"
if (Test-Path -LiteralPath $f) { Write-Output ('__IMAS_UAT_GW_PAYLOAD=' + ((Get-Content -Raw -LiteralPath $f).Trim().Split('.')[1])) } else { Write-Output '__IMAS_UAT_GW_PAYLOAD='; $global:LASTEXITCODE = 3 }`, windowsGatewayJWTFile),
	}
}

// PackageInfo prints PKG_VERSION (the installed imas-sprout package
// version, empty if none), SERVICE (active|inactive) and FARMER (the
// config file's farmerinterface).
func PackageInfo() HostScript {
	return HostScript{
		Linux: fmt.Sprintf(`v=""
if command -v dpkg-query >/dev/null 2>&1; then v=$(dpkg-query -W -f='${Version}' imas-sprout 2>/dev/null); fi
if [ -z "$v" ] && command -v rpm >/dev/null 2>&1; then v=$(rpm -q --qf '%%{VERSION}-%%{RELEASE}' imas-sprout 2>/dev/null | grep -v 'not installed'); fi
echo "__IMAS_UAT_PKG_VERSION=$v"
if systemctl is-active --quiet imas-sprout; then echo "__IMAS_UAT_SERVICE=active"; else echo "__IMAS_UAT_SERVICE=inactive"; fi
echo "__IMAS_UAT_FARMER=$(sed -n 's/^farmerinterface:[[:space:]]*//p' %s | tr -d "\"'" | head -n1)"`, LinuxSproutConfig),
		Windows: fmt.Sprintf(`$v = ''
$k = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'imas*sprout*' } | Select-Object -First 1
if ($k) { $v = $k.DisplayVersion }
Write-Output ('__IMAS_UAT_PKG_VERSION=' + $v)
$s = Get-Service -Name 'imas-sprout' -ErrorAction SilentlyContinue
if ($s -and $s.Status -eq 'Running') { Write-Output '__IMAS_UAT_SERVICE=active' } else { Write-Output '__IMAS_UAT_SERVICE=inactive' }
$m = Select-String -LiteralPath "%s" -Pattern '^farmerinterface:\s*(.+)$' -ErrorAction SilentlyContinue | Select-Object -First 1
$fi = ''
if ($m) { $fi = $m.Matches[0].Groups[1].Value.Trim().Trim('"', "'") }
Write-Output ('__IMAS_UAT_FARMER=' + $fi)`, windowsSproutConfig),
	}
}

// RemoveFiles deletes paths, ignoring the ones that don't exist.
func RemoveFiles(paths ...string) HostScript {
	var l, w []string
	for _, p := range paths {
		l = append(l, "rm -f "+ShQuote(p))
		w = append(w, "Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "+PSQuote(p))
	}
	return HostScript{Linux: strings.Join(l, "\n"), Windows: strings.Join(w, "\n")}
}

// TouchCmd is a cmd.run that creates an empty file at path on the
// sprout's family, without a shell.
func TouchCmd(sp Sprout, path string) CmdRun {
	if sp.IsWindows() {
		return CmdRun{
			Cmd:  "powershell.exe",
			Args: []string{"-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType File -Force -Path " + PSQuote(path) + " | Out-Null"},
		}
	}
	return CmdRun{Cmd: "touch", Args: []string{path}}
}

// TrueCmd is a cmd.run that succeeds and changes nothing.
func TrueCmd(sp Sprout) CmdRun {
	if sp.IsWindows() {
		return CmdRun{Cmd: "hostname.exe"}
	}
	return CmdRun{Cmd: "id -u"}
}

// ExitCmd is a cmd.run that exits with code.
func ExitCmd(sp Sprout, code int) CmdRun {
	if sp.IsWindows() {
		return CmdRun{Cmd: "cmd.exe", Args: []string{"/c", "exit", strconv.Itoa(code)}}
	}
	return CmdRun{Cmd: "sh", Args: []string{"-c", "exit " + strconv.Itoa(code)}}
}

// SleepCmd is a cmd.run that sleeps for seconds.
func SleepCmd(sp Sprout, seconds int) CmdRun {
	if sp.IsWindows() {
		return CmdRun{Cmd: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds " + strconv.Itoa(seconds)}}
	}
	return CmdRun{Cmd: "sleep " + strconv.Itoa(seconds)}
}
