package harness

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func needShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts; the harness runs on the Linux runner")
	}
	for _, tool := range []string{"sh", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
}

// runLinux runs a host script through the Linux wrapper locally, as
// vmctl.sh would on a Linux VM, and parses the output.
func runLinux(t *testing.T, script string) *RunResult {
	t.Helper()
	out, _ := exec.Command("sh", "-c", WrapScript(FamilyLinux, script)).CombinedOutput()
	return ParseRunOutput(out)
}

func TestLinuxWrapperKeepsExitCodeAndValues(t *testing.T) {
	needShell(t)
	res := runLinux(t, "echo noise\necho '__IMAS_UAT_FOO=a=b c'\nexit 3")
	if res.ExitCode != 3 {
		t.Errorf("exit code %d", res.ExitCode)
	}
	if v, _ := res.Value("FOO"); v != "a=b c" {
		t.Errorf("FOO %q", v)
	}
	if res := runLinux(t, "true"); res.ExitCode != 0 {
		t.Errorf("exit code %d", res.ExitCode)
	}
}

func TestParseRunOutput(t *testing.T) {
	out := "Enable succeeded:\r\n[stdout]\r\n  __IMAS_UAT_EXISTS=yes\r\n__IMAS_UAT_bad=x\n__IMAS_UAT_X\n" +
		"prefix __IMAS_UAT_K=1\n__IMAS_UAT_K=2\n__IMAS_UAT_RC=0\r\n[stderr]\n"
	res := ParseRunOutput([]byte(out))
	if res.ExitCode != 0 {
		t.Errorf("rc %d", res.ExitCode)
	}
	if v, _ := res.Value("EXISTS"); v != "yes" {
		t.Errorf("EXISTS %q", v)
	}
	if v, _ := res.Value("K"); v != "2" {
		t.Errorf("K %q (the last value wins)", v)
	}
	if _, ok := res.Value("bad"); ok {
		t.Error("a lowercase key was parsed")
	}
	if ParseRunOutput([]byte("nothing")).ExitCode != -1 {
		t.Error("no RC line should give -1")
	}
}

func TestWindowsWrapperShape(t *testing.T) {
	w := WrapScript(FamilyWindows, "Write-Output '__IMAS_UAT_A=1'")
	for _, want := range []string{"& {", "Write-Output '__IMAS_UAT_A=1'", "'" + ValuePrefix + "RC=' + $__imasRc", "catch"} {
		if !strings.Contains(w, want) {
			t.Errorf("the Windows wrapper lacks %q:\n%s", want, w)
		}
	}
	if pwsh, err := exec.LookPath("pwsh"); err == nil {
		out, _ := exec.Command(pwsh, "-NoProfile", "-Command", WrapScript(FamilyWindows, "Write-Output '__IMAS_UAT_A=1'; $global:LASTEXITCODE = 4")).CombinedOutput()
		res := ParseRunOutput(out)
		if res.ExitCode != 4 || res.Values["A"] != "1" {
			t.Errorf("pwsh: %+v", res)
		}
	}
}

// fakeVMCtl writes a vmctl.sh that records its arguments and answers like
// the real one.
func fakeVMCtl(t *testing.T, body string) (*VMCtl, string) {
	t.Helper()
	needShell(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := "#!/usr/bin/env bash\nprintf '%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" >> " + ShQuote(log) + "\n" + body
	path := filepath.Join(dir, "vmctl.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return NewVMCtl(path, "/run/uat.json"), log
}

func TestVMCtlRunsThroughTheScript(t *testing.T) {
	// The fake runs the command it is given, as run-command would.
	v, log := fakeVMCtl(t, `case "$2" in
run) echo "[stdout]"; sh -c "$4"; echo "exit code: $?";;
restart) exit 0;;
stop-sprout) echo "no such VM $3" >&2; exit 7;;
*) exit 0;;
esac`)
	c := context.Background()
	res, err := v.Run(c, "t1-ubuntu", FamilyLinux, "echo __IMAS_UAT_V=ok; exit 5")
	if err != nil || res.ExitCode != 5 || res.Values["V"] != "ok" {
		t.Errorf("run: %+v %v", res, err)
	}
	if err := v.Restart(c, "t1-ubuntu"); err != nil {
		t.Errorf("restart: %v", err)
	}
	err = v.StopSprout(c, "t9")
	if err == nil || !strings.Contains(err.Error(), "exited 7") || !strings.Contains(err.Error(), "no such VM t9") {
		t.Errorf("stop-sprout: %v", err)
	}
	calls, _ := os.ReadFile(log)
	if !strings.HasPrefix(string(calls), "/run/uat.json|run|t1-ubuntu\n") {
		t.Errorf("calls:\n%s", calls)
	}
}

func TestVMCtlNoStatusLine(t *testing.T) {
	v, _ := fakeVMCtl(t, `echo "az: run-command failed"; exit 1`)
	_, err := v.Run(context.Background(), "t1-ubuntu", FamilyLinux, "true")
	if err == nil || !strings.Contains(err.Error(), "no exit status line") || !strings.Contains(err.Error(), "run-command failed") {
		t.Errorf("want an error with vmctl's output, got %v", err)
	}
	var none *VMCtl
	if _, err := none.Run(context.Background(), "x", FamilyLinux, "true"); err == nil || !strings.Contains(err.Error(), EnvVMCtl) {
		t.Errorf("no vmctl: %v", err)
	}
	if err := NewVMCtl("", "u").Restart(context.Background(), "x"); err == nil {
		t.Error("an empty path should fail")
	}
}

func TestVMCtlTimeout(t *testing.T) {
	v, _ := fakeVMCtl(t, `sleep 5`)
	v.Timeout = 300 * time.Millisecond
	start := time.Now()
	if err := v.Restart(context.Background(), "x"); err == nil {
		t.Error("want a timeout")
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("the timeout didn't stop the call (%s)", time.Since(start))
	}
}

func TestVMCtlSerializesPerVM(t *testing.T) {
	var running, maxSeen atomic.Int32
	v := NewVMCtl("", "u")
	v.Exec = func(_ context.Context, args []string) ([]byte, int, error) {
		n := running.Add(1)
		for {
			m := maxSeen.Load()
			if n <= m || maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return []byte("__IMAS_UAT_RC=0\n"), 0, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.Run(context.Background(), "same-vm", FamilyLinux, "true")
		}()
	}
	wg.Wait()
	if maxSeen.Load() != 1 {
		t.Errorf("%d calls ran at once on one VM", maxSeen.Load())
	}
}

func TestHostScriptsOnLinux(t *testing.T) {
	needShell(t)
	for _, tool := range []string{"base64", "stat", "timeout"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	dir := t.TempDir()
	odd := filepath.Join(dir, "it's here")
	if err := os.WriteFile(odd, []byte("hello\nworld\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sp := Sprout{OS: OSUbuntu}

	fi, err := ParseFileState(runLinux(t, FileState(sp, odd).Linux))
	if err != nil || !fi.Exists || fi.Content != "hello\nworld\n" || fi.Owner == "" || fi.MTime == 0 {
		t.Errorf("FileState %+v %v", fi, err)
	}
	fi, err = ParseFileState(runLinux(t, FileState(sp, odd+"x").Linux))
	if err != nil || fi.Exists {
		t.Errorf("missing file %+v %v", fi, err)
	}
	ex, err := ParseMultiFileState(runLinux(t, MultiFileState([]string{odd, odd + "x"}).Linux), 2)
	if err != nil || !ex[0] || ex[1] {
		t.Errorf("MultiFileState %v %v", ex, err)
	}
	if _, err := ParseMultiFileState(&RunResult{Values: map[string]string{}}, 1); err == nil {
		t.Error("missing lines should fail")
	}
	if res := runLinux(t, RemoveFiles(odd, odd+"x").Linux); res.ExitCode != 0 {
		t.Errorf("RemoveFiles exit %d", res.ExitCode)
	}
	if _, err := os.Stat(odd); !os.IsNotExist(err) {
		t.Error("RemoveFiles left the file")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	targets := []Target{{"127.0.0.1", open}, {"127.0.0.1", closedPort}}
	got, err := ParseTCPProbe(runLinux(t, TCPProbe(targets).Linux), 2)
	if err != nil || !got[0] || got[1] {
		t.Errorf("TCPProbe %v %v (ports %d, %d)", got, err, open, closedPort)
	}
	if targets[0].String() != "127.0.0.1:"+strconv.Itoa(open) {
		t.Errorf("Target.String %s", targets[0])
	}
}

func TestHostScriptShapes(t *testing.T) {
	w := Sprout{OS: OSWindows}
	l := Sprout{OS: OSAlma}
	if c := TouchCmd(w, `C:\a b\it's`); c.Cmd != "powershell.exe" || !strings.Contains(c.Args[3], `-Path 'C:\a b\it''s'`) {
		t.Errorf("TouchCmd windows %+v", c)
	}
	if c := TouchCmd(l, "/var/tmp/x"); c.Cmd != "touch" || c.Args[0] != "/var/tmp/x" {
		t.Errorf("TouchCmd linux %+v", c)
	}
	if c := ExitCmd(w, 7); c.Cmd != "cmd.exe" || strings.Join(c.Args, " ") != "/c exit 7" {
		t.Errorf("ExitCmd windows %+v", c)
	}
	if c := ExitCmd(l, 7); c.Args[1] != "exit 7" {
		t.Errorf("ExitCmd linux %+v", c)
	}
	if c := SleepCmd(l, 9); c.Cmd != "sleep 9" || c.Args != nil {
		t.Errorf("SleepCmd linux %+v", c)
	}
	if c := TrueCmd(w); c.Cmd != "hostname.exe" {
		t.Errorf("TrueCmd windows %+v", c)
	}
	for _, h := range []HostScript{FileState(w, `C:\x`), GatewayClaims(), PackageInfo(), TCPProbe([]Target{{"h", 1}}), MultiFileState([]string{"a"})} {
		if h.For(FamilyWindows) == "" || h.For(FamilyLinux) == "" || h.For(FamilyWindows) == h.For(FamilyLinux) {
			t.Errorf("a host script lacks a family: %+v", h)
		}
	}
	if PSQuote("it's") != "'it''s'" || ShQuote("it's") != `'it'"'"'s'` {
		t.Error("quoting")
	}
}
