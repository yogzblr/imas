package ingredients

import (
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func TestParseReleaseTag(t *testing.T) {
	for tag, want := range map[string][2]string{"v0.1.0": {"0.1.0", ""}, "v1.22.3-rc.4": {"1.22.3", "rc.4"}} {
		core, pre, err := ParseReleaseTag(tag)
		if err != nil || core != want[0] || pre != want[1] {
			t.Errorf("%s: %q %q %v", tag, core, pre, err)
		}
	}
	for _, bad := range []string{"", "0.1.0", "v0.1", "v0.1.0-beta", "latest"} {
		if _, _, err := ParseReleaseTag(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPackageVersionIs(t *testing.T) {
	for _, tc := range []struct {
		installed, tag string
		want           bool
	}{
		{"0.1.0~rc.4+git", "v0.1.0-rc.4", true},
		{"0.1.0~rc.4+git-1", "v0.1.0-rc.4", true},
		{"1:0.1.0~rc.4+git-1", "v0.1.0-rc.4", true},
		{"0.1.0~rc.40+git", "v0.1.0-rc.4", false},
		{"0.1.0~rc.3+git", "v0.1.0-rc.4", false},
		{"0.1.0+git", "v0.1.0", true},
		{"0.1.0-1", "v0.1.0", true},
		{"0.1.0~rc.4+git", "v0.1.0", false},
		{"0.1.0", "v0.1.0", true},
		{"", "v0.1.0", false},
	} {
		if got := PackageVersionIs(tc.installed, tc.tag); got != tc.want {
			t.Errorf("PackageVersionIs(%q, %q) = %v", tc.installed, tc.tag, got)
		}
	}
}

// TestL4L5ScriptsParse checks the L4/L5 host scripts are valid POSIX
// sh, and that the shell's is_release agrees with PackageVersionIs.
func TestL4L5ScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	down, err := DowngradeScript("v0.1.0-rc.3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DowngradeScript("nope"); err == nil {
		t.Error("a bad tag is refused")
	}
	for name, s := range map[string]string{"downgrade": down, "upgrade": UpgradeScript("0.1.0~rc.4+git")} {
		if out, err := exec.Command(sh, "-n", "-c", s).CombinedOutput(); err != nil {
			t.Errorf("%s script: %v: %s", name, err, out)
		}
	}
	for _, tc := range []struct {
		v    string
		want bool
	}{{"0.1.0~rc.3+git", true}, {"0.1.0~rc.3+git-1", true}, {"0.1.0~rc.30+git", false}, {"0.1.0~rc.4+git", false}} {
		script := "want=0.1.0-rc.3\n" + shVersionFns + "is_release '" + tc.v + "'"
		err := exec.Command(sh, "-c", script).Run()
		if (err == nil) != tc.want || PackageVersionIs(tc.v, "v0.1.0-rc.3") != tc.want {
			t.Errorf("is_release %q: sh %v, want %v", tc.v, err == nil, tc.want)
		}
	}
}

func TestFlagOn(t *testing.T) {
	for v, want := range map[string]bool{"on": true, "TRUE": true, "1": true, "yes": true, "": false, "off": false, "0": false} {
		if FlagOn(v) != want {
			t.Errorf("FlagOn(%q)", v)
		}
	}
}

func TestAlteredScratchVersion(t *testing.T) {
	for tag, want := range map[string]string{
		"v0.2.0-rc.4": "v0.2.1-uat.altered",
		"v1.9.9":      "v1.9.10-uat.altered",
		"v0.1.0":      "v0.1.1-uat.altered",
	} {
		got, err := AlteredScratchVersion(tag)
		if err != nil || got != want {
			t.Errorf("AlteredScratchVersion(%q) = %q, %v; want %q", tag, got, err, want)
		}
		// Above the release, so the sprout's downgrade check passes and
		// only the signature can refuse it.
		if semver.Compare(got, tag) <= 0 {
			t.Errorf("%s is not above %s", got, tag)
		}
	}
	if _, err := AlteredScratchVersion("latest"); err == nil {
		t.Error("a bad tag is accepted")
	}
}

// TestRefusalCheckScript runs the L5 refusal check under sh: valid POSIX
// sh, every value printed, and a hostile jid stays one quoted word.
func TestRefusalCheckScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, jid := range []string{"jid_0123", "x'; touch /tmp/pwned; '"} {
		s := RefusalCheckScript(jid)
		if out, err := exec.Command(sh, "-n", "-c", s).CombinedOutput(); err != nil {
			t.Errorf("jid %q: %v: %s", jid, err, out)
		}
		if !strings.Contains(s, harness.ShQuote(SproutJobLogDir+"/"+jid+".jsonl")) {
			t.Errorf("jid %q is not quoted in the script", jid)
		}
	}
	out, err := exec.Command(sh, "-c", RefusalCheckScript("no-such-job")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	res := harness.ParseRunOutput(out)
	for k, want := range map[string]string{"JOBLOG": "absent", "SIG_REFUSED": "no", "DOWNLOADED": "no"} {
		if got, _ := res.Value(k); got != want {
			t.Errorf("%s = %q, want %q (output %s)", k, got, want, out)
		}
	}
	for _, k := range []string{"STAGED", "PKG_VERSION", "KEYRING_SHA", "JOBLOG_TAIL"} {
		if _, ok := res.Value(k); !ok {
			t.Errorf("%s not printed (output %s)", k, out)
		}
	}
}
