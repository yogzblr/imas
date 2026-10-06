package ingredients

import (
	"os/exec"
	"testing"
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
