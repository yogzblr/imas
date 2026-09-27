//go:build !windows

package config

import (
	"testing"

	"github.com/taigrr/jety"
)

// TestUnixDefaultPaths pins the Unix defaults the packages (rpm/deb/apk)
// lay out; the Windows ones live in paths_windows.go.
func TestUnixDefaultPaths(t *testing.T) {
	for _, tc := range []struct{ name, got, want string }{
		{"config root", defaultSystemConfigRoot(), "/etc/imas"},
		{"cachedir", defaultSproutCacheDir(), "/var/cache/imas/sprout/files/provided"},
		{"joblogdir", defaultSproutJobLogDir(), "/var/cache/imas/sprout/jobs"},
		{"handled jobs", defaultSproutHandledJobsFile(), "/var/lib/imas/sprout/handled-jobs"},
		{"bus status", SproutBusStatusFile(), "/var/lib/imas/sprout/bus-status.json"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if err := SecureSproutConfigRoot(); err != nil {
		t.Errorf("SecureSproutConfigRoot() = %v, want no-op", err)
	}
}

func TestLoadConfig_SproutUnixDefaults(t *testing.T) {
	tmpRoot := t.TempDir()
	writeTempConfig(t, tmpRoot, "sprout", "")
	resetForBinaryTest(t, tmpRoot)

	LoadConfig("sprout")

	for _, tc := range []struct{ name, got, want string }{
		{"ConfigRoot", ConfigRoot, tmpRoot + "/"},
		{"SproutPKI", SproutPKI, tmpRoot + "/pki/sprout/"},
		{"CacheDir", CacheDir, "/var/cache/imas/sprout/files/provided"},
		{"JobLogDir", JobLogDir, "/var/cache/imas/sprout/jobs"},
		{"SproutHandledJobsFile", SproutHandledJobsFile, "/var/lib/imas/sprout/handled-jobs"},
		{"configroot", jety.GetString("configroot"), tmpRoot + "/"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}
