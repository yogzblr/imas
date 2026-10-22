package packagingtest

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mountNamespaceSettings are the systemd.exec settings that put a service
// in a mount namespace of its own (with slave propagation). A sprout in
// one mounts and unmounts only inside it, invisible to the host, so the
// mount ingredient cannot work (UAT Run 2, I.mount.*), and the Protect*
// ones also make /proc/sys or the cgroup tree read-only to it.
var mountNamespaceSettings = []string{
	"PrivateTmp", "PrivateDevices", "PrivateMounts", "PrivateNetwork",
	"ProtectSystem", "ProtectHome", "ProtectKernelTunables",
	"ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
	"ProtectClock", "ProtectHostname", "ProtectProc", "ReadWritePaths",
	"ReadOnlyPaths", "InaccessiblePaths", "TemporaryFileSystem",
	"BindPaths", "BindReadOnlyPaths", "RootDirectory", "RootImage",
	"MountFlags",
}

// The sprout's units must share the host's mount namespace: the sprout
// manages the host.
func TestSproutUnitsShareTheHostMountNamespace(t *testing.T) {
	for _, unit := range []string{"imas-sprout.service", "imas-sprout-standalone.service"} {
		path := filepath.Join(repoRoot(t), "packaging", "systemd", unit)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			key, _, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			for _, s := range mountNamespaceSettings {
				if strings.TrimSpace(key) == s {
					t.Errorf("%s:%d sets %s, which gives the sprout its own mount namespace", unit, n, s)
				}
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
}
