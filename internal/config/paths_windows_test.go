//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/taigrr/jety"
	"golang.org/x/sys/windows"
)

func TestProgramDataFrom(t *testing.T) {
	cases := []struct {
		name  string
		value string
		set   bool
		want  string
	}{
		{"set", `D:\Data`, true, `D:\Data`},
		{"cleaned", `D:\Data\`, true, `D:\Data`},
		{"unset", "", false, `C:\ProgramData`},
		{"empty", "", true, `C:\ProgramData`},
		{"relative", `ProgramData`, true, `C:\ProgramData`},
		{"drive-relative", `\ProgramData`, true, `C:\ProgramData`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				if key != "PROGRAMDATA" {
					t.Errorf("looked up %q, want PROGRAMDATA", key)
				}
				return tc.value, tc.set
			}
			if got := programDataFrom(lookup); got != tc.want {
				t.Errorf("programDataFrom(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestWindowsDefaultPaths(t *testing.T) {
	t.Setenv("PROGRAMDATA", `E:\PD`)
	for _, tc := range []struct{ name, got, want string }{
		{"config root", defaultSystemConfigRoot(), `E:\PD\imas`},
		{"cachedir", defaultSproutCacheDir(), `E:\PD\imas\cache\sprout\files\provided`},
		{"joblogdir", defaultSproutJobLogDir(), `E:\PD\imas\cache\sprout\jobs`},
		{"handled jobs", defaultSproutHandledJobsFile(), `E:\PD\imas\state\sprout\handled-jobs`},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestLoadConfig_SproutWindowsDefaults checks the sprout's resolved paths
// against the MSI layout (packaging/windows/imas-sprout.wxs), with
// %ProgramData% pointed at a temp directory.
func TestLoadConfig_SproutWindowsDefaults(t *testing.T) {
	// Registered before t.Setenv so it runs after PROGRAMDATA is restored
	// (cleanups run last-in first-out).
	t.Cleanup(resetSystemConfigRoot)
	pd := t.TempDir()
	t.Setenv("PROGRAMDATA", pd)
	root := filepath.Join(pd, "imas")
	resetForBinaryTest(t, defaultSystemConfigRoot())
	if systemConfigRoot != root {
		t.Fatalf("systemConfigRoot = %q, want %q", systemConfigRoot, root)
	}

	LoadConfig("sprout")

	if _, err := os.Stat(filepath.Join(root, "sprout")); err != nil {
		t.Errorf("config file not created at %%ProgramData%%\\imas\\sprout: %v", err)
	}
	pki := filepath.Join(root, "pki", "sprout")
	for _, tc := range []struct{ name, got, want string }{
		{"ConfigRoot", ConfigRoot, root + `\`},
		{"CacheDir", CacheDir, filepath.Join(root, "cache", "sprout", "files", "provided")},
		{"JobLogDir", JobLogDir, filepath.Join(root, "cache", "sprout", "jobs")},
		{"SproutHandledJobsFile", SproutHandledJobsFile, filepath.Join(root, "state", "sprout", "handled-jobs")},
		{"SproutPKI", SproutPKI, pki + `\`},
		{"SproutRootCA", SproutRootCA, filepath.Join(pki, "tls-rootca.pem")},
		{"SproutFleetSigningJWKS", SproutFleetSigningJWKS, filepath.Join(pki, "fleet-signing-jwks.json")},
		{"NKeySproutPubFile", NKeySproutPubFile, filepath.Join(pki, "sprout.nkey.pub")},
		{"NKeySproutPrivFile", NKeySproutPrivFile, filepath.Join(pki, "sprout.nkey")},
		{"SproutUserJWTFile", SproutUserJWTFile, filepath.Join(pki, "sprout.jwt")},
		{"SproutGatewayJWTFile", SproutGatewayJWTFile, filepath.Join(pki, "gateway.jwt")},
		{"SproutTenantX25519PubFile", SproutTenantX25519PubFile, filepath.Join(pki, "tenant-x25519.pub")},
		{"SproutBusURLsFile", SproutBusURLsFile, filepath.Join(pki, "bus-urls.json")},
		{"SproutBoxPrivFile", SproutBoxPrivFile, filepath.Join(pki, "sprout-x25519.key")},
		{"SproutBoxPubFile", SproutBoxPubFile, filepath.Join(pki, "sprout-x25519.pub")},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if got := jety.GetString("configroot"); got != root+`\` {
		t.Errorf("configroot = %q, want %q", got, root+`\`)
	}
}

// fileAllAccess is FILE_ALL_ACCESS, SDDL's "FA", which x/sys/windows
// doesn't define: STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

func TestSproutConfigRootSDDL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(sproutConfigRootSDDL)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("DACL is not protected: %ProgramData%'s inheritable ACEs would still apply")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("DACL = %v, want 2 ACEs", dacl)
	}
	var sids []*windows.SID
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("ACE %d type = %d, want allow", i, ace.Header.AceType)
		}
		if want := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE); ace.Header.AceFlags != want {
			t.Errorf("ACE %d flags = %#x, want %#x (OICI)", i, ace.Header.AceFlags, want)
		}
		if ace.Mask != fileAllAccess {
			t.Errorf("ACE %d mask = %#x, want FILE_ALL_ACCESS", i, ace.Mask)
		}
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)))
	}
	if !sids[0].IsWellKnown(windows.WinLocalSystemSid) || !sids[1].IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Errorf("ACE trustees = %s, %s; want SYSTEM, Administrators", sids[0], sids[1])
	}
}

// TestSecureDir applies the DACL to a temp directory. It needs an
// elevated token: the DACL leaves only SYSTEM and Administrators access,
// so a non-elevated test could neither read it back nor clean it up.
func TestSecureDir(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (Administrators) token")
	}
	dir := filepath.Join(t.TempDir(), "imas")
	if err := secureDir(dir, sproutConfigRootSDDL); err != nil {
		t.Fatal(err)
	}
	// A file created afterwards inherits the DACL, as os.WriteFile's
	// mode sets none.
	f := filepath.Join(dir, "sprout")
	if err := os.WriteFile(f, []byte("jointoken: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Idempotent: the second run re-applies without error.
	if err := secureDir(dir, sproutConfigRootSDDL); err != nil {
		t.Fatalf("second secureDir: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: DACL not protected (%s)", dir, sd)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !trustedOwner(owner) {
		t.Errorf("%s owner = %s, want SYSTEM or Administrators", dir, owner)
	}
	assertOnlySystemAndAdmins(t, dir)
	assertOnlySystemAndAdmins(t, f)
}

func assertOnlySystemAndAdmins(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatalf("%s: NULL DACL (everyone has access)", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Errorf("%s: ACE %d grants %s (%s)", path, i, sid, sd)
		}
	}
}
