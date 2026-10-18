package fleetsign

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestWinACLError checks the Windows owner and DACL rules on descriptors
// as readWindowsACL would return them (a fake ACL reader), so it runs on
// every platform.
func TestWinACLError(t *testing.T) {
	const (
		users     = "S-1-5-32-545"
		authUsers = "S-1-5-11"
		everyone  = "S-1-1-0"
		creator   = "S-1-3-0"
		aUser     = "S-1-5-21-1-2-3-1001"

		fullAccess  = 0x001f01ff // FILE_ALL_ACCESS
		readExecute = 0x001200a9 // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
		appendData  = 0x00000004 // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
		writeDAC    = 0x00040000
	)
	allow := func(sid string, mask uint32, flags uint8) winACE {
		return winACE{aceType: aceTypeAllowed, flags: flags, mask: mask, sid: sid}
	}
	// What the MSI's MsiLockPermissionsEx gives %ProgramData%\imas
	// (D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)), as a child inherits it.
	programData := []winACE{allow(sidSystem, fullAccess, aceFlagInherited), allow(sidAdministrators, fullAccess, aceFlagInherited)}

	for _, tc := range []struct {
		name string
		acl  winACL
		want string // "" accepted, else a substring of the refusal
	}{
		{"SYSTEM-owned, the MSI's DACL", winACL{owner: sidSystem, aces: programData}, ""},
		{"Administrators-owned", winACL{owner: sidAdministrators, aces: programData}, ""},
		{"TrustedInstaller may write", winACL{owner: sidSystem, aces: append(programData, allow(sidTrustedInstaller, fullAccess, 0))}, ""},
		{"Users may read", winACL{owner: sidSystem, aces: append(programData, allow(users, readExecute, aceFlagInherited))}, ""},
		{"inherit-only Users write applies to children only", winACL{owner: sidSystem, aces: append(programData, allow(users, appendData, aceFlagInheritOnly))}, ""},
		{"a deny ACE takes access away", winACL{owner: sidSystem, aces: append(programData, winACE{aceType: aceTypeDenied, mask: fullAccess, sid: everyone})}, ""},

		{"owned by a user", winACL{owner: aUser, aces: programData}, "owner " + aUser},
		{"owned by Users", winACL{owner: users, aces: programData}, "not SYSTEM or Administrators"},
		{"NULL DACL", winACL{owner: sidSystem, nullDACL: true}, "no DACL"},
		// %ProgramData%'s own default: Users may create files and folders,
		// inherited by anything created under it without a protected DACL.
		{"inherited write for Users", winACL{owner: sidSystem, aces: append(programData, allow(users, appendData, aceFlagInherited))}, "an inherited ACE grants write access (mask 0x00000004) to " + users},
		{"explicit full control for Users", winACL{owner: sidSystem, aces: append(programData, allow(users, fullAccess, 0))}, "an explicit ACE"},
		{"Authenticated Users modify", winACL{owner: sidSystem, aces: append(programData, allow(authUsers, 0x001301bf, aceFlagInherited))}, authUsers},
		{"Everyone WRITE_DAC", winACL{owner: sidSystem, aces: append(programData, allow(everyone, writeDAC, 0))}, everyone},
		{"Everyone GENERIC_WRITE", winACL{owner: sidSystem, aces: append(programData, allow(everyone, 0x40000000, 0))}, everyone},
		{"CREATOR OWNER on the object itself", winACL{owner: sidSystem, aces: append(programData, allow(creator, fullAccess, 0))}, creator},
		{"a user account", winACL{owner: sidSystem, aces: append(programData, allow(aUser, fullAccess, aceFlagInherited))}, aUser},
		{"an object allow ACE with write", winACL{owner: sidSystem, aces: append(programData, winACE{aceType: 5, mask: fullAccess})}, "type 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := winACLError(tc.acl)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && err == nil:
				t.Errorf("accepted, want a refusal naming %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("refusal %q does not name %q", err, tc.want)
			}
		})
	}
}

// fakeInfo is an os.FileInfo with a given mode, for plainDir.
type fakeInfo struct{ mode os.FileMode }

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// TestPlainDir: a Windows junction (Lstat: ModeDir|ModeIrregular) and a
// symlink are not plain directories.
func TestPlainDir(t *testing.T) {
	for mode, want := range map[os.FileMode]bool{
		os.ModeDir | 0o700:                    true,
		os.ModeDir | os.ModeIrregular | 0o700: false,
		os.ModeDir | os.ModeSymlink | 0o700:   false,
		os.ModeSymlink | 0o777:                false,
		0o600:                                 false,
	} {
		if got := plainDir(fakeInfo{mode}); got != want {
			t.Errorf("plainDir(%v) = %v, want %v", mode, got, want)
		}
	}
}
