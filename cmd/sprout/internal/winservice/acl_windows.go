//go:build windows

package winservice

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which owns and can
// write most of Program Files and System32. A service SID is S-1-5-80
// followed by the SHA-1 of the upper-cased service name (UTF-16LE).
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// Access rights that let a principal replace a file, or a file in a
// directory: write/append data (add file/subdirectory on a directory),
// delete child, delete, change the DACL or owner, and the generic rights
// that map to them.
const replaceRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x40 /* FILE_DELETE_CHILD */ |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// checkNotUserWritable returns an error if anyone but SYSTEM,
// Administrators or TrustedInstaller could replace exe: through the file
// itself or through its directory (a new file, a rename, a deleted child).
// A LocalSystem service whose binary a user can replace hands that user
// SYSTEM. Only the file and its directory are checked, which is what the
// usual "modifiable service binary" audits check; deny ACEs are ignored,
// so the check errs towards refusing.
func checkNotUserWritable(exe string) error {
	for _, p := range []string{exe, filepath.Dir(exe)} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("read the security of %s: %w", p, err)
		}
		if who := untrustedWriters(sd); len(who) > 0 {
			return fmt.Errorf("%s can be modified by %s, and the service would run it as LocalSystem: "+
				"copy the binary to a directory only administrators can write, such as %%ProgramFiles%%\\imas, "+
				"and install from there", p, strings.Join(who, ", "))
		}
	}
	return nil
}

// untrustedWriters lists the principals, other than SYSTEM, Administrators
// and TrustedInstaller, that sd's owner and DACL let replace the object.
func untrustedWriters(sd *windows.SECURITY_DESCRIPTOR) []string {
	var who []string
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return []string{"an unknown owner"}
	}
	ownerTrusted := trustedSID(owner)
	if !ownerTrusted {
		// An owner can always rewrite the DACL.
		who = append(who, "its owner "+owner.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return append(who, "an unreadable DACL")
	}
	if dacl == nil {
		return append(who, "everyone (NULL DACL)")
	}
	creatorOwner, _ := windows.StringToSid("S-1-3-0")
	creatorGroup, _ := windows.StringToSid("S-1-3-1")
	ownerRights, _ := windows.StringToSid("S-1-3-4")
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return append(who, "an unreadable ACE")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 ||
			ace.Mask&replaceRights == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case trustedSID(sid),
			// Placeholders that only matter on inherit-only ACEs.
			sid.Equals(creatorOwner), sid.Equals(creatorGroup),
			// OWNER RIGHTS stands for the owner, checked above.
			ownerTrusted && sid.Equals(ownerRights):
			continue
		}
		who = append(who, sid.String())
	}
	return who
}

func trustedSID(sid *windows.SID) bool {
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	ti, err := windows.StringToSid(trustedInstallerSID)
	return err == nil && sid.Equals(ti)
}
