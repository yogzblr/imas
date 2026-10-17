package fleetsign

import (
	"errors"
	"fmt"
)

// The Windows half of the trust path check (trustpath.go), on a parsed
// security descriptor, so it is tested on every platform with a fake
// reader's output (trustpath_windows.go reads the real one).

// winACL is a file's owner and DACL as readWindowsACL reads them.
type winACL struct {
	owner string // the owner SID, "S-1-5-18"
	// nullDACL: the object has no DACL, which grants everyone everything.
	nullDACL bool
	aces     []winACE
}

// winACE is one ACE. sid is set for the access-allowed and access-denied
// types; the others are refused when they allow anything (winACLError).
type winACE struct {
	aceType uint8
	flags   uint8
	mask    uint32
	sid     string
}

// ACE types and flags, and the access rights that let a principal change
// a file or directory, its entries, its DACL or its owner (winnt.h).
const (
	aceTypeAllowed = 0x0
	aceTypeDenied  = 0x1

	aceFlagInheritOnly = 0x08
	aceFlagInherited   = 0x10

	winWriteMask uint32 = 0x00000002 | // FILE_WRITE_DATA, FILE_ADD_FILE
		0x00000004 | // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
		0x00000010 | // FILE_WRITE_EA
		0x00000040 | // FILE_DELETE_CHILD
		0x00000100 | // FILE_WRITE_ATTRIBUTES
		0x00010000 | // DELETE
		0x00040000 | // WRITE_DAC
		0x00080000 | // WRITE_OWNER
		0x10000000 | // GENERIC_ALL
		0x40000000 | // GENERIC_WRITE
		0x02000000 // MAXIMUM_ALLOWED
)

// Principals that may own and write a trust path: LocalSystem, the
// built-in Administrators group, and TrustedInstaller (which owns
// %SystemRoot% and may appear on a path an installer created).
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

var (
	winTrustedOwners  = map[string]bool{sidSystem: true, sidAdministrators: true}
	winTrustedWriters = map[string]bool{sidSystem: true, sidAdministrators: true, sidTrustedInstaller: true}
)

// winACLError is nil when acl is owned by SYSTEM or Administrators and
// no ACE that applies to the object itself (inherited or explicit) lets
// any other principal (Users, Authenticated Users, Everyone, CREATOR
// OWNER, a user account) write it. Deny ACEs only take access away and
// inherit-only ACEs apply to children, so neither is counted; an allow
// ACE of a type this check doesn't parse (object or callback ACEs) is
// refused rather than guessed at, as is a NULL DACL.
func winACLError(acl winACL) error {
	if !winTrustedOwners[acl.owner] {
		return fmt.Errorf("owner %s is not SYSTEM or Administrators", acl.owner)
	}
	if acl.nullDACL {
		return errors.New("no DACL: everyone has full access")
	}
	for _, e := range acl.aces {
		if e.flags&aceFlagInheritOnly != 0 || e.aceType == aceTypeDenied {
			continue
		}
		if e.mask&winWriteMask == 0 {
			continue
		}
		if e.aceType != aceTypeAllowed {
			return fmt.Errorf("an allow ACE of type %d grants write access", e.aceType)
		}
		if !winTrustedWriters[e.sid] {
			how := "an explicit"
			if e.flags&aceFlagInherited != 0 {
				how = "an inherited"
			}
			return fmt.Errorf("%s ACE grants write access (mask 0x%08x) to %s", how, e.mask, e.sid)
		}
	}
	return nil
}
