//go:build windows

package fleetsign

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkOwnerAndMode checks the owner and DACL of path (winACLError): the
// Windows equivalent of the Unix owner and mode check. Mode bits mean
// nothing on Windows, so maxPerm is not used.
func checkOwnerAndMode(path string, _ os.FileInfo, _ os.FileMode, _ bool) error {
	acl, err := readWindowsACL(path)
	if err != nil {
		return fmt.Errorf("%w: %s: reading its security descriptor: %v", ErrUnsafePath, path, err)
	}
	if err := winACLError(acl); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnsafePath, path, err)
	}
	return nil
}

// readWindowsACL reads path's owner and DACL, without following a
// reparse point (the caller has refused those already with Lstat).
func readWindowsACL(path string) (winACL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return winACL{}, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return winACL{}, err
	}
	out := winACL{owner: owner.String()}
	dacl, _, err := sd.DACL()
	if err != nil {
		return winACL{}, err
	}
	if dacl == nil {
		// A NULL DACL grants everyone full access.
		out.nullDACL = true
		return out, nil
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return winACL{}, err
		}
		e := winACE{aceType: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
			e.sid = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		out.aces = append(out.aces, e)
	}
	return out, nil
}
