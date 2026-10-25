//go:build windows

package windacl

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

// toExplicitAccess renders an aceEntry back to the form
// SetEntriesInAcl expects. The Trustee.Name field is reused to hold a
// *SID (rather than a string) when TrusteeForm is TRUSTEE_IS_SID, the
// same convention github.com/hectane/go-acl's own GrantSid/DenySid
// helpers use. The SID is parsed from sidString; the returned value
// keeps it reachable for as long as the EXPLICIT_ACCESS is.
func (a aceEntry) toExplicitAccess() (api.ExplicitAccess, error) {
	sid, err := windows.StringToSid(a.sidString)
	if err != nil {
		return api.ExplicitAccess{}, fmt.Errorf("%w: %q: %v", ErrUnknownPrincipal, a.sidString, err)
	}
	return api.ExplicitAccess{
		AccessPermissions: a.rights,
		AccessMode:        a.mode,
		Inheritance:       a.inherit,
		Trustee: api.Trustee{
			TrusteeForm: api.TRUSTEE_IS_SID,
			Name:        (*uint16)(unsafe.Pointer(sid)),
		},
	}, nil
}

// fromExplicitAccess is the inverse of toExplicitAccess, for entries
// read back from GetExplicitEntriesFromAclW (which always returns
// TRUSTEE_IS_SID entries, since ACEs store SIDs, never names).
func fromExplicitAccess(e api.ExplicitAccess) aceEntry {
	sid := (*windows.SID)(unsafe.Pointer(e.Trustee.Name))
	return aceEntry{
		sidString: sid.String(),
		mode:      e.AccessMode,
		rights:    e.AccessPermissions,
		inherit:   e.Inheritance,
	}
}

// kindOf is what req's object is: a registry key, a directory or a file.
// A file whose type cannot be read is taken as a file, the kind whose
// comparison ignores inheritance flags; the ACL calls report the real
// error if the path is wrong.
func kindOf(req aclRequest) objectKind {
	if req.objType == objectTypeRegistry {
		return kindRegistry
	}
	if fi, err := os.Stat(req.name); err == nil && fi.IsDir() {
		return kindDirectory
	}
	return kindFile
}
