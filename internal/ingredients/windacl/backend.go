//go:build windows

package windacl

import (
	"fmt"
	"unsafe"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

// advapi32 backs the one Win32 call this package needs that
// github.com/hectane/go-acl's api package doesn't already wrap:
// GetExplicitEntriesFromAclW. It's loaded the same way (MustLoadDLL +
// MustFindProc) that package's own api.go loads advapi32.dll, so this
// is an extension of that library's approach rather than a new
// dependency or a different interop style.
var (
	advapi32                       = windows.MustLoadDLL("advapi32.dll")
	procGetExplicitEntriesFromAclW = advapi32.MustFindProc("GetExplicitEntriesFromAclW")
	procInitializeAcl              = advapi32.MustFindProc("InitializeAcl")
)

// emptyACL returns a valid ACL with no ACE (ACL_REVISION, 8 bytes, DWORD
// aligned), built with InitializeAcl in Go memory. The caller keeps buf
// reachable (runtime.KeepAlive) until the call that reads the ACL returns.
func emptyACL() (buf *[2]uint64, acl windows.Handle, err error) {
	const aclRevision = 2
	buf = new([2]uint64)
	ret, _, callErr := procInitializeAcl.Call(uintptr(unsafe.Pointer(buf)), unsafe.Sizeof(*buf), aclRevision)
	if ret == 0 {
		return nil, 0, fmt.Errorf("InitializeAcl: %w", callErr)
	}
	return buf, windows.Handle(unsafe.Pointer(buf)), nil
}

// resolvePrincipal accepts either a SID string (e.g. "S-1-5-32-544") or
// an account name ("DOMAIN\User", "BUILTIN\Administrators", ...) and
// returns the resolved SID.
func resolvePrincipal(principal string) (*windows.SID, error) {
	if sid, err := windows.StringToSid(principal); err == nil {
		return sid, nil
	}
	sid, _, _, err := windows.LookupSID("", principal)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrUnknownPrincipal, principal, err)
	}
	return sid, nil
}

// getDACL fetches name's current DACL and the security descriptor it
// lives in. Only secDesc must be freed (via freeHandle); dacl points
// into the same allocation and must not be freed separately -- the
// same contract github.com/hectane/go-acl's own Apply() relies on.
func getDACL(seObjType int32, name string) (dacl, secDesc windows.Handle, err error) {
	err = api.GetNamedSecurityInfo(name, seObjType, api.DACL_SECURITY_INFORMATION, nil, nil, &dacl, nil, &secDesc)
	return
}

// setDACL writes dacl as name's DACL, setting or clearing DACL
// protection (SE_DACL_PROTECTED) as requested. dacl must be a valid
// ACL handle -- passing 0 here would set a NULL DACL, which grants
// Everyone full control, not "leave the DACL unchanged", so every
// caller in this package always passes either the freshly-built ACL it
// wants applied or the object's current DACL handle (from getDACL),
// never 0.
func setDACL(seObjType int32, name string, dacl windows.Handle, protected bool) error {
	secInfo := uint32(api.DACL_SECURITY_INFORMATION)
	if protected {
		secInfo |= uint32(api.PROTECTED_DACL_SECURITY_INFORMATION)
	} else {
		secInfo |= uint32(api.UNPROTECTED_DACL_SECURITY_INFORMATION)
	}
	return api.SetNamedSecurityInfo(name, seObjType, secInfo, nil, nil, dacl, 0)
}

// isProtected reports whether secDesc's DACL is currently protected
// (SE_DACL_PROTECTED), i.e. not inheriting ACEs from its parent.
func isProtected(secDesc windows.Handle) (bool, error) {
	if secDesc == 0 {
		return false, nil
	}
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(secDesc))
	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	return control&windows.SE_DACL_PROTECTED != 0, nil
}

// freeHandle releases memory GetNamedSecurityInfo or SetEntriesInAcl
// allocated (via LocalAlloc) and handed back to the caller.
func freeHandle(h windows.Handle) {
	if h != 0 {
		windows.LocalFree(h)
	}
}

// getExplicitEntriesFromACL returns acl's explicit (non-inherited)
// entries via GetExplicitEntriesFromAclW. Entries inherited from a
// parent are deliberately excluded by this Win32 call -- that's exactly
// the set ace_present/ace_absent are meant to manage; an object's
// inherited ACEs are its parent's business, changed via
// inheritance_enabled/inheritance_disabled instead.
func getExplicitEntriesFromACL(acl windows.Handle) ([]api.ExplicitAccess, error) {
	if acl == 0 {
		return nil, nil
	}
	var (
		count uint32
		list  uintptr
	)
	ret, _, _ := procGetExplicitEntriesFromAclW.Call(
		uintptr(acl),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&list)),
	)
	if ret != 0 {
		return nil, windows.Errno(ret)
	}
	if list == 0 || count == 0 {
		return nil, nil
	}
	defer windows.LocalFree(windows.Handle(list))
	src := unsafe.Slice((*api.ExplicitAccess)(unsafe.Pointer(list)), int(count))
	out := make([]api.ExplicitAccess, count)
	copy(out, src)
	return out, nil
}

// inheritedExplicitAccess returns EXPLICIT_ACCESS-shaped copies of
// every ACE in dacl that carries the INHERITED_ACE flag, i.e. a
// snapshot of what this object currently receives purely from its
// parent. It's used to preserve effective permissions when inheritance
// is about to be blocked (inheritance_disabled with copy_inherited,
// matching `icacls /inheritance:d`).
//
// This walks the raw ACL (windows.GetAce) rather than using
// GetExplicitEntriesFromAclW, which by design excludes inherited
// entries -- the two helpers are complementary, not interchangeable.
// Only ALLOW and DENY ACEs are copied; audit (SACL-style) ACE types
// don't apply here and are skipped.
func inheritedExplicitAccess(dacl windows.Handle) ([]api.ExplicitAccess, error) {
	if dacl == 0 {
		return nil, nil
	}
	acl := (*windows.ACL)(unsafe.Pointer(dacl))
	var out []api.ExplicitAccess
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return nil, err
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			continue
		}
		var mode int32
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			mode = api.GRANT_ACCESS
		case windows.ACCESS_DENIED_ACE_TYPE:
			mode = api.DENY_ACCESS
		default:
			continue
		}
		// The SID immediately follows the fixed Header+Mask portion of
		// the ACE; SidStart marks that offset. EXPLICIT_ACCESS.Inheritance
		// doesn't accept INHERITED_ACE (that bit is only meaningful in an
		// ACE header), so it's masked out here -- the copy becomes a
		// normal, non-inherited explicit entry.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		inheritance := uint32(ace.Header.AceFlags) & (uint32(api.OBJECT_INHERIT_ACE) | uint32(api.CONTAINER_INHERIT_ACE) | uint32(api.NO_PROPAGATE_INHERIT_ACE) | uint32(api.INHERIT_ONLY_ACE))
		out = append(out, api.ExplicitAccess{
			AccessPermissions: uint32(ace.Mask),
			AccessMode:        mode,
			Inheritance:       inheritance,
			Trustee: api.Trustee{
				TrusteeForm: api.TRUSTEE_IS_SID,
				Name:        (*uint16)(unsafe.Pointer(sid)),
			},
		})
	}
	return out, nil
}

// setEntriesInACLRaw builds a brand-new ACL containing exactly entries
// (canonically ordered -- deny before allow -- by SetEntriesInAclW
// itself), with no merge against any prior ACL. Every caller in this
// package first reads and merges the existing explicit ACEs itself (see
// merge.go), so passing oldAcl=0 here is intentional: it avoids relying
// on SetEntriesInAclW's own trustee-merge heuristics, which are
// documented but easy to get subtly wrong when a trustee already has
// entries with different access modes.
func setEntriesInACLRaw(entries []api.ExplicitAccess) (windows.Handle, error) {
	var acl windows.Handle
	if err := api.SetEntriesInAcl(entries, 0, &acl); err != nil {
		return 0, err
	}
	return acl, nil
}
