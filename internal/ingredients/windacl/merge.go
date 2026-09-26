//go:build windows

package windacl

import (
	"unsafe"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

// aceEntry is imas's own representation of a single explicit ACE,
// factored out of api.ExplicitAccess so the merge/match logic below is
// plain slice manipulation over comparable fields -- no live DACL
// handle, security descriptor, or Win32 call involved -- and can be
// unit tested directly.
type aceEntry struct {
	sidString string
	sid       *windows.SID
	mode      int32
	rights    uint32
	inherit   uint32
}

// toExplicitAccess renders an aceEntry back to the form
// SetEntriesInAcl expects. The Trustee.Name field is reused to hold a
// *SID (rather than a string) when TrusteeForm is TRUSTEE_IS_SID, the
// same convention github.com/hectane/go-acl's own GrantSid/DenySid
// helpers use.
func (a aceEntry) toExplicitAccess() api.ExplicitAccess {
	return api.ExplicitAccess{
		AccessPermissions: a.rights,
		AccessMode:        a.mode,
		Inheritance:       a.inherit,
		Trustee: api.Trustee{
			TrusteeForm: api.TRUSTEE_IS_SID,
			Name:        (*uint16)(unsafe.Pointer(a.sid)),
		},
	}
}

// fromExplicitAccess is the inverse of toExplicitAccess, for entries
// read back from GetExplicitEntriesFromAclW (which always returns
// TRUSTEE_IS_SID entries, since ACEs store SIDs, never names).
func fromExplicitAccess(e api.ExplicitAccess) aceEntry {
	sid := (*windows.SID)(unsafe.Pointer(e.Trustee.Name))
	return aceEntry{
		sidString: sid.String(),
		sid:       sid,
		mode:      e.AccessMode,
		rights:    e.AccessPermissions,
		inherit:   e.Inheritance,
	}
}

// aceEqual reports whether two entries would produce the same ACE.
func aceEqual(a, b aceEntry) bool {
	return a.sidString == b.sidString && a.mode == b.mode && a.rights == b.rights && a.inherit == b.inherit
}

// upsertACE ensures desired is present in existing, matching an
// existing entry by trustee (sidString) and access mode (allow/deny)
// only -- not by rights or propagation. A principal can hold at most
// one explicit allow ACE and one explicit deny ACE this ingredient
// manages; ace_present on an existing entry with different
// rights/propagation replaces it rather than adding a second ACE for
// the same trustee, so re-applying ace_present with new rights doesn't
// leave the old grant in place alongside the new one.
func upsertACE(existing []aceEntry, desired aceEntry) ([]aceEntry, bool) {
	out := make([]aceEntry, 0, len(existing)+1)
	found := false
	changed := false
	for _, e := range existing {
		if e.sidString == desired.sidString && e.mode == desired.mode {
			found = true
			if !aceEqual(e, desired) {
				changed = true
				out = append(out, desired)
			} else {
				out = append(out, e)
			}
			continue
		}
		out = append(out, e)
	}
	if !found {
		out = append(out, desired)
		changed = true
	}
	return out, changed
}

// removeACE ensures no entry in existing matches the given trustee and
// access mode, regardless of its rights or propagation -- ace_absent
// removes "whatever grant/deny this principal has", it doesn't require
// the caller to restate the exact rights being removed.
func removeACE(existing []aceEntry, sidString string, mode int32) ([]aceEntry, bool) {
	out := make([]aceEntry, 0, len(existing))
	changed := false
	for _, e := range existing {
		if e.sidString == sidString && e.mode == mode {
			changed = true
			continue
		}
		out = append(out, e)
	}
	return out, changed
}
