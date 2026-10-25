package windacl

// The decisions of ace_present and ace_absent: which explicit ACE a
// principal has, whether the one asked for is already there as Windows
// reads it back, and whether an explicit list may become empty. They work
// on plain values, with no SID handle or Win32 call, so they have no build
// constraint and are unit-tested on every platform.

import "errors"

var (
	ErrInvalidObjectType  = errors.New("invalid object_type")
	ErrInvalidAccessMode  = errors.New("invalid access_mode")
	ErrInvalidPropagation = errors.New("invalid propagation")
	ErrInvalidRights      = errors.New("invalid rights")
	ErrUnknownPrincipal   = errors.New("unknown principal")
	ErrInvalidRegistryKey = errors.New("invalid registry key name")
	ErrWouldClearDACL     = errors.New("operation would leave a protected DACL with no ACEs (nobody could open the object)")
	ErrMissingProperty    = errors.New("missing required property")
)

// ACCESS_MODE values (accctrl.h), as EXPLICIT_ACCESS carries them.
const (
	modeGrant int32 = 1 // GRANT_ACCESS
	modeSet   int32 = 2 // SET_ACCESS
	modeDeny  int32 = 3 // DENY_ACCESS
)

// ACE flags (winnt.h) that EXPLICIT_ACCESS.Inheritance carries.
const (
	flagObjectInherit    uint32 = 0x1  // OBJECT_INHERIT_ACE
	flagContainerInherit uint32 = 0x2  // CONTAINER_INHERIT_ACE
	flagNoPropagate      uint32 = 0x4  // NO_PROPAGATE_INHERIT_ACE
	flagInheritOnly      uint32 = 0x8  // INHERIT_ONLY_ACE
	flagInherited        uint32 = 0x10 // INHERITED_ACE
)

// Generic access rights (winnt.h).
const (
	genericRead    uint32 = 0x80000000
	genericWrite   uint32 = 0x40000000
	genericExecute uint32 = 0x20000000
	genericAll     uint32 = 0x10000000
	genericMask           = genericRead | genericWrite | genericExecute | genericAll
)

// objectKind is what an ACE sits on; it decides the generic mapping and
// whether inheritance flags mean anything.
type objectKind int

const (
	kindFile      objectKind = iota // a file: a leaf, nothing inherits from it
	kindDirectory                   // a directory: files and subdirectories inherit
	kindRegistry                    // a registry key: subkeys inherit
)

// genericMapping is the object manager's GENERIC_MAPPING for files and
// directories (FILE_GENERIC_READ, FILE_GENERIC_WRITE,
// FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS) and registry keys (KEY_READ,
// KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS).
var genericMapping = map[objectKind][4]uint32{
	kindFile:      {0x120089, 0x120116, 0x1200A0, 0x1F01FF},
	kindDirectory: {0x120089, 0x120116, 0x1200A0, 0x1F01FF},
	kindRegistry:  {0x20019, 0x20006, 0x20019, 0xF003F},
}

// mapGeneric replaces the generic rights in mask with the specific rights
// they stand for on kind. Windows does the same when it stores an ACE that
// applies to the object itself, so an ACE written with GENERIC_READ reads
// back as FILE_GENERIC_READ (0x120089), and comparing the raw masks
// reported a change on every run.
func mapGeneric(mask uint32, kind objectKind) uint32 {
	m, ok := genericMapping[kind]
	if !ok || mask&genericMask == 0 {
		return mask
	}
	out := mask &^ genericMask
	if mask&genericRead != 0 {
		out |= m[0]
	}
	if mask&genericWrite != 0 {
		out |= m[1]
	}
	if mask&genericExecute != 0 {
		out |= m[2]
	}
	if mask&genericAll != 0 {
		out |= m[3]
	}
	return out
}

// normalizeInherit keeps the inheritance flags that mean something on
// kind: none on a file (nothing inherits from a leaf), container and
// propagation flags on a registry key (keys have no leaf objects), all
// four on a directory. INHERITED_ACE and any other bit are dropped:
// ace_present compares explicit ACEs only.
func normalizeInherit(flags uint32, kind objectKind) uint32 {
	switch kind {
	case kindFile:
		return 0
	case kindRegistry:
		return flags & (flagContainerInherit | flagNoPropagate | flagInheritOnly)
	default:
		return flags & (flagObjectInherit | flagContainerInherit | flagNoPropagate | flagInheritOnly)
	}
}

// normalizeMode reads SET_ACCESS, which GetExplicitEntriesFromAcl can
// report for an access-allowed ACE, as GRANT_ACCESS: both are an allow ACE.
func normalizeMode(mode int32) int32 {
	if mode == modeSet {
		return modeGrant
	}
	return mode
}

// aceEntry is imas's own representation of a single explicit ACE: plain
// comparable fields, so the merge/match logic below is slice manipulation
// with no SID handle or Win32 call (backend.go turns it into an
// EXPLICIT_ACCESS).
type aceEntry struct {
	sidString string
	mode      int32
	rights    uint32
	inherit   uint32
}

// normalize is e as Windows stores and reads it back on kind: generic
// rights mapped (unless the ACE is inherit-only, which applies to children
// only and keeps them), inheritance flags kind can carry, allow as
// GRANT_ACCESS.
func (e aceEntry) normalize(kind objectKind) aceEntry {
	inherit := normalizeInherit(e.inherit, kind)
	rights := e.rights
	if inherit&flagInheritOnly == 0 {
		rights = mapGeneric(rights, kind)
	}
	return aceEntry{sidString: e.sidString, mode: normalizeMode(e.mode), rights: rights, inherit: inherit}
}

// aceEqual reports whether two entries are the same ACE on kind, as
// Windows reads them back: SID, type (allow or deny), access mask after
// the generic mapping, and inheritance and propagation flags.
func aceEqual(a, b aceEntry, kind objectKind) bool {
	a, b = a.normalize(kind), b.normalize(kind)
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
func upsertACE(existing []aceEntry, desired aceEntry, kind objectKind) ([]aceEntry, bool) {
	desired = desired.normalize(kind)
	out := make([]aceEntry, 0, len(existing)+1)
	found := false
	changed := false
	for _, e := range existing {
		if e.sidString == desired.sidString && normalizeMode(e.mode) == desired.mode {
			if found {
				// A second explicit ACE of the same type for the trustee
				// (made by another tool): fold it into the one desired.
				changed = true
				continue
			}
			found = true
			if !aceEqual(e, desired, kind) {
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
		if e.sidString == sidString && normalizeMode(e.mode) == normalizeMode(mode) {
			changed = true
			continue
		}
		out = append(out, e)
	}
	return out, changed
}

// checkEmptyExplicit decides whether an object may be left with no
// explicit ACE.
//
// The choice (UAT I.win_dacl.ace_absent, Run 2 on rc.21): an object whose
// DACL is not protected keeps every ACE it inherits from its parent, so
// removing its last explicit ACE is legal and leaves exactly the access
// the parent grants -- what `icacls <file> /remove:g` does. The old guard
// refused every such removal ("operation would leave the object with no
// explicit ACEs"), which made ace_absent unusable on the commonest object
// there is: a file whose only explicit ACE is the one being removed. A
// protected DACL (inheritance disabled) with no explicit ACE is an empty
// DACL, which denies everyone, the owner's implicit rights aside; that
// stays refused.
func checkEmptyExplicit(entries []aceEntry, protected bool) error {
	if len(entries) == 0 && protected {
		return ErrWouldClearDACL
	}
	return nil
}
