//go:build windows

package windacl

import (
	"fmt"

	"github.com/hectane/go-acl/api"
)

// Propagation controls which of an object's descendants an ACE also
// applies to, matching the addendum's "KEY/KEY&SUBKEYS/SUBKEYS"
// propagation model (see G.4 in
// docs/design/imas-windows-parity-addendum.md, which in turn mirrors
// Salt's win_dacl propagation choices for registry keys). The same
// three values are accepted for files, where they mean "this file or
// folder" / "this folder, its subfolders and the files in them" /
// "subfolders and the files in them, but not this folder itself".
const (
	// propagationKey: the ACE applies to this object only. Encoded as
	// NO_INHERITANCE (0x0): no OBJECT_INHERIT_ACE/CONTAINER_INHERIT_ACE
	// bit, so nothing propagates to children at all.
	propagationKey = "key"
	// propagationKeyAndSubkeys: the ACE applies to this object AND is
	// inherited by its children. This is the default -- the common case
	// for "grant this principal access here" is that access should also
	// cover what's underneath.
	propagationKeyAndSubkeys = "key_and_subkeys"
	// propagationSubkeys: the ACE is inherited by children but does NOT
	// apply to this object itself. Encoded with INHERIT_ONLY_ACE (0x8)
	// added on top of the container/object-inherit bits: without that
	// bit, an ACE marked "inheritable" still also applies to the object
	// it's set on, which is exactly the KEY_AND_SUBKEYS behavior, not
	// SUBKEYS. Dropping INHERIT_ONLY_ACE here is the single easiest way
	// to accidentally turn a "children only" grant into a "this object
	// too" grant.
	propagationSubkeys = "subkeys"
)

// parsePropagation resolves a propagation value to the Inheritance mask
// an api.ExplicitAccess entry needs, for the given object type.
//
// Files use OBJECT_INHERIT_ACE (propagate to files created under this
// folder) together with CONTAINER_INHERIT_ACE (propagate to
// subfolders); SUB_CONTAINERS_AND_OBJECTS_INHERIT is exactly that pair.
// Registry keys have no separate "leaf object" inheritance concept --
// only subkeys (containers) exist under a key -- so only
// CONTAINER_INHERIT_ACE applies; adding OBJECT_INHERIT_ACE there would
// be a meaningless flag rather than a functional no-op, so it's left
// out rather than included "just in case".
func parsePropagation(objType, propagation string) (uint32, error) {
	if propagation == "" {
		propagation = propagationKeyAndSubkeys
	}

	var toChildren uint32
	switch objType {
	case objectTypeFile:
		toChildren = uint32(api.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	case objectTypeRegistry:
		toChildren = uint32(api.CONTAINER_INHERIT_ACE)
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidObjectType, objType)
	}

	switch propagation {
	case propagationKey:
		return uint32(api.NO_INHERITANCE), nil
	case propagationKeyAndSubkeys:
		return toChildren, nil
	case propagationSubkeys:
		return toChildren | uint32(api.INHERIT_ONLY_ACE), nil
	default:
		return 0, fmt.Errorf("%w: %q (must be %q, %q, or %q)",
			ErrInvalidPropagation, propagation, propagationKey, propagationKeyAndSubkeys, propagationSubkeys)
	}
}
