//go:build windows

package windacl

import (
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"golang.org/x/sys/windows"
)

// inheritanceEnabled implements the inheritance_enabled method: name's
// DACL is unprotected, so it inherits ACEs from its parent.
//
// The object's current DACL handle (from getDACL) is written straight
// back with only the protection bit cleared -- never a zero/nil DACL.
// SetNamedSecurityInfo treats a NULL dacl argument as "apply a NULL
// DACL" (Everyone: full control), not "leave the DACL alone", so
// reusing the handle just read is what makes this "only touch
// inheritance" instead of accidentally opening the object up.
func inheritanceEnabled(req aclRequest, test bool) (cook.Result, error) {
	dacl, secDesc, err := getDACL(req.seObjType, req.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	defer freeHandle(secDesc)

	protected, err := isProtected(secDesc)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if !protected {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s already inherits permissions from its parent", req.displayName),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would be changed to inherit permissions from its parent", req.displayName),
		}}, nil
	}
	if err := setDACL(req.seObjType, req.name, dacl, false); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s now inherits permissions from its parent", req.displayName),
	}}, nil
}

// inheritanceDisabled implements the inheritance_disabled method:
// name's DACL is protected, so it stops inheriting ACEs from its
// parent.
//
// With copy_inherited (the default), currently-inherited ACEs are
// snapshotted as explicit ones first, so effective permissions don't
// change at the moment inheritance is blocked -- the same behavior as
// `icacls <path> /inheritance:d`. With copy_inherited=false, they're
// dropped instead (`icacls <path> /inheritance:r`): a real permissions
// change, which is why it isn't the default.
func inheritanceDisabled(req aclRequest, test bool) (cook.Result, error) {
	dacl, secDesc, err := getDACL(req.seObjType, req.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	defer freeHandle(secDesc)

	protected, err := isProtected(secDesc)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if protected {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s already does not inherit permissions from its parent", req.displayName),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would be changed to not inherit permissions from its parent", req.displayName),
		}}, nil
	}

	explicit, err := getExplicitEntriesFromACL(dacl)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	final := explicit
	if req.copyInherited {
		inherited, err := inheritedExplicitAccess(dacl)
		if err != nil {
			return cook.Result{Failed: true}, err
		}
		final = append(final, inherited...)
	}
	if len(final) == 0 {
		return cook.Result{Failed: true}, fmt.Errorf("%w: %s", ErrWouldClearDACL, req.displayName)
	}

	newACL, err := setEntriesInACLRaw(final)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	defer windows.LocalFree(newACL)

	if err := setDACL(req.seObjType, req.name, newACL, true); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s no longer inherits permissions from its parent", req.displayName),
	}}, nil
}
