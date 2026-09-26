//go:build windows

package windacl

import (
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

// acePresent implements the ace_present method: name has an explicit
// ACE for req.principal with req.accessMode/req.rights/req.inheritance.
// A principal's existing explicit ACE for the same access mode is
// replaced (see upsertACE) rather than left alongside a new one, so
// re-applying ace_present with different rights or propagation actually
// changes what's granted instead of layering an extra ACE on top.
//
// The object's DACL protection (inherited vs. not) is read and written
// back unchanged: ace_present/ace_absent only ever touch the explicit
// ACE list, never the inheritance flag itself -- that's
// inheritance_enabled/inheritance_disabled's job.
func acePresent(req aclRequest, test bool) (cook.Result, error) {
	sid, err := resolvePrincipal(req.principal)
	if err != nil {
		return cook.Result{Failed: true}, err
	}

	dacl, secDesc, err := getDACL(req.seObjType, req.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	defer freeHandle(secDesc)

	protected, err := isProtected(secDesc)
	if err != nil {
		return cook.Result{Failed: true}, err
	}

	rawExisting, err := getExplicitEntriesFromACL(dacl)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	existing := make([]aceEntry, len(rawExisting))
	for i, e := range rawExisting {
		existing[i] = fromExplicitAccess(e)
	}

	desired := aceEntry{
		sidString: sid.String(),
		sid:       sid,
		mode:      req.accessMode,
		rights:    req.rights,
		inherit:   req.inheritance,
	}
	merged, changed := upsertACE(existing, desired)
	verb := accessModeVerb(req.accessMode)

	if !changed {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s already has a %s ACE for %s", req.displayName, verb, req.principal),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would get a %s ACE for %s", req.displayName, verb, req.principal),
		}}, nil
	}
	if err := commitACL(req.seObjType, req.name, merged, protected); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s now has a %s ACE for %s", req.displayName, verb, req.principal),
	}}, nil
}
