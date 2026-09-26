//go:build windows

package windacl

import (
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

// aceAbsent implements the ace_absent method: name has no explicit ACE
// for req.principal at req.accessMode, regardless of what rights or
// propagation that ACE had. Only explicit ACEs are touched -- an
// inherited grant/deny for the same principal is left alone, since it
// belongs to the parent object, not this one.
func aceAbsent(req aclRequest, test bool) (cook.Result, error) {
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

	remaining, changed := removeACE(existing, sid.String(), req.accessMode)
	verb := accessModeVerb(req.accessMode)

	if !changed {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s already has no %s ACE for %s", req.displayName, verb, req.principal),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s's %s ACE for %s would be removed", req.displayName, verb, req.principal),
		}}, nil
	}
	if err := commitACL(req.seObjType, req.name, remaining, protected); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s's %s ACE for %s has been removed", req.displayName, verb, req.principal),
	}}, nil
}
