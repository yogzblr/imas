//go:build windows

package windacl

import (
	"fmt"
	"runtime"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

// commitACL writes entries as name's explicit DACL, preserving the
// object's current inheritance-protection state (protected). With no
// entries it writes an empty explicit list, which an unprotected object
// fills with what it inherits; checkEmptyExplicit (decide.go) refuses it
// for a protected DACL, which would deny everyone. The empty list is built
// with InitializeAcl, not SetEntriesInAcl (go-acl's wrapper indexes
// entries[0]), and is never a NULL DACL, which would grant everyone full
// control.
func commitACL(seObjType int32, name string, entries []aceEntry, protected bool) error {
	if err := checkEmptyExplicit(entries, protected); err != nil {
		return fmt.Errorf("%w: %s", err, name)
	}
	if len(entries) == 0 {
		buf, empty, err := emptyACL()
		if err != nil {
			return err
		}
		err = setDACL(seObjType, name, empty, protected)
		runtime.KeepAlive(buf)
		return err
	}
	explicit := make([]api.ExplicitAccess, len(entries))
	for i, e := range entries {
		ea, err := e.toExplicitAccess()
		if err != nil {
			return err
		}
		explicit[i] = ea
	}
	newACL, err := setEntriesInACLRaw(explicit)
	if err != nil {
		return err
	}
	defer windows.LocalFree(newACL)
	return setDACL(seObjType, name, newACL, protected)
}
