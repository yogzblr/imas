//go:build windows

package windacl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

const (
	objectTypeFile     = "file"
	objectTypeRegistry = "registry"
)

// seObjectType maps the ingredient's object_type property to the
// SE_OBJECT_TYPE constant GetNamedSecurityInfo/SetNamedSecurityInfo
// expect.
func seObjectType(objType string) (int32, error) {
	switch objType {
	case objectTypeFile:
		return api.SE_FILE_OBJECT, nil
	case objectTypeRegistry:
		return api.SE_REGISTRY_KEY, nil
	default:
		return 0, fmt.Errorf("%w: %q (must be %q or %q)", ErrInvalidObjectType, objType, objectTypeFile, objectTypeRegistry)
	}
}

// registryHiveSecurityNames maps the same hive aliases the registry
// ingredient accepts to the predefined-key name strings the *security*
// APIs use for SE_REGISTRY_KEY object names. These are deliberately not
// the "HKEY_..." names golang.org/x/sys/windows/registry uses to open a
// key -- GetNamedSecurityInfo/SetNamedSecurityInfo expect the object
// name in the form documented for those APIs (e.g. "MACHINE", not
// "HKEY_LOCAL_MACHINE" or "HKLM"). HKEY_CURRENT_CONFIG has no
// documented security-API name and is intentionally not mapped: a
// silently-wrong hive translation here points the ACL call at the
// wrong key, so an unrecognized or unsupported hive is rejected rather
// than guessed.
var registryHiveSecurityNames = map[string]string{
	"HKEY_CLASSES_ROOT":  "CLASSES_ROOT",
	"HKCR":               "CLASSES_ROOT",
	"HKEY_CURRENT_USER":  "CURRENT_USER",
	"HKCU":               "CURRENT_USER",
	"HKEY_LOCAL_MACHINE": "MACHINE",
	"HKLM":               "MACHINE",
	"HKEY_USERS":         "USERS",
	"HKU":                "USERS",
}

// resolveObjectName translates the ingredient's "name" property into
// the object name string GetNamedSecurityInfo/SetNamedSecurityInfo
// expect for the given object type. File names pass through unchanged;
// registry names are rewritten from their imas hive alias to the
// security APIs' own predefined-key form (see
// registryHiveSecurityNames).
func resolveObjectName(objType, name string) (string, error) {
	if objType != objectTypeRegistry {
		return name, nil
	}
	parts := strings.SplitN(name, `\`, 2)
	secName, ok := registryHiveSecurityNames[strings.ToUpper(parts[0])]
	if !ok {
		return "", fmt.Errorf("%w: unknown or unsupported registry hive %q", ErrInvalidRegistryKey, parts[0])
	}
	if len(parts) < 2 || parts[1] == "" {
		return "", fmt.Errorf("%w: %q is missing a subkey path", ErrInvalidRegistryKey, name)
	}
	return secName + `\` + parts[1], nil
}

const (
	accessModeAllow = "allow"
	accessModeDeny  = "deny"
)

// parseAccessMode maps the ingredient's access_mode property to the
// ACCESS_MODE SetEntriesInAcl expects. GRANT_ACCESS/DENY_ACCESS are
// the only two imas exposes: SET_ACCESS and REVOKE_ACCESS have
// different (and easy to misuse) merge semantics that Salt's own
// ALLOW/DENY model doesn't need.
func parseAccessMode(s string) (int32, error) {
	switch s {
	case accessModeAllow:
		return api.GRANT_ACCESS, nil
	case accessModeDeny:
		return api.DENY_ACCESS, nil
	default:
		return 0, fmt.Errorf("%w: %q (must be %q or %q)", ErrInvalidAccessMode, s, accessModeAllow, accessModeDeny)
	}
}

// accessModeVerb renders an ACCESS_MODE back to the property value that
// produced it, for result messages.
func accessModeVerb(mode int32) string {
	if mode == api.DENY_ACCESS {
		return accessModeDeny
	}
	return accessModeAllow
}

// namedRights maps imas's named rights to the standard Win32 generic
// access rights. Generic rights (rather than object-specific masks
// such as FILE_GENERIC_READ or the registry's KEY_READ) are used
// deliberately: SetNamedSecurityInfo stores them as-is in the ACE, and
// the OS's access-check maps a generic right to the correct
// object-type-specific mask at evaluation time using the object
// manager's own generic mapping -- the same mechanism, and the same
// GENERIC_ALL/GENERIC_READ/GENERIC_WRITE/GENERIC_EXECUTE rights, the
// canonical MSDN SetNamedSecurityInfo/BuildExplicitAccessWithName
// examples use. That avoids imas hand-rolling a specific-rights bitmask
// per object type that can't be verified without a Windows host.
var namedRights = map[string]uint32{
	"read":         windows.GENERIC_READ,
	"write":        windows.GENERIC_WRITE,
	"execute":      windows.GENERIC_EXECUTE,
	"full_control": windows.GENERIC_ALL,
}

// parseRights accepts one of namedRights' keys, or a numeric access
// mask (e.g. "0x1F01FF") for callers who need a specific-rights value
// this ingredient doesn't name.
func parseRights(s string) (uint32, error) {
	if v, ok := namedRights[strings.ToLower(s)]; ok {
		return v, nil
	}
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q (must be read, write, execute, full_control, or a numeric access mask)", ErrInvalidRights, s)
	}
	return uint32(n), nil
}
