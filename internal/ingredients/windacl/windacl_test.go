//go:build windows

package windacl

import (
	"errors"
	"testing"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"github.com/yogzblr/imas/internal/ingredients"
)

// Well-known SIDs that resolve without touching any live object, used
// throughout as stand-ins for real principals.
const (
	sidEveryone       = "S-1-1-0"      // Everyone
	sidAdministrators = "S-1-5-32-544" // BUILTIN\Administrators
)

func mustSID(t *testing.T, s string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		t.Fatalf("StringToSid(%q): %v", s, err)
	}
	return sid
}

func TestSeObjectType(t *testing.T) {
	if v, err := seObjectType(objectTypeFile); err != nil || v != api.SE_FILE_OBJECT {
		t.Errorf("file: got (%d, %v)", v, err)
	}
	if v, err := seObjectType(objectTypeRegistry); err != nil || v != api.SE_REGISTRY_KEY {
		t.Errorf("registry: got (%d, %v)", v, err)
	}
	if _, err := seObjectType("printer"); !errors.Is(err, ErrInvalidObjectType) {
		t.Errorf("expected ErrInvalidObjectType, got %v", err)
	}
}

func TestResolveObjectNameFile(t *testing.T) {
	name, err := resolveObjectName(objectTypeFile, `C:\Windows\Temp\foo.txt`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != `C:\Windows\Temp\foo.txt` {
		t.Errorf("expected passthrough, got %q", name)
	}
}

func TestResolveObjectNameRegistry(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`HKLM\SOFTWARE\Contoso`, `MACHINE\SOFTWARE\Contoso`},
		{`HKEY_LOCAL_MACHINE\SOFTWARE\Contoso`, `MACHINE\SOFTWARE\Contoso`},
		{`hklm\SOFTWARE\Contoso`, `MACHINE\SOFTWARE\Contoso`},
		{`HKCU\Software\Contoso`, `CURRENT_USER\Software\Contoso`},
		{`HKCR\.txt`, `CLASSES_ROOT\.txt`},
		{`HKU\S-1-5-18`, `USERS\S-1-5-18`},
	}
	for _, c := range cases {
		got, err := resolveObjectName(objectTypeRegistry, c.in)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: expected %q, got %q", c.in, c.want, got)
		}
	}
}

func TestResolveObjectNameRegistryRejectsUnsupportedHive(t *testing.T) {
	// HKEY_CURRENT_CONFIG has no documented security-API predefined
	// name; this must fail rather than guess one.
	if _, err := resolveObjectName(objectTypeRegistry, `HKCC\System`); !errors.Is(err, ErrInvalidRegistryKey) {
		t.Errorf("expected ErrInvalidRegistryKey, got %v", err)
	}
	if _, err := resolveObjectName(objectTypeRegistry, `HKLM`); !errors.Is(err, ErrInvalidRegistryKey) {
		t.Errorf("expected ErrInvalidRegistryKey for missing subkey, got %v", err)
	}
	if _, err := resolveObjectName(objectTypeRegistry, `BOGUS\Foo`); !errors.Is(err, ErrInvalidRegistryKey) {
		t.Errorf("expected ErrInvalidRegistryKey for unknown hive, got %v", err)
	}
}

func TestParseAccessMode(t *testing.T) {
	if v, err := parseAccessMode(accessModeAllow); err != nil || v != api.GRANT_ACCESS {
		t.Errorf("allow: got (%d, %v)", v, err)
	}
	if v, err := parseAccessMode(accessModeDeny); err != nil || v != api.DENY_ACCESS {
		t.Errorf("deny: got (%d, %v)", v, err)
	}
	if _, err := parseAccessMode("maybe"); !errors.Is(err, ErrInvalidAccessMode) {
		t.Errorf("expected ErrInvalidAccessMode, got %v", err)
	}
	if accessModeVerb(api.DENY_ACCESS) != accessModeDeny || accessModeVerb(api.GRANT_ACCESS) != accessModeAllow {
		t.Errorf("accessModeVerb round-trip failed")
	}
}

func TestParseRightsNamed(t *testing.T) {
	cases := map[string]uint32{
		"read":         windows.GENERIC_READ,
		"WRITE":        windows.GENERIC_WRITE,
		"Execute":      windows.GENERIC_EXECUTE,
		"full_control": windows.GENERIC_ALL,
	}
	for in, want := range cases {
		got, err := parseRights(in)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: expected %#x, got %#x", in, want, got)
		}
	}
}

func TestParseRightsNumeric(t *testing.T) {
	got, err := parseRights("0x1F01FF")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0x1F01FF {
		t.Errorf("expected 0x1F01FF, got %#x", got)
	}
}

func TestParseRightsInvalid(t *testing.T) {
	if _, err := parseRights("bogus"); !errors.Is(err, ErrInvalidRights) {
		t.Errorf("expected ErrInvalidRights, got %v", err)
	}
}

func TestParsePropagationDefaultsToKeyAndSubkeys(t *testing.T) {
	withDefault, err := parsePropagation(objectTypeRegistry, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	explicit, err := parsePropagation(objectTypeRegistry, propagationKeyAndSubkeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if withDefault != explicit {
		t.Errorf("default propagation %#x != explicit key_and_subkeys %#x", withDefault, explicit)
	}
}

func TestParsePropagationRegistry(t *testing.T) {
	key, err := parsePropagation(objectTypeRegistry, propagationKey)
	if err != nil || key != uint32(api.NO_INHERITANCE) {
		t.Errorf("key: got (%#x, %v)", key, err)
	}
	keyAndSubkeys, err := parsePropagation(objectTypeRegistry, propagationKeyAndSubkeys)
	if err != nil || keyAndSubkeys != uint32(api.CONTAINER_INHERIT_ACE) {
		t.Errorf("key_and_subkeys: got (%#x, %v)", keyAndSubkeys, err)
	}
	subkeys, err := parsePropagation(objectTypeRegistry, propagationSubkeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subkeys&uint32(api.CONTAINER_INHERIT_ACE) == 0 {
		t.Errorf("subkeys propagation must still carry CONTAINER_INHERIT_ACE, got %#x", subkeys)
	}
	if subkeys&uint32(api.INHERIT_ONLY_ACE) == 0 {
		t.Errorf("subkeys propagation must set INHERIT_ONLY_ACE so the ACE doesn't also apply to the key itself, got %#x", subkeys)
	}
	if subkeys == keyAndSubkeys {
		t.Errorf("subkeys and key_and_subkeys must not encode to the same mask")
	}
}

func TestParsePropagationFile(t *testing.T) {
	keyAndSubkeys, err := parsePropagation(objectTypeFile, propagationKeyAndSubkeys)
	if err != nil || keyAndSubkeys != uint32(api.SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
		t.Errorf("key_and_subkeys: got (%#x, %v)", keyAndSubkeys, err)
	}
	subkeys, err := parsePropagation(objectTypeFile, propagationSubkeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subkeys&uint32(api.INHERIT_ONLY_ACE) == 0 {
		t.Errorf("file subkeys propagation must set INHERIT_ONLY_ACE, got %#x", subkeys)
	}
}

func TestParsePropagationInvalid(t *testing.T) {
	if _, err := parsePropagation(objectTypeFile, "bogus"); !errors.Is(err, ErrInvalidPropagation) {
		t.Errorf("expected ErrInvalidPropagation, got %v", err)
	}
}

func TestExplicitAccessRoundTrip(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	entry := aceEntry{sidString: everyone.String(), mode: api.DENY_ACCESS, rights: windows.GENERIC_WRITE, inherit: uint32(api.CONTAINER_INHERIT_ACE)}
	ea, err := entry.toExplicitAccess()
	if err != nil {
		t.Fatal(err)
	}
	back := fromExplicitAccess(ea)
	if back != entry {
		t.Errorf("round trip mismatch: %+v != %+v", entry, back)
	}
}

func TestParseRequiresName(t *testing.T) {
	if _, err := (Dacl{}).Parse("id1", methodAcePresent, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	if _, err := (Dacl{}).Parse("id1", "bogus", map[string]interface{}{"name": `C:\foo`}); err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseAcePresentOK(t *testing.T) {
	cooker, err := (Dacl{}).Parse("id1", methodAcePresent, map[string]interface{}{
		"name":        `C:\ProgramData\Contoso`,
		"object_type": objectTypeFile,
		"principal":   sidEveryone,
		"access_mode": accessModeAllow,
		"rights":      "read",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d, ok := cooker.(Dacl)
	if !ok {
		t.Fatalf("expected Dacl, got %T", cooker)
	}
	if d.name != `C:\ProgramData\Contoso` {
		t.Errorf("unexpected name %q", d.name)
	}
}

func TestParseAcePresentMissingRights(t *testing.T) {
	_, err := (Dacl{}).Parse("id1", methodAcePresent, map[string]interface{}{
		"name":        `C:\ProgramData\Contoso`,
		"object_type": objectTypeFile,
		"principal":   sidEveryone,
		"access_mode": accessModeAllow,
	})
	if !errors.Is(err, ErrMissingProperty) {
		t.Errorf("expected ErrMissingProperty, got %v", err)
	}
}

func TestParseInheritanceEnabledOK(t *testing.T) {
	_, err := (Dacl{}).Parse("id1", methodInheritanceEnabled, map[string]interface{}{
		"name":        `HKLM\SOFTWARE\Contoso`,
		"object_type": objectTypeRegistry,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Dacl{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 4 {
		t.Errorf("expected 4 methods, got %d", len(methods))
	}
}

func TestPropertiesForMethodUnknown(t *testing.T) {
	if _, err := (Dacl{}).PropertiesForMethod("bogus"); err == nil {
		t.Errorf("expected an error for an undefined method")
	}
}
