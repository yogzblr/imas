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

func TestUpsertACEAddsNewTrustee(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	desired := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.GRANT_ACCESS, rights: windows.GENERIC_READ, inherit: uint32(api.NO_INHERITANCE)}
	merged, changed := upsertACE(nil, desired)
	if !changed || len(merged) != 1 || !aceEqual(merged[0], desired) {
		t.Errorf("expected desired to be added, got merged=%v changed=%v", merged, changed)
	}
}

func TestUpsertACEIsIdempotent(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	entry := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.GRANT_ACCESS, rights: windows.GENERIC_READ, inherit: uint32(api.NO_INHERITANCE)}
	merged, changed := upsertACE([]aceEntry{entry}, entry)
	if changed {
		t.Errorf("expected no change when the identical ACE already exists")
	}
	if len(merged) != 1 {
		t.Errorf("expected exactly one entry, got %d", len(merged))
	}
}

func TestUpsertACEReplacesSameTrusteeAndMode(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	admins := mustSID(t, sidAdministrators)
	old := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.GRANT_ACCESS, rights: windows.GENERIC_READ, inherit: uint32(api.NO_INHERITANCE)}
	other := aceEntry{sidString: admins.String(), sid: admins, mode: api.GRANT_ACCESS, rights: windows.GENERIC_ALL, inherit: uint32(api.NO_INHERITANCE)}
	desired := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.GRANT_ACCESS, rights: windows.GENERIC_ALL, inherit: uint32(api.CONTAINER_INHERIT_ACE)}

	merged, changed := upsertACE([]aceEntry{old, other}, desired)
	if !changed {
		t.Fatalf("expected a change when rights/propagation differ")
	}
	if len(merged) != 2 {
		t.Fatalf("expected the trustee's old entry to be replaced, not added alongside, got %d entries", len(merged))
	}
	var found bool
	for _, e := range merged {
		if e.sidString == everyone.String() {
			found = true
			if !aceEqual(e, desired) {
				t.Errorf("expected replaced entry to match desired, got %+v", e)
			}
		}
	}
	if !found {
		t.Errorf("expected an entry for %s", everyone.String())
	}
}

func TestUpsertACEAllowAndDenyCoexist(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	allow := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.GRANT_ACCESS, rights: windows.GENERIC_READ, inherit: uint32(api.NO_INHERITANCE)}
	deny := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.DENY_ACCESS, rights: windows.GENERIC_WRITE, inherit: uint32(api.NO_INHERITANCE)}

	merged, changed := upsertACE([]aceEntry{allow}, deny)
	if !changed || len(merged) != 2 {
		t.Errorf("expected allow and deny for the same trustee to coexist, got merged=%v changed=%v", merged, changed)
	}
}

func TestRemoveACE(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	admins := mustSID(t, sidAdministrators)
	entries := []aceEntry{
		{sidString: everyone.String(), sid: everyone, mode: api.GRANT_ACCESS, rights: windows.GENERIC_READ},
		{sidString: admins.String(), sid: admins, mode: api.GRANT_ACCESS, rights: windows.GENERIC_ALL},
	}

	remaining, changed := removeACE(entries, everyone.String(), api.GRANT_ACCESS)
	if !changed || len(remaining) != 1 || remaining[0].sidString != admins.String() {
		t.Errorf("expected everyone's entry removed, got remaining=%v changed=%v", remaining, changed)
	}

	remaining2, changed2 := removeACE(remaining, everyone.String(), api.GRANT_ACCESS)
	if changed2 {
		t.Errorf("expected no-op when the trustee has no matching entry")
	}
	if len(remaining2) != 1 {
		t.Errorf("expected unchanged remaining list, got %v", remaining2)
	}
}

func TestExplicitAccessRoundTrip(t *testing.T) {
	everyone := mustSID(t, sidEveryone)
	entry := aceEntry{sidString: everyone.String(), sid: everyone, mode: api.DENY_ACCESS, rights: windows.GENERIC_WRITE, inherit: uint32(api.CONTAINER_INHERIT_ACE)}
	back := fromExplicitAccess(entry.toExplicitAccess())
	if !aceEqual(entry, back) {
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
