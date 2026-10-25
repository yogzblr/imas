package windacl

import (
	"errors"
	"testing"
)

const (
	sidUsers  = "S-1-5-32-545" // BUILTIN\Users, as the UAT cases use
	sidAdmins = "S-1-5-32-544"
	sidWorld  = "S-1-1-0"
)

// UAT I.win_dacl.ace_present, Run 2 on rc.21: rights 0x120089 on a file,
// default propagation (key_and_subkeys: OBJECT_INHERIT|CONTAINER_INHERIT),
// and the second real cook reported "now has a allow ACE for
// S-1-5-32-545" again. On a file the inheritance flags mean nothing and
// are compared as none, whichever way Windows stores them.
func TestAcePresentFileIsIdempotentAsReadBack(t *testing.T) {
	desired := aceEntry{sidString: sidUsers, mode: modeGrant, rights: 0x120089, inherit: flagObjectInherit | flagContainerInherit}
	for _, readBack := range []aceEntry{
		{sidString: sidUsers, mode: modeGrant, rights: 0x120089, inherit: 0},
		{sidString: sidUsers, mode: modeGrant, rights: 0x120089, inherit: flagObjectInherit | flagContainerInherit},
		{sidString: sidUsers, mode: modeSet, rights: 0x120089, inherit: 0},
	} {
		merged, changed := upsertACE([]aceEntry{readBack}, desired, kindFile)
		if changed || len(merged) != 1 {
			t.Errorf("read back %+v: changed=%v merged=%+v, want no change", readBack, changed, merged)
		}
	}
}

// A named right is a generic one; Windows stores the specific rights it
// maps to on an ACE that applies to the object itself.
func TestGenericRightsCompareAsMapped(t *testing.T) {
	tests := []struct {
		kind    objectKind
		generic uint32
		stored  uint32
		inherit uint32
	}{
		{kindFile, genericRead, 0x120089, 0},
		{kindFile, genericAll, 0x1F01FF, 0},
		{kindDirectory, genericWrite, 0x120116, flagObjectInherit | flagContainerInherit},
		{kindDirectory, genericExecute, 0x1200A0, 0},
		{kindRegistry, genericRead, 0x20019, flagContainerInherit},
		{kindRegistry, genericAll, 0xF003F, flagContainerInherit},
	}
	for _, tt := range tests {
		a := aceEntry{sidString: sidUsers, mode: modeGrant, rights: tt.generic, inherit: tt.inherit}
		b := aceEntry{sidString: sidUsers, mode: modeGrant, rights: tt.stored, inherit: tt.inherit}
		if !aceEqual(a, b, tt.kind) {
			t.Errorf("kind %d: %#x and %#x should compare equal", tt.kind, tt.generic, tt.stored)
		}
	}
	// An inherit-only ACE applies to children only; Windows keeps its
	// generic rights, and so does the comparison.
	io := aceEntry{sidString: sidUsers, mode: modeGrant, rights: genericRead, inherit: flagContainerInherit | flagObjectInherit | flagInheritOnly}
	if got := io.normalize(kindDirectory); got.rights != genericRead {
		t.Errorf("inherit-only rights = %#x, want GENERIC_READ kept", got.rights)
	}
}

func TestAceEqualStillSeesRealDifferences(t *testing.T) {
	base := aceEntry{sidString: sidUsers, mode: modeGrant, rights: 0x120089, inherit: flagObjectInherit | flagContainerInherit}
	for name, other := range map[string]aceEntry{
		"sid":         {sidString: sidAdmins, mode: modeGrant, rights: 0x120089, inherit: base.inherit},
		"type":        {sidString: sidUsers, mode: modeDeny, rights: 0x120089, inherit: base.inherit},
		"mask":        {sidString: sidUsers, mode: modeGrant, rights: 0x1F01FF, inherit: base.inherit},
		"propagation": {sidString: sidUsers, mode: modeGrant, rights: 0x120089, inherit: flagContainerInherit},
	} {
		if aceEqual(base, other, kindDirectory) {
			t.Errorf("%s: %+v and %+v must differ on a directory", name, base, other)
		}
	}
	// INHERITED_ACE is not part of an explicit ACE's identity.
	if !aceEqual(base, aceEntry{sidString: sidUsers, mode: modeGrant, rights: 0x120089, inherit: base.inherit | flagInherited}, kindDirectory) {
		t.Error("INHERITED_ACE must be ignored")
	}
}

func TestUpsertACE(t *testing.T) {
	read := aceEntry{sidString: sidWorld, mode: modeGrant, rights: genericRead}
	other := aceEntry{sidString: sidAdmins, mode: modeGrant, rights: genericAll}

	merged, changed := upsertACE(nil, read, kindRegistry)
	if !changed || len(merged) != 1 || !aceEqual(merged[0], read, kindRegistry) {
		t.Errorf("add: merged=%+v changed=%v", merged, changed)
	}

	full := aceEntry{sidString: sidWorld, mode: modeGrant, rights: genericAll, inherit: flagContainerInherit}
	merged, changed = upsertACE([]aceEntry{read, other}, full, kindRegistry)
	if !changed || len(merged) != 2 {
		t.Fatalf("replace: merged=%+v changed=%v", merged, changed)
	}
	if !aceEqual(merged[0], full, kindRegistry) || merged[1] != other {
		t.Errorf("replace: merged=%+v", merged)
	}

	deny := aceEntry{sidString: sidWorld, mode: modeDeny, rights: genericWrite}
	if merged, changed := upsertACE([]aceEntry{read}, deny, kindRegistry); !changed || len(merged) != 2 {
		t.Errorf("allow and deny coexist: merged=%+v changed=%v", merged, changed)
	}

	// Two explicit allow ACEs for one trustee (another tool made them)
	// fold into the one asked for.
	dup := []aceEntry{{sidString: sidUsers, mode: modeGrant, rights: 0x120089}, {sidString: sidUsers, mode: modeGrant, rights: 0x1200A0}}
	merged, changed = upsertACE(dup, aceEntry{sidString: sidUsers, mode: modeGrant, rights: 0x120089}, kindFile)
	if !changed || len(merged) != 1 {
		t.Errorf("fold duplicates: merged=%+v changed=%v", merged, changed)
	}
}

func TestRemoveACE(t *testing.T) {
	entries := []aceEntry{
		{sidString: sidWorld, mode: modeGrant, rights: genericRead},
		{sidString: sidAdmins, mode: modeGrant, rights: genericAll},
	}
	remaining, changed := removeACE(entries, sidWorld, modeGrant)
	if !changed || len(remaining) != 1 || remaining[0].sidString != sidAdmins {
		t.Errorf("remaining=%+v changed=%v", remaining, changed)
	}
	if _, changed := removeACE(remaining, sidWorld, modeGrant); changed {
		t.Error("no-op expected")
	}
	// An allow ACE read back as SET_ACCESS is still the allow ACE.
	if _, changed := removeACE([]aceEntry{{sidString: sidUsers, mode: modeSet}}, sidUsers, modeGrant); !changed {
		t.Error("SET_ACCESS must match allow")
	}
}

// UAT I.win_dacl.ace_absent, Run 2 on rc.21: the setup's file has one
// explicit ACE (Users, read) and inherits the rest from C:\Windows\Temp;
// removing it failed with "operation would leave the object with no
// explicit ACEs". On an inheriting DACL that is legal; on a protected one
// it would deny everyone, and stays refused.
func TestAceAbsentLastExplicitACE(t *testing.T) {
	existing := []aceEntry{{sidString: sidUsers, mode: modeGrant, rights: 0x120089}}
	remaining, changed := removeACE(existing, sidUsers, modeGrant)
	if !changed || len(remaining) != 0 {
		t.Fatalf("remaining=%+v changed=%v", remaining, changed)
	}
	if err := checkEmptyExplicit(remaining, false); err != nil {
		t.Errorf("inheriting DACL: %v, want nil", err)
	}
	if err := checkEmptyExplicit(remaining, true); !errors.Is(err, ErrWouldClearDACL) {
		t.Errorf("protected DACL: %v, want ErrWouldClearDACL", err)
	}
	if err := checkEmptyExplicit(existing, true); err != nil {
		t.Errorf("a non-empty list is always fine: %v", err)
	}
}
