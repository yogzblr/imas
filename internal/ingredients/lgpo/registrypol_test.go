package lgpo

import (
	"bytes"
	"testing"
)

func TestParseBytesRoundTrip(t *testing.T) {
	f := NewFile()
	f.Upsert(Entry{Key: `Software\Policies\Imas`, ValueName: "EnableFeature", Type: RegDWORD, Data: dwordBytes(1)})
	f.Upsert(Entry{Key: `Software\Policies\Imas`, ValueName: "Label", Type: RegSZ, Data: utf16leString("hello")})
	f.Upsert(Entry{Key: `Software\Policies\Imas`, ValueName: "", Type: RegSZ, Data: utf16leString("default value")})

	raw := f.Bytes()
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(got.Entries) != len(f.Entries) {
		t.Fatalf("got %d entries, want %d", len(got.Entries), len(f.Entries))
	}
	for i, e := range f.Entries {
		g := got.Entries[i]
		if g.Key != e.Key || g.ValueName != e.ValueName || g.Type != e.Type || !bytes.Equal(g.Data, e.Data) {
			t.Errorf("entry %d = %+v, want %+v", i, g, e)
		}
	}

	// Re-serializing an unmodified parse should round-trip byte-for-byte.
	if !bytes.Equal(got.Bytes(), raw) {
		t.Error("re-serialized bytes do not match original")
	}
}

func TestParseEmptyFile(t *testing.T) {
	f := NewFile()
	got, err := Parse(f.Bytes())
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(got.Entries))
	}
}

func TestParseBadSignature(t *testing.T) {
	if _, err := Parse([]byte("not a pol file")); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
	if _, err := Parse([]byte{1, 2, 3}); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature for short input, got %v", err)
	}
}

func TestParseBadVersion(t *testing.T) {
	f := NewFile()
	raw := f.Bytes()
	raw[4] = 2 // corrupt version field
	if _, err := Parse(raw); err != ErrBadVersion {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestParseTruncated(t *testing.T) {
	f := NewFile()
	f.Upsert(Entry{Key: "K", ValueName: "V", Type: RegDWORD, Data: dwordBytes(1)})
	raw := f.Bytes()
	if _, err := Parse(raw[:len(raw)-4]); err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestFindAndUpsert(t *testing.T) {
	f := NewFile()
	f.Upsert(Entry{Key: `HKLM\Foo`, ValueName: "A", Type: RegDWORD, Data: dwordBytes(1)})
	if _, ok := f.Find(`hklm\foo`, "a"); !ok {
		t.Error("Find should be case-insensitive")
	}
	f.Upsert(Entry{Key: `HKLM\Foo`, ValueName: "A", Type: RegDWORD, Data: dwordBytes(2)})
	if len(f.Entries) != 1 {
		t.Fatalf("expected upsert to replace in place, got %d entries", len(f.Entries))
	}
	got, _ := f.Find(`HKLM\Foo`, "A")
	if got.Data[0] != 2 {
		t.Errorf("expected replaced value, got %v", got.Data)
	}
}

func TestMarkDeletedAndMarkers(t *testing.T) {
	f := NewFile()
	f.Upsert(Entry{Key: `HKLM\Foo`, ValueName: "A", Type: RegDWORD, Data: dwordBytes(1)})
	f.MarkDeleted(`HKLM\Foo`, "A")
	if len(f.Entries) != 1 {
		t.Fatalf("expected marker to replace the entry in place, got %d entries", len(f.Entries))
	}
	e := f.Entries[0]
	name, ok := e.IsDeleteMarker()
	if !ok || name != "A" {
		t.Errorf("IsDeleteMarker() = %q, %v, want \"A\", true", name, ok)
	}

	f.MarkAllDeleted(`HKLM\Foo`)
	if len(f.Entries) != 2 {
		t.Fatalf("expected MarkAllDeleted to append, got %d entries", len(f.Entries))
	}
	if !f.Entries[1].IsDeleteAllMarker() {
		t.Error("expected a **delvals. marker")
	}

	// A second MarkAllDeleted for the same key should replace in place,
	// not append another marker.
	f.MarkAllDeleted(`HKLM\Foo`)
	if len(f.Entries) != 2 {
		t.Errorf("expected MarkAllDeleted to be idempotent, got %d entries", len(f.Entries))
	}
}

func TestUTF16RoundTripNonASCII(t *testing.T) {
	f := NewFile()
	key := "HKLM\\Foö"
	f.Upsert(Entry{Key: key, ValueName: "Namé", Type: RegSZ, Data: utf16leString("café")})
	got, err := Parse(f.Bytes())
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if got.Entries[0].Key != key {
		t.Errorf("Key = %q, want %q", got.Entries[0].Key, key)
	}
}
