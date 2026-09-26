// Package lgpo implements a imas ingredient for managing Windows Local
// Group Policy (LGPO): parsing/writing the binary registry.pol format that
// backs Administrative Template policies, and resolving policies defined by
// ADMX/ADML template files into the registry.pol entries that express them.
//
// This is a v1 subset, not a full win_lgpo port — see the package-level
// doc comment on Policy in admx.go for exactly what's in and out of scope.
package lgpo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// RegType mirrors the Win32 registry value type constants used inside a
// registry.pol entry's type field.
type RegType uint32

const (
	RegNone     RegType = 0
	RegSZ       RegType = 1
	RegExpandSZ RegType = 2
	RegBinary   RegType = 3
	RegDWORD    RegType = 4
	RegDWORDBE  RegType = 5
	RegMultiSZ  RegType = 7
	RegQWORD    RegType = 11
)

var (
	ErrBadSignature = errors.New("registry.pol: bad file signature")
	ErrBadVersion   = errors.New("registry.pol: unsupported file version")
	ErrTruncated    = errors.New("registry.pol: truncated or malformed entry")
)

// polSignature is the 4-byte magic "PReg" and polVersion the only version
// this format has ever shipped, both stored little-endian per the
// documented registry.pol header.
const (
	polSignature uint32 = 0x67655250
	polVersion   uint32 = 1
)

var (
	marker    = [2]byte{'[', 0}
	semicolon = [2]byte{';', 0}
	closeMark = [2]byte{']', 0}
)

// Entry is one key/value record in a registry.pol file. Value and Type are
// meaningless when Delete is true — the entry is instead a "**del."/
// "**delvals." marker instructing the Group Policy client to remove a
// value (or every value) that a prior application of this .pol file, or
// another policy layer, may have set.
type Entry struct {
	Key       string
	ValueName string
	Type      RegType
	Data      []byte
}

const (
	deleteValuePrefix = "**del."
	deleteAllValues   = "**delvals."
)

// IsDeleteAllMarker reports whether e instructs the GP client to delete
// every value under e.Key.
func (e Entry) IsDeleteAllMarker() bool {
	return e.ValueName == deleteAllValues
}

// IsDeleteMarker reports whether e instructs the GP client to delete a
// single named value, returning that value's real name.
func (e Entry) IsDeleteMarker() (string, bool) {
	if strings.HasPrefix(e.ValueName, deleteValuePrefix) {
		return e.ValueName[len(deleteValuePrefix):], true
	}
	return "", false
}

// deleteValueEntry builds the marker Entry that asks the GP client to
// remove valueName under key.
func deleteValueEntry(key, valueName string) Entry {
	return Entry{
		Key:       key,
		ValueName: deleteValuePrefix + valueName,
		Type:      RegSZ,
		Data:      utf16leString(" "),
	}
}

// deleteAllValuesEntry builds the marker Entry that asks the GP client to
// remove every value under key.
func deleteAllValuesEntry(key string) Entry {
	return Entry{
		Key:       key,
		ValueName: deleteAllValues,
		Type:      RegSZ,
		Data:      utf16leString(" "),
	}
}

// File is a parsed registry.pol document: an ordered list of entries.
// Order is preserved across Upsert/Delete so re-serializing an unchanged
// File round-trips byte-for-byte.
type File struct {
	Entries []Entry
}

// NewFile returns an empty registry.pol document.
func NewFile() *File {
	return &File{}
}

// Parse decodes a registry.pol document from raw file bytes.
func Parse(data []byte) (*File, error) {
	if len(data) < 8 {
		return nil, ErrBadSignature
	}
	if binary.LittleEndian.Uint32(data[0:4]) != polSignature {
		return nil, ErrBadSignature
	}
	if binary.LittleEndian.Uint32(data[4:8]) != polVersion {
		return nil, ErrBadVersion
	}
	f := &File{}
	rest := data[8:]
	for len(rest) > 0 {
		e, n, err := parseEntry(rest)
		if err != nil {
			return nil, err
		}
		f.Entries = append(f.Entries, e)
		rest = rest[n:]
	}
	return f, nil
}

// parseEntry decodes one "[key;value;type;size;data]" record from the
// front of b and returns how many bytes it consumed.
func parseEntry(b []byte) (Entry, int, error) {
	pos := 0
	consume := func(want [2]byte) error {
		if pos+2 > len(b) || b[pos] != want[0] || b[pos+1] != want[1] {
			return ErrTruncated
		}
		pos += 2
		return nil
	}
	readUTF16String := func() (string, error) {
		var units []uint16
		for {
			if pos+2 > len(b) {
				return "", ErrTruncated
			}
			u := binary.LittleEndian.Uint16(b[pos : pos+2])
			pos += 2
			if u == 0 {
				break
			}
			units = append(units, u)
		}
		return string(utf16.Decode(units)), nil
	}
	readDWORD := func() (uint32, error) {
		if pos+4 > len(b) {
			return 0, ErrTruncated
		}
		v := binary.LittleEndian.Uint32(b[pos : pos+4])
		pos += 4
		return v, nil
	}

	if err := consume(marker); err != nil {
		return Entry{}, 0, err
	}
	key, err := readUTF16String()
	if err != nil {
		return Entry{}, 0, err
	}
	if err := consume(semicolon); err != nil {
		return Entry{}, 0, err
	}
	valueName, err := readUTF16String()
	if err != nil {
		return Entry{}, 0, err
	}
	if err := consume(semicolon); err != nil {
		return Entry{}, 0, err
	}
	typ, err := readDWORD()
	if err != nil {
		return Entry{}, 0, err
	}
	if err := consume(semicolon); err != nil {
		return Entry{}, 0, err
	}
	size, err := readDWORD()
	if err != nil {
		return Entry{}, 0, err
	}
	if err := consume(semicolon); err != nil {
		return Entry{}, 0, err
	}
	if pos+int(size) > len(b) {
		return Entry{}, 0, ErrTruncated
	}
	data := make([]byte, size)
	copy(data, b[pos:pos+int(size)])
	pos += int(size)
	if err := consume(closeMark); err != nil {
		return Entry{}, 0, err
	}
	return Entry{Key: key, ValueName: valueName, Type: RegType(typ), Data: data}, pos, nil
}

// Bytes serializes f back into registry.pol's on-disk binary form.
func (f *File) Bytes() []byte {
	var buf bytes.Buffer
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], polSignature)
	binary.LittleEndian.PutUint32(hdr[4:8], polVersion)
	buf.Write(hdr[:])
	for _, e := range f.Entries {
		var typSize [8]byte
		binary.LittleEndian.PutUint32(typSize[0:4], uint32(e.Type))
		binary.LittleEndian.PutUint32(typSize[4:8], uint32(len(e.Data)))

		buf.Write(marker[:])
		buf.Write(utf16leString(e.Key))
		buf.Write(semicolon[:])
		buf.Write(utf16leString(e.ValueName))
		buf.Write(semicolon[:])
		buf.Write(typSize[0:4])
		buf.Write(semicolon[:])
		buf.Write(typSize[4:8])
		buf.Write(semicolon[:])
		buf.Write(e.Data)
		buf.Write(closeMark[:])
	}
	return buf.Bytes()
}

// utf16leString encodes s as null-terminated UTF-16LE, the encoding used
// for every text field (key, value name, and REG_SZ/REG_EXPAND_SZ data) in
// a registry.pol file.
func utf16leString(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, len(units)*2+2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return buf
}

// Find returns the entry for key/valueName (case-insensitive on both, as
// the registry itself is) and whether it was found.
func (f *File) Find(key, valueName string) (Entry, bool) {
	for _, e := range f.Entries {
		if strings.EqualFold(e.Key, key) && strings.EqualFold(e.ValueName, valueName) {
			return e, true
		}
	}
	return Entry{}, false
}

// Upsert replaces the entry matching e's key/valueName in place, or
// appends e if no such entry exists yet.
func (f *File) Upsert(e Entry) {
	for i, existing := range f.Entries {
		if strings.EqualFold(existing.Key, e.Key) && strings.EqualFold(existing.ValueName, e.ValueName) {
			f.Entries[i] = e
			return
		}
	}
	f.Entries = append(f.Entries, e)
}

// MarkDeleted replaces (or appends) the entry for key/valueName with a
// "**del." marker, so a subsequent gpupdate removes the live registry
// value rather than merely leaving our own prior entry out of the file.
// It matches an existing entry by its logical value name, whether that
// entry is currently a live value or an earlier "**del." marker for the
// same name — Upsert alone can't do this match, since the marker's own
// ValueName ("**del.<name>") differs from the plain name it targets.
func (f *File) MarkDeleted(key, valueName string) {
	marker := deleteValueEntry(key, valueName)
	for i, existing := range f.Entries {
		if !strings.EqualFold(existing.Key, key) {
			continue
		}
		if strings.EqualFold(existing.ValueName, valueName) {
			f.Entries[i] = marker
			return
		}
		if name, ok := existing.IsDeleteMarker(); ok && strings.EqualFold(name, valueName) {
			f.Entries[i] = marker
			return
		}
	}
	f.Entries = append(f.Entries, marker)
}

// MarkAllDeleted replaces (or appends) the entry for key/"**delvals."
// with a marker that removes every value under key.
func (f *File) MarkAllDeleted(key string) {
	for i, existing := range f.Entries {
		if strings.EqualFold(existing.Key, key) && existing.IsDeleteAllMarker() {
			f.Entries[i] = deleteAllValuesEntry(key)
			return
		}
	}
	f.Entries = append(f.Entries, deleteAllValuesEntry(key))
}

// String implements fmt.Stringer for debugging/logging.
func (e Entry) String() string {
	return fmt.Sprintf("%s\\%s (type=%d, %d bytes)", e.Key, e.ValueName, e.Type, len(e.Data))
}
