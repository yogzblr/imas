//go:build windows

package registry

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/yogzblr/imas/internal/ingredients"
)

// regKey is the subset of registry.Key used by this ingredient, factored
// out so tests can substitute an in-memory fake.
type regKey interface {
	Close() error
	GetStringValue(name string) (val string, valtype uint32, err error)
	GetIntegerValue(name string) (val uint64, valtype uint32, err error)
	GetStringsValue(name string) (val []string, valtype uint32, err error)
	GetBinaryValue(name string) (val []byte, valtype uint32, err error)
	SetStringValue(name, value string) error
	SetExpandStringValue(name, value string) error
	SetDWordValue(name string, value uint32) error
	SetQWordValue(name string, value uint64) error
	SetStringsValue(name string, value []string) error
	SetBinaryValue(name string, value []byte) error
	DeleteValue(name string) error
	ReadSubKeyNames(n int) ([]string, error)
	ReadValueNames(n int) ([]string, error)
}

var _ regKey = registry.Key(0)

// registryBackend is the subset of package-level registry functions used
// by this ingredient, factored out so tests can substitute an in-memory
// fake instead of touching a real Windows registry.
type registryBackend interface {
	OpenKey(hive registry.Key, path string, access uint32) (regKey, error)
	CreateKey(hive registry.Key, path string, access uint32) (regKey, bool, error)
	DeleteKey(hive registry.Key, path string) error
}

type realBackend struct{}

func (realBackend) OpenKey(hive registry.Key, path string, access uint32) (regKey, error) {
	return registry.OpenKey(hive, path, access)
}

func (realBackend) CreateKey(hive registry.Key, path string, access uint32) (regKey, bool, error) {
	return registry.CreateKey(hive, path, access)
}

func (realBackend) DeleteKey(hive registry.Key, path string) error {
	return registry.DeleteKey(hive, path)
}

// backend is replaceable in tests.
var backend registryBackend = realBackend{}

var hiveAliases = map[string]registry.Key{
	"HKEY_CLASSES_ROOT":   registry.CLASSES_ROOT,
	"HKCR":                registry.CLASSES_ROOT,
	"HKEY_CURRENT_USER":   registry.CURRENT_USER,
	"HKCU":                registry.CURRENT_USER,
	"HKEY_LOCAL_MACHINE":  registry.LOCAL_MACHINE,
	"HKLM":                registry.LOCAL_MACHINE,
	"HKEY_USERS":          registry.USERS,
	"HKU":                 registry.USERS,
	"HKEY_CURRENT_CONFIG": registry.CURRENT_CONFIG,
	"HKCC":                registry.CURRENT_CONFIG,
}

// splitName splits a "HIVE\sub\key\path" name into its hive constant and
// subkey path.
func splitName(name string) (registry.Key, string, error) {
	if name == "" {
		return 0, "", ingredients.ErrMissingName
	}
	parts := strings.SplitN(name, `\`, 2)
	hive, ok := hiveAliases[strings.ToUpper(parts[0])]
	if !ok {
		return 0, "", fmt.Errorf("%w: unknown registry hive %q", ErrInvalidHive, parts[0])
	}
	if len(parts) < 2 || parts[1] == "" {
		return 0, "", fmt.Errorf("%w: %q is missing a subkey path", ErrInvalidHive, name)
	}
	return hive, parts[1], nil
}

// displayName returns a human-readable label for a (possibly empty,
// meaning "default") value name.
func displayName(vname string) string {
	if vname == "" {
		return "(Default)"
	}
	return vname
}

// valueExists reports whether a value named vname is present under k,
// including the unnamed default value.
func valueExists(k regKey, vname string) (bool, error) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if strings.EqualFold(n, vname) {
			return true, nil
		}
	}
	return false, nil
}

// deleteKeyRecursive deletes subkey and everything beneath it.
func deleteKeyRecursive(hive registry.Key, subkey string) error {
	k, err := backend.OpenKey(hive, subkey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := deleteKeyRecursive(hive, subkey+`\`+name); err != nil {
			return err
		}
	}
	return backend.DeleteKey(hive, subkey)
}
