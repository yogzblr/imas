package pkg

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/gogrlx/snack"
	"github.com/yogzblr/imas/internal/cook"
)

var errKeyNotSupported = errors.New("package manager does not support key management")

func (p Pkg) keyManaged(ctx context.Context, test bool) (cook.Result, error) {
	mgr, err := getManager()
	if err != nil {
		return failResult(err)
	}
	keyMgr, ok := mgr.(snack.KeyManager)
	if !ok {
		return failResult(errKeyNotSupported)
	}
	absent := getBoolProp(p.properties, "absent", false)
	if absent {
		return p.keyRemoved(ctx, keyMgr, test)
	}
	return p.keyAdded(ctx, keyMgr, test)
}

func (p Pkg) keyAdded(ctx context.Context, keyMgr snack.KeyManager, test bool) (cook.Result, error) {
	// Check if key already present.
	keys, err := keyMgr.ListKeys(ctx)
	if err != nil {
		return failResult(err)
	}
	if keyListed(keys, keyListingName(keyMgr, p.name)) {
		return cook.Result{
			Succeeded: true,
			Changed:   false,
			Notes:     []fmt.Stringer{note("key already present: %s", p.name)},
		}, nil
	}
	if test {
		return cook.Result{
			Succeeded: true,
			Changed:   true,
			Notes:     []fmt.Stringer{note("would add key: %s", p.name)},
		}, nil
	}
	err = keyMgr.AddKey(ctx, p.name)
	if err != nil {
		return failResult(err)
	}
	// A key given as a URL or file is listed by the key's own ID (rpm's
	// gpg-pubkey-<id>-<date>), not by what the recipe names, so the check
	// above can't find it. Compare the listing before and after instead:
	// importing a key that is already there changes nothing.
	after, err := keyMgr.ListKeys(ctx)
	if err == nil && !keysAdded(keys, after) {
		return cook.Result{
			Succeeded: true,
			Changed:   false,
			Notes:     []fmt.Stringer{note("key already present: %s", p.name)},
		}, nil
	}
	return cook.Result{
		Succeeded: true,
		Changed:   true,
		Notes:     []fmt.Stringer{note("added key: %s", p.name)},
	}, nil
}

// keyListingName returns the name the key manager lists key as. apt
// stores a key fetched from a URL in /etc/apt/keyrings/<base>.gpg (the
// URL's last element without its extension, snack's apt.AddKey) and lists
// that path; every other key is listed under the name it was given.
func keyListingName(keyMgr snack.KeyManager, key string) string {
	if managerName(keyMgr) != "apt" {
		return key
	}
	if !strings.HasPrefix(key, "http://") && !strings.HasPrefix(key, "https://") {
		return key
	}
	base := path.Base(key)
	return path.Join("/etc/apt/keyrings", strings.TrimSuffix(base, path.Ext(base))+".gpg")
}

// managerName returns the package manager's name (snack's "apt", "dnf",
// ...), or "" when it doesn't say.
func managerName(m interface{}) string {
	if n, ok := m.(interface{ Name() string }); ok {
		return n.Name()
	}
	return ""
}

func keyListed(keys []string, name string) bool {
	for _, k := range keys {
		if k == name {
			return true
		}
	}
	return false
}

// keysAdded reports whether after lists a key before doesn't.
func keysAdded(before, after []string) bool {
	seen := make(map[string]bool, len(before))
	for _, k := range before {
		seen[k] = true
	}
	for _, k := range after {
		if !seen[k] {
			return true
		}
	}
	return false
}

func (p Pkg) keyRemoved(ctx context.Context, keyMgr snack.KeyManager, test bool) (cook.Result, error) {
	// Check if key exists.
	keys, err := keyMgr.ListKeys(ctx)
	if err != nil {
		return failResult(err)
	}
	found := false
	for _, k := range keys {
		if k == p.name {
			found = true
			break
		}
	}
	if !found {
		return cook.Result{
			Succeeded: true,
			Changed:   false,
			Notes:     []fmt.Stringer{note("key already absent: %s", p.name)},
		}, nil
	}
	if test {
		return cook.Result{
			Succeeded: true,
			Changed:   true,
			Notes:     []fmt.Stringer{note("would remove key: %s", p.name)},
		}, nil
	}
	err = keyMgr.RemoveKey(ctx, p.name)
	if err != nil {
		return failResult(err)
	}
	return cook.Result{
		Succeeded: true,
		Changed:   true,
		Notes:     []fmt.Stringer{note("removed key: %s", p.name)},
	}, nil
}
