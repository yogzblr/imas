//go:build windows

package fleetsign

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// trustTempACLs gives every path the ACL an installed keyring has (owned
// by SYSTEM, writable only by SYSTEM and Administrators): a test's temp
// files are owned by the user running it, which the check refuses.
func trustTempACLs(t *testing.T) {
	t.Helper()
	orig := readACL
	readACL = func(string) (winACL, error) {
		return winACL{owner: sidSystem, aces: []winACE{
			{aceType: aceTypeAllowed, flags: aceFlagInherited, mask: 0x001f01ff, sid: sidSystem},
			{aceType: aceTypeAllowed, flags: aceFlagInherited, mask: 0x001f01ff, sid: sidAdministrators},
		}}, nil
	}
	t.Cleanup(func() { readACL = orig })
}

// TestLoadArmoredKeyring_UntrustedACL: on Windows the keyring is refused
// when its ACL lets Users write it, whatever its mode bits.
func TestLoadArmoredKeyring_UntrustedACL(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fleet-signing-keys.asc")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := readACL
	readACL = func(string) (winACL, error) {
		return winACL{owner: sidSystem, aces: []winACE{{aceType: aceTypeAllowed, flags: aceFlagInherited, mask: 0x4, sid: "S-1-5-32-545"}}}, nil
	}
	t.Cleanup(func() { readACL = orig })
	if _, err := LoadArmoredKeyring(file); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Users-writable keyring: %v, want ErrUnsafePath", err)
	}
}
