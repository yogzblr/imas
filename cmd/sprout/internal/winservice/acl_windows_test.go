//go:build windows

package winservice

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// The TrustedInstaller SID is derived from its service name; recompute it
// rather than trust the constant.
func TestTrustedInstallerSID(t *testing.T) {
	var name []byte
	for _, u := range utf16.Encode([]rune("TRUSTEDINSTALLER")) {
		name = binary.LittleEndian.AppendUint16(name, u)
	}
	h := sha1.Sum(name)
	want := "S-1-5-80"
	for i := 0; i < 5; i++ {
		want += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(h[i*4:]))
	}
	if trustedInstallerSID != want {
		t.Errorf("trustedInstallerSID = %s, want %s", trustedInstallerSID, want)
	}
}

func TestUntrustedWriters(t *testing.T) {
	ti := trustedInstallerSID
	cases := []struct {
		name string
		sddl string
		want []string // substrings, each expected in the result; nil = none
	}{
		{
			name: "Program Files style",
			sddl: "O:" + ti + "D:PAI(A;;FA;;;" + ti + ")(A;OICIIO;GA;;;" + ti + ")(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)" +
				"(A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)",
		},
		{
			name: "MSI config root",
			sddl: "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		},
		{
			// A folder an admin created under C:\ inherits Modify for
			// Authenticated Users.
			name: "folder under C:",
			sddl: "O:BAD:AI(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)" +
				"(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)",
			want: []string{"S-1-5-11"},
		},
		{
			name: "user-owned (Downloads)",
			sddl: "O:S-1-5-21-1-2-3-1001D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)",
			want: []string{"owner S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001"},
		},
		{
			name: "Everyone generic write",
			sddl: "O:SYD:(A;;GW;;;WD)",
			want: []string{"S-1-1-0"},
		},
		{
			name: "Users delete only",
			sddl: "O:SYD:(A;;SD;;;BU)",
			want: []string{"S-1-5-32-545"},
		},
		{
			name: "Users can change the DACL",
			sddl: "O:SYD:(A;;WD;;;BU)",
			want: []string{"S-1-5-32-545"},
		},
		{
			name: "Users read and execute only",
			sddl: "O:SYD:(A;;0x1200a9;;;BU)",
		},
		{
			name: "inherit-only write ignored",
			sddl: "O:SYD:(A;;FA;;;SY)(A;OICIIO;FA;;;BU)",
		},
		{
			name: "OWNER RIGHTS with a trusted owner",
			sddl: "O:BAD:(A;;FA;;;OW)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("SDDL %q: %v", tc.sddl, err)
			}
			got := untrustedWriters(sd)
			if tc.want == nil {
				if len(got) != 0 {
					t.Errorf("untrustedWriters = %v, want none", got)
				}
				return
			}
			joined := strings.Join(got, "; ")
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("untrustedWriters = %v, want it to name %s", got, w)
				}
			}
		})
	}
}

// Built directly: wine's SDDL parser turns NO_ACCESS_CONTROL into an
// empty DACL, not a NULL one.
func TestUntrustedWriters_NullAndMissingDACL(t *testing.T) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		present bool
		want    string
	}{
		{"NULL DACL", true, "NULL DACL"},
		{"no DACL", false, "unreadable DACL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.NewSecurityDescriptor()
			if err != nil {
				t.Fatal(err)
			}
			if err := sd.SetOwner(system, false); err != nil {
				t.Fatal(err)
			}
			if err := sd.SetDACL(nil, tc.present, false); err != nil {
				t.Fatal(err)
			}
			got := untrustedWriters(sd)
			if !strings.Contains(strings.Join(got, "; "), tc.want) {
				t.Errorf("untrustedWriters = %v, want %q", got, tc.want)
			}
		})
	}
}
