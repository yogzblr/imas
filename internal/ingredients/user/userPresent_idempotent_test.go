//go:build !windows

package user

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"testing"
)

// withAccountFiles points passwdFilePath and groupFilePath at fixtures
// holding passwd and group for the duration of the test.
func withAccountFiles(t *testing.T, passwd, group string) {
	t.Helper()
	dir := t.TempDir()
	pw := filepath.Join(dir, "passwd")
	gr := filepath.Join(dir, "group")
	if err := os.WriteFile(pw, []byte(passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gr, []byte(group), 0o600); err != nil {
		t.Fatal(err)
	}
	origPw, origGr := passwdFilePath, groupFilePath
	passwdFilePath, groupFilePath = pw, gr
	t.Cleanup(func() { passwdFilePath, groupFilePath = origPw, origGr })
}

// shellTree makes dir/usr/bin/{sh,bash} as two files and dir/bin as a
// symlink to usr/bin, the merged-/usr layout of Ubuntu 24.04 and
// AlmaLinux 9. It returns dir.
func shellTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	usrBin := filepath.Join(dir, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"sh", "bash"} {
		if err := os.WriteFile(filepath.Join(usrBin, f), []byte("#!"+f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("usr/bin", filepath.Join(dir, "bin")); err != nil {
		t.Fatal(err)
	}
	return dir
}

var testUser = &user.User{Uid: "1001", Gid: "1001", Username: "iuu", HomeDir: "/home/iuu", Name: "imas uat"}

func usermodArgs(shell string, groups []string) []string {
	return buildUsermodArgs("iuu", "", "", shell, "", "imas uat", "", groups, testUser)
}

func TestSameShell(t *testing.T) {
	dir := shellTree(t)
	bin := func(n string) string { return filepath.Join(dir, "bin", n) }
	usr := func(n string) string { return filepath.Join(dir, "usr", "bin", n) }
	// A symlink to the reported shell, under the shell's own name.
	local := filepath.Join(dir, "local")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(usr("bash"), filepath.Join(local, "bash")); err != nil {
		t.Fatal(err)
	}
	// sh as a symlink to bash, as on AlmaLinux.
	alias := filepath.Join(dir, "alias")
	if err := os.MkdirAll(alias, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(usr("bash"), filepath.Join(alias, "sh")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                string
		configured, current string
		want                bool
	}{
		{"equal paths", "/bin/sh", "/bin/sh", true},
		{"equal paths, missing on this host", "/no/such/sh", "/no/such/sh", true},
		{"merged usr, configured under the symlinked dir", bin("sh"), usr("sh"), true},
		{"merged usr, reported under the symlinked dir", usr("bash"), bin("bash"), true},
		{"configured is a symlink to the reported shell", filepath.Join(local, "bash"), usr("bash"), true},
		{"reported is a symlink to the configured shell", usr("bash"), filepath.Join(local, "bash"), true},
		{"different shells", bin("sh"), usr("bash"), false},
		{"same binary under another name", filepath.Join(alias, "sh"), usr("bash"), false},
		{"nothing reported", "/bin/sh", "", false},
		{"configured missing", filepath.Join(dir, "nope", "sh"), usr("sh"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameShell(tt.configured, tt.current); got != tt.want {
				t.Errorf("sameShell(%q, %q) = %v, want %v", tt.configured, tt.current, got, tt.want)
			}
		})
	}
}

func TestPasswdShell(t *testing.T) {
	withAccountFiles(t, "# comment\nroot:x:0:0:root:/root:/bin/bash\niuu:x:1001:1001:imas uat:/home/iuu:/bin/sh\nshort:x:1\n", "")
	for name, want := range map[string]string{"iuu": "/bin/sh", "root": "/bin/bash", "short": "", "nobody": ""} {
		if got := passwdShell(name); got != want {
			t.Errorf("passwdShell(%q) = %q, want %q", name, got, want)
		}
	}
	passwdFilePath = filepath.Join(t.TempDir(), "missing")
	if got := passwdShell("iuu"); got != "" {
		t.Errorf("passwdShell with no file = %q, want empty", got)
	}
}

func TestBuildUsermodArgsShell(t *testing.T) {
	dir := shellTree(t)
	tests := []struct {
		name, reported, configured string
		want                       []string
	}{
		{"already set", "/bin/sh", "/bin/sh", nil},
		{"merged usr alias", filepath.Join(dir, "usr", "bin", "sh"), filepath.Join(dir, "bin", "sh"), nil},
		{"different shell", "/bin/bash", "/bin/sh", []string{"-s", "/bin/sh", "iuu"}},
		{"not set", "/bin/bash", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withAccountFiles(t, "iuu:x:1001:1001:imas uat:/home/iuu:"+tt.reported+"\n", "iuu:x:1001:\n")
			if got := usermodArgs(tt.configured, nil); !slices.Equal(got, tt.want) {
				t.Errorf("args = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSupplementaryGroupsAndPrimary(t *testing.T) {
	withAccountFiles(t, "", "iuu:x:1001:\nwheel:x:10:root,iuu\ndocker:x:990:iuu\nusers:x:100:iuux\nbad:x\n")
	if got, want := supplementaryGroups("iuu"), []string{"wheel", "docker"}; !slices.Equal(got, want) {
		t.Errorf("supplementaryGroups = %q, want %q", got, want)
	}
	if got := primaryGroupName("1001"); got != "iuu" {
		t.Errorf("primaryGroupName(1001) = %q, want iuu", got)
	}
	if got := primaryGroupName("4242"); got != "" {
		t.Errorf("primaryGroupName(4242) = %q, want empty", got)
	}
}

func TestBuildUsermodArgsGroups(t *testing.T) {
	const passwd = "iuu:x:1001:1001:imas uat:/home/iuu:/bin/sh\n"
	tests := []struct {
		name, group string
		groups      []string
		want        []string
	}{
		{"same set, other order", "iuu:x:1001:\nwheel:x:10:iuu\ndocker:x:990:iuu\n", []string{"docker", "wheel"}, nil},
		{"primary group listed", "iuu:x:1001:\nwheel:x:10:iuu\n", []string{"iuu", "wheel"}, nil},
		{"missing one", "iuu:x:1001:\nwheel:x:10:iuu\ndocker:x:990:\n", []string{"wheel", "docker"}, []string{"-G", "wheel,docker", "iuu"}},
		{"extra one", "iuu:x:1001:\nwheel:x:10:iuu\ndocker:x:990:iuu\n", []string{"wheel"}, []string{"-G", "wheel", "iuu"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withAccountFiles(t, passwd, tt.group)
			if got := usermodArgs("", tt.groups); !slices.Equal(got, tt.want) {
				t.Errorf("args = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPresentSecondCookNoChange is the I.user.present UAT case: once the
// first cook has set the shell and comment, the second must change
// nothing. Before the fix it always ran `usermod -s /bin/sh`.
func TestPresentSecondCookNoChange(t *testing.T) {
	withAccountFiles(t, "iuu:x:1001:1001:imas uat:/home/iuu:/bin/sh\n", "iuu:x:1001:\nwheel:x:10:iuu\n")
	rec := &cmdRecorder{}
	withMockExec(rec.successFactory, func() {
		withMockLookup(lookupFound(testUser), func() {
			u := User{id: "uat", method: "present", params: map[string]interface{}{
				"name": "iuu", "comment": "imas uat", "shell": "/bin/sh",
				"createhome": false, "groups": []interface{}{"wheel"},
			}}
			for _, test := range []bool{true, false} {
				result, err := u.present(context.Background(), test)
				if err != nil {
					t.Fatalf("present(test=%v): %v", test, err)
				}
				if !result.Succeeded || result.Changed {
					t.Errorf("present(test=%v) = %+v, want succeeded, no change", test, result)
				}
			}
		})
	})
	if len(rec.calls) != 0 {
		t.Errorf("ran %q, want no command", rec.calls)
	}
}

// TestPresentShellChange: a user whose shell differs gets exactly
// usermod -s.
func TestPresentShellChange(t *testing.T) {
	withAccountFiles(t, "iuu:x:1001:1001:imas uat:/home/iuu:/bin/bash\n", "iuu:x:1001:\n")
	rec := &cmdRecorder{}
	withMockExec(rec.successFactory, func() {
		withMockLookup(lookupFound(testUser), func() {
			u := User{id: "uat", method: "present", params: map[string]interface{}{
				"name": "iuu", "comment": "imas uat", "shell": "/bin/sh",
			}}
			result, err := u.present(context.Background(), false)
			if err != nil || !result.Succeeded || !result.Changed {
				t.Fatalf("present = %+v, %v; want succeeded and changed", result, err)
			}
		})
	})
	if want := [][]string{{"usermod", "-s", "/bin/sh", "iuu"}}; len(rec.calls) != 1 || !slices.Equal(rec.calls[0], want[0]) {
		t.Errorf("ran %q, want %q", rec.calls, want)
	}
}
