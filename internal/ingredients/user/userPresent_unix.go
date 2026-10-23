//go:build !windows

// Package user implements the "present" method for Linux/Unix targets by
// shelling out to useradd/usermod. See userPresent_windows.go for the
// Windows equivalent, backed by the netapi32 NetUser* Win32 API instead.
package user

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
)

// execCommandContext is a test-overridable factory for exec.Cmd.
var execCommandContext = exec.CommandContext

// validHashPrefixes lists accepted crypt(3) hash algorithm prefixes.
var validHashPrefixes = []string{
	"$1$",  // MD5
	"$5$",  // SHA-256
	"$6$",  // SHA-512
	"$y$",  // yescrypt
	"$2b$", // bcrypt
	"$2a$", // bcrypt (older)
}

// isValidPasswordHash checks that a password hash string starts with a
// recognised crypt(3) prefix.
func isValidPasswordHash(hash string) bool {
	for _, prefix := range validHashPrefixes {
		if strings.HasPrefix(hash, prefix) {
			return true
		}
	}
	return false
}

// shadowPasswordHash reads /etc/shadow and returns the current password hash
// for the given username.  Returns an empty string when the user is not found
// or the file is unreadable.
var shadowFilePath = "/etc/shadow"

func shadowPasswordHash(username string) (string, error) {
	f, err := os.Open(shadowFilePath)
	if err != nil {
		return "", fmt.Errorf("cannot read shadow file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	prefix := username + ":"
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 2 {
			return "", nil
		}
		return fields[1], nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("cannot scan shadow file: %w", err)
	}
	return "", nil
}

// passwdFilePath and groupFilePath are the files usermod edits; tests
// point them at fixtures.
var (
	passwdFilePath = "/etc/passwd"
	groupFilePath  = "/etc/group"
)

// passwdShell returns the login shell (field 7) of username in
// passwdFilePath, or "" when the user or the file can't be read. A ""
// never matches a configured shell, so the caller sets it.
func passwdShell(username string) string {
	shell := ""
	scanColonFile(passwdFilePath, func(fields []string) bool {
		if len(fields) >= 7 && fields[0] == username {
			shell = fields[6]
			return false
		}
		return true
	})
	return shell
}

// sameShell reports whether the configured shell is the one the system
// reports. Equal paths match. So do two paths to the same file with the
// same base name: /bin/sh and /usr/bin/sh on a merged-/usr system, or a
// symlink to the reported shell under its own name. Two names for one
// binary do not match (/bin/sh linked to bash is not /bin/bash): the
// shell sees the name it was started with, and bash run as sh runs in
// POSIX mode, so changing the name is a real change.
func sameShell(configured, current string) bool {
	if configured == current {
		return true
	}
	if current == "" || filepath.Base(configured) != filepath.Base(current) {
		return false
	}
	a, err := os.Stat(configured)
	if err != nil {
		return false
	}
	b, err := os.Stat(current)
	if err != nil {
		return false
	}
	return os.SameFile(a, b)
}

// supplementaryGroups returns the groups in groupFilePath that list
// username as a member, the set `usermod -G` replaces.
func supplementaryGroups(username string) []string {
	var names []string
	scanColonFile(groupFilePath, func(fields []string) bool {
		if len(fields) < 4 {
			return true
		}
		for _, m := range strings.Split(fields[3], ",") {
			if m == username {
				names = append(names, fields[0])
				break
			}
		}
		return true
	})
	return names
}

// groupName returns the name of the group id names: a group ID, as usermod
// reads an all-digit -g or -G entry, becomes the name of the group with
// that ID in groupFilePath; a name, or an ID no group has, is returned as
// is.
func groupName(id string) string {
	if id == "" || strings.Trim(id, "0123456789") != "" {
		return id
	}
	name := id
	scanColonFile(groupFilePath, func(fields []string) bool {
		if len(fields) >= 3 && fields[2] == id {
			name = fields[0]
			return false
		}
		return true
	})
	return name
}

// sameGroups reports whether usermod -G with desired would leave the
// supplementary groups as they are. desired may name groups by ID. The
// primary group (a name) may be listed in desired: usermod accepts it, but
// it never shows as a supplementary member, so it is left out of the
// comparison.
func sameGroups(desired, current []string, primary string) bool {
	want := map[string]bool{}
	for _, g := range desired {
		if g = groupName(g); g != "" && g != primary {
			want[g] = true
		}
	}
	have := map[string]bool{}
	for _, g := range current {
		if g != primary {
			have[g] = true
		}
	}
	if len(want) != len(have) {
		return false
	}
	for g := range want {
		if !have[g] {
			return false
		}
	}
	return true
}

// scanColonFile calls fn with the colon-separated fields of each line of
// path until fn returns false. An unreadable file reads as empty.
func scanColonFile(path string, fn func(fields []string) bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !fn(strings.Split(line, ":")) {
			return
		}
	}
}

func (u User) present(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	userName, ok := u.params["name"].(string)
	if !ok || userName == "" {
		result.Failed = true
		return result, errors.New("invalid user; name must be a non-empty string")
	}

	uid := stringParam(u.params, "uid")
	gid := stringParam(u.params, "gid")
	shell := stringParam(u.params, "shell")
	home := stringParam(u.params, "home")
	comment := stringParam(u.params, "comment")
	passwordHash := stringParam(u.params, "password_hash")
	groups := stringSliceParam(u.params, "groups")
	createHome := boolParam(u.params, "createhome", true)
	system := boolParam(u.params, "system", false)

	// Validate password hash format if provided.
	if passwordHash != "" && !isValidPasswordHash(passwordHash) {
		result.Failed = true
		return result, fmt.Errorf("invalid password_hash: must start with a recognised crypt prefix (%s)",
			strings.Join(validHashPrefixes, ", "))
	}

	existing, err := lookupUser(userName)
	if err != nil {
		// User does not exist — useradd
		args := buildUseraddArgs(userName, uid, gid, shell, home, comment, passwordHash, groups, createHome, system)
		cmd := execCommandContext(ctx, "useradd", args...)
		if test {
			result.Succeeded = true
			result.Changed = true
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("would create user with command: %s", cmd.String())))
			return result, nil
		}
		if err := cmd.Run(); err != nil {
			result.Failed = true
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("failed to create user: %s", err.Error())))
			return result, err
		}
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("created user with command: %s", cmd.String())))
		return result, nil
	}

	// User exists — check if modifications are needed
	args := buildUsermodArgs(userName, uid, gid, shell, home, comment, passwordHash, groups, existing)
	if len(args) == 0 {
		// No changes needed
		result.Succeeded = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("user %s is already in the desired state", userName)))
		return result, nil
	}

	cmd := execCommandContext(ctx, "usermod", args...)
	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("would modify user with command: %s", cmd.String())))
		return result, nil
	}
	if err := cmd.Run(); err != nil {
		result.Failed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("failed to modify user: %s", err.Error())))
		return result, err
	}
	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes,
		cook.SimpleNote(fmt.Sprintf("modified user with command: %s", cmd.String())))
	return result, nil
}

func buildUseraddArgs(name, uid, gid, shell, home, comment, passwordHash string, groups []string, createHome, system bool) []string {
	var args []string
	if uid != "" {
		args = append(args, "-u", uid)
	}
	if gid != "" {
		args = append(args, "-g", gid)
	}
	if shell != "" {
		args = append(args, "-s", shell)
	}
	if home != "" {
		args = append(args, "-d", home)
	}
	if comment != "" {
		args = append(args, "-c", comment)
	}
	if passwordHash != "" {
		args = append(args, "-p", passwordHash)
	}
	if len(groups) > 0 {
		args = append(args, "-G", strings.Join(groups, ","))
	}
	if createHome {
		args = append(args, "-m")
	}
	if system {
		args = append(args, "-r")
	}
	args = append(args, name)
	return args
}

func buildUsermodArgs(name, uid, gid, shell, home, comment, passwordHash string, groups []string, existing *user.User) []string {
	var args []string
	if uid != "" && uid != existing.Uid {
		args = append(args, "-u", uid)
	}
	if gid != "" && gid != existing.Gid {
		args = append(args, "-g", gid)
	}
	if shell != "" && !sameShell(shell, passwdShell(name)) {
		args = append(args, "-s", shell)
	}
	if home != "" && home != existing.HomeDir {
		args = append(args, "-d", home)
	}
	if comment != "" {
		// user.User.Name is the GECOS field
		if comment != existing.Name {
			args = append(args, "-c", comment)
		}
	}
	if passwordHash != "" {
		// Check if the hash differs from the current shadow entry.
		currentHash, _ := shadowPasswordHash(name)
		if currentHash != passwordHash {
			args = append(args, "-p", passwordHash)
		}
	}
	// The primary group after this usermod: the requested one when -g is
	// given, so a group it stops being primary still gets -G.
	primary := existing.Gid
	if gid != "" {
		primary = gid
	}
	if len(groups) > 0 && !sameGroups(groups, supplementaryGroups(name), groupName(primary)) {
		args = append(args, "-G", strings.Join(groups, ","))
	}
	if len(args) == 0 {
		return nil
	}
	args = append(args, name)
	return args
}
