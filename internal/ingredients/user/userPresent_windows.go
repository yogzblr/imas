//go:build windows

// Package user implements the "present" method for Windows targets against
// the netapi32 NetUser*/NetLocalGroup* Win32 API (via
// github.com/deploymenttheory/go-bindings-win32's generated bindings),
// mirroring win_useradd's add/modify/list surface. See
// userPresent_unix.go for the Linux/Unix equivalent (useradd/usermod).
//
// Local accounts only: servername is always passed as nil (local machine),
// matching win_useradd's own scope. Domain-account management is out of
// scope for this provider.
package user

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"

	"github.com/yogzblr/imas/internal/cook"
)

// Selected NET_API_STATUS / Win32 error codes returned by the NetUser*/
// NetLocalGroup* APIs. The generated bindings return raw uint32 status
// codes rather than Go errors (NET_API_STATUS is not marked
// SetLastError in the Win32 metadata), so these are checked by hand —
// same approach the upstream package's own examples/localaccount uses.
const (
	nerrSuccess           uint32 = 0    // NERR_Success
	nerrUserNotFound      uint32 = 2221 // NERR_UserNotFound
	nerrUserExists        uint32 = 2224 // NERR_UserExists
	nerrGroupNotFound     uint32 = 2220 // NERR_GroupNotFound
	errorAccessDenied     uint32 = 5    // ERROR_ACCESS_DENIED
	errorMemberInAlias    uint32 = 1378 // ERROR_MEMBER_IN_ALIAS (already a member)
	errorNoSuchMember     uint32 = 1387 // ERROR_NO_SUCH_MEMBER
	errorMemberNotInAlias uint32 = 1377 // ERROR_MEMBER_NOT_IN_ALIAS

	userInfoLevel1              uint32 = 1 // USER_INFO_1
	localGroupUsersInfoLevel0   uint32 = 0 // LOCALGROUP_USERS_INFO_0
	localGroupMembersInfoLevel3 uint32 = 3 // LOCALGROUP_MEMBERS_INFO_3 (domain\name)

	netUserGetLocalGroupsMaxPreferredLength uint32 = 0xFFFFFFFF
)

// ErrWindowsPasswordHashUnsupported is returned when a "password_hash"
// property is supplied on a Windows target. Windows local accounts take a
// cleartext password at creation time (NetUserAdd's USER_INFO_1); there is
// no crypt(3)-style hash to submit instead. Treating the hash string as if
// it were the literal cleartext password would silently create an account
// whose real password is that hash text — a security bug, not a
// convenience — so this provider fails closed instead.
var ErrWindowsPasswordHashUnsupported = errors.New(
	"password_hash is not supported on Windows: Windows accounts require a cleartext " +
		"password and imas will not submit a crypt hash string as a literal account password; " +
		"use the \"password\" property instead")

func (u User) present(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	userName, ok := u.params["name"].(string)
	if !ok || userName == "" {
		result.Failed = true
		return result, errors.New("invalid user; name must be a non-empty string")
	}

	home := stringParam(u.params, "home")
	comment := stringParam(u.params, "comment")
	password := stringParam(u.params, "password")
	passwordHash := stringParam(u.params, "password_hash")
	groups := stringSliceParam(u.params, "groups")

	if passwordHash != "" {
		result.Failed = true
		return result, ErrWindowsPasswordHashUnsupported
	}

	for _, ignored := range []string{"uid", "gid", "shell"} {
		if _, ok := u.params[ignored]; ok {
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("%q has no equivalent on Windows and was ignored", ignored)))
		}
	}
	if boolParam(u.params, "system", false) {
		result.Notes = append(result.Notes,
			cook.SimpleNote("\"system\" has no equivalent local-account concept on Windows and was ignored"))
	}

	_, err := lookupUser(userName)
	if err != nil {
		if password == "" {
			result.Failed = true
			return result, errors.New(
				"creating a Windows user requires a \"password\" property; imas will not create an account with a blank or fabricated password")
		}
		if test {
			result.Succeeded = true
			result.Changed = true
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("would create Windows user %q via NetUserAdd", userName)))
			return result, nil
		}
		if err := netUserAdd(userName, password, home, comment); err != nil {
			result.Failed = true
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to create user: %s", err.Error())))
			return result, err
		}
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("created user %q via NetUserAdd", userName)))

		if len(groups) > 0 {
			if err := reconcileLocalGroups(userName, groups); err != nil {
				result.Failed = true
				result.Succeeded = false
				result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to set local group membership: %s", err.Error())))
				return result, err
			}
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("set local group membership: %v", groups)))
		}
		return result, nil
	}

	// User exists — reconcile home/comment via NetUserGetInfo/SetInfo, and
	// local group membership (exact-set, matching usermod -G semantics)
	// via NetUserGetLocalGroups + NetLocalGroupAddMembers/DelMembers.
	changed, changeDesc, err := diffAndModifyUser(userName, home, comment, test)
	if err != nil {
		result.Failed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to modify user: %s", err.Error())))
		return result, err
	}
	if changed {
		result.Changed = true
		verb := "modified"
		if test {
			verb = "would modify"
		}
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s user %q: %s", verb, userName, changeDesc)))
	}

	if len(groups) > 0 {
		groupsChanged, groupDesc, err := diffLocalGroups(userName, groups, test)
		if err != nil {
			result.Failed = true
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to reconcile local group membership: %s", err.Error())))
			return result, err
		}
		if groupsChanged {
			result.Changed = true
			verb := "set"
			if test {
				verb = "would set"
			}
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s local group membership: %s", verb, groupDesc)))
		}
	}

	if !result.Changed {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("user %s is already in the desired state", userName)))
		return result, nil
	}
	result.Succeeded = true
	return result, nil
}

// netUserAdd creates a local Windows user account via NetUserAdd (level 1).
func netUserAdd(name, password, home, comment string) error {
	info := netmanagement.USER_INFO_1{
		Usri1_name:     foundation.PWSTR(win32.UTF16Ptr(name)),
		Usri1_password: foundation.PWSTR(win32.UTF16Ptr(password)),
		Usri1_priv:     netmanagement.USER_PRIV_USER,
		Usri1_home_dir: foundation.PWSTR(win32.UTF16Ptr(home)),
		Usri1_comment:  foundation.PWSTR(win32.UTF16Ptr(comment)),
		Usri1_flags:    netmanagement.USER_ACCOUNT_FLAGS(netmanagement.UF_NORMAL_ACCOUNT),
	}
	var parmErr uint32
	status := netmanagement.NetUserAdd(nil, userInfoLevel1, (*byte)(unsafe.Pointer(&info)), &parmErr)
	switch status {
	case nerrSuccess:
		return nil
	case errorAccessDenied:
		return errors.New("NetUserAdd: access denied — imas sprout must be running elevated (Administrator/SYSTEM) to manage local accounts")
	case nerrUserExists:
		return fmt.Errorf("NetUserAdd: an account named %q already exists", name)
	default:
		return fmt.Errorf("NetUserAdd failed: status %d (invalid parameter index %d)", status, parmErr)
	}
}

// diffAndModifyUser reads the current USER_INFO_1 for name, updates the
// home/comment fields that differ from the desired values, and (outside
// test mode) writes the change back via NetUserSetInfo. It reports whether
// a change was (or would be) made.
func diffAndModifyUser(name, home, comment string, test bool) (bool, string, error) {
	var buffer *byte
	status := netmanagement.NetUserGetInfo(nil, name, userInfoLevel1, &buffer)
	if status != nerrSuccess {
		return false, "", fmt.Errorf("NetUserGetInfo returned status %d", status)
	}
	defer netmanagement.NetApiBufferFree(unsafe.Pointer(buffer))

	current := (*netmanagement.USER_INFO_1)(unsafe.Pointer(buffer))
	currentHome := win32.UTF16ToString((*uint16)(current.Usri1_home_dir))
	currentComment := win32.UTF16ToString((*uint16)(current.Usri1_comment))

	var changes []string
	newHome, newComment := currentHome, currentComment
	if home != "" && home != currentHome {
		changes = append(changes, fmt.Sprintf("home_dir %q→%q", currentHome, home))
		newHome = home
	}
	if comment != "" && comment != currentComment {
		changes = append(changes, fmt.Sprintf("comment %q→%q", currentComment, comment))
		newComment = comment
	}
	if len(changes) == 0 {
		return false, "", nil
	}
	desc := fmt.Sprintf("%v", changes)
	if test {
		return true, desc, nil
	}

	update := netmanagement.USER_INFO_1{
		Usri1_name:         foundation.PWSTR(win32.UTF16Ptr(name)),
		Usri1_password:     nil,
		Usri1_password_age: current.Usri1_password_age,
		Usri1_priv:         current.Usri1_priv,
		Usri1_home_dir:     foundation.PWSTR(win32.UTF16Ptr(newHome)),
		Usri1_comment:      foundation.PWSTR(win32.UTF16Ptr(newComment)),
		Usri1_flags:        current.Usri1_flags,
		Usri1_script_path:  current.Usri1_script_path,
	}
	var parmErr uint32
	setStatus := netmanagement.NetUserSetInfo(nil, name, userInfoLevel1, (*byte)(unsafe.Pointer(&update)), &parmErr)
	if setStatus != nerrSuccess {
		return false, "", fmt.Errorf("NetUserSetInfo failed: status %d (invalid parameter index %d)", setStatus, parmErr)
	}
	return true, desc, nil
}

// currentLocalGroups returns the names of the local groups the given user
// currently belongs to, via NetUserGetLocalGroups (level 0).
func currentLocalGroups(name string) ([]string, error) {
	var (
		buffer      *byte
		read, total uint32
	)
	status := netmanagement.NetUserGetLocalGroups(nil, name, localGroupUsersInfoLevel0, 0,
		&buffer, netUserGetLocalGroupsMaxPreferredLength, &read, &total)
	if status != nerrSuccess {
		return nil, fmt.Errorf("NetUserGetLocalGroups returned status %d", status)
	}
	if buffer == nil || read == 0 {
		return nil, nil
	}
	defer netmanagement.NetApiBufferFree(unsafe.Pointer(buffer))

	entries := unsafe.Slice((*netmanagement.LOCALGROUP_USERS_INFO_0)(unsafe.Pointer(buffer)), read)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, win32.UTF16ToString((*uint16)(e.Lgrui0_name)))
	}
	return names, nil
}

// reconcileLocalGroups adds name as a member of each group in groups,
// tolerating a group it already belongs to.
func reconcileLocalGroups(name string, groups []string) error {
	for _, g := range groups {
		if err := addLocalGroupMember(g, name); err != nil {
			return err
		}
	}
	return nil
}

// diffLocalGroups sets name's local group membership to exactly groups
// (adding missing memberships, removing memberships not in the desired
// list), matching the exact-set semantics of the Unix provider's
// `usermod -G`. It reports whether a change was (or would be) made.
func diffLocalGroups(name string, groups []string, test bool) (bool, string, error) {
	current, err := currentLocalGroups(name)
	if err != nil {
		return false, "", err
	}
	toAdd, toRemove := diffMembership(current, groups)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		return false, "", nil
	}
	desc := fmt.Sprintf("+%v -%v", toAdd, toRemove)
	if test {
		return true, desc, nil
	}
	for _, g := range toAdd {
		if err := addLocalGroupMember(g, name); err != nil {
			return false, "", err
		}
	}
	for _, g := range toRemove {
		if err := removeLocalGroupMember(g, name); err != nil {
			return false, "", err
		}
	}
	return true, desc, nil
}

func addLocalGroupMember(groupName, memberName string) error {
	member := netmanagement.LOCALGROUP_MEMBERS_INFO_3{
		Lgrmi3_domainandname: foundation.PWSTR(win32.UTF16Ptr(memberName)),
	}
	status := netmanagement.NetLocalGroupAddMembers(nil, groupName, localGroupMembersInfoLevel3,
		(*byte)(unsafe.Pointer(&member)), 1)
	if status != nerrSuccess && status != errorMemberInAlias {
		return fmt.Errorf("NetLocalGroupAddMembers(%q, %q) failed: status %d", groupName, memberName, status)
	}
	return nil
}

func removeLocalGroupMember(groupName, memberName string) error {
	member := netmanagement.LOCALGROUP_MEMBERS_INFO_3{
		Lgrmi3_domainandname: foundation.PWSTR(win32.UTF16Ptr(memberName)),
	}
	status := netmanagement.NetLocalGroupDelMembers(nil, groupName, localGroupMembersInfoLevel3,
		(*byte)(unsafe.Pointer(&member)), 1)
	if status != nerrSuccess && status != errorNoSuchMember && status != errorMemberNotInAlias {
		return fmt.Errorf("NetLocalGroupDelMembers(%q, %q) failed: status %d", groupName, memberName, status)
	}
	return nil
}
