//go:build windows

// Package group implements the "present"/"absent" methods for Windows
// targets against the netapi32 NetLocalGroup* Win32 API (via
// github.com/deploymenttheory/go-bindings-win32's generated bindings),
// mirroring win_groupadd's add/delete/list surface. See
// groupPresent_unix.go for the Linux/Unix equivalent
// (groupadd/groupmod/groupdel/gpasswd).
//
// Local groups only: servername is always passed as nil (local machine),
// matching win_groupadd's own scope.
package group

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

// Selected NET_API_STATUS / Win32 error codes returned by the
// NetLocalGroup* APIs. The generated bindings return raw uint32 status
// codes rather than Go errors (NET_API_STATUS is not marked
// SetLastError in the Win32 metadata), so these are checked by hand.
const (
	nerrSuccess       uint32 = 0    // NERR_Success
	nerrGroupNotFound uint32 = 2220 // NERR_GroupNotFound
	nerrGroupExists   uint32 = 2223 // NERR_GroupExists
	errorAccessDenied uint32 = 5    // ERROR_ACCESS_DENIED

	localGroupInfoLevel1        uint32 = 1 // LOCALGROUP_INFO_1
	localGroupMembersInfoLevel3 uint32 = 3 // LOCALGROUP_MEMBERS_INFO_3 (domain\name)
)

func (g Group) present(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	groupName, ok := g.params["name"].(string)
	if groupName == "" || !ok {
		result.Failed = true
		return result, errors.New("invalid group; name must be a non-empty string")
	}

	members := stringSliceParam(g.params, "members")
	for _, ignored := range []string{"gid", "system"} {
		if _, ok := g.params[ignored]; ok {
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("%q has no equivalent for a Windows local group and was ignored", ignored)))
		}
	}

	if !groupExistsBy(groupName) {
		if test {
			result.Succeeded = true
			result.Changed = true
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("would create local group %q via NetLocalGroupAdd", groupName)))
			if len(members) > 0 {
				result.Notes = append(result.Notes,
					cook.SimpleNote(fmt.Sprintf("would set members to: %v", members)))
			}
			return result, nil
		}
		if err := netLocalGroupAdd(groupName); err != nil {
			result.Failed = true
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to create group: %s", err.Error())))
			return result, err
		}
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("created local group %q via NetLocalGroupAdd", groupName)))

		if len(members) > 0 {
			if err := netLocalGroupSetMembers(groupName, members); err != nil {
				result.Failed = true
				result.Succeeded = false
				result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to set members: %s", err.Error())))
				return result, err
			}
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("set members to: %v", members)))
		}
		return result, nil
	}

	// Group exists.
	if len(members) > 0 {
		if test {
			result.Succeeded = true
			result.Changed = true
			result.Notes = append(result.Notes,
				cook.SimpleNote(fmt.Sprintf("would set members to: %v", members)))
			return result, nil
		}
		if err := netLocalGroupSetMembers(groupName, members); err != nil {
			result.Failed = true
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("failed to set members: %s", err.Error())))
			return result, err
		}
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("set members to: %v", members)))
		return result, nil
	}

	result.Succeeded = true
	result.Notes = append(result.Notes, cook.SimpleNote("group already exists"))
	return result, nil
}

func netLocalGroupAdd(name string) error {
	info := netmanagement.LOCALGROUP_INFO_1{
		Lgrpi1_name: foundation.PWSTR(win32.UTF16Ptr(name)),
	}
	var parmErr uint32
	status := netmanagement.NetLocalGroupAdd(nil, localGroupInfoLevel1, (*byte)(unsafe.Pointer(&info)), &parmErr)
	switch status {
	case nerrSuccess:
		return nil
	case errorAccessDenied:
		return errors.New("NetLocalGroupAdd: access denied — imas sprout must be running elevated (Administrator/SYSTEM) to manage local groups")
	case nerrGroupExists:
		return fmt.Errorf("NetLocalGroupAdd: a group named %q already exists", name)
	default:
		return fmt.Errorf("NetLocalGroupAdd failed: status %d (invalid parameter index %d)", status, parmErr)
	}
}

// netLocalGroupSetMembers sets the exact member list of a local group via
// NetLocalGroupSetMembers (level 3, name-addressed members), matching the
// Unix provider's `gpasswd -M` exact-set semantics.
func netLocalGroupSetMembers(groupName string, members []string) error {
	entries := make([]netmanagement.LOCALGROUP_MEMBERS_INFO_3, len(members))
	for i, m := range members {
		entries[i] = netmanagement.LOCALGROUP_MEMBERS_INFO_3{
			Lgrmi3_domainandname: foundation.PWSTR(win32.UTF16Ptr(m)),
		}
	}
	status := netmanagement.NetLocalGroupSetMembers(nil, groupName, localGroupMembersInfoLevel3,
		(*byte)(unsafe.Pointer(&entries[0])), uint32(len(entries)))
	if status != nerrSuccess {
		return fmt.Errorf("NetLocalGroupSetMembers(%q) failed: status %d", groupName, status)
	}
	return nil
}
