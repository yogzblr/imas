//go:build windows

package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"

	"github.com/yogzblr/imas/internal/cook"
)

func (u User) absent(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	userName, ok := u.params["name"].(string)
	if !ok || userName == "" {
		result.Failed = true
		return result, errors.New("invalid user; name must be a non-empty string")
	}

	if !userExists(userName) {
		result.Succeeded = true
		result.Notes = append(result.Notes,
			cook.SimpleNote("user "+userName+" already absent, nothing to do"))
		return result, nil
	}

	if boolParam(u.params, "purge", false) {
		result.Notes = append(result.Notes, cook.SimpleNote(
			"\"purge\" has no equivalent on Windows (NetUserDel does not remove the user profile/home "+
				"directory) and was ignored; remove it separately if needed"))
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote("user "+userName+" would be deleted"))
		return result, nil
	}

	status := netmanagement.NetUserDel(nil, userName)
	if status != nerrSuccess && status != nerrUserNotFound {
		result.Failed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("failed to delete user %s: NetUserDel returned status %d", userName, status)))
		return result, fmt.Errorf("NetUserDel(%q) failed: status %d", userName, status)
	}

	if userExists(userName) {
		result.Failed = true
		return result, errors.New("user " + userName + " could not be deleted")
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes,
		cook.SimpleNote("user "+userName+" deleted"))
	return result, nil
}
