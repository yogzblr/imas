//go:build windows

package group

import (
	"context"
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"

	"github.com/yogzblr/imas/internal/cook"
)

func (g Group) absent(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	groupName, ok := g.params["name"].(string)
	if !ok || groupName == "" {
		result.Failed = true
		return result, errors.New("invalid group; name must be a non-empty string")
	}

	if !groupExistsBy(groupName) {
		result.Succeeded = true
		result.Notes = append(result.Notes,
			cook.SimpleNote("group "+groupName+" already absent, nothing to do"))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote("group "+groupName+" would be deleted"))
		return result, nil
	}

	status := netmanagement.NetLocalGroupDel(nil, groupName)
	if status != nerrSuccess && status != nerrGroupNotFound {
		result.Failed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("failed to delete group %s: NetLocalGroupDel returned status %d", groupName, status)))
		return result, fmt.Errorf("NetLocalGroupDel(%q) failed: status %d", groupName, status)
	}

	if groupExistsBy(groupName) {
		result.Failed = true
		return result, errors.New("group " + groupName + " could not be deleted")
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes,
		cook.SimpleNote("group "+groupName+" deleted"))
	return result, nil
}
