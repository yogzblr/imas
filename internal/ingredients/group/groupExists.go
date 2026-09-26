package group

import (
	"context"
	"errors"
	"os/user"

	"github.com/yogzblr/imas/internal/cook"
)

// lookupGroup is a test-overridable wrapper around user.LookupGroup. It is
// implemented by the stdlib os/user package on every OS imas targets, so
// it is shared between the Unix and Windows providers rather than
// reimplemented per platform.
var lookupGroup = user.LookupGroup

// groupExistsBy reports whether a local group with the given name exists.
var groupExistsBy = func(name string) bool {
	_, err := lookupGroup(name)
	return err == nil
}

func (g Group) exists(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result
	result.Succeeded = true
	result.Failed = false

	groupName, ok := g.params["name"].(string)
	if !ok {
		result.Failed = true
		result.Succeeded = false
		return result, errors.New("invalid group; name must be a string")
	}
	if !groupExistsBy(groupName) {
		result.Failed = true
		result.Succeeded = false
		result.Notes = append(result.Notes, cook.SimpleNote("group "+groupName+" does not exist"))
		return result, nil
	}
	result.Notes = append(result.Notes, cook.SimpleNote("group "+groupName+" exists"))
	return result, nil
}
