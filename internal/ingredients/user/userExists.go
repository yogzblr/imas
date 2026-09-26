package user

import (
	"context"
	"errors"
	"os/user"

	"github.com/yogzblr/imas/internal/cook"
)

// lookupUser is a test-overridable wrapper around user.Lookup. It is
// implemented by the stdlib os/user package on every OS imas targets, so
// it is shared between the Unix and Windows providers rather than
// reimplemented per platform.
var lookupUser = user.Lookup

func (u User) exists(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	userName, ok := u.params["name"].(string)
	if !ok {
		result.Failed = true
		result.Succeeded = false
		return result, errors.New("invalid user; name must be a string")
	}
	if !userExists(userName) {
		result.Failed = true
		result.Succeeded = false
		result.Notes = append(result.Notes, cook.SimpleNote("user "+userName+" does not exist"))
		return result, nil
	}
	result.Failed = false
	result.Succeeded = true
	result.Notes = append(result.Notes, cook.SimpleNote("user "+userName+" exists"))
	return result, nil
}

func userExists(name string) bool {
	_, err := lookupUser(name)
	return err == nil
}
