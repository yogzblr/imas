package client

import (
	"encoding/json"
	"fmt"

	apitypes "github.com/yogzblr/imas/internal/api/types"
)

// WhoAmI retrieves the identity and role of the authenticated user: the
// user whose registered CLI box key the sealed request opened under.
func WhoAmI() (apitypes.UserInfo, error) {
	var info apitypes.UserInfo
	resp, err := NatsRequest("auth.whoami", nil)
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(resp, &info); err != nil {
		return info, fmt.Errorf("whoami: %w", err)
	}
	return info, nil
}

// ExplainAccess retrieves a permission summary for the authenticated user.
func ExplainAccess() (apitypes.ExplainResponse, error) {
	var result apitypes.ExplainResponse
	resp, err := NatsRequest("auth.explain", nil)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("explain: %w", err)
	}
	return result, nil
}

// UsersList is auth.users's answer: every user and role, and the
// fingerprint of each user's active CLI box key (users without one can't
// make requests).
type UsersList struct {
	apitypes.UsersListResponse
	BoxKeys map[string]string `json:"box_keys,omitempty"` // pubkey -> fingerprint
}

// ListUsersWithBoxKeys retrieves all users, role definitions and the
// users' active CLI box key fingerprints.
func ListUsersWithBoxKeys() (UsersList, error) {
	var result UsersList
	resp, err := NatsRequest("auth.users", nil)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("list users: %w", err)
	}
	return result, nil
}

// ListUsers retrieves all configured users and role definitions.
func ListUsers() (apitypes.UsersListResponse, error) {
	l, err := ListUsersWithBoxKeys()
	return l.UsersListResponse, err
}

// userAddParams is auth.users.add's request: the new user's NKey public
// key, role, optional username, and their CLI box public key (printed by
// their imas auth keygen), registered together.
type userAddParams struct {
	Pubkey   string `json:"pubkey"`
	RoleName string `json:"role"`
	Username string `json:"username,omitempty"`
	BoxPub   string `json:"boxpub"`
}

// AddUser registers a user (NKey public key, role) with their CLI box
// public key on the farmer. username may be empty.
func AddUser(pubkey, roleName, username, boxPub string) (apitypes.UserMutateResponse, error) {
	var result apitypes.UserMutateResponse
	resp, err := NatsRequest("auth.users.add", userAddParams{
		Pubkey: pubkey, RoleName: roleName, Username: username, BoxPub: boxPub,
	})
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("add user: %w", err)
	}
	return result, nil
}

// RemoveUser removes a user, and retires their CLI box keys, on the
// farmer.
func RemoveUser(pubkey string) (apitypes.UserMutateResponse, error) {
	var result apitypes.UserMutateResponse
	resp, err := NatsRequest("auth.users.remove", apitypes.UserRemoveRequest{Pubkey: pubkey})
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("remove user: %w", err)
	}
	return result, nil
}

// ResetUserKey replaces a user's CLI box key (a lost or stolen key): every
// key they hold is retired and boxPub becomes their only key. Admin only.
func ResetUserKey(pubkey, boxPub string) (apitypes.UserMutateResponse, error) {
	var result apitypes.UserMutateResponse
	resp, err := NatsRequest("auth.users.resetkey", map[string]string{"pubkey": pubkey, "boxpub": boxPub})
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("reset user key: %w", err)
	}
	return result, nil
}
