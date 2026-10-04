package client

import (
	"encoding/json"
	"fmt"

	apitypes "github.com/yogzblr/imas/internal/api/types"
)

// Login performs a formal auth handshake with the farmer: a sealed
// auth.login that opens on farmer only under the CLI box key registered
// for this user, answered with the user's identity, role, and
// permissions in a sealed reply.
//
// This is distinct from WhoAmI in that it returns the full permission
// set and is intended as an explicit "login" action.
func Login() (apitypes.LoginResponse, error) {
	var result apitypes.LoginResponse
	resp, err := NatsRequest("auth.login", nil)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("login: %w", err)
	}
	return result, nil
}

// ValidateAuth performs a lightweight auth check by calling Login and
// returning an error if the CLI's key is not recognized by the farmer.
// This is used during CLI startup to catch misconfigured keys early.
func ValidateAuth() (apitypes.LoginResponse, error) {
	result, err := Login()
	if err != nil {
		return result, fmt.Errorf("auth validation failed: %w", err)
	}
	if !result.Authenticated {
		return result, fmt.Errorf("auth validation failed: %s", result.Message)
	}
	return result, nil
}
