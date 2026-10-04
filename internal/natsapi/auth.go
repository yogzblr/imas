package natsapi

// auth.* on the sealed API (J.3). Every handler here learns who is
// calling from apiCaller.UserID: the user whose registered CLI box key the
// sealed request opened under (sealedrouter.go). Nothing in a request's
// params names the caller; there is no token.

import (
	"encoding/json"
	"errors"
	"fmt"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// displayName is how a user is named in messages: their username, or the
// start of their key.
func displayName(pubkey, username string) string {
	if username != "" {
		return username
	}
	if len(pubkey) >= 12 {
		return pubkey[:12] + "..."
	}
	return pubkey
}

// handleAuthLogin confirms the CLI's sealed request opened under a key
// registered for its user, and returns the user's role, permissions, and
// admin status: a formal handshake before the user runs any real
// commands.
func handleAuthLogin(c apiCaller, _ json.RawMessage) (any, error) {
	roleName, username := intauth.UserIdentity(c.UserID)
	summary := rbac.ExplainAccess(intauth.CurrentPolicy(), c.UserID)

	actions := make([]apitypes.ActionExplain, 0, len(summary.Actions))
	for _, a := range summary.Actions {
		actions = append(actions, apitypes.ActionExplain{Action: a.Action, Scope: a.Scope})
	}
	return apitypes.LoginResponse{
		Authenticated: true,
		Pubkey:        c.UserID,
		RoleName:      roleName,
		Username:      username,
		IsAdmin:       summary.IsAdmin,
		Actions:       actions,
		Message:       fmt.Sprintf("authenticated as %s (role: %s)", displayName(c.UserID, username), roleName),
	}, nil
}

func handleAuthWhoAmI(c apiCaller, _ json.RawMessage) (any, error) {
	roleName, username := intauth.UserIdentity(c.UserID)
	return apitypes.UserInfo{Pubkey: c.UserID, RoleName: roleName, Username: username}, nil
}

func handleAuthExplain(c apiCaller, _ json.RawMessage) (any, error) {
	roleName, _ := intauth.UserIdentity(c.UserID)
	summary := rbac.ExplainAccess(intauth.CurrentPolicy(), c.UserID)
	resp := apitypes.ExplainResponse{
		Pubkey:   c.UserID,
		RoleName: roleName,
		IsAdmin:  summary.IsAdmin,
		Warnings: summary.Warnings,
	}
	for _, a := range summary.Actions {
		resp.Actions = append(resp.Actions, apitypes.ActionExplain{Action: a.Action, Scope: a.Scope})
	}
	return resp, nil
}

// UserAddParams holds the params for adding a user: their NKey public key
// (the user ID), role, optional username, and their CLI box public key
// (standard base64, printed by their imas auth keygen), registered
// together so the new user can make sealed requests at once.
type UserAddParams struct {
	Pubkey   string `json:"pubkey"`
	RoleName string `json:"role"`
	Username string `json:"username,omitempty"`
	BoxPub   string `json:"boxpub"`
}

// UserRemoveParams holds the params for removing a user.
type UserRemoveParams struct {
	Pubkey string `json:"pubkey"`
}

// UserResetKeyParams holds the params for an admin's reset of a user's
// CLI box key.
type UserResetKeyParams struct {
	Pubkey string `json:"pubkey"`
	BoxPub string `json:"boxpub"`
}

func handleAuthAddUser(_ string, params json.RawMessage) (any, error) {
	var p UserAddParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}

	if p.Pubkey == "" || p.RoleName == "" {
		return nil, fmt.Errorf("pubkey and role are required")
	}
	if p.BoxPub == "" {
		return nil, intauth.ErrBoxPubRequired
	}

	if err := intauth.AddUser(p.Pubkey, p.RoleName, p.Username, p.BoxPub); err != nil {
		return nil, err
	}

	return apitypes.UserMutateResponse{
		Success: true,
		Message: fmt.Sprintf("user %s added with role %s and CLI box key %s", p.Pubkey, p.RoleName, boxKeyFingerprint(p.BoxPub)),
	}, nil
}

func handleAuthRemoveUser(_ string, params json.RawMessage) (any, error) {
	var p UserRemoveParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}

	if p.Pubkey == "" {
		return nil, fmt.Errorf("pubkey is required")
	}

	if err := intauth.RemoveUser(p.Pubkey); err != nil {
		return nil, err
	}

	return apitypes.UserMutateResponse{
		Success: true,
		Message: fmt.Sprintf("user %s removed; their CLI box keys are retired", p.Pubkey),
	}, nil
}

// handleAuthResetKey is an admin's reset of a user's CLI box key: every
// key the user holds is retired and the given one becomes their only key
// (a lost or stolen key, or a config-file user's first key).
func handleAuthResetKey(_ string, params json.RawMessage) (any, error) {
	var p UserResetKeyParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	if p.Pubkey == "" || p.BoxPub == "" {
		return nil, fmt.Errorf("pubkey and boxpub are required")
	}
	if err := intauth.ResetUserCLIBoxKey(p.Pubkey, p.BoxPub); err != nil {
		return nil, err
	}
	return apitypes.UserMutateResponse{
		Success: true,
		Message: fmt.Sprintf("user %s's CLI box key is now %s; every earlier key is retired", p.Pubkey, boxKeyFingerprint(p.BoxPub)),
	}, nil
}

// UsersListResult is auth.users's answer: apitypes.UsersListResponse, plus
// each user's active CLI box key fingerprint.
type UsersListResult struct {
	apitypes.UsersListResponse
	BoxKeys map[string]string `json:"box_keys,omitempty"`
}

func handleAuthListUsers(_ string, _ json.RawMessage) (any, error) {
	users := intauth.ListAllUsers()

	roleNames := intauth.ListRoles()
	roles := make([]apitypes.RoleInfo, 0, len(roleNames))
	for _, name := range roleNames {
		role, err := intauth.GetRole(name)
		if err != nil {
			continue
		}
		roles = append(roles, apitypes.RoleInfo{
			Name:  role.Name,
			Rules: role.Rules,
		})
	}

	boxKeys, err := intauth.UserCLIBoxKeyFingerprints()
	if err != nil && !errors.Is(err, intauth.ErrStoreNotConfigured) {
		return nil, err
	}
	return UsersListResult{
		UsersListResponse: apitypes.UsersListResponse{Users: users, Roles: roles},
		BoxKeys:           boxKeys,
	}, nil
}

// handleAuthRotateKey records a c2f.userkey.pub: the caller's new CLI box
// key, sealed under their current one (imas auth rotate-key). Only the
// active key may change the active key (pki.RecordCLIBoxKeySubmission).
// The router seals the reply to the user's active key after this ran, so
// once the rotation is recorded the reply opens only under the new key,
// which is what tells the CLI to promote it.
func handleAuthRotateKey(c apiCaller, params json.RawMessage) (any, error) {
	if c.req == nil || c.req.Purpose != payloadbox.PurposeCLIUserKeySubmit {
		return nil, errors.New("auth.rotatekey: not a key submission")
	}
	body := &payloadbox.CallBody{Method: c.req.Method, Subject: c.req.Subject, Params: params}
	pub, err := pki.RecordCLIBoxKeySubmission(c.TenantID, c.UserID, c.req.SealedUnder, body)
	if err != nil {
		return nil, err
	}
	return map[string]string{"box_pub": pub, "fingerprint": boxKeyFingerprint(pub)}, nil
}

func boxKeyFingerprint(pub string) string {
	k, err := intauth.DecodeCLIBoxPub(pub)
	if err != nil {
		return ""
	}
	return payloadbox.Fingerprint(k)
}
