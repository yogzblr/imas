package natsapi

import (
	"encoding/json"
	"fmt"
	"strings"

	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/rbac"
)

// natsActionMap maps NATS API method names to RBAC actions.
// Methods not listed here require ActionAdmin (deny by default).
var natsActionMap = map[string]rbac.Action{
	// Read-only
	MethodHealth:          rbac.ActionView,
	MethodVersion:         rbac.ActionView,
	MethodSproutsList:     rbac.ActionView,
	MethodSproutsGet:      rbac.ActionView,
	MethodJobsList:        rbac.ActionView,
	MethodJobsGet:         rbac.ActionView,
	MethodJobsForSprout:   rbac.ActionView,
	MethodPropsGetAll:     rbac.ActionView,
	MethodPropsGet:        rbac.ActionView,
	MethodCohortsList:     rbac.ActionView,
	MethodCohortsGet:      rbac.ActionView,
	MethodCohortsResolve:  rbac.ActionView,
	MethodCohortsRefresh:  rbac.ActionView,
	MethodCohortsValidate: rbac.ActionView,
	MethodRecipesList:     rbac.ActionView,
	MethodRecipesGet:      rbac.ActionView,

	// Write: scoped
	MethodCook:        rbac.ActionCook,
	MethodCookResync:  rbac.ActionCook,
	MethodCmdRun:      rbac.ActionCmd,
	MethodShellOpen:   rbac.ActionShell,
	MethodTestPing:    rbac.ActionTest,
	MethodPropsSet:    rbac.ActionProps,
	MethodPropsDelete: rbac.ActionProps,
	MethodJobsCancel:  rbac.ActionJobAdmin,
	MethodJobsDelete:  rbac.ActionJobAdmin,

	// Global: PKI
	MethodPKIList:         rbac.ActionPKI,
	MethodPKIAccept:       rbac.ActionPKI,
	MethodPKIReject:       rbac.ActionPKI,
	MethodPKIDeny:         rbac.ActionPKI,
	MethodPKIUnaccept:     rbac.ActionPKI,
	MethodPKIDelete:       rbac.ActionPKI,
	MethodPKIRotateBoxKey: rbac.ActionPKI,

	MethodPKIRotateTenantBoxKey: rbac.ActionPKI,

	// Auth
	MethodAuthLogin:      rbac.ActionUserRead,
	MethodAuthWhoAmI:     rbac.ActionUserRead,
	MethodAuthListUsers:  rbac.ActionAdmin,
	MethodAuthAddUser:    rbac.ActionAdmin,
	MethodAuthRemoveUser: rbac.ActionAdmin,
	MethodAuthResetKey:   rbac.ActionAdmin,
	MethodAuthExplain:    rbac.ActionUserRead,
	MethodAuthRotateKey:  rbac.ActionUserRead,

	// Audit
	MethodAuditDates: rbac.ActionAdmin,
	MethodAuditQuery: rbac.ActionAdmin,
}

// selfMethods are about the caller themselves, so any user whose sealed
// request opened (that is, any user with a registered CLI box key) may
// call them whatever their role: health and version, who am I and what may
// I do, and rotating my own CLI box key. Opening is still required: there
// is no unauthenticated method on the sealed API (health and version are
// also answered in plaintext, for monitoring; see sealedrouter.go).
var selfMethods = map[string]bool{
	MethodHealth:        true,
	MethodVersion:       true,
	MethodAuthLogin:     true,
	MethodAuthWhoAmI:    true,
	MethodAuthExplain:   true,
	MethodAuthRotateKey: true,
}

// NATSMethodAction returns the RBAC action required for a NATS API method.
// A cook trigger (MethodCookTriggerPrefix + jid) needs cook, like the
// cook that created it. Unknown methods require ActionAdmin (deny by
// default).
func NATSMethodAction(method string) rbac.Action {
	if a, ok := natsActionMap[method]; ok {
		return a
	}
	if strings.HasPrefix(method, MethodCookTriggerPrefix) {
		return rbac.ActionCook
	}
	return rbac.ActionAdmin
}

// authorize decides whether c, the user a sealed request opened under,
// may call method with params: the role must include the method's action
// and, for a method that targets sprouts, permit it on every one of them
// (checkScopedAccess, in c's tenant). Both checks look the role up by
// c.UserID, never by anything in params. nil means allowed;
// rbac.ErrAccessDenied otherwise.
//
// dangerously_allow_root changes nothing here (owner decision 2026-10-04,
// PR #95: "remove dangerously_allow_root bypass from the NATS path"): a
// sealed request always goes through the role and scope checks for the
// user it opened under.
func authorize(method string, c apiCaller, params json.RawMessage) error {
	if selfMethods[method] {
		return nil
	}
	requiredAction := NATSMethodAction(method)
	if !intauth.UserHasAction(c.UserID, requiredAction) {
		return rbac.ErrAccessDenied
	}
	if extractor := scopeExtractors[method]; extractor != nil {
		sproutIDs, err := extractor(params)
		if err != nil {
			// Fail closed: a request whose targets can't be read is
			// never handed to a handler that might read them more
			// leniently than the scope check did. (Until J.3 it was.)
			return fmt.Errorf("invalid params: %w", err)
		}
		if err := checkScopedAccess(c.TenantID, c.UserID, requiredAction, sproutIDs); err != nil {
			return rbac.ErrAccessDenied
		}
	}
	return nil
}
