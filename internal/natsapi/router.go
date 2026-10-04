// Package natsapi provides a NATS-based API for the farmer.
// Users of the imas CLI send requests to imas.api.<method> subjects; the
// farmer subscribes to these subjects and dispatches to the appropriate
// handler.
//
// Every request and reply is sealed (docs/design/
// imas-payload-encryption-design.md, Decision A, J.3): a request is a
// payloadbox c2f.api Call from the user's CLI box key to the tenant key,
// and the reply an f2c.api Reply back, carrying {"result": ...} or
// {"error": "..."} inside the box. sealedrouter.go is the one place that
// opens, authorizes, audits and seals; handlers see only the verified
// caller and the opened params. Only health and version are also answered
// in plaintext, for monitoring.
package natsapi

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"

	intauth "github.com/yogzblr/imas/internal/auth"
	log "github.com/yogzblr/imas/internal/log"
)

// handler is a function that processes a NATS API request that doesn't
// need to know who sent it (authorization already ran). It receives the
// tenant ID of the connection the request arrived on (connection-level
// metadata captured by Subscribe's closure, per
// docs/design/imas-tenant-context-threading.md's Option A) and the opened
// JSON params, and returns a result or error.
type handler func(tenantID string, params json.RawMessage) (any, error)

// userHandler is a handler that needs the caller: apiCaller.UserID is the
// user whose registered CLI box key the request opened under.
type userHandler func(c apiCaller, params json.RawMessage) (any, error)

// response is the plaintext envelope health and version answer
// unsealed requests with (sealedrouter.go). Every other reply is sealed.
type response struct {
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// routes maps subject suffixes (after "imas.api.") to handlers.
var routes = map[string]handler{
	// Health
	MethodHealth: handleHealth,

	// Version
	MethodVersion: handleVersion,

	// PKI management
	MethodPKIList:         handlePKIList,
	MethodPKIAccept:       handlePKIAccept,
	MethodPKIReject:       handlePKIReject,
	MethodPKIDeny:         handlePKIDeny,
	MethodPKIUnaccept:     handlePKIUnaccept,
	MethodPKIDelete:       handlePKIDelete,
	MethodPKIRotateBoxKey: handlePKIRotateBoxKey,

	MethodPKIRotateTenantBoxKey: handlePKIRotateTenantBoxKey,

	// Sprouts
	MethodSproutsGet: handleSproutsGet,

	// Test
	MethodTestPing: handleTestPing,

	// Cmd
	MethodCmdRun: handleCmdRun,

	// Cook
	MethodCookResync: handleCookResync,

	// Jobs
	MethodJobsGet:       handleJobsGet,
	MethodJobsForSprout: handleJobsListForSprout,

	// Props
	MethodPropsGetAll: handlePropsGetAll,
	MethodPropsGet:    handlePropsGet,
	MethodPropsSet:    handlePropsSet,
	MethodPropsDelete: handlePropsDelete,

	// Cohorts
	MethodCohortsList:     handleCohortsList,
	MethodCohortsGet:      handleCohortsGet,
	MethodCohortsResolve:  handleCohortsResolve,
	MethodCohortsRefresh:  handleCohortsRefresh,
	MethodCohortsValidate: handleCohortsValidate,

	// Auth
	MethodAuthListUsers:  handleAuthListUsers,
	MethodAuthAddUser:    handleAuthAddUser,
	MethodAuthRemoveUser: handleAuthRemoveUser,
	MethodAuthResetKey:   handleAuthResetKey,

	// Recipes
	MethodRecipesList: handleRecipesList,
	MethodRecipesGet:  handleRecipesGet,

	// Audit
	MethodAuditDates: handleAuditList,
	MethodAuditQuery: handleAuditQuery,
}

// userRoutes are the methods whose handlers need the verified caller:
// scope filtering by the user's role, job attribution, the user's own
// identity, their own key.
var userRoutes = map[string]userHandler{
	MethodSproutsList:   handleSproutsList,
	MethodCook:          handleCook,
	MethodJobsList:      handleJobsList,
	MethodJobsDelete:    handleJobsDelete,
	MethodJobsCancel:    handleJobsCancel,
	MethodAuthLogin:     handleAuthLogin,
	MethodAuthWhoAmI:    handleAuthWhoAmI,
	MethodAuthExplain:   handleAuthExplain,
	MethodAuthRotateKey: handleAuthRotateKey,
	MethodShellStart:    handleShellStart,
}

// apiRoutes is every imas.api.* method Subscribe registers, as a
// userHandler.
func apiRoutes() map[string]userHandler {
	all := make(map[string]userHandler, len(routes)+len(userRoutes))
	for method, h := range routes {
		all[method] = func(c apiCaller, params json.RawMessage) (any, error) { return h(c.TenantID, params) }
	}
	for method, h := range userRoutes {
		all[method] = h
	}
	return all
}

// natsCoreQueueGroup is the NATS queue group shared by all farmer replicas
// for imas.api.> request handling. Queue-subscribing (rather than plain
// Subscribe) ensures that when multiple farmer replicas run behind the same
// NATS subject, exactly one replica processes each API request instead of
// every replica processing it and racing to reply / duplicating side
// effects (e.g. running a cmd twice, deleting a job twice).
const natsCoreQueueGroup = "imas-core"

// Subscribe registers all NATS API handlers on the given connection,
// scoped to tenantID — the connection's own tenant identity, per
// docs/design/imas-tenant-context-threading.md's Option A. Each
// imas.api.<method> subject gets a queue subscription whose messages go
// through the sealed router (sealedAPI.serve): opened under the sending
// user's registered CLI box key, authorized for that user, run, audited,
// and answered sealed. Called once per tenant connection: farmer opens
// one NATS connection per tenant (cmd/farmer/main.go's ConnectFarmer),
// and every one of them gets its own full set of registrations.
func Subscribe(nc *nats.Conn, tenantID string) error {
	SetNatsConn(tenantID, nc)

	for method, run := range apiRoutes() {
		subject := Subject(method)
		_, err := nc.QueueSubscribe(subject, natsCoreQueueGroup, func(msg *nats.Msg) {
			replicaSealedAPI.serve(tenantID, method, run, msg)
		})
		if err != nil {
			return fmt.Errorf("natsapi: failed to subscribe to %s: %w", subject, err)
		}
		log.Tracef("natsapi: registered handler for %s (tenant %s)", subject, tenantID)
	}

	if err := registerBoxKeySubmitListener(nc, tenantID); err != nil {
		return err
	}

	if announceCLIPin && tenantID == intauth.UsersTenantID() {
		go logCLIPin(tenantID)
	}
	return nil
}
