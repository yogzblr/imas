// Package natsapi provides a NATS-based API for the farmer.
// Authenticated users connect to the NATS bus and send requests to
// imas.api.<method> subjects. The farmer subscribes to these subjects
// and dispatches to the appropriate handler.
//
// Request/response follows a simple JSON-RPC-like pattern:
//
//	Request:  JSON params (or empty)
//	Response: {"result": ...} or {"error": "..."}
package natsapi

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/audit"
	log "github.com/yogzblr/imas/internal/log"
)

// handler is a function that processes a NATS API request. It receives the
// tenant ID of the connection the request arrived on — connection-level
// metadata captured by Subscribe's closure, per
// docs/design/imas-tenant-context-threading.md's Option A — and the raw
// JSON params, and returns a result or error.
type handler func(tenantID string, params json.RawMessage) (any, error)

// response is the envelope returned to the caller.
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

	// Sprouts
	MethodSproutsList: handleSproutsList,
	MethodSproutsGet:  handleSproutsGet,

	// Test
	MethodTestPing: handleTestPing,

	// Cmd
	MethodCmdRun: handleCmdRun,

	// Cook
	MethodCook: handleCook,

	// Jobs
	MethodJobsList:      handleJobsList,
	MethodJobsGet:       handleJobsGet,
	MethodJobsDelete:    handleJobsDelete,
	MethodJobsCancel:    handleJobsCancel,
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
	MethodAuthLogin:      handleAuthLogin,
	MethodAuthWhoAmI:     handleAuthWhoAmI,
	MethodAuthListUsers:  handleAuthListUsers,
	MethodAuthAddUser:    handleAuthAddUser,
	MethodAuthRemoveUser: handleAuthRemoveUser,
	MethodAuthExplain:    handleAuthExplain,

	// Shell (interactive SSH-like sessions)
	MethodShellStart: handleShellStart,

	// Audit
	MethodAuditDates: handleAuditList,
	MethodAuditQuery: handleAuditQuery,
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
// docs/design/imas-tenant-context-threading.md's Option A. It subscribes
// to "imas.api.>" and dispatches based on subject suffix. Each handler is
// wrapped with RBAC enforcement middleware that checks the caller's token
// before dispatching. Called once per tenant connection: farmer opens one
// NATS connection per tenant (cmd/farmer/main.go's ConnectFarmer), and
// every one of them gets its own full set of registrations.
func Subscribe(nc *nats.Conn, tenantID string) error {
	SetNatsConn(tenantID, nc)

	for method, h := range routes {
		subject := Subject(method)
		handler := authMiddleware(method, h) // wrap with RBAC enforcement
		action := method                     // capture for audit
		_, err := nc.QueueSubscribe(subject, natsCoreQueueGroup, func(msg *nats.Msg) {
			result, err := handler(tenantID, msg.Data)

			// Audit log: record actions based on configured audit level.
			if audit.ShouldLog(action) {
				if auditErr := audit.LogAction(action, msg.Data, result, err); auditErr != nil {
					log.Errorf("natsapi: audit log failed for %s: %v", action, auditErr)
				}
			}

			var resp response
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.Result = result
			}
			data, marshalErr := json.Marshal(resp)
			if marshalErr != nil {
				data = []byte(fmt.Sprintf(`{"error":"marshal error: %s"}`, marshalErr.Error()))
			}
			if msg.Reply != "" {
				if pubErr := msg.Respond(data); pubErr != nil {
					log.Errorf("natsapi: failed to respond to %s: %v", msg.Subject, pubErr)
				}
			}
		})
		if err != nil {
			return fmt.Errorf("natsapi: failed to subscribe to %s: %w", subject, err)
		}
		log.Tracef("natsapi: registered handler for %s (tenant %s)", subject, tenantID)
	}

	if err := registerBoxKeySubmitListener(nc, tenantID); err != nil {
		return err
	}

	return nil
}
