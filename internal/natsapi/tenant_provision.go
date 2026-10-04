package natsapi

// Farmer's half of the SaaS API's tenant-provisioning bridge
// (cloudxp-machine-manager-api-design.md §2.2): internal.tenant.provision
// and internal.tenant.deprovision in, internal.tenant.provisioned.{job_id}
// and internal.tenant.deprovisioned.{job_id} out.
//
// Unlike every other registration in this package, these handlers are not
// per-tenant: they're platform-level control-plane subjects in the SYS
// Account, registered once per farmer process on its SYS listener
// connection (cmd/farmer/main.go's initSystemAccountListeners) — not on
// any tenant's connection, and not via Subscribe/routes, whose handlers
// all receive a connection-bound tenantID. See
// docs/design/imas-internal-api-account.md for that decision.
//
// FLAG FOR SECURITY REVIEW. Authorization is not the bus's per-User
// permission check: a compromised bus ignores its own permissions, and
// until J.4 that let it forge provisioning and deprovisioning and their
// results (docs/design/imas-payload-encryption-design.md, "Sealing the
// control plane", Decision B). Every request is now a payloadbox Call
// sealed by the SaaS API's registered box key to the platform key, bound
// to its purpose, method and subject, fresh, and accepted once on this
// replica and once cluster-wide (openSaaSAPIRequest). A plaintext,
// forged, moved or replayed request is dropped without running anything
// and without an answer (the subjects are fire-and-forget). Every result
// is a sealed f2a Call bound to its job's subject (sealSaaSAPIResult),
// never plaintext. The SaaS API's scoped SYS User
// (pki.EnsureSaaSAPICredential) still limits who may publish here on an
// honest bus; it is no longer what farmer relies on.
//
// A re-sent request (the SaaS API's outbox sweeper) is a new sealed
// message with a new ID, accepted like the first. That is safe for the
// same reason it was before J.4: pki.ProvisionTenant and
// pki.DeprovisionTenant are idempotent for a repeated job_id, and the
// SaaS API applies one result per job (CL.3).

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// provisionTenant/deprovisionTenant are indirections over pki's real
// functions so handler-level unit tests can exercise decode/validation/
// reply behavior without a full PKI+bus setup. Production code and the
// end-to-end test (internal/saasapi/provisioning_e2e_test.go) always run
// the real pki.ProvisionTenant/pki.DeprovisionTenant.
var (
	provisionTenant   = pki.ProvisionTenant
	deprovisionTenant = pki.DeprovisionTenant
)

// Audit action names for the two handlers, matching the subject names.
const (
	auditActionTenantProvision   = controlplane.SubjectTenantProvision
	auditActionTenantDeprovision = controlplane.SubjectTenantDeprovision
)

// RegisterTenantProvisioning queue-subscribes nc — farmer's SYS listener
// connection — to internal.tenant.provision and internal.tenant.deprovision.
// It uses the same natsCoreQueueGroup as imas.api.> (workstream D's
// discipline) so that with several farmer replicas, exactly one processes
// each request. Call once per process, not once per tenant.
//
// It also registers internal.sprout.action (RegisterSproutAction), the
// other SaaS API -> farmer subject on this connection, so that
// cmd/farmer/main.go's initSystemAccountListeners picks it up through its
// existing call here.
//
// Each request is opened (openSaaSAPIRequest) before its handler sees
// anything; the handler gets only the opened params.
func RegisterTenantProvisioning(nc *nats.Conn) error {
	return registerSaaSAPIHandlers(nc, replicaSealedAPI)
}

// registerSaaSAPIHandlers is RegisterTenantProvisioning with the replica's
// sealed-request state passed in, so tests can stand up two replicas.
func registerSaaSAPIHandlers(nc *nats.Conn, s *sealedAPI) error {
	if _, err := nc.QueueSubscribe(controlplane.SubjectTenantProvision, natsCoreQueueGroup, func(msg *nats.Msg) {
		if req := s.openSaaSAPIRequestOrRefuse(msg, false); req != nil {
			handleTenantProvision(nc, req.Params)
		}
	}); err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", controlplane.SubjectTenantProvision, err)
	}
	if _, err := nc.QueueSubscribe(controlplane.SubjectTenantDeprovision, natsCoreQueueGroup, func(msg *nats.Msg) {
		if req := s.openSaaSAPIRequestOrRefuse(msg, false); req != nil {
			handleTenantDeprovision(nc, req.Params)
		}
	}); err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", controlplane.SubjectTenantDeprovision, err)
	}
	log.Info("natsapi: registered tenant provisioning handlers (SYS account, sealed)")
	return registerSproutAction(nc, s)
}

// handleTenantProvision runs data, an opened internal.tenant.provision
// request's params, and publishes its sealed result.
func handleTenantProvision(nc *nats.Conn, data []byte) {
	var req controlplane.TenantProvisionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: dropping malformed %s request: %v", controlplane.SubjectTenantProvision, err)
		return
	}
	// With no valid job ID there's no subject to report a result on — the
	// SaaS API's outbox row stays pending, which is the honest outcome.
	if !controlplane.ValidJobID(req.JobID) {
		log.Errorf("natsapi: dropping %s request with invalid job_id %q (tenant %q)", controlplane.SubjectTenantProvision, req.JobID, req.TenantID)
		return
	}

	res := controlplane.TenantResult{JobID: req.JobID, TenantID: req.TenantID, Status: controlplane.StatusActive}
	err := provisionTenant(req.TenantID, req.Name)
	if err != nil {
		// The full error stays here, keyed by job ID; only a fixed code
		// goes on the bus (see controlplane.ErrorCode).
		log.Errorf("natsapi: provisioning tenant %q (job %s) failed: %v", req.TenantID, req.JobID, err)
		res.Status = controlplane.StatusFailed
		res.ErrorCode = tenantErrorCode(err)
	}
	auditTenantAction(auditActionTenantProvision, data, res, err)
	publishTenantResult(nc, false, res)
}

// handleTenantDeprovision runs data, an opened internal.tenant.deprovision
// request's params, and publishes its sealed result.
func handleTenantDeprovision(nc *nats.Conn, data []byte) {
	var req controlplane.TenantDeprovisionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: dropping malformed %s request: %v", controlplane.SubjectTenantDeprovision, err)
		return
	}
	if !controlplane.ValidJobID(req.JobID) {
		log.Errorf("natsapi: dropping %s request with invalid job_id %q (tenant %q)", controlplane.SubjectTenantDeprovision, req.JobID, req.TenantID)
		return
	}

	res := controlplane.TenantResult{JobID: req.JobID, TenantID: req.TenantID, Status: controlplane.StatusOffboarded}
	err := deprovisionTenant(req.TenantID)
	switch {
	case errors.Is(err, pki.ErrTenantNotFound):
		// No pki_tenants row at all — e.g. provisioning failed before
		// anything was created — so there's nothing to tear down: the
		// tenant's end state (no Account on the bus) already holds.
		// Offboarded, with a warning. Safe only because pki returns
		// ErrTenantNotFound solely for a genuinely absent row, never for a
		// database error (see getTenantRow).
		log.Warnf("natsapi: deprovisioning tenant %q (job %s): tenant was never provisioned; nothing to tear down", req.TenantID, req.JobID)
		res.WarningCode = controlplane.WarningTenantNotProvisioned
		err = nil
	case err != nil:
		log.Errorf("natsapi: deprovisioning tenant %q (job %s) failed: %v", req.TenantID, req.JobID, err)
		res.Status = controlplane.StatusFailed
		res.ErrorCode = tenantErrorCode(err)
	}
	auditTenantAction(auditActionTenantDeprovision, data, res, err)
	publishTenantResult(nc, true, res)
}

// tenantErrorCode maps a pki provisioning error to the fixed code
// published on the bus. Only pki's own sentinel errors get a specific
// code; everything else — wrapped filesystem, database and resolver-push
// errors, whose text can carry paths and internal detail — is
// ErrorInternal.
func tenantErrorCode(err error) controlplane.ErrorCode {
	switch {
	case errors.Is(err, pki.ErrTenantIDInvalid):
		return controlplane.ErrorInvalidTenantID
	case errors.Is(err, pki.ErrTenantNotFound):
		return controlplane.ErrorTenantNotFound
	default:
		return controlplane.ErrorInternal
	}
}

// publishTenantResult seals res (sealSaaSAPIResult) and publishes it on
// its job's result subject. A result that can't be sealed (the platform
// key unreadable) is logged and not published, never sent in plaintext:
// the SaaS API's job stays pending, its outbox sweeper sends the request
// again, and the idempotent handlers answer it then.
func publishTenantResult(nc *nats.Conn, deprovision bool, res controlplane.TenantResult) {
	subject, data, err := sealSaaSAPIResult(deprovision, res.JobID, res)
	if err != nil {
		log.Errorf("natsapi: sealing the result of job %s (tenant %s): %v; not published", res.JobID, res.TenantID, err)
		return
	}
	msg := nats.NewMsg(subject)
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Data = data
	if err := nc.PublishMsg(msg); err != nil {
		log.Errorf("natsapi: publishing %s: %v", subject, err)
	}
}

func auditTenantAction(action string, params []byte, result any, err error) {
	if !audit.ShouldLog(action) {
		return
	}
	if auditErr := audit.LogAction(action, params, result, err); auditErr != nil {
		log.Errorf("natsapi: audit log failed for %s: %v", action, auditErr)
	}
}
