// Package controlplane is the wire contract for the platform-level
// internal.* NATS subjects between the SaaS API (internal/saasapi) and
// farmer (internal/natsapi) — cloudxp-machine-manager-api-design.md §2.2.
// It holds only subject names, message shapes, and validation, and has no
// dependencies of its own, so that both sides — and internal/pki, which
// scopes the SaaS API's NATS User permissions to exactly these subjects —
// can share one definition without internal/saasapi pulling in farmer's
// whole dependency tree.
//
// These subjects live in the SYS Account, not any tenant's: see
// docs/design/imas-internal-api-account.md for that decision and why.
package controlplane

import (
	"encoding/json"
	"strings"
	"time"
)

// Request subjects, published by the SaaS API and queue-subscribed by
// farmer. Fire-and-forget (design doc §2.2): no NATS reply is expected;
// the outcome comes back on the matching per-job result subject below.
const (
	SubjectTenantProvision   = "internal.tenant.provision"
	SubjectTenantDeprovision = "internal.tenant.deprovision"
)

// SubjectSproutAction is the one request-reply subject in this package
// (design doc §2.2): published by the SaaS API with a reply inbox under
// SaaSAPIInboxPrefix, queue-subscribed by farmer, which replies directly
// on that inbox. It dispatches a single action to a single, already
// resolved sprout — the SaaS API fans a §1.5 batch out into one request
// per item.
const SubjectSproutAction = "internal.sprout.action"

// SaaSAPIInboxPrefix is the only reply-inbox prefix the SaaS API's NATS
// User may subscribe to (pki's saasAPIUserPermissions grants
// SaaSAPIInboxWildcard, never a bare _INBOX.>), so it can't subscribe to
// other SYS users' reply inboxes. The SaaS API must dial with
// nats.CustomInboxPrefix(SaaSAPIInboxPrefix), or its own replies are
// refused by the bus. Farmer, in turn, refuses to reply anywhere else
// (ValidSaaSAPIReplySubject).
const (
	SaaSAPIInboxPrefix   = "_INBOX.saasapi"
	SaaSAPIInboxWildcard = SaaSAPIInboxPrefix + ".>"
)

// Result subject prefixes, published by farmer with the job's ID as the
// final token (e.g. internal.tenant.provisioned.pj_abc123) and subscribed
// by the SaaS API via the single-token wildcards below.
const (
	SubjectTenantProvisionedPrefix   = "internal.tenant.provisioned."
	SubjectTenantDeprovisionedPrefix = "internal.tenant.deprovisioned."

	SubjectTenantProvisionedWildcard   = SubjectTenantProvisionedPrefix + "*"
	SubjectTenantDeprovisionedWildcard = SubjectTenantDeprovisionedPrefix + "*"
)

// Result statuses farmer reports. A provision succeeds as StatusActive; a
// deprovision succeeds as StatusOffboarded; either can fail as
// StatusFailed with Error set.
//
// internal.sprout.action replies use StatusCompleted (a cmd.run the sprout
// ran and answered — which says nothing about the command's own exit code,
// see CmdRunResult.ExitCode), StatusDispatched (a cook, which runs
// asynchronously under the returned JID), or StatusFailed.
const (
	StatusActive     = "active"
	StatusOffboarded = "offboarded"
	StatusFailed     = "failed"

	StatusCompleted  = "completed"
	StatusDispatched = "dispatched"
)

// ErrorCode classifies a failed provisioning result. Farmer never puts raw
// error text on the bus: a pki error can carry filesystem paths, key file
// names, or database detail, and the SaaS API relays a failed job's error
// to its external callers (GET /tenants/{id}/status). Farmer logs the full
// error locally, keyed by job ID; only one of these fixed codes crosses the
// service boundary, and the SaaS API only ever displays PublicErrorMessage
// for it.
type ErrorCode string

const (
	// ErrorInvalidTenantID: farmer rejected the tenant ID's format.
	ErrorInvalidTenantID ErrorCode = "invalid_tenant_id"
	// ErrorTenantNotFound: farmer has no record of the tenant (e.g. a
	// deprovision for a tenant that was never provisioned).
	ErrorTenantNotFound ErrorCode = "tenant_not_found"
	// ErrorInternal: anything else. The detail stays in farmer's logs.
	ErrorInternal ErrorCode = "internal_error"

	// internal.sprout.action only:

	// ErrorInvalidRequest: the request was malformed (bad JSON, a bad
	// tenant or sprout ID, or params that don't decode for the action).
	ErrorInvalidRequest ErrorCode = "invalid_request"
	// ErrorUnsupportedAction: action.type isn't one farmer handles.
	ErrorUnsupportedAction ErrorCode = "unsupported_action"
	// ErrorSproutNotFound: farmer's point-of-effect check failed — no
	// accepted sprout with that ID is registered under the asserted
	// tenant, or the tenant itself isn't live. Deliberately the same code
	// for "doesn't exist" and "belongs to another tenant" (design doc §4:
	// a mismatch resolves to not-found, never a distinguishable
	// authorization error).
	ErrorSproutNotFound ErrorCode = "sprout_not_found"
	// ErrorSproutUnreachable: the sprout is registered but didn't answer
	// (offline, or the command outlived its timeout).
	ErrorSproutUnreachable ErrorCode = "sprout_unreachable"
)

var publicErrorMessages = map[ErrorCode]string{
	ErrorInvalidTenantID: "the tenant ID was rejected by the provisioning service",
	ErrorTenantNotFound:  "the tenant is not known to the provisioning service",
	ErrorInternal:        "an internal error occurred during provisioning; retry or contact support",

	ErrorInvalidRequest:    "the action request was rejected as malformed",
	ErrorUnsupportedAction: "the action type is not supported",
	ErrorSproutNotFound:    "the sprout is not known to this tenant",
	ErrorSproutUnreachable: "the sprout did not respond; it may be offline",
}

// PublicErrorMessage returns the fixed, caller-safe message for code. An
// unrecognized code (a newer farmer, or a malformed result) maps to the
// ErrorInternal message rather than being echoed back, so nothing a
// result carries is ever displayed verbatim.
func PublicErrorMessage(code ErrorCode) string {
	if msg, ok := publicErrorMessages[code]; ok {
		return msg
	}
	return publicErrorMessages[ErrorInternal]
}

// WarningCode qualifies a successful result: the operation's end state was
// reached, but not by the usual path. Like ErrorCode it's a fixed code, not
// text, and the SaaS API displays only PublicWarningMessage for it.
type WarningCode string

const (
	// WarningTenantNotProvisioned: a deprovision found no record of the
	// tenant on farmer (e.g. its provisioning had failed before anything
	// was created), so there was nothing to tear down. The tenant is
	// offboarded all the same.
	WarningTenantNotProvisioned WarningCode = "tenant_not_provisioned"
)

var publicWarningMessages = map[WarningCode]string{
	WarningTenantNotProvisioned: "the tenant was never provisioned on the provisioning service; there was nothing to tear down",
}

// PublicWarningMessage returns the fixed, caller-safe message for code, or
// "" for no warning. An unrecognized code gets a generic message rather
// than being echoed back.
func PublicWarningMessage(code WarningCode) string {
	if code == "" {
		return ""
	}
	if msg, ok := publicWarningMessages[code]; ok {
		return msg
	}
	return "the operation completed with a warning; contact support for details"
}

// TenantProvisionRequest is the internal.tenant.provision payload.
type TenantProvisionRequest struct {
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// TenantDeprovisionRequest is the internal.tenant.deprovision payload.
type TenantDeprovisionRequest struct {
	JobID    string `json:"job_id"`
	TenantID string `json:"tenant_id"`
}

// TenantResult is the payload of both internal.tenant.provisioned.{job_id}
// and internal.tenant.deprovisioned.{job_id}. A failure carries only an
// ErrorCode and a qualified success only a WarningCode — never text; see
// ErrorCode.
type TenantResult struct {
	JobID       string      `json:"job_id"`
	TenantID    string      `json:"tenant_id"`
	Status      string      `json:"status"`
	ErrorCode   ErrorCode   `json:"error_code,omitempty"`
	WarningCode WarningCode `json:"warning_code,omitempty"`
}

// Action types for SproutActionRequest.Action.Type. ActionSelfUpdate's
// params are SelfUpdateParams.
const (
	ActionCmdRun     = "cmd.run"
	ActionCook       = "cook"
	ActionSelfUpdate = "self_update"
)

// SelfUpdateParams is a self_update action's params (design doc §2.2):
// one saas.fleet_versions row, signature included. Farmer re-verifies
// Signature against the imas-fleet-signing public key before dispatching
// (§2.5), and the sprout verifies it again against its pinned copy before
// fetching anything; a missing or invalid signature is refused at each.
type SelfUpdateParams struct {
	Version        string `json:"version"`
	ArtifactURL    string `json:"artifact_url"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	Signature      string `json:"signature"`
}

// SproutActionRequest is the internal.sprout.action payload. TenantID is
// the SaaS API's assertion, not a fact: farmer independently checks it
// against the sprout's own stored tenant before doing anything (the
// point-of-effect check, design doc §2.2).
type SproutActionRequest struct {
	TenantID string       `json:"tenant_id"`
	SproutID string       `json:"sprout_id"`
	Action   SproutAction `json:"action"`
}

// SproutAction is one action to run on one sprout. Params is the action
// payload farmer's own imas.api.cmd.run / imas.api.cook handlers take
// (internal/api/types CmdRun / CmdCook, e.g. {"command": "systemctl",
// "args": ["restart", "nginx"]} or {"recipe": "nginx.harden"}) — mapping
// the SaaS API's external request shape onto it is the SaaS API's job.
type SproutAction struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

// SproutActionReply is farmer's reply to internal.sprout.action. Like
// TenantResult it carries only a fixed ErrorCode on failure, never error
// text. Result is set for a completed cmd.run (a CmdRunResult); JID for a
// dispatched cook.
type SproutActionReply struct {
	TenantID  string        `json:"tenant_id"`
	SproutID  string        `json:"sprout_id"`
	Status    string        `json:"status"`
	JID       string        `json:"jid,omitempty"`
	Result    *CmdRunResult `json:"result,omitempty"`
	ErrorCode ErrorCode     `json:"error_code,omitempty"`
}

// CmdRunResult is what a sprout reported for a cmd.run. A non-zero
// ExitCode is still StatusCompleted: the action ran; whether the command
// succeeded is the caller's call.
type CmdRunResult struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

// ValidSaaSAPIReplySubject reports whether subject is a reply inbox farmer
// may answer an internal.sprout.action request on: a literal subject (no
// wildcards, no empty tokens, no whitespace) strictly under
// SaaSAPIInboxPrefix. Farmer replies from its SYS user, which has no
// permission restrictions, and NATS doesn't check a publisher's
// permissions against the reply subject it sets — so without this, the
// SaaS API credential could name any subject as its "inbox" (another
// user's inbox, $SYS.REQ.*, a forged internal.tenant.provisioned.*
// result) and have farmer publish there on its behalf.
func ValidSaaSAPIReplySubject(subject string) bool {
	rest, ok := strings.CutPrefix(subject, SaaSAPIInboxPrefix+".")
	if !ok || rest == "" || len(subject) > 255 {
		return false
	}
	for _, tok := range strings.Split(rest, ".") {
		if tok == "" || strings.ContainsAny(tok, " \t\r\n*>") {
			return false
		}
	}
	return true
}

// maxJobIDLen matches saas.provisioning_jobs.id's column size.
const maxJobIDLen = 36

// ValidJobID reports whether id is safe to use as a single NATS subject
// token: non-empty, bounded, and restricted to [0-9A-Za-z_-]. Farmer builds
// the result subject by appending the request's job_id, so without this a
// crafted job_id containing '.' (an extra token), '*'/'>' (wildcards,
// rejected by the server on publish anyway) or whitespace could publish a
// result somewhere other than the one subject the SaaS API is waiting on.
func ValidJobID(id string) bool {
	if id == "" || len(id) > maxJobIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ProvisionedSubject returns the result subject for a provision job.
// jobID must already satisfy ValidJobID.
func ProvisionedSubject(jobID string) string { return SubjectTenantProvisionedPrefix + jobID }

// DeprovisionedSubject returns the result subject for a deprovision job.
// jobID must already satisfy ValidJobID.
func DeprovisionedSubject(jobID string) string { return SubjectTenantDeprovisionedPrefix + jobID }

// JobIDFromSubject extracts the trailing job-ID token from a result
// subject received on one of the wildcards above, reporting false if the
// subject doesn't carry prefix or its remaining token isn't a valid job ID.
func JobIDFromSubject(subject, prefix string) (string, bool) {
	id, ok := strings.CutPrefix(subject, prefix)
	if !ok || !ValidJobID(id) {
		return "", false
	}
	return id, true
}
