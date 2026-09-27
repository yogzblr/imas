// Package natsapi — subjects.go defines NATS subject constants and
// typed request/reply message types for all farmer API endpoints.
//
// All API subjects follow the pattern: imas.api.<domain>.<action>
// Sprout-facing subjects use: imas.sprouts.<sproutID>.<domain>.<action>
package natsapi

import (
	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/shell"
)

// ──────────────────────────────────────────────
// Subject prefix
// ──────────────────────────────────────────────

// SubjectPrefix is the root prefix for all farmer API subjects.
const SubjectPrefix = "imas.api."

// SproutSubjectPrefix is the root prefix for sprout-facing subjects.
const SproutSubjectPrefix = "imas.sprouts."

// ──────────────────────────────────────────────
// API method constants (suffix after SubjectPrefix)
// ──────────────────────────────────────────────

const (
	// Health
	MethodHealth = "health"

	// Version
	MethodVersion = "version"

	// PKI management
	MethodPKIList     = "pki.list"
	MethodPKIAccept   = "pki.accept"
	MethodPKIReject   = "pki.reject"
	MethodPKIDeny     = "pki.deny"
	MethodPKIUnaccept = "pki.unaccept"
	MethodPKIDelete   = "pki.delete"

	// MethodPKIRotateBoxKey asks a sprout to rotate its payload-encryption
	// X25519 keypair (docs/design/imas-payload-encryption-design.md). Per
	// the design doc, this only ever carries an instruction — the sprout
	// generates its own new keypair and reports back the new public key
	// on SproutBoxKeySubmit; farmer never generates or holds a sprout's
	// private key.
	MethodPKIRotateBoxKey = "pki.rotatebox"

	// MethodPKIRotateTenantBoxKey rotates the calling tenant's own
	// payload-encryption X25519 keypair in OpenBao
	// (pki.RotateTenantX25519Keypair): the design doc's accepted
	// mitigation for static keys having no forward secrecy. Params:
	// {"sever": bool}, sever for suspected exposure.
	MethodPKIRotateTenantBoxKey = "pki.rotatetenantbox"

	// Sprouts
	MethodSproutsList = "sprouts.list"
	MethodSproutsGet  = "sprouts.get"

	// Test
	MethodTestPing = "test.ping"

	// Cmd
	MethodCmdRun = "cmd.run"

	// Cook
	MethodCook = "cook"
	// MethodCookResync nudges sprouts to pull their staged recipe and
	// cook it if they missed its push (cook.NudgeSprout).
	MethodCookResync = "cook.resync"

	// Jobs
	MethodJobsList      = "jobs.list"
	MethodJobsGet       = "jobs.get"
	MethodJobsDelete    = "jobs.delete"
	MethodJobsCancel    = "jobs.cancel"
	MethodJobsForSprout = "jobs.forsprout"

	// Props
	MethodPropsGetAll = "props.getall"
	MethodPropsGet    = "props.get"
	MethodPropsSet    = "props.set"
	MethodPropsDelete = "props.delete"

	// Cohorts
	MethodCohortsList     = "cohorts.list"
	MethodCohortsGet      = "cohorts.get"
	MethodCohortsResolve  = "cohorts.resolve"
	MethodCohortsRefresh  = "cohorts.refresh"
	MethodCohortsValidate = "cohorts.validate"

	// Auth
	MethodAuthLogin      = "auth.login"
	MethodAuthWhoAmI     = "auth.whoami"
	MethodAuthListUsers  = "auth.users"
	MethodAuthAddUser    = "auth.users.add"
	MethodAuthRemoveUser = "auth.users.remove"
	MethodAuthExplain    = "auth.explain"

	// Shell
	MethodShellStart = "shell.start"

	// Audit
	MethodAuditDates = "audit.dates"
	MethodAuditQuery = "audit.query"
)

// Subject returns the full NATS subject for a given API method.
func Subject(method string) string {
	return SubjectPrefix + method
}

// SproutSubject builds a sprout-facing subject:
// imas.sprouts.<sproutID>.<suffix>
func SproutSubject(sproutID, suffix string) string {
	return SproutSubjectPrefix + sproutID + "." + suffix
}

// ──────────────────────────────────────────────
// Sprout-facing subject suffixes
// ──────────────────────────────────────────────

const (
	// SproutTestPing is the suffix for ping probes to a sprout.
	SproutTestPing = "test.ping"

	// SproutCancel is the suffix for job cancel messages to a sprout.
	SproutCancel = "cancel"

	// SproutShellStart is the suffix for starting a shell session on a sprout.
	SproutShellStart = "shell.start"

	// SproutCookTrigger is the prefix for cook trigger responses.
	// Full subject: imas.farmer.cook.trigger.<jid>
	SproutCookTriggerPrefix = "imas.farmer.cook.trigger."

	// SproutBoxKeyRotateCmd is the suffix for farmer's rotate-trigger
	// instruction to a sprout (MethodPKIRotateBoxKey's handler publishes
	// here). Carries no key material — see MethodPKIRotateBoxKey's doc
	// comment.
	SproutBoxKeyRotateCmd = "boxkey.rotate"

	// SproutBoxKeySubmitPattern is the wildcard subject farmer subscribes
	// on to receive a sprout's new payload-encryption public key, whether
	// self-initiated or in response to SproutBoxKeyRotateCmd. Trust model
	// matches internal/facts's listener: the subject's embedded sprout ID
	// is taken from the connection's own authenticated identity, not from
	// the message body.
	SproutBoxKeySubmitPattern = SproutSubjectPrefix + "*.boxkey.pub"
)

// ──────────────────────────────────────────────
// Request types
// ──────────────────────────────────────────────

// PKIRequest identifies a sprout for PKI operations (accept/reject/deny/unaccept/delete).
type PKIRequest = pki.KeyManager

// SproutsGetRequest identifies a sprout to retrieve.
type SproutsGetRequest = pki.KeyManager

// JobsListRequest holds optional parameters for listing jobs.
type JobsListRequest = JobsListParams

// JobsGetRequest identifies a job by JID.
type JobsGetRequest = JobsGetParams

// JobsForSproutRequest identifies a sprout for job listing.
type JobsForSproutRequest = JobsForSproutParams

// PropsRequest holds sprout and property identifiers for props operations.
type PropsRequest = PropsParams

// CohortGetRequest identifies a cohort by name.
type CohortGetRequest = CohortGetParams

// CohortResolveRequest identifies a cohort to resolve.
type CohortResolveRequest = CohortResolveParams

// CohortRefreshRequest optionally identifies a cohort to refresh (empty = all).
type CohortRefreshRequest = CohortRefreshParams

// AuthTokenRequest holds a token for auth operations.
type AuthTokenRequest = AuthParams

// AuthLoginResponse is the response for the auth.login endpoint.
type AuthLoginResponse = apitypes.LoginResponse

// ShellStartRequest is the request to start an interactive shell session.
type ShellStartRequest = shell.CLIStartRequest

// RecipesGetRequest identifies a recipe by name.
type RecipesGetRequest struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// AuditQueryRequest holds query parameters for audit log searches.
type AuditQueryRequest = audit.QueryParams

// ──────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────

// HealthCheckResponse is the typed response for the health endpoint.
type HealthCheckResponse = HealthResponse

// VersionResponse is the response for the version endpoint.
type VersionResponse = config.Version

// PKIListResponse is the list of all NKeys grouped by state.
type PKIListResponse = pki.KeysByType

// SproutsListResponse wraps the sprout list.
type SproutsListResponse struct {
	Sprouts []SproutInfo `json:"sprouts"`
}

// JobsListResponse is a list of job summaries.
type JobsListResponse = []jobs.JobSummary

// JobsGetResponse is a single job detail.
type JobsGetResponse = jobs.JobSummary

// JobsDeleteResponse confirms a job was deleted from the farmer-side store.
type JobsDeleteResponse struct {
	JID     string `json:"jid"`
	Message string `json:"message"`
}

// JobsCancelResponse confirms a cancel request was sent.
type JobsCancelResponse struct {
	JID     string `json:"jid"`
	Sprout  string `json:"sprout"`
	Message string `json:"message"`
}

// PropsGetAllResponse is a map of all properties for a sprout.
type PropsGetAllResponse = map[string]interface{}

// PropsGetResponse is a single property value.
type PropsGetResponse struct {
	SproutID string `json:"sprout_id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}

// PropsSuccessResponse indicates a successful set/delete operation.
type PropsSuccessResponse struct {
	Success bool `json:"success"`
}

// CohortsListResponse wraps the cohort summary list.
type CohortsListResponse struct {
	Cohorts []CohortSummary `json:"cohorts"`
}

// CohortsGetResponse is the full detail of a single cohort.
type CohortsGetResponse = CohortDetail

// CohortsResolveResponse lists the resolved sprout members of a cohort.
type CohortsResolveResponse struct {
	Name    string   `json:"name"`
	Sprouts []string `json:"sprouts"`
}

// CohortsRefreshResponse wraps the results of a refresh operation.
type CohortsRefreshResponse = CohortRefreshResponse

// CohortsValidateResponse describes whether all cohort references are valid.
type CohortsValidateResponse = CohortValidateResponse

// ShellStartResponse contains session subjects for the CLI to use.
type ShellStartResponse = shell.StartResponse

// AuditDatesResponse is a list of dates with audit entries.
type AuditDatesResponse = []string

// AuditQueryResponse is the result of an audit log query.
type AuditQueryResponse = audit.QueryResult

// ──────────────────────────────────────────────
// Generic response envelope
// ──────────────────────────────────────────────

// Response is the standard envelope for all NATS API responses.
// Handlers return either a Result or an Error, never both.
type Response = response

// AllMethods returns all registered API method constants.
// Useful for documentation generation and client code generation.
func AllMethods() []string {
	return []string{
		MethodHealth,
		MethodVersion,
		MethodPKIList, MethodPKIAccept, MethodPKIReject,
		MethodPKIDeny, MethodPKIUnaccept, MethodPKIDelete, MethodPKIRotateBoxKey, MethodPKIRotateTenantBoxKey,
		MethodSproutsList, MethodSproutsGet,
		MethodTestPing,
		MethodCmdRun,
		MethodCook, MethodCookResync,
		MethodJobsList, MethodJobsGet, MethodJobsDelete, MethodJobsCancel, MethodJobsForSprout,
		MethodPropsGetAll, MethodPropsGet, MethodPropsSet, MethodPropsDelete,
		MethodCohortsList, MethodCohortsGet, MethodCohortsResolve, MethodCohortsRefresh, MethodCohortsValidate,
		MethodAuthLogin, MethodAuthWhoAmI, MethodAuthListUsers, MethodAuthAddUser, MethodAuthRemoveUser, MethodAuthExplain,
		MethodShellStart,
		MethodAuditDates, MethodAuditQuery,
	}
}
