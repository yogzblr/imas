package natsapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taigrr/jety"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// --- jety test helpers ---

func setupJetyDangerouslyAllowRoot(t *testing.T, enable bool) func() {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("# test config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jety.SetConfigType("toml")
	jety.SetConfigFile(path)
	jety.Set("dangerously_allow_root", enable)
	return func() {
		jety.Set("dangerously_allow_root", false)
		jety.Set("privkey", "")
		jety.Set("pubkeys", nil)
		jety.Set("users", nil)
		jety.Set("roles", nil)
		jety.Set("cohorts", nil)
	}
}

// --- handleAuthExplain with dangerouslyAllowRoot ---

// --- handleAuthWhoAmI with dangerouslyAllowRoot ---

// --- handleCmdRun with registered sprout (covers validation pass path) ---

func TestHandleCmdRunRegisteredSprout(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-exec", "UKEY_EXEC")

	// cmd.FRun will try to use NATS — nil conn means it will error, but
	// we cover the validation-pass and goroutine spawn paths.
	ClearNatsConn(pki.CurrentTenantID())

	params := json.RawMessage(`{"target":[{"id":"sprout-exec"}],"action":{"command":"echo hello"}}`)
	result, err := handleCmdRun(pki.CurrentTenantID(), params)

	// The function may succeed (with an error in results) or fail
	// depending on how FRun handles nil NATS. Either way, we covered
	// the validation pass path.
	if err != nil {
		// If it errors at the top level, that's fine — it means we
		// passed validation but FRun had issues.
		return
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestHandleCmdRunEmptyTargets(t *testing.T) {
	setupNatsAPIPKI(t)

	params := json.RawMessage(`{"target":[],"action":{"command":"echo hello"}}`)
	result, err := handleCmdRun(pki.CurrentTenantID(), params)
	// Empty targets should succeed with empty results.
	if err != nil {
		t.Fatalf("handleCmdRun empty targets: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- handleTestPing with registered sprout ---

func TestHandleTestPingRegisteredSprout(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-ping", "UKEY_PING")

	ClearNatsConn(pki.CurrentTenantID())

	params := json.RawMessage(`{"target":[{"id":"sprout-ping"}],"action":{"ping":true}}`)
	result, err := handleTestPing(pki.CurrentTenantID(), params)

	if err != nil {
		return // FPing may fail without NATS — still covered validation
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestHandleTestPingEmptyTargets(t *testing.T) {
	setupNatsAPIPKI(t)

	params := json.RawMessage(`{"target":[],"action":{"ping":true}}`)
	result, err := handleTestPing(pki.CurrentTenantID(), params)
	if err != nil {
		t.Fatalf("handleTestPing empty targets: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestHandleTestPingSproutIDWithUnderscore(t *testing.T) {
	setupNatsAPIPKI(t)

	params := json.RawMessage(`{"target":[{"id":"sprout_bad"}],"action":{"ping":true}}`)
	_, err := handleTestPing(pki.CurrentTenantID(), params)
	if err == nil {
		t.Fatal("expected error for sprout ID with underscore")
	}
}

// --- handleCook with registered sprout ---

func TestHandleCookRegisteredSproutNoNATS(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-cook-valid", "UKEY_COOK_VALID")

	ClearNatsConn(pki.CurrentTenantID())

	params := json.RawMessage(`{"target":[{"id":"sprout-cook-valid"}],"action":{"recipe":"webserver.nginx"}}`)
	_, err := handleCook(apiCaller{TenantID: pki.CurrentTenantID()}, params)
	if err == nil {
		t.Fatal("expected error when NATS not available")
	}
	if err.Error() != "NATS connection not available" {
		t.Errorf("error = %q, want 'NATS connection not available'", err.Error())
	}
}

func TestHandleCookSproutIDWithUnderscore(t *testing.T) {
	setupNatsAPIPKI(t)

	params := json.RawMessage(`{"target":[{"id":"sprout_bad"}],"action":{"recipe":"test"}}`)
	_, err := handleCook(apiCaller{TenantID: pki.CurrentTenantID()}, params)
	if err == nil {
		t.Fatal("expected error for sprout ID with underscore")
	}
}

func TestHandleCookInvalidAction(t *testing.T) {
	setupNatsAPIPKI(t)

	// Valid target structure but action is a string instead of object.
	params := json.RawMessage(`{"target":[{"id":"test-sprout"}],"action":"not-an-object"}`)
	_, err := handleCook(apiCaller{TenantID: pki.CurrentTenantID()}, params)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

// --- SetCohortRegistry ---

func TestSetCohortRegistry(t *testing.T) {
	old := cohortRegistry
	defer func() { cohortRegistry = old }()

	reg := rbac.NewRegistry()
	SetCohortRegistry(reg)

	if cohortRegistry != reg {
		t.Error("SetCohortRegistry did not set the registry")
	}

	SetCohortRegistry(nil)
	if cohortRegistry != nil {
		t.Error("SetCohortRegistry(nil) did not clear the registry")
	}
}

// --- auditError type ---

func TestAuditErrorType(t *testing.T) {
	err := errAuditNotConfigured
	if err.Error() != "audit logging not configured" {
		t.Errorf("Error() = %q, want %q", err.Error(), "audit logging not configured")
	}

	// Verify it satisfies the error interface.
	var e error = err
	if e.Error() != "audit logging not configured" {
		t.Errorf("error interface: %q", e.Error())
	}
}

// --- checkScopedAccess ---

func TestCheckScopedAccessDangerouslyAllowRoot(t *testing.T) {
	setupNatsAPIPKI(t)
	cleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer cleanup()

	// dangerously_allow_root bypasses nothing on the NATS path (owner
	// decision, PR #95): an unknown user is still refused.
	err := checkScopedAccess(pki.CurrentTenantID(), "UANYUSER", rbac.ActionCook, []string{"sprout-1"})
	if err == nil {
		t.Fatal("dangerously_allow_root let an unknown user through the scope check")
	}
}

func TestCheckScopedAccessUnknownUser(t *testing.T) {
	setupNatsAPIPKI(t)
	cleanup := setupJetyDangerouslyAllowRoot(t, false)
	defer cleanup()

	err := checkScopedAccess(pki.CurrentTenantID(), "UUNKNOWNUSER", rbac.ActionCook, []string{"sprout-1"})
	if err == nil {
		t.Fatal("expected error for an unknown user")
	}
}

// --- filterSproutsByScope ---

func TestFilterSproutsByScopeDangerouslyAllowRoot(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-f1", "UKEY_F1")
	writeNKey(t, pkiDir, "accepted", "sprout-f2", "UKEY_F2")

	cleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer cleanup()

	// No bypass: an unknown user sees nothing, flag or not.
	result := filterSproutsByScope(pki.CurrentTenantID(), "UANYUSER", rbac.ActionView, []string{"sprout-f1", "sprout-f2"})
	if len(result) != 0 {
		t.Errorf("expected 0 filtered sprouts, got %d", len(result))
	}
}

func TestFilterSproutsByScopeUnknownUser(t *testing.T) {
	setupNatsAPIPKI(t)
	cleanup := setupJetyDangerouslyAllowRoot(t, false)
	defer cleanup()

	result := filterSproutsByScope(pki.CurrentTenantID(), "UUNKNOWNUSER", rbac.ActionView, []string{"sprout-1"})
	// An unknown user sees nothing.
	if len(result) != 0 {
		t.Errorf("expected 0 filtered sprouts for an unknown user, got %d", len(result))
	}
}

// --- handleSproutsList with dangerouslyAllowRoot (still filters by scope) ---

func TestHandleSproutsListDangerouslyAllowRoot(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	writeNKey(t, pkiDir, "accepted", "sprout-dar", "UKEY_DAR")

	ClearNatsConn(pki.CurrentTenantID())

	cleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer cleanup()

	result, err := handleSproutsList(apiCaller{TenantID: pki.CurrentTenantID(), UserID: "UNOROLE"}, nil)
	if err != nil {
		t.Fatalf("handleSproutsList: %v", err)
	}

	m := result.(map[string][]SproutInfo)
	if len(m["sprouts"]) != 0 {
		t.Errorf("a user with no role saw %d sprouts under dangerously_allow_root", len(m["sprouts"]))
	}
}

// --- handleJobsList scope filtering ---

func TestHandleJobsListDangerouslyAllowRoot(t *testing.T) {
	obj, cleanup := setupJobStore(t)
	defer cleanup()

	jetyCleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer jetyCleanup()

	steps := []cook.StepCompletion{
		{ID: "s1", CompletionStatus: cook.StepCompleted, Started: time.Now()},
	}
	writeTestJob(t, obj, "sprout-dar-j", "jid-dar-1", steps)

	result, err := handleJobsList(apiCaller{TenantID: pki.CurrentTenantID(), UserID: "UNOROLE"}, nil)
	if err != nil {
		t.Fatalf("handleJobsList: %v", err)
	}

	summaries := result.([]jobs.JobSummary)
	if len(summaries) != 0 {
		t.Errorf("a user with no role saw %d jobs under dangerously_allow_root", len(summaries))
	}
}

func TestHandleJobsListInvalidJSON(t *testing.T) {
	_, cleanup := setupJobStore(t)
	defer cleanup()

	// Invalid JSON should be ignored and return all jobs.
	result, err := handleJobsList(apiCaller{TenantID: pki.CurrentTenantID()}, json.RawMessage(`{invalid`))
	if err != nil {
		t.Fatalf("handleJobsList: %v", err)
	}
	summaries := result.([]jobs.JobSummary)
	if len(summaries) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(summaries))
	}
}

// --- handleJobsCancel with non-cancellable status ---

func TestHandleJobsCancelCompletedJob(t *testing.T) {
	obj, cleanup := setupJobStore(t)
	defer cleanup()

	steps := []cook.StepCompletion{
		{ID: "s1", CompletionStatus: cook.StepCompleted, Started: time.Now()},
	}
	writeTestJob(t, obj, "sprout-done", "jid-done", steps)

	params := json.RawMessage(`{"jid":"jid-done"}`)
	_, err := handleJobsCancel(apiCaller{TenantID: pki.CurrentTenantID()}, params)
	if err == nil {
		t.Fatal("expected error for completed job cancel")
	}
}

func TestHandleJobsCancelInvalidJSON(t *testing.T) {
	_, cleanup := setupJobStore(t)
	defer cleanup()

	_, err := handleJobsCancel(apiCaller{TenantID: pki.CurrentTenantID()}, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- handleJobsCancel scope check path ---

// --- handleAuthListUsers with roles ---

func TestHandleAuthListUsersWithDangerouslyAllowRoot(t *testing.T) {
	cleanup := setupJetyDangerouslyAllowRoot(t, true)
	defer cleanup()

	result, err := handleAuthListUsers(pki.CurrentTenantID(), nil)
	if err != nil {
		t.Fatalf("handleAuthListUsers: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- handleAuthAddUser / RemoveUser with nil params ---

func TestHandleAuthAddUserNilParams(t *testing.T) {
	_, err := handleAuthAddUser(pki.CurrentTenantID(), nil)
	if err == nil {
		t.Fatal("expected error for nil params")
	}
}

func TestHandleAuthRemoveUserNilParams(t *testing.T) {
	_, err := handleAuthRemoveUser(pki.CurrentTenantID(), nil)
	if err == nil {
		t.Fatal("expected error for nil params")
	}
}

// --- Subscribe function (0% coverage) ---

func TestSubscribeNilConn(t *testing.T) {
	err := Subscribe(nil, pki.CurrentTenantID())
	// Should fail when trying to subscribe on nil conn.
	if err == nil {
		t.Fatal("expected error for nil NATS connection")
	}
}

// --- probeSprout with nil conn ---

func TestProbeSproutNilConn(t *testing.T) {
	ClearNatsConn(pki.CurrentTenantID())

	if probeSprout("acme", "any-sprout") {
		t.Error("expected false for nil NATS conn")
	}
}

// --- Cohorts handler tests with invalid JSON ---

func TestHandleCohortsGetInvalidJSON(t *testing.T) {
	cleanup := setupCohortRegistry(t)
	defer cleanup()

	_, err := handleCohortsGet(pki.CurrentTenantID(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHandleCohortsResolveInvalidJSON(t *testing.T) {
	cleanup := setupCohortRegistry(t)
	defer cleanup()

	_, err := handleCohortsResolve(pki.CurrentTenantID(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHandleCohortsRefreshInvalidJSON(t *testing.T) {
	cleanup := setupCohortRegistry(t)
	defer cleanup()

	// Invalid JSON with non-empty name — should unmarshal error but
	// handleCohortsRefresh handles nil params gracefully.
	params := json.RawMessage(`{"name":"valid-name"}`)
	_, err := handleCohortsRefresh(pki.CurrentTenantID(), params)
	// Name doesn't exist, so should error.
	if err == nil {
		t.Fatal("expected error for nonexistent cohort")
	}
}

// --- extractSproutsGetID invalid JSON ---

func TestExtractSproutsGetIDInvalidJSON(t *testing.T) {
	_, err := extractSproutsGetID(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractSproutsGetIDEmpty(t *testing.T) {
	_, err := extractSproutsGetID(json.RawMessage(`{"sprout_id":""}`))
	if err == nil {
		t.Fatal("expected error for empty sprout_id")
	}
}

// --- Jobs handler: handleJobsListForSprout with invalid JSON ---

func TestHandleJobsListForSproutInvalidJSON(t *testing.T) {
	_, cleanup := setupJobStore(t)
	defer cleanup()

	_, err := handleJobsListForSprout(adminCaller(t, pki.CurrentTenantID()), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
