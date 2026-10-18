package controlplane

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidJobID(t *testing.T) {
	valid := []string{"pj_abc123", "PJ-9", "a", strings.Repeat("x", 36)}
	for _, id := range valid {
		if !ValidJobID(id) {
			t.Errorf("ValidJobID(%q) = false, want true", id)
		}
	}
	invalid := []string{"", "pj.abc", "pj_*", "pj_>", "pj abc", "pj\tabc", "pj_é", strings.Repeat("x", 37)}
	for _, id := range invalid {
		if ValidJobID(id) {
			t.Errorf("ValidJobID(%q) = true, want false", id)
		}
	}
}

func TestResultSubjectsRoundTrip(t *testing.T) {
	if got := ProvisionedSubject("pj_1"); got != "internal.tenant.provisioned.pj_1" {
		t.Fatalf("ProvisionedSubject = %q", got)
	}
	if got := DeprovisionedSubject("pj_1"); got != "internal.tenant.deprovisioned.pj_1" {
		t.Fatalf("DeprovisionedSubject = %q", got)
	}
	id, ok := JobIDFromSubject(ProvisionedSubject("pj_1"), SubjectTenantProvisionedPrefix)
	if !ok || id != "pj_1" {
		t.Fatalf("JobIDFromSubject = %q, %v", id, ok)
	}
	// A deprovision result must not parse as a provision result.
	if _, ok := JobIDFromSubject(DeprovisionedSubject("pj_1"), SubjectTenantProvisionedPrefix); ok {
		t.Fatal("expected a deprovisioned subject not to match the provisioned prefix")
	}
	if _, ok := JobIDFromSubject(SubjectTenantProvisionedPrefix+"a.b", SubjectTenantProvisionedPrefix); ok {
		t.Fatal("expected a multi-token suffix to be rejected")
	}
}

func TestPublicErrorMessage(t *testing.T) {
	for _, code := range []ErrorCode{ErrorInvalidTenantID, ErrorTenantNotFound, ErrorInternal} {
		if PublicErrorMessage(code) == "" {
			t.Errorf("no public message for %q", code)
		}
	}
	// Anything unrecognized — including text that looks like a leaked
	// error — maps to the generic message, never echoed back.
	leaked := ErrorCode("mkdir /etc/imas/pki/nats-auth/tenants: not a directory")
	if got := PublicErrorMessage(leaked); got != PublicErrorMessage(ErrorInternal) {
		t.Fatalf("PublicErrorMessage(unknown) = %q, want the internal-error message", got)
	}
	if got := PublicErrorMessage(""); got != PublicErrorMessage(ErrorInternal) {
		t.Fatalf("PublicErrorMessage(\"\") = %q", got)
	}
}

func TestPublicWarningMessage(t *testing.T) {
	if PublicWarningMessage("") != "" {
		t.Fatal("expected no message for no warning")
	}
	if PublicWarningMessage(WarningTenantNotProvisioned) == "" {
		t.Fatal("no public message for WarningTenantNotProvisioned")
	}
	leaked := WarningCode("stat /etc/imas/pki/nats-auth/tenants/t_1: no such file")
	if got := PublicWarningMessage(leaked); got == "" || got == string(leaked) {
		t.Fatalf("PublicWarningMessage(unknown) = %q, want a generic message", got)
	}
}

func TestValidSaaSAPIReplySubject(t *testing.T) {
	valid := []string{
		"_INBOX.saasapi.abc",
		"_INBOX.saasapi.Ab12CdEf.9", // nats.go's respmux form: prefix.<nuid>.<token>
		"_INBOX.saasapi.x-y_z.deeper.ok",
	}
	for _, s := range valid {
		if !ValidSaaSAPIReplySubject(s) {
			t.Errorf("ValidSaaSAPIReplySubject(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"",
		"_INBOX.saasapi",                        // the prefix alone
		"_INBOX.saasapi.",                       // empty token
		"_INBOX.saasapi..x",                     // empty token
		"_INBOX.saasapix.abc",                   // not a token boundary
		"_INBOX.abc",                            // another user's inbox
		"_INBOX.abc.saasapi.x",                  // prefix not at the start
		"_INBOX.saasapi.*",                      // wildcard
		"_INBOX.saasapi.>",                      // wildcard
		"_INBOX.saasapi.a>",                     // wildcard char inside a token
		"_INBOX.saasapi.a b",                    // whitespace
		"_INBOX.saasapi.a\tb",                   // whitespace
		"$SYS.REQ.CLAIMS.UPDATE",                // server administration
		"internal.tenant.provisioned.pj_forged", // a forged result
		"imas.api.cmd.run",
		"_INBOX.saasapi." + strings.Repeat("x", 250), // over-long
	}
	for _, s := range invalid {
		if ValidSaaSAPIReplySubject(s) {
			t.Errorf("ValidSaaSAPIReplySubject(%q) = true, want false", s)
		}
	}
}

func TestSaaSAPIInboxWildcardCoversOnlyThePrefix(t *testing.T) {
	if SaaSAPIInboxWildcard != "_INBOX.saasapi.>" {
		t.Fatalf("SaaSAPIInboxWildcard = %q; widening this is a security-review change", SaaSAPIInboxWildcard)
	}
}

func TestPublicErrorMessage_SproutActionCodesHaveFixedMessages(t *testing.T) {
	for _, code := range []ErrorCode{ErrorInvalidRequest, ErrorUnsupportedAction, ErrorSproutNotFound, ErrorSproutUnreachable} {
		if PublicErrorMessage(code) == PublicErrorMessage(ErrorInternal) {
			t.Errorf("code %q has no message of its own", code)
		}
	}
}

// The internal.sprout.action codes the SaaS API keeps verbatim
// (internal/saasapi, replyUpdate and farmerErrorCode) and farmer sends
// (internal/natsapi). Changing one is a wire change on both sides.
func TestSproutActionErrorCodeValues(t *testing.T) {
	for code, want := range map[ErrorCode]string{
		ErrorSelfUpdateDisabled:     "self_update_disabled",
		ErrorRolloutWindowClosed:    "rollout_window_closed",
		ErrorFarmerBusy:             "farmer_busy",
		ErrorSproutReenrollRequired: "sprout_reenroll_required",
	} {
		if string(code) != want {
			t.Errorf("%s, want %s", code, want)
		}
	}
}

// TestDecodeSelfUpdateParams: exactly {"version": ...}. A caller still
// sending the pre-FU.7 artifact_url, checksum_sha256 or signature is
// refused rather than having them dropped.
func TestDecodeSelfUpdateParams(t *testing.T) {
	if p, err := DecodeSelfUpdateParams([]byte(`{"version":"v2.4.1"}`)); err != nil || p.Version != "v2.4.1" {
		t.Fatalf("valid params: %+v, %v", p, err)
	}
	for _, raw := range []string{
		`{"version":"v2.4.1","artifact_url":""}`,
		`{"version":"v2.4.1","checksum_sha256":"","signature":""}`,
		`{"version":"v2.4.1","Version2":"x"}`,
		`{"version":2}`,
		`{"version":"v2.4.1"} {}`,
		`{"version":"v2.4.1"}x`,
		`["v2.4.1"]`,
		``,
	} {
		if p, err := DecodeSelfUpdateParams([]byte(raw)); !errors.Is(err, ErrSelfUpdateParams) {
			t.Errorf("DecodeSelfUpdateParams(%s) = %+v, %v; want ErrSelfUpdateParams", raw, p, err)
		}
	}
	b, _ := json.Marshal(SelfUpdateParams{Version: "v2.4.1"})
	if string(b) != `{"version":"v2.4.1"}` {
		t.Errorf("encodes as %s", b)
	}
}

func TestTenantJobSubjects(t *testing.T) {
	for _, c := range []struct {
		job             TenantJob
		request, result string
	}{
		{TenantJobProvision, "internal.tenant.provision", "internal.tenant.provisioned.pj_1"},
		{TenantJobDeprovision, "internal.tenant.deprovision", "internal.tenant.deprovisioned.pj_1"},
		{TenantJobPurge, "internal.tenant.purge", "internal.tenant.purged.pj_1"},
	} {
		if got := c.job.RequestSubject(); got != c.request {
			t.Errorf("%s request subject %q, want %q", c.job, got, c.request)
		}
		if got := c.job.ResultSubject("pj_1"); got != c.result {
			t.Errorf("%s result subject %q, want %q", c.job, got, c.result)
		}
	}
	if TenantJob("rename").RequestSubject() != "" || TenantJob("rename").ResultPrefix() != "" {
		t.Error("an unknown tenant job has subjects")
	}
	if PurgedSubject("pj_1") != TenantJobPurge.ResultSubject("pj_1") || SubjectTenantPurgedWildcard != "internal.tenant.purged.*" {
		t.Error("purged subject helpers disagree")
	}
	if id, ok := JobIDFromSubject("internal.tenant.purged.pj_9", SubjectTenantPurgedPrefix); !ok || id != "pj_9" {
		t.Errorf("JobIDFromSubject on a purged subject: %q %v", id, ok)
	}
}

func TestPurgeValidators(t *testing.T) {
	for _, tr := range []string{PurgeTriggerRetention, PurgeTriggerOperator} {
		if !ValidPurgeTrigger(tr) {
			t.Errorf("trigger %q refused", tr)
		}
	}
	for _, tr := range []string{"", "Retention", "manual"} {
		if ValidPurgeTrigger(tr) {
			t.Errorf("trigger %q accepted", tr)
		}
	}
	for _, s := range PurgeSteps {
		if !ValidPurgeStep(s) {
			t.Errorf("step %q refused", s)
		}
	}
	if ValidPurgeStep("bucket") || ValidPurgeStep("") {
		t.Error("an unknown step accepted")
	}
	for _, c := range []string{"db.props", "objects.sprout_jwts", "valkey.heartbeat", "transit.keys"} {
		if !ValidPurgeCategory(c) {
			t.Errorf("category %q refused", c)
		}
	}
	for _, c := range []string{"", "db.Props", "tenants/t_1/recipes/x", "a b", "db-props", string(make([]byte, 65))} {
		if ValidPurgeCategory(c) {
			t.Errorf("category %q accepted", c)
		}
	}
	for _, code := range []ErrorCode{ErrorPurgeRefused, ErrorPurgeIncomplete} {
		if PublicErrorMessage(code) == PublicErrorMessage(ErrorInternal) {
			t.Errorf("%s has no public message of its own", code)
		}
	}
}

// A cmd.run's output never crosses internal.sprout.action (security review
// 2026-10, L9): the result carries only the exit code and duration, so a
// field added for output fails here before it reaches the unsealed bus.
func TestCmdRunResultCarriesNoOutput(t *testing.T) {
	typ := reflect.TypeOf(CmdRunResult{})
	var got []string
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	if want := []string{"ExitCode", "Duration"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CmdRunResult fields %v, want %v", got, want)
	}
}
