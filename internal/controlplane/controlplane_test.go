package controlplane

import (
	"encoding/json"
	"errors"
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
