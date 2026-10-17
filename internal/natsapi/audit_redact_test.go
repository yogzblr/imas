package natsapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/audit"
	"github.com/yogzblr/imas/internal/shell"
)

// auditSecrets is a fixture holding a password, an X-Api-Key, an NATS
// seed and a JWT; none of them may reach the audit writer.
type auditSecrets struct {
	password, apiKey, seed, jwt string
}

// newAuditSecrets is the fixture, with a fresh NATS seed.
func newAuditSecrets(t *testing.T) auditSecrets {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return auditSecrets{
		password: "hunter2-pw-fixture",
		apiKey:   "apikey-fixture-0042",
		seed:     string(seed),
		jwt:      "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJzdWIiOiJVRklYVFVSRSJ9.Zml4dHVyZS1zaWduYXR1cmU",
	}
}

// text is the fixture as one free-text string.
func (s auditSecrets) text() string {
	return "mysql --password=" + s.password + "; curl -H 'X-Api-Key: " + s.apiKey + "' -d " + s.seed + " -H 'x: " + s.jwt + "'"
}

// params is the fixture as a params object: secret keys and secret text.
func (s auditSecrets) params(t *testing.T, extra map[string]any) json.RawMessage {
	t.Helper()
	m := map[string]any{"sprout_id": "web-1", "password": s.password, "X-Api-Key": s.apiKey,
		"nested": []any{map[string]any{"note": s.text()}}}
	for k, v := range extra {
		m[k] = v
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// assertAbsent fails t if written is empty or holds any of the secrets.
func (s auditSecrets) assertAbsent(t *testing.T, written string) {
	t.Helper()
	if written == "" {
		t.Fatal("nothing audited")
	}
	for name, v := range map[string]string{"password": s.password, "X-Api-Key": s.apiKey, "seed": s.seed, "jwt": s.jwt} {
		if strings.Contains(written, v) {
			t.Errorf("the %s reached the audit writer: %s", name, written)
		}
	}
}

// withAuditBuffer sets a global audit logger writing to a new buffer for
// the test.
func withAuditBuffer(t *testing.T) *auditBuffer {
	t.Helper()
	buf := &auditBuffer{}
	audit.SetGlobal(audit.NewLogger(buf))
	t.Cleanup(func() { audit.SetGlobal(nil) })
	return buf
}

// auditCall, for an ordinary write, a free-form write and a failed call
// whose error quotes the secrets.
func TestAuditCallRedacts(t *testing.T) {
	s := newAuditSecrets(t)
	caller := apiCaller{TenantID: "t_1", UserID: "UAUDITREDACTFIXTURE"}
	for _, method := range []string{MethodPKIAccept, MethodPropsSet, MethodCmdRun, MethodCook, MethodShellOpen, MethodAuthAddUser} {
		t.Run(method, func(t *testing.T) {
			buf := withAuditBuffer(t)
			auditCall(caller, method, s.params(t, nil), nil, errors.New("failed: "+s.text()))
			s.assertAbsent(t, buf.String())
			var e audit.Entry
			if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &e); err != nil {
				t.Fatal(err)
			}
			if e.Action != method || e.Pubkey != caller.UserID || e.Success {
				t.Errorf("entry %+v", e)
			}
			var p map[string]any
			if err := json.Unmarshal(e.Parameters, &p); err != nil {
				t.Fatalf("params %s: %v", e.Parameters, err)
			}
			if audit.IsFreeForm(method) {
				if p["redacted"] != "free-form" {
					t.Errorf("params = %s, want the free-form shape", e.Parameters)
				}
			} else if p["sprout_id"] != "web-1" || p["password"] != audit.Redacted {
				t.Errorf("params = %s, want masked", e.Parameters)
			}
		})
	}
}

// auditCall passes params that are not JSON to the logger, which logs
// their shape only.
func TestAuditCallUnparseable(t *testing.T) {
	s := newAuditSecrets(t)
	buf := withAuditBuffer(t)
	auditCall(apiCaller{TenantID: "t_1", UserID: "UAUDITREDACTFIXTURE"}, MethodPKIAccept, json.RawMessage(s.text()), nil, nil)
	s.assertAbsent(t, buf.String())
	if !strings.Contains(buf.String(), `"redacted":"unparseable"`) {
		t.Errorf("line %s, want the unparseable shape", buf.String())
	}
}

// The shell writer: a shell path carrying the secrets is masked in
// shell.start.
func TestShellAuditRedacts(t *testing.T) {
	s := newAuditSecrets(t)
	buf := withAuditBuffer(t)
	fs := &farmerShell{
		key:  shell.SessionKey{TenantID: "t_1", SessionID: "sess-1"},
		info: &shell.SessionInfo{TenantID: "t_1", SessionID: "sess-1", SproutID: "web-1", Pubkey: "UALICE", RoleName: "admin", Shell: s.text()},
	}
	fs.auditStart(false, "start_failed")
	s.assertAbsent(t, buf.String())
	if !strings.Contains(buf.String(), `"action":"shell.start"`) || !strings.Contains(buf.String(), `"sprout_id":"web-1"`) {
		t.Errorf("line %s", buf.String())
	}
}

// LogAction, as tenant provisioning calls it.
func TestTenantAuditRedacts(t *testing.T) {
	s := newAuditSecrets(t)
	buf := withAuditBuffer(t)
	auditTenantAction(auditActionTenantProvision, s.params(t, map[string]any{"tenant_id": "t_9", "token": s.jwt}), nil, errors.New(s.text()))
	s.assertAbsent(t, buf.String())
	if !strings.Contains(buf.String(), `"tenant_id":"t_9"`) {
		t.Errorf("line %s, want tenant_id kept", buf.String())
	}
}
