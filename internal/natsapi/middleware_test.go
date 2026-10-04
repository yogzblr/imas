package natsapi

import (
	"encoding/json"
	"testing"

	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

func TestNATSMethodAction(t *testing.T) {
	tests := []struct {
		method string
		want   rbac.Action
	}{
		{"version", rbac.ActionView},
		{"sprouts.list", rbac.ActionView},
		{"sprouts.get", rbac.ActionView},
		{"cook", rbac.ActionCook},
		{"cmd.run", rbac.ActionCmd},
		{"test.ping", rbac.ActionTest},
		{"pki.accept", rbac.ActionPKI},
		{"pki.list", rbac.ActionPKI},
		{"props.set", rbac.ActionProps},
		{"props.delete", rbac.ActionProps},
		{"jobs.cancel", rbac.ActionJobAdmin},
		{"auth.whoami", rbac.ActionUserRead},
		{"auth.users", rbac.ActionAdmin},
		{"unknown.method", rbac.ActionAdmin},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := NATSMethodAction(tt.method)
			if got != tt.want {
				t.Errorf("NATSMethodAction(%q) = %q, want %q", tt.method, got, tt.want)
			}
		})
	}
}

// The self methods are about the caller themselves: any user whose
// request opened may call them. Nothing that acts on sprouts, keys or
// other users is among them.
func TestSelfMethods(t *testing.T) {
	want := map[string]bool{
		MethodHealth: true, MethodVersion: true, MethodAuthLogin: true,
		MethodAuthWhoAmI: true, MethodAuthExplain: true, MethodAuthRotateKey: true,
	}
	if len(selfMethods) != len(want) {
		t.Errorf("selfMethods = %v", selfMethods)
	}
	for m := range want {
		if !selfMethods[m] {
			t.Errorf("%s is not a self method", m)
		}
	}
	for _, m := range []string{MethodCook, MethodPKIAccept, MethodAuthAddUser, MethodAuthResetKey, MethodAuthListUsers} {
		if selfMethods[m] {
			t.Errorf("%s must not be a self method", m)
		}
	}
}

// authorize looks the role up by the verified caller, never by anything
// in params: a request whose params name an admin, or carry a token,
// gets the caller's own access and no more.
func TestAuthorize(t *testing.T) {
	setupNatsAPIPKI(t)
	defer setupJetyDangerouslyAllowRoot(t, false)()
	rs := rbac.NewRoleStore()
	for _, r := range []*rbac.Role{
		{Name: "admin", Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}}},
		{Name: "viewer", Rules: []rbac.Rule{{Action: rbac.ActionView, Scope: "*"}}},
		{Name: "web", Rules: []rbac.Rule{{Action: rbac.ActionCook, Scope: "sprout:web-1"}}},
	} {
		if err := rs.Register(r); err != nil {
			t.Fatal(err)
		}
	}
	urm := rbac.NewUserRoleMap()
	urm.Set("UADMIN", "admin")
	urm.Set("UVIEWER", "viewer")
	urm.Set("UWEB", "web")
	intauth.SetPolicy(rs, urm, nil)
	defer intauth.SetPolicy(nil, nil, nil)

	tenant := pki.CurrentTenantID()
	cookOn := func(sprout string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"token": "UADMIN", "user": "UADMIN", "target": []map[string]string{{"sprout_id": sprout}}})
		return b
	}
	for _, tc := range []struct {
		name, method, user string
		params             json.RawMessage
		want               error
	}{
		{"admin, admin method", MethodAuditDates, "UADMIN", nil, nil},
		{"viewer, admin method", MethodAuditDates, "UVIEWER", nil, rbac.ErrAccessDenied},
		{"viewer, admin method, params naming the admin", MethodAuthAddUser, "UVIEWER", json.RawMessage(`{"token":"UADMIN","pubkey":"UADMIN"}`), rbac.ErrAccessDenied},
		{"viewer, read", MethodJobsGet, "UVIEWER", nil, nil},
		{"unknown user", MethodJobsGet, "UNOBODY", nil, rbac.ErrAccessDenied},
		{"unknown user, self method", MethodAuthWhoAmI, "UNOBODY", nil, nil},
		{"scoped cook, granted sprout", MethodCook, "UWEB", cookOn("web-1"), nil},
		{"scoped cook, other sprout", MethodCook, "UWEB", cookOn("db-1"), rbac.ErrAccessDenied},
		{"method not granted", MethodCmdRun, "UWEB", cookOn("web-1"), rbac.ErrAccessDenied},
		{"cook trigger needs cook", MethodCookTriggerPrefix + "j1", "UVIEWER", nil, rbac.ErrAccessDenied},
		{"cook trigger", MethodCookTriggerPrefix + "j1", "UWEB", nil, nil},
		{"key reset is admin", MethodAuthResetKey, "UWEB", nil, rbac.ErrAccessDenied},
	} {
		err := authorize(tc.method, apiCaller{TenantID: tenant, UserID: tc.user}, tc.params)
		if err != tc.want {
			t.Errorf("%s: authorize = %v, want %v", tc.name, err, tc.want)
		}
	}

	// Targets that can't be read are refused, not handed to the handler.
	if err := authorize(MethodCook, apiCaller{TenantID: tenant, UserID: "UADMIN"}, json.RawMessage(`{"target":"not-an-array"}`)); err == nil {
		t.Error("unreadable targets were authorized")
	}
}

// dangerously_allow_root bypasses nothing on the NATS path (owner
// decision 2026-10-04, PR #95: "remove dangerously_allow_root bypass from
// the NATS path"): with it set, a registered user whose role lacks the
// action is still refused, and a scoped role is still held to its scope.
func TestAuthorize_DangerouslyAllowRootBypassesNothing(t *testing.T) {
	setupNatsAPIPKI(t)
	defer setupJetyDangerouslyAllowRoot(t, true)()
	if !intauth.DangerouslyAllowRoot() {
		t.Fatal("control: the flag isn't set")
	}
	rs := rbac.NewRoleStore()
	for _, r := range []*rbac.Role{
		{Name: "viewer", Rules: []rbac.Rule{{Action: rbac.ActionView, Scope: "*"}}},
		{Name: "web", Rules: []rbac.Rule{{Action: rbac.ActionCmd, Scope: "sprout:web-1"}}},
	} {
		if err := rs.Register(r); err != nil {
			t.Fatal(err)
		}
	}
	urm := rbac.NewUserRoleMap()
	urm.Set("UVIEWER", "viewer")
	urm.Set("UWEB", "web")
	intauth.SetPolicy(rs, urm, nil)
	defer intauth.SetPolicy(nil, nil, nil)

	tenant := pki.CurrentTenantID()
	on := func(sprout string) json.RawMessage {
		return json.RawMessage(`{"target":[{"sprout_id":"` + sprout + `"}]}`)
	}
	for _, tc := range []struct {
		name, method, user string
		params             json.RawMessage
		want               error
	}{
		{"registered user without the action", MethodCmdRun, "UVIEWER", on("web-1"), rbac.ErrAccessDenied},
		{"registered user, admin method", MethodAuthAddUser, "UVIEWER", nil, rbac.ErrAccessDenied},
		{"unknown user", MethodJobsGet, "UNOBODY", nil, rbac.ErrAccessDenied},
		{"scoped role, outside its scope", MethodCmdRun, "UWEB", on("db-1"), rbac.ErrAccessDenied},
		{"scoped role, inside its scope", MethodCmdRun, "UWEB", on("web-1"), nil},
	} {
		if err := authorize(tc.method, apiCaller{TenantID: tenant, UserID: tc.user}, tc.params); err != tc.want {
			t.Errorf("%s: authorize = %v, want %v", tc.name, err, tc.want)
		}
	}
	if err := authorize(MethodCmdRun, apiCaller{TenantID: tenant, UserID: "UWEB"}, json.RawMessage(`{"target":[]}`)); err == nil {
		t.Error("an empty target list was authorized")
	}
	if got := filterSproutsByScope(tenant, "UWEB", rbac.ActionCmd, []string{"web-1", "db-1"}); len(got) != 1 || got[0] != "web-1" {
		t.Errorf("scope filter under the flag = %v, want [web-1]", got)
	}
}

func TestViewerRoleNATSAccess(t *testing.T) {
	viewer := rbac.BuiltinViewerRole()

	// Read-only NATS methods the viewer should access
	allowedMethods := []string{
		"version", "sprouts.list", "sprouts.get",
		"jobs.list", "jobs.get", "jobs.forsprout",
		"props.getall", "props.get",
		"cohorts.list", "cohorts.get", "cohorts.resolve", "cohorts.refresh",
		"auth.whoami", "auth.explain",
	}
	for _, method := range allowedMethods {
		action := NATSMethodAction(method)
		if !viewer.HasAction(action) {
			t.Errorf("viewer should be able to call %q (requires %q)", method, action)
		}
	}

	// Write NATS methods the viewer should be denied
	deniedMethods := []string{
		"cook", "cook.resync", "cmd.run", "shell.start", "test.ping",
		"props.set", "props.delete",
		"jobs.cancel",
		"pki.list", "pki.accept", "pki.reject", "pki.deny", "pki.unaccept", "pki.delete",
		"auth.users", "auth.users.add", "auth.users.remove",
		"audit.dates", "audit.query",
	}
	for _, method := range deniedMethods {
		action := NATSMethodAction(method)
		if viewer.HasAction(action) {
			t.Errorf("viewer should NOT be able to call %q (requires %q)", method, action)
		}
	}
}

func TestOperatorRoleNATSAccess(t *testing.T) {
	op := rbac.BuiltinOperatorRole()

	// Methods the operator should access
	allowedMethods := []string{
		"version", "sprouts.list", "sprouts.get",
		"jobs.list", "jobs.get", "jobs.forsprout", "jobs.cancel",
		"props.getall", "props.get", "props.set", "props.delete",
		"cohorts.list", "cohorts.get", "cohorts.resolve", "cohorts.refresh",
		"cook", "cook.resync", "cmd.run", "shell.start", "test.ping",
		"auth.whoami", "auth.explain",
	}
	for _, method := range allowedMethods {
		action := NATSMethodAction(method)
		if !op.HasAction(action) {
			t.Errorf("operator should be able to call %q (requires %q)", method, action)
		}
	}

	// Methods the operator should be denied (PKI + user management + audit)
	deniedMethods := []string{
		"pki.list", "pki.accept", "pki.reject", "pki.deny", "pki.unaccept", "pki.delete",
		"auth.users", "auth.users.add", "auth.users.remove",
		"audit.dates", "audit.query",
	}
	for _, method := range deniedMethods {
		action := NATSMethodAction(method)
		if op.HasAction(action) {
			t.Errorf("operator should NOT be able to call %q (requires %q)", method, action)
		}
	}
}

func TestAllRoutesHaveActionMapping(t *testing.T) {
	// Every route in the router should have an entry in natsActionMap.
	for method := range apiRoutes() {
		if _, ok := natsActionMap[method]; !ok {
			t.Errorf("route %q has no entry in natsActionMap (will default to admin)", method)
		}
	}
}

// No method is both a tenant-only route and a user route.
func TestRouteTablesDisjoint(t *testing.T) {
	for m := range userRoutes {
		if _, ok := routes[m]; ok {
			t.Errorf("%s is in both route tables", m)
		}
	}
	if len(apiRoutes()) != len(routes)+len(userRoutes) {
		t.Error("apiRoutes lost a method")
	}
}
