package harness

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

func TestTokens(t *testing.T) {
	f, _ := fakeFleet(t)
	c := ctx(t)
	a, err := f.Tokens.Tenant(c, 1, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := f.Tokens.Tenant(c, 1, RoleAdmin)
	if a != again {
		t.Error("a cached token should be reused")
	}
	fresh, err := f.Tokens.Fresh(c, 1, RoleAdmin)
	if err != nil || fresh == "" {
		t.Errorf("fresh %v", err)
	}
	claims, err := DecodeClaims(a)
	if err != nil {
		t.Fatal(err)
	}
	org, _ := claims["organization"].(map[string]any)
	if org["id"] != f.TenantID(1) {
		t.Errorf("organization %v", org)
	}
	if !f.Tokens.HasUser(2, RoleReadOnly) || f.Tokens.HasUser(3, RoleAdmin) {
		t.Error("HasUser")
	}
	other, ok, err := f.Tokens.OtherAudience(c, 1)
	if !ok || err != nil {
		t.Fatalf("other audience %v %v", ok, err)
	}
	if oc, _ := DecodeClaims(other); oc["aud"] == fakestack.Audience {
		t.Error("the other client's token carries saasapi's audience")
	}
}

func TestScratchUser(t *testing.T) {
	f, _ := fakeFleet(t)
	c := ctx(t)
	u, err := f.Tokens.ScratchUser(c, "t_cccccccccccccccc", "imas-recipes-read")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := u.Token(c)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := DecodeClaims(tok)
	if org, _ := claims["organization"].(map[string]any); org["id"] != "t_cccccccccccccccc" {
		t.Errorf("scratch token organization %v", claims["organization"])
	}
	if err := u.Delete(c); err != nil {
		t.Error(err)
	}
	if err := u.Delete(c); err != nil {
		t.Errorf("deleting twice should be fine (404): %v", err)
	}

	f.Tokens.cfg.Admin = nil
	if _, err := f.Tokens.ScratchUser(c, "t_x"); !errors.Is(err, ErrNoKeycloakAdmin) {
		t.Errorf("no admin: %v", err)
	}
	f.Tokens.cfg.Admin = &KeycloakAdmin{ClientID: "admin-cli", Username: "kcadmin", Password: "kcadmin-password"}
	f.Tokens.cfg.TenantAttribute = ""
	if _, err := f.Tokens.ScratchUser(c, "t_x"); err == nil || !strings.Contains(err.Error(), "tenant_attribute") {
		t.Errorf("no tenant attribute: %v", err)
	}
	f.Tokens.cfg.OtherAudienceClient = nil
	if _, ok, _ := f.Tokens.OtherAudience(c, 1); ok {
		t.Error("no other client configured, but ok")
	}
}

func TestTokenErrorsKeepSecretsOut(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`)
	}))
	defer srv.Close()
	k, err := NewTokens(KeycloakConfig{
		Issuer: srv.URL + "/realms/r", ClientID: "c", ClientSecret: "client-secret-value",
		Tenants: map[string]KeycloakTenant{"1": {Admin: Credentials{Username: "u", Password: "password-value"}}},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Tenant(ctx(t), 1, RoleAdmin)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("want Keycloak's error code, got %v", err)
	}
	for _, secret := range []string{"password-value", "client-secret-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error carries a secret: %v", err)
		}
	}
	if _, err := k.Tenant(ctx(t), 1, RoleReadOnly); err == nil {
		t.Error("no read only user configured, but a token came back")
	}
}
