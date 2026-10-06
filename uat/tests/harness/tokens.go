package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Role is which of a tenant's configured users a token is for.
type Role string

// Roles of keycloak.json's tenant users.
const (
	// RoleAdmin holds imas-recipes-read and imas-recipes-write.
	RoleAdmin Role = "admin"
	// RoleReadOnly holds imas-recipes-read only.
	RoleReadOnly Role = "readonly"
)

// ErrNoKeycloakAdmin is returned by ScratchUser when keycloak.json has no
// admin identity.
var ErrNoKeycloakAdmin = errors.New("keycloak.json has no admin identity, so no user can be made for a tenant created during the run")

// Tokens gets Keycloak access tokens. Tokens are cached per user and
// client until 30 seconds before they expire. Safe for concurrent use.
type Tokens struct {
	cfg  KeycloakConfig
	http *http.Client
	base string
	// realm is the test realm, from the issuer.
	realm string
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	token string
	exp   time.Time
}

// NewTokens returns a Tokens for cfg.
func NewTokens(cfg KeycloakConfig, hc *http.Client) (*Tokens, error) {
	base, realm, err := splitIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return &Tokens{cfg: cfg, http: hc, base: base, realm: realm, now: time.Now, cache: map[string]cachedToken{}}, nil
}

// TenantUser returns the configured user of a tenant and role.
func (k *Tokens) TenantUser(tenant int, role Role) (Credentials, error) {
	t, ok := k.cfg.Tenants[strconv.Itoa(tenant)]
	if !ok {
		return Credentials{}, fmt.Errorf("keycloak.json has no tenant %d", tenant)
	}
	c := t.Admin
	if role == RoleReadOnly {
		c = t.ReadOnly
	}
	if !c.set() {
		return Credentials{}, fmt.Errorf("keycloak.json tenants.%d.%s has no username and password", tenant, role)
	}
	return c, nil
}

// HasUser reports whether the tenant has a user for the role.
func (k *Tokens) HasUser(tenant int, role Role) bool {
	_, err := k.TenantUser(tenant, role)
	return err == nil
}

// Tenant returns a token for a tenant's configured user.
func (k *Tokens) Tenant(ctx context.Context, tenant int, role Role) (string, error) {
	c, err := k.TenantUser(tenant, role)
	if err != nil {
		return "", err
	}
	return k.Password(ctx, ClientCreds{ClientID: k.cfg.ClientID, ClientSecret: k.cfg.ClientSecret}, c)
}

// Fresh returns a new token for a tenant's user, bypassing the cache.
func (k *Tokens) Fresh(ctx context.Context, tenant int, role Role) (string, error) {
	c, err := k.TenantUser(tenant, role)
	if err != nil {
		return "", err
	}
	tok, _, err := k.grant(ctx, k.tokenURL(k.realm), passwordForm(ClientCreds{ClientID: k.cfg.ClientID, ClientSecret: k.cfg.ClientSecret}, c))
	return tok, err
}

// OtherAudience returns a token for a tenant's admin user from
// keycloak.json's other_audience_client, whose tokens don't carry
// saasapi's audience. ok is false when no such client is configured.
func (k *Tokens) OtherAudience(ctx context.Context, tenant int) (tok string, ok bool, err error) {
	if k.cfg.OtherAudienceClient == nil || k.cfg.OtherAudienceClient.ClientID == "" {
		return "", false, nil
	}
	c, err := k.TenantUser(tenant, RoleAdmin)
	if err != nil {
		return "", true, err
	}
	tok, err = k.Password(ctx, *k.cfg.OtherAudienceClient, c)
	return tok, true, err
}

// Password returns a token for a user from a client of the test realm
// (password grant), cached.
func (k *Tokens) Password(ctx context.Context, client ClientCreds, user Credentials) (string, error) {
	key := client.ClientID + "\x00" + user.Username
	k.mu.Lock()
	if c, ok := k.cache[key]; ok && k.now().Add(30*time.Second).Before(c.exp) {
		k.mu.Unlock()
		return c.token, nil
	}
	k.mu.Unlock()
	tok, exp, err := k.grant(ctx, k.tokenURL(k.realm), passwordForm(client, user))
	if err != nil {
		return "", fmt.Errorf("token for %s from client %s: %w", user.Username, client.ClientID, err)
	}
	k.mu.Lock()
	k.cache[key] = cachedToken{token: tok, exp: exp}
	k.mu.Unlock()
	return tok, nil
}

func passwordForm(client ClientCreds, user Credentials) url.Values {
	f := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientID},
		"username":   {user.Username},
		"password":   {user.Password},
		"scope":      {"openid"},
	}
	if client.ClientSecret != "" {
		f.Set("client_secret", client.ClientSecret)
	}
	return f
}

func (k *Tokens) tokenURL(realm string) string {
	return k.base + "/realms/" + url.PathEscape(realm) + "/protocol/openid-connect/token"
}

// grant posts a token request and returns the access token and when it
// expires. Errors carry the status and Keycloak's error code only.
func (k *Tokens) grant(ctx context.Context, endpoint string, form url.Values) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("keycloak answered HTTP %d %s %s", resp.StatusCode, out.Error, out.Description)
	}
	exp := k.now().Add(time.Duration(out.ExpiresIn) * time.Second)
	if e, err := ExpiresAt(out.AccessToken); err == nil {
		exp = e
	}
	return out.AccessToken, exp, nil
}

// HasAdmin reports whether keycloak.json has an admin identity.
func (k *Tokens) HasAdmin() bool {
	a := k.cfg.Admin
	return a != nil && a.ClientID != "" && (a.ClientSecret != "" || (a.Username != "" && a.Password != ""))
}

func (k *Tokens) adminToken(ctx context.Context) (string, error) {
	if !k.HasAdmin() {
		return "", ErrNoKeycloakAdmin
	}
	a := k.cfg.Admin
	realm := a.Realm
	if realm == "" {
		realm = "master"
	}
	key := "\x00admin"
	k.mu.Lock()
	if c, ok := k.cache[key]; ok && k.now().Add(30*time.Second).Before(c.exp) {
		k.mu.Unlock()
		return c.token, nil
	}
	k.mu.Unlock()
	form := url.Values{"client_id": {a.ClientID}}
	if a.Username != "" {
		form.Set("grant_type", "password")
		form.Set("username", a.Username)
		form.Set("password", a.Password)
		if a.ClientSecret != "" {
			form.Set("client_secret", a.ClientSecret)
		}
	} else {
		form.Set("grant_type", "client_credentials")
		form.Set("client_secret", a.ClientSecret)
	}
	tok, exp, err := k.grant(ctx, k.tokenURL(realm), form)
	if err != nil {
		return "", fmt.Errorf("keycloak admin token: %w", err)
	}
	k.mu.Lock()
	k.cache[key] = cachedToken{token: tok, exp: exp}
	k.mu.Unlock()
	return tok, nil
}

// ScratchUser is a realm user made for one tenant during the run. Delete
// it when done.
type ScratchUser struct {
	ID       string
	TenantID string
	User     Credentials
	k        *Tokens
}

// Token returns a token for the scratch user.
func (u *ScratchUser) Token(ctx context.Context) (string, error) {
	return u.k.Password(ctx, ClientCreds{ClientID: u.k.cfg.ClientID, ClientSecret: u.k.cfg.ClientSecret}, u.User)
}

// Delete removes the user from the realm.
func (u *ScratchUser) Delete(ctx context.Context) error {
	tok, err := u.k.adminToken(ctx)
	if err != nil {
		return err
	}
	r, err := u.k.admin(ctx, tok, http.MethodDelete, "/users/"+url.PathEscape(u.ID), nil)
	if err != nil {
		return err
	}
	if r.Status != http.StatusNoContent && r.Status != http.StatusNotFound {
		return fmt.Errorf("deleting scratch user: %s", r)
	}
	return nil
}

// ScratchUser creates an enabled user in the test realm whose
// tenant_attribute is tenantID (so its tokens carry organization.id =
// tenantID, the way the realm maps it), with the given realm roles. It
// needs keycloak.json's admin identity and tenant_attribute.
func (k *Tokens) ScratchUser(ctx context.Context, tenantID string, realmRoles ...string) (*ScratchUser, error) {
	if !k.HasAdmin() {
		return nil, ErrNoKeycloakAdmin
	}
	if k.cfg.TenantAttribute == "" {
		return nil, errors.New("keycloak.json has no tenant_attribute, so a scratch user can't be mapped to a tenant")
	}
	tok, err := k.adminToken(ctx)
	if err != nil {
		return nil, err
	}
	name := "uat-scratch-" + randomLower(10)
	pw := randomLower(24) + "A1!"
	user := map[string]any{
		"username":        name,
		"enabled":         true,
		"email":           name + "@uat.invalid",
		"emailVerified":   true,
		"firstName":       "UAT",
		"lastName":        "Scratch",
		"requiredActions": []string{},
		"attributes":      map[string][]string{k.cfg.TenantAttribute: {tenantID}},
		"credentials":     []map[string]any{{"type": "password", "value": pw, "temporary": false}},
	}
	r, err := k.admin(ctx, tok, http.MethodPost, "/users", user)
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusCreated {
		return nil, fmt.Errorf("creating scratch user: %s", r)
	}
	loc := r.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if id == "" {
		return nil, errors.New("creating scratch user: no Location in Keycloak's answer")
	}
	u := &ScratchUser{ID: id, TenantID: tenantID, User: Credentials{Username: name, Password: pw}, k: k}
	if len(realmRoles) > 0 {
		var roles []json.RawMessage
		for _, role := range realmRoles {
			rr, err := k.admin(ctx, tok, http.MethodGet, "/roles/"+url.PathEscape(role), nil)
			if err != nil || rr.Status != http.StatusOK {
				_ = u.Delete(ctx)
				return nil, fmt.Errorf("reading realm role %s: %v %s", role, err, rr)
			}
			roles = append(roles, json.RawMessage(rr.Body))
		}
		rr, err := k.admin(ctx, tok, http.MethodPost, "/users/"+url.PathEscape(id)+"/role-mappings/realm", roles)
		if err != nil || rr.Status != http.StatusNoContent {
			_ = u.Delete(ctx)
			return nil, fmt.Errorf("granting realm roles: %v %s", err, rr)
		}
	}
	return u, nil
}

// admin calls the Keycloak admin REST API of the test realm.
func (k *Tokens) admin(ctx context.Context, token, method, path string, body any) (*Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+"/admin/realms/"+url.PathEscape(k.realm)+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak admin %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

const lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

// randomLower returns n random lowercase letters and digits, starting
// with a letter (valid in recipe names, usernames and sprout IDs).
func randomLower(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		if i == 0 {
			b[i] = lowerAlnum[int(b[i])%26]
			continue
		}
		b[i] = lowerAlnum[int(b[i])%len(lowerAlnum)]
	}
	return string(b)
}

// Nonce returns n random lowercase letters and digits starting with a
// letter, for names a test makes (recipes, files, tenants).
func Nonce(n int) string { return randomLower(n) }
