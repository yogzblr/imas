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
var ErrNoKeycloakAdmin = errors.New("keycloak.json has no Keycloak admin identity for the admin REST API")

// lockoutWait bounds how long Password waits out what looks like a
// Keycloak temporary lockout. Keycloak 26's quick-login rule locks a user
// for minimumQuickLoginWaitSeconds (60 by default) after two failed
// logins less than quickLoginCheckMilliSeconds (1000) apart, whatever the
// failureFactor; waitIncrementSeconds (60) applies otherwise.
const (
	lockoutWait  = 150 * time.Second
	lockoutRetry = 10 * time.Second
)

// refreshMargin: a cached token is replaced this long before it expires,
// so a call (or a batch poll) never goes out on one about to expire (W11).
const refreshMargin = 60 * time.Second

// Tokens gets Keycloak access tokens. Tokens are cached per user and
// client until refreshMargin before they expire, and one user's token is
// fetched once at a time however many tests ask for it. Safe for
// concurrent use.
type Tokens struct {
	cfg  KeycloakConfig
	http *http.Client
	base string
	// realm is the test realm, from the issuer.
	realm string
	now   func() time.Time
	// sleep waits d or until ctx ends. For tests.
	sleep func(ctx context.Context, d time.Duration) error
	// Logf, when set, reports a lockout being waited out.
	Logf func(format string, args ...any)

	mu       sync.Mutex
	cache    map[string]cachedToken
	inflight map[string]chan struct{}
	// granted holds the client, user and password triples that got a
	// token during the run: a password known to work that Keycloak then
	// refuses is a lockout, not a wrong password.
	granted map[grantKey]bool
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
	return &Tokens{cfg: cfg, http: hc, base: base, realm: realm, now: time.Now, sleep: sleepCtx,
		cache: map[string]cachedToken{}, inflight: map[string]chan struct{}{}, granted: map[grantKey]bool{}}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Forget drops every cached token, so the next ones are fetched afresh
// (after bind-tenant.sh changed the users' organization.id).
func (k *Tokens) Forget() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cache = map[string]cachedToken{}
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

// TenantFunc is a TokenFunc for a tenant's configured user: the cached
// token, or with renew a new one that replaces it in the cache.
func (k *Tokens) TenantFunc(tenant int, role Role) TokenFunc {
	return func(ctx context.Context, renew bool) (string, error) {
		if renew {
			if c, err := k.TenantUser(tenant, role); err == nil {
				k.drop(ClientCreds{ClientID: k.cfg.ClientID, ClientSecret: k.cfg.ClientSecret}, c)
			}
		}
		return k.Tenant(ctx, tenant, role)
	}
}

// drop forgets the cached token of one user and client.
func (k *Tokens) drop(client ClientCreds, user Credentials) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.cache, passwordKey(client, user))
}

// Fresh returns a new token for a tenant's user, bypassing the cache.
func (k *Tokens) Fresh(ctx context.Context, tenant int, role Role) (string, error) {
	c, err := k.TenantUser(tenant, role)
	if err != nil {
		return "", err
	}
	client := ClientCreds{ClientID: k.cfg.ClientID, ClientSecret: k.cfg.ClientSecret}
	tok, _, err := k.passwordGrant(ctx, client, c)
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
// (password grant), cached. Concurrent calls for the same user and client
// share one request: parallel tests that all miss the cache would
// otherwise send a burst of password grants for one user.
func (k *Tokens) Password(ctx context.Context, client ClientCreds, user Credentials) (string, error) {
	key := passwordKey(client, user)
	for {
		k.mu.Lock()
		if c, ok := k.cache[key]; ok && k.now().Add(refreshMargin).Before(c.exp) {
			k.mu.Unlock()
			return c.token, nil
		}
		if wait, ok := k.inflight[key]; ok {
			k.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return "", fmt.Errorf("token for %s from client %s: %w", user.Username, client.ClientID, ctx.Err())
			}
		}
		done := make(chan struct{})
		k.inflight[key] = done
		k.mu.Unlock()

		tok, exp, err := k.passwordGrant(ctx, client, user)
		k.mu.Lock()
		delete(k.inflight, key)
		if err == nil {
			k.cache[key] = cachedToken{token: tok, exp: exp}
		}
		k.mu.Unlock()
		close(done)
		if err != nil {
			return "", fmt.Errorf("token for %s from client %s: %w", user.Username, client.ClientID, err)
		}
		return tok, nil
	}
}

// grantKey names the exact credentials of a grant, so a changed password
// isn't taken for a known-good one.
type grantKey struct{ client, user, password string }

func passwordKey(client ClientCreds, user Credentials) string {
	return client.ClientID + "\x00" + user.Username
}

// passwordGrant gets a token by password grant. When Keycloak refuses a
// user whose password already got a token from this client during the
// run, it is waiting out a temporary brute-force lockout (Keycloak answers
// a locked-out user with the same invalid_grant "Invalid user
// credentials" as a wrong password, and doesn't count a refused attempt
// as another failure): it retries for up to lockoutWait.
func (k *Tokens) passwordGrant(ctx context.Context, client ClientCreds, user Credentials) (string, time.Time, error) {
	key := grantKey{client.ClientID, user.Username, user.Password}
	form := passwordForm(client, user)
	start := k.now()
	for attempt := 1; ; attempt++ {
		tok, exp, err := k.grant(ctx, k.tokenURL(k.realm), form)
		if err == nil {
			k.mu.Lock()
			k.granted[key] = true
			k.mu.Unlock()
			if attempt > 1 {
				k.logf("Keycloak gave %s a token from client %s again after %s (%d attempts): it was a temporary lockout",
					user.Username, client.ClientID, k.now().Sub(start).Round(time.Second), attempt)
			}
			return tok, exp, nil
		}
		k.mu.Lock()
		known := k.granted[key]
		k.mu.Unlock()
		if !known || !isInvalidGrant(err) {
			return "", time.Time{}, err
		}
		waited := k.now().Sub(start)
		if waited >= lockoutWait {
			return "", time.Time{}, fmt.Errorf("%w; this password got a token earlier in the run and Keycloak still refuses it after %s: a brute-force lockout (look for user_temporarily_disabled in the Keycloak log) or a changed password",
				err, waited.Round(time.Second))
		}
		if attempt == 1 {
			k.logf("Keycloak refused %s's password from client %s (%v) although it got a token earlier in the run: waiting up to %s for a temporary lockout to end",
				user.Username, client.ClientID, err, lockoutWait)
		}
		if serr := k.sleep(ctx, lockoutRetry); serr != nil {
			return "", time.Time{}, fmt.Errorf("%w (while waiting out a possible Keycloak temporary lockout: %v)", err, serr)
		}
	}
}

func (k *Tokens) logf(format string, args ...any) {
	if k.Logf != nil {
		k.Logf(format, args...)
	}
}

// grantError is Keycloak's refusal of a token request.
type grantError struct {
	status      int
	code, descr string
}

func (e *grantError) Error() string {
	return fmt.Sprintf("keycloak answered HTTP %d %s %s", e.status, e.code, e.descr)
}

func isInvalidGrant(err error) bool {
	var g *grantError
	return errors.As(err, &g) && g.status == http.StatusUnauthorized && g.code == "invalid_grant"
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
		return "", time.Time{}, &grantError{status: resp.StatusCode, code: out.Error, descr: out.Description}
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
	// NoDelete is set for a user bind-tenant.sh made: uat/hub/core has no
	// way to delete one, so Delete leaves it (it dies with the run).
	NoDelete bool
	k        *Tokens
}

// Token returns a token for the scratch user.
func (u *ScratchUser) Token(ctx context.Context) (string, error) {
	return u.k.Password(ctx, ClientCreds{ClientID: u.k.cfg.ClientID, ClientSecret: u.k.cfg.ClientSecret}, u.User)
}

// Delete removes the user from the realm (a no-op with NoDelete).
func (u *ScratchUser) Delete(ctx context.Context) error {
	if u.NoDelete {
		return nil
	}
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
