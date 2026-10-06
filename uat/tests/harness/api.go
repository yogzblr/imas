package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewHTTPClient returns a client that trusts pool (nil: the system roots)
// and never follows redirects, so a test sees exactly what a server said.
func NewHTTPClient(pool *x509.CertPool, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewHTTP11Client is NewHTTPClient limited to HTTP/1.1, for requests an
// HTTP/2 connection can't carry (a websocket upgrade).
func NewHTTP11Client(pool *x509.CertPool, timeout time.Duration) *http.Client {
	c := NewHTTPClient(pool, timeout)
	tr := c.Transport.(*http.Transport)
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	return c
}

// APIError is saasapi's error body: {"error": code, "message": ..., "details": ...}.
type APIError struct {
	Code    string         `json:"error"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Response is what a server answered. Error is decoded when the body is
// saasapi's error shape.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	Error  APIError
}

// String is a one-line description for failure messages: the status, the
// error code and message, or the start of a non-JSON body.
func (r *Response) String() string {
	if r == nil {
		return "no response"
	}
	if r.Error.Code != "" {
		return fmt.Sprintf("HTTP %d %s: %s", r.Status, r.Error.Code, r.Error.Message)
	}
	body := strings.TrimSpace(string(r.Body))
	if len(body) > 200 {
		body = body[:200] + "..."
	}
	return fmt.Sprintf("HTTP %d %s", r.Status, body)
}

// Is reports whether the response has this status and, if code isn't
// empty, this error code.
func (r *Response) Is(status int, code string) bool {
	return r != nil && r.Status == status && (code == "" || r.Error.Code == code)
}

// Decode unmarshals the body into v.
func (r *Response) Decode(v any) error {
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("decoding %s: %w", r.String(), err)
	}
	return nil
}

// Request is one call to saasapi. Path starts with /v1. Body is sent as
// JSON unless RawBody is set. By default both credentials are sent; the
// fields below take one away or replace it, for the auth scenarios.
type Request struct {
	Method      string
	Path        string
	Token       string
	Body        any
	RawBody     []byte
	ContentType string
	Header      http.Header
	// NoInternalAuth leaves X-Internal-Auth out; InternalAuth, if set,
	// sends that value instead of the configured secret.
	NoInternalAuth bool
	InternalAuth   string
}

// Client calls saasapi.
type Client struct {
	BaseURL      string
	InternalAuth string
	HTTP         *http.Client
}

// NewClient returns a Client for baseURL (without /v1).
func NewClient(baseURL, internalAuth string, hc *http.Client) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), InternalAuth: internalAuth, HTTP: hc}
}

// Do sends req. The error is for transport failures only: any HTTP status
// comes back as a Response.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	var body io.Reader
	contentType := req.ContentType
	switch {
	case req.RawBody != nil:
		body = bytes.NewReader(req.RawBody)
	case req.Body != nil:
		b, err := json.Marshal(req.Body)
		if err != nil {
			return nil, fmt.Errorf("encoding %s %s: %w", req.Method, req.Path, err)
		}
		body = bytes.NewReader(b)
		if contentType == "" {
			contentType = "application/json"
		}
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, c.BaseURL+req.Path, body)
	if err != nil {
		return nil, fmt.Errorf("building %s %s: %w", req.Method, req.Path, err)
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	if contentType != "" {
		hr.Header.Set("Content-Type", contentType)
	}
	switch {
	case req.InternalAuth != "":
		hr.Header.Set("X-Internal-Auth", req.InternalAuth)
	case !req.NoInternalAuth:
		hr.Header.Set("X-Internal-Auth", c.InternalAuth)
	}
	if req.Token != "" {
		hr.Header.Set("Authorization", "Bearer "+req.Token)
	}
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.Path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("%s %s: reading the response: %w", req.Method, req.Path, err)
	}
	out := &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}
	if resp.StatusCode >= 400 {
		_ = json.Unmarshal(b, &out.Error)
	}
	return out, nil
}

// TenantPath is /v1/tenants/<id> followed by the elements, each escaped.
func TenantPath(tenantID string, elems ...string) string {
	p := "/v1/tenants/" + url.PathEscape(tenantID)
	for _, e := range elems {
		p += "/" + url.PathEscape(e)
	}
	return p
}

// TenantStatus is the body of POST /v1/tenants, DELETE and GET .../status.
type TenantStatus struct {
	TenantID  string `json:"tenant_id"`
	Status    string `json:"status"`
	LastError string `json:"last_error,omitempty"`
	Warning   string `json:"warning,omitempty"`
}

// Tenant statuses.
const (
	TenantPending     = "pending"
	TenantActive      = "active"
	TenantFailed      = "failed"
	TenantOffboarding = "offboarding"
	TenantOffboarded  = "offboarded"
)

// CreateTenant posts {"name": name}.
func (c *Client) CreateTenant(ctx context.Context, token, name string) (TenantStatus, *Response, error) {
	var out TenantStatus
	r, err := c.Do(ctx, Request{Method: http.MethodPost, Path: "/v1/tenants", Token: token, Body: map[string]string{"name": name}})
	if err == nil && r.Status == http.StatusAccepted {
		err = r.Decode(&out)
	}
	return out, r, err
}

// GetTenantStatus calls GET .../status.
func (c *Client) GetTenantStatus(ctx context.Context, token, tenantID string) (TenantStatus, *Response, error) {
	var out TenantStatus
	r, err := c.Do(ctx, Request{Method: http.MethodGet, Path: TenantPath(tenantID, "status"), Token: token})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
	}
	return out, r, err
}

// DeleteTenant calls DELETE /v1/tenants/<id>.
func (c *Client) DeleteTenant(ctx context.Context, token, tenantID string) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodDelete, Path: TenantPath(tenantID), Token: token})
}

// WaitTenantStatus polls the status until it is one of want, or until
// timeout. The last status read comes back either way.
func (c *Client) WaitTenantStatus(ctx context.Context, token, tenantID string, timeout time.Duration, want ...string) (TenantStatus, error) {
	deadline := time.Now().Add(timeout)
	var last TenantStatus
	for {
		st, r, err := c.GetTenantStatus(ctx, token, tenantID)
		if err == nil && r.Status != http.StatusOK {
			err = fmt.Errorf("GET status: %s", r)
		}
		if err == nil {
			last = st
			for _, w := range want {
				if st.Status == w {
					return st, nil
				}
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return last, err
			}
			return last, fmt.Errorf("tenant %s is %q after %s, want one of %v (last_error %q)", tenantID, last.Status, timeout, want, last.LastError)
		}
		if err := sleep(ctx, 3*time.Second); err != nil {
			return last, err
		}
	}
}

// EnrollmentKey is the body of POST .../enrollment-keys. RegistrationKey
// is a secret: never print it.
type EnrollmentKey struct {
	KeyID           string    `json:"key_id"`
	RegistrationKey string    `json:"registration_key"`
	ExpiresAt       time.Time `json:"expires_at"`
	MaxUses         int       `json:"max_uses"`
}

// KeyInfo is one entry of GET .../enrollment-keys.
type KeyInfo struct {
	KeyID     string    `json:"key_id"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateKey mints one enrollment key, once (no retry on 429).
func (c *Client) CreateKey(ctx context.Context, token, tenantID string, hours, maxUses int) (EnrollmentKey, *Response, error) {
	var out EnrollmentKey
	r, err := c.Do(ctx, Request{
		Method: http.MethodPost, Path: TenantPath(tenantID, "enrollment-keys"), Token: token,
		Body: map[string]int{"expires_in_hours": hours, "max_uses": maxUses},
	})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
	}
	return out, r, err
}

// MintKey mints a key, waiting out 429 rate_limited answers for up to a
// minute. Any other refusal is an error.
func (c *Client) MintKey(ctx context.Context, token, tenantID string, hours, maxUses int) (EnrollmentKey, error) {
	var key EnrollmentKey
	err := retryRateLimited(ctx, time.Minute, func() (*Response, error) {
		k, r, err := c.CreateKey(ctx, token, tenantID, hours, maxUses)
		key = k
		return r, err
	}, http.StatusOK)
	return key, err
}

// ListKeys calls GET .../enrollment-keys.
func (c *Client) ListKeys(ctx context.Context, token, tenantID string) ([]KeyInfo, *Response, error) {
	var out struct {
		Keys []KeyInfo `json:"enrollment_keys"`
	}
	r, err := c.Do(ctx, Request{Method: http.MethodGet, Path: TenantPath(tenantID, "enrollment-keys"), Token: token})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
	}
	return out.Keys, r, err
}

// FindKey returns the listed key with this ID.
func FindKey(keys []KeyInfo, keyID string) (KeyInfo, bool) {
	for _, k := range keys {
		if k.KeyID == keyID {
			return k, true
		}
	}
	return KeyInfo{}, false
}

// RevokeKey calls DELETE .../enrollment-keys/<key_id>.
func (c *Client) RevokeKey(ctx context.Context, token, tenantID, keyID string) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodDelete, Path: TenantPath(tenantID, "enrollment-keys", keyID), Token: token})
}

// LinkAsset calls POST .../sprouts/<sprout_id>/asset-link.
func (c *Client) LinkAsset(ctx context.Context, token, tenantID, sproutID, assetID string) (*Response, error) {
	return c.Do(ctx, Request{
		Method: http.MethodPost, Path: TenantPath(tenantID, "sprouts", sproutID, "asset-link"), Token: token,
		Body: map[string]string{"asset_id": assetID},
	})
}

// UnlinkAsset calls DELETE .../sprouts/<sprout_id>/asset-link.
func (c *Client) UnlinkAsset(ctx context.Context, token, tenantID, sproutID string) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodDelete, Path: TenantPath(tenantID, "sprouts", sproutID, "asset-link"), Token: token})
}

// AssetResult is one resolved asset ID of a lookup.
type AssetResult struct {
	SproutID  string `json:"sprout_id"`
	AssetID   string `json:"asset_id"`
	KeyState  string `json:"key_state"`
	Connected bool   `json:"connected"`
}

// Lookup is the body of GET .../sprouts?asset_ids=.
type Lookup struct {
	Results    []AssetResult `json:"results"`
	Unresolved []string      `json:"unresolved"`
}

// Find returns the result for an asset ID.
func (l Lookup) Find(assetID string) (AssetResult, bool) {
	for _, r := range l.Results {
		if r.AssetID == assetID {
			return r, true
		}
	}
	return AssetResult{}, false
}

// IsUnresolved reports whether the asset ID came back unresolved.
func (l Lookup) IsUnresolved(assetID string) bool {
	for _, u := range l.Unresolved {
		if u == assetID {
			return true
		}
	}
	return false
}

// LookupAssets calls GET .../sprouts?asset_ids=a,b.
func (c *Client) LookupAssets(ctx context.Context, token, tenantID string, assetIDs []string) (Lookup, *Response, error) {
	var out Lookup
	q := url.Values{"asset_ids": {strings.Join(assetIDs, ",")}}
	r, err := c.Do(ctx, Request{Method: http.MethodGet, Path: TenantPath(tenantID, "sprouts") + "?" + q.Encode(), Token: token})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
	}
	return out, r, err
}

// Action is a batch action: cmd.run or cook.
type Action struct {
	Type   string `json:"type"`
	Params any    `json:"params"`
}

// CmdRun is cmd.run's params. Args nil means Cmd is split on whitespace
// (and shell syntax is refused); set Args, even empty, to pass Cmd as
// the executable verbatim.
type CmdRun struct {
	Cmd            string   `json:"cmd"`
	Args           []string `json:"args,omitempty"`
	CWD            string   `json:"cwd,omitempty"`
	RunAs          string   `json:"run_as,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// CmdRunAction is a cmd.run action.
func CmdRunAction(c CmdRun) Action { return Action{Type: "cmd.run", Params: c} }

// CookAction is a cook action.
func CookAction(recipe string, test bool) Action {
	return Action{Type: "cook", Params: map[string]any{"recipe": recipe, "test": test}}
}

// Item statuses and the batch statuses of GET .../actions/<batch_id>.
const (
	ItemQueued      = "queued"
	ItemDispatching = "dispatching"
	ItemRunning     = "running"
	ItemSucceeded   = "succeeded"
	ItemFailed      = "failed"
	ItemUnresolved  = "unresolved"

	BatchInProgress = "in_progress"
	BatchCompleted  = "completed"
)

// Item is one asset ID's result in a batch.
type Item struct {
	AssetID  string `json:"asset_id"`
	SproutID string `json:"sprout_id,omitempty"`
	Status   string `json:"status"`
	JID      string `json:"jid,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
}

// String describes the item for a failure message.
func (it Item) String() string {
	s := fmt.Sprintf("asset %s sprout %s: %s", it.AssetID, it.SproutID, it.Status)
	if it.ExitCode != nil {
		s += fmt.Sprintf(" exit_code=%d", *it.ExitCode)
	}
	if it.Error != "" {
		s += fmt.Sprintf(" error=%s (%s)", it.Error, it.Message)
	}
	return s
}

// Batch is the body of GET .../sprouts/actions/<batch_id>.
type Batch struct {
	BatchID    string    `json:"batch_id"`
	Status     string    `json:"status"`
	ActionType string    `json:"action_type"`
	CreatedAt  time.Time `json:"created_at"`
	Items      []Item    `json:"items"`
}

// Item returns the item of an asset ID.
func (b *Batch) Item(assetID string) (Item, bool) {
	if b == nil {
		return Item{}, false
	}
	for _, it := range b.Items {
		if it.AssetID == assetID {
			return it, true
		}
	}
	return Item{}, false
}

// For returns the item of a sprout's asset ID.
func (b *Batch) For(sp Sprout) (Item, bool) { return b.Item(sp.AssetID) }

// PostBatch posts one batch, once (no retry on 429).
func (c *Client) PostBatch(ctx context.Context, token, tenantID string, assetIDs []string, act Action) (string, *Response, error) {
	var out struct {
		BatchID string `json:"batch_id"`
	}
	r, err := c.Do(ctx, Request{
		Method: http.MethodPost, Path: TenantPath(tenantID, "sprouts", "actions"), Token: token,
		Body: map[string]any{"asset_ids": assetIDs, "action": act},
	})
	if err == nil && r.Status == http.StatusAccepted {
		err = r.Decode(&out)
	}
	return out.BatchID, r, err
}

// StartBatch posts a batch, waiting out 429 rate_limited answers for up to
// two minutes.
func (c *Client) StartBatch(ctx context.Context, token, tenantID string, assetIDs []string, act Action) (string, error) {
	var id string
	err := retryRateLimited(ctx, 2*time.Minute, func() (*Response, error) {
		b, r, err := c.PostBatch(ctx, token, tenantID, assetIDs, act)
		id = b
		return r, err
	}, http.StatusAccepted)
	return id, err
}

// GetBatch calls GET .../sprouts/actions/<batch_id>.
func (c *Client) GetBatch(ctx context.Context, token, tenantID, batchID string) (*Batch, *Response, error) {
	var out Batch
	r, err := c.Do(ctx, Request{Method: http.MethodGet, Path: TenantPath(tenantID, "sprouts", "actions", batchID), Token: token})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
		return &out, r, err
	}
	return nil, r, err
}

// WaitBatch polls a batch until it is completed, or until timeout. The
// last batch read comes back either way.
func (c *Client) WaitBatch(ctx context.Context, token, tenantID, batchID string, timeout time.Duration) (*Batch, error) {
	deadline := time.Now().Add(timeout)
	var last *Batch
	for {
		b, r, err := c.GetBatch(ctx, token, tenantID, batchID)
		if err == nil && r.Status != http.StatusOK {
			err = fmt.Errorf("GET batch %s: %s", batchID, r)
		}
		if err == nil {
			last = b
			if b.Status == BatchCompleted {
				return b, nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return last, err
			}
			return last, fmt.Errorf("batch %s still %s after %s: %s", batchID, last.Status, timeout, describeItems(last))
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return last, err
		}
	}
}

func describeItems(b *Batch) string {
	if b == nil {
		return "no items"
	}
	var parts []string
	for _, it := range b.Items {
		parts = append(parts, it.String())
	}
	return strings.Join(parts, "; ")
}

// Recipe is a recipe's metadata, and its content on a GET of one recipe.
type Recipe struct {
	Name      string    `json:"name"`
	SHA256    string    `json:"sha256,omitempty"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
	Content   *string   `json:"content,omitempty"`
}

// Precondition is the header a recipe PUT carries.
type Precondition struct {
	// IfNoneMatch "*" creates only; IfMatch is "*" or a sha256 (quoted
	// here). Both empty sends no precondition.
	IfNoneMatch string
	IfMatch     string
}

// Create is If-None-Match: *.
var Create = Precondition{IfNoneMatch: "*"}

// Replace is If-Match: *.
var Replace = Precondition{IfMatch: "*"}

// ReplaceVersion is If-Match: "<sha256>".
func ReplaceVersion(sha string) Precondition { return Precondition{IfMatch: `"` + sha + `"`} }

func (p Precondition) header() http.Header {
	h := http.Header{}
	if p.IfNoneMatch != "" {
		h.Set("If-None-Match", p.IfNoneMatch)
	}
	if p.IfMatch != "" {
		h.Set("If-Match", p.IfMatch)
	}
	return h
}

// PutRecipe calls PUT .../recipes/<name> with the raw content, once.
func (c *Client) PutRecipe(ctx context.Context, token, tenantID, name, content string, pre Precondition) (Recipe, *Response, error) {
	var out Recipe
	r, err := c.Do(ctx, Request{
		Method: http.MethodPut, Path: TenantPath(tenantID, "recipes") + "/" + name, Token: token,
		RawBody: []byte(content), ContentType: "application/yaml", Header: pre.header(),
	})
	if err == nil && (r.Status == http.StatusOK || r.Status == http.StatusCreated) {
		err = r.Decode(&out)
	}
	return out, r, err
}

// UploadRecipe puts a recipe with If-Match: * semantics for an existing
// one and If-None-Match: * for a new one, waiting out 429s for a minute.
func (c *Client) UploadRecipe(ctx context.Context, token, tenantID, name, content string) (Recipe, error) {
	var rec Recipe
	err := retryRateLimited(ctx, time.Minute, func() (*Response, error) {
		out, r, err := c.PutRecipe(ctx, token, tenantID, name, content, Create)
		if err == nil && r.Status == http.StatusPreconditionFailed {
			out, r, err = c.PutRecipe(ctx, token, tenantID, name, content, Replace)
		}
		rec = out
		return r, err
	}, http.StatusCreated, http.StatusOK)
	return rec, err
}

// GetRecipe calls GET .../recipes/<name>.
func (c *Client) GetRecipe(ctx context.Context, token, tenantID, name string) (Recipe, *Response, error) {
	var out Recipe
	r, err := c.Do(ctx, Request{Method: http.MethodGet, Path: TenantPath(tenantID, "recipes") + "/" + name, Token: token})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
	}
	return out, r, err
}

// ListRecipes calls GET .../recipes once (one page).
func (c *Client) ListRecipes(ctx context.Context, token, tenantID string, limit int, pageToken string) ([]Recipe, string, *Response, error) {
	var out struct {
		Recipes []Recipe `json:"recipes"`
		Next    string   `json:"next_page_token"`
	}
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprint(limit))
	}
	if pageToken != "" {
		q.Set("page_token", pageToken)
	}
	path := TenantPath(tenantID, "recipes")
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	r, err := c.Do(ctx, Request{Method: http.MethodGet, Path: path, Token: token})
	if err == nil && r.Status == http.StatusOK {
		err = r.Decode(&out)
	}
	return out.Recipes, out.Next, r, err
}

// AllRecipes lists every page.
func (c *Client) AllRecipes(ctx context.Context, token, tenantID string) ([]Recipe, error) {
	var all []Recipe
	next := ""
	for page := 0; page < 100; page++ {
		recs, n, r, err := c.ListRecipes(ctx, token, tenantID, 500, next)
		if err != nil {
			return all, err
		}
		if r.Status != http.StatusOK {
			return all, fmt.Errorf("listing recipes: %s", r)
		}
		all = append(all, recs...)
		if n == "" {
			return all, nil
		}
		next = n
	}
	return all, errors.New("listing recipes: more than 100 pages")
}

// DeleteRecipe calls DELETE .../recipes/<name>.
func (c *Client) DeleteRecipe(ctx context.Context, token, tenantID, name string) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodDelete, Path: TenantPath(tenantID, "recipes") + "/" + name, Token: token})
}

// retryRateLimited calls fn until it answers one of ok, retrying while it
// answers 429 rate_limited, for up to budget. Other answers are errors.
func retryRateLimited(ctx context.Context, budget time.Duration, fn func() (*Response, error), ok ...int) error {
	deadline := time.Now().Add(budget)
	wait := time.Second
	for {
		r, err := fn()
		if err != nil {
			return err
		}
		for _, s := range ok {
			if r.Status == s {
				return nil
			}
		}
		if r.Status != http.StatusTooManyRequests || time.Now().Add(wait).After(deadline) {
			return fmt.Errorf("unexpected answer: %s", r)
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
		if wait < 8*time.Second {
			wait *= 2
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
