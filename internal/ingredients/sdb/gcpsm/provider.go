// Package gcpsm implements the sdb.SecretProvider for GCP Secret Manager,
// authenticating via the VM's attached service account only (v1 scope; no
// workload identity federation). This only works for a sprout actually
// running on GCP infrastructure with a service account attached — the
// metadata server it talks to is link-local and unreachable from
// anywhere else.
//
// No GCP client library is used: acquiring a service-account access token
// is a single documented metadata-server call, and reading a secret
// version is a single documented Secret Manager REST call, so a net/http
// client avoids pulling in cloud.google.com/go's dependency tree (gRPC,
// protobuf, etc.) for two HTTP requests.
package gcpsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/log"
)

const backendName = "gcpsm"

// DefaultMetadataTokenURL is GCE's real metadata-server token endpoint.
// Tests override metadataTokenURL to point at a mock server instead.
const DefaultMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

const defaultVersion = "latest"

// Provider is the sdb.SecretProvider implementation for GCP Secret
// Manager.
type Provider struct {
	metadataTokenURL string
	// smBaseURL overrides the "https://secretmanager.googleapis.com"
	// origin. Empty in production; tests point it at an httptest server.
	smBaseURL  string
	httpClient *http.Client
	tokens     sdb.TokenCache
}

// Compile-time interface check.
var _ sdb.SecretProvider = (*Provider)(nil)

// New builds a Provider that fetches service-account tokens from
// metadataURL (pass "" for the real GCE metadata endpoint) using
// httpClient (pass nil for a sane default).
func New(metadataURL string, httpClient *http.Client) *Provider {
	if metadataURL == "" {
		metadataURL = DefaultMetadataTokenURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	p := &Provider{metadataTokenURL: metadataURL, httpClient: httpClient}
	p.tokens.Fetch = p.fetchToken
	return p
}

func init() {
	if err := sdb.RegisterProvider(backendName, New("", nil)); err != nil {
		log.Warnf("sdb/gcpsm: %v", err)
	}
}

type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (p *Provider) fetchToken(ctx context.Context) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.metadataTokenURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("gcp metadata server request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("reading gcp metadata response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("gcp metadata server returned status %d: %s", resp.StatusCode, string(data))
	}
	var tr metadataTokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return "", 0, fmt.Errorf("decoding gcp metadata response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("gcp metadata response had no access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return tr.AccessToken, ttl, nil
}

type accessSecretVersionResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"` // base64-encoded
	} `json:"payload"`
}

// Get implements sdb.SecretProvider. ref is
// sdb://gcpsm/<project>/<secret-name>[/<version>][#field]; version
// defaults to "latest". If the payload is a JSON object, the fragment (if
// present) selects a field out of it; otherwise the raw payload string is
// returned.
func (p *Provider) Get(ctx context.Context, ref string) (string, error) {
	_, u, err := sdb.ParseRef(ref)
	if err != nil {
		return "", err
	}
	project, secretName, version, err := splitProjectSecretVersion(u.Path)
	if err != nil {
		return "", err
	}

	token, err := p.tokens.Get(ctx)
	if err != nil {
		return "", err
	}

	value, err := p.readSecret(ctx, token, project, secretName, version)
	if err != nil {
		return "", err
	}
	if u.Fragment == "" {
		return value, nil
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(value), &fields); err != nil {
		return "", fmt.Errorf("%w: secret is not a JSON object, cannot select field %q", sdb.ErrInvalidRef, u.Fragment)
	}
	return sdb.SelectField(fields, u.Fragment)
}

func splitProjectSecretVersion(uriPath string) (project, secret, version string, err error) {
	parts := strings.Split(strings.Trim(uriPath, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("%w: expected sdb://gcpsm/<project>/<secret>[/<version>], got path %q", sdb.ErrInvalidRef, uriPath)
	}
	version = defaultVersion
	if len(parts) >= 3 && parts[2] != "" {
		version = parts[2]
	}
	return parts[0], parts[1], version, nil
}

func (p *Provider) readSecret(ctx context.Context, token, project, secretName, version string) (string, error) {
	base := p.smBaseURL
	if base == "" {
		base = "https://secretmanager.googleapis.com"
	}
	reqURL := fmt.Sprintf("%s/v1/projects/%s/secrets/%s/versions/%s:access", base, project, secretName, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp secret manager request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading gcp secret manager response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp secret manager returned status %d: %s", resp.StatusCode, string(data))
	}
	var sv accessSecretVersionResponse
	if err := json.Unmarshal(data, &sv); err != nil {
		return "", fmt.Errorf("decoding gcp secret manager response: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(sv.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("decoding gcp secret manager payload: %w", err)
	}
	return string(decoded), nil
}
