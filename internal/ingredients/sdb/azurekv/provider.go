// Package azurekv implements the sdb.SecretProvider for Azure Key Vault,
// authenticating via the VM/pod's managed identity only (v1 scope; no OIDC
// federation). This means it only works for a sprout actually running on
// Azure infrastructure with a managed identity attached — the Instance
// Metadata Service (IMDS) endpoint it talks to is link-local and
// unreachable from anywhere else.
//
// No Azure SDK is used: acquiring a managed-identity token is a single
// documented IMDS call, and reading a secret is a single documented Key
// Vault REST call, so a net/http client avoids pulling in the Azure SDK's
// dependency tree for two HTTP requests.
package azurekv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/log"
)

const backendName = "azurekv"

// DefaultIMDSTokenURL is Azure's real Instance Metadata Service token
// endpoint. Tests override imdsTokenURL to point at a mock server instead.
const DefaultIMDSTokenURL = "http://169.254.169.254/metadata/identity/oauth2/token"

const keyVaultResource = "https://vault.azure.net"

const keyVaultAPIVersion = "7.4"

// Provider is the sdb.SecretProvider implementation for Azure Key Vault.
type Provider struct {
	imdsTokenURL string
	// kvBaseURL overrides the per-vault "https://<vault>.vault.azure.net"
	// origin. Empty in production; tests point it at an httptest server.
	kvBaseURL  string
	httpClient *http.Client
	tokens     sdb.TokenCache
}

// Compile-time interface check.
var _ sdb.SecretProvider = (*Provider)(nil)

// New builds a Provider that fetches managed-identity tokens from imdsURL
// (pass "" for the real Azure IMDS endpoint) using httpClient (pass nil
// for a sane default).
func New(imdsURL string, httpClient *http.Client) *Provider {
	if imdsURL == "" {
		imdsURL = DefaultIMDSTokenURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	p := &Provider{imdsTokenURL: imdsURL, httpClient: httpClient}
	p.tokens.Fetch = p.fetchToken
	return p
}

func init() {
	if err := sdb.RegisterProvider(backendName, New("", nil)); err != nil {
		log.Warnf("sdb/azurekv: %v", err)
	}
}

type imdsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
}

func (p *Provider) fetchToken(ctx context.Context) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.imdsTokenURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata", "true")
	q := req.URL.Query()
	q.Set("api-version", "2018-02-01")
	q.Set("resource", keyVaultResource)
	req.URL.RawQuery = q.Encode()

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("azure IMDS request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("reading azure IMDS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("azure IMDS returned status %d: %s", resp.StatusCode, string(data))
	}
	var tr imdsTokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return "", 0, fmt.Errorf("decoding azure IMDS response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("azure IMDS response had no access_token")
	}
	ttlSeconds, err := strconv.ParseInt(tr.ExpiresIn, 10, 64)
	if err != nil || ttlSeconds <= 0 {
		ttlSeconds = 3600
	}
	return tr.AccessToken, time.Duration(ttlSeconds) * time.Second, nil
}

type secretResponse struct {
	Value string `json:"value"`
}

// Get implements sdb.SecretProvider. ref is
// sdb://azurekv/<vault-name>/<secret-name>[/<version>][#field]. The
// fragment, if present, selects a field out of the secret value when it's
// a JSON object; otherwise the raw secret string is returned.
func (p *Provider) Get(ctx context.Context, ref string) (string, error) {
	_, u, err := sdb.ParseRef(ref)
	if err != nil {
		return "", err
	}
	vaultName, secretName, version, err := splitVaultSecretVersion(u.Path)
	if err != nil {
		return "", err
	}

	token, err := p.tokens.Get(ctx)
	if err != nil {
		return "", err
	}

	value, err := p.readSecret(ctx, token, vaultName, secretName, version)
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

func splitVaultSecretVersion(uriPath string) (vault, secret, version string, err error) {
	parts := strings.Split(strings.Trim(uriPath, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("%w: expected sdb://azurekv/<vault>/<secret>[/<version>], got path %q", sdb.ErrInvalidRef, uriPath)
	}
	vault = parts[0]
	secret = parts[1]
	if len(parts) >= 3 {
		version = parts[2]
	}
	return vault, secret, version, nil
}

func (p *Provider) readSecret(ctx context.Context, token, vaultName, secretName, version string) (string, error) {
	base := p.kvBaseURL
	if base == "" {
		base = fmt.Sprintf("https://%s.vault.azure.net", vaultName)
	}
	reqURL := base + "/secrets/" + secretName
	if version != "" {
		reqURL += "/" + version
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	q := req.URL.Query()
	q.Set("api-version", keyVaultAPIVersion)
	req.URL.RawQuery = q.Encode()

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure key vault request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading azure key vault response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azure key vault returned status %d: %s", resp.StatusCode, string(data))
	}
	var sr secretResponse
	if err := json.Unmarshal(data, &sr); err != nil {
		return "", fmt.Errorf("decoding azure key vault response: %w", err)
	}
	return sr.Value, nil
}
