// Package awssm implements the sdb.SecretProvider for AWS Secrets
// Manager, authenticating via the instance's attached IAM role only (v1
// scope; no OIDC/web-identity federation). This only works for a sprout
// actually running on AWS infrastructure with a role attached — IMDS is a
// link-local endpoint unreachable from anywhere else.
//
// No AWS SDK is used: credential retrieval is two documented IMDSv2
// calls and GetSecretValue is a single documented JSON API call signed
// with SigV4 (implemented in sigv4.go using only crypto/hmac and
// crypto/sha256), so a net/http client avoids pulling in aws-sdk-go-v2's
// dependency tree for that.
package awssm

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/log"
)

const backendName = "awssm"

// DefaultIMDSBaseURL is AWS's real Instance Metadata Service origin.
// Tests override imdsBaseURL to point at a mock server instead.
const DefaultIMDSBaseURL = "http://169.254.169.254"

const imdsTokenTTL = "21600" // seconds; IMDSv2 token lifetime

// Provider is the sdb.SecretProvider implementation for AWS Secrets
// Manager.
type Provider struct {
	imdsBaseURL string
	// smEndpoint overrides the per-region
	// "https://secretsmanager.<region>.amazonaws.com" origin. Empty in
	// production; tests point it at an httptest server.
	smEndpoint string
	httpClient *http.Client
	creds      sdb.TokenCache // token cache's "token" holds a JSON-encoded awsCreds
}

// Compile-time interface check.
var _ sdb.SecretProvider = (*Provider)(nil)

// New builds a Provider that fetches role credentials from imdsBaseURL
// (pass "" for the real AWS IMDS endpoint) using httpClient (pass nil for
// a sane default).
func New(imdsBaseURL string, httpClient *http.Client) *Provider {
	if imdsBaseURL == "" {
		imdsBaseURL = DefaultIMDSBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	p := &Provider{imdsBaseURL: imdsBaseURL, httpClient: httpClient}
	p.creds.Fetch = p.fetchCredsJSON
	return p
}

func init() {
	if err := sdb.RegisterProvider(backendName, New("", nil)); err != nil {
		log.Warnf("sdb/awssm: %v", err)
	}
}

type imdsRoleCreds struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func (p *Provider) imdsToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.imdsBaseURL+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", imdsTokenTTL)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("aws IMDS token request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading aws IMDS token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aws IMDS token request returned status %d: %s", resp.StatusCode, string(data))
	}
	return strings.TrimSpace(string(data)), nil
}

func (p *Provider) imdsGet(ctx context.Context, token, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.imdsBaseURL+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("aws IMDS request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading aws IMDS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aws IMDS request to %s returned status %d: %s", path, resp.StatusCode, string(data))
	}
	return string(data), nil
}

// fetchCredsJSON retrieves the instance role's temporary credentials via
// IMDSv2 and returns them JSON-encoded so they fit sdb.TokenCache's
// string-token shape.
func (p *Provider) fetchCredsJSON(ctx context.Context) (string, time.Duration, error) {
	token, err := p.imdsToken(ctx)
	if err != nil {
		return "", 0, err
	}

	rolesRaw, err := p.imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return "", 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(rolesRaw))
	if !scanner.Scan() {
		return "", 0, fmt.Errorf("aws IMDS returned no attached IAM role")
	}
	role := strings.TrimSpace(scanner.Text())
	if role == "" {
		return "", 0, fmt.Errorf("aws IMDS returned no attached IAM role")
	}

	credsRaw, err := p.imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/"+role)
	if err != nil {
		return "", 0, err
	}
	var ic imdsRoleCreds
	if err := json.Unmarshal([]byte(credsRaw), &ic); err != nil {
		return "", 0, fmt.Errorf("decoding aws IMDS role credentials: %w", err)
	}
	if ic.AccessKeyID == "" || ic.SecretAccessKey == "" {
		return "", 0, fmt.Errorf("aws IMDS role credentials response was incomplete")
	}

	ttl := 15 * time.Minute
	if exp, err := time.Parse(time.RFC3339, ic.Expiration); err == nil {
		if d := time.Until(exp); d > 0 {
			ttl = d
		}
	}
	return credsRaw, ttl, nil
}

func (p *Provider) currentCreds(ctx context.Context) (awsCreds, error) {
	raw, err := p.creds.Get(ctx)
	if err != nil {
		return awsCreds{}, err
	}
	var ic imdsRoleCreds
	if err := json.Unmarshal([]byte(raw), &ic); err != nil {
		return awsCreds{}, fmt.Errorf("decoding cached aws credentials: %w", err)
	}
	return awsCreds{AccessKeyID: ic.AccessKeyID, SecretAccessKey: ic.SecretAccessKey, SessionToken: ic.Token}, nil
}

type getSecretValueResponse struct {
	Name         string `json:"Name"`
	SecretString string `json:"SecretString"`
	SecretBinary []byte `json:"SecretBinary"`
}

// Get implements sdb.SecretProvider. ref is
// sdb://awssm/<region>/<secret-id...>[#field]; a secret-id may itself
// contain slashes (AWS commonly names secrets like "prod/db/password").
// If the secret value is a JSON object, the fragment (if present) selects
// a field out of it; otherwise the raw string is returned.
func (p *Provider) Get(ctx context.Context, ref string) (string, error) {
	_, u, err := sdb.ParseRef(ref)
	if err != nil {
		return "", err
	}
	region, secretID, err := splitRegionAndSecretID(u.Path)
	if err != nil {
		return "", err
	}

	creds, err := p.currentCreds(ctx)
	if err != nil {
		return "", err
	}

	value, err := p.readSecret(ctx, creds, region, secretID)
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

func splitRegionAndSecretID(uriPath string) (region, secretID string, err error) {
	trimmed := strings.Trim(uriPath, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: expected sdb://awssm/<region>/<secret-id>, got path %q", sdb.ErrInvalidRef, uriPath)
	}
	return parts[0], parts[1], nil
}

func (p *Provider) readSecret(ctx context.Context, creds awsCreds, region, secretID string) (string, error) {
	endpoint := p.smEndpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", region)
	}

	body, err := json.Marshal(map[string]string{"SecretId": secretID})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	signSigV4(req, body, creds, region, "secretsmanager", time.Now())

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("aws secrets manager request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading aws secrets manager response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aws secrets manager returned status %d: %s", resp.StatusCode, string(data))
	}
	var sv getSecretValueResponse
	if err := json.Unmarshal(data, &sv); err != nil {
		return "", fmt.Errorf("decoding aws secrets manager response: %w", err)
	}
	if sv.SecretString != "" {
		return sv.SecretString, nil
	}
	if len(sv.SecretBinary) > 0 {
		return string(sv.SecretBinary), nil
	}
	return "", fmt.Errorf("aws secrets manager returned an empty secret value for %s", secretID)
}
