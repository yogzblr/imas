// Package openbao implements the sdb.SecretProvider for OpenBao and
// customer-managed HashiCorp Vault, authenticating via a customer-supplied
// client certificate (cert auth) rather than any credential imas controls.
//
// The official OpenBao/Vault Go client (github.com/openbao/openbao/api,
// github.com/hashicorp/vault/api) is MPL-2.0 licensed, which conflicts with
// this repo's Apache-2.0/MIT-only dependency constraint (see CLAUDE.md).
// This package therefore talks to Vault's HTTP API directly with net/http
// instead of depending on either SDK.
package openbao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/log"
)

const backendName = "openbao"

// Environment variables configuring the default, self-registered
// provider instance. All but the address and cert/key pair are optional.
const (
	EnvAddr       = "IMAS_SDB_OPENBAO_ADDR"
	EnvClientCert = "IMAS_SDB_OPENBAO_CLIENT_CERT"
	EnvClientKey  = "IMAS_SDB_OPENBAO_CLIENT_KEY"
	EnvCACert     = "IMAS_SDB_OPENBAO_CACERT"
	EnvAuthMount  = "IMAS_SDB_OPENBAO_AUTH_MOUNT" // default "cert"
	EnvAuthRole   = "IMAS_SDB_OPENBAO_ROLE"       // optional cert auth role name
)

var (
	ErrNotConfigured = errors.New("openbao sdb provider not configured")
	ErrLoginFailed   = errors.New("openbao cert login failed")
	ErrReadFailed    = errors.New("openbao secret read failed")
)

// Provider is the sdb.SecretProvider implementation for OpenBao/Vault
// cert-authenticated access.
type Provider struct {
	Addr       string
	AuthMount  string // e.g. "cert", mounted path of the cert auth method
	AuthRole   string // optional named role for auth/<mount>/login
	httpClient *http.Client

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
}

// Compile-time interface check.
var _ sdb.SecretProvider = (*Provider)(nil)

// New builds a Provider that authenticates with the given client
// certificate/key (hot-reloaded via an sdb.CertWatcher so a rotated cert
// is picked up without a restart) and, optionally, verifies the server
// against caCertFile instead of the system trust store.
func New(addr, certFile, keyFile, caCertFile, authMount, authRole string) (*Provider, error) {
	if addr == "" || certFile == "" || keyFile == "" {
		return nil, ErrNotConfigured
	}
	if authMount == "" {
		authMount = "cert"
	}
	watcher, err := sdb.NewCertWatcher(certFile, keyFile, 0)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		GetClientCertificate: watcher.GetClientCertificate,
		MinVersion:           tls.VersionTLS12,
	}
	if caCertFile != "" {
		pem, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in CA bundle %s", caCertFile)
		}
		tlsCfg.RootCAs = pool
	}
	return newWithTransport(addr, authMount, authRole, &http.Transport{
		TLSClientConfig: tlsCfg,
		// Cert rotation is only observed on a fresh TLS handshake. Secret
		// reads are infrequent enough (recipe execution, not a hot loop)
		// that trading away connection reuse for "the very next request
		// after rotation uses the new cert" is the right default.
		DisableKeepAlives: true,
	}), nil
}

func newWithTransport(addr, authMount, authRole string, transport http.RoundTripper) *Provider {
	return &Provider{
		Addr:       strings.TrimRight(addr, "/"),
		AuthMount:  authMount,
		AuthRole:   authRole,
		httpClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

// FromEnv builds a Provider from the Env* variables, for use by init()
// self-registration. It returns (nil, nil) when the minimum required
// variables aren't set, so registration is silently skipped rather than
// failing sprout startup for customers who don't use OpenBao.
func FromEnv() (*Provider, error) {
	addr := os.Getenv(EnvAddr)
	cert := os.Getenv(EnvClientCert)
	key := os.Getenv(EnvClientKey)
	if addr == "" && cert == "" && key == "" {
		return nil, nil
	}
	return New(addr, cert, key, os.Getenv(EnvCACert), os.Getenv(EnvAuthMount), os.Getenv(EnvAuthRole))
}

func init() {
	p, err := FromEnv()
	if err != nil {
		log.Warnf("sdb/openbao: not registering provider: %v", err)
		return
	}
	if p == nil {
		return
	}
	if err := sdb.RegisterProvider(backendName, p); err != nil {
		log.Warnf("sdb/openbao: %v", err)
	}
}

type loginResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

// login authenticates via the cert auth method over the already-mTLS'd
// connection and caches the resulting token until shortly before its
// lease expires.
func (p *Provider) login(ctx context.Context) (string, error) {
	body := []byte("{}")
	if p.AuthRole != "" {
		b, err := json.Marshal(map[string]string{"name": p.AuthRole})
		if err != nil {
			return "", err
		}
		body = b
	}
	reqURL := fmt.Sprintf("%s/v1/auth/%s/login", p.Addr, p.AuthMount)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLoginFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: reading response: %w", ErrLoginFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d: %s", ErrLoginFailed, resp.StatusCode, string(data))
	}
	var lr loginResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", fmt.Errorf("%w: decoding response: %w", ErrLoginFailed, err)
	}
	if lr.Auth == nil || lr.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: %s", ErrLoginFailed, strings.Join(lr.Errors, "; "))
	}
	p.tokenMu.Lock()
	p.token = lr.Auth.ClientToken
	// Renew a little before the lease actually expires.
	margin := time.Duration(lr.Auth.LeaseDuration) * time.Second / 10
	p.tokenExpiry = time.Now().Add(time.Duration(lr.Auth.LeaseDuration)*time.Second - margin)
	p.tokenMu.Unlock()
	return lr.Auth.ClientToken, nil
}

func (p *Provider) currentToken(ctx context.Context) (string, error) {
	p.tokenMu.Lock()
	tok := p.token
	valid := tok != "" && time.Now().Before(p.tokenExpiry)
	p.tokenMu.Unlock()
	if valid {
		return tok, nil
	}
	return p.login(ctx)
}

type kvV2Response struct {
	Data struct {
		Data map[string]any `json:"data"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

type kvV1Response struct {
	Data   map[string]any `json:"data"`
	Errors []string       `json:"errors"`
}

// Get implements sdb.SecretProvider. ref is
// sdb://openbao/<mount>/<path...>[#field]; the secret is read as KV v2
// (falling back to KV v1's flatter shape if the path isn't KV v2-mounted).
func (p *Provider) Get(ctx context.Context, ref string) (string, error) {
	_, u, err := sdb.ParseRef(ref)
	if err != nil {
		return "", err
	}
	mount, secretPath, err := splitMountAndPath(u.Path)
	if err != nil {
		return "", err
	}

	token, err := p.currentToken(ctx)
	if err != nil {
		return "", err
	}

	fields, err := p.readKV(ctx, token, mount, secretPath)
	if err != nil {
		return "", err
	}
	return sdb.SelectField(fields, u.Fragment)
}

func splitMountAndPath(uriPath string) (mount, secretPath string, err error) {
	trimmed := strings.Trim(uriPath, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: expected sdb://openbao/<mount>/<path>, got path %q", sdb.ErrInvalidRef, uriPath)
	}
	return parts[0], parts[1], nil
}

func (p *Provider) readKV(ctx context.Context, token, mount, secretPath string) (map[string]string, error) {
	fields, err := p.readKVv2(ctx, token, mount, secretPath)
	if err == nil {
		return fields, nil
	}
	if !errors.Is(err, errNotKVv2) {
		return nil, err
	}
	return p.readKVv1(ctx, token, mount, secretPath)
}

var errNotKVv2 = errors.New("not a kv-v2 mount")

func (p *Provider) readKVv2(ctx context.Context, token, mount, secretPath string) (map[string]string, error) {
	reqURL := fmt.Sprintf("%s/v1/%s/data/%s", p.Addr, mount, secretPath)
	data, status, err := p.doRead(ctx, token, reqURL)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, errNotKVv2
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrReadFailed, status, string(data))
	}
	var kr kvV2Response
	if err := json.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %w", ErrReadFailed, err)
	}
	if kr.Data.Data == nil {
		return nil, errNotKVv2
	}
	return stringify(kr.Data.Data), nil
}

func (p *Provider) readKVv1(ctx context.Context, token, mount, secretPath string) (map[string]string, error) {
	reqURL := fmt.Sprintf("%s/v1/%s/%s", p.Addr, mount, secretPath)
	data, status, err := p.doRead(ctx, token, reqURL)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrReadFailed, status, string(data))
	}
	var kr kvV1Response
	if err := json.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %w", ErrReadFailed, err)
	}
	if kr.Data == nil {
		return nil, fmt.Errorf("%w: %s", ErrReadFailed, strings.Join(kr.Errors, "; "))
	}
	return stringify(kr.Data), nil
}

func (p *Provider) doRead(ctx context.Context, token, reqURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading response: %w", ErrReadFailed, err)
	}
	return data, resp.StatusCode, nil
}

func stringify(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			out[k] = val
		default:
			b, err := json.Marshal(val)
			if err != nil {
				continue
			}
			out[k] = string(b)
		}
	}
	return out
}
