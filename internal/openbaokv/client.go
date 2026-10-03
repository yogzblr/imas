// Package openbaokv is a minimal client for OpenBao's KV v2 secrets
// engine: read and write one secret's data at a caller-supplied path.
// Its one consumer today is `farmer publish-saasapi-credential`
// (cmd/farmer), which pushes the SaaS API's freshly-minted NATS User JWT
// into OpenBao for External Secrets Operator to deliver to the saasapi
// Deployment. See docs/design/imas-internal-api-account.md's "JWT ->
// OpenBao hand-off".
//
// FLAG FOR SECURITY REVIEW: this is the only code in the repo that
// *writes* to OpenBao. The OpenBao identity it authenticates as (see
// EnvOpenBaoAuthMethod) must be a dedicated one, used only by that
// subcommand's Kubernetes Job, and must never be granted to farmer's
// long-running server process. deploy/farmer/README.md states the exact
// policy boundary.
//
// The client is internal/openbao (the official OpenBao Go client), which
// owns auth, TLS and error decoding for every server-side OpenBao
// identity; this package keeps the KV v2 paths and its own errors.
package openbaokv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/yogzblr/imas/internal/openbao"
)

// Environment variables configuring the OpenBao KV v2 client. Addr is
// always required; which of the rest matter depends on AuthMethod. Named
// IMAS_SAASAPI_CRED_OPENBAO_* rather than reusing internal/certs's
// IMAS_CERTS_OPENBAO_* or internal/gatewayjwt's IMAS_GATEWAY_OPENBAO_*:
// this is a distinct OpenBao identity (the only one with KV write access)
// and must never share an env block — or an auth role — with farmer's
// long-running process.
const (
	EnvOpenBaoAddr       = "IMAS_SAASAPI_CRED_OPENBAO_ADDR"
	EnvOpenBaoKVMount    = "IMAS_SAASAPI_CRED_OPENBAO_KV_MOUNT" // default "secret"
	EnvOpenBaoCACert     = "IMAS_SAASAPI_CRED_OPENBAO_CACERT"   // optional, verify OpenBao's own TLS
	EnvOpenBaoAuthMethod = "IMAS_SAASAPI_CRED_OPENBAO_AUTH_METHOD"

	// EnvOpenBaoToken is the bearer token used when AuthMethod is "token" (the default).
	EnvOpenBaoToken = "IMAS_SAASAPI_CRED_OPENBAO_TOKEN"

	// EnvOpenBaoK8sRole/EnvOpenBaoK8sMount/EnvOpenBaoK8sJWTPath configure
	// OpenBao's kubernetes auth method, used when AuthMethod is "kubernetes".
	EnvOpenBaoK8sRole    = "IMAS_SAASAPI_CRED_OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount   = "IMAS_SAASAPI_CRED_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvOpenBaoK8sJWTPath = "IMAS_SAASAPI_CRED_OPENBAO_K8S_JWT_PATH" // default openbao.DefaultK8sJWTPath

	// EnvOpenBaoNamespace optionally sets the X-Vault-Namespace header.
	EnvOpenBaoNamespace = "IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE"
)

// Recognized values for IMAS_SAASAPI_CRED_OPENBAO_AUTH_METHOD.
const (
	AuthMethodToken      = openbao.AuthMethodToken
	AuthMethodKubernetes = openbao.AuthMethodKubernetes
)

const defaultKVMount = "secret"

var openBaoEnv = openbao.Env{
	Addr:       EnvOpenBaoAddr,
	CACert:     EnvOpenBaoCACert,
	AuthMethod: EnvOpenBaoAuthMethod,
	Token:      EnvOpenBaoToken,
	K8sRole:    EnvOpenBaoK8sRole,
	K8sMount:   EnvOpenBaoK8sMount,
	K8sJWTPath: EnvOpenBaoK8sJWTPath,
	Namespace:  EnvOpenBaoNamespace,
}

var (
	ErrNotConfigured = errors.New("openbaokv: openbao kv client not configured")
	ErrInvalidPath   = errors.New("openbaokv: invalid kv path")
	ErrReadFailed    = errors.New("openbaokv: openbao kv read failed")
	ErrWriteFailed   = errors.New("openbaokv: openbao kv write failed")

	ErrK8sJWTUnavailable = errors.New("openbaokv: openbao kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("openbaokv: openbao kubernetes auth login failed")
)

// Client is a KV v2 client for GET and POST /v1/<mount>/data/<path>.
type Client struct {
	ob    *openbao.Client
	mount string // KV v2 secrets engine mount, default "secret"
}

// NewClientFromEnv builds a Client from the Env* variables above, read
// fresh on every call rather than cached at package init (tests change
// the environment to point at a local server).
func NewClientFromEnv() (*Client, error) {
	ob, err := openbao.NewFromEnv(openBaoEnv, openbao.Errors{
		NotConfigured:     ErrNotConfigured,
		K8sJWTUnavailable: ErrK8sJWTUnavailable,
		K8sAuthFailed:     ErrK8sAuthFailed,
	})
	if err != nil {
		return nil, err
	}
	mount := strings.Trim(os.Getenv(EnvOpenBaoKVMount), "/")
	if mount == "" {
		mount = defaultKVMount
	}
	if err := validatePath(mount); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNotConfigured, EnvOpenBaoKVMount, err)
	}
	return &Client{ob: ob, mount: mount}, nil
}

// Mount is the KV v2 mount this client reads and writes under.
func (c *Client) Mount() string { return c.mount }

// validatePath rejects a mount or secret path that is empty, has empty
// segments, or contains "." / ".." segments. OpenBao's policy language
// matches on the literal request path, so a path that a proxy or the
// server could normalize to something else is refused outright rather
// than escaped.
func validatePath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty", ErrInvalidPath)
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "":
			return fmt.Errorf("%w: %q has an empty segment", ErrInvalidPath, p)
		case ".", "..":
			return fmt.Errorf("%w: %q has a %q segment", ErrInvalidPath, p, seg)
		}
	}
	return nil
}

// dataPath is KV v2's data endpoint for secretPath under c.mount. The
// client escapes each segment when it builds the URL.
func (c *Client) dataPath(secretPath string) (string, error) {
	secretPath = strings.Trim(secretPath, "/")
	if err := validatePath(secretPath); err != nil {
		return "", err
	}
	return c.mount + "/data/" + secretPath, nil
}

type kvReadData struct {
	Data map[string]any `json:"data"`
}

// Read returns the latest version of the secret at secretPath, keeping
// only its string-valued fields. A secret that doesn't exist — or whose
// latest version is soft-deleted or destroyed, which KV v2 also answers
// with 404 — is reported as (nil, nil), not an error.
func (c *Client) Read(ctx context.Context, secretPath string) (map[string]string, error) {
	path, err := c.dataPath(secretPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	secret, err := c.ob.Read(ctx, path, nil)
	if openbao.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	var rd kvReadData
	if err := openbao.DecodeData(secret, &rd); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	if rd.Data == nil {
		return nil, nil
	}
	out := make(map[string]string, len(rd.Data))
	for k, v := range rd.Data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, nil
}

type kvWriteData struct {
	Version int `json:"version"`
}

// Write stores data as a new version of the secret at secretPath (KV v2
// POST /v1/<mount>/data/<path>), replacing every field of the previous
// version, and returns the version number OpenBao assigned.
func (c *Client) Write(ctx context.Context, secretPath string, data map[string]string) (int, error) {
	path, err := c.dataPath(secretPath)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	secret, err := c.ob.Post(ctx, path, map[string]any{"data": data})
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	var wd kvWriteData
	if err := openbao.DecodeData(secret, &wd); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	return wd.Version, nil
}

// Secret binds a Client to one secret path, for callers (such as
// pki.PublishSaaSAPICredential) that only ever read and write a single
// secret.
type Secret struct {
	c    *Client
	path string
}

// At returns a Secret for secretPath, validated up front so a bad path
// fails before anything is minted or sent.
func (c *Client) At(secretPath string) (*Secret, error) {
	secretPath = strings.Trim(secretPath, "/")
	if err := validatePath(secretPath); err != nil {
		return nil, err
	}
	return &Secret{c: c, path: secretPath}, nil
}

// Path is the secret path (relative to the client's mount).
func (s *Secret) Path() string { return s.path }

// Read is (*Client).Read at s's path.
func (s *Secret) Read(ctx context.Context) (map[string]string, error) {
	return s.c.Read(ctx, s.path)
}

// Write is (*Client).Write at s's path, discarding the version number.
func (s *Secret) Write(ctx context.Context, data map[string]string) error {
	_, err := s.c.Write(ctx, s.path, data)
	return err
}
