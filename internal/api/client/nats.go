package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/log"
)

// NatsConn is the shared NATS connection used by the CLI client.
var NatsConn *nats.Conn

// NatsRequestTimeout is the default timeout for NATS request/reply.
var NatsRequestTimeout = 30 * time.Second

// natsResponse is the envelope returned by NATS API handlers.
type natsResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// NewNatsClient creates a new NATS connection authenticated via NKey.
func NewNatsClient() (*nats.Conn, error) {
	URL := config.FarmerBusURL
	pubkey, err := auth.GetPubkey()
	if err != nil {
		return nil, err
	}
	auth.NewToken()
	rootCA := config.ImasRootCA
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(rootCA)
	if err != nil || rootPEM == nil {
		log.Panicf("nats: error loading or parsing rootCA file: %v", err)
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %q", rootCA)
	}
	connOpts := []nats.Option{nats.Name("imas-cli"), nats.Nkey(pubkey, auth.Sign), nats.Secure(busTLSConfig(certPool))}

	log.Tracef("Connecting to %s", URL)
	return nats.Connect(URL, connOpts...)
}

// busTLSConfig is the TLS config the CLI dials the bus with. It verifies
// the bus certificate against config.BusTLSServerName() — the explicit
// farmerbustlsservername, else the host of config.FarmerBusURL — not
// config.FarmerInterface, which need not be a name the bus cert carries
// once farmerbusurl points somewhere else.
func busTLSConfig(rootCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName: config.BusTLSServerName(),
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}
}

// ConnectNats establishes the shared NATS connection for the CLI.
func ConnectNats() error {
	nc, err := NewNatsClient()
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	NatsConn = nc
	return nil
}

// NatsRequest sends a request to a NATS API method and returns the result.
// The method is appended to "imas.api." to form the subject.
// params is marshaled to JSON; pass nil for no params.
// The local user's auth token is automatically injected into the JSON
// payload so the farmer can attribute the request to the invoking user.
func NatsRequest(method string, params any) (json.RawMessage, error) {
	if NatsConn == nil {
		return nil, fmt.Errorf("NATS connection not established")
	}

	subject := "imas.api." + method

	var data []byte
	if params != nil {
		var err error
		data, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal params: %w", err)
		}
	}

	// Inject the auth token into the JSON payload so the farmer can
	// identify the invoking user for attribution and RBAC checks.
	data = injectToken(data)

	msg, err := NatsConn.Request(subject, data, NatsRequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("NATS request to %s failed: %w", subject, err)
	}

	var resp natsResponse
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	return resp.Result, nil
}

// injectToken merges a "token" field into the JSON payload. If the
// payload is nil or empty, it creates a new JSON object with just
// the token. If the token cannot be generated, the payload is
// returned unchanged (the request will proceed unauthenticated).
func injectToken(data []byte) []byte {
	token, err := auth.NewToken()
	if err != nil {
		return data
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return data
	}

	if len(data) == 0 {
		return []byte(fmt.Sprintf(`{"token":%s}`, tokenJSON))
	}

	// Inject token into existing JSON object by replacing the opening
	// brace with an opening brace + token field. This avoids
	// unmarshaling/remarshaling the entire payload.
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		// Avoid emitting a trailing comma for an empty object ({}), which
		// would produce invalid JSON like {"token":"...",}.
		if rest := bytes.TrimLeft(trimmed[1:], " \t\r\n"); len(rest) > 0 && rest[0] == '}' {
			return append([]byte(fmt.Sprintf(`{"token":%s`, tokenJSON)), rest...)
		}
		return append([]byte(fmt.Sprintf(`{"token":%s,`, tokenJSON)), trimmed[1:]...)
	}

	return data
}
