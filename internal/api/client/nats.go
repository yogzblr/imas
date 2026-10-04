package client

// The imas CLI's end of the farmer API on the bus
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", Decision A, J.3). FLAG FOR SECURITY REVIEW.
//
// Every imas.api.<method> request is a payloadbox c2f.api Call sealed from
// this CLI's box key to the tenant box key it pins (tenantboxpub, with
// tenantid; internal/pki's cliboxclient.go), bound to the method and the
// subject, with the user's NKey public key in the Imas-Principal header.
// Farmer works out who sent it from the registered box key the request
// opens under, never from anything in the request. Every reply must be
// an f2c.api Reply that opens under this CLI's key and names this
// request's ID: a plaintext reply is an error, never a result, and so is
// one that doesn't open.
//
// The NKey authenticates the bus connection (nats.Nkey) and signs nothing
// else. There are no bearer tokens: the bus chooses the nonce the NKey
// signs, so any credential built from an NKey signature is one the bus
// can mint.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// NatsConn is the shared NATS connection used by the CLI client.
var NatsConn *nats.Conn

// NatsRequestTimeout is the default timeout for NATS request/reply.
var NatsRequestTimeout = 30 * time.Second

// ErrPlaintextReply: a reply to a sealed request came back without the
// payloadbox marker. The CLI never reads a plaintext reply as a result:
// anything on the bus could have written it.
var ErrPlaintextReply = errors.New("farmer's reply wasn't sealed; refusing it")

// ErrReplyDidNotOpen: a sealed reply didn't open under this CLI's box key,
// or wasn't the reply to this request (another request's, another
// method's, or forged).
var ErrReplyDidNotOpen = errors.New("farmer's reply didn't open under this CLI's box key, or answered another request; refusing it")

// RefusedError is farmer's refusal of a sealed request before any handler
// ran: a fixed payloadbox.ErrorHeader code, with no detail on the wire.
type RefusedError struct{ Code string }

func (e *RefusedError) Error() string {
	switch e.Code {
	case payloadbox.ErrorCodeOpenFailed:
		return "farmer refused the request (open-failed): it didn't open under a CLI box key registered for this user, or it was stale or a replay. Check tenantboxpub, tenantid and that an admin registered your key (imas auth keygen)"
	case payloadbox.ErrorCodeEncryptionRequired:
		return "farmer refused the request (encryption-required)"
	default:
		return fmt.Sprintf("farmer refused the request (%s)", e.Code)
	}
}

// NewNatsClient creates a new NATS connection authenticated via NKey.
// The NKey signs the server's nonce and nothing else.
func NewNatsClient() (*nats.Conn, error) {
	URL := config.FarmerBusURL
	pubkey, err := auth.GetPubkey()
	if err != nil {
		return nil, err
	}
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

// NatsRequest sends a sealed request for method (subject
// "imas.api.<method>") with params, and returns the result from farmer's
// sealed reply. params is JSON-marshalled; pass nil for none (a
// json.RawMessage is sent as is). A handler's error comes back inside the
// sealed reply and is returned as an error; a refusal before any handler
// ran is a *RefusedError. A reply that isn't sealed, doesn't open, or
// answers another request is an error, never a result.
func NatsRequest(method string, params any) (json.RawMessage, error) {
	return SealedRequest(NatsConn, payloadbox.PurposeCLIRequest, method, params, NatsRequestTimeout)
}

// SealedRequest is NatsRequest on nc, under purpose (c2f.api, or a
// method's own c2f purpose), with timeout.
func SealedRequest(nc *nats.Conn, purpose, method string, params any, timeout time.Duration) (json.RawMessage, error) {
	if nc == nil {
		return nil, fmt.Errorf("NATS connection not established")
	}
	if b, ok := params.([]byte); ok {
		// A []byte would marshal as a base64 string, not as the JSON it
		// holds: send it as the JSON it is.
		params = json.RawMessage(b)
	}
	data, id, principal, err := pki.CLISealRequest(purpose, method, params)
	if err != nil {
		return nil, err
	}
	subject := pki.CLIAPISubjectPrefix + method
	msg := nats.NewMsg(subject)
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Header.Set(payloadbox.PrincipalHeader, principal)
	msg.Data = data
	resp, err := nc.RequestMsg(msg, timeout)
	if err != nil {
		return nil, fmt.Errorf("NATS request to %s failed: %w", subject, err)
	}
	return openReply(method, id, resp)
}

// openReply turns farmer's answer to request id into a result.
func openReply(method, id string, resp *nats.Msg) (json.RawMessage, error) {
	if code := resp.Header.Get(payloadbox.ErrorHeader); code != "" {
		return nil, &RefusedError{Code: code}
	}
	if resp.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, ErrPlaintextReply
	}
	body, err := pki.CLIOpenReply(method, id, resp.Data)
	if err != nil {
		if errors.Is(err, payloadbox.ErrOpen) {
			return nil, ErrReplyDidNotOpen
		}
		return nil, err
	}
	if body.Error != "" {
		return nil, errors.New(body.Error)
	}
	return body.Result, nil
}
