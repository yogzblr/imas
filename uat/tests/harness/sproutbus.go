package harness

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// What an enrolled sprout publishes to farmer (brief W1, U1): its facts
// report and its cook step events, sealed from its box key to the
// tenant's key (security review P6, unit U3), or, to show farmer refuses
// them, in plaintext as a sprout built before U3 would send them.

// FactsSubject is a sprout's facts subject (cmd/sprout factsloop.go).
func FactsSubject(sproutID string) string { return "imas.sprouts." + sproutID + ".facts" }

// StepEventSubject is where a sprout publishes job jid's step events
// (internal/cook StepEventSubject).
func StepEventSubject(sproutID, jid string) string { return "imas.cook." + sproutID + "." + jid }

// ConnectThroughEnvoy opens a bus connection as the enrolled sprout e, the
// way a sprout does (internal/pki LoadSproutBus): wss:// to Envoy's
// listener at envoyURL (the runner's EnvoyURL, https://<dmz>:8443), the
// gateway JWT as the bearer token of the websocket handshake (Envoy's
// jwt_authn), the User JWT with the NKey signing the server's nonce. TLS
// is verified against pool for envoyURL's host. The caller closes it.
func (e *Enrolment) ConnectThroughEnvoy(ctx context.Context, envoyURL string, pool *x509.CertPool) (*nats.Conn, error) {
	if e.userJWT == "" || e.gatewayJWT == "" {
		return nil, errors.New("the sprout has no User JWT or gateway JWT: enrol it in full first")
	}
	u, err := url.Parse(envoyURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("Envoy URL %q: %v", envoyURL, err)
	}
	seed, err := e.Seed()
	if err != nil {
		return nil, err
	}
	timeout := 20 * time.Second
	if d, ok := ctx.Deadline(); ok && time.Until(d) < timeout {
		timeout = time.Until(d)
	}
	gw := e.gatewayJWT
	return nats.Connect("wss://"+u.Host+"/",
		nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}),
		nats.UserJWTAndSeed(e.userJWT, string(seed)),
		nats.WebSocketConnectionHeadersHandler(func() (http.Header, error) {
			return http.Header{"Authorization": {"Bearer " + gw}}, nil
		}),
		nats.IgnoreDiscoveredServers(),
		nats.Name("imas-uat-sprout"),
		nats.Timeout(timeout),
		nats.NoReconnect(),
	)
}

// Facts is a facts report naming e, with marker as its hostname so a
// test can tell its report from any other in farmer's props.
func (e *Enrolment) Facts(marker string) facts.SystemFacts {
	return facts.SystemFacts{OS: "linux", Arch: "amd64", Hostname: marker, GoVersion: "go-uat", NumCPU: 1,
		IPAddresses: []string{"192.0.2.10"}, KernelArch: "amd64", SproutID: e.SproutID}
}

// tenantKey is the tenant's X25519 public key e pinned at enrolment.
func (e *Enrolment) tenantKey() (*[32]byte, error) {
	b, err := base64.StdEncoding.DecodeString(e.tenantPub)
	if err != nil || len(b) != 32 {
		return nil, errors.New("the enrolment named no tenant X25519 key")
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}

// SealedFacts is f sealed as the sprout seals it: purpose s2f.facts, from
// e's box key to the tenant's key, with the payloadbox header.
func (e *Enrolment) SealedFacts(f facts.SystemFacts) (*nats.Msg, error) {
	return e.sealedFactsWith(f, e.boxPriv)
}

// ForgedSealedFacts is f sealed the same way under a box key that isn't
// the sprout's: what anyone else on the bus could make.
func (e *Enrolment) ForgedSealedFacts(f facts.SystemFacts) (*nats.Msg, error) {
	var other [32]byte
	if _, err := rand.Read(other[:]); err != nil {
		return nil, err
	}
	return e.sealedFactsWith(f, &other)
}

func (e *Enrolment) sealedFactsWith(f facts.SystemFacts, priv *[32]byte) (*nats.Msg, error) {
	tk, err := e.tenantKey()
	if err != nil {
		return nil, err
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeFacts, e.TenantID, e.SproutID, "", f)
	if err != nil {
		return nil, err
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tk, Priv: priv}})
	if err != nil {
		return nil, err
	}
	m := nats.NewMsg(FactsSubject(e.SproutID))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m, nil
}

// PlaintextFacts is f as a sprout built before sealed facts sends it: the
// JSON report with no payloadbox header.
func (e *Enrolment) PlaintextFacts(f facts.SystemFacts) (*nats.Msg, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	m := nats.NewMsg(FactsSubject(e.SproutID))
	m.Data = b
	return m, nil
}

// PlaintextStepEvent is a step event of job jid as a sprout built before
// sealed step events sends it: the step completion as JSON, with no
// payloadbox header.
func (e *Enrolment) PlaintextStepEvent(jid, stepID string) *nats.Msg {
	b, _ := json.Marshal(map[string]any{"ID": stepID, "CompletionStatus": 0, "ChangesMade": true, "Changes": []string{"uat"}})
	m := nats.NewMsg(StepEventSubject(e.SproutID, jid))
	m.Data = b
	return m
}

// Publish publishes m on nc and flushes, so the server has it before the
// call returns.
func Publish(nc *nats.Conn, m *nats.Msg) error {
	if err := nc.PublishMsg(m); err != nil {
		return err
	}
	return nc.FlushTimeout(10 * time.Second)
}
