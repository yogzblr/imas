package pki

// Sprout-side bus connection: which addresses a sprout dials, and the TLS
// and auth options it dials them with. cmd/sprout's ConnectSprout and the
// real-Envoy e2e test both connect through LoadSproutBus, so the test
// exercises the production path.
//
// FLAG FOR SECURITY REVIEW. This is the sprout-to-bus authentication path.
//
//   - Addresses come from, in order: the sprout config's "busurls" pin
//     (config.BusURLs); the nats_urls farmer returned at enrollment,
//     persisted by PersistEnrollment (config.SproutBusURLsFile); and
//     only when neither exists, the legacy config.FarmerBusURL
//     (farmerinterface:farmerbusport, dialled as TLS NATS). A pinned or
//     persisted list that fails ValidateBusURLs is an error, never a
//     silent fallback to FarmerBusURL.
//   - Every connection is TLS, verified against SproutRootCA only.
//     ValidateBusURLs accepts only wss://, tls:// and nats:// (the last
//     upgraded to TLS by nats.Secure, which refuses a server that doesn't
//     offer it), never ws://, and no userinfo, since URL credentials
//     would be sent in place of the User JWT.
//   - The TLS ServerName is left empty, so nats.go verifies each server
//     against the host of the URL it dialled, not a single FarmerInterface
//     name that the DMZ addresses don't carry.
//   - For a pinned or enrolled list, servers the bus advertises in INFO
//     are ignored (nats.IgnoreDiscoveredServers): they are the cluster's
//     internal addresses, which would bypass Envoy, and the sprout should
//     only dial addresses it was configured or enrolled with.
//   - Auth is unchanged: the NATS User JWT plus the NKey seed signing the
//     CONNECT nonce, and on ws(s):// the gateway JWT as a bearer token on
//     each websocket handshake (GatewayJWTHeaders), which Envoy's
//     jwt_authn checks.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
)

// BusURLSource says where a sprout's bus addresses came from.
type BusURLSource string

const (
	BusURLsFromConfig     BusURLSource = "sprout config (busurls)"
	BusURLsFromEnrollment BusURLSource = "enrollment (nats_urls)"
	BusURLsFromLegacy     BusURLSource = "legacy farmerinterface:farmerbusport"
)

// Bounds on a bus URL list, so a bad enrollment response can't persist
// something unbounded.
const (
	maxBusURLs      = 32
	maxBusURLLength = 2048
)

// ValidateBusURLs checks a list of bus addresses a sprout may dial and
// returns them trimmed. Each must be a wss://, tls:// or nats:// URL with
// a host, and no userinfo, query or fragment; only wss:// may carry a
// path. Websocket and plain NATS URLs can't be mixed, which nats.go
// refuses too. An empty list is valid and returned as nil.
func ValidateBusURLs(urls []string) ([]string, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	if len(urls) > maxBusURLs {
		return nil, fmt.Errorf("pki: %d bus URLs, more than the %d allowed", len(urls), maxBusURLs)
	}
	out := make([]string, 0, len(urls))
	var ws, nonWS bool
	for _, raw := range urls {
		s := strings.TrimSpace(raw)
		if s == "" {
			return nil, errors.New("pki: empty bus URL")
		}
		if len(s) > maxBusURLLength {
			return nil, fmt.Errorf("pki: bus URL longer than %d bytes", maxBusURLLength)
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("pki: bus URL %q: %w", s, err)
		}
		switch strings.ToLower(u.Scheme) {
		case "wss":
			ws = true
		case "tls", "nats":
			nonWS = true
			if u.Path != "" && u.Path != "/" {
				return nil, fmt.Errorf("pki: bus URL %q: only wss:// URLs may have a path", s)
			}
		case "ws":
			return nil, fmt.Errorf("pki: bus URL %q: ws:// is not allowed, use wss://", s)
		default:
			return nil, fmt.Errorf("pki: bus URL %q: scheme must be wss, tls or nats", s)
		}
		if u.Opaque != "" || u.Hostname() == "" {
			return nil, fmt.Errorf("pki: bus URL %q has no host", s)
		}
		if u.User != nil {
			return nil, fmt.Errorf("pki: bus URL %q must not carry credentials", redactURL(u))
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("pki: bus URL %q must not have a query or fragment", s)
		}
		out = append(out, s)
	}
	if ws && nonWS {
		return nil, errors.New("pki: bus URLs mix wss:// with tls:// or nats://")
	}
	return out, nil
}

func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	return c.String()
}

// persistBusURLs writes enrollment's nats_urls to config.SproutBusURLsFile,
// or removes that file when farmer returned none, so what is on disk is
// always what the last enrollment said. urls must already have passed
// ValidateBusURLs.
func persistBusURLs(urls []string) error {
	path := config.SproutBusURLsFile
	if path == "" {
		return errors.New("pki: sproutbusurlsfile is not configured")
	}
	if len(urls) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("pki: removing stale bus URLs: %w", err)
		}
		return nil
	}
	b, err := json.Marshal(urls)
	if err != nil {
		return fmt.Errorf("pki: encoding bus URLs: %w", err)
	}
	if err := writeFileAtomic(path, b, 0o644); err != nil {
		return fmt.Errorf("pki: persisting bus URLs: %w", err)
	}
	return nil
}

// loadPersistedBusURLs returns the bus URLs persisted at enrollment, or
// nil if there are none.
func loadPersistedBusURLs() ([]string, error) {
	path := config.SproutBusURLsFile
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pki: reading persisted bus URLs: %w", err)
	}
	var urls []string
	if err := json.Unmarshal(b, &urls); err != nil {
		return nil, fmt.Errorf("pki: %s is not a JSON list of bus URLs: %w", path, err)
	}
	urls, err = ValidateBusURLs(urls)
	if err != nil {
		return nil, fmt.Errorf("pki: persisted bus URLs in %s: %w", path, err)
	}
	return urls, nil
}

// ResolveSproutBusURLs returns the bus addresses a sprout connects to and
// where they came from: the "busurls" pin if set, else the nats_urls
// persisted at enrollment, else the legacy FarmerBusURL.
func ResolveSproutBusURLs() ([]string, BusURLSource, error) {
	if len(config.BusURLs) > 0 {
		urls, err := ValidateBusURLs(config.BusURLs)
		if err != nil {
			return nil, "", fmt.Errorf("pki: sprout config busurls: %w", err)
		}
		return urls, BusURLsFromConfig, nil
	}
	urls, err := loadPersistedBusURLs()
	if err != nil {
		return nil, "", err
	}
	if len(urls) > 0 {
		return urls, BusURLsFromEnrollment, nil
	}
	if config.FarmerBusURL == "" {
		return nil, "", errors.New("pki: no bus URL: none enrolled, none pinned (busurls), and no farmerinterface/farmerbusport")
	}
	return []string{config.FarmerBusURL}, BusURLsFromLegacy, nil
}

// SproutBus is what a sprout connects to the bus with.
type SproutBus struct {
	Servers []string
	Source  BusURLSource
	// Options are the TLS and auth options; Connect appends its callers'.
	Options []nats.Option
	// UserJWT is the NATS User JWT in Options, so callers can check its
	// grants (e.g. SproutUserJWTGrantsLogs) against the one actually sent,
	// not a newer one a refresh has since written to disk.
	UserJWT string
}

// LoadSproutBus resolves the sprout's bus addresses
// (ResolveSproutBusURLs) and builds its connection options from the
// persisted NATS User JWT, the NKey seed and SproutRootCA.
func LoadSproutBus() (*SproutBus, error) {
	servers, source, err := ResolveSproutBusURLs()
	if err != nil {
		return nil, err
	}
	// Operator-mode nats-server needs the NATS User JWT from enrollment
	// alongside the NKey seed that signs the CONNECT nonce.
	userJWT, err := LoadSproutUserJWT()
	if err != nil {
		return nil, fmt.Errorf("pki: loading NATS User JWT: %w", err)
	}
	seed, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		return nil, fmt.Errorf("pki: loading NKey seed: %w", err)
	}
	rootPEM, err := os.ReadFile(config.SproutRootCA)
	if err != nil {
		return nil, fmt.Errorf("pki: loading sprout root CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("pki: no certificate in sprout root CA %q", config.SproutRootCA)
	}
	tlsConfig := &tls.Config{
		// No ServerName: nats.go verifies each server against the host
		// of the URL it dialled.
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	opts := []nats.Option{
		nats.Secure(tlsConfig),
		nats.UserJWTAndSeed(userJWT, strings.TrimSpace(string(seed))),
		// Presents the current gateway JWT to Envoy's jwt_authn on each
		// websocket handshake. Only consulted for ws(s):// URLs.
		nats.WebSocketConnectionHeadersHandler(GatewayJWTHeaders),
	}
	if source != BusURLsFromLegacy {
		opts = append(opts, nats.IgnoreDiscoveredServers())
	}
	return &SproutBus{Servers: servers, Source: source, Options: opts, UserJWT: userJWT}, nil
}

// Connect dials b.Servers with b.Options followed by extra.
func (b *SproutBus) Connect(extra ...nats.Option) (*nats.Conn, error) {
	opts := append(append([]nats.Option{}, b.Options...), extra...)
	return nats.Connect(strings.Join(b.Servers, ","), opts...)
}
