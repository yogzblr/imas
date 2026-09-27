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
//   - With the sprout config's "busproxyurl" (config.BusProxyURL) set,
//     every bus address is dialled through that proxy (busProxyDialer):
//     an HTTP CONNECT tunnel or SOCKS5. nats.go dials every transport
//     (wss://, tls://, nats://) through its CustomDialer and layers TLS
//     and the websocket upgrade on the conn it returns, so the proxy
//     only relays bytes and never sees plaintext bus traffic; TLS is
//     still verified against SproutRootCA and the URL's host. The
//     proxy's own credentials, if any, are the URL's userinfo, sent only
//     to the proxy (Proxy-Authorization or SOCKS5 username/password).
//     HTTP_PROXY/HTTPS_PROXY/NO_PROXY, which the sprout's HTTP clients
//     honour, do not apply to the bus.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"golang.org/x/net/proxy"

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

// Bounds on a bus proxy URL. maxProxyCredentialLength is SOCKS5's
// (RFC 1929) limit on each of the username and password, applied to
// http:// too.
const (
	maxBusProxyURLLength     = 2048
	maxProxyCredentialLength = 255
)

// ValidateBusProxyURL checks the "busproxyurl" a sprout dials the bus
// through and returns it parsed, or nil for an empty one. It must be an
// http:// (HTTP CONNECT) or socks5:// URL with a host and an explicit
// port, and no path, query or fragment. Userinfo is allowed, since both
// schemes define it as the proxy's own credentials (HTTP Basic, SOCKS5
// username/password), but must have a username; error messages never
// echo it.
func ValidateBusProxyURL(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	if len(s) > maxBusProxyURLLength {
		return nil, fmt.Errorf("pki: bus proxy URL longer than %d bytes", maxBusProxyURLLength)
	}
	u, err := url.Parse(s)
	if err != nil {
		// url.Error quotes the input, which may carry a password.
		return nil, errors.New("pki: bus proxy URL is not a valid URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "socks5":
	default:
		return nil, fmt.Errorf("pki: bus proxy URL %q: scheme must be http or socks5", redactURL(u))
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return nil, fmt.Errorf("pki: bus proxy URL %q has no host", redactURL(u))
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("pki: bus proxy URL %q must have a port", redactURL(u))
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("pki: bus proxy URL %q must not have a path", redactURL(u))
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("pki: bus proxy URL %q must not have a query or fragment", redactURL(u))
	}
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		switch {
		case user == "":
			return nil, fmt.Errorf("pki: bus proxy URL %q: credentials without a username", redactURL(u))
		case strings.Contains(user, ":"):
			// HTTP Basic can't carry it: the first ':' ends the username.
			return nil, fmt.Errorf("pki: bus proxy URL %q: username contains ':'", redactURL(u))
		case len(user) > maxProxyCredentialLength || len(pass) > maxProxyCredentialLength:
			return nil, fmt.Errorf("pki: bus proxy URL %q: username or password longer than %d bytes", redactURL(u), maxProxyCredentialLength)
		}
	}
	u.Path = ""
	return u, nil
}

// busProxyDialer is the nats.CustomDialer a sprout dials the bus with when
// busproxyurl is set. nats.go hands it "host:port" of the bus URL it is
// connecting to (unresolved, see nats.SkipHostLookup in LoadSproutBus)
// and then runs TLS, and for wss:// the websocket upgrade, over the conn
// it returns, so the proxy sees only the target address and ciphertext.
type busProxyDialer struct {
	proxy *url.URL
	// timeout bounds the whole dial, proxy handshake included. SproutBus.
	// Connect sets it to the connection's nats.Timeout.
	timeout time.Duration
}

var _ nats.CustomDialer = (*busProxyDialer)(nil)

func (d *busProxyDialer) Dial(network, addr string) (net.Conn, error) {
	ctx := context.Background()
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	var (
		conn net.Conn
		err  error
	)
	switch d.proxy.Scheme {
	case "socks5":
		conn, err = d.dialSOCKS5(ctx, network, addr)
	case "http":
		conn, err = d.dialHTTPConnect(ctx, network, addr)
	default:
		err = fmt.Errorf("unsupported scheme %q", d.proxy.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("pki: dialling %s through bus proxy %s: %w", addr, redactURL(d.proxy), err)
	}
	return conn, nil
}

func (d *busProxyDialer) dialSOCKS5(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if d.proxy.User != nil {
		pass, _ := d.proxy.User.Password()
		auth = &proxy.Auth{User: d.proxy.User.Username(), Password: pass}
	}
	// A hostname addr is sent to the proxy as a domain name, so the proxy
	// resolves it.
	s, err := proxy.SOCKS5("tcp", d.proxy.Host, auth, &net.Dialer{})
	if err != nil {
		return nil, err
	}
	cd, ok := s.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not take a context")
	}
	return cd.DialContext(ctx, network, addr)
}

func (d *busProxyDialer) dialHTTPConnect(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, d.proxy.Host)
	if err != nil {
		return nil, err
	}
	// Unblock the handshake below when ctx ends, not just at its deadline.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if u := d.proxy.User; u != nil {
		pass, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy refused CONNECT: %s", resp.Status)
	}
	if !stop() {
		conn.Close()
		return nil, ctx.Err()
	}
	conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		// The bus spoke first (a tls:// or nats:// server's INFO) and
		// its bytes arrived with the proxy's response: keep them.
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn reads what an HTTP CONNECT exchange had already buffered
// before reading the tunnel itself.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// busProxyTimeout is appended after every caller option in
// SproutBus.Connect, so the proxy dialer's timeout is the connection's
// final nats.Timeout (nats.go only applies that to its own *net.Dialer).
func busProxyTimeout(o *nats.Options) error {
	if d, ok := o.CustomDialer.(*busProxyDialer); ok {
		c := *d
		c.timeout = o.Timeout
		o.CustomDialer = &c
	}
	return nil
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
	// Proxy is the busproxyurl every server is dialled through, without
	// its credentials, or empty when the sprout dials directly.
	Proxy string
	// Options are the TLS, auth and proxy options; Connect appends its
	// callers'.
	Options []nats.Option
	// UserJWT is the NATS User JWT in Options, so callers can check its
	// grants (e.g. SproutUserJWTGrantsLogs) against the one actually sent,
	// not a newer one a refresh has since written to disk.
	UserJWT string
}

// LoadSproutBus resolves the sprout's bus addresses
// (ResolveSproutBusURLs) and builds its connection options from the
// persisted NATS User JWT, the NKey seed and SproutRootCA, dialling
// through config.BusProxyURL when it is set.
func LoadSproutBus() (*SproutBus, error) {
	servers, source, err := ResolveSproutBusURLs()
	if err != nil {
		return nil, err
	}
	proxyURL, err := ValidateBusProxyURL(config.BusProxyURL)
	if err != nil {
		return nil, fmt.Errorf("pki: sprout config busproxyurl: %w", err)
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
	bus := &SproutBus{Servers: servers, Source: source, Options: opts, UserJWT: userJWT}
	if proxyURL != nil {
		bus.Proxy = redactURL(proxyURL)
		bus.Options = append(bus.Options,
			nats.SetCustomDialer(&busProxyDialer{proxy: proxyURL}),
			// Hand the dialer the bus hostname rather than addresses
			// resolved here: the proxy resolves it, as a sprout behind
			// one may have no DNS for the bus, and an HTTP proxy's
			// allowlist usually names hosts.
			nats.SkipHostLookup(),
		)
	}
	return bus, nil
}

// Connect dials b.Servers with b.Options followed by extra.
func (b *SproutBus) Connect(extra ...nats.Option) (*nats.Conn, error) {
	opts := append(append([]nats.Option{}, b.Options...), extra...)
	opts = append(opts, busProxyTimeout)
	return nats.Connect(strings.Join(b.Servers, ","), opts...)
}
