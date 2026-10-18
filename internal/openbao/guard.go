package openbao

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// The guards in this file are shared with the sprout-side sdb://openbao
// provider (internal/ingredients/sdb/openbao), which builds its own
// official client but must refuse the same addresses, redirects and
// paths.

// ErrInvalidPath is a path refused by ValidatePath or ValidateMountPath.
var ErrInvalidPath = errors.New("openbao: invalid path")

// ErrOtherHost is a request, normally a redirect the official client
// follows, to a scheme, host or port other than the configured address.
// It is refused before anything is sent.
var ErrOtherHost = errors.New("openbao: refusing a request to a host other than the configured address")

// reservedFirstSegments are the API trees a secret path must never
// reach: auth methods (logins, token lookup), system backends and the
// identity store. A ref that starts with one of them is not a secret.
var reservedFirstSegments = []string{"auth", "sys", "identity"}

// CheckAddr accepts an https:// address with a host, and an http:// one
// only when allowInsecure is true. addrName and allowName are the
// settings that hold them (an environment variable, or a chart value),
// so the refusal says what to change.
func CheckAddr(addr, addrName, allowName string, allowInsecure bool) error {
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("%s=%q is not a URL: %w", addrName, addr, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowInsecure {
			return fmt.Errorf("%s=%q is plain http://, which would send OpenBao tokens and secrets unencrypted: use https://, or set %s=true (tests and throwaway installs only)",
				addrName, addr, allowName)
		}
	default:
		return fmt.Errorf("%s=%q must be an https:// URL", addrName, addr)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%s=%q has no host", addrName, addr)
	}
	return nil
}

// PinTransport wraps base so that it sends a request only to addr's
// scheme, host and port (default ports made explicit, host names
// compared case-insensitively). Anything else, which can only be a
// redirect the official client is following, fails with ErrOtherHost
// without a connection being made: the token, the body and a client
// certificate never reach another host. The official client follows at
// most one redirect, so a redirect on the configured host is one hop.
func PinTransport(base http.RoundTripper, addr string) (http.RoundTripper, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	want, ok := canonicalOrigin(u)
	if !ok {
		return nil, fmt.Errorf("address %q has no https or http host", addr)
	}
	return &pinnedTransport{base: base, origin: want}, nil
}

type pinnedTransport struct {
	base   http.RoundTripper
	origin string
}

func (p *pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if got, ok := canonicalOrigin(req.URL); !ok || got != p.origin {
		// A RoundTripper must close the body, even on error.
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("%w: %s, configured %s", ErrOtherHost, originForError(req.URL), p.origin)
	}
	return p.base.RoundTrip(req)
}

// CloseIdleConnections passes through, so http.Client.CloseIdleConnections
// still reaches the pooled transport.
func (p *pinnedTransport) CloseIdleConnections() {
	if c, ok := p.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// canonicalOrigin is "scheme://host:port" with the scheme and host
// lower-cased and the scheme's default port filled in.
func canonicalOrigin(u *url.URL) (string, bool) {
	if u == nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch scheme {
	case "https":
		if port == "" {
			port = "443"
		}
	case "http":
		if port == "" {
			port = "80"
		}
	default:
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	return scheme + "://" + net.JoinHostPort(host, port), true
}

// originForError names where a refused request was going, without its
// path or query (which could carry a secret path).
func originForError(u *url.URL) string {
	if o, ok := canonicalOrigin(u); ok {
		return o
	}
	if u == nil {
		return "<nil>"
	}
	return u.Scheme + "://" + u.Host
}

// ValidatePath refuses a secret path that is empty or has a segment
// that is empty, "." or "..", or that decodes to one of those or to
// something with a "/" when percent-decoded (once or more). OpenBao's
// policies match the literal request path, and the official client
// builds the URL with path.Join, which resolves "..": a path that could
// be normalised into another one is refused, not escaped.
func ValidatePath(p string) error {
	return validatePath(p, false)
}

// ValidateMountPath is ValidatePath for a path that starts at a mount,
// so its first segment also must not be auth, sys or identity (in any
// case, percent-encoded or not).
func ValidateMountPath(p string) error {
	return validatePath(p, true)
}

func validatePath(p string, mount bool) error {
	if p == "" {
		return fmt.Errorf("%w: empty", ErrInvalidPath)
	}
	for i, seg := range strings.Split(p, "/") {
		if seg == "" {
			return fmt.Errorf("%w: %q has an empty segment", ErrInvalidPath, p)
		}
		// Check the segment as given, then each percent-decoding of it
		// until decoding changes nothing (or fails: then it is literal).
		cur := seg
		for {
			switch {
			case cur == "", cur == ".", cur == "..":
				return fmt.Errorf("%w: %q has a %q segment", ErrInvalidPath, p, seg)
			case strings.ContainsAny(cur, "/\\"):
				return fmt.Errorf("%w: %q has a segment %q that decodes to a path separator", ErrInvalidPath, p, seg)
			}
			if mount && i == 0 {
				for _, r := range reservedFirstSegments {
					if strings.EqualFold(cur, r) {
						return fmt.Errorf("%w: %q starts with %q, which is not a secrets mount", ErrInvalidPath, p, seg)
					}
				}
			}
			next, err := url.PathUnescape(cur)
			if err != nil || next == cur {
				break
			}
			cur = next
		}
	}
	return nil
}
