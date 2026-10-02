package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// maxPackageBytes caps a downloaded package. A sprout package is a
	// few tens of MB; this only stops an endless response filling the
	// disk.
	maxPackageBytes = 512 << 20
	downloadTimeout = 15 * time.Minute
	maxRedirects    = 10
	maxRepoURLLen   = 2048
	// repoUser is the basic-auth user name sent with the repo token: the
	// one the Ansible role gives apt, yum and zypper for a private
	// Buildkite registry.
	repoUser = "buildkite"
)

// repoRootCAs is the trust root for the repository host. nil, always in
// production, means the OS trust store: the repo is an external host, so
// SproutRootCA (which only issued farmer's, or the DMZ edge's,
// certificate) is deliberately not used for it (design doc §1.8). Tests
// set it to trust their local HTTPS server.
var repoRootCAs *x509.CertPool

// repoFileURL builds the download URL for fileName under the configured
// repository base URL: <base>/<fileName>. base must be an absolute https
// URL with no user info, query or fragment. fileName is a signed,
// validated manifest file name (a single path component of
// [A-Za-z0-9._+~-]), so it needs no escaping and can't leave the base
// path.
func repoFileURL(base, fileName string) (string, error) {
	if base == "" {
		return "", ErrRepoNotConfigured
	}
	u, err := url.Parse(base)
	switch {
	case err != nil, len(base) > maxRepoURLLen,
		strings.ContainsFunc(base, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "", fmt.Errorf("%w: sproutupdaterepourl is not a valid URL", ErrRepoNotConfigured)
	case u.Scheme != "https" || u.Host == "":
		return "", fmt.Errorf("%w: sproutupdaterepourl must be an https URL", ErrRepoNotConfigured)
	case u.User != nil:
		return "", fmt.Errorf("%w: sproutupdaterepourl must not carry credentials; use sproutupdaterepotoken", ErrRepoNotConfigured)
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return "", fmt.Errorf("%w: sproutupdaterepourl must not have a query or fragment", ErrRepoNotConfigured)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + fileName
	u.RawPath = ""
	return u.String(), nil
}

// repoClient downloads from the repository: TLS verified against the OS
// trust store (repoRootCAs), the environment's proxy settings
// (HTTPS_PROXY/NO_PROXY, as for the sprout's other HTTP clients), and
// https-only redirects.
func repoClient() *http.Client {
	return &http.Client{
		Timeout: downloadTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{RootCAs: repoRootCAs, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing a redirect to non-https %s", req.URL.Redacted())
			}
			// net/http already drops Authorization on a redirect to another
			// domain; drop it on any change of host, so the repo token only
			// ever goes to the configured repository host.
			if req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}

// download fetches rawURL into dest (which must not exist) and checks its
// SHA-256 against wantSHA256, the signed manifest's checksum. The file is
// removed again on any error, so a file left at dest has exactly the
// signed bytes. The request carries the repo token if one is configured,
// and nothing else: no sprout JWT.
func download(ctx context.Context, rawURL, token, dest, wantSHA256 string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("selfupdate: building download request: %w", err)
	}
	if token != "" {
		req.SetBasicAuth(repoUser, token)
	}
	resp, err := repoClient().Do(req)
	if err != nil {
		return fmt.Errorf("selfupdate: downloading %s: %w", redact(rawURL), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("selfupdate: downloading %s: HTTP %d", redact(rawURL), resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("selfupdate: creating %s: %w", dest, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("selfupdate: writing %s: %w", dest, cerr)
		}
		if err != nil {
			os.Remove(dest)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxPackageBytes+1))
	if err != nil {
		return fmt.Errorf("selfupdate: downloading %s: %w", redact(rawURL), err)
	}
	if n > maxPackageBytes {
		return fmt.Errorf("selfupdate: %s is larger than %d bytes", redact(rawURL), maxPackageBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
		return fmt.Errorf("%w: got %s, signed %s", ErrChecksumMismatch, got, wantSHA256)
	}
	return f.Sync()
}

// redact drops anything but scheme, host and path from a URL for
// messages. Repo URLs carry no credentials (repoFileURL refuses them), so
// this is belt and braces.
func redact(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid URL>"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}
