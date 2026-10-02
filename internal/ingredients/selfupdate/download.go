package selfupdate

import (
	"archive/zip"
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

// Downloads from the update repository: the repository configured in the
// sprout (repo.go), never a URL from the step or the manifest.
//
//   - TLS is verified against the OS trust store. SproutRootCA, which only
//     issued farmer's (or the DMZ edge's) certificate, is not used: the
//     repository is an external host (design doc §1.8).
//   - The environment's proxy settings apply (HTTPS_PROXY/NO_PROXY), as
//     for the sprout's other HTTP clients.
//   - The optional repo token is sent, as HTTP basic auth, only to the
//     configured repository's host, and never across a redirect to
//     another host. The sprout's JWT is never sent.
//   - Only https is followed, for the repository URL, every URL its index
//     names, and every redirect.
//
// Nothing a download returns is trusted until its SHA-256 matches the
// signed manifest: the indexes only say where to look.

const (
	// maxPackageBytes caps a downloaded package (and the .nupkg carrying
	// an MSI). A sprout package is a few tens of MB; this only stops an
	// endless response filling the disk.
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
// production, means the OS trust store. Tests set it to trust their local
// HTTPS server.
var repoRootCAs *x509.CertPool

// newRepoClient returns the client for repository requests.
func newRepoClient() *http.Client {
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

// get sends a GET for u and returns the response if it is a 200. The
// caller closes the body.
func (r repo) get(ctx context.Context, u *url.URL) (*http.Response, error) {
	if u.Scheme != "https" || u.User != nil {
		return nil, fmt.Errorf("selfupdate: refusing to fetch %s: not a plain https URL", redact(u))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: building request for %s: %w", redact(u), err)
	}
	if r.token != "" && u.Host == r.base.Host {
		req.SetBasicAuth(repoUser, r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: GET %s: %w", redact(u), err)
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		return nil, &httpStatusError{url: redact(u), status: resp.StatusCode}
	}
	return resp, nil
}

// httpStatusError is a non-200 answer from the repository.
type httpStatusError struct {
	url    string
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("selfupdate: GET %s: HTTP %d", e.url, e.status)
}

// download fetches u into dest (which must not exist) and checks its
// SHA-256 against wantSHA256, the signed manifest's checksum. The file is
// removed again on any error, so a file left at dest has exactly the
// signed bytes.
func (r repo) download(ctx context.Context, u *url.URL, dest, wantSHA256 string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	resp, err := r.get(ctx, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return writeVerified(resp.Body, dest, wantSHA256)
}

// downloadFromNupkg fetches the .nupkg at u into dir, takes the entry
// named fileName from the package root, and writes it to dest, checking
// its SHA-256 against wantSHA256. The .nupkg itself is unsigned and only
// a container: what is checked and installed is the MSI inside it.
func (r repo) downloadFromNupkg(ctx context.Context, u *url.URL, dir, fileName, dest, wantSHA256 string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	resp, err := r.get(ctx, u)
	if err != nil {
		return err
	}
	nupkg, err := os.CreateTemp(dir, "package-*.nupkg")
	if err != nil {
		resp.Body.Close()
		return fmt.Errorf("selfupdate: staging the NuGet package: %w", err)
	}
	defer os.Remove(nupkg.Name())
	n, err := io.Copy(nupkg, io.LimitReader(resp.Body, maxPackageBytes+1))
	resp.Body.Close()
	if cerr := nupkg.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("selfupdate: downloading %s: %w", redact(u), err)
	}
	if n > maxPackageBytes {
		return fmt.Errorf("selfupdate: %s is larger than %d bytes", redact(u), maxPackageBytes)
	}

	zr, err := zip.OpenReader(nupkg.Name())
	if err != nil {
		return fmt.Errorf("selfupdate: %s is not a NuGet package: %w", redact(u), err)
	}
	defer zr.Close()
	var entry *zip.File
	for _, f := range zr.File {
		if f.Name == fileName {
			if entry != nil {
				return fmt.Errorf("selfupdate: %s holds %s twice", redact(u), fileName)
			}
			entry = f
		}
	}
	if entry == nil {
		return fmt.Errorf("%w: %s has no %s at its root", ErrNotInRepo, redact(u), fileName)
	}
	rc, err := entry.Open()
	if err != nil {
		return fmt.Errorf("selfupdate: opening %s in %s: %w", fileName, redact(u), err)
	}
	defer rc.Close()
	return writeVerified(rc, dest, wantSHA256)
}

// writeVerified copies at most maxPackageBytes from src to a new file at
// dest and checks its SHA-256. dest is removed on any error.
func writeVerified(src io.Reader, dest, wantSHA256 string) (err error) {
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
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(src, maxPackageBytes+1))
	if err != nil {
		return fmt.Errorf("selfupdate: downloading the package: %w", err)
	}
	if n > maxPackageBytes {
		return fmt.Errorf("selfupdate: the package is larger than %d bytes", maxPackageBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
		return fmt.Errorf("%w: got %s, signed %s", ErrChecksumMismatch, got, wantSHA256)
	}
	return f.Sync()
}

// redact drops anything but scheme, host and path from a URL for
// messages.
func redact(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// hasControl reports whether s has an ASCII control character.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
