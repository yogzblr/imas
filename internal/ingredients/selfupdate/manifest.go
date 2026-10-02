package selfupdate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/pki"
)

// manifestPath is farmer's update manifest endpoint (design doc §2.6),
// on the same recipe HTTP endpoint (and Envoy route) as GET /files/.
const manifestPath = "/v1/sprout/update-manifest"

const (
	manifestTimeout = 30 * time.Second
	// maxManifestBody bounds the response read; fleetsign.ParseManifest
	// refuses anything over 4 KiB anyway.
	maxManifestBody = 8 << 10
)

// Seams for tests. Production code always uses these values.
var (
	// gatewayJWT returns the sprout's current gateway JWT, the bearer
	// token farmer's Auth (and Envoy's jwt_authn) checks on this route.
	gatewayJWT = func(context.Context) (string, error) {
		if tok := pki.CurrentGatewayJWT(); tok != "" {
			return tok, nil
		}
		return pki.LoadGatewayJWT()
	}
	// refreshGatewayJWT gets a fresh gateway JWT, for one retry after
	// farmer rejects the current one.
	refreshGatewayJWT = func(ctx context.Context) (string, error) {
		if _, err := pki.RefreshGatewayJWT(ctx); err != nil {
			return "", err
		}
		return pki.CurrentGatewayJWT(), nil
	}
)

// farmerClient is an HTTP client for farmer that trusts only
// config.SproutRootCA, never the system roots, and follows no redirect,
// so the gateway JWT goes to config.FarmerURL and nowhere else. It uses
// the environment's proxy settings, as the sprout's other farmer clients
// do (pki.LoadRootCA).
func farmerClient() (*http.Client, error) {
	pemBytes, err := os.ReadFile(config.SproutRootCA)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: reading SproutRootCA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("selfupdate: %s holds no usable PEM certificate", config.SproutRootCA)
	}
	return &http.Client{
		Timeout: manifestTimeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// fetchManifest asks farmer for the signed manifest for version on p's
// OS, arch and package type (one linux/amd64 binary ships as both a .deb
// and an .rpm). It checks only that the response is a well-formed manifest
// for exactly what was asked (fleetsign.ParseManifest plus field
// equality); the caller verifies the signature. Farmer answers 404 for
// every reason it has nothing to serve (not approved for this tenant,
// revoked, no package for this OS/arch), and that is ErrNoManifest.
func fetchManifest(ctx context.Context, p platform, version string) (fleetsign.Manifest, error) {
	client, err := farmerClient()
	if err != nil {
		return fleetsign.Manifest{}, err
	}
	u, err := url.Parse(config.FarmerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fleetsign.Manifest{}, fmt.Errorf("selfupdate: farmer URL %q is not an https URL", config.FarmerURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + manifestPath
	u.RawPath = ""
	u.RawQuery = url.Values{"os": {p.os}, "arch": {p.arch}, "package_type": {p.pkgType}, "version": {version}}.Encode()

	tok, err := gatewayJWT(ctx)
	if err != nil {
		return fleetsign.Manifest{}, fmt.Errorf("selfupdate: gateway JWT: %w", err)
	}
	body, status, err := getManifest(ctx, client, u.String(), tok)
	if err == nil && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		if tok, err = refreshGatewayJWT(ctx); err != nil {
			return fleetsign.Manifest{}, fmt.Errorf("selfupdate: refreshing the gateway JWT after HTTP %d: %w", status, err)
		}
		body, status, err = getManifest(ctx, client, u.String(), tok)
	}
	if err != nil {
		return fleetsign.Manifest{}, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return fleetsign.Manifest{}, fmt.Errorf("%w for %s on %s/%s %s (not approved for this tenant, revoked, or not released for this platform)",
			ErrNoManifest, version, p.os, p.arch, p.pkgType)
	default:
		return fleetsign.Manifest{}, fmt.Errorf("selfupdate: GET %s: HTTP %d", manifestPath, status)
	}
	m, err := fleetsign.ParseManifest(body)
	if err != nil {
		return fleetsign.Manifest{}, fmt.Errorf("selfupdate: farmer's manifest: %w", err)
	}
	if m.Version != version || m.OS != p.os || m.Arch != p.arch {
		return fleetsign.Manifest{}, fmt.Errorf("%w: asked for %s %s/%s, got %s %s/%s",
			ErrManifestMismatch, version, p.os, p.arch, m.Version, m.OS, m.Arch)
	}
	return m, nil
}

// getManifest sends one GET with tok as the bearer token and returns the
// status, and the body on a 200.
func getManifest(ctx context.Context, client *http.Client, rawURL, tok string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("selfupdate: building manifest request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("selfupdate: GET %s: %w", manifestPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, resp.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBody+1))
	if err != nil {
		return nil, 0, fmt.Errorf("selfupdate: reading manifest: %w", err)
	}
	if len(data) > maxManifestBody {
		return nil, 0, fmt.Errorf("selfupdate: manifest response exceeds %d bytes", maxManifestBody)
	}
	return data, resp.StatusCode, nil
}
