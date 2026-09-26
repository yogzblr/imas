package pki

// Sprout-side client for farmer's GET /files/<key>
// (internal/api/handlers/recipes.go's GetFile), authenticated with the
// sprout's gateway JWT as a bearer token, the form internal/api's Auth
// (and Envoy's jwt_authn in front of it) checks on that route.
//
// The gateway JWT is short-lived. A token that has expired, or is within
// gatewayJWTMinRemaining() of expiring, is refreshed through the same
// RefreshGatewayJWT the background refresher (RunGatewayJWTRefresher)
// uses, before the request is sent, rather than failing the download. A
// token farmer rejects anyway (clock skew between sprout and gateway, a
// retired verification key) is refreshed and the download retried, up to
// maxFileAuthRetries times.
//
// The token only ever goes to config.FarmerURL, over the
// SproutRootCA-pinned client LoadRootCA builds, and redirects are not
// followed, so it can't be forwarded anywhere else.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
)

// gatewayJWTMinRemaining is how much lifetime a gateway JWT must have
// left to be sent as is: config.GatewayJWTRefreshMargin
// ("gatewayjwtrefreshmargin", default 5m). Less than that and it is
// refreshed first, so it can't expire between being read here and being
// checked at the gateway. Clock skew beyond this is covered by the
// refresh-and-retry on a 401/403.
func gatewayJWTMinRemaining() time.Duration {
	if m := config.GatewayJWTRefreshMargin; m > 0 {
		return m
	}
	return config.DefaultGatewayJWTRefreshMargin
}

// maxFileAuthRetries is how many times a download farmer rejects the
// gateway JWT for (401/403) is retried, each time with a freshly
// refreshed token. Retries after the first wait fileRetryBackoff,
// doubling each time.
const maxFileAuthRetries = 3

// fileRetryBackoff is the wait before the second auth retry. A variable
// so tests can shorten it.
var fileRetryBackoff = time.Second

// rejectedToken reports whether status is farmer (or Envoy) refusing the
// gateway JWT: 401 from Envoy's jwt_authn or a missing header, 403 from
// farmer's Auth. Auth also answers 403 for a key outside the token's
// prefix, which a refresh can't fix; this client only builds in-scope
// keys, so that costs at most the retries, never a wrong result.
func rejectedToken(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// maxFarmerFileBytes caps how much of a GET /files/ response is read.
const maxFarmerFileBytes = 32 << 20

// ErrFarmerFileNotFound means farmer answered GET /files/<key> with 404:
// nothing is stored under that key, e.g. no recipe staged for this
// sprout yet.
var ErrFarmerFileNotFound = errors.New("pki: farmer has no file at that key")

// onDemandRefreshMu serializes refreshes started by downloads, so
// concurrent downloads holding the same stale token refresh it once.
var onDemandRefreshMu sync.Mutex

// FetchFarmerFile downloads the object stored under key from farmer's
// GET /files/<key>, sending the sprout's gateway JWT as
// "Authorization: Bearer <jwt>". A gateway JWT sprout may only read keys
// under its own sprouts/<tenant_id>/<sprout_id>/ prefix.
//
// If the refresh it needs fails, the download fails with that error.
// ErrTenantKeyMismatch and ErrTenantKeyNotPinned come through wrapped, and
// callers treat them as fatal, as RunGatewayJWTRefresher's caller does.
func FetchFarmerFile(ctx context.Context, key string) ([]byte, error) {
	if !isFarmerFileKey(key) {
		return nil, fmt.Errorf("pki: %q is not a valid file key", key)
	}
	tok, err := usableGatewayJWT(ctx)
	if err != nil {
		return nil, err
	}
	data, status, err := getFarmerFile(ctx, key, tok)
	if err != nil {
		return nil, err
	}
	backoff := fileRetryBackoff
	for retry := 1; retry <= maxFileAuthRetries && rejectedToken(status); retry++ {
		log.Warnf("files: farmer rejected the gateway JWT for %s (HTTP %d); refreshing it and retrying (%d/%d)", key, status, retry, maxFileAuthRetries)
		if retry > 1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		if tok, err = refreshGatewayJWTFrom(ctx, tok); err != nil {
			return nil, err
		}
		if data, status, err = getFarmerFile(ctx, key, tok); err != nil {
			return nil, err
		}
	}
	switch status {
	case http.StatusOK:
		return data, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrFarmerFileNotFound, key)
	default:
		return nil, fmt.Errorf("pki: GET /files/%s: HTTP %d", key, status)
	}
}

// GatewayJWTIdentity returns the tenant_id and sprout_id claims of the
// sprout's gateway JWT, refreshing the token first if FetchFarmerFile
// would. These are the IDs Auth scopes GET /files/ to, so a key built from
// them is one this sprout can read. The token's signature isn't checked
// here; the sprout isn't its validator, farmer is.
func GatewayJWTIdentity(ctx context.Context) (tenantID, sproutID string, err error) {
	tok, err := usableGatewayJWT(ctx)
	if err != nil {
		return "", "", err
	}
	parsed, err := jwxjwt.ParseInsecure([]byte(tok))
	if err != nil {
		return "", "", fmt.Errorf("pki: gateway JWT does not parse: %w", err)
	}
	tenantID, _ = claimString(parsed, "tenant_id")
	sproutID, _ = claimString(parsed, "sprout_id")
	if tenantID == "" || sproutID == "" {
		return "", "", errors.New("pki: gateway JWT has no tenant_id or sprout_id claim")
	}
	return tenantID, sproutID, nil
}

func claimString(tok jwxjwt.Token, name string) (string, bool) {
	v, ok := tok.Get(name)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// usableGatewayJWT returns the gateway JWT to send: the one in memory
// (loaded from disk if nothing is), or a freshly refreshed one if that is
// missing, expired, or expiring within gatewayJWTMinRemaining().
func usableGatewayJWT(ctx context.Context) (string, error) {
	if !SproutEnrolled() {
		return "", ErrNotEnrolled
	}
	tok := CurrentGatewayJWT()
	if tok == "" {
		// A missing file is recovered by the refresh below.
		if loaded, err := LoadGatewayJWT(); err == nil {
			tok = loaded
		} else if !errors.Is(err, ErrNotEnrolled) {
			return "", fmt.Errorf("pki: loading gateway JWT: %w", err)
		}
	}
	if gatewayJWTFresh(tok, enrollClock()) {
		return tok, nil
	}
	return refreshGatewayJWTFrom(ctx, tok)
}

// gatewayJWTFresh reports whether tok parses and has more than
// gatewayJWTMinRemaining() left before it expires.
func gatewayJWTFresh(tok string, now time.Time) bool {
	if tok == "" {
		return false
	}
	parsed, err := jwxjwt.ParseInsecure([]byte(tok))
	if err != nil {
		return false
	}
	exp := parsed.Expiration()
	return !exp.IsZero() && exp.Sub(now) > gatewayJWTMinRemaining()
}

// refreshGatewayJWTFrom replaces stale, the token the caller found
// unusable, via RefreshGatewayJWT and returns the new one. If another
// caller already replaced stale with a fresh token while this one waited
// for the lock, that token is returned without a second refresh.
func refreshGatewayJWTFrom(ctx context.Context, stale string) (string, error) {
	onDemandRefreshMu.Lock()
	defer onDemandRefreshMu.Unlock()
	if cur := CurrentGatewayJWT(); cur != stale && gatewayJWTFresh(cur, enrollClock()) {
		return cur, nil
	}
	if _, err := RefreshGatewayJWT(ctx); err != nil {
		return "", fmt.Errorf("pki: refreshing gateway JWT for a file download: %w", err)
	}
	return CurrentGatewayJWT(), nil
}

// getFarmerFile sends one GET /files/<key> with tok as the bearer token
// and returns the status code, and the body on a 200.
func getFarmerFile(ctx context.Context, key, tok string) ([]byte, int, error) {
	nkeyClientMu.RLock()
	client := nkeyClient
	nkeyClientMu.RUnlock()
	if client == nil {
		return nil, 0, ErrNKeyClientNotReady
	}
	// Same pinned transport, but a redirect comes back as a response
	// instead of being followed, carrying the token with it.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	u, err := url.Parse(config.FarmerURL)
	if err != nil {
		return nil, 0, fmt.Errorf("pki: parsing farmer URL: %w", err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/files/" + key
	u.RawPath = ""

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("pki: building GET /files/%s request: %w", key, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("pki: GET /files/%s: %w", key, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, resp.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFarmerFileBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("pki: reading GET /files/%s response: %w", key, err)
	}
	if len(data) > maxFarmerFileBytes {
		return nil, 0, fmt.Errorf("pki: GET /files/%s response exceeds %d bytes", key, maxFarmerFileBytes)
	}
	return data, resp.StatusCode, nil
}

// isFarmerFileKey reports whether key is a non-empty "/"-separated path
// of plain segments: no leading or trailing slash, no empty, "." or ".."
// segments, no backslashes or NULs. The same shape internal/api's Auth
// requires below a sprout's prefix, so nothing along the way can
// normalize the key into a different one.
func isFarmerFileKey(key string) bool {
	if key == "" {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "\\\x00") {
			return false
		}
	}
	return true
}
