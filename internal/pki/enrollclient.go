package pki

// Sprout-side client for POST /v1/enroll
// (docs/design/imas-envoy-enrollment-design.md,
// cloudxp-machine-manager-api-design.md §3), and for refreshing the
// short-lived gateway JWT through that same endpoint's idempotent-replay
// path.
//
// FLAG FOR SECURITY REVIEW. This is the sprout's half of the front door of
// the trust chain: what it sends decides which identity farmer hands out,
// and what it persists is what it authenticates with afterwards.
//
//   - Key material is generated here, locally, and only public halves are
//     sent: the NKey public key (certs.GenNKey made the seed) and the
//     X25519 box public key (EnsureSproutBoxKey). Every request carries
//     the NKey seed's signature over EnrollSigningPayload, the proof of
//     possession Enroll checks before anything else.
//   - Requests go over the SproutRootCA-pinned client LoadRootCA builds,
//     the same one PutNKey used. That root CA is itself fetched
//     trust-on-first-use (FetchRootCA), which this file does not change.
//   - A response is validated in full (validateEnrollResponse) before any
//     of it touches disk, so a bad or mismatched response never leaves a
//     partial enrollment behind.
//   - Refreshes never send the configured join token (see
//     refreshJoinToken): a refresh can only replay an existing
//     enrollment, never redeem a token.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/curve25519"

	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

// refreshJoinToken is the join_token a gateway JWT refresh sends instead
// of the configured one. POST /v1/enroll requires a non-empty join_token
// on every request, but Enroll only looks at it after the idempotency
// replay lookup has missed, so for an enrolled sprout its value is never
// read. Sending this constant rather than config.JoinToken means:
//   - the join token can be deleted from the host after enrollment
//     without breaking refreshes, and
//   - a sprout an operator has deleted on farmer can't silently re-enroll
//     itself from its refresh loop with a still-valid join token. This
//     value has no '.', so splitJoinToken rejects it and it can never
//     redeem anything.
const refreshJoinToken = "imas-refresh-only"

// maxEnrollResponseBytes caps how much of a /v1/enroll response is read.
// A real response is a few KB.
const maxEnrollResponseBytes = 1 << 20

// ErrNotEnrolled is returned when the sprout has no persisted NATS User
// JWT, i.e. it has not completed POST /v1/enroll yet.
var ErrNotEnrolled = errors.New("pki: sprout is not enrolled")

// enrollWireRequest and EnrollResponse mirror
// internal/api/handlers/enroll.go's enrollRequest and
// enrollSuccessResponse. They're duplicated rather than shared because
// handlers imports this package, not the other way around; the
// handler-level client test (internal/api/handlers/enroll_client_test.go)
// runs this client against the real handler to keep the two in step.
type enrollWireRequest struct {
	JoinToken string `json:"join_token"`
	NKeyPub   string `json:"nkey_pub"`
	Hostname  string `json:"hostname"`
	SproutPub string `json:"sprout_pub"`
	Timestamp int64  `json:"timestamp"`
	NKeySig   string `json:"nkey_sig"`
}

// EnrollResponse is POST /v1/enroll's success body.
type EnrollResponse struct {
	SproutID         string          `json:"sprout_id"`
	JWT              string          `json:"jwt"`
	GatewayJWT       string          `json:"gateway_jwt"`
	NKeyIdentity     string          `json:"nkey_identity"`
	TenantX25519Pub  string          `json:"tenant_x25519_pub"`
	FleetSigningJWKS json.RawMessage `json:"fleet_signing_jwks"`
	NatsURLs         []string        `json:"nats_urls"`
}

// enrollClock is time.Now, swappable in tests.
var enrollClock = time.Now

// loadSproutNKey reads the sprout's NKey seed (certs.GenNKey) and returns
// its key pair. The public key is derived from the seed rather than read
// from NKeySproutPubFile, so what is signed and what is presented can't
// disagree.
func loadSproutNKey() (nkeys.KeyPair, error) {
	seed, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		return nil, fmt.Errorf("pki: reading sprout NKey seed: %w", err)
	}
	defer wipe(seed)
	kp, err := nkeys.FromSeed(bytes.TrimSpace(seed))
	if err != nil {
		return nil, fmt.Errorf("pki: parsing sprout NKey seed: %w", err)
	}
	return kp, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EnsureSproutBoxKey returns the sprout's X25519 box public key (standard
// base64), generating the keypair on first call
// (docs/design/imas-payload-encryption-design.md, "Bootstrap"). The
// private key is written once, 0600, to config.SproutBoxPrivFile and is
// never replaced here; the public key is always re-derived from it.
func EnsureSproutBoxKey() (string, error) {
	privPath := config.SproutBoxPrivFile
	if privPath == "" {
		return "", errors.New("pki: sproutboxprivfile is not configured")
	}
	priv, err := readBoxPrivKey(privPath)
	if os.IsNotExist(err) {
		var fresh [32]byte
		if _, err := rand.Read(fresh[:]); err != nil {
			return "", fmt.Errorf("pki: generating sprout X25519 key: %w", err)
		}
		encoded := []byte(base64.StdEncoding.EncodeToString(fresh[:]))
		wipe(fresh[:])
		err = writeFileOnce(privPath, encoded, 0o600)
		wipe(encoded)
		if err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("pki: writing sprout X25519 key: %w", err)
		}
		// Either this call wrote it or a concurrent one did; read back
		// whatever is there now.
		priv, err = readBoxPrivKey(privPath)
	}
	if err != nil {
		return "", err
	}
	defer wipe(priv)
	pubBytes, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("pki: deriving sprout X25519 public key: %w", err)
	}
	pub := base64.StdEncoding.EncodeToString(pubBytes)
	if config.SproutBoxPubFile != "" {
		if err := writeFileAtomic(config.SproutBoxPubFile, []byte(pub), 0o644); err != nil {
			return "", fmt.Errorf("pki: writing sprout X25519 public key: %w", err)
		}
	}
	return pub, nil
}

func readBoxPrivKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("pki: reading sprout X25519 key: %w", err)
	}
	defer wipe(data)
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(priv) != 32 {
		wipe(priv)
		return nil, fmt.Errorf("pki: %s is not a base64 32-byte X25519 private key", path)
	}
	return priv, nil
}

// EnrollSprout calls POST /v1/enroll with joinToken, signing the request
// with the sprout's NKey seed, and returns the validated response. It
// persists nothing; see PersistEnrollment. hostname is the sprout ID the
// sprout asks for; farmer may assign a suffixed one on a collision, which
// the response's SproutID carries.
func EnrollSprout(ctx context.Context, joinToken, hostname, sproutPub string) (*EnrollResponse, error) {
	if joinToken == "" {
		return nil, errors.New("pki: no join token configured")
	}
	return enrollRequest(ctx, joinToken, hostname, sproutPub)
}

func enrollRequest(ctx context.Context, joinToken, hostname, sproutPub string) (*EnrollResponse, error) {
	kp, err := loadSproutNKey()
	if err != nil {
		return nil, err
	}
	defer kp.Wipe()
	nkeyPub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("pki: sprout NKey public key: %w", err)
	}
	req := enrollWireRequest{
		JoinToken: joinToken,
		NKeyPub:   nkeyPub,
		Hostname:  hostname,
		SproutPub: sproutPub,
		Timestamp: enrollClock().Unix(),
	}
	sig, err := kp.Sign(EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken))
	if err != nil {
		return nil, fmt.Errorf("pki: signing enrollment request: %w", err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("pki: encoding enrollment request: %w", err)
	}
	nkeyClientMu.RLock()
	client := nkeyClient
	nkeyClientMu.RUnlock()
	if client == nil {
		return nil, ErrNKeyClientNotReady
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, config.FarmerURL+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pki: building enrollment request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("pki: enrollment request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("pki: reading enrollment response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Farmer returns the same generic enrollment_failed for every
		// failure (design doc §3.4); its own log has the reason.
		return nil, fmt.Errorf("pki: enrollment rejected: HTTP %d (see farmer's log for the reason; check the join token and that this host's clock is within %s of farmer's)", resp.StatusCode, EnrollSigMaxSkew)
	}
	var out EnrollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("pki: decoding enrollment response: %w", err)
	}
	if err := validateEnrollResponse(&out, nkeyPub); err != nil {
		return nil, err
	}
	return &out, nil
}

// validateEnrollResponse checks that resp is complete and issued to
// nkeyPub before any of it is persisted.
func validateEnrollResponse(resp *EnrollResponse, nkeyPub string) error {
	if !IsValidSproutID(resp.SproutID) {
		return fmt.Errorf("pki: enrollment response has an invalid sprout_id %q", resp.SproutID)
	}
	if resp.NKeyIdentity != nkeyPub {
		return errors.New("pki: enrollment response's nkey_identity is not this sprout's NKey")
	}
	uc, err := natsjwt.DecodeUserClaims(resp.JWT)
	if err != nil {
		return fmt.Errorf("pki: enrollment response's jwt is not a NATS User JWT: %w", err)
	}
	if uc.Subject != nkeyPub {
		return errors.New("pki: enrollment response's jwt was not issued to this sprout's NKey")
	}
	if _, err := checkGatewayJWT(resp.GatewayJWT, nkeyPub); err != nil {
		return err
	}
	if _, err := DecodeBoxPubKey(resp.TenantX25519Pub); err != nil {
		return fmt.Errorf("pki: enrollment response's tenant_x25519_pub: %w", err)
	}
	if _, err := fleetsign.ParseJWKS(resp.FleetSigningJWKS); err != nil {
		return fmt.Errorf("pki: enrollment response's fleet_signing_jwks: %w", err)
	}
	return nil
}

// checkGatewayJWT parses a gateway JWT without verifying its signature
// and checks it names nkeyPub and hasn't expired. The sprout isn't the
// validator of this token (Envoy is, against farmer's JWKS, which the
// sprout doesn't hold); this only guards against persisting something
// that is plainly not this sprout's current token, and reads the
// timestamps the refresh loop schedules from.
func checkGatewayJWT(token, nkeyPub string) (jwxjwt.Token, error) {
	tok, err := jwxjwt.ParseInsecure([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("pki: gateway JWT does not parse: %w", err)
	}
	if tok.Subject() != nkeyPub {
		return nil, errors.New("pki: gateway JWT was not issued to this sprout's NKey")
	}
	if exp := tok.Expiration(); exp.IsZero() || !exp.After(enrollClock()) {
		return nil, errors.New("pki: gateway JWT has no expiry or has already expired")
	}
	return tok, nil
}

// maxEnrollRetryDelay caps the backoff between failed first-time
// enrollment attempts.
const maxEnrollRetryDelay = 5 * time.Minute

// ErrNoJoinToken is returned by EnsureEnrolled when the sprout isn't
// enrolled yet and has no join token to enroll with.
var ErrNoJoinToken = errors.New("pki: sprout is not enrolled and no join token is configured: set it with --join-token, the " +
	config.EnvJoinToken + " environment variable, or \"jointoken\" in the sprout config file")

// EnsureEnrolled makes sure the sprout holds a NATS User JWT, enrolling
// through POST /v1/enroll with joinToken and persisting the result if it
// doesn't. It retries failures with exponential backoff from retryDelay
// until ctx is done. Retrying is safe: farmer answers a retry with the
// same NKey from its idempotent replay path, without spending another use
// of the join token. It returns the sprout ID to run as, which on a first
// enrollment is farmer's: farmer may assign a suffixed ID when the
// requested one collides with another sprout in the tenant. For an
// already-enrolled sprout it is requestedID unchanged.
func EnsureEnrolled(ctx context.Context, joinToken, requestedID, sproutPub string, retryDelay time.Duration) (string, error) {
	if SproutEnrolled() {
		return requestedID, nil
	}
	if joinToken == "" {
		return "", ErrNoJoinToken
	}
	if retryDelay <= 0 {
		retryDelay = 5 * time.Second
	}
	backoff := retryDelay
	for {
		resp, err := EnrollSprout(ctx, joinToken, requestedID, sproutPub)
		if err == nil {
			if err := PersistEnrollment(resp); err != nil {
				return "", err
			}
			log.Infof("enroll: enrolled as sprout %s", resp.SproutID)
			return resp.SproutID, nil
		}
		log.Errorf("enroll: enrollment failed, retrying in %s: %v", backoff, err)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxEnrollRetryDelay)
	}
}

// PersistEnrollment writes a validated enrollment response next to the
// sprout's NKey seed and root CA: the gateway JWT and tenant X25519
// public key first, then the fleet signing JWKS pin, and the NATS User
// JWT last. SproutEnrolled keys off the User JWT, so a crash part-way
// leaves the sprout un-enrolled and it enrolls again on restart, which
// farmer answers from its idempotent replay without spending another use
// of the join token.
func PersistEnrollment(resp *EnrollResponse) error {
	if err := writeFileAtomic(config.SproutGatewayJWTFile, []byte(resp.GatewayJWT), 0o600); err != nil {
		return fmt.Errorf("pki: persisting gateway JWT: %w", err)
	}
	setCurrentGatewayJWT(resp.GatewayJWT)
	if err := persistTenantX25519Pub(resp.TenantX25519Pub); err != nil {
		return err
	}
	if err := PinFleetSigningKeys(resp.FleetSigningJWKS); err != nil {
		// A different set already pinned means an earlier, interrupted
		// enrollment pinned one and farmer's key has rotated since. The
		// pin is only a bootstrap fallback (fleetkey.go), and replacing
		// an existing pin is exactly what it must never do silently, so
		// keep the old one.
		if !errors.Is(err, ErrFleetKeyAlreadyPinned) {
			return fmt.Errorf("pki: pinning fleet signing keys: %w", err)
		}
		log.Warnf("enroll: keeping the already-pinned fleet signing key set; farmer returned a different one")
	}
	// Not a secret without the NKey seed, but there's no reason for
	// anything but the sprout to read it.
	if err := writeFileAtomic(config.SproutUserJWTFile, []byte(resp.JWT), 0o600); err != nil {
		return fmt.Errorf("pki: persisting NATS User JWT: %w", err)
	}
	return nil
}

func persistTenantX25519Pub(pub string) error {
	path := config.SproutTenantX25519PubFile
	if existing, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(existing)) != pub {
		log.Warnf("enroll: farmer returned a different tenant X25519 public key than the one on disk; replacing it")
	}
	if err := writeFileAtomic(path, []byte(pub), 0o644); err != nil {
		return fmt.Errorf("pki: persisting tenant X25519 public key: %w", err)
	}
	return nil
}

// SproutEnrolled reports whether the sprout has a persisted NATS User
// JWT from a completed enrollment.
func SproutEnrolled() bool {
	_, err := os.Stat(config.SproutUserJWTFile)
	return err == nil
}

// LoadSproutUserJWT returns the persisted NATS User JWT, or
// ErrNotEnrolled if there is none.
func LoadSproutUserJWT() (string, error) {
	return readTokenFile(config.SproutUserJWTFile)
}

// LoadGatewayJWT returns the persisted gateway JWT, or ErrNotEnrolled if
// there is none. It also makes it the one GatewayJWTHeaders serves.
func LoadGatewayJWT() (string, error) {
	tok, err := readTokenFile(config.SproutGatewayJWTFile)
	if err == nil {
		setCurrentGatewayJWT(tok)
	}
	return tok, err
}

func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", ErrNotEnrolled
	}
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", ErrNotEnrolled
	}
	return tok, nil
}

var currentGatewayJWT atomic.Value // string

func setCurrentGatewayJWT(tok string) { currentGatewayJWT.Store(tok) }

// CurrentGatewayJWT returns the most recently persisted or refreshed
// gateway JWT held in memory, or "" if none has been loaded.
func CurrentGatewayJWT() string {
	tok, _ := currentGatewayJWT.Load().(string)
	return tok
}

// GatewayJWTHeaders is a nats.WebSocketHeadersHandler: it supplies the
// current gateway JWT as a bearer token on every websocket (re)connect
// handshake, which is where Envoy's jwt_authn reads it (deploy/envoy).
// nats.go only calls it for ws:// and wss:// URLs. Because it's called per
// handshake, a refreshed token takes effect on the next reconnect with
// no need to rebuild the connection.
func GatewayJWTHeaders() (http.Header, error) {
	tok := CurrentGatewayJWT()
	if tok == "" {
		return nil, errors.New("pki: no gateway JWT loaded")
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	return h, nil
}

// RefreshGatewayJWT gets a fresh gateway JWT from POST /v1/enroll's
// idempotent-replay path (Enroll's step 1, gated only by the proof of
// possession) and persists it. It sends refreshJoinToken, never the
// configured join token. If farmer returns a different NATS User JWT
// than the one on disk (for instance, re-minted after a signing key
// change), that is persisted too and picked up on the sprout's next
// start. It returns the sprout_id farmer replayed.
func RefreshGatewayJWT(ctx context.Context, hostname, sproutPub string) (string, error) {
	resp, err := enrollRequest(ctx, refreshJoinToken, hostname, sproutPub)
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(config.SproutGatewayJWTFile, []byte(resp.GatewayJWT), 0o600); err != nil {
		return "", fmt.Errorf("pki: persisting refreshed gateway JWT: %w", err)
	}
	setCurrentGatewayJWT(resp.GatewayJWT)
	if existing, err := LoadSproutUserJWT(); err != nil || existing != resp.JWT {
		if err := writeFileAtomic(config.SproutUserJWTFile, []byte(resp.JWT), 0o600); err != nil {
			return "", fmt.Errorf("pki: persisting refreshed NATS User JWT: %w", err)
		}
		log.Infof("enroll: farmer returned a new NATS User JWT; it takes effect on the next sprout restart")
	}
	return resp.SproutID, nil
}

// gatewayRefreshMinDelay keeps a token farmer mints with a very short
// lifetime from turning the refresh loop into a hot loop.
const gatewayRefreshMinDelay = 30 * time.Second

// gatewayRefreshDelay returns how long to wait before refreshing token:
// two thirds of the way through its lifetime (iat to exp), less up to a
// tenth of the lifetime of random jitter so sprouts enrolled in the same
// Ansible run don't all refresh in the same second. The lifetime falls
// back to config.GatewayJWTTTL if the token has no iat. A token that
// doesn't parse, is missing, or is already past its refresh point is
// refreshed now (0). jitter returns a value in [0, n).
func gatewayRefreshDelay(token string, now time.Time, jitter func(n int64) int64) time.Duration {
	if token == "" {
		return 0
	}
	tok, err := jwxjwt.ParseInsecure([]byte(token))
	if err != nil {
		return 0
	}
	exp := tok.Expiration()
	if exp.IsZero() {
		return 0
	}
	lifetime := exp.Sub(tok.IssuedAt())
	if tok.IssuedAt().IsZero() || lifetime <= 0 {
		lifetime = config.GatewayJWTTTL
	}
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	refreshAt := exp.Add(-lifetime / 3)
	if n := int64(lifetime / 10); n > 0 {
		refreshAt = refreshAt.Add(-time.Duration(jitter(n)))
	}
	d := refreshAt.Sub(now)
	if d <= 0 {
		return 0
	}
	if d < gatewayRefreshMinDelay {
		return gatewayRefreshMinDelay
	}
	return d
}

func cryptoJitter(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

// maxRefreshRetryDelay caps the refresh loop's backoff after failures.
const maxRefreshRetryDelay = 5 * time.Minute

// RunGatewayJWTRefresher keeps the sprout's gateway JWT fresh until ctx
// is done: it sleeps until gatewayRefreshDelay says the current token is
// due, then calls RefreshGatewayJWT, retrying failures with exponential
// backoff from retryDelay up to maxRefreshRetryDelay. A token that
// already expired, as after a sprout was powered off for longer than the
// TTL, is refreshed immediately. hostname is the sprout's current ID;
// a refresh that replays a different one is logged, not adopted, since
// the sprout's subscriptions are already bound to its current ID.
func RunGatewayJWTRefresher(ctx context.Context, hostname, sproutPub string, retryDelay time.Duration) {
	if retryDelay <= 0 {
		retryDelay = 5 * time.Second
	}
	backoff := retryDelay
	var wait time.Duration
	failed := false
	for {
		if !failed {
			wait = gatewayRefreshDelay(CurrentGatewayJWT(), time.Now(), cryptoJitter)
		}
		if wait > 0 {
			log.Debugf("enroll: next gateway JWT refresh in %s", wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		sproutID, err := RefreshGatewayJWT(ctx, hostname, sproutPub)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("enroll: refreshing gateway JWT failed, retrying in %s: %v", backoff, err)
			failed = true
			wait = backoff
			backoff = min(backoff*2, maxRefreshRetryDelay)
			continue
		}
		if sproutID != hostname {
			log.Errorf("enroll: gateway JWT refresh replayed sprout_id %q, but this sprout runs as %q", sproutID, hostname)
		}
		log.Debugf("enroll: refreshed gateway JWT")
		failed = false
		backoff = retryDelay
	}
}

// writeFileAtomic writes data to path via a temp file in the same
// directory and a rename, so a crash never leaves a truncated credential
// behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("pki: no path configured")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	// CreateTemp makes the file 0600; chmod before any data is written so
	// a wider perm is never applied to half-written secret data and a
	// narrower one holds from the start.
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// writeFileOnce is writeFileAtomic that fails with an os.IsExist error
// instead of replacing path if it already exists.
func writeFileOnce(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Link, unlike Rename, refuses to replace an existing path.
	return os.Link(tmpPath, path)
}
