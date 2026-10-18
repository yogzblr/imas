package pki

// Sprout-side client for POST /v1/enroll
// (docs/design/imas-envoy-enrollment-design.md,
// imas-machine-manager-api-design.md §3), and for refreshing the
// short-lived gateway JWT through POST /v1/refresh.
//
// FLAG FOR SECURITY REVIEW. This is the sprout's half of the front door of
// the trust chain: what it sends decides which identity farmer hands out,
// and what it persists is what it authenticates with afterwards.
//
//   - Key material is generated here, locally, and only public halves are
//     sent: the NKey public key (certs.GenNKey made the seed) and the
//     X25519 box public key (EnsureSproutBoxKey). Enrollment requests
//     carry the NKey seed's signature over EnrollSigningPayload, the proof
//     of possession farmer checks before anything else. Refresh carries no
//     NKey signature at all (J.2): the seed also signs the bus's CONNECT
//     nonce, which a compromised bus chooses, so a refresh is sealed with
//     the box key instead (SproutSealedRefresh) and its reply, the new
//     gateway JWT, sealed back (refreshsealed.go). The seed now signs only
//     bus nonces and enrollment requests, and farmer issues a gateway JWT
//     for neither on its own.
//   - Requests go over the SproutRootCA-pinned client LoadRootCA builds,
//     the same one PutNKey used. That root CA is itself fetched
//     trust-on-first-use (FetchRootCA), which this file does not change.
//   - A response is validated in full (validateEnrollResponse) before any
//     of it touches disk, so a bad or mismatched response never leaves a
//     partial enrollment behind.
//   - Refreshes carry no join token at all (their own contract,
//     POST /v1/refresh), so a refresh can only re-issue an existing
//     identity, never redeem a token or create a sprout.
//   - A 503 is the one retryable answer: another farmer replica holds
//     the sprout's User JWT mint lease. The client waits its Retry-After
//     (5 s when absent or invalid, at most 60 s) plus up to 20 percent
//     jitter, and retries with a freshly signed or sealed request, at most
//     enrollStep2Attempts times (retryWhileBusy). Envoy must not retry a
//     503 on these routes itself, or the Retry-After never reaches here
//     (deploy/helm/nats's envoy-configmap.yaml).
//   - nats_urls, the bus addresses the sprout will send its User JWT and
//     gateway JWT to, must pass ValidateBusURLs (TLS schemes only, no
//     credentials) or the whole response is refused; see busconnect.go.
//   - The tenant X25519 public key is pinned at enrollment. A response
//     carrying a different one is refused whole, and the error
//     (ErrTenantKeyMismatch) is fatal to the sprout, unless the response
//     also carries a continuity proof sealed under the pinned key's
//     private half that names the new key (authenticated tenant key
//     rotation, sproutbox.go's reconcileTenantKeyPin); then the pin
//     moves to the new key.
//   - The tenant X25519 public key a first enrollment returns is checked
//     against the tenant key fingerprint in the join token (security
//     review 2026-10, L24; internal/jointoken) before anything is sealed
//     to it or pinned, so the pin is no longer trust on first use against
//     the DMZ Envoy: an Envoy that substitutes its own key is refused
//     with ErrTenantKeyFingerprintMismatch. A token with no fingerprint is
//     refused (ErrJoinTokenNoFingerprint) unless the sprout's
//     "enrollpinrequired" is false, and then every enrollment logs a
//     warning. Later tenant keys reach the sprout through continuity
//     proofs (reconcileTenantKeyPin), not through a token.
//   - The tenant ID is pinned at enrollment too (sproutbox.go's
//     pinSproutTenant), and never moves. Every sealed message names it.
//     So is the sprout ID farmer assigned (pinSproutID), which a sealed
//     refresh names.
//   - A first enrollment is two requests (enroll.go's package comment,
//     "Proof of possession of the box key"): the first issues the
//     identity and names the tenant's box key; the second, on farmer's
//     replay path, carries the sprout's proof that it holds its box
//     private key, sealed to that tenant key, and only then does farmer
//     record the box key. The second also returns the enrollment binding
//     the first response carried (enroll.go, SEC.7b): farmer records a
//     first box key only with it, and issues it only on the request that
//     issued the identity, so a step 2 that keeps failing past
//     EnrollBindingTTL leaves an identity that has to be enrolled again
//     under a new NKey.

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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/curve25519"

	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/jointoken"
	log "github.com/yogzblr/imas/internal/log"
)

// maxEnrollResponseBytes caps how much of a /v1/enroll or /v1/refresh
// response is read.
// A real response is a few KB.
const maxEnrollResponseBytes = 1 << 20

// ErrTenantKeyMismatch means farmer returned a tenant X25519 public key
// different from the one this sprout has pinned, without a continuity
// proof from the pinned key that verifies (a rotation farmer severed, a
// sprout offline past every retained key version, a farmer-side bug, or
// something worse; "it came over pinned TLS" rules out an outside
// attacker, not those). Nothing from that response is persisted. Callers
// treat it as fatal: the sprout has to be re-enrolled.
var ErrTenantKeyMismatch = errors.New("pki: farmer returned a different tenant X25519 public key than the one pinned at enrollment; refusing it")

// ErrTenantKeyNotPinned means an enrolled sprout has no pinned tenant
// X25519 public key. PersistEnrollment writes the pin before the User
// JWT, so this is tampered or corrupted state, not something to re-pin
// silently from the next response. Callers treat it as fatal, like
// ErrTenantKeyMismatch.
var ErrTenantKeyNotPinned = errors.New("pki: sprout is enrolled but has no pinned tenant X25519 public key; refusing to accept one from a refresh")

// ErrTenantKeyFingerprintMismatch means the tenant X25519 public key a
// first enrollment response carried is not the one whose fingerprint the
// join token carries (security review 2026-10, L24). Either something
// between the sprout and farmer (the DMZ Envoy) substituted its own key,
// or the tenant key was rotated after the token was minted. Nothing is
// sealed to the key or pinned; callers treat it as fatal. Mint a new join
// token, and if the tenant key was not rotated, investigate the path to
// farmer.
var ErrTenantKeyFingerprintMismatch = errors.New("pki: the tenant X25519 public key in farmer's enrollment response does not match the tenant key fingerprint in the join token; refusing it (a substituted key on the path to farmer, or a token minted before the tenant key was rotated: mint a new one)")

// ErrJoinTokenNoFingerprint means the join token carries no tenant key
// fingerprint ({key_id}.{secret}, minted before L24 was fixed) and the
// sprout's "enrollpinrequired" is true, the default. Nothing is sent to
// farmer. Mint a new token, or set enrollpinrequired: false to enroll
// trusting the first tenant key farmer's response names.
var ErrJoinTokenNoFingerprint = errors.New("pki: the join token carries no tenant key fingerprint and enrollpinrequired is true; refusing to enroll with it (mint a new join token, or set enrollpinrequired: false to trust the tenant key on first use)")

// ErrNotEnrolled is returned when the sprout has no persisted NATS User
// JWT, i.e. it has not completed POST /v1/enroll yet.
var ErrNotEnrolled = errors.New("pki: sprout is not enrolled")

// enrollWireRequest/EnrollResponse and refreshWireRequest/RefreshResponse
// mirror internal/api/handlers' enrollRequest/enrollSuccessResponse and
// refreshRequest/refreshSuccessResponse. They're duplicated rather than
// shared because handlers imports this package, not the other way
// around; the handler-level client test
// (internal/api/handlers/enroll_client_test.go) runs this client against
// the real handlers to keep the two in step.
type enrollWireRequest struct {
	JoinToken string `json:"join_token"`
	NKeyPub   string `json:"nkey_pub"`
	Hostname  string `json:"hostname"`
	SproutPub string `json:"sprout_pub"`
	Timestamp int64  `json:"timestamp"`
	NKeySig   string `json:"nkey_sig"`
	// SproutPubProof is set on the second request of a first enrollment;
	// see EnrollSprout.
	SproutPubProof json.RawMessage `json:"sprout_pub_proof,omitempty"`
	// EnrollBinding is returned with SproutPubProof: the binding the
	// first response carried, if it carried one. Opaque to the sprout.
	EnrollBinding json.RawMessage `json:"enroll_binding,omitempty"`
}

// EnrollResponse is POST /v1/enroll's success body.
type EnrollResponse struct {
	SproutID string `json:"sprout_id"`
	// TenantID is the tenant the sprout pins (pinSproutTenant).
	TenantID        string   `json:"tenant_id"`
	JWT             string   `json:"jwt"`
	GatewayJWT      string   `json:"gateway_jwt"`
	NKeyIdentity    string   `json:"nkey_identity"`
	TenantX25519Pub string   `json:"tenant_x25519_pub"`
	NatsURLs        []string `json:"nats_urls"`
	// TenantX25519Continuity is set after a tenant key rotation; see
	// reconcileTenantKeyPin.
	TenantX25519Continuity json.RawMessage `json:"tenant_x25519_continuity,omitempty"`
	// EnrollBinding is set on the response that issued the identity; the
	// sprout returns it with its box key proof (EnrollSprout).
	EnrollBinding json.RawMessage `json:"enroll_binding,omitempty"`
}

// refreshWireRequest is POST /v1/refresh's body: the sprout's NKey public
// key, saying which sprout it claims to be, and its sealed request
// (SproutSealedRefresh), which proves it. No NKey signature.
type refreshWireRequest struct {
	NKeyPub string          `json:"nkey_pub"`
	Sealed  json.RawMessage `json:"sealed"`
}

// refreshWireResponse is POST /v1/refresh's success body: farmer's sealed
// reply, whose result is a RefreshResponse.
type refreshWireResponse struct {
	Sealed json.RawMessage `json:"sealed"`
}

// RefreshResponse is the result inside farmer's sealed reply to a
// refresh (refreshsealed.go); nothing of it travels in plaintext.
type RefreshResponse struct {
	SproutID string `json:"sprout_id"`
	// TenantID is checked against the tenant pinned at enrollment on
	// every refresh (checkRefreshTenant).
	TenantID        string `json:"tenant_id"`
	JWT             string `json:"jwt"`
	GatewayJWT      string `json:"gateway_jwt"`
	NKeyIdentity    string `json:"nkey_identity"`
	TenantX25519Pub string `json:"tenant_x25519_pub"`
	// TenantX25519Continuity is set after a tenant key rotation; see
	// reconcileTenantKeyPin.
	TenantX25519Continuity json.RawMessage `json:"tenant_x25519_continuity,omitempty"`
}

// enrollClock is time.Now, swappable in tests.
var enrollClock = time.Now

// maxSigningTimestampLead bounds how far nextSigningTimestamp may run
// ahead of enrollClock, in seconds. Well inside EnrollSigMaxSkew.
const maxSigningTimestampLead = 60

var (
	signingTimestampMu   sync.Mutex
	lastSigningTimestamp int64
)

// nextSigningTimestamp returns the timestamp for the next signed
// /v1/enroll request: enrollClock's Unix seconds, bumped past the
// previous one if that was the same second or later. Farmer accepts each
// signed payload only once (replaycache.go), and a payload is fully
// determined by its fields and this second-granularity timestamp, so two
// requests signed in the same second (an enrollment's two requests, say)
// would otherwise be identical and the second rejected. A previous
// timestamp at least maxSigningTimestampLead ahead of the clock (the
// clock was stepped back) is not bumped past. (A sealed refresh needs
// none of this: each carries a fresh random message ID.)
func nextSigningTimestamp() int64 {
	signingTimestampMu.Lock()
	defer signingTimestampMu.Unlock()
	ts := enrollClock().Unix()
	if ts <= lastSigningTimestamp && lastSigningTimestamp-ts < maxSigningTimestampLead {
		ts = lastSigningTimestamp + 1
	}
	lastSigningTimestamp = ts
	return ts
}

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

// EnrollSprout enrolls through POST /v1/enroll with joinToken, signing
// each request with the sprout's NKey seed, and returns the validated
// response. It persists nothing; see PersistEnrollment. hostname is the
// sprout ID the sprout asks for; farmer may assign a suffixed one on a
// collision, which the response's SproutID carries. sproutPub must be the
// public half of the box key on disk (EnsureSproutBoxKey).
//
// It is EnrollClient.Enroll with the sprout's own keys (its NKey seed and
// box key files), farmer URL and SproutRootCA-pinned client.
func EnrollSprout(ctx context.Context, joinToken, hostname, sproutPub string) (*EnrollResponse, error) {
	if joinToken == "" {
		return nil, errors.New("pki: no join token configured")
	}
	kp, err := loadSproutNKey()
	if err != nil {
		return nil, err
	}
	defer kp.Wipe()
	priv, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		return nil, err
	}
	defer wipe(priv[:])
	if pub, err := boxPubFromPriv(priv); err != nil || pub != sproutPub {
		return nil, errors.New("pki: the box key on disk is not the one being enrolled")
	}
	nkeyClientMu.RLock()
	client := nkeyClient
	nkeyClientMu.RUnlock()
	if client == nil {
		return nil, ErrNKeyClientNotReady
	}
	c := &EnrollClient{HTTP: client, FarmerURL: config.FarmerURL, AllowTokenWithoutFingerprint: !config.EnrollPinRequired}
	return c.Enroll(ctx, joinToken, hostname, EnrollKeys{NKey: kp, BoxPriv: priv})
}

// EnrollKeys is the key material of one enrollment: the sprout's NKey
// (a user key pair, which signs each request) and its X25519 box private
// key, whose public half is enrolled as sprout_pub and whose possession
// the second request proves. Only public halves leave the process.
type EnrollKeys struct {
	NKey    nkeys.KeyPair
	BoxPriv *[32]byte
}

// EnrollClient sends enrollment requests to one farmer. A sprout has one
// (EnrollSprout builds it from its config); tools/loadtest builds one to
// enroll many simulated sprouts through the real enrollment path, each
// with its own EnrollKeys.
type EnrollClient struct {
	// HTTP is the client requests go over: for a sprout, the
	// SproutRootCA-pinned one LoadRootCA builds.
	HTTP *http.Client
	// FarmerURL is farmer's (or the DMZ Envoy's) base URL; /v1/enroll is
	// appended.
	FarmerURL string
	// Timestamp returns the signing timestamp of the next request (Unix
	// seconds). Nil uses nextSigningTimestamp, the process-wide one a
	// sprout needs. Enroll makes its own requests' timestamps strictly
	// increasing either way.
	Timestamp func() int64
	// AllowTokenWithoutFingerprint lets Enroll use a join token that
	// carries no tenant key fingerprint, trusting the tenant key the
	// first response names (with a warning). False, the zero value,
	// refuses such a token (ErrJoinTokenNoFingerprint). A sprout sets it
	// from "enrollpinrequired: false".
	AllowTokenWithoutFingerprint bool
}

// Enroll enrolls keys through POST /v1/enroll with joinToken, asking for
// hostname as the sprout ID, and returns the validated response. It
// persists nothing.
//
// It makes two requests (enroll.go's "Proof of possession of the box
// key"). The first issues the identity, names the tenant and its box
// public key, and carries an enrollment binding. The second, which farmer
// answers from its replay path without spending the token again, carries
// sprout_pub_proof: proof that this sprout holds the private half of
// sproutPub, sealed to that tenant key, and returns the binding. Farmer
// records sproutPub only then, and only the second response carries a
// gateway JWT: farmer issues none for an NKey signature alone, which a
// compromised bus can obtain (enroll.go's package comment). The second
// response must name the same sprout, tenant and tenant key as the first.
//
// The first response's tenant key must match the tenant key fingerprint
// the join token carries (ErrTenantKeyFingerprintMismatch), checked before
// the proof is sealed to it; a token without one is refused before any
// request (ErrJoinTokenNoFingerprint) unless AllowTokenWithoutFingerprint.
//
// The second request is tried enrollStep2Attempts times, each with a
// fresh signature and proof: farmer issues the binding only once, so a
// sprout that gives up on it has to be enrolled again under a new NKey.
// When the first request was answered from farmer's replay path (this
// NKey was already enrolled, with a box key), there is no binding, and
// the second request re-asserts the box key on record.
//
// A 503 (another farmer replica holds this sprout's User JWT mint lease)
// is retried after its Retry-After (retryWhileBusy, busyDelay), within the
// same attempt limit.
func (c *EnrollClient) Enroll(ctx context.Context, joinToken, hostname string, keys EnrollKeys) (*EnrollResponse, error) {
	if joinToken == "" {
		return nil, errors.New("pki: no join token configured")
	}
	if keys.NKey == nil || keys.BoxPriv == nil {
		return nil, errors.New("pki: enrollment needs the sprout's NKey and box key")
	}
	nkeyPub, err := keys.NKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("pki: sprout NKey public key: %w", err)
	}
	sproutPub, err := boxPubFromPriv(keys.BoxPriv)
	if err != nil {
		return nil, err
	}
	tok, err := jointoken.Parse(joinToken)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	if tok.Fingerprint == "" {
		if !c.AllowTokenWithoutFingerprint {
			return nil, ErrJoinTokenNoFingerprint
		}
		log.Warnf("enroll: the join token (key_id %s) carries no tenant key fingerprint and enrollpinrequired is false: trusting the tenant key farmer's response names on first use, so a substituted key on the path to farmer would go unnoticed", tok.KeyID)
	}
	var last int64
	var first *EnrollResponse
	err = retryWhileBusy(ctx, "/v1/enroll", func() error {
		var err error
		first, err = c.postEnroll(ctx, keys.NKey, nkeyPub, joinToken, hostname, sproutPub, nil, nil, &last)
		return err
	})
	if err != nil {
		return nil, err
	}
	if tok.Fingerprint != "" {
		if err := checkTenantKeyFingerprint(first.TenantX25519Pub, tok.Fingerprint); err != nil {
			return nil, err
		}
	}
	var second *EnrollResponse
	for attempt := 1; ; attempt++ {
		proof, err := sealEnrollProof(keys.BoxPriv, first.TenantID, first.SproutID, first.TenantX25519Pub, nkeyPub, sproutPub)
		if err != nil {
			return nil, fmt.Errorf("pki: building the box key proof of possession: %w", err)
		}
		second, err = c.postEnroll(ctx, keys.NKey, nkeyPub, joinToken, hostname, sproutPub, proof, first.EnrollBinding, &last)
		if err == nil {
			break
		}
		if attempt == enrollStep2Attempts || ctx.Err() != nil {
			return nil, fmt.Errorf("pki: proving possession of the box key (if this sprout has no box key on record and its first enrollment was not completed within %s, it has to be deleted and enrolled again under a new NKey with a fresh join token): %w", EnrollBindingTTL, err)
		}
		delay := enrollStep2RetryDelay << (attempt - 1)
		var busy *farmerBusyError
		if errors.As(err, &busy) {
			delay = busyDelay(busy.retryAfter, busyJitter)
			logBusy(busy.path, delay)
		} else {
			log.Warnf("enroll: proving possession of the box key failed (attempt %d of %d), retrying: %v", attempt, enrollStep2Attempts, err)
		}
		if err := busyWait(ctx, delay); err != nil {
			return nil, err
		}
	}
	if second.SproutID != first.SproutID || second.TenantID != first.TenantID || second.TenantX25519Pub != first.TenantX25519Pub {
		return nil, errors.New("pki: farmer's two enrollment responses name different sprouts, tenants or tenant keys")
	}
	return second, nil
}

// checkTenantKeyFingerprint returns ErrTenantKeyFingerprintMismatch
// unless tenantPub (standard base64, already validated) has fingerprint.
func checkTenantKeyFingerprint(tenantPub, fingerprint string) error {
	got, err := jointoken.FingerprintB64(tenantPub)
	if err != nil || got != fingerprint {
		return ErrTenantKeyFingerprintMismatch
	}
	return nil
}

// enrollStep2Attempts and enrollStep2RetryDelay bound EnrollSprout's
// retries of its second request (delays of 1s, 2s, 4s, 8s: well inside
// EnrollBindingTTL). enrollStep2Attempts is also the attempt limit for a
// request farmer answers busy (retryWhileBusy). Variables so tests can
// shorten them.
var (
	enrollStep2Attempts   = 5
	enrollStep2RetryDelay = time.Second
)

// timestamp returns the signing timestamp of the next request, strictly
// after *last, and records it there.
func (c *EnrollClient) timestamp(last *int64) int64 {
	next := nextSigningTimestamp
	if c.Timestamp != nil {
		next = c.Timestamp
	}
	ts := max(next(), *last+1)
	*last = ts
	return ts
}

// postEnroll sends one signed POST /v1/enroll request, with proof as its
// sprout_pub_proof and binding as its enroll_binding if set, and returns
// the validated response. A response to a request with a proof must
// carry a gateway JWT; one to a request without may not.
func (c *EnrollClient) postEnroll(ctx context.Context, kp nkeys.KeyPair, nkeyPub, joinToken, hostname, sproutPub string, proof, binding json.RawMessage, last *int64) (*EnrollResponse, error) {
	req := enrollWireRequest{
		JoinToken:      joinToken,
		NKeyPub:        nkeyPub,
		Hostname:       hostname,
		SproutPub:      sproutPub,
		Timestamp:      c.timestamp(last),
		SproutPubProof: proof,
		EnrollBinding:  binding,
	}
	sig, err := kp.Sign(EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken))
	if err != nil {
		return nil, fmt.Errorf("pki: signing enrollment request: %w", err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)

	var out EnrollResponse
	if err := postJSON(ctx, c.HTTP, c.FarmerURL, "/v1/enroll", req, &out); err != nil {
		return nil, err
	}
	if err := validateEnrollResponse(&out, nkeyPub, len(proof) > 0); err != nil {
		return nil, err
	}
	return &out, nil
}

// ErrFarmerBusy is what a request farmer answered 503 matches
// (errors.Is): another farmer replica holds the sprout's User JWT mint
// lease (pki.ErrSproutJWTBusy on farmer's side). It is retryable; the
// answer's Retry-After says when.
var ErrFarmerBusy = errors.New("pki: server busy (lease held)")

// farmerBusyError is a 503 from farmer on path, with the wait its
// Retry-After asked for (parseRetryAfter).
type farmerBusyError struct {
	path       string
	retryAfter time.Duration
}

func (e *farmerBusyError) Error() string {
	return fmt.Sprintf("pki: %s: server busy (lease held)", e.path)
}

func (e *farmerBusyError) Is(target error) bool { return target == ErrFarmerBusy }

// defaultBusyRetryAfter is the wait for a 503 without a usable
// Retry-After, and maxBusyRetryAfter caps the wait one may ask for. The
// jitter busyDelay adds is up to busyJitterPercent of the wait on top.
const (
	defaultBusyRetryAfter = 5 * time.Second
	maxBusyRetryAfter     = 60 * time.Second
	busyJitterPercent     = 20
)

// parseRetryAfter reads a 503's Retry-After as whole seconds: absent,
// not a whole number, or below 1 is defaultBusyRetryAfter (an HTTP date
// included: farmer sends seconds), and more than maxBusyRetryAfter is
// capped there.
func parseRetryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 {
		return defaultBusyRetryAfter
	}
	return min(time.Duration(n)*time.Second, maxBusyRetryAfter)
}

// busyDelay is wait plus jitter of up to busyJitterPercent of it, so the
// sprouts one busy lease turned away don't all come back in the same
// second. jitter returns a value in [0, n).
func busyDelay(wait time.Duration, jitter func(n int64) int64) time.Duration {
	if n := int64(wait) * busyJitterPercent / 100; n > 0 {
		wait += time.Duration(jitter(n + 1))
	}
	return wait
}

// busyJitter and busyWait are cryptoJitter and a context-aware sleep,
// swappable in tests.
var (
	busyJitter = cryptoJitter
	busyWait   = func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}
)

// logBusy logs the one message a busy answer gets, in place of the token
// or clock hint a rejection carries.
func logBusy(path string, delay time.Duration) {
	log.Warnf("%s", busyMessage(path, delay))
}

// busyMessage is logBusy's message.
func busyMessage(path string, delay time.Duration) string {
	return fmt.Sprintf("enroll: %s: server busy (lease held), retrying in %.1fs", path, delay.Seconds())
}

// retryWhileBusy runs send, which must build a fresh request each time
// (a new signature or sealed message: farmer accepts each only once),
// until it returns anything but a busy answer, waiting busyDelay of the
// answer's Retry-After between tries, at most enrollStep2Attempts tries.
// The last busy error is returned as is.
func retryWhileBusy(ctx context.Context, path string, send func() error) error {
	for attempt := 1; ; attempt++ {
		err := send()
		var busy *farmerBusyError
		if !errors.As(err, &busy) || attempt >= enrollStep2Attempts {
			return err
		}
		delay := busyDelay(busy.retryAfter, busyJitter)
		logBusy(path, delay)
		if err := busyWait(ctx, delay); err != nil {
			return err
		}
	}
}

// postToFarmer POSTs body as JSON to path on farmer over the
// SproutRootCA-pinned client and decodes a 200 response into out.
func postToFarmer(ctx context.Context, path string, body, out any) error {
	nkeyClientMu.RLock()
	client := nkeyClient
	nkeyClientMu.RUnlock()
	if client == nil {
		return ErrNKeyClientNotReady
	}
	return postJSON(ctx, client, config.FarmerURL, path, body, out)
}

// postJSON POSTs body as JSON to baseURL+path over client and decodes a
// 200 response into out. A 503 is a *farmerBusyError (ErrFarmerBusy)
// carrying its Retry-After; any other status is a rejection.
func postJSON(ctx context.Context, client *http.Client, baseURL, path string, body, out any) error {
	if client == nil {
		return ErrNKeyClientNotReady
	}
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pki: encoding %s request: %w", path, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("pki: building %s request: %w", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("pki: %s request: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponseBytes))
	if err != nil {
		return fmt.Errorf("pki: reading %s response: %w", path, err)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		// Retryable, unlike every other failure: say so, and not the
		// token or clock hint below.
		return &farmerBusyError{path: path, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode != http.StatusOK {
		// Farmer returns the same generic enrollment_failed for every
		// failure (design doc §3.4); its own log has the reason.
		return fmt.Errorf("pki: %s rejected: HTTP %d (see farmer's log for the reason; check the join token or enrollment state, and that this host's clock is within %s of farmer's)", path, resp.StatusCode, EnrollSigMaxSkew)
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("pki: decoding %s response: %w", path, err)
	}
	return nil
}

// validateEnrollResponse checks that resp is complete and issued to
// nkeyPub before any of it is persisted. The gateway JWT is required only
// if wantGateway (the response to a request that proved possession of the
// box key); otherwise it is checked if present.
func validateEnrollResponse(resp *EnrollResponse, nkeyPub string, wantGateway bool) error {
	checkGateway := wantGateway || resp.GatewayJWT != ""
	if err := validateIdentity(resp.SproutID, resp.NKeyIdentity, resp.JWT, resp.GatewayJWT, checkGateway, resp.TenantX25519Pub, nkeyPub); err != nil {
		return err
	}
	if !IsValidTenantID(resp.TenantID) {
		return fmt.Errorf("pki: farmer's response has an invalid tenant_id %q", resp.TenantID)
	}
	urls, err := ValidateBusURLs(resp.NatsURLs)
	if err != nil {
		return fmt.Errorf("pki: enrollment response's nats_urls: %w", err)
	}
	resp.NatsURLs = urls
	return nil
}

// validateIdentity checks the fields enrollment and refresh responses
// share: that they are well-formed and issued to nkeyPub. gatewayJWT is
// checked only if checkGateway (an enrollment request without a box key
// proof legitimately gets none).
func validateIdentity(sproutID, nkeyIdentity, userJWT, gatewayJWT string, checkGateway bool, tenantPub, nkeyPub string) error {
	if !IsValidSproutID(sproutID) {
		return fmt.Errorf("pki: farmer's response has an invalid sprout_id %q", sproutID)
	}
	if nkeyIdentity != nkeyPub {
		return errors.New("pki: farmer's response's nkey_identity is not this sprout's NKey")
	}
	uc, err := natsjwt.DecodeUserClaims(userJWT)
	if err != nil {
		return fmt.Errorf("pki: farmer's response's jwt is not a NATS User JWT: %w", err)
	}
	if uc.Subject != nkeyPub {
		return errors.New("pki: farmer's response's jwt was not issued to this sprout's NKey")
	}
	if checkGateway {
		if _, err := checkGatewayJWT(gatewayJWT, nkeyPub); err != nil {
			return err
		}
	}
	if _, err := DecodeBoxPubKey(tenantPub); err != nil {
		return fmt.Errorf("pki: farmer's response's tenant_x25519_pub: %w", err)
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
		if errors.Is(err, ErrJoinTokenNoFingerprint) || errors.Is(err, ErrTenantKeyFingerprintMismatch) {
			// Not retried: the same token gets the same answer.
			return "", err
		}
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
// sprout's NKey seed and root CA. The tenant ID and tenant X25519 public
// key are checked against any already-pinned ones before anything else
// is written (ErrSproutTenantMismatch; reconcileTenantKeyPin:
// ErrTenantKeyMismatch, unless a continuity proof moves the key pin; the
// sprout ID, ErrSproutIDMismatch), then the gateway JWT, the tenant ID,
// sprout ID and tenant key pins and the bus URLs (nats_urls, which
// LoadSproutBus connects to) are written, and the NATS User JWT last.
// SproutEnrolled keys off the User JWT, so a crash part-way leaves the
// sprout un-enrolled and it enrolls again on restart, which farmer answers
// from its idempotent replay without spending another use of the join
// token.
func PersistEnrollment(resp *EnrollResponse) error {
	if err := checkPinnedSproutTenant(resp.TenantID); err != nil {
		return err
	}
	if err := checkPinnedSproutID(resp.SproutID); err != nil {
		return err
	}
	if err := reconcileTenantKeyPin(resp.SproutID, resp.TenantX25519Pub, resp.TenantX25519Continuity); err != nil {
		return err
	}
	if err := writeFileAtomic(config.SproutGatewayJWTFile, []byte(resp.GatewayJWT), 0o600); err != nil {
		return fmt.Errorf("pki: persisting gateway JWT: %w", err)
	}
	setCurrentGatewayJWT(resp.GatewayJWT)
	if err := pinSproutTenant(resp.TenantID); err != nil {
		return err
	}
	if err := pinSproutID(resp.SproutID); err != nil {
		return err
	}
	if err := pinTenantX25519Pub(resp.TenantX25519Pub); err != nil {
		return err
	}
	// Not a pin: every enrollment replaces it (or removes it, when farmer
	// sent none, which falls back to FarmerBusURL).
	if err := persistBusURLs(resp.NatsURLs); err != nil {
		return err
	}
	// Not a secret without the NKey seed, but there's no reason for
	// anything but the sprout to read it.
	if err := writeFileAtomic(config.SproutUserJWTFile, []byte(resp.JWT), 0o600); err != nil {
		return fmt.Errorf("pki: persisting NATS User JWT: %w", err)
	}
	return nil
}

// checkPinnedTenantKey returns ErrTenantKeyMismatch if a tenant X25519
// public key is already pinned and pub differs from it. No pin yet is not
// an error.
func checkPinnedTenantKey(pub string) error {
	existing, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pki: reading pinned tenant X25519 public key: %w", err)
	}
	if strings.TrimSpace(string(existing)) != pub {
		return ErrTenantKeyMismatch
	}
	return nil
}

// pinTenantX25519Pub writes pub as the pinned tenant X25519 public key if
// none is pinned yet. It never replaces a pin, and a different key is
// ErrTenantKeyMismatch; the only way a pin moves is
// reconcileTenantKeyPin's verified continuity proof.
func pinTenantX25519Pub(pub string) error {
	err := writeFileOnce(config.SproutTenantX25519PubFile, []byte(pub), 0o644)
	if err == nil {
		return nil
	}
	if os.IsExist(err) {
		return checkPinnedTenantKey(pub)
	}
	return fmt.Errorf("pki: pinning tenant X25519 public key: %w", err)
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

// RefreshGatewayJWT gets a fresh gateway JWT from POST /v1/refresh and
// persists it. The request is nkey_pub and a sealed s2f.refresh
// (SproutSealedRefresh: the box key, to the pinned tenant key, naming the
// pinned tenant and sprout ID); no NKey signature and no join token. The
// pins and keys it needs are checked first, and a sprout missing one
// can't refresh at all and must be re-enrolled (fatal, IsFatalRefreshError:
// ErrTenantKeyNotPinned, ErrSproutTenantNotPinned, ErrSproutIDNotPinned,
// ErrSproutBoxNotReady).
//
// Farmer's reply must open under the pinned tenant key, for this sprout
// and tenant, as the reply to this very request (sproutOpenRefreshReply);
// anything else is an error and nothing is written. The result is then
// validated in full, and its tenant X25519 key checked against the pinned
// one, before anything is written: a different key re-pins only with a
// continuity proof that verifies (reconcileTenantKeyPin); otherwise it
// returns ErrTenantKeyMismatch and persists nothing. Its tenant_id is
// checked against the tenant pinned at enrollment the same way
// (checkRefreshTenant: ErrSproutTenantMismatch). If farmer returns a
// different NATS User JWT than the one on disk (for instance, re-minted
// after a signing key change), that is persisted too and picked up on the
// sprout's next start. It returns the sprout_id farmer re-issued.
//
// A refresh farmer refuses (the generic 401) is an ordinary, retryable
// error: farmer gives no reason, and nothing it could send unsealed would
// be authenticated. That includes a sprout pinned to a tenant key farmer
// no longer holds (a severing rotation): it can't seal anything farmer
// opens, nor open anything farmer seals, so it is cut off until it is
// re-enrolled, and its refreshes keep failing.
func RefreshGatewayJWT(ctx context.Context) (string, error) {
	kp, err := loadSproutNKey()
	if err != nil {
		return "", err
	}
	nkeyPub, err := kp.PublicKey()
	kp.Wipe()
	if err != nil {
		return "", fmt.Errorf("pki: sprout NKey public key: %w", err)
	}
	if _, err := os.Stat(config.SproutTenantX25519PubFile); os.IsNotExist(err) {
		return "", ErrTenantKeyNotPinned
	}
	if _, err := SproutTenantID(); err != nil {
		return "", err
	}
	sproutID, err := PinnedSproutID()
	if err != nil {
		return "", err
	}
	// Each try seals afresh: farmer opens a sealed message only once.
	var wire refreshWireResponse
	var msgID string
	err = retryWhileBusy(ctx, "/v1/refresh", func() error {
		sealed, id, err := SproutSealedRefresh(sproutID, nkeyPub)
		if err != nil {
			return fmt.Errorf("pki: sealing the refresh request: %w", err)
		}
		msgID = id
		return postToFarmer(ctx, "/v1/refresh", refreshWireRequest{NKeyPub: nkeyPub, Sealed: sealed}, &wire)
	})
	if err != nil {
		return "", err
	}
	resp, err := sproutOpenRefreshReply(sproutID, msgID, wire.Sealed)
	if err != nil {
		return "", fmt.Errorf("pki: farmer's refresh reply: %w", err)
	}
	if err := validateIdentity(resp.SproutID, resp.NKeyIdentity, resp.JWT, resp.GatewayJWT, true, resp.TenantX25519Pub, nkeyPub); err != nil {
		return "", err
	}
	if resp.SproutID != sproutID {
		return "", ErrSproutIDMismatch
	}
	if err := checkRefreshTenant(resp.TenantID); err != nil {
		return "", err
	}
	if err := reconcileTenantKeyPin(resp.SproutID, resp.TenantX25519Pub, resp.TenantX25519Continuity); err != nil {
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
		log.Infof("refresh: farmer returned a new NATS User JWT; it takes effect on the next sprout restart")
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
// TTL, is refreshed immediately. sproutID is the sprout's current ID; a
// refresh that re-issues a different one is logged, not adopted, since
// the sprout's subscriptions are already bound to its current ID.
//
// It returns nil when ctx is done, and IsFatalRefreshError's errors
// (without retrying, since a retry would get the same answer) when
// farmer's tenant key or tenant ID can't be checked against the pinned
// one; the caller must treat that as fatal.
func RunGatewayJWTRefresher(ctx context.Context, sproutID string, retryDelay time.Duration) error {
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
			log.Debugf("refresh: next gateway JWT refresh in %s", wait)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		gotID, err := RefreshGatewayJWT(ctx)
		if IsFatalRefreshError(err) {
			return err
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Errorf("refresh: refreshing gateway JWT failed, retrying in %s: %v", backoff, err)
			failed = true
			wait = backoff
			backoff = min(backoff*2, maxRefreshRetryDelay)
			continue
		}
		if gotID != sproutID {
			log.Errorf("refresh: farmer re-issued sprout_id %q, but this sprout runs as %q", gotID, sproutID)
		}
		log.Debugf("refresh: refreshed gateway JWT")
		failed = false
		backoff = retryDelay
	}
}

// writeFileAtomic writes data to path via a temp file in the same
// directory and a rename, then fsyncs the directory (syncDir), so a crash
// or power loss never leaves a truncated credential behind or loses the
// new one, and a concurrent reader sees the old contents or the new,
// never a partial file.
//
// FLAG FOR SECURITY REVIEW. It writes the sprout's credentials and pins:
// its User and gateway JWTs, its box keys and the tenant X25519 key it
// pinned (enrollclient.go, sproutbox.go). Farmer writes no file (E3).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("pki: no path configured")
	}
	dir := filepath.Dir(path)
	if err := mkdirAllDurable(dir); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// mkdirAllDurable is os.MkdirAll(dir, 0o755) that also fsyncs the parent
// of every directory it creates, so a new credential directory's own
// entry survives a power loss along with the file written into it
// (syncDir covers only the entries inside dir).
func mkdirAllDurable(dir string) error {
	var created []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); !os.IsNotExist(err) {
			break
		}
		created = append(created, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, d := range created {
		if err := syncDir(filepath.Dir(d)); err != nil {
			return err
		}
	}
	return nil
}

// syncDir fsyncs dir, so a rename or link into it survives a power loss
// (security review 2026-10, I12): without it the new directory entry can
// be lost even though the file's data was synced. Windows has no
// directory fsync (FlushFileBuffers refuses a directory handle) and NTFS
// journals the rename itself, so there it does nothing. A variable so a
// test can see when it runs.
var syncDir = func(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("pki: syncing directory %s: %w", dir, err)
	}
	return d.Close()
}

// writeFileOnce is writeFileAtomic that fails with an os.IsExist error
// instead of replacing path if it already exists.
func writeFileOnce(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("pki: no path configured")
	}
	dir := filepath.Dir(path)
	if err := mkdirAllDurable(dir); err != nil {
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
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// checkRefreshTenant checks tenantID, the tenant a /v1/refresh response
// names, against the one this sprout pinned at enrollment (security
// review 2026-10, H3): ErrSproutTenantMismatch if it differs. A sprout
// with no tenant pin gets ErrSproutTenantNotPinned rather than pinning
// whatever the refresh names: the pin is set at enrollment only, and a
// sprout enrolled before SEC.3b (nothing is deployed) re-enrolls. Both
// are fatal (IsFatalRefreshError), and nothing from the response is
// persisted.
func checkRefreshTenant(tenantID string) error {
	if !IsValidTenantID(tenantID) {
		return fmt.Errorf("pki: farmer's refresh response has an invalid tenant_id %q", tenantID)
	}
	pinned, err := SproutTenantID()
	if err != nil {
		return err
	}
	if pinned != tenantID {
		return ErrSproutTenantMismatch
	}
	return nil
}

// IsFatalRefreshError reports whether err, from RefreshGatewayJWT (or a
// download that refreshed first), means the sprout can't trust farmer's
// answer about its tenant, tenant key or sprout ID, or can't make a
// sealed refresh at all (no box key, or a pin missing): a retry would get
// the same answer, so the sprout must stop and be re-enrolled.
func IsFatalRefreshError(err error) bool {
	return errors.Is(err, ErrTenantKeyMismatch) || errors.Is(err, ErrTenantKeyNotPinned) ||
		errors.Is(err, ErrSproutTenantMismatch) || errors.Is(err, ErrSproutTenantNotPinned) ||
		errors.Is(err, ErrSproutIDMismatch) || errors.Is(err, ErrSproutIDNotPinned) ||
		errors.Is(err, ErrSproutBoxNotReady)
}
