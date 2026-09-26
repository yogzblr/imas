package pki

// Replay cache for proof-of-possession signatures
// (docs/design/imas-envoy-enrollment-design.md, "Replay cache").
//
// FLAG FOR SECURITY REVIEW. A signed /v1/enroll or /v1/refresh request
// verifies for as long as its timestamp stays inside EnrollSigMaxSkew, so
// on its own a captured request could be resubmitted for up to that long
// to mint fresh gateway JWTs. claimSignedPayload makes every verified
// request single-use: the first request to claim it proceeds, and any
// later request carrying the same signed payload fails, whichever farmer
// replica it lands on.
//
// Claims live in Valkey, the same cluster farmer already uses for sprout
// heartbeats (config.ValkeyAddrs, internal/heartbeat), not in an
// in-process map: farmer runs as several replicas behind Envoy, and a map
// would let a resubmission routed to a different replica through, and
// would forget every claim on a restart. Each claim is one SET NX with a
// TTL, so Valkey expires it without any sweeping.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/valkey-io/valkey-go"
)

// replayKeyPrefix namespaces replay-cache keys in the Valkey farmer shares
// with internal/heartbeat ("imas:heartbeat:").
const replayKeyPrefix = "imas:replay:"

// replayCacheClockMargin extends each claim's lifetime past the end of
// its timestamp's skew window, to cover clock differences between farmer
// replicas: a claim made on one replica must outlive the window in which
// another, whose clock runs behind, would still accept its payload.
const replayCacheClockMargin = time.Minute

// replayCacheTimeout bounds one claim's round trip to Valkey. A claim
// that doesn't complete in time fails the request, like any other error.
const replayCacheTimeout = time.Second

// replayClient is the Valkey client claims are written through. Nil until
// SetReplayCacheClient is called, and while it's nil every claim fails:
// enrollment and refresh fail closed rather than run without replay
// protection.
var replayClient valkey.Client

// SetReplayCacheClient installs the Valkey client the replay cache writes
// through. Call once at startup (cmd/farmer's initValkeyClient).
func SetReplayCacheClient(c valkey.Client) { replayClient = c }

// errSignatureReplayed is claimSignedPayload's error for a payload that
// has already been claimed. Logged locally only; callers collapse it to
// ErrEnrollmentFailed like every other failure.
var errSignatureReplayed = errors.New("signed request already used")

// replayKey returns the Valkey key for one signed request: the hex SHA-256
// of the decoded signature followed by the signed payload.
//
// It covers the decoded signature bytes, not the nkey_sig string:
// base64url decoding ignores a final character's unused low bits, so one
// signature has several string forms but only one byte form (and Ed25519
// verification accepts only one byte form: a non-canonical scalar or
// point encoding fails). It covers the signature and not only the payload
// because a refresh payload is predictable (a domain tag, a timestamp and
// a public nkey_pub), and farmer's Valkey connection has no auth yet:
// anyone able to write to Valkey could otherwise claim a sprout's future
// payloads in advance and lock it out of refreshing. The signature can
// only be computed with the NKey seed. The signature is a fixed 64 bytes,
// so putting it first keeps the hashed input unambiguous.
//
// Not keyed on (tenant_id, sprout_id): the key is globally unique by
// construction (the payload carries its domain tag, nkey_pub and
// timestamp), and a request isn't tied to a tenant until after it has
// been claimed.
func replayKey(payload, sig []byte) string {
	h := sha256.New()
	h.Write(sig)
	h.Write(payload)
	return replayKeyPrefix + hex.EncodeToString(h.Sum(nil))
}

// claimSignedPayload records the request that signed payload with sig at
// timestamp as used. It returns nil only for the first claim of that
// request. A resubmission fails with errSignatureReplayed, and so does
// every Valkey error, timeout or missing client with its own error: either
// way the caller must reject the request (fail closed). Call it only after
// the signature has verified, and before anything is issued.
//
// SET NX is atomic in Valkey, so of two replicas claiming the same request
// at once, exactly one wins. The TTL is relative, computed from farmer's
// own clock, so Valkey's clock doesn't need to agree with farmer's.
func claimSignedPayload(ctx context.Context, payload, sig []byte, timestamp int64) error {
	if replayClient == nil {
		return errors.New("no replay cache configured (SetReplayCacheClient was never called)")
	}
	expiresAt := time.Unix(timestamp, 0).Add(EnrollSigMaxSkew + replayCacheClockMargin)
	ttl := max(expiresAt.Sub(enrollNow()), time.Second)

	ctx, cancel := context.WithTimeout(ctx, replayCacheTimeout)
	defer cancel()
	cmd := replayClient.B().Set().Key(replayKey(payload, sig)).Value("1").Nx().
		ExSeconds(int64((ttl + time.Second - 1) / time.Second)).Build()
	err := replayClient.Do(ctx, cmd).Error()
	if valkey.IsValkeyNil(err) {
		return errSignatureReplayed
	}
	return err
}
