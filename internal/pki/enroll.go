package pki

// Sprout enrollment: docs/design/imas-envoy-enrollment-design.md and
// cloudxp-machine-manager-api-design.md §3 ("the one moment in the whole
// system where a caller has no credential yet").
//
// FLAG FOR SECURITY REVIEW per the task brief — this is the literal front
// door of the trust chain. Every request must first prove it holds the
// seed of the nkey_pub it presents (verifyNKeyPossession). After that, a
// valid, unexhausted join token is the only authorization check between
// an anonymous caller and a new signed sprout identity. For an
// already-enrolled nkey_pub, that proof of possession is the only check
// before its identity is replayed. Each signed request is single-use
// (claimSignedPayload, replaycache.go), so a captured one can't be
// resubmitted while its timestamp is still inside the skew window.
//
// Proof of possession of the box key (security review 2026-10, H3). The
// NKey signature proves the caller holds the NKey seed, not that it holds
// the private half of sprout_pub, the X25519 box key farmer will seal
// that sprout's commands to. Without a second proof, an enroller could
// register a box public key it copied from another sprout, and farmer
// would seal its commands to that key. So a box key is only recorded once
// the sprout has proved it holds the private half:
//
//  1. The first enrollment (the join token path) issues the identity but
//     records no box key: the sprout can't prove anything yet, because
//     it doesn't know the tenant's box public key, and X25519 has no
//     signatures. It does learn the tenant key from the response.
//  2. The sprout immediately enrolls again, on the replay path (its NKey
//     is now known, no token is spent), with sprout_pub_proof: a
//     payloadbox message (PurposeEnrollProof) naming its tenant, sprout
//     ID, NKey and sprout_pub, sealed with its box private key to the
//     tenant's box public key. verifyEnrollProof opens it with the
//     tenant's private key paired with sprout_pub. box authenticates:
//     only a holder of the sprout_pub private key (or of the tenant
//     private key, which is farmer) can produce a box that opens under
//     that pair. Then, and only then, sprout_pub is recorded.
//
// Until step 2, farmer has no box key for the sprout and seals nothing to
// it. A proof that doesn't verify fails the whole request. A proof is
// only accepted on the replay path, and only to record the sprout's
// first box key (or re-assert the one on record); changing a box key is
// a rotation (boxkeys.go), which needs the current key.
//
// A first box key only from the exchange that issued the identity
// (security review 2026-10-b, B2; SEC.7b, FLAG FOR SECURITY REVIEW). The
// proof binds sprout_pub to itself: whoever holds a box private key can
// prove it, so on its own it can't say whether that key is the sprout's.
// Before SEC.7b, any accepted sprout with no active box key (an abandoned
// step 1, revoked keys, or one accepted outside this flow) took the first
// proven key it was sent, and a compromised bus can get the NKey
// signature that request needs over a CONNECT nonce. So step 1, and only
// step 1 (the join token path, which issues the identity), also returns
// an enrollment binding (issueEnrollBinding): a payloadbox message farmer
// seals to itself under the tenant key, naming the tenant, sprout ID,
// nkey_pub and the sprout_pub the NKey-signed step 1 request carried, and
// valid for EnrollBindingTTL. Step 2 returns it, and a first box key is
// recorded only when the binding opens, names exactly the sprout_pub
// being proven, is fresh, and its message ID is claimed once
// cluster-wide (ClaimSealedMessage). Only farmer can make one (its tenant
// private key is the only way to seal under the tenant key pair), so a
// bus that reads step 1's response still can't bind another key, and an
// unauthenticated Valkey can at worst pre-claim one (refusing an
// enrollment), never forge one. The replay path never issues a binding.
// An accepted sprout with no active box key and no live binding is a
// closed state: every replay request from it is refused, with or without
// a proof, and it must be enrolled again under a new NKey with a fresh
// join token (an operator deletes the old identity; see
// docs/design/imas-envoy-enrollment-design.md).
//
// A gateway JWT only for a box key proof (J.2, FLAG FOR SECURITY REVIEW).
// The NKey seed also signs the bus's CONNECT nonce, and a compromised bus
// chooses that nonce, so it can get EnrollSigningPayload signed for any
// sprout, with any join token it likes. The replay path never looks at the
// join token, so before J.2 that signature alone replayed an enrolled
// sprout's identity with a fresh gateway JWT, which reads the sprout's
// staged rendered recipe from /files/: the same hole as the NKey-signed
// refresh. Now a request with only the NKey proof (step 1 on either path,
// or a retry of it) gets the identity, the tenant and its key, and no
// gateway JWT. The gateway JWT comes only with step 2's sprout_pub_proof,
// whose message ID is claimed once cluster-wide (ClaimSealedMessage), or
// from a sealed refresh (refreshsealed.go). The sprout never used step
// 1's gateway JWT.
//
// Every failure path in Enroll returns the single generic
// ErrEnrollmentFailed sentinel (design doc §3.4) — unknown key_id,
// malformed token, a hash mismatch, revoked, expired, exhausted, and a
// lost redemption race are all deliberately indistinguishable over the
// wire, to deny an attacker an oracle for enumerating key_ids or timing a
// race against expiry. The specific reason is logged locally (log.Warnf
// below) for operator visibility, never returned.
import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// ErrEnrollmentFailed is the single error every enrollment failure mode
// collapses to before crossing the HTTP boundary (design doc §3.4).
var ErrEnrollmentFailed = errors.New("enrollment_failed")

// gatewayJWTMinter abstracts minting the Envoy-facing companion token
// (internal/gatewayjwt — see its package doc for why a second token
// exists at all: the NATS User JWT's "ed25519-nkey" alg header isn't
// something a standard JOSE validator like Envoy's jwt_authn recognizes).
// An interface here, rather than a direct *gatewayjwt.GatewaySigner
// dependency, lets tests swap in a fake instead of requiring a live
// OpenBao Transit backend — the same reasoning as enrollmentKeyStore
// above.
type gatewayJWTMinter interface {
	MintGatewayJWT(ctx context.Context, claims gatewayjwt.GatewayClaims) (string, error)
}

// gatewayMinter is nil until SetGatewaySigner is called (see
// cmd/farmer/main.go). Enroll fails closed — ErrEnrollmentFailed, not a
// panic or a response silently missing gateway_jwt — if it's still nil
// when an enrollment is attempted.
var gatewayMinter gatewayJWTMinter

// SetGatewaySigner installs the signer Enroll mints gateway JWTs
// through. Call once at startup, after gatewayjwt.NewGatewaySigner.
func SetGatewaySigner(s gatewayJWTMinter) { gatewayMinter = s }

// enrollmentKeyRow mirrors the columns of saas.enrollment_keys this farmer
// is granted SELECT on (design doc §4.1/§5.1). It deliberately excludes
// asset_id: that column belongs to the not-yet-built §1.3 asset-linking
// work and isn't part of internal/saasapi/model.go's EnrollmentKey struct
// yet either.
type enrollmentKeyRow struct {
	TenantID  string
	KeyHash   string
	Expiry    time.Time
	MaxUses   int
	UsedCount int
	Revoked   bool
}

// enrollmentKeyStore abstracts reads/writes against saas.enrollment_keys.
// The production implementation (mysqlEnrollmentKeyStore, below) issues
// raw, schema-qualified SQL against this package's shared `db` handle —
// which in production points at the same PXC cluster farmer's own schema
// lives in (design doc §5.1: single cluster, cross-schema grants), but in
// this package's tests is an in-memory SQLite database (see
// pki_test.go's newTestDB) that can't run MySQL-specific cross-schema SQL
// (schema-qualified table names, NOW(), etc.). Tests install a fake here
// instead of standing up a real MySQL instance.
type enrollmentKeyStore interface {
	lookup(keyID string) (*enrollmentKeyRow, error)
	// redeem performs design doc §3.3 step 4's atomic check-and-increment,
	// returning whether this call actually redeemed a use (false means the
	// WHERE guard didn't match — the key was exhausted/revoked/expired by
	// the time this ran, including losing a race to a concurrent redeemer).
	redeem(keyID string) (bool, error)
}

var enrollKeyStore enrollmentKeyStore = mysqlEnrollmentKeyStore{}

type mysqlEnrollmentKeyStore struct{}

func (mysqlEnrollmentKeyStore) lookup(keyID string) (*enrollmentKeyRow, error) {
	var row enrollmentKeyRow
	err := db.Raw(
		`SELECT tenant_id, key_hash, expiry, max_uses, used_count, revoked
		 FROM saas.enrollment_keys WHERE key_id = ?`, keyID,
	).Row().Scan(&row.TenantID, &row.KeyHash, &row.Expiry, &row.MaxUses, &row.UsedCount, &row.Revoked)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (mysqlEnrollmentKeyStore) redeem(keyID string) (bool, error) {
	res := db.Exec(
		`UPDATE saas.enrollment_keys
		 SET used_count = used_count + 1, last_used_at = NOW()
		 WHERE key_id = ? AND used_count < max_uses AND revoked = FALSE AND expiry > NOW()`,
		keyID,
	)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// UseInMemoryJoinToken makes Enroll accept joinToken ("{key_id}.{secret}")
// for tenantID up to maxUses times, from an in-memory store that replaces
// saas.enrollment_keys until the returned function restores it. For tests
// outside this package that drive POST /v1/enroll end to end
// (internal/api/handlers): the production store's cross-schema MySQL
// can't run on their SQLite database, and since SEC.7b a sprout's first
// box key can only be recorded through the join token path, so those tests
// can no longer start from a sprout accepted outside it. Never called
// outside tests.
func UseInMemoryJoinToken(joinToken, tenantID string, maxUses int) (restore func()) {
	keyID, secret, ok := splitJoinToken(joinToken)
	if !ok {
		panic("pki: UseInMemoryJoinToken: malformed join token")
	}
	orig := enrollKeyStore
	enrollKeyStore = &memoryEnrollmentKeyStore{keyID: keyID, row: enrollmentKeyRow{
		TenantID: tenantID, KeyHash: hashSecret(secret), Expiry: time.Now().Add(24 * time.Hour), MaxUses: maxUses,
	}}
	return func() { enrollKeyStore = orig }
}

// memoryEnrollmentKeyStore holds UseInMemoryJoinToken's one join token.
type memoryEnrollmentKeyStore struct {
	mu    sync.Mutex
	keyID string
	row   enrollmentKeyRow
}

func (m *memoryEnrollmentKeyStore) lookup(keyID string) (*enrollmentKeyRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if keyID != m.keyID {
		return nil, sql.ErrNoRows
	}
	row := m.row
	return &row, nil
}

func (m *memoryEnrollmentKeyStore) redeem(keyID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if keyID != m.keyID || m.row.Revoked || m.row.UsedCount >= m.row.MaxUses || time.Now().After(m.row.Expiry) {
		return false, nil
	}
	m.row.UsedCount++
	return true, nil
}

// EnrollResult is what a successful Enroll call hands back to the HTTP
// layer for the design doc §3.2 success response.
type EnrollResult struct {
	SproutID string
	// JWT is the native NATS User JWT (workstream B, "ed25519-nkey" alg)
	// — what nats-server itself validates. Unchanged by the gateway JWT
	// work below.
	JWT string
	// GatewayJWT is the standard alg:EdDSA companion token
	// (internal/gatewayjwt) presented to Envoy's jwt_authn-gated wss://
	// and recipe-download routes. Minted fresh, and only for a request
	// that proved possession of the sprout's box key (a verified
	// sprout_pub_proof, or a sealed refresh); empty for a request with
	// the NKey proof alone (see the package comment). It's meant to be
	// short-lived (config.GatewayJWTTTL), unlike the cached-to-disk NATS
	// JWT above.
	GatewayJWT string
	// TenantID is the sprout's tenant, which the sprout pins at
	// enrollment and every sealed message names (payloadbox.Message).
	TenantID string
	// TenantX25519Pub is the sprout's tenant's current NaCl box public
	// key, backed by OpenBao custody of the private half (see
	// tenantbox.go).
	TenantX25519Pub string
	// TenantX25519Continuity is TenantKeyContinuity's proof, sealed to
	// this sprout's box key, that TenantX25519Pub succeeds the tenant
	// keys the sprout may have pinned before a rotation; nil if the
	// tenant has never rotated.
	TenantX25519Continuity json.RawMessage
	// EnrollBinding is set only on the response that issued the identity
	// (the join token path): the farmer-sealed binding the sprout returns
	// with its box key proof (issueEnrollBinding). Opaque to the sprout.
	EnrollBinding json.RawMessage
}

// EnrollRequest carries one POST /v1/enroll request's fields into Enroll.
//
// Timestamp and NKeySig are the proof-of-possession for NKeyPub
// (docs/design/imas-envoy-enrollment-design.md, "Proof of possession"):
// NKeySig is the sprout's NKey seed's signature (nkeys KeyPair.Sign) over
// EnrollSigningPayload(Timestamp, NKeyPub, Hostname, SproutPub,
// JoinToken), unpadded base64url-encoded — the same encoding NATS's own
// CONNECT nonce signature uses.
type EnrollRequest struct {
	JoinToken string
	NKeyPub   string
	Hostname  string
	SproutPub string
	// Timestamp is the Unix time, in seconds, at which the sprout signed
	// this request.
	Timestamp int64
	NKeySig   string
	// SproutPubProof is the sprout's proof of possession of SproutPub's
	// private half (see the package comment and verifyEnrollProof), sent
	// on the second, replay-path request of a first enrollment. Not
	// covered by NKeySig: the proof binds NKeyPub and SproutPub itself,
	// and is sealed so only a holder of the box private key could have
	// made it.
	SproutPubProof json.RawMessage
	// EnrollBinding is the binding the first request's response carried
	// (EnrollResult.EnrollBinding), returned with SproutPubProof. Required
	// to record a first box key; ignored once one is active. Not covered
	// by NKeySig: farmer sealed it to itself.
	EnrollBinding json.RawMessage
}

// enrollSigDomain prefixes every enrollment signing payload so a
// signature made for this purpose can't be lifted from, or mistaken for,
// anything else the same NKey signs (NATS CONNECT nonces in particular).
// Bump its version for any change to EnrollSigningPayload's layout.
const enrollSigDomain = "imas-enroll-v1"

// EnrollSigMaxSkew bounds how far a request's Timestamp may sit from
// farmer's clock, in either direction, and still be accepted. It is the
// window in which a captured signed request can be resubmitted. See the
// design doc's "Proof of possession" section for why a timestamp was
// chosen over a server-issued nonce.
const EnrollSigMaxSkew = 5 * time.Minute

// enrollNow is time.Now, swappable in tests.
var enrollNow = time.Now

// EnrollSigningPayload returns the exact bytes a sprout signs with its
// NKey seed to prove possession of nkeyPub: enrollSigDomain, then each
// field, newline-separated, in this order. Every request field is covered
// so none can be swapped under a captured signature. It is exported so a
// Go client and the tests build byte-identical input to what Enroll
// verifies. Enroll rejects any field containing a newline, so the
// encoding is unambiguous.
func EnrollSigningPayload(timestamp int64, nkeyPub, hostname, sproutPub, joinToken string) []byte {
	return []byte(strings.Join([]string{
		enrollSigDomain,
		strconv.FormatInt(timestamp, 10),
		nkeyPub,
		hostname,
		sproutPub,
		joinToken,
	}, "\n"))
}

// verifyNKeyPossession checks req.NKeySig against req.NKeyPub over
// EnrollSigningPayload, and req.Timestamp against EnrollSigMaxSkew, and
// returns the verified payload and decoded signature for
// claimSignedPayload. The error is for local logging only; Enroll
// collapses it to ErrEnrollmentFailed.
func verifyNKeyPossession(req EnrollRequest) (payload, sig []byte, err error) {
	for _, f := range []string{req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken} {
		if strings.ContainsRune(f, '\n') {
			return nil, nil, errors.New("a signed field contains a newline")
		}
	}
	payload = EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken)
	sig, err = verifyTimestampedNKeySig(req.NKeyPub, req.Timestamp, req.NKeySig, payload)
	if err != nil {
		return nil, nil, err
	}
	return payload, sig, nil
}

// verifyTimestampedNKeySig checks that timestamp is within
// EnrollSigMaxSkew of farmer's clock and that sigB64 (unpadded base64url)
// is nkeyPub's signature over payload, and returns the decoded signature.
// Shared by enrollment (verifyNKeyPossession) and gateway JWT refresh
// (RefreshSprout), which sign different, domain-tagged payloads.
func verifyTimestampedNKeySig(nkeyPub string, timestamp int64, sigB64 string, payload []byte) ([]byte, error) {
	skew := enrollNow().Sub(time.Unix(timestamp, 0))
	if skew > EnrollSigMaxSkew || skew < -EnrollSigMaxSkew {
		return nil, errors.New("timestamp " + strconv.FormatInt(timestamp, 10) + " is outside the allowed skew")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("nkey_sig is not unpadded base64url")
	}
	kp, err := nkeys.FromPublicKey(nkeyPub)
	if err != nil {
		return nil, err
	}
	if err := kp.Verify(payload, sig); err != nil {
		return nil, errors.New("nkey_sig does not verify against nkey_pub")
	}
	return sig, nil
}

// Enroll implements design doc §3.3's step-by-step flow end to end:
// proof of possession of the NKey, the idempotency check, join-token
// lookup/validation, atomic redemption, and minting. This repo runs
// farmer and the bus in one process, so there's no
// internal.sprout.mint NATS hop here (cloudxp-machine-manager-api-design.md
// §2.2's subject exists for a split SaaS-API/farmer deployment this repo
// doesn't have yet) — farmer validates the token against saas schema
// directly and mints the JWT itself, in one call.
func Enroll(ctx context.Context, req EnrollRequest) (*EnrollResult, error) {
	joinToken, nkeyPub, hostname, sproutPub := req.JoinToken, req.NKeyPub, req.Hostname, req.SproutPub
	if !nkeys.IsValidPublicUserKey(nkeyPub) {
		log.Warnf("enroll: rejected malformed nkey_pub")
		return nil, ErrEnrollmentFailed
	}
	// Only step 2 mints a gateway JWT, so check the signer is there before
	// step 1 can redeem a join token for an enrollment that can't finish.
	if gatewayMinter == nil {
		log.Errorf("enroll: no gateway JWT signer configured (SetGatewaySigner was never called)")
		return nil, ErrEnrollmentFailed
	}
	// Validated up front, alongside nkeyPub, and before any DB work below:
	// a malformed sprout_pub is a client-side mistake, not a real
	// enrollment attempt, and shouldn't cost a possibly single-use join
	// token's redemption (same reasoning as resolveEnrollSproutID's
	// ordering further down).
	if _, err := decodeBoxPub(sproutPub); err != nil {
		log.Warnf("enroll: rejected malformed sprout_pub: %v", err)
		return nil, ErrEnrollmentFailed
	}

	// Proof of possession, before anything is looked up by nkey_pub (FLAG
	// FOR SECURITY REVIEW). nkey_pub is not a secret: Envoy forwards it
	// upstream as x-imas-sprout-nkey, and it appears in every JWT this
	// sprout holds. Without this check, the idempotency replay below would
	// mint a gateway JWT for an already-enrolled sprout to anyone who knew
	// its nkey_pub. First-time enrollments are checked too: otherwise a
	// join-token holder could register a nkey_pub whose seed they don't
	// hold, and when the real owner later enrolls, replay would place its
	// sprout in their tenant.
	signedPayload, sig, err := verifyNKeyPossession(req)
	if err != nil {
		log.Warnf("enroll: rejected proof of possession for nkey_pub %s: %v", nkeyPub, err)
		return nil, ErrEnrollmentFailed
	}

	// Step 1 (design doc §3.3): idempotency check first, before the join
	// token is even looked at. A sprout retrying after a dropped
	// connection generates its keypair once, locally, before ever calling
	// out — so a retry presents the same nkey_pub and should get the same
	// identity back rather than burning a second use of a possibly
	// single-use token. This has to search across every tenant (see
	// SproutIDAndTenantForNKey) rather than just "the current" one: the
	// caller's tenant isn't known yet at this point (that only comes from
	// decoding the join token below), but nkey_pub alone already
	// unambiguously identifies both the sprout and its tenant if it's been
	// accepted before.
	if replayTenantID, sproutID, err := SproutIDAndTenantForNKey(nkeyPub); err == nil {
		if err := claimSignedPayload(ctx, signedPayload, sig, req.Timestamp); err != nil {
			log.Warnf("enroll: rejected resubmitted or unrecordable signed request for nkey_pub %s: %v", nkeyPub, err)
			return nil, ErrEnrollmentFailed
		}
		// The NKey proof alone gets no gateway JWT: a compromised bus can
		// obtain one (see the package comment). Only a verified proof of
		// possession of the box key does.
		proven := len(req.SproutPubProof) > 0
		// An accepted sprout with no active box key is closed: only step
		// 2 of the exchange that issued its identity, carrying that
		// exchange's binding, gives it one (see the package comment).
		if !proven {
			if _, _, err := ValidSproutBoxKeys(replayTenantID, sproutID); err != nil {
				log.Warnf("enroll: refused a replay for sprout %s in tenant %s with no box key proof: it has no active box key (%v); it must be enrolled again under a new NKey with a fresh join token", sproutID, replayTenantID, err)
				return nil, ErrEnrollmentFailed
			}
		}
		if proven {
			if err := recordProvenSproutBoxKey(ctx, replayTenantID, sproutID, nkeyPub, sproutPub, req.SproutPubProof, req.EnrollBinding); err != nil {
				log.Warnf("enroll: refused sprout_pub_proof for sprout %s in tenant %s: %v", sproutID, replayTenantID, err)
				return nil, ErrEnrollmentFailed
			}
		}
		return replayExistingEnrollment(ctx, replayTenantID, sproutID, nkeyPub, proven)
	}
	// A proof is only meaningful for an identity that exists: the sprout
	// can't know its tenant's box key, or its final sprout ID, before
	// the first response.
	if len(req.SproutPubProof) > 0 || len(req.EnrollBinding) > 0 {
		log.Warnf("enroll: rejected a sprout_pub_proof or enroll_binding on a first enrollment for nkey_pub %s", nkeyPub)
		return nil, ErrEnrollmentFailed
	}

	keyID, secret, ok := splitJoinToken(joinToken)
	if !ok {
		log.Warnf("enroll: malformed join token")
		return nil, ErrEnrollmentFailed
	}

	row, err := enrollKeyStore.lookup(keyID)
	if errors.Is(err, sql.ErrNoRows) {
		log.Warnf("enroll: unknown key_id %s", keyID)
		return nil, ErrEnrollmentFailed
	}
	if err != nil {
		log.Errorf("enroll: looking up key_id %s: %v", keyID, err)
		return nil, ErrEnrollmentFailed
	}

	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(row.KeyHash)) != 1 {
		log.Warnf("enroll: key_id %s presented a secret that did not match", keyID)
		return nil, ErrEnrollmentFailed
	}

	// Defense in depth (workstream E, FLAG FOR SECURITY REVIEW): row.TenantID
	// is about to be threaded into filesystem paths (tenantAuthDir) and PXC
	// primary keys for the rest of this call. It's expected to already be a
	// well-formed saasapi-generated ID (idgen.go's "t_"-prefixed IDs), but
	// this fails closed rather than trusting that invariant blindly.
	if !IsValidTenantID(row.TenantID) {
		log.Errorf("enroll: key_id %s has a malformed tenant_id %q", keyID, row.TenantID)
		return nil, ErrEnrollmentFailed
	}

	now := time.Now().UTC()
	switch {
	case row.Revoked:
		log.Warnf("enroll: key_id %s is revoked", keyID)
		return nil, ErrEnrollmentFailed
	case now.After(row.Expiry):
		log.Warnf("enroll: key_id %s is expired", keyID)
		return nil, ErrEnrollmentFailed
	case row.UsedCount >= row.MaxUses:
		log.Warnf("enroll: key_id %s is exhausted", keyID)
		return nil, ErrEnrollmentFailed
	}

	// Resolve the sprout ID before redeeming the token below: this is
	// pure local computation over hostname/nkeyPub, so failing here (bad
	// hostname, too many colliding sprouts) shouldn't burn a use of an
	// otherwise-valid, possibly-single-use token — a client-side mistake
	// on the request shouldn't have the same cost as a real redemption.
	// Scoped to row.TenantID (the enrollment key's own tenant, not any
	// global default) so a hostname collision is only ever checked against
	// that tenant's own sprouts — see resolveEnrollSproutID.
	sproutID, err := resolveEnrollSproutID(row.TenantID, hostname, nkeyPub)
	if err != nil {
		log.Errorf("enroll: resolving sprout id for hostname %q: %v", hostname, err)
		return nil, ErrEnrollmentFailed
	}
	// An NKey revoked by deleting or replacing its sprout (H1) stays
	// revoked: enrolling it again would clear its revocation on the
	// Account and bring the retired host's User JWT back. Checked before
	// redeeming, like the ID above.
	if revoked, err := isNKeyRevoked(row.TenantID, nkeyPub); err != nil || revoked {
		log.Warnf("enroll: nkey_pub %s is revoked in tenant %s, or the check failed (%v)", nkeyPub, row.TenantID, err)
		return nil, ErrEnrollmentFailed
	}

	// row.TenantID (workstream E, FLAG FOR SECURITY REVIEW: tenant
	// isolation correctness) is the enrollment key's real tenant, and is
	// what every PKI/NATS-auth operation below is scoped to — accepting
	// the sprout, minting/reusing its User JWT, and syncing/pushing its
	// tenant's Account (lazily provisioning that tenant's Account if this
	// is its first-ever sprout — see ReloadNKeysForTenant). This is the one
	// place in this package where the tenant comes from real per-request
	// data (saas.enrollment_keys) rather than the process-global tenantID()
	// seam every admin/CLI-driven lifecycle function (AcceptNKey and
	// friends) still uses — see store.go's tenantID() doc comment for why
	// that placeholder remains elsewhere.
	//
	// The signed request is claimed first, so that of two identical
	// requests racing past the idempotency check above, only one goes on
	// to redeem and mint; a later resubmission of it takes the replay path
	// above and fails its claim there. Claimed here, only after the join
	// token has checked out, rather than straight after
	// verifyNKeyPossession: anyone can sign with a freshly generated NKey,
	// so claiming earlier would let unauthenticated callers write keys.
	if err := claimSignedPayload(ctx, signedPayload, sig, req.Timestamp); err != nil {
		log.Warnf("enroll: rejected resubmitted or unrecordable signed request for nkey_pub %s: %v", nkeyPub, err)
		return nil, ErrEnrollmentFailed
	}
	redeemed, err := enrollKeyStore.redeem(keyID)
	if err != nil {
		log.Errorf("enroll: redeeming key_id %s: %v", keyID, err)
		return nil, ErrEnrollmentFailed
	}
	if !redeemed {
		log.Warnf("enroll: key_id %s lost the atomic redemption race (exhausted/revoked/expired between lookup and redeem)", keyID)
		return nil, ErrEnrollmentFailed
	}

	if err := acceptEnrolledNKey(row.TenantID, sproutID, nkeyPub); err != nil {
		log.Errorf("enroll: accepting sprout %s for tenant %s: %v", sproutID, row.TenantID, err)
		return nil, ErrEnrollmentFailed
	}
	// The tenant's X25519 key is read (and, for a tenant's first
	// enrollment, created fresh: tenantbox.go). This sprout's box key is
	// not recorded on this path at all (see below), so a failure here
	// leaves no box key behind.
	tenantPub, err := GetTenantX25519PublicKey(row.TenantID)
	if err != nil {
		log.Errorf("enroll: sprout %s accepted but failed to load tenant %s X25519 key: %v", sproutID, row.TenantID, err)
		return nil, ErrEnrollmentFailed
	}
	// sprout_pub is NOT recorded here: the sprout hasn't proved it holds
	// its private half yet. It does so on its next request, the replay
	// path above (recordProvenSproutBoxKey), once this response has told
	// it the tenant key to seal its proof to.

	signedJWT, err := GetSproutUserJWTForTenant(row.TenantID, sproutID)
	if err != nil {
		log.Errorf("enroll: sprout %s accepted but no readable JWT: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	// A sprout re-enrolling after an interrupted first attempt may
	// already have pinned an earlier tenant key; see reissueExistingIdentity.
	continuity, err := TenantKeyContinuity(row.TenantID, sproutID, sproutPub)
	if err != nil {
		log.Errorf("enroll: sprout %s enrolled but failed to build tenant key continuity proof: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	// No gateway JWT yet: the sprout hasn't proved it holds a box key.
	// Its next request, on the replay path with sprout_pub_proof and this
	// binding, gets one (see the package comment). This is the only place
	// a binding is issued.
	binding, err := issueEnrollBinding(row.TenantID, sproutID, nkeyPub, sproutPub)
	if err != nil {
		log.Errorf("enroll: sprout %s enrolled but failed to issue its enrollment binding: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}

	log.Infof("enroll: sprout %s enrolled via key_id %s", sproutID, keyID)
	return &EnrollResult{SproutID: sproutID, JWT: signedJWT, TenantID: row.TenantID, TenantX25519Pub: tenantPub, TenantX25519Continuity: continuity, EnrollBinding: binding}, nil
}

// EnrollBindingTTL is how long after step 1 an enrollment binding is
// accepted (see the package comment). The sprout sends step 2 straight
// after step 1, so this only has to cover a few retries; a sprout that
// misses it is closed and has to be enrolled again. It must stay below
// SealedClaimTTL minus replayCacheClockMargin, so that a binding's claim
// outlives every replica that would still accept it. Owner decision,
// 2026-10-05 (SEC.7d, answering SEC.7b's open question): keep 5 minutes.
const EnrollBindingTTL = 5 * time.Minute

// enrollBindingPurpose is an enrollment binding's payloadbox purpose:
// farmer to itself. Defined here rather than in payloadbox because no
// other party ever seals or opens one, and the tenant self-pair it is
// sealed under (openEnrollBinding) opens nothing else.
const enrollBindingPurpose = "f2f.enroll.binding"

// enrollBindingBody is an enrollment binding's body: the NKey and box
// key the identity-issuing request named.
type enrollBindingBody struct {
	NKeyPub   string `json:"nkey_pub"`
	SproutPub string `json:"sprout_pub"`
}

// issueEnrollBinding seals, from farmer to farmer, the binding of
// tenantID's sproutID to nkeyPub and sproutPub, as the identity-issuing
// request named them (see the package comment). Its message ID is the
// one-time nonce recordProvenSproutBoxKey claims.
func issueEnrollBinding(tenantID, sproutID, nkeyPub, sproutPub string) (json.RawMessage, error) {
	pairs, err := tenantSelfPairs(tenantID)
	if err != nil {
		return nil, err
	}
	msg, err := payloadbox.NewMessage(enrollBindingPurpose, tenantID, sproutID, "",
		enrollBindingBody{NKeyPub: nkeyPub, SproutPub: sproutPub})
	if err != nil {
		return nil, err
	}
	return payloadbox.Seal(msg, pairs)
}

// verifyEnrollBinding checks binding, an enrollment binding returned on
// step 2: that farmer sealed it (openEnrollBinding) for this tenant and
// sprout, it answers nothing (no ReplyTo), names exactly nkeyPub and
// sproutPub, and was issued no more than EnrollBindingTTL ago (and not
// more than replayCacheClockMargin ahead of this replica's clock). It
// returns the binding's message ID, which the caller claims. The error
// is for local logging only.
func verifyEnrollBinding(tenantID, sproutID, nkeyPub, sproutPub string, binding []byte) (string, error) {
	if len(binding) == 0 {
		return "", errors.New("no enroll_binding: a first box key is accepted only with the binding its identity was issued with")
	}
	msg, err := openEnrollBinding(tenantID, sproutID, binding)
	if err != nil {
		return "", fmt.Errorf("enroll_binding does not open: %w", err)
	}
	if msg.ReplyTo != "" {
		return "", errors.New("enroll_binding names a request it answers")
	}
	var body enrollBindingBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return "", errors.New("enroll_binding body does not decode")
	}
	if subtle.ConstantTimeCompare([]byte(body.NKeyPub), []byte(nkeyPub)) != 1 ||
		subtle.ConstantTimeCompare([]byte(body.SproutPub), []byte(sproutPub)) != 1 {
		return "", errors.New("enroll_binding names another nkey_pub or sprout_pub")
	}
	age := enrollNow().Sub(time.Unix(msg.IssuedAt, 0))
	if age > EnrollBindingTTL || age < -replayCacheClockMargin {
		return "", errors.New("enroll_binding has expired or is from the future")
	}
	return msg.ID, nil
}

// verifyEnrollProof checks proof, a sprout's sprout_pub_proof: that it
// opens under one of tenantID's box private keys paired with sproutPub
// (which only a holder of sproutPub's private half, or of the tenant
// key, could have sealed), is for this tenant and sprout
// (payloadbox.PurposeEnrollProof), is a request (no ReplyTo), names
// exactly nkeyPub and sproutPub, and was issued within EnrollSigMaxSkew
// of farmer's clock. It returns the proof's message ID, which the caller
// claims. The error is for local logging only.
func verifyEnrollProof(tenantID, sproutID, nkeyPub, sproutPub string, proof []byte) (string, error) {
	msg, err := openEnrollProof(tenantID, sproutID, sproutPub, proof)
	if err != nil {
		return "", err
	}
	if msg.ReplyTo != "" {
		return "", errors.New("proof names a request it answers")
	}
	var body enrollProofBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return "", errors.New("proof body does not decode")
	}
	if body.NKeyPub != nkeyPub || body.SproutPub != sproutPub {
		return "", errors.New("proof names another nkey_pub or sprout_pub")
	}
	skew := enrollNow().Sub(time.Unix(msg.IssuedAt, 0))
	if skew > EnrollSigMaxSkew || skew < -EnrollSigMaxSkew {
		return "", errors.New("proof is outside the allowed skew")
	}
	return msg.ID, nil
}

// upsertBoxKeyActive writes the sprout's first box key. A variable so a test
// can fail the write.
var upsertBoxKeyActive = upsertSproutBoxKeyActive

// recordProvenSproutBoxKey verifies proof (verifyEnrollProof), claims its
// message ID once cluster-wide (ClaimSealedMessage, failing closed
// without Valkey), and records sproutPub as sproutID's active box key,
// scoped to tenantID: the tenant SproutIDAndTenantForNKey found the NKey
// under, never a global one (pki_sprout_box_keys is (tenant_id,
// sprout_id)-keyed). The claim matters because this proof is what earns
// the response its gateway JWT: an NKey signature the bus can obtain,
// plus a proof copied from an earlier request, must not earn another. The
// sprout builds a fresh proof for every attempt.
//
// Only a sprout's first box key is recorded this way, and only with
// binding, the enrollment binding step 1 issued (verifyEnrollBinding),
// whose message ID is claimed too, so it records one key once. A proof
// for the key already active is a no-op that needs no binding (a retried
// second request: the proof is under the key on record, so only the
// sprout can make it); one for a different key, while one is active, is
// refused: replacing a key is a rotation, which must be sealed under the
// current one (boxkeys.go).
func recordProvenSproutBoxKey(ctx context.Context, tenantID, sproutID, nkeyPub, sproutPub string, proof, binding []byte) error {
	msgID, err := verifyEnrollProof(tenantID, sproutID, nkeyPub, sproutPub, proof)
	if err != nil {
		return err
	}
	active, _, err := ValidSproutBoxKeys(tenantID, sproutID)
	switch {
	case err == nil && active == sproutPub:
		return ClaimSealedMessage(ctx, tenantID, sproutID, msgID)
	case err == nil:
		return errors.New("the sprout already has a different active box key; a new one needs a rotation")
	case !errors.Is(err, ErrNoActiveBoxKey):
		return err
	}
	// A first box key: only with the binding of the exchange that issued
	// this identity, checked before either claim so that a request
	// without one spends nothing.
	bindingID, err := verifyEnrollBinding(tenantID, sproutID, nkeyPub, sproutPub, binding)
	if err != nil {
		return err
	}
	if err := ClaimSealedMessage(ctx, tenantID, sproutID, msgID); err != nil {
		return err
	}
	if err := ClaimSealedMessage(ctx, tenantID, sproutID, bindingID); err != nil {
		return fmt.Errorf("enroll_binding already used or unclaimable: %w", err)
	}
	if err := upsertBoxKeyActive(tenantID, sproutID, sproutPub); err != nil {
		// Nothing was recorded and no gateway JWT goes out, so the binding
		// has not been acted on: give it back, or the sprout's only way to
		// a box key (this binding, until it expires) is spent by a
		// transient database error and it has to be enrolled again with a
		// new token. The proof's claim stays: the sprout builds a fresh
		// proof for every attempt, so a retry does not need it, and a
		// captured proof stays unusable.
		if rerr := ReleaseSealedMessage(context.WithoutCancel(ctx), tenantID, sproutID, bindingID); rerr != nil {
			log.Warnf("enroll: could not release the enroll_binding of sprout %s in tenant %s after a failed box key write (a retry has to wait until it expires or the sprout be enrolled again): %v", sproutID, tenantID, rerr)
		}
		return err
	}
	log.Infof("enroll: sprout %s in tenant %s proved possession of its payload-encryption key; recorded it", sproutID, tenantID)
	return nil
}

// replayExistingEnrollment handles design doc §3.3 step 1: an already-
// accepted nkey_pub gets its existing identity back, no token touched.
// Enroll only calls it after verifyNKeyPossession has passed and the
// signed request has been claimed; the caller has proven it holds
// nkeyPub's seed, not just that it knows nkeyPub, and isn't resubmitting
// an earlier request. A gateway JWT is minted, fresh (see
// EnrollResult.GatewayJWT), only if proven: the request also carried a
// sprout_pub_proof that verified and was claimed. tenantID is the tenant
// SproutIDAndTenantForNKey found this sprout under, not necessarily
// whatever tenant a caller might have guessed from context.
func replayExistingEnrollment(ctx context.Context, tenantID, sproutID, nkeyPub string, proven bool) (*EnrollResult, error) {
	res, err := reissueExistingIdentity(ctx, tenantID, sproutID, nkeyPub, proven)
	if err != nil {
		return nil, err
	}
	log.Infof("enroll: sprout %s replayed an existing enrollment (idempotency check)", sproutID)
	return res, nil
}

// reissueExistingIdentity returns an accepted sprout's existing NATS User
// JWT and the tenant X25519 public key, and, if withGateway, a freshly
// minted gateway JWT. Shared by the enrollment replay path and
// RefreshSprout. Callers must have verified and claimed the request
// first, and pass withGateway only for a request that proved possession
// of the sprout's box key (a sprout_pub_proof or a sealed refresh): an
// NKey signature alone is not enough, since the bus can obtain one.
func reissueExistingIdentity(ctx context.Context, tenantID, sproutID, nkeyPub string, withGateway bool) (*EnrollResult, error) {
	existingJWT, err := GetSproutUserJWTForTenant(tenantID, sproutID)
	if err != nil {
		log.Errorf("enroll: sprout %s has an accepted nkey but no readable JWT: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	tenantPub, err := GetTenantX25519PublicKey(tenantID)
	if err != nil {
		log.Errorf("enroll: reissuing identity for %s but failed to load tenant %s X25519 key: %v", sproutID, tenantID, err)
		return nil, ErrEnrollmentFailed
	}
	continuity, err := sproutTenantKeyContinuity(tenantID, sproutID)
	if err != nil {
		log.Errorf("enroll: reissuing identity for %s but failed to build tenant key continuity proof: %v", sproutID, err)
		return nil, ErrEnrollmentFailed
	}
	var gatewayJWT string
	if withGateway {
		if gatewayJWT, err = mintGatewayJWTFor(ctx, tenantID, sproutID, nkeyPub); err != nil {
			log.Errorf("enroll: reissuing identity for %s but failed to mint gateway JWT: %v", sproutID, err)
			return nil, ErrEnrollmentFailed
		}
	}
	return &EnrollResult{SproutID: sproutID, JWT: existingJWT, GatewayJWT: gatewayJWT, TenantID: tenantID, TenantX25519Pub: tenantPub, TenantX25519Continuity: continuity}, nil
}

// sproutTenantKeyContinuity is TenantKeyContinuity sealed to the
// sprout's active box public key on record. A sprout with none (enrolled
// before workstream J) has no tenant key pinned either, so nil.
func sproutTenantKeyContinuity(tenantID, sproutID string) (json.RawMessage, error) {
	active, _, err := ValidSproutBoxKeys(tenantID, sproutID)
	if errors.Is(err, ErrNoActiveBoxKey) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return TenantKeyContinuity(tenantID, sproutID, active)
}

// mintGatewayJWTFor builds this sprout's gateway-JWT claims and mints it
// via the installed gatewayMinter (SetGatewaySigner). Both of Enroll's
// success paths call this, per the implementation brief's "Both tokens
// must be minted in the same call — don't split into two round-trips"
// and "don't special-case rotation to mint only one token."
func mintGatewayJWTFor(ctx context.Context, tenantID, sproutID, nkeyPub string) (string, error) {
	if gatewayMinter == nil {
		return "", errors.New("pki: no gateway JWT signer configured (SetGatewaySigner was never called)")
	}
	return gatewayMinter.MintGatewayJWT(ctx, gatewayjwt.GatewayClaims{
		Subject:  nkeyPub,
		TenantID: tenantID,
		SproutID: sproutID,
		Expiry:   time.Now().Add(config.GatewayJWTTTL),
	})
}

// splitJoinToken splits design doc §3.1's "{key_id}.{secret}" token on its
// first '.', rejecting anything that doesn't leave both halves non-empty.
func splitJoinToken(token string) (keyID, secret string, ok bool) {
	i := strings.IndexByte(token, '.')
	if i <= 0 || i == len(token)-1 {
		return "", "", false
	}
	return token[:i], token[i+1:], true
}

// hashSecret must stay byte-for-byte identical to internal/saasapi's own
// hashSecret (idgen.go): both sides hash the secret half of the same
// {key_id}.{secret} token the same way. farmer can't import
// internal/saasapi (separate schema/service boundary — design doc §5.1's
// "SaaS API" vs. "Farmer" split), so this is a deliberate, small
// duplication rather than a cross-service dependency.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// resolveEnrollSproutID picks the sprout ID an enrolling host gets,
// applying the same hostname normalization and same-nkey/collision
// handling as the legacy PutNKey path
// (internal/api/handlers/pki.go) so both mechanisms agree on how a
// hostname becomes a sprout ID. Collision-checked within tenantID only —
// two different tenants may legitimately each have a sprout resolving to
// the same base hostname (e.g. "web-01"), and must not collide with each
// other's sprout IDs.
//
// The hostname is normalised by NormalizeSproutID, which maps '.' to '-'
// (security review 2026-10, M4): "web01.example.com" enrols as
// "web01-example-com", never with a dot that would let "web01"'s grants
// cover its subjects. A reserved ID (reservedSproutIDs) is refused.
//
// An ID freed by DeleteNKey is handed out again: the new host enrols
// under it with its own NKey and box key, and the old host's NKey and box
// keys stay revoked.
func resolveEnrollSproutID(tenantID, hostname, nkeyPub string) (string, error) {
	base := NormalizeSproutID(hostname)
	if !IsValidSproutID(base) {
		return "", ErrSproutIDInvalid
	}
	if registered, matches := NKeyExistsInTenant(tenantID, base, nkeyPub); !registered || matches {
		return base, nil
	}
	for i := 1; i < 100; i++ {
		id := base + "_" + strconv.Itoa(i)
		if registered, matches := NKeyExistsInTenant(tenantID, id, nkeyPub); !registered || matches {
			return id, nil
		}
	}
	return "", errors.New("pki: too many sprouts sharing hostname " + base)
}

// acceptEnrolledNKey upserts sprout directly into the accepted state in
// one write, scoped to tenantID (the enrollment key's own tenant — see
// Enroll). Unlike the legacy Unaccept-then-admin-Accept flow, presenting a
// valid, unexhausted join token *is* the authorization decision here —
// there's no separate pending-review step to go through first. Reloads via
// ReloadNKeysForTenant (tenant.go), not the legacy current-tenant
// ReloadNKeys — this lazily provisions tenantID's own NATS Account (mint +
// push) the first time it's ever seen, which is what actually makes a
// freshly-enrolled sprout's User JWT valid against the bus.
func acceptEnrolledNKey(tenantID, id, nkey string) error {
	defer func() {
		if err := ReloadNKeysForTenant(tenantID); err != nil {
			log.Errorf("failed to reload NATS auth for enrolled sprout %s in tenant %s: %v", id, tenantID, err)
		}
	}()
	return upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: id, NKey: nkey, State: stateAccepted})
}
