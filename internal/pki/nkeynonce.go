package pki

// Proof of possession for the legacy NKey registration, PUT /pki/putnkey
// (security review 2026-10, L12). FLAG FOR SECURITY REVIEW.
//
// The route exists only where enrolment is off (config "enrollment:
// false", a standalone install; the Helm chart always has it on, and then
// the route is not registered at all). There, a sprout first asks
// GET /pki/nkeynonce for a server nonce and then submits its public NKey
// with a signature, made with that NKey's seed, over NKeySubmissionPayload:
// the nonce, its sprout ID and the NKey. Without the signature anyone who
// knew a public NKey could file it under any ID.
//
// A nonce holds no state until it is spent: it is a timestamp and random
// bytes, authenticated with an HMAC under a key this process draws at
// start, so a flood of nonce requests fills nothing and cannot lock
// legitimate registrations out. It is spendable for nkeyNonceTTL, by
// this farmer process only (a standalone install runs one, which serves
// both requests). A nonce is recorded as spent only once a submission
// over it verifies, and kept until it would have expired, so a captured
// submission cannot be replayed.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nkeys"
)

const (
	// nkeySubmissionDomain separates this signature from every other one
	// the NKey seed makes (enrolment requests, bus CONNECT nonces).
	nkeySubmissionDomain = "imas-putnkey-v1"
	// nkeyNonceTTL is how long a nonce may be spent.
	nkeyNonceTTL = 2 * time.Minute
	// nkeyNonceRandBytes and nkeyNonceMACBytes size a nonce: 8 bytes of
	// Unix nanoseconds, the random bytes, then the truncated HMAC.
	nkeyNonceRandBytes = 16
	nkeyNonceMACBytes  = 16
	nkeyNonceLen       = 8 + nkeyNonceRandBytes + nkeyNonceMACBytes
)

// ErrNKeySubmissionUnproven: the nonce is not one this process issued, is
// expired or spent, or the signature does not verify against the
// submitted NKey.
var ErrNKeySubmissionUnproven = errors.New("pki: the NKey submission does not prove possession of the NKey")

// nkeyNonceStore issues nonces and remembers the spent ones.
type nkeyNonceStore struct {
	key   []byte
	now   func() time.Time
	mu    sync.Mutex
	spent map[string]time.Time // nonce -> when it expires
}

func newNKeyNonceStore(now func() time.Time) *nkeyNonceStore {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("pki: no randomness for the NKey nonce key: " + err.Error())
	}
	return &nkeyNonceStore{key: key, now: now, spent: map[string]time.Time{}}
}

var nkeyNonces = newNKeyNonceStore(time.Now)

func (s *nkeyNonceStore) mac(body []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(body)
	return m.Sum(nil)[:nkeyNonceMACBytes]
}

// issue returns a fresh nonce, unpadded base64url. It stores nothing.
func (s *nkeyNonceStore) issue() (string, error) {
	b := make([]byte, 8+nkeyNonceRandBytes, nkeyNonceLen)
	binary.BigEndian.PutUint64(b, uint64(s.now().UnixNano()))
	if _, err := rand.Read(b[8:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(append(b, s.mac(b)...)), nil
}

// valid reports whether nonce is one this store issued and has not yet
// expired, without spending it.
func (s *nkeyNonceStore) valid(nonce string) (time.Time, bool) {
	b, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(b) != nkeyNonceLen {
		return time.Time{}, false
	}
	body := b[:8+nkeyNonceRandBytes]
	if !hmac.Equal(b[8+nkeyNonceRandBytes:], s.mac(body)) {
		return time.Time{}, false
	}
	exp := time.Unix(0, int64(binary.BigEndian.Uint64(body))).Add(nkeyNonceTTL)
	now := s.now()
	if !now.Before(exp) || exp.Sub(now) > nkeyNonceTTL {
		return time.Time{}, false
	}
	return exp, true
}

// spend records nonce as spent until exp and reports whether it was not
// spent already. Expired entries are dropped on the way.
func (s *nkeyNonceStore) spend(nonce string, exp time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for n, at := range s.spent {
		if !now.Before(at) {
			delete(s.spent, n)
		}
	}
	if _, ok := s.spent[nonce]; ok {
		return false
	}
	s.spent[nonce] = exp
	return true
}

// IssueNKeyNonce returns a single-use nonce for one NKey submission.
func IssueNKeyNonce() (string, error) { return nkeyNonces.issue() }

// NKeySubmissionPayload is what a sprout signs, with the NKey's seed, to
// submit that NKey under sproutID.
func NKeySubmissionPayload(nonce, sproutID, nkey string) []byte {
	return []byte(strings.Join([]string{nkeySubmissionDomain, nonce, sproutID, nkey}, "\n"))
}

// VerifyNKeySubmission checks that sub.Nonce is one this process issued
// and has not expired, checks sub.Sig (unpadded base64url) against
// sub.NKey over NKeySubmissionPayload, and only then spends the nonce. Any
// failure, a nonce already spent included, is
// ErrNKeySubmissionUnproven. sub.NKey and sub.SproutID must already be
// valid (the handler checks them first).
func VerifyNKeySubmission(sub KeySubmission) error {
	exp, ok := nkeyNonces.valid(sub.Nonce)
	if !ok {
		return ErrNKeySubmissionUnproven
	}
	sig, err := base64.RawURLEncoding.DecodeString(sub.Sig)
	if err != nil || len(sig) == 0 {
		return ErrNKeySubmissionUnproven
	}
	kp, err := nkeys.FromPublicKey(sub.NKey)
	if err != nil {
		return ErrNKeySubmissionUnproven
	}
	if kp.Verify(NKeySubmissionPayload(sub.Nonce, sub.SproutID, sub.NKey), sig) != nil {
		return ErrNKeySubmissionUnproven
	}
	if !nkeyNonces.spend(sub.Nonce, exp) {
		return ErrNKeySubmissionUnproven
	}
	return nil
}
