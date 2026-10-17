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
// Nonces are random, single-use, held in this process's memory for
// nkeyNonceTTL and capped at maxNKeyNonces outstanding: a standalone
// install runs one farmer process, which serves both requests.

import (
	"crypto/rand"
	"encoding/base64"
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
	// maxNKeyNonces caps the outstanding nonces; beyond it a request
	// for one fails (ErrNKeyNoncesExhausted) until some expire.
	maxNKeyNonces = 10000
	// nkeyNonceBytes is the nonce's entropy.
	nkeyNonceBytes = 32
)

var (
	// ErrNKeyNoncesExhausted: too many nonces outstanding. Retryable.
	ErrNKeyNoncesExhausted = errors.New("pki: too many outstanding NKey registration nonces; retry later")
	// ErrNKeySubmissionUnproven: the nonce is unknown, spent or expired,
	// or the signature does not verify against the submitted NKey.
	ErrNKeySubmissionUnproven = errors.New("pki: the NKey submission does not prove possession of the NKey")
)

// nkeyNonceStore is the outstanding nonce set.
type nkeyNonceStore struct {
	mu  sync.Mutex
	now func() time.Time
	exp map[string]time.Time
}

var nkeyNonces = &nkeyNonceStore{now: time.Now, exp: map[string]time.Time{}}

// issue returns a fresh nonce, unpadded base64url.
func (s *nkeyNonceStore) issue() (string, error) {
	var b [nkeyNonceBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.exp) >= maxNKeyNonces {
		for n, at := range s.exp {
			if !now.Before(at) {
				delete(s.exp, n)
			}
		}
		if len(s.exp) >= maxNKeyNonces {
			return "", ErrNKeyNoncesExhausted
		}
	}
	s.exp[nonce] = now.Add(nkeyNonceTTL)
	return nonce, nil
}

// spend removes nonce and reports whether it was outstanding and not
// expired. A nonce is spent by any attempt, valid signature or not.
func (s *nkeyNonceStore) spend(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.exp[nonce]
	delete(s.exp, nonce)
	return ok && s.now().Before(at)
}

// IssueNKeyNonce returns a single-use nonce for one NKey submission.
func IssueNKeyNonce() (string, error) { return nkeyNonces.issue() }

// NKeySubmissionPayload is what a sprout signs, with the NKey's seed, to
// submit that NKey under sproutID.
func NKeySubmissionPayload(nonce, sproutID, nkey string) []byte {
	return []byte(strings.Join([]string{nkeySubmissionDomain, nonce, sproutID, nkey}, "\n"))
}

// VerifyNKeySubmission spends sub.Nonce and checks sub.Sig (unpadded
// base64url) against sub.NKey over NKeySubmissionPayload. Any failure is
// ErrNKeySubmissionUnproven. sub.NKey and sub.SproutID must already be
// valid (the handler checks them first).
func VerifyNKeySubmission(sub KeySubmission) error {
	if sub.Nonce == "" || !nkeyNonces.spend(sub.Nonce) {
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
	return nil
}
