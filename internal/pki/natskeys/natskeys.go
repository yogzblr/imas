// Package natskeys holds the NATS trust chain's private keys in OpenBao
// Transit and hands out nkeys.KeyPair values that sign through it, so no
// operator, SYS account or tenant signing seed exists outside OpenBao
// (P21 slice 1, docs/briefs/P21-slice1-transit-signer.md §1; design
// docs/design/imas-openbao-signing-design.md).
//
// A pair from KeyStore.KeyPair drops into every place a seed-derived
// pair went: jwt/v2's claims.Encode(kp) calls kp.PublicKey() for the
// issuer and kp.Sign("header.payload") for the signature, and Transit's
// ed25519 sign returns exactly that raw 64-byte Ed25519 signature.
//
// It is a package of its own, not part of internal/pki, so test helpers
// and the bootstrap subcommand can import it without an import cycle.
//
// FLAG FOR SECURITY REVIEW: these keys are the trust anchor of every
// NATS connection.
package natskeys

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/openbao"
)

// Prefix is the NKey prefix a key's public half is encoded with:
// nkeys.PrefixByteOperator or nkeys.PrefixByteAccount.
type Prefix = nkeys.PrefixByte

// Sentinel errors; every error this package returns about a key or a
// signature wraps one of them.
var (
	ErrKeyNotFound    = errors.New("natskeys: transit key not found")
	ErrKeyRetired     = errors.New("natskeys: transit key is soft-deleted")
	ErrKeyNotHardened = errors.New("natskeys: transit key is not hardened (exportable, plaintext backup, imported or derived)")
	ErrKeyType        = errors.New("natskeys: transit key is not a usable ed25519 key")
	ErrSignFailed     = errors.New("natskeys: transit sign failed")
	// ErrSignTimeout is any Transit request (sign, or a key read, create
	// or soft delete) that timed out on every attempt, or a caller's
	// deadline; it wraps context.DeadlineExceeded.
	ErrSignTimeout   = errors.New("natskeys: transit request timed out")
	ErrBadSignature  = errors.New("natskeys: transit returned a bad signature")
	ErrNotConfigured = errors.New("natskeys: openbao transit not configured")
	ErrClosed        = errors.New("natskeys: key store closed")

	errK8sJWTUnavailable = errors.New("natskeys: openbao kubernetes auth: could not read service account token")
	errK8sAuthFailed     = errors.New("natskeys: openbao kubernetes auth login failed")
)

// KeyStore hands out signing pairs for Transit keys.
type KeyStore interface {
	// KeyPair returns a signing pair for an existing Transit key. It reads the key,
	// validates hardening, pins key_version to latest_version, caches the public key.
	KeyPair(ctx context.Context, name string, prefix Prefix) (nkeys.KeyPair, error)
	// EnsureKeyPair reads; on 404 creates with hardened parameters; then KeyPair.
	EnsureKeyPair(ctx context.Context, name string, prefix Prefix) (nkeys.KeyPair, error)
	// RetireKey soft-deletes (DELETE keys/<name>/soft-delete). 404 and already
	// soft-deleted are success.
	RetireKey(ctx context.Context, name string) error
	Close() error // stops workers; pending signs get ErrClosed
}

// Config configures a TransitKeyStore. ConfigFromEnv builds one; zero
// numeric fields and an empty mount take the Default* values.
type Config struct {
	// OpenBao names the identity's environment variables, read by
	// internal/openbao when the store is built.
	OpenBao      openbao.Env
	TransitMount string
	// Timeout bounds each request to OpenBao.
	Timeout time.Duration
	// BatchMax is the most queued signs one request carries.
	BatchMax int
	// Workers is how many sign requests run at once.
	Workers int
}

func (c Config) withDefaults() Config {
	c.TransitMount = strings.Trim(c.TransitMount, "/")
	if c.TransitMount == "" {
		c.TransitMount = DefaultTransitMount
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.BatchMax <= 0 {
		c.BatchMax = DefaultBatchMax
	}
	if c.Workers <= 0 {
		c.Workers = DefaultWorkers
	}
	return c
}

// Retry policy for requests to OpenBao (brief §1.4): up to maxAttempts
// on a network error, 429 or 5xx, sleeping a jittered backoff[i] before
// attempt i+2.
const maxAttempts = 3

var defaultBackoff = []time.Duration{100 * time.Millisecond, 300 * time.Millisecond}

// keyNameMatcher keeps a key name to one path segment of Transit's API,
// so a name can never reach keys/<other>/config, export/... or another
// mount.
var keyNameMatcher = regexp.MustCompile(`^[0-9A-Za-z_-]{1,255}$`)

// TransitKeyStore is the KeyStore over OpenBao Transit. Safe for
// concurrent use.
type TransitKeyStore struct {
	ob      *openbao.Client
	mount   string
	timeout time.Duration
	kube    bool // kubernetes auth: re-login once on 403
	backoff []time.Duration
	d       *dispatcher
}

var _ KeyStore = (*TransitKeyStore)(nil)

// NewTransitKeyStore builds a store and starts its sign workers. Nothing
// is sent to OpenBao until the first KeyPair. Close stops the workers.
func NewTransitKeyStore(cfg Config) (*TransitKeyStore, error) {
	cfg = cfg.withDefaults()
	ob, err := openbao.NewFromEnv(cfg.OpenBao, openbao.Errors{
		NotConfigured:     ErrNotConfigured,
		K8sJWTUnavailable: errK8sJWTUnavailable,
		K8sAuthFailed:     errK8sAuthFailed,
	})
	if err != nil {
		return nil, err
	}
	s := &TransitKeyStore{
		ob:      ob,
		mount:   cfg.TransitMount,
		timeout: cfg.Timeout,
		kube:    os.Getenv(cfg.OpenBao.AuthMethod) == openbao.AuthMethodKubernetes,
		backoff: defaultBackoff,
	}
	s.d = newDispatcher(cfg.Workers, cfg.BatchMax, s.signGroup)
	return s, nil
}

// Close stops the sign workers. Signs still queued or in flight return
// ErrClosed. Safe to call more than once.
func (s *TransitKeyStore) Close() error {
	s.d.close()
	s.ob.Close()
	return nil
}

// KeyPair implements KeyStore.
func (s *TransitKeyStore) KeyPair(ctx context.Context, name string, prefix Prefix) (nkeys.KeyPair, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	if !keyNameMatcher.MatchString(name) {
		return nil, fmt.Errorf("natskeys: invalid key name %q", name)
	}
	info, err := s.readKey(ctx, name)
	if err != nil {
		return nil, err
	}
	return newKeyPair(s, name, prefix, info)
}

// EnsureKeyPair implements KeyStore. It never trusts the create call's
// outcome: whether Transit answers a create of an existing key with an
// error is unverified, and two farmers may race, so after any create
// (failed or not) it reads the key again and that read decides.
func (s *TransitKeyStore) EnsureKeyPair(ctx context.Context, name string, prefix Prefix) (nkeys.KeyPair, error) {
	kp, err := s.KeyPair(ctx, name, prefix)
	if !errors.Is(err, ErrKeyNotFound) {
		return kp, err
	}
	// Never deletion_allowed: soft delete doesn't need it, and a hard
	// delete is an operator's action.
	_, createErr := s.call(ctx, func(ctx context.Context) error {
		_, err := s.ob.Post(ctx, s.mount+"/keys/"+name, map[string]any{
			"type":                   "ed25519",
			"exportable":             false,
			"allow_plaintext_backup": false,
		})
		return err
	})
	kp, err = s.KeyPair(ctx, name, prefix)
	if err != nil && createErr != nil {
		return nil, fmt.Errorf("natskeys: creating key %s: %w (then reading it: %w)", name, createErr, err)
	}
	return kp, err
}

// RetireKey implements KeyStore. Whether a second soft delete of the
// same key is an error is unverified, so a failed delete is followed by
// a read: a key that reads as soft-deleted (or is gone) is success.
func (s *TransitKeyStore) RetireKey(ctx context.Context, name string) error {
	if !keyNameMatcher.MatchString(name) {
		return fmt.Errorf("natskeys: invalid key name %q", name)
	}
	_, err := s.call(ctx, func(ctx context.Context) error {
		_, err := s.ob.Delete(ctx, s.mount+"/keys/"+name+"/soft-delete")
		return err
	})
	if err == nil || openbao.IsNotFound(err) {
		return nil
	}
	info, readErr := s.readKey(ctx, name)
	switch {
	case errors.Is(readErr, ErrKeyNotFound):
		return nil
	case readErr == nil && info.SoftDeleted != nil && *info.SoftDeleted:
		return nil
	}
	return fmt.Errorf("natskeys: soft-deleting key %s: %w", name, err)
}

func checkPrefix(p Prefix) error {
	if p != nkeys.PrefixByteOperator && p != nkeys.PrefixByteAccount {
		return fmt.Errorf("natskeys: unsupported NKey prefix %v (want operator or account)", p)
	}
	return nil
}

// keyInfo is the part of GET <mount>/keys/<name> this package checks.
// The hardening flags are pointers so an answer that leaves one out
// fails the check instead of reading as false.
type keyInfo struct {
	Type                 string `json:"type"`
	Exportable           *bool  `json:"exportable"`
	AllowPlaintextBackup *bool  `json:"allow_plaintext_backup"`
	ImportedKey          *bool  `json:"imported_key"`
	Derived              *bool  `json:"derived"`
	SoftDeleted          *bool  `json:"soft_deleted"`
	LatestVersion        int    `json:"latest_version"`
	Keys                 map[string]struct {
		PublicKey string `json:"public_key"`
	} `json:"keys"`
}

func (s *TransitKeyStore) readKey(ctx context.Context, name string) (*keyInfo, error) {
	var info keyInfo
	_, err := s.call(ctx, func(ctx context.Context) error {
		secret, err := s.ob.Read(ctx, s.mount+"/keys/"+name, nil)
		if err != nil {
			return err
		}
		if secret == nil || secret.Data == nil {
			return fmt.Errorf("%w: %s: empty response", ErrKeyType, name)
		}
		return openbao.DecodeData(secret, &info)
	})
	if openbao.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s: %w", ErrKeyNotFound, name, err)
	}
	if err != nil {
		return nil, fmt.Errorf("natskeys: reading key %s: %w", name, err)
	}
	return &info, nil
}

// publicKey checks info's hardening and returns the pinned version and
// its raw 32-byte public key.
func (info *keyInfo) publicKey(name string) (int, ed25519.PublicKey, error) {
	if info.SoftDeleted != nil && *info.SoftDeleted {
		return 0, nil, fmt.Errorf("%w: %s", ErrKeyRetired, name)
	}
	if info.Type != "ed25519" {
		return 0, nil, fmt.Errorf("%w: %s has type %q", ErrKeyType, name, info.Type)
	}
	for flag, v := range map[string]*bool{
		"exportable":             info.Exportable,
		"allow_plaintext_backup": info.AllowPlaintextBackup,
		"imported_key":           info.ImportedKey,
		"derived":                info.Derived,
		"soft_deleted":           info.SoftDeleted, // true is handled above
	} {
		if v == nil || *v {
			return 0, nil, fmt.Errorf("%w: %s: %s is not false", ErrKeyNotHardened, name, flag)
		}
	}
	v, ok := info.Keys[strconv.Itoa(info.LatestVersion)]
	if info.LatestVersion < 1 || !ok {
		return 0, nil, fmt.Errorf("%w: %s: no public key for latest_version %d", ErrKeyType, name, info.LatestVersion)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(v.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return 0, nil, fmt.Errorf("%w: %s: public key is not 32 bytes of standard base64", ErrKeyType, name)
	}
	return info.LatestVersion, ed25519.PublicKey(raw), nil
}

// call runs one request with the retry policy: up to maxAttempts on a
// network error (a per-attempt timeout included), 429 or 5xx; never on 400 or 404; on 403 with
// kubernetes auth, one fresh login and one more try. Each attempt is
// bounded by the store's timeout. The int is the number of attempts.
func (s *TransitKeyStore) call(ctx context.Context, req func(context.Context) error) (int, error) {
	relogged := false
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, s.timeout)
		err := req(actx)
		timedOut := errors.Is(actx.Err(), context.DeadlineExceeded)
		cancel()
		if err == nil {
			return attempt, nil
		}
		if ctx.Err() != nil {
			return attempt, ctxError(ctx.Err())
		}
		// A request that ran out of its per-attempt time is a network
		// error: retried, and ErrSignTimeout only after the last attempt.
		if timedOut && attempt >= maxAttempts {
			return attempt, fmt.Errorf("%w: %w", ErrSignTimeout, context.DeadlineExceeded)
		}
		code := openbao.StatusCode(err)
		if code == http.StatusForbidden && s.kube && !relogged {
			relogged = true
			s.ob.ResetToken()
			attempt-- // the re-login try is extra, not one of the three
			continue
		}
		if (!timedOut && !retryable(code, err)) || attempt >= maxAttempts {
			return attempt, err
		}
		d := s.backoff[min(attempt-1, len(s.backoff)-1)]
		// Jitter within [d/2, 3d/2).
		d = d/2 + rand.N(d+1)
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return attempt, ctxError(ctx.Err())
		case <-t.C:
		}
	}
}

func retryable(code int, err error) bool {
	if code == http.StatusTooManyRequests || code >= 500 {
		return true
	}
	var ne net.Error
	return code == 0 && errors.As(err, &ne)
}

// ctxError maps a caller's context error: a deadline is ErrSignTimeout
// (wrapping context.DeadlineExceeded), a cancel stays context.Canceled.
func ctxError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrSignTimeout, err)
	}
	return err
}
