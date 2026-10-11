package natskeys

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/nats-io/nkeys"
)

// transitKeyPair is an nkeys.KeyPair whose private half stays in
// Transit. It signs with the key version that was latest when it was
// loaded: a rotation must not silently change the identity behind trust
// already built on this key.
type transitKeyPair struct {
	store   *TransitKeyStore
	name    string
	version int
	pub     ed25519.PublicKey
	pubStr  string // NKey encoding of pub
}

var _ nkeys.KeyPair = (*transitKeyPair)(nil)

func newKeyPair(s *TransitKeyStore, name string, prefix Prefix, info *keyInfo) (*transitKeyPair, error) {
	version, pub, err := info.publicKey(name)
	if err != nil {
		return nil, err
	}
	enc, err := nkeys.Encode(prefix, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrKeyType, name, err)
	}
	pubStr := string(enc)
	valid := nkeys.IsValidPublicOperatorKey
	if prefix == nkeys.PrefixByteAccount {
		valid = nkeys.IsValidPublicAccountKey
	}
	if !valid(pubStr) {
		return nil, fmt.Errorf("%w: %s: %s is not a valid public NKey", ErrKeyType, name, pubStr)
	}
	return &transitKeyPair{store: s, name: name, version: version, pub: pub, pubStr: pubStr}, nil
}

// PublicKey returns the NKey public string, cached at load.
func (kp *transitKeyPair) PublicKey() (string, error) { return kp.pubStr, nil }

// Sign signs input through Transit and returns the raw 64-byte Ed25519
// signature, verified locally first. This is what jwt/v2's Encode calls.
// Each request is bounded by the store's timeout.
func (kp *transitKeyPair) Sign(input []byte) ([]byte, error) {
	return kp.SignContext(context.Background(), input)
}

// SignContext is Sign for callers with a deadline or cancellation.
func (kp *transitKeyPair) SignContext(ctx context.Context, input []byte) ([]byte, error) {
	return kp.store.d.submit(ctx, &signJob{
		ctx:   ctx,
		key:   groupKey{name: kp.name, version: kp.version, pub: kp.pubStr},
		pub:   kp.pub,
		input: input,
		done:  make(chan signResult, 1),
	})
}

// Verify checks sig over input against the cached public key, locally.
func (kp *transitKeyPair) Verify(input, sig []byte) error {
	if !ed25519.Verify(kp.pub, input, sig) {
		return nkeys.ErrInvalidSignature
	}
	return nil
}

// Seed returns nkeys.ErrPublicKeyOnly: the seed never leaves Transit.
func (kp *transitKeyPair) Seed() ([]byte, error) { return nil, nkeys.ErrPublicKeyOnly }

// PrivateKey returns nkeys.ErrPublicKeyOnly.
func (kp *transitKeyPair) PrivateKey() ([]byte, error) { return nil, nkeys.ErrPublicKeyOnly }

// Wipe does nothing: there is no private material here to wipe.
func (kp *transitKeyPair) Wipe() {}

// Seal returns nkeys.ErrInvalidNKeyOperation (curve keys only).
func (kp *transitKeyPair) Seal([]byte, string) ([]byte, error) {
	return nil, nkeys.ErrInvalidNKeyOperation
}

// SealWithRand returns nkeys.ErrInvalidNKeyOperation (curve keys only).
func (kp *transitKeyPair) SealWithRand([]byte, string, io.Reader) ([]byte, error) {
	return nil, nkeys.ErrInvalidNKeyOperation
}

// Open returns nkeys.ErrInvalidNKeyOperation (curve keys only).
func (kp *transitKeyPair) Open([]byte, string) ([]byte, error) {
	return nil, nkeys.ErrInvalidNKeyOperation
}

// ContextSigner is implemented by every pair a KeyStore returns, for
// callers that need SignContext through the nkeys.KeyPair interface.
type ContextSigner interface {
	SignContext(ctx context.Context, input []byte) ([]byte, error)
}

var _ ContextSigner = (*transitKeyPair)(nil)
