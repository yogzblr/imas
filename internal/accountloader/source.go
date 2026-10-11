package accountloader

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/objectstore"
)

// Bucket layout (brief §4.1): one object per Account JWT, plus an index
// object whose random token farmer replaces on every change.
const (
	AccountsPrefix = "accounts/"
	IndexKey       = AccountsPrefix + "index"
	jwtSuffix      = ".jwt"

	// MaxJWTSize caps one Account JWT object (brief §4.2).
	MaxJWTSize = 1 << 20
	// maxIndexSize caps the index object; it holds three short fields.
	maxIndexSize = 4 << 10
	// listPageSize is the page size of a listing (brief §5.3 step 2).
	listPageSize = 1000
)

// ObjInfo is what the loader knows about one bucket object. ETag is
// opaque and only compared for equality with the last value seen.
type ObjInfo struct {
	Key  string
	ETag string
}

// ErrNotExist is returned (wrapped) by ObjectSource.Get for a missing
// object.
var ErrNotExist = errors.New("accountloader: object does not exist")

// ErrTooLarge is returned (wrapped) by ObjectSource.Get, with the
// object's info, for an object over MaxJWTSize.
var ErrTooLarge = errors.New("accountloader: object is over the size limit")

// ObjectSource is the loader's read-only view of the accounts bucket.
type ObjectSource interface {
	// Index returns the token of accounts/index; empty when there is no
	// index object yet.
	Index(ctx context.Context) (token string, err error)
	// List returns every object under accounts/, index included.
	List(ctx context.Context) ([]ObjInfo, error)
	// Get returns one object, at most MaxJWTSize bytes, with the info of
	// exactly the bytes returned. A missing key wraps ErrNotExist; a
	// larger object wraps ErrTooLarge and still returns its info.
	Get(ctx context.Context, key string) ([]byte, ObjInfo, error)
}

// ReadOnlyChecker is implemented by a source that can prove its
// credential cannot write (brief §10). Run calls it before the first load.
type ReadOnlyChecker interface {
	CheckReadOnly(ctx context.Context, rp objectstore.RetryPolicy) error
}

// AccountKey is the object key of an account's JWT.
func AccountKey(pub string) string { return AccountsPrefix + pub + jwtSuffix }

// accountFromKey returns the account public key an object key names, or
// ok=false for a key that is not accounts/<valid account pub>.jwt.
func accountFromKey(key string) (pub string, isJWT, ok bool) {
	rest, found := strings.CutPrefix(key, AccountsPrefix)
	if !found {
		return "", false, false
	}
	pub, isJWT = strings.CutSuffix(rest, jwtSuffix)
	if !isJWT {
		return "", false, false
	}
	return pub, true, nkeys.IsValidPublicAccountKey(pub)
}

// index is the JSON body of accounts/index.
type index struct {
	V     int    `json:"v"`
	Token string `json:"token"`
}

func parseIndex(b []byte) (string, error) {
	var ix index
	if err := json.Unmarshal(b, &ix); err != nil {
		return "", fmt.Errorf("accountloader: decoding %s: %w", IndexKey, err)
	}
	if ix.V != 1 || ix.Token == "" {
		return "", fmt.Errorf("accountloader: %s has version %d and token %q, want version 1 and a token", IndexKey, ix.V, ix.Token)
	}
	return ix.Token, nil
}

// StoreSource is the ObjectSource over internal/objectstore. It re-opens
// the store (re-reading the credential through open) after any failed
// request, so a rotated Secret is picked up without a restart.
type StoreSource struct {
	open func() (*objectstore.Store, error)

	mu    sync.Mutex
	store *objectstore.Store
}

// NewStoreSource returns a source that calls open for its store, again
// after every failed request.
func NewStoreSource(open func() (*objectstore.Store, error)) *StoreSource {
	return &StoreSource{open: open}
}

func (s *StoreSource) get() (*objectstore.Store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		st, err := s.open()
		if err != nil {
			return nil, err
		}
		s.store = st
	}
	return s.store, nil
}

// failed drops the store so the next request opens a fresh one, unless
// err only says an object is missing.
func (s *StoreSource) failed(err error) {
	if err == nil || objectstore.IsNotExist(err) || errors.Is(err, objectstore.ErrObjectTooLarge) {
		return
	}
	s.mu.Lock()
	s.store = nil
	s.mu.Unlock()
}

// Index implements ObjectSource.
func (s *StoreSource) Index(ctx context.Context) (string, error) {
	st, err := s.get()
	if err != nil {
		return "", err
	}
	b, err := st.GetLimited(ctx, IndexKey, maxIndexSize)
	s.failed(err)
	if objectstore.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return parseIndex(b)
}

// List implements ObjectSource.
func (s *StoreSource) List(ctx context.Context) ([]ObjInfo, error) {
	st, err := s.get()
	if err != nil {
		return nil, err
	}
	var out []ObjInfo
	after := ""
	for {
		page, more, err := st.ListPage(ctx, AccountsPrefix, after, listPageSize)
		if err != nil {
			s.failed(err)
			return nil, err
		}
		for _, o := range page {
			out = append(out, ObjInfo{Key: o.Key, ETag: o.ETag})
		}
		if !more || len(page) == 0 {
			return out, nil
		}
		after = page[len(page)-1].Key
	}
}

// Get implements ObjectSource.
func (s *StoreSource) Get(ctx context.Context, key string) ([]byte, ObjInfo, error) {
	st, err := s.get()
	if err != nil {
		return nil, ObjInfo{}, err
	}
	b, info, err := st.GetLimitedWithInfo(ctx, key, MaxJWTSize)
	s.failed(err)
	if objectstore.IsNotExist(err) {
		return nil, ObjInfo{}, fmt.Errorf("%w: %s", ErrNotExist, key)
	}
	if errors.Is(err, objectstore.ErrObjectTooLarge) {
		return nil, ObjInfo{Key: key, ETag: info.ETag}, fmt.Errorf("%w: %s is over %d bytes", ErrTooLarge, key, MaxJWTSize)
	}
	if err != nil {
		return nil, ObjInfo{}, err
	}
	return b, ObjInfo{Key: key, ETag: info.ETag}, nil
}

// CheckReadOnly implements ReadOnlyChecker: a put and a delete probe on
// a fresh key under accounts/ must both be denied. It returns an error
// wrapping objectstore.ErrAccessAllowed when the credential may write,
// and one wrapping objectstore.ErrProbeInconclusive when the store gave
// no answer it could classify. FLAG FOR SECURITY REVIEW.
func (s *StoreSource) CheckReadOnly(ctx context.Context, rp objectstore.RetryPolicy) error {
	st, err := s.get()
	if err != nil {
		return err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	key := AccountsPrefix + ".loader-write-probe-" + hex.EncodeToString(b[:])
	err = st.ExpectDenied(ctx, []objectstore.Probe{
		{Op: objectstore.ProbePut, Key: key},
		{Op: objectstore.ProbeDelete, Key: key},
	}, rp)
	if err != nil && !errors.Is(err, objectstore.ErrAccessAllowed) {
		s.failed(err)
	}
	return err
}
