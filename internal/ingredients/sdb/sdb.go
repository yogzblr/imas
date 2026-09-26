// Package sdb implements imas's SDB-equivalent secret resolution: a
// sprout-side SecretProvider interface behind the sdb:// URI scheme, with
// self-registering backend implementations selected by the ref's backend
// name (the URI's host segment), following the same self-registering
// plugin pattern used by the other imas ingredients (see
// internal/ingredients/file for the closest analog).
//
// A ref looks like sdb://<backend>/<backend-specific-path>, e.g.
// sdb://openbao/secret/myapp/db#password. Recipes carry these refs
// opaquely; the sprout resolves them at execution time via Get. See
// docs/design/imas-sdb-secrets-design.md for the full design.
package sdb

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/yogzblr/imas/internal/log"
)

// SecretProvider resolves a single sdb:// ref to its secret value.
// Implementations receive the full, unparsed ref (not just the portion
// after the backend name) so they can be exercised directly in tests
// without going through the package registry.
type SecretProvider interface {
	Get(ctx context.Context, ref string) (string, error)
}

var (
	provTex sync.Mutex
	provMap = make(map[string]SecretProvider)
)

var (
	ErrUnknownBackend    = errors.New("unknown sdb backend")
	ErrDuplicateBackend  = errors.New("duplicate sdb backend")
	ErrInvalidRef        = errors.New("invalid sdb ref")
	ErrEmptyBackendName  = errors.New("cannot register empty sdb backend name")
	ErrAmbiguousSecret   = errors.New("secret has multiple fields; a #field selector is required")
	ErrSecretFieldNotSet = errors.New("secret field not found")
)

// RegisterProvider registers a SecretProvider under the given backend name
// (the host segment of an sdb:// ref, e.g. "openbao", "azurekv"). It does
// not override an already-registered backend.
func RegisterProvider(backend string, provider SecretProvider) error {
	provTex.Lock()
	defer provTex.Unlock()
	if backend == "" {
		return ErrEmptyBackendName
	}
	if _, ok := provMap[backend]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateBackend, backend)
	}
	provMap[backend] = provider
	log.Tracef("registered sdb backend %s", backend)
	return nil
}

// ParseRef splits an sdb:// ref into its backend name and the
// backend-specific remainder (path plus optional query/fragment), as the
// URI would render them back. It does not require the backend to be
// registered.
func ParseRef(ref string) (backend string, u *url.URL, err error) {
	u, err = url.Parse(ref)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidRef, err)
	}
	if u.Scheme != "sdb" {
		return "", nil, fmt.Errorf("%w: scheme must be sdb, got %q", ErrInvalidRef, u.Scheme)
	}
	if u.Host == "" {
		return "", nil, fmt.Errorf("%w: missing backend name (sdb://<backend>/...)", ErrInvalidRef)
	}
	return u.Host, u, nil
}

// Get resolves ref by dispatching to the registered SecretProvider for its
// backend.
func Get(ctx context.Context, ref string) (string, error) {
	backend, _, err := ParseRef(ref)
	if err != nil {
		return "", err
	}
	provTex.Lock()
	provider, ok := provMap[backend]
	provTex.Unlock()
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownBackend, backend)
	}
	return provider.Get(ctx, ref)
}

// SelectField picks a single value out of a secret's key/value fields
// given an optional explicit field name (typically the ref's URI
// fragment). An empty field is only valid when the secret has exactly one
// field, in which case that field's value is returned.
func SelectField(fields map[string]string, field string) (string, error) {
	if field != "" {
		v, ok := fields[field]
		if !ok {
			return "", fmt.Errorf("%w: %s", ErrSecretFieldNotSet, field)
		}
		return v, nil
	}
	if len(fields) == 1 {
		for _, v := range fields {
			return v, nil
		}
	}
	return "", ErrAmbiguousSecret
}
