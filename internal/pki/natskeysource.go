package pki

// Key pair provider seam (P21 slice 1 PR4a,
// docs/briefs/P21-slice1-transit-signer.md §7 item 4). Every key pair of
// the NATS trust chain that the farmer signs with (operator, operator
// signing, SYS account, legacy tenant account and signing, per-tenant
// account and signing) is obtained through natsKeys, so PR4b can swap
// the seed files for OpenBao Transit pairs (internal/pki/natskeys) by
// changing where the pairs come from, not how they are used.
//
// The only implementation here is seedNATSKeys, which is exactly the
// behaviour before the seam: loadOrCreateSeed with the same file paths
// and IMAS_NATS_<NAME>_SEED[_FILE] names. User-kind seeds (SYS_USER,
// SAASAPI_USER) are not trust chain keys and do not go through it.
//
// FLAG FOR SECURITY REVIEW: these pairs sign every NATS account and user
// JWT the farmer issues.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/nkeys"
)

// natsKeyRole is one role of the NATS trust chain.
type natsKeyRole int

const (
	natsKeyOperator natsKeyRole = iota
	natsKeyOperatorSigning
	natsKeySysAccount
	natsKeyTenantAccount
	natsKeyTenantSigning
)

func (r natsKeyRole) String() string {
	switch r {
	case natsKeyOperator:
		return "operator"
	case natsKeyOperatorSigning:
		return "operator-signing"
	case natsKeySysAccount:
		return "sys-account"
	case natsKeyTenantAccount:
		return "tenant-account"
	case natsKeyTenantSigning:
		return "tenant-signing"
	}
	return fmt.Sprintf("natsKeyRole(%d)", int(r))
}

// prefix is the NKey prefix the role's public key carries.
func (r natsKeyRole) prefix() nkeys.PrefixByte {
	switch r {
	case natsKeyOperator, natsKeyOperatorSigning:
		return nkeys.PrefixByteOperator
	default:
		return nkeys.PrefixByteAccount
	}
}

// natsKeyRef names one key pair of the trust chain. tenantID is set only
// for the per-tenant roles; empty means the legacy single tenant
// (jwtauth.go's tenant.nk / tenant-signing.nk). The platform roles
// ignore it.
type natsKeyRef struct {
	role     natsKeyRole
	tenantID string
}

func (k natsKeyRef) String() string {
	if k.tenantID == "" {
		return k.role.String()
	}
	return k.role.String() + "/" + k.tenantID
}

// natsKeyProvider supplies the trust chain's key pairs. Its shape follows
// natskeys.KeyStore so the Transit store can sit behind it in PR4b.
type natsKeyProvider interface {
	// keyPair returns the pair for an existing key and fails if the key
	// does not exist.
	keyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error)
	// ensureKeyPair returns the pair, creating the key if it does not
	// exist.
	ensureKeyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error)
}

// natsKeys is the provider the farmer signs with. It is set only at
// start-up (and in tests), never while signing is in progress.
var natsKeys natsKeyProvider = seedNATSKeys{}

// seedNATSKeys keeps each key as an NKey seed: an external seed
// (IMAS_NATS_<NAME>_SEED_FILE or _SEED) or, failing that, a 0600 file
// under natsAuthDir.
type seedNATSKeys struct{}

// seedLocation maps a key to its seed file and external seed name, the
// arguments jwtauth.go and tenant.go passed to loadOrCreateSeed.
func seedLocation(k natsKeyRef) (path, name string, err error) {
	switch k.role {
	case natsKeyOperator:
		return filepath.Join(natsAuthDir(), "operator.nk"), "OPERATOR", nil
	case natsKeyOperatorSigning:
		return filepath.Join(natsAuthDir(), "operator-signing.nk"), "OPERATOR_SIGNING", nil
	case natsKeySysAccount:
		return filepath.Join(natsAuthDir(), "sys-account.nk"), "SYS_ACCOUNT", nil
	case natsKeyTenantAccount:
		if k.tenantID == "" {
			return filepath.Join(natsAuthDir(), "tenant.nk"), "TENANT", nil
		}
		return tenantAccountKeyPath(k.tenantID), externalSeedNameForTenant(k.tenantID), nil
	case natsKeyTenantSigning:
		if k.tenantID == "" {
			return filepath.Join(natsAuthDir(), "tenant-signing.nk"), "TENANT_SIGNING", nil
		}
		return tenantAccountSigningKeyPath(k.tenantID), externalSeedNameForTenant(k.tenantID) + "_SIGNING", nil
	}
	return "", "", fmt.Errorf("pki: unknown NATS key role %v", k.role)
}

func (seedNATSKeys) ensureKeyPair(_ context.Context, k natsKeyRef) (nkeys.KeyPair, error) {
	path, name, err := seedLocation(k)
	if err != nil {
		return nil, err
	}
	create := nkeys.CreateAccount
	if k.role.prefix() == nkeys.PrefixByteOperator {
		create = nkeys.CreateOperator
	}
	return loadOrCreateSeed(path, name, create)
}

func (seedNATSKeys) keyPair(_ context.Context, k natsKeyRef) (nkeys.KeyPair, error) {
	path, name, err := seedLocation(k)
	if err != nil {
		return nil, err
	}
	if kp, ok, err := loadExternalSeed(name); ok {
		return kp, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pki: NATS key %v: %w", k, err)
	}
	return nkeys.FromSeed(bytes.TrimSpace(b))
}
