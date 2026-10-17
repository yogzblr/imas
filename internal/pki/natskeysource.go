package pki

// Where the farmer's NATS trust chain key pairs come from (P21 slice 1,
// docs/briefs/P21-slice1-transit-signer.md §2). Every key pair the farmer
// signs with (operator signing, SYS account, legacy and per-tenant
// account signing) and every account identity whose public key it needs
// is an OpenBao Transit key, reached through natskeys. No operator,
// operator-signing, SYS account, tenant or tenant-signing seed exists in
// the farmer any more; old seed files are simply not read (design D6).
// User-kind seeds (SYS_USER, SAASAPI_USER) are not trust chain keys and
// do not go through here.
//
// FLAG FOR SECURITY REVIEW: these pairs sign every NATS account and user
// JWT the farmer issues.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki/natskeys"
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
// for the per-tenant roles; empty means the legacy single tenant, whose
// keys are named after currentTenantID(). The platform roles ignore it.
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

// transitName is the Transit key name of k (natskeys/names.go).
func (k natsKeyRef) transitName() (string, error) {
	tenant := k.tenantID
	if tenant == "" {
		tenant = currentTenantID()
	}
	switch k.role {
	case natsKeyOperator:
		return natskeys.OperatorKey(), nil
	case natsKeyOperatorSigning:
		return natskeys.OperatorSigningKey(), nil
	case natsKeySysAccount:
		return natskeys.SysAccountKey(), nil
	case natsKeyTenantAccount:
		return natskeys.TenantAccountKey(tenant), nil
	case natsKeyTenantSigning:
		return natskeys.TenantSigningKey(tenant), nil
	}
	return "", fmt.Errorf("pki: unknown NATS key role %v", k.role)
}

// natsKeyProvider supplies the trust chain's key pairs.
type natsKeyProvider interface {
	// keyPair returns the pair for an existing key and fails (wrapping
	// natskeys.ErrKeyNotFound) if the key does not exist.
	keyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error)
	// ensureKeyPair returns the pair, creating the key if it does not
	// exist. Only tenant provisioning calls it.
	ensureKeyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error)
	// retireKey soft-deletes the key; a missing or already retired key
	// is success.
	retireKey(ctx context.Context, k natsKeyRef) error
	// destroyKey deletes the key permanently and reports whether it
	// existed; a missing key is success.
	destroyKey(ctx context.Context, k natsKeyRef) (bool, error)
	// store is the underlying key store, for trust verification.
	store() (natskeys.KeyStore, error)
}

// natsKeys is the provider the farmer signs with. It is set only at
// start-up (and in tests), never while signing is in progress.
var natsKeys natsKeyProvider = &transitNATSKeys{getenv: os.Getenv}

// natsSignEnvSuffixes are the IMAS_NATSSIGN_* settings the store is built
// from (natskeys.ConfigFromEnv and internal/openbao).
var natsSignEnvSuffixes = []string{
	natskeys.EnvOpenBaoAddr, natskeys.EnvOpenBaoCACert, natskeys.EnvOpenBaoAuthMethod,
	natskeys.EnvOpenBaoToken, natskeys.EnvOpenBaoK8sRole, natskeys.EnvOpenBaoK8sMount,
	natskeys.EnvOpenBaoK8sJWTPath, natskeys.EnvOpenBaoNamespace, natskeys.EnvOpenBaoTransitMount,
	natskeys.EnvTimeout, natskeys.EnvBatchMax, natskeys.EnvWorkers,
}

// transitNATSKeys builds a natskeys.TransitKeyStore from the farmer's
// IMAS_NATSSIGN_* environment on first use and caches the pairs it hands
// out (a pair pins its key version and caches its public key, so reusing
// it costs no request). The store is rebuilt, and the cache dropped, when
// that environment changes, which only tests do.
type transitNATSKeys struct {
	getenv func(string) string

	mu    sync.Mutex
	envFP [sha256.Size]byte
	ks    *natskeys.TransitKeyStore
	pairs map[string]nkeys.KeyPair
}

func (p *transitNATSKeys) fingerprint() [sha256.Size]byte {
	h := sha256.New()
	for _, s := range natsSignEnvSuffixes {
		fmt.Fprintf(h, "%s=%s\x00", s, p.getenv(natskeys.EnvPrefixSign+s))
	}
	var fp [sha256.Size]byte
	copy(fp[:], h.Sum(nil))
	return fp
}

// current returns the store for the present environment, building it
// when needed.
func (p *transitNATSKeys) current() (*natskeys.TransitKeyStore, error) {
	fp := p.fingerprint()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ks != nil && p.envFP == fp {
		return p.ks, nil
	}
	cfg, err := natskeys.ConfigFromEnv(natskeys.EnvPrefixSign, p.getenv)
	if err != nil {
		return nil, fmt.Errorf("pki: NATS signing: %w", err)
	}
	ks, err := natskeys.NewTransitKeyStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("pki: NATS signing: %w", err)
	}
	if p.ks != nil {
		p.ks.Close()
	}
	p.ks, p.envFP, p.pairs = ks, fp, map[string]nkeys.KeyPair{}
	return ks, nil
}

func (p *transitNATSKeys) store() (natskeys.KeyStore, error) { return p.current() }

func (p *transitNATSKeys) cached(ks *natskeys.TransitKeyStore, name string) nkeys.KeyPair {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ks != ks {
		return nil
	}
	return p.pairs[name]
}

func (p *transitNATSKeys) remember(ks *natskeys.TransitKeyStore, name string, kp nkeys.KeyPair) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ks == ks {
		p.pairs[name] = kp
	}
}

func (p *transitNATSKeys) get(ctx context.Context, k natsKeyRef, create bool) (nkeys.KeyPair, error) {
	name, err := k.transitName()
	if err != nil {
		return nil, err
	}
	ks, err := p.current()
	if err != nil {
		return nil, err
	}
	if kp := p.cached(ks, name); kp != nil {
		return kp, nil
	}
	var kp nkeys.KeyPair
	if create {
		kp, err = ks.EnsureKeyPair(ctx, name, k.role.prefix())
	} else {
		kp, err = ks.KeyPair(ctx, name, k.role.prefix())
	}
	if err != nil {
		return nil, fmt.Errorf("pki: NATS key %v: %w", k, err)
	}
	p.remember(ks, name, kp)
	return kp, nil
}

func (p *transitNATSKeys) keyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error) {
	return p.get(ctx, k, false)
}

func (p *transitNATSKeys) ensureKeyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error) {
	return p.get(ctx, k, true)
}

func (p *transitNATSKeys) retireKey(ctx context.Context, k natsKeyRef) error {
	name, err := k.transitName()
	if err != nil {
		return err
	}
	ks, err := p.current()
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.ks == ks {
		delete(p.pairs, name)
	}
	p.mu.Unlock()
	if err := ks.RetireKey(ctx, name); err != nil {
		return fmt.Errorf("pki: retiring NATS key %v: %w", k, err)
	}
	return nil
}

func (p *transitNATSKeys) destroyKey(ctx context.Context, k natsKeyRef) (bool, error) {
	name, err := k.transitName()
	if err != nil {
		return false, err
	}
	ks, err := p.current()
	if err != nil {
		return false, err
	}
	p.mu.Lock()
	if p.ks == ks {
		delete(p.pairs, name)
	}
	p.mu.Unlock()
	destroyed, err := ks.DestroyKey(ctx, name)
	if err != nil {
		return false, fmt.Errorf("pki: destroying NATS key %v: %w", k, err)
	}
	return destroyed, nil
}
