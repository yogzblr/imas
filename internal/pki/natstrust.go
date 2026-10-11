package pki

// NATS trust model (P21 slice 1, docs/briefs/P21-slice1-transit-signer.md
// §2.1). The public half of the NATS trust chain (operator JWT, the
// operator, operator-signing and SYS account public keys, the SYS
// account JWT and the optional bus fence user JWT) lives in the
// ConfigMap imas-nats-trust, mounted at IMAS_NATS_TRUST_DIR. The private
// halves live only in OpenBao Transit (internal/pki/natskeys); the
// bootstrap Job mints the JWTs once with BootstrapNATSTrust.
//
// FLAG FOR SECURITY REVIEW: this is the trust anchor every NATS
// connection is verified against. BootstrapNATSTrust never replaces an
// existing anchor (ErrTrustWouldChange).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki/natskeys"
)

// Keys of the trust ConfigMap, which are also the file names in the
// mounted trust directory.
const (
	TrustOperatorJWT        = "operator.jwt"
	TrustOperatorPub        = "operator.pub"
	TrustOperatorSigningPub = "operator-signing.pub"
	TrustSysAccountPub      = "sys-account.pub"
	TrustSysAccountJWT      = "sys-account.jwt"
	TrustBusFenceUserJWT    = "bus-fence-user.jwt" // optional
)

// NATSTrustDirEnv names the directory the trust ConfigMap is mounted at;
// DefaultNATSTrustDir applies when it is unset.
const (
	NATSTrustDirEnv     = "IMAS_NATS_TRUST_DIR"
	DefaultNATSTrustDir = "/var/run/imas/nats-trust"
)

// Trust errors; every error from this file about trust content wraps one.
var (
	// ErrTrustIncomplete is a required trust key that is missing or empty.
	ErrTrustIncomplete = errors.New("pki: nats trust is incomplete")
	// ErrTrustInvalid is trust content that does not decode, does not
	// verify, has the wrong prefix or issuer, or is inconsistent.
	ErrTrustInvalid = errors.New("pki: nats trust is invalid")
	// ErrTrustMismatch is trust whose public keys differ from Transit's.
	ErrTrustMismatch = errors.New("pki: nats trust does not match transit keys")
	// ErrTrustWouldChange is a bootstrap that would replace an existing
	// trust anchor with different keys. Nothing is minted.
	ErrTrustWouldChange = errors.New("pki: nats trust anchor would change")
)

// NATSTrust is the public NATS trust chain. Every field is public data.
type NATSTrust struct {
	OperatorJWT        string
	OperatorPub        string
	OperatorSigningPub string
	SysAccountPub      string
	SysAccountJWT      string
	BusFenceUserJWT    string // empty when no fence user is configured
}

// NATSTrustDir is IMAS_NATS_TRUST_DIR, or DefaultNATSTrustDir when unset.
func NATSTrustDir() string {
	if d := os.Getenv(NATSTrustDirEnv); d != "" {
		return d
	}
	return DefaultNATSTrustDir
}

// Files is t as ConfigMap data, keyed by the Trust* names. The fence
// user JWT is left out when empty.
func (t *NATSTrust) Files() map[string][]byte {
	m := map[string][]byte{
		TrustOperatorJWT:        []byte(t.OperatorJWT),
		TrustOperatorPub:        []byte(t.OperatorPub),
		TrustOperatorSigningPub: []byte(t.OperatorSigningPub),
		TrustSysAccountPub:      []byte(t.SysAccountPub),
		TrustSysAccountJWT:      []byte(t.SysAccountJWT),
	}
	if t.BusFenceUserJWT != "" {
		m[TrustBusFenceUserJWT] = []byte(t.BusFenceUserJWT)
	}
	return m
}

// ParseNATSTrust builds a NATSTrust from ConfigMap data and validates it:
// every required key present, every public key a valid NKey of its kind,
// every JWT decoding with a verified signature and no blocking
// validation issue, the operator JWT self-signed by operator.pub, listing
// operator-signing.pub as a signing key and sys-account.pub as the
// system account, the SYS account JWT about sys-account.pub and issued by
// operator-signing.pub, and the fence user JWT (if any) issued by
// sys-account.pub. Surrounding whitespace in values is ignored.
func ParseNATSTrust(files map[string][]byte) (*NATSTrust, error) {
	get := func(k string) string { return strings.TrimSpace(string(files[k])) }
	t := &NATSTrust{
		OperatorJWT:        get(TrustOperatorJWT),
		OperatorPub:        get(TrustOperatorPub),
		OperatorSigningPub: get(TrustOperatorSigningPub),
		SysAccountPub:      get(TrustSysAccountPub),
		SysAccountJWT:      get(TrustSysAccountJWT),
		BusFenceUserJWT:    get(TrustBusFenceUserJWT),
	}
	var missing []string
	for _, kv := range []struct{ k, v string }{
		{TrustOperatorJWT, t.OperatorJWT},
		{TrustOperatorPub, t.OperatorPub},
		{TrustOperatorSigningPub, t.OperatorSigningPub},
		{TrustSysAccountPub, t.SysAccountPub},
		{TrustSysAccountJWT, t.SysAccountJWT},
	} {
		if kv.v == "" {
			missing = append(missing, kv.k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: missing %s", ErrTrustIncomplete, strings.Join(missing, ", "))
	}
	if err := checkTrustPubs(t.OperatorPub, t.OperatorSigningPub, t.SysAccountPub); err != nil {
		return nil, err
	}
	if _, err := checkOperatorJWT(t.OperatorJWT, t.OperatorPub, t.OperatorSigningPub, t.SysAccountPub); err != nil {
		return nil, err
	}
	if _, err := checkSysAccountJWT(t.SysAccountJWT, t.SysAccountPub, t.OperatorSigningPub); err != nil {
		return nil, err
	}
	if t.BusFenceUserJWT != "" {
		if _, err := checkFenceUserJWT(t.BusFenceUserJWT, t.SysAccountPub); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// LoadNATSTrustDir reads the trust files from dir (a mounted ConfigMap;
// its entries may be symlinks) and parses them with ParseNATSTrust.
// Production callers pass NATSTrustDir().
func LoadNATSTrustDir(dir string) (*NATSTrust, error) {
	files := map[string][]byte{}
	for _, k := range []string{
		TrustOperatorJWT, TrustOperatorPub, TrustOperatorSigningPub,
		TrustSysAccountPub, TrustSysAccountJWT, TrustBusFenceUserJWT,
	} {
		b, err := os.ReadFile(filepath.Join(dir, k))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pki: read nats trust %s: %w", k, err)
		}
		files[k] = b
	}
	t, err := ParseNATSTrust(files)
	if err != nil {
		return nil, fmt.Errorf("%w (trust dir %s)", err, dir)
	}
	return t, nil
}

// VerifyAgainst reads the three platform Transit keys (read only, never
// created) and checks their public keys equal t's. A difference is
// ErrTrustMismatch; a Transit failure is returned as is (wrapping a
// natskeys sentinel).
func (t *NATSTrust) VerifyAgainst(ctx context.Context, ks natskeys.KeyStore) error {
	pubs, err := platformPubs(ctx, ks)
	if err != nil {
		return err
	}
	for _, c := range []struct{ name, have, transit string }{
		{TrustOperatorPub, t.OperatorPub, pubs.operator},
		{TrustOperatorSigningPub, t.OperatorSigningPub, pubs.operatorSigning},
		{TrustSysAccountPub, t.SysAccountPub, pubs.sysAccount},
	} {
		if c.have != c.transit {
			return fmt.Errorf("%w: %s is %s, transit has %s", ErrTrustMismatch, c.name, c.have, c.transit)
		}
	}
	return nil
}

// BootstrapInput is what BootstrapNATSTrust starts from.
type BootstrapInput struct {
	// Existing is the current trust ConfigMap data; nil or empty on a
	// first install.
	Existing map[string][]byte
	// OperatorName is the operator JWT's name when it is minted.
	OperatorName string
	// BusFenceUserPub is the bus fence user's public NKey (prefix U).
	// When set, a fence user JWT for it is minted unless Existing holds
	// a valid one for the same key. When empty, a valid existing fence
	// user JWT is kept.
	BusFenceUserPub string
}

// BootstrapNATSTrust returns the trust chain for the platform Transit
// keys, which must exist (the bootstrap subcommand ensures them first).
// It reuses every JWT in in.Existing that decodes, verifies and matches
// the Transit public keys, and mints only what is missing: the operator
// JWT signed by nats-operator, the SYS account JWT signed by
// nats-operator-signing and the fence user JWT signed by
// nats-sys-account. A second run over its own output signs nothing and
// returns byte-identical JWTs.
//
// It never replaces the trust anchor: if an existing public key file, or
// a key named inside an existing JWT, differs from Transit, it returns
// ErrTrustWouldChange and mints nothing. A present but invalid entry is
// ErrTrustInvalid; it is not overwritten either.
func BootstrapNATSTrust(ctx context.Context, ks natskeys.KeyStore, in BootstrapInput) (*NATSTrust, error) {
	pubs, err := platformPubs(ctx, ks)
	if err != nil {
		return nil, err
	}
	get := func(k string) string { return strings.TrimSpace(string(in.Existing[k])) }

	// Refuse first, mint after: nothing is signed if any check fails.
	for _, c := range []struct{ name, have, transit string }{
		{TrustOperatorPub, get(TrustOperatorPub), pubs.operator},
		{TrustOperatorSigningPub, get(TrustOperatorSigningPub), pubs.operatorSigning},
		{TrustSysAccountPub, get(TrustSysAccountPub), pubs.sysAccount},
	} {
		if c.have != "" && c.have != c.transit {
			return nil, fmt.Errorf("%w: %s is %s, transit has %s", ErrTrustWouldChange, c.name, c.have, c.transit)
		}
	}
	opJWT := get(TrustOperatorJWT)
	if opJWT != "" {
		if err := checkExistingOperatorJWT(opJWT, pubs); err != nil {
			return nil, err
		}
	}
	sysJWT := get(TrustSysAccountJWT)
	if sysJWT != "" {
		if err := checkExistingSysAccountJWT(sysJWT, pubs); err != nil {
			return nil, err
		}
	}
	fenceJWT := get(TrustBusFenceUserJWT)
	if fenceJWT != "" {
		uc, err := checkFenceUserJWT(fenceJWT, pubs.sysAccount)
		if err != nil {
			return nil, err
		}
		if in.BusFenceUserPub != "" && uc.Subject != in.BusFenceUserPub {
			fenceJWT = "" // a new fence user: not part of the anchor, re-minted
		}
	}
	if in.BusFenceUserPub != "" && !nkeys.IsValidPublicUserKey(in.BusFenceUserPub) {
		return nil, fmt.Errorf("%w: bus fence user %q is not a user public key", ErrTrustInvalid, in.BusFenceUserPub)
	}

	if opJWT == "" {
		oc := jwt.NewOperatorClaims(pubs.operator)
		oc.Name = in.OperatorName
		oc.SystemAccount = pubs.sysAccount
		oc.SigningKeys.Add(pubs.operatorSigning)
		if opJWT, err = oc.Encode(pubs.operatorKP); err != nil {
			return nil, fmt.Errorf("pki: sign operator jwt: %w", err)
		}
	}
	if sysJWT == "" {
		ac := jwt.NewAccountClaims(pubs.sysAccount)
		ac.Name = "SYS"
		if sysJWT, err = ac.Encode(pubs.operatorSigningKP); err != nil {
			return nil, fmt.Errorf("pki: sign sys account jwt: %w", err)
		}
	}
	if fenceJWT == "" && in.BusFenceUserPub != "" {
		uc := jwt.NewUserClaims(in.BusFenceUserPub)
		uc.Name = "imas-bus-fence"
		if fenceJWT, err = uc.Encode(pubs.sysAccountKP); err != nil {
			return nil, fmt.Errorf("pki: sign bus fence user jwt: %w", err)
		}
	}

	t := &NATSTrust{
		OperatorJWT:        opJWT,
		OperatorPub:        pubs.operator,
		OperatorSigningPub: pubs.operatorSigning,
		SysAccountPub:      pubs.sysAccount,
		SysAccountJWT:      sysJWT,
		BusFenceUserJWT:    fenceJWT,
	}
	// Belt and braces: what is returned must load back.
	if _, err := ParseNATSTrust(t.Files()); err != nil {
		return nil, err
	}
	return t, nil
}

type trustPubs struct {
	operator, operatorSigning, sysAccount string
	// The pairs the public keys were read from, for signing.
	operatorKP, operatorSigningKP, sysAccountKP nkeys.KeyPair
}

// platformPubs reads the three platform Transit keys and their public
// keys. The keys are only read (KeyPair), never created.
func platformPubs(ctx context.Context, ks natskeys.KeyStore) (trustPubs, error) {
	var p trustPubs
	for _, k := range []struct {
		name   string
		prefix natskeys.Prefix
		kp     *nkeys.KeyPair
		pub    *string
	}{
		{natskeys.OperatorKey(), nkeys.PrefixByteOperator, &p.operatorKP, &p.operator},
		{natskeys.OperatorSigningKey(), nkeys.PrefixByteOperator, &p.operatorSigningKP, &p.operatorSigning},
		{natskeys.SysAccountKey(), nkeys.PrefixByteAccount, &p.sysAccountKP, &p.sysAccount},
	} {
		kp, err := ks.KeyPair(ctx, k.name, k.prefix)
		if err != nil {
			return trustPubs{}, err
		}
		if *k.pub, err = kp.PublicKey(); err != nil {
			return trustPubs{}, err
		}
		*k.kp = kp
	}
	return p, nil
}

func checkTrustPubs(operator, operatorSigning, sysAccount string) error {
	if !nkeys.IsValidPublicOperatorKey(operator) {
		return fmt.Errorf("%w: %s is not an operator public key", ErrTrustInvalid, TrustOperatorPub)
	}
	if !nkeys.IsValidPublicOperatorKey(operatorSigning) {
		return fmt.Errorf("%w: %s is not an operator public key", ErrTrustInvalid, TrustOperatorSigningPub)
	}
	if !nkeys.IsValidPublicAccountKey(sysAccount) {
		return fmt.Errorf("%w: %s is not an account public key", ErrTrustInvalid, TrustSysAccountPub)
	}
	return nil
}

// validateClaims fails on a blocking validation issue (time checks
// included: an expired anchor is not usable).
func validateClaims(name string, c jwt.Claims) error {
	vr := jwt.CreateValidationResults()
	c.Validate(vr)
	if vr.IsBlocking(true) {
		return fmt.Errorf("%w: %s: %v", ErrTrustInvalid, name, vr.Errors())
	}
	return nil
}

// checkOperatorJWT decodes s (which verifies its signature against its
// issuer) and checks it is self-signed by operator, lists
// operatorSigning and names sysAccount.
func checkOperatorJWT(s, operator, operatorSigning, sysAccount string) (*jwt.OperatorClaims, error) {
	oc, err := jwt.DecodeOperatorClaims(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustOperatorJWT, err)
	}
	if err := validateClaims(TrustOperatorJWT, oc); err != nil {
		return nil, err
	}
	switch {
	case oc.Subject != operator:
		return nil, fmt.Errorf("%w: %s subject %s is not %s", ErrTrustInvalid, TrustOperatorJWT, oc.Subject, operator)
	case oc.Issuer != operator:
		return nil, fmt.Errorf("%w: %s is issued by %s, not self-signed", ErrTrustInvalid, TrustOperatorJWT, oc.Issuer)
	case !oc.SigningKeys.Contains(operatorSigning):
		return nil, fmt.Errorf("%w: %s does not list signing key %s", ErrTrustInvalid, TrustOperatorJWT, operatorSigning)
	case oc.SystemAccount != sysAccount:
		return nil, fmt.Errorf("%w: %s system account %s is not %s", ErrTrustInvalid, TrustOperatorJWT, oc.SystemAccount, sysAccount)
	}
	return oc, nil
}

// checkSysAccountJWT checks s is the account JWT of sysAccount issued by
// operatorSigning.
func checkSysAccountJWT(s, sysAccount, operatorSigning string) (*jwt.AccountClaims, error) {
	ac, err := jwt.DecodeAccountClaims(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustSysAccountJWT, err)
	}
	if err := validateClaims(TrustSysAccountJWT, ac); err != nil {
		return nil, err
	}
	switch {
	case ac.Subject != sysAccount:
		return nil, fmt.Errorf("%w: %s subject %s is not %s", ErrTrustInvalid, TrustSysAccountJWT, ac.Subject, sysAccount)
	case ac.Issuer != operatorSigning:
		return nil, fmt.Errorf("%w: %s is issued by %s, not %s", ErrTrustInvalid, TrustSysAccountJWT, ac.Issuer, operatorSigning)
	}
	return ac, nil
}

// checkFenceUserJWT checks s is a user JWT issued directly by sysAccount
// (no issuer_account: the SYS account has no signing keys).
func checkFenceUserJWT(s, sysAccount string) (*jwt.UserClaims, error) {
	uc, err := jwt.DecodeUserClaims(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustBusFenceUserJWT, err)
	}
	if err := validateClaims(TrustBusFenceUserJWT, uc); err != nil {
		return nil, err
	}
	if uc.Issuer != sysAccount || (uc.IssuerAccount != "" && uc.IssuerAccount != sysAccount) {
		return nil, fmt.Errorf("%w: %s is issued by %s, not %s", ErrTrustInvalid, TrustBusFenceUserJWT, uc.Issuer, sysAccount)
	}
	return uc, nil
}

// checkExistingOperatorJWT is checkOperatorJWT for a bootstrap: a JWT
// that verifies but names keys other than Transit's is a changed anchor
// (ErrTrustWouldChange), not merely invalid.
func checkExistingOperatorJWT(s string, p trustPubs) error {
	oc, err := jwt.DecodeOperatorClaims(s)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustOperatorJWT, err)
	}
	if oc.Subject != p.operator || oc.Issuer != p.operator ||
		!oc.SigningKeys.Contains(p.operatorSigning) || oc.SystemAccount != p.sysAccount {
		return fmt.Errorf("%w: existing %s names operator %s, signing keys %v, system account %s",
			ErrTrustWouldChange, TrustOperatorJWT, oc.Subject, []string(oc.SigningKeys), oc.SystemAccount)
	}
	_, err = checkOperatorJWT(s, p.operator, p.operatorSigning, p.sysAccount)
	return err
}

// checkExistingSysAccountJWT is checkSysAccountJWT for a bootstrap; a
// different subject or issuer is ErrTrustWouldChange.
func checkExistingSysAccountJWT(s string, p trustPubs) error {
	ac, err := jwt.DecodeAccountClaims(s)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustSysAccountJWT, err)
	}
	if ac.Subject != p.sysAccount || ac.Issuer != p.operatorSigning {
		return fmt.Errorf("%w: existing %s is about %s issued by %s",
			ErrTrustWouldChange, TrustSysAccountJWT, ac.Subject, ac.Issuer)
	}
	_, err = checkSysAccountJWT(s, p.sysAccount, p.operatorSigning)
	return err
}
