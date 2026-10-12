package pki

// The Account JWTs and farmer User JWTs farmer holds (E3, P27.2): in
// memory only, never in a file. FLAG FOR SECURITY REVIEW: the held copy
// and the accounts bucket are what every re-sign starts from.
//
// Farmer writes no JWT to disk. Its sources of truth are shared:
//   - Account JWTs: the accounts bucket, written by the AccountPublisher
//     (accountpublisher.go) on every push. A replica that does not hold an
//     account's JWT yet reads the bucket's copy; every re-sign starts from
//     the newest of the held and the bucket copy (latestAccountJWT), so a
//     replica builds on what another replica signed, and a replica that
//     dies loses nothing.
//   - Sprout User JWTs: the sprout JWT bucket (jwtusers.go).
//   - The farmer's own User JWTs (one per Account it connects to): signed
//     on first use and held here; any replica signs its own, so there is
//     nothing to share.
//
// Without a publisher (this package's in-process test bus) the held copy
// is the only one.

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountrank"
	log "github.com/yogzblr/imas/internal/log"
)

// heldAccount is one Account JWT this process holds.
type heldAccount struct {
	jwt string
	// minted: a minimal Account JWT minted because neither this process
	// nor the bucket held one, and not yet re-signed with the account's
	// revocations. It never outranks a bucket copy.
	minted bool
}

var (
	heldMu       sync.Mutex
	heldAccounts = map[string]heldAccount{} // Account public key -> JWT
	// heldFarmerUsers are the farmer's own User JWTs, by the public key
	// of the Account that issued them.
	heldFarmerUsers = map[string]string{}
	// heldSysUser is the SYS user's JWT (ensureSysUserLocked).
	heldSysUser string
)

// holdAccountJWT records accountJWT as the copy of its Account this
// process holds, unless it already holds a newer one (accountrank.Better):
// two writers in one process can finish out of order, and the older
// must not replace the newer. A minimal mint never replaces a JWT that
// is not one.
func holdAccountJWT(accountJWT string, minted bool) error {
	ac, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		return fmt.Errorf("pki: holding an Account JWT that does not decode: %w", err)
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	if cur, ok := heldAccounts[ac.Subject]; ok && cur.jwt != accountJWT && !cur.minted {
		if minted {
			return nil
		}
		if held, err := jwt.DecodeAccountClaims(cur.jwt); err == nil &&
			accountrank.Better(claimOf(held, cur.jwt), claimOf(ac, accountJWT)) {
			return nil
		}
	}
	heldAccounts[ac.Subject] = heldAccount{jwt: accountJWT, minted: minted}
	return nil
}

// heldAccountJWT returns the Account JWT this process holds for
// accountPub.
func heldAccountJWT(accountPub string) (heldAccount, bool) {
	heldMu.Lock()
	defer heldMu.Unlock()
	h, ok := heldAccounts[accountPub]
	return h, ok
}

// heldAccountJWTs returns every Account JWT this process holds, sorted;
// with synced, only those that are not a minimal mint.
func heldAccountJWTs(synced bool) []string {
	heldMu.Lock()
	defer heldMu.Unlock()
	var out []string
	for _, h := range heldAccounts {
		if !synced || !h.minted {
			out = append(out, h.jwt)
		}
	}
	slices.Sort(out)
	return out
}

// forgetHeldJWTs drops every JWT this process holds, as a restart does.
func forgetHeldJWTs() {
	heldMu.Lock()
	defer heldMu.Unlock()
	heldAccounts = map[string]heldAccount{}
	heldFarmerUsers = map[string]string{}
	heldSysUser = ""
}

// bucketAccountJWT returns the accounts bucket's Account JWT for
// accountPub through the installed publisher, or "" when there is no
// publisher, no object, or an object that is not a valid Account JWT of
// a trusted issuer for accountPub.
func bucketAccountJWT(ctx context.Context, accountPub string) (string, error) {
	p := currentAccountPublisher()
	if p == nil {
		return "", nil
	}
	return p.Current(ctx, accountPub)
}

// latestAccountJWT returns the newest of the Account JWT this process
// holds for accountPub and the accounts bucket's copy (accountrank.Better),
// counting only those valid accepts, and whether the one returned is a
// minimal mint. A minimal mint never outranks the bucket's copy. It
// returns "" when neither is there. A failed bucket read is returned as
// an error, never taken for an empty bucket: a re-sign from an older copy
// could drop a revocation another replica made.
func latestAccountJWT(ctx context.Context, accountPub string, valid func(*jwt.AccountClaims) bool) (string, bool, error) {
	fromBucket, err := bucketAccountJWT(ctx, accountPub)
	if err != nil {
		return "", false, fmt.Errorf("pki: reading Account %s from the accounts bucket: %w", accountPub, err)
	}
	var best accountrank.Claim
	have, minted := false, false
	if h, ok := heldAccountJWT(accountPub); ok {
		if ac, err := jwt.DecodeAccountClaims(h.jwt); err == nil && ac.Subject == accountPub && valid(ac) {
			best, have, minted = claimOf(ac, h.jwt), true, h.minted
		}
	}
	if fromBucket != "" {
		if ac, err := jwt.DecodeAccountClaims(fromBucket); err == nil && ac.Subject == accountPub && valid(ac) {
			c := claimOf(ac, fromBucket)
			if !have || minted || accountrank.Better(c, best) {
				best, have, minted = c, true, false
			}
		}
	}
	if !have {
		return "", false, nil
	}
	return best.Raw, minted, nil
}

// loadAccountJWT is what an ensure path starts from: the held Account
// JWT for accountPub if valid accepts it, or else the bucket's
// (latestAccountJWT), which it then holds. "" means there is none. Only
// a process's first load of an account reads the bucket; a failed read
// is returned (the caller retries on its next call), never taken for an
// empty bucket.
func loadAccountJWT(ctx context.Context, accountPub string, valid func(*jwt.AccountClaims) bool) (string, bool, error) {
	if h, ok := heldAccountJWT(accountPub); ok {
		if ac, err := jwt.DecodeAccountClaims(h.jwt); err == nil && ac.Subject == accountPub && valid(ac) {
			return h.jwt, h.minted, nil
		}
	}
	j, minted, err := latestAccountJWT(ctx, accountPub, valid)
	if err != nil || j == "" {
		return "", false, err
	}
	if err := holdAccountJWT(j, minted); err != nil {
		return "", false, err
	}
	return j, minted, nil
}

// resignBase returns the Account JWT a re-sign of accountPub starts from,
// raw and decoded: the newest of what this process holds and the bucket's
// copy, or fallback (the caller's own copy, fallbackMinted if a minimal
// mint) when neither validates. minted reports a minimal mint, whose iat a
// re-sign need not outrank.
func resignBase(ctx context.Context, accountPub, fallback string, fallbackMinted bool, valid func(*jwt.AccountClaims) bool) (ac *jwt.AccountClaims, raw string, minted bool, err error) {
	raw, minted, err = latestAccountJWT(ctx, accountPub, valid)
	if err != nil {
		return nil, "", false, err
	}
	if raw == "" {
		raw, minted = fallback, fallbackMinted
	}
	ac, err = jwt.DecodeAccountClaims(raw)
	if err != nil {
		return nil, "", false, err
	}
	return ac, raw, minted, nil
}

// signsWith accepts an Account JWT that lists signingPub as a signing key.
func signsWith(signingPub string) func(*jwt.AccountClaims) bool {
	return func(ac *jwt.AccountClaims) bool { return ac.SigningKeys.Contains(signingPub) }
}

// issuedBy accepts an Account JWT whose issuer is issuerPub.
func issuedBy(issuerPub string) func(*jwt.AccountClaims) bool {
	return func(ac *jwt.AccountClaims) bool { return ac.Issuer == issuerPub }
}

// mintOrReuseUserJWT returns existing when it is a User JWT for pubkey
// under the Account issuerAccountPub carrying exactly perms, and
// otherwise a fresh one signed with signingKP; minted reports which.
// Comparing the permissions is what makes a change to allowAllPermissions
// or sproutPermissions reach a JWT minted before it. It reads and writes
// nothing: the caller holds or stores the result.
func mintOrReuseUserJWT(existing, pubkey, name string, perms jwt.Permissions, issuerAccountPub string, signingKP nkeys.KeyPair) (signed string, minted bool, err error) {
	if existing != "" {
		if uc, derr := jwt.DecodeUserClaims(existing); derr == nil && uc.Subject == pubkey &&
			uc.IssuerAccount == issuerAccountPub && reflect.DeepEqual(uc.Permissions, perms) {
			return existing, false, nil
		}
	}
	uc := jwt.NewUserClaims(pubkey)
	uc.Name = name
	uc.IssuerAccount = issuerAccountPub
	uc.Permissions = perms
	if signed, err = uc.Encode(signingKP); err != nil {
		return "", false, err
	}
	return signed, true, nil
}

// farmerUserJWT returns the farmer's own User JWT under the Account
// accountPub, signing it with signingKP on first use (or when the
// permissions it carries are no longer current) and holding it. It is
// never written anywhere: any replica signs its own.
func farmerUserJWT(accountPub string, signingKP nkeys.KeyPair) (string, error) {
	farmerKey, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		return "", fmt.Errorf("pki: loading the farmer's NKey: %w", err)
	}
	heldMu.Lock()
	held := heldFarmerUsers[accountPub]
	heldMu.Unlock()
	signed, minted, err := mintOrReuseUserJWT(held, farmerKey, "farmer", allowAllPermissions(), accountPub, signingKP)
	if err != nil || !minted {
		return signed, err
	}
	heldMu.Lock()
	heldFarmerUsers[accountPub] = signed
	heldMu.Unlock()
	log.Tracef("Signed farmer's User JWT under Account %s", accountPub)
	return signed, nil
}
