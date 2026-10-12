package pki

// The DMZ bus's auth configuration (cmd/farmerbus). FLAG FOR SECURITY
// REVIEW.
//
// The bus holds no private key of the trust chain and talks to no
// OpenBao (P21 slice 1 brief §2.6). Everything it trusts comes from the
// public trust directory (the imas-nats-trust ConfigMap, natstrust.go)
// that the bootstrap Job writes once:
//
//   - the operator JWT, its trust anchor (never synced);
//   - the SYS account public key and the SYS Account JWT, seeded into the
//     resolver because the server needs the system account before it can
//     accept core's first push. The bootstrap signed it before core
//     signed anything, so every SYS Account JWT core pushes (with its
//     revocations) is newer and replaces it, both on push and in any
//     resolver sync;
//   - for a clustered bus, the fence user's JWT (bus-fence-user.jwt,
//     signed by the SYS account at bootstrap). Its seed is the only
//     secret the bus holds, a user key from the BUS_FENCE_USER Secret
//     (IMAS_NATS_BUS_FENCE_USER_SEED_FILE).
//
// The bus mints nothing: no tenant Account JWT, no SYS Account JWT, no
// user. It learns every Account from core's pushes (PushAllAccounts, run
// whenever core's SYS connection connects or reconnects) or from its
// peers. Nothing is written to the bus's nats-auth directory except the
// resolver's own store.

import (
	"errors"
	"fmt"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
)

// busFenceUserSeedName is the external seed the fence user comes from:
// IMAS_NATS_BUS_FENCE_USER_SEED_FILE (or _SEED), see loadExternalSeed.
const busFenceUserSeedName = "BUS_FENCE_USER"

// ErrBusFenceUser is a fence user that is configured only in part (a seed
// without the trust's bus-fence-user.jwt, or the other way round) or
// whose seed does not match the JWT.
var ErrBusFenceUser = errors.New("pki: bus fence user is misconfigured")

// BusSysUser is the SYS account user cmd/farmerbus's fence uses for its
// in-process connection: the seed from the BUS_FENCE_USER Secret and the
// JWT from the trust directory. The zero value means none is configured,
// which only a single-node bus may run with.
type BusSysUser struct {
	JWT  string
	Seed string
}

// Configured reports whether u holds a fence user.
func (u BusSysUser) Configured() bool { return u.JWT != "" && u.Seed != "" }

// LoadBusNats builds the NATS server options for the DMZ bus
// (cmd/farmerbus): the listeners and TLS of ConfigureNats, the operator
// and system account from the trust directory (NATSTrustDir), and a full
// resolver seeded with nothing but the trust's SYS Account JWT. It also
// returns the fence user, zero when none is configured. See this file's
// header comment.
func LoadBusNats() (nats_server.Options, BusSysUser, error) {
	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		return nats_server.Options{}, BusSysUser{}, err
	}
	fence, err := loadBusFenceUser(trust)
	if err != nil {
		return nats_server.Options{}, BusSysUser{}, err
	}
	// ParseNATSTrust has verified the operator JWT; decode it again for
	// the claims the server wants.
	opClaims, err := jwt.DecodeOperatorClaims(trust.OperatorJWT)
	if err != nil {
		return nats_server.Options{}, BusSysUser{}, fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustOperatorJWT, err)
	}

	opts := baseNatsOptions()
	opts.TrustedOperators = []*jwt.OperatorClaims{opClaims}
	opts.SystemAccount = trust.SysAccountPub
	resolver, err := nats_server.NewDirAccResolver(resolverStoreDir(), 0, 0, nats_server.HardDelete)
	if err != nil {
		return nats_server.Options{}, BusSysUser{}, fmt.Errorf("pki: create the account resolver: %w", err)
	}
	// Store is saveIfNewer: a SYS Account JWT core pushed earlier (and
	// this node kept on its volume) is newer than the trust's and stays.
	if err := resolver.Store(trust.SysAccountPub, trust.SysAccountJWT); err != nil {
		return nats_server.Options{}, BusSysUser{}, fmt.Errorf("pki: seed the SYS account into the resolver: %w", err)
	}
	opts.AccountResolver = resolver
	return opts, fence, nil
}

// ConfigureBusNats is LoadBusNats for cmd/farmerbus's start-up: it panics
// on any error, as a bus without its trust cannot serve anyone.
func ConfigureBusNats() (nats_server.Options, BusSysUser) {
	opts, fence, err := LoadBusNats()
	if err != nil {
		log.Panicf("nats: failed to load the bus's auth configuration: %v", err)
	}
	return opts, fence
}

// loadBusFenceUser pairs the BUS_FENCE_USER seed with the trust's fence
// user JWT. Neither present is no fence user; one without the other, a
// seed that is not a user key, or a seed whose public key is not the
// JWT's subject is ErrBusFenceUser.
func loadBusFenceUser(trust *NATSTrust) (BusSysUser, error) {
	kp, ok, err := loadExternalSeed(busFenceUserSeedName)
	if err != nil {
		return BusSysUser{}, fmt.Errorf("%w: %v", ErrBusFenceUser, err)
	}
	switch {
	case !ok && trust.BusFenceUserJWT == "":
		return BusSysUser{}, nil
	case !ok:
		return BusSysUser{}, fmt.Errorf("%w: the trust has %s but no %s seed is set (IMAS_NATS_%s_SEED_FILE)",
			ErrBusFenceUser, TrustBusFenceUserJWT, busFenceUserSeedName, busFenceUserSeedName)
	case trust.BusFenceUserJWT == "":
		return BusSysUser{}, fmt.Errorf("%w: a %s seed is set but the trust has no %s",
			ErrBusFenceUser, busFenceUserSeedName, TrustBusFenceUserJWT)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return BusSysUser{}, fmt.Errorf("%w: %v", ErrBusFenceUser, err)
	}
	if !nkeys.IsValidPublicUserKey(pub) {
		return BusSysUser{}, fmt.Errorf("%w: the %s seed is not a user key", ErrBusFenceUser, busFenceUserSeedName)
	}
	// ParseNATSTrust has checked the JWT is issued by the SYS account.
	uc, err := jwt.DecodeUserClaims(trust.BusFenceUserJWT)
	if err != nil {
		return BusSysUser{}, fmt.Errorf("%w: %s: %v", ErrBusFenceUser, TrustBusFenceUserJWT, err)
	}
	if uc.Subject != pub {
		return BusSysUser{}, fmt.Errorf("%w: %s is for %s, the %s seed is %s",
			ErrBusFenceUser, TrustBusFenceUserJWT, uc.Subject, busFenceUserSeedName, pub)
	}
	seed, err := kp.Seed()
	if err != nil {
		return BusSysUser{}, fmt.Errorf("%w: %v", ErrBusFenceUser, err)
	}
	return BusSysUser{JWT: trust.BusFenceUserJWT, Seed: string(seed)}, nil
}
