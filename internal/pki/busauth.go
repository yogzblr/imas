package pki

// The DMZ bus's own auth bootstrap (cmd/farmerbus). FLAG FOR SECURITY
// REVIEW.
//
// The bus holds the operator, operator signing and SYS account seeds (the
// same ones core uses), so it could sign any Account JWT. Older versions
// did: on an empty volume ensureNatsAuth minted the legacy tenant's
// Account JWT and the SYS Account JWT, and ConfigureNats seeded both into
// the resolver. Those copies carry none of core's revocations (denied
// sprouts, rotated-out SaaS API keys) and an issued-at of "now", so they
// outranked everything core had pushed before then; in a cluster, the
// resolver sync (nats-server's own, and cmd/farmerbus's fence) spread
// them to every node, re-admitting revoked credentials.
//
// The bus now signs nothing that can win against core:
//
//   - no tenant Account JWT at all, for the legacy tenant or any other.
//     The bus learns every Account from core's pushes (PushAllAccounts,
//     run whenever core's SYS connection connects or reconnects) or from
//     its peers;
//   - one SYS Account JWT, because the server needs the system account
//     before it can accept core's first push. It is issued at the Unix
//     epoch, so any SYS Account JWT core signs outranks it, both when core
//     pushes and in any resolver sync;
//   - the operator JWT (a trust anchor, never synced) and an ephemeral SYS
//     user for cmd/farmerbus's in-process fence connection, both in memory.
//
// Nothing here is written to the bus's nats-auth directory, except the
// seeds loadOrCreateSeed generates when none is supplied externally (a
// bus deployed without the chart's seed Secret, which can't talk to core
// anyway).

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
)

// busBootstrapIssuedAt is the issued-at of the bus's SYS bootstrap JWT:
// one second after the Unix epoch, older than anything core signs.
// (Zero would be omitted from the claims.)
const busBootstrapIssuedAt = 1

// BusSysUser is the credential cmd/farmerbus's fence uses for its
// in-process SYS connection. It is minted per process start and never
// persisted.
type BusSysUser struct {
	JWT  string
	Seed string
}

// busAuthMaterial is what the bus needs from the trust chain.
type busAuthMaterial struct {
	operatorClaims  *jwt.OperatorClaims
	sysAccountPub   string
	sysBootstrapJWT string
	sysUser         BusSysUser
}

// loadBusAuth builds the bus's auth material from the operator, operator
// signing and SYS account seeds, without minting any tenant claims.
func loadBusAuth() (*busAuthMaterial, error) {
	dir := natsAuthDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	operatorKP, err := loadOrCreateSeed(filepath.Join(dir, "operator.nk"), "OPERATOR", nkeys.CreateOperator)
	if err != nil {
		return nil, err
	}
	operatorPub, err := operatorKP.PublicKey()
	if err != nil {
		return nil, err
	}
	operatorSigningKP, err := loadOrCreateSeed(filepath.Join(dir, "operator-signing.nk"), "OPERATOR_SIGNING", nkeys.CreateOperator)
	if err != nil {
		return nil, err
	}
	operatorSigningPub, err := operatorSigningKP.PublicKey()
	if err != nil {
		return nil, err
	}
	sysAccountKP, err := loadOrCreateSeed(filepath.Join(dir, "sys-account.nk"), "SYS_ACCOUNT", nkeys.CreateAccount)
	if err != nil {
		return nil, err
	}
	sysAccountPub, err := sysAccountKP.PublicKey()
	if err != nil {
		return nil, err
	}

	// Same operator claims ensureNatsAuth signs, but kept in memory.
	oc := jwt.NewOperatorClaims(operatorPub)
	oc.Name = "imas-operator"
	oc.SystemAccount = sysAccountPub
	oc.SigningKeys.Add(operatorSigningPub)
	opJWT, err := oc.Encode(operatorKP)
	if err != nil {
		return nil, err
	}
	opClaims, err := jwt.DecodeOperatorClaims(opJWT)
	if err != nil {
		return nil, err
	}

	sc := jwt.NewAccountClaims(sysAccountPub)
	sc.Name = "SYS"
	sysJWT, err := signAccountClaimsAt(sc, operatorSigningKP, busBootstrapIssuedAt)
	if err != nil {
		return nil, fmt.Errorf("signing the SYS bootstrap Account JWT: %w", err)
	}

	userKP, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	userPub, err := userKP.PublicKey()
	if err != nil {
		return nil, err
	}
	userSeed, err := userKP.Seed()
	if err != nil {
		return nil, err
	}
	uc := jwt.NewUserClaims(userPub)
	uc.Name = "imas-farmerbus-fence"
	userJWT, err := uc.Encode(sysAccountKP)
	if err != nil {
		return nil, err
	}

	return &busAuthMaterial{
		operatorClaims:  opClaims,
		sysAccountPub:   sysAccountPub,
		sysBootstrapJWT: sysJWT,
		sysUser:         BusSysUser{JWT: userJWT, Seed: string(userSeed)},
	}, nil
}

// signAccountClaimsAt signs ac like ac.Encode(kp), but with the given
// issued-at instead of the current time. jwt/v2 always stamps "now", so
// this signs the token itself: it encodes once to fill in the issuer,
// version and header, then rewrites iat, recomputes the jti over the
// generic claims exactly as jwt/v2 does, and signs header.payload with kp.
// The result is checked by decoding it with jwt/v2.
func signAccountClaimsAt(ac *jwt.AccountClaims, kp nkeys.KeyPair, iat int64) (string, error) {
	first, err := ac.Encode(kp)
	if err != nil {
		return "", err
	}
	header, _, ok := strings.Cut(first, ".")
	if !ok {
		return "", errors.New("unexpected JWT shape")
	}
	ac.IssuedAt = iat
	ac.ID = ""
	generic, err := json.Marshal(ac.ClaimsData)
	if err != nil {
		return "", err
	}
	h := sha512.New512_256()
	h.Write(generic)
	ac.ID = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
	payload, err := json.Marshal(ac)
	if err != nil {
		return "", err
	}
	toSign := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := kp.Sign([]byte(toSign))
	if err != nil {
		return "", err
	}
	token := toSign + "." + base64.RawURLEncoding.EncodeToString(sig)

	back, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return "", fmt.Errorf("re-signed JWT does not decode: %w", err)
	}
	if back.IssuedAt != iat || back.ID != ac.ID || back.Subject != ac.Subject {
		return "", errors.New("re-signed JWT does not carry the requested claims")
	}
	return token, nil
}

// ConfigureBusNats builds the NATS server options for the DMZ bus
// (cmd/farmerbus): the listeners and TLS of ConfigureNats, and a full
// resolver seeded with nothing but the SYS bootstrap Account JWT. See this
// file's header comment for why.
func ConfigureBusNats() (nats_server.Options, BusSysUser) {
	opts := baseNatsOptions()
	bm, err := loadBusAuth()
	if err != nil {
		log.Panicf("nats: failed to load the bus's auth material: %v", err)
	}
	opts.TrustedOperators = []*jwt.OperatorClaims{bm.operatorClaims}
	opts.SystemAccount = bm.sysAccountPub

	dropSelfMintedClaims(resolverStoreDir())

	resolver, err := nats_server.NewDirAccResolver(resolverStoreDir(), 0, 0, nats_server.HardDelete)
	if err != nil {
		log.Panicf("nats: failed to create the account resolver: %v", err)
	}
	// Store is saveIfNewer: a SYS Account JWT core pushed earlier (and
	// this node kept on its volume) is newer than the bootstrap and stays.
	if err := resolver.Store(bm.sysAccountPub, bm.sysBootstrapJWT); err != nil {
		log.Panicf("nats: failed to seed the SYS bootstrap account into the resolver: %v", err)
	}
	opts.AccountResolver = resolver
	return opts, bm.sysUser
}

// dropSelfMintedClaims removes from the resolver directory any Account JWT
// an older bus minted for itself and seeded there: the legacy tenant's and
// the SYS account's, recognised by being byte-identical to the
// nats-auth/tenant.jwt and nats-auth/sys-account.jwt that version wrote
// next to it. A JWT core pushed since differs from those files and is
// kept. Runs before the resolver opens the directory.
func dropSelfMintedClaims(resolverDir string) {
	for _, name := range []string{"tenant.jwt", "sys-account.jwt"} {
		own, err := os.ReadFile(filepath.Join(natsAuthDir(), name))
		if err != nil {
			continue
		}
		ac, err := jwt.DecodeAccountClaims(string(own))
		if err != nil || !nkeys.IsValidPublicAccountKey(ac.Subject) {
			continue
		}
		stored := filepath.Join(resolverDir, ac.Subject+".jwt")
		cur, err := os.ReadFile(stored)
		if err != nil || strings.TrimSpace(string(cur)) != strings.TrimSpace(string(own)) {
			continue
		}
		if err := os.Remove(stored); err != nil {
			log.Errorf("nats: failed to drop the self-minted %s from the resolver: %v", name, err)
			continue
		}
		log.Warnf("nats: dropped the Account JWT for %s that an older bus minted for itself (%s); core's push or a peer supplies it", ac.Subject, name)
	}
}
