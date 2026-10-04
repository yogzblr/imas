package main

// The fixture path: simulated sprouts get their NATS credentials minted
// here, from the operator signing and SYS account seeds, instead of from
// POST /v1/enroll. Every JWT has the shape internal/pki gives the real
// thing:
//
//   - the tenant Account is signed by the operator signing key and
//     delegates User issuance to its own signing key (tenant.go's
//     ensureTenantAccountMaterial);
//   - each sprout User JWT is signed by that signing key, names the
//     Account as its issuer and carries sproutPermissions (jwtusers.go's
//     mintOrReuseUserJWT);
//   - the requester that plays core gets core's per-tenant "farmer" User
//     shape, allowAllPermissions;
//   - the Account reaches the bus the way core pushes it, a request to
//     $SYS.REQ.CLAIMS.UPDATE as a SYS account user (resolver.go).
//
// So the bus does the same work per CONNECT (verify the User JWT against
// the Account's signing key, check the nonce signature, load the
// permissions) as for an enrolled sprout. What this path skips is listed
// in docs/loadtest.md, "What the fixture path does not test".
//
// sproutPermissions and corePermissions are copies: internal/pki keeps
// its own unexported. TestSproutPermissionsMatchPKI pins the copy to the
// grants internal/pki's exported helpers name, but a new grant added there
// has to be added here by hand.

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

const claimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"

// trust is the part of the bus's trust chain the fixture signs with.
type trust struct {
	operatorSigning nkeys.KeyPair
	sysAccount      nkeys.KeyPair
	sysUserJWT      string
	sysUserSeed     string
}

// seedFiles are the seed paths a local bus is started with, as the chart
// mounts them (IMAS_NATS_<NAME>_SEED_FILE).
type seedFiles map[string]string

// newLocalTrust generates a fresh trust chain for a local bus and writes
// its seeds to dir (mode 0600).
func newLocalTrust(dir string) (*trust, seedFiles, error) {
	makers := map[string]func() (nkeys.KeyPair, error){
		"OPERATOR":         nkeys.CreateOperator,
		"OPERATOR_SIGNING": nkeys.CreateOperator,
		"SYS_ACCOUNT":      nkeys.CreateAccount,
	}
	files := seedFiles{}
	kps := map[string]nkeys.KeyPair{}
	for name, mk := range makers {
		kp, err := mk()
		if err != nil {
			return nil, nil, err
		}
		seed, err := kp.Seed()
		if err != nil {
			return nil, nil, err
		}
		p := filepath.Join(dir, strings.ToLower(name)+".nk")
		if err := os.WriteFile(p, seed, 0o600); err != nil {
			return nil, nil, err
		}
		files[name] = p
		kps[name] = kp
	}
	tr, err := newTrust(kps["OPERATOR_SIGNING"], kps["SYS_ACCOUNT"])
	return tr, files, err
}

// loadTrust reads the operator signing and SYS account seeds of an
// existing bus: the same files the chart mounts into farmer and the bus.
func loadTrust(operatorSigningFile, sysAccountFile string) (*trust, error) {
	read := func(path string, want nkeys.PrefixByte) (nkeys.KeyPair, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(b))))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, err
		}
		if nkeys.Prefix(pub) != want {
			return nil, fmt.Errorf("%s: seed is not a %s key", path, want)
		}
		return kp, nil
	}
	op, err := read(operatorSigningFile, nkeys.PrefixByteOperator)
	if err != nil {
		return nil, fmt.Errorf("operator signing seed: %w", err)
	}
	sys, err := read(sysAccountFile, nkeys.PrefixByteAccount)
	if err != nil {
		return nil, fmt.Errorf("SYS account seed: %w", err)
	}
	return newTrust(op, sys)
}

func newTrust(operatorSigning, sysAccount nkeys.KeyPair) (*trust, error) {
	user, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	pub, _ := user.PublicKey()
	seed, _ := user.Seed()
	uc := jwt.NewUserClaims(pub)
	uc.Name = "imas-loadtest-sys"
	signed, err := uc.Encode(sysAccount)
	if err != nil {
		return nil, err
	}
	return &trust{operatorSigning: operatorSigning, sysAccount: sysAccount, sysUserJWT: signed, sysUserSeed: string(seed)}, nil
}

// tenantFixture is one load-test tenant: an Account with a delegated
// signing key, and the requester that plays core in it.
type tenantFixture struct {
	name       string
	accountPub string
	signing    nkeys.KeyPair
	signingPub string
	accountJWT string
	issuedAt   int64
	coreJWT    string
	coreSeed   string
}

func (tr *trust) newTenant(name string) (*tenantFixture, error) {
	if !pki.IsValidTenantID(name) {
		return nil, fmt.Errorf("tenant name %q is not a valid tenant ID", name)
	}
	acct, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	signing, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	tf := &tenantFixture{name: name, signing: signing}
	tf.accountPub, _ = acct.PublicKey()
	tf.signingPub, _ = signing.PublicKey()
	ac := jwt.NewAccountClaims(tf.accountPub)
	ac.Name = name
	ac.SigningKeys.Add(tf.signingPub)
	if tf.accountJWT, err = ac.Encode(tr.operatorSigning); err != nil {
		return nil, err
	}
	tf.issuedAt = ac.IssuedAt
	if tf.coreJWT, tf.coreSeed, err = tf.mintUser("farmer", corePermissions()); err != nil {
		return nil, err
	}
	return tf, nil
}

// lockedOutJWT re-signs the Account the way internal/pki locks out a
// deprovisioned tenant (lockOutAccount): every User revoked, no
// connections allowed. Its issued-at is strictly after the live JWT's, so
// it wins in a cluster's resolver sync.
func (tf *tenantFixture) lockedOutJWT(tr *trust) (string, error) {
	if d := time.Until(time.Unix(tf.issuedAt+1, 0)); d > 0 {
		time.Sleep(d)
	}
	ac := jwt.NewAccountClaims(tf.accountPub)
	ac.Name = tf.name
	ac.SigningKeys.Add(tf.signingPub)
	ac.RevokeAt(jwt.All, time.Now())
	ac.Limits.Conn = 0
	ac.Limits.LeafNodeConn = 0
	return ac.Encode(tr.operatorSigning)
}

func (tf *tenantFixture) mintUser(name string, perms jwt.Permissions) (userJWT, seed string, err error) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		return "", "", err
	}
	pub, _ := kp.PublicKey()
	s, _ := kp.Seed()
	uc := jwt.NewUserClaims(pub)
	uc.Name = name
	uc.IssuerAccount = tf.accountPub
	uc.Permissions = perms
	userJWT, err = uc.Encode(tf.signing)
	return userJWT, string(s), err
}

// sproutCred is one simulated sprout's identity.
type sproutCred struct {
	ID   string
	JWT  string
	Seed string
}

// sproutID is the ID of simulated sprout i under prefix.
func sproutID(prefix string, i int) string { return fmt.Sprintf("%s-%07d", prefix, i) }

// mintSprouts mints n sprout identities, IDs prefix-<i> for i in
// [0, n), in parallel.
func (tf *tenantFixture) mintSprouts(prefix string, n int) ([]sproutCred, error) {
	creds := make([]sproutCred, n)
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < n; i += workers {
				id := sproutID(prefix, i)
				j, s, err := tf.mintUser(id, sproutPermissions(id))
				if err != nil {
					errs <- err
					return
				}
				creds[i] = sproutCred{ID: id, JWT: j, Seed: s}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	return creds, nil
}

// sproutPermissions copies internal/pki/jwtusers.go's sproutPermissions.
func sproutPermissions(id string) jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"imas.sprouts.announce." + id,
			"_INBOX.>",
			"imas.cook." + id + ".>",
			"imas.sprouts." + id + ".facts",
			pki.SproutBoxKeySubmitSubject(id),
			pki.SproutLogSubjectPrefix(id) + ".>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			"imas.sprouts." + id + ".>",
		}},
	}
}

// corePermissions copies internal/pki/jwtusers.go's allowAllPermissions,
// what core's per-tenant connection is granted.
func corePermissions() jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"imas.>", "_INBOX.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"imas.>", "_INBOX.>"}},
	}
}

// pushAccount sends accountJWT to every server in servers, one connection
// each, as core's pushAccountUpdate does, and fails unless each accepted
// it. A server list that is really one load-balanced address reaches one
// node; a cluster's own resolver sync carries it to the rest.
func (tr *trust) pushAccount(servers []string, tlsCfg *tls.Config, accountJWT string) error {
	var errs []error
	for _, url := range servers {
		nc, err := nats.Connect(url, nats.Secure(tlsCfg), nats.UserJWTAndSeed(tr.sysUserJWT, tr.sysUserSeed),
			nats.Timeout(5*time.Second), nats.NoReconnect(), nats.Name("imas-loadtest-push"))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		err = publishClaimsUpdate(nc, accountJWT)
		nc.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
		}
	}
	return errors.Join(errs...)
}

func publishClaimsUpdate(nc *nats.Conn, accountJWT string) error {
	resp, err := nc.Request(claimsUpdateSubject, []byte(accountJWT), 5*time.Second)
	if err != nil {
		return fmt.Errorf("claims update request: %w", err)
	}
	var st nats_server.ServerAPIClaimUpdateResponse
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return fmt.Errorf("decoding claims update response: %w", err)
	}
	if st.Error != nil {
		return fmt.Errorf("bus rejected the claims update: %s", st.Error.Description)
	}
	return nil
}

// pkiSanity reports whether creds minted by the fixture pass internal/pki's
// own check that a sprout's User JWT carries the log grant (the one
// ConnectSprout makes before shipping logs).
func pkiSanity(c sproutCred) error {
	if !pki.SproutUserJWTGrantsLogs(c.JWT, c.ID) {
		return fmt.Errorf("sprout %s: minted User JWT fails pki.SproutUserJWTGrantsLogs", c.ID)
	}
	return nil
}
