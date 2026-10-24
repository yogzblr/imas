package pki

// Enrollment against MySQL, where its locking actually happens: InnoDB's
// next-key and gap locks on pki_nkeys, the enrolment key's row lock, and
// the deadlocks (1213) they produce when many sprouts enrol in the same
// second. Skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a MySQL-compatible
// server by its root account (internal/migrations/mysqltest):
//
//	IMAS_TEST_MYSQL_ROOT_DSN='root:pw@tcp(127.0.0.1:3306)/' go test ./internal/pki/ -run MySQL

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/migrations/mysqltest"
)

// setupMySQLEnrollTest is setupEnrollTest on MySQL: a fresh farmer schema
// (the farmer migration set) as this package's database, and a fresh saas
// schema (the saas set) whose enrollment_keys the production key store
// reads and redeems. It returns a root handle on the saas schema for the
// test's own key rows. Both schemas are dropped when the test ends.
func setupMySQLEnrollTest(t *testing.T) (saas *sql.DB) {
	t.Helper()
	return setupMySQLEnrollTestDSN(t, nil)
}

// setupMySQLEnrollTestDSN is setupMySQLEnrollTest with tweak applied to
// the DSN of the farmer handle this package uses, if not nil.
func setupMySQLEnrollTestDSN(t *testing.T, tweak func(*mysql.Config)) (saas *sql.DB) {
	t.Helper()
	cfg := mysqltest.RootConfig(t)
	setupEnrollTest(t)

	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	farmerSchema := "t_pki_enroll_" + hex.EncodeToString(sfx)
	saasSchema := "t_pki_enroll_saas_" + hex.EncodeToString(sfx)
	cfg = cfg.Clone()
	cfg.DBName = ""
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })

	open := func(schema string, set migrations.Set) *sql.DB {
		if _, err := root.Exec("CREATE DATABASE `" + schema + "`"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
		c := cfg.Clone()
		c.DBName, c.ParseTime, c.Loc = schema, true, time.UTC
		sdb, err := sql.Open("mysql", c.FormatDSN())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sdb.Close() })
		if _, err := migrations.Up(context.Background(), sdb, set, t.Logf); err != nil {
			t.Fatal(err)
		}
		return sdb
	}
	saas = open(saasSchema, migrations.Saas)
	open(farmerSchema, migrations.Farmer)

	c := cfg.Clone()
	c.DBName, c.ParseTime, c.Loc = farmerSchema, true, time.UTC
	if tweak != nil {
		tweak(c)
	}
	g, err := gorm.Open(gormmysql.Open(c.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := g.DB(); err == nil {
		// Enough connections that every enrolment runs at once, as the
		// rig's did, rather than queueing for one.
		s.SetMaxOpenConns(128)
		t.Cleanup(func() { s.Close() })
	}
	SetDB(g)
	t.Cleanup(func() { SetDB(nil) })

	origTable, origStore := enrollmentKeysTable, enrollKeyStore
	enrollmentKeysTable = "`" + saasSchema + "`.enrollment_keys"
	enrollKeyStore = mysqlEnrollmentKeyStore{}
	t.Cleanup(func() { enrollmentKeysTable, enrollKeyStore = origTable, origStore })
	return saas
}

// insertMySQLEnrollmentKey adds a join token for tenantID with maxUses
// uses to the saas schema and returns it.
func insertMySQLEnrollmentKey(t *testing.T, saas *sql.DB, keyID, tenantID string, maxUses int) string {
	t.Helper()
	secret := "secret-" + keyID
	if _, err := saas.Exec(
		"INSERT INTO enrollment_keys (key_id, tenant_id, key_hash, expiry, max_uses, used_count, revoked, created_at) VALUES (?, ?, ?, ?, ?, 0, FALSE, ?)",
		keyID, tenantID, hashSecret(secret), time.Now().UTC().Add(time.Hour), maxUses, time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	return keyID + "." + secret
}

// mysqlKeyUses returns keyID's used_count.
func mysqlKeyUses(t *testing.T, saas *sql.DB, keyID string) int {
	t.Helper()
	var n int
	if err := saas.QueryRow("SELECT used_count FROM enrollment_keys WHERE key_id = ?", keyID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// enrollRequestAt is signedEnroll with an explicit timestamp and an error
// rather than a test failure, for use off the test's goroutine.
func enrollRequestAt(kp nkeys.KeyPair, ts int64, joinToken, hostname, sproutPub string) (EnrollRequest, error) {
	pub, err := kp.PublicKey()
	if err != nil {
		return EnrollRequest{}, err
	}
	req := EnrollRequest{JoinToken: joinToken, NKeyPub: pub, Hostname: hostname, SproutPub: sproutPub, Timestamp: ts}
	sig, err := kp.Sign(EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken))
	if err != nil {
		return EnrollRequest{}, err
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	return req, nil
}

// enrollBothSteps runs a sprout's whole first enrolment, as the client
// does: step 1 with joinToken, then step 2 with its box key proof and step
// 1's binding. It returns step 1's result.
func enrollBothSteps(ctx context.Context, kp nkeys.KeyPair, joinToken, hostname string) (*EnrollResult, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nkeyPub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	req, err := enrollRequestAt(kp, ts, joinToken, hostname, b64(pub))
	if err != nil {
		return nil, err
	}
	first, err := Enroll(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("step 1: %w", err)
	}
	proof, err := sealEnrollProof(priv, first.TenantID, first.SproutID, first.TenantX25519Pub, nkeyPub, b64(pub))
	if err != nil {
		return nil, err
	}
	req, err = enrollRequestAt(kp, ts+1, joinToken, hostname, b64(pub))
	if err != nil {
		return nil, err
	}
	req.SproutPubProof, req.EnrollBinding = proof, first.EnrollBinding
	second, err := Enroll(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("step 2: %w", err)
	}
	if second.GatewayJWT == "" || second.SproutID != first.SproutID || second.TenantID != first.TenantID {
		return nil, fmt.Errorf("step 2 answered %+v after step 1's %+v", second, first)
	}
	return first, nil
}

// Many sprouts enrolling in the same instant, across several tenants and
// with the same sprout IDs in each tenant (as the rig's do), all enrol;
// each single-use key is spent exactly once and the shared keys exactly
// once per sprout. Before the enrolment transaction was retried, the
// concurrent first INSERTs into pki_nkeys deadlocked on each other's gap
// locks and the losers' keys were spent without a sprout to show for it.
func TestMySQLEnroll_ConcurrentSproutsAcrossTenants(t *testing.T) {
	saas := setupMySQLEnrollTest(t)

	const (
		tenants          = 5
		sproutsPerTenant = 12 // 60 sprouts in all
	)
	type sprout struct {
		tenant, host, keyID, token string
		kp                         nkeys.KeyPair
	}
	var sprouts []sprout
	sharedKeys := map[string]int{}
	for ti := range tenants {
		tenant := fmt.Sprintf("t_conc%02d", ti)
		// Tenants 0-2 give every sprout a single-use key of its own, as
		// the rig does; tenants 3 and 4 share one key among their sprouts.
		shared := ti >= 3
		var sharedKey, sharedToken string
		if shared {
			sharedKey = fmt.Sprintf("ek_shared%02d", ti)
			sharedToken = insertMySQLEnrollmentKey(t, saas, sharedKey, tenant, sproutsPerTenant)
			sharedKeys[sharedKey] = sproutsPerTenant
		}
		for si := range sproutsPerTenant {
			s := sprout{tenant: tenant, host: fmt.Sprintf("sprout-%02d", si), kp: testEnrollNKey(t)}
			if shared {
				s.keyID, s.token = sharedKey, sharedToken
			} else {
				s.keyID = fmt.Sprintf("ek_c%02d_%02d", ti, si)
				s.token = insertMySQLEnrollmentKey(t, saas, s.keyID, tenant, 1)
			}
			sprouts = append(sprouts, s)
		}
	}

	start := make(chan struct{})
	errs := make([]error, len(sprouts))
	results := make([]*EnrollResult, len(sprouts))
	var wg sync.WaitGroup
	for i, s := range sprouts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = enrollBothSteps(t.Context(), s.kp, s.token, s.host)
		}()
	}
	close(start)
	wg.Wait()

	failed := 0
	for i, s := range sprouts {
		if errs[i] != nil {
			failed++
			t.Errorf("sprout %s in tenant %s (key %s): %v", s.host, s.tenant, s.keyID, errs[i])
			continue
		}
		if results[i].TenantID != s.tenant || results[i].SproutID != s.host {
			t.Errorf("sprout %s in tenant %s enrolled as %s in tenant %s", s.host, s.tenant, results[i].SproutID, results[i].TenantID)
		}
		gotTenant, gotID, err := SproutIDAndTenantForNKey(testNKeyPub(t, s.kp))
		if err != nil || gotTenant != s.tenant || gotID != s.host {
			t.Errorf("sprout %s in tenant %s: accepted as %s in %s (%v)", s.host, s.tenant, gotID, gotTenant, err)
		}
		if !hasActiveBoxKey(t, s.tenant, s.host) {
			t.Errorf("sprout %s in tenant %s has no active box key", s.host, s.tenant)
		}
		if _, shared := sharedKeys[s.keyID]; !shared {
			if n := mysqlKeyUses(t, saas, s.keyID); n != 1 {
				t.Errorf("single-use key %s used %d times, want 1", s.keyID, n)
			}
		}
	}
	for keyID, want := range sharedKeys {
		if n := mysqlKeyUses(t, saas, keyID); n != want {
			t.Errorf("shared key %s used %d times, want %d", keyID, n, want)
		}
	}
	if failed > 0 {
		t.Errorf("%d of %d concurrent enrolments failed", failed, len(sprouts))
	}
}
