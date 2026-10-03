package pki

// PKI.1: deterministic interleaving tests for the provision/deprovision
// race (FLAG FOR SECURITY REVIEW). A copy of a provision request
// re-published by saasapi's outbox sweeper can run on one farmer replica
// while a deprovision of the same tenant runs on another. Every test here
// drives one interleaving to completion through the test hooks in
// tenant.go (channels, no sleeps) against a real embedded bus with a full
// resolver, then checks what the bus actually enforces: the Account JWT
// its resolver holds is a lockout, and the tenant's sprout can't connect.
//
// The in-process tests share one tenantAuthMu; TestProvisionDeprovisionRace_TwoProcesses
// runs the provision in a second process (this test binary re-executed),
// with its own tenantAuthMu, sharing only the database and the bus, as two
// replicas do.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
)

// raceTenant is a provisioned tenant with one accepted, connectable
// sprout, on a running test bus.
type raceTenant struct {
	id         string
	sproutJWT  string
	sproutSeed []byte
}

// setupRaceTenant provisions tenantID with an accepted sprout on the
// running test bus and checks that the sprout can connect. The caller has
// already run setupTestPKI (or its file-backed variant), useRealFarmerKey
// and startTestBus.
func setupRaceTenant(t *testing.T, tenantID string) raceTenant {
	t.Helper()
	if err := ProvisionTenant(tenantID, "Race Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	kp, _ := nkeys.CreateUser()
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: pub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant(tenantID); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	sproutJWT, err := GetSproutUserJWTForTenant(tenantID, "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}
	nc, err := dialAsSprout(t, sproutJWT, seed)
	if err != nil {
		t.Fatalf("expected the sprout to connect before the race: %v", err)
	}
	nc.Close()
	return raceTenant{id: tenantID, sproutJWT: sproutJWT, sproutSeed: seed}
}

// startRaceBus is the common setup: in-memory database, test PKI, a real
// farmer NKey and a running bus. It also clears every hook afterwards.
func startRaceBus(t *testing.T) {
	t.Helper()
	setupTestPKI(t)
	// newTestDB's named in-memory database outlives the test unless its
	// last connection closes; close it so -count=N starts clean.
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { sqlDB.Close() })
	}
	useRealFarmerKey(t)
	startTestBus(t)
	resetRaceHooks(t)
}

func resetRaceHooks(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		testHookBeforeLivePush = nil
		testHookAfterLivePush = nil
		testHookDeprovisionBeforePush = nil
		tenantDeprovisionedHook = nil
		tenantProvisionedHook = nil
	})
}

// claimsLookupSubject is answered by the full resolver with the Account
// JWT it holds.
const claimsLookupSubject = "$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP"

// isLockedOut reports whether ac carries lockOutAccount's lockout.
func isLockedOut(ac *jwt.AccountClaims) bool {
	return ac.Limits.Conn == 0 && ac.Revocations[jwt.All] > 0
}

// busAccountClaims returns the Account JWT the bus's resolver holds for
// tenantID, decoded.
func busAccountClaims(t *testing.T, tenantID string) *jwt.AccountClaims {
	t.Helper()
	row, err := getTenantRow(tenantID)
	if err != nil || row.AccountPub == "" {
		t.Fatalf("tenant %q has no recorded Account pubkey: row=%+v err=%v", tenantID, row, err)
	}
	nc, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	defer nc.Close()
	resp, err := nc.Request(fmt.Sprintf(claimsLookupSubject, row.AccountPub), nil, 5*time.Second)
	if err != nil {
		t.Fatalf("claims lookup: %v", err)
	}
	ac, err := jwt.DecodeAccountClaims(string(resp.Data))
	if err != nil {
		t.Fatalf("decoding the bus's Account JWT for %q (%q): %v", tenantID, resp.Data, err)
	}
	return ac
}

// assertBusLockedOut checks what the bus enforces for a deleted tenant: its
// resolver holds a locked-out Account JWT, the tenant's sprout is refused,
// and the database row is deleted.
func assertBusLockedOut(t *testing.T, rt raceTenant) {
	t.Helper()
	if ac := busAccountClaims(t, rt.id); !isLockedOut(ac) {
		t.Fatalf("the bus holds a live Account JWT for deprovisioned tenant %q (conn limit %d, revoked-at %d)",
			rt.id, ac.Limits.Conn, ac.Revocations[jwt.All])
	}
	if nc, err := dialAsSprout(t, rt.sproutJWT, rt.sproutSeed); err == nil {
		nc.Close()
		t.Fatalf("the sprout of deprovisioned tenant %q can still connect", rt.id)
	}
	row, err := getTenantRow(rt.id)
	if err != nil || !row.Deleted {
		t.Fatalf("tenant %q row = %+v, err %v; want deleted", rt.id, row, err)
	}
}

// pauseAt returns a hook for one tenant that, on its first call, signals
// reached and then blocks until release is closed.
func pauseAt(tenantID string) (hook func(string), reached, release chan struct{}) {
	reached = make(chan struct{})
	release = make(chan struct{})
	var once sync.Once
	hook = func(id string) {
		if id != tenantID {
			return
		}
		once.Do(func() {
			close(reached)
			<-release
		})
	}
	return hook, reached, release
}

// addDeniedSprout records a denied sprout, so the next sync adds a
// revocation and re-signs the Account JWT instead of pushing the copy on
// disk: the live JWT a racing provision pushes is then signed during the
// race, the case that can win on iat. It also makes ReloadNKeysForTenant
// push at all.
func addDeniedSprout(t *testing.T, tenantID, sproutID string) {
	t.Helper()
	kp, _ := nkeys.CreateUser()
	pub, _ := kp.PublicKey()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: pub, State: stateDenied}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
}

// await fails the test instead of hanging if a hook never fires.
func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Provision first: a late copy has passed its deleted check and is about
// to push its live JWT when a deprovision runs to completion. Its push
// then lands after the lockout (on a tie in iat the bus keeps it), and
// only the post-push re-check puts the lockout back.
func TestProvisionDeprovisionRace_LivePushAfterLockout(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_race_before_push")
	addDeniedSprout(t, rt.id, "web-02")

	hook, reached, release := pauseAt(rt.id)
	testHookBeforeLivePush = hook
	provErr := make(chan error, 1)
	go func() { provErr <- ProvisionTenant(rt.id, "Race Co") }()
	await(t, reached, "the paused push")

	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	close(release)
	if err := <-provErr; !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("ProvisionTenant = %v, want ErrTenantDeprovisioned", err)
	}
	assertBusLockedOut(t, rt)

	// The provision re-signed the on-disk JWT live during the race; the
	// re-check must have written the lockout back over it too.
	b, err := os.ReadFile(tenantAccountJWTPath(rt.id))
	if err != nil {
		t.Fatal(err)
	}
	if ac, err := jwt.DecodeAccountClaims(string(b)); err != nil || !isLockedOut(ac) {
		t.Fatalf("on-disk Account JWT is not locked out (err %v)", err)
	}
}

// Provision first, the live JWT already on the bus: the deprovision's
// lockout lands after it, and the late copy's re-check sees the row deleted
// and pushes a fresh lockout.
func TestProvisionDeprovisionRace_DeprovisionAfterLivePush(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_race_after_push")
	addDeniedSprout(t, rt.id, "web-02")

	hook, reached, release := pauseAt(rt.id)
	testHookAfterLivePush = hook
	provErr := make(chan error, 1)
	go func() { provErr <- ProvisionTenant(rt.id, "Race Co") }()
	await(t, reached, "the paused push")

	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	close(release)
	if err := <-provErr; !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("ProvisionTenant = %v, want ErrTenantDeprovisioned", err)
	}
	assertBusLockedOut(t, rt)
}

// Both paused before their pushes: the provision has passed its check, the
// deprovision has marked the row and signed its lockout. The provision
// pushes live, re-checks, and pushes a newer lockout; the deprovision's
// older lockout is then dropped by the resolver, and its read-back must
// accept the newer lockout it finds instead.
func TestProvisionDeprovisionRace_BothPausedBeforePush(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_race_both")
	addDeniedSprout(t, rt.id, "web-02")

	provHook, provReached, provRelease := pauseAt(rt.id)
	testHookBeforeLivePush = provHook
	provErr := make(chan error, 1)
	go func() { provErr <- ProvisionTenant(rt.id, "Race Co") }()
	await(t, provReached, "the paused provision")

	depHook, depReached, depRelease := pauseAt(rt.id)
	testHookDeprovisionBeforePush = depHook
	depErr := make(chan error, 1)
	go func() { depErr <- DeprovisionTenant(rt.id) }()
	await(t, depReached, "the paused deprovision")

	close(provRelease)
	if err := <-provErr; !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("ProvisionTenant = %v, want ErrTenantDeprovisioned", err)
	}
	close(depRelease)
	if err := <-depErr; err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	assertBusLockedOut(t, rt)
}

// Deprovision first, paused before its push: the row is already deleted,
// so a provision arriving now is refused before it pushes anything.
func TestProvisionDeprovisionRace_ProvisionDuringDeprovision(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_race_dep_first")

	depHook, depReached, depRelease := pauseAt(rt.id)
	testHookDeprovisionBeforePush = depHook
	depErr := make(chan error, 1)
	go func() { depErr <- DeprovisionTenant(rt.id) }()
	await(t, depReached, "the paused deprovision")

	pushed := false
	testHookBeforeLivePush = func(string) { pushed = true }
	if err := ProvisionTenant(rt.id, "Race Co"); !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("ProvisionTenant = %v, want ErrTenantDeprovisioned", err)
	}
	if pushed {
		t.Fatal("ProvisionTenant pushed a live JWT for a tenant already marked deleted")
	}
	close(depRelease)
	if err := <-depErr; err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	assertBusLockedOut(t, rt)
}

// Deprovision first, completed: a late provision copy is refused and the
// bus stays locked out.
func TestProvisionDeprovisionRace_ProvisionAfterDeprovision(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_race_late_copy")

	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	if err := ProvisionTenant(rt.id, "Race Co"); !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("ProvisionTenant = %v, want ErrTenantDeprovisioned", err)
	}
	assertBusLockedOut(t, rt)
}

// The enrollment path pushes a live JWT the same way (ReloadNKeysForTenant)
// and gets the same re-check.
func TestProvisionDeprovisionRace_EnrollmentReload(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_race_enroll")
	addDeniedSprout(t, rt.id, "web-02")

	hook, reached, release := pauseAt(rt.id)
	testHookBeforeLivePush = hook
	reloadErr := make(chan error, 1)
	go func() { reloadErr <- ReloadNKeysForTenant(rt.id) }()
	await(t, reached, "the paused push")

	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	close(release)
	if err := <-reloadErr; !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("ReloadNKeysForTenant = %v, want ErrTenantDeprovisioned", err)
	}
	assertBusLockedOut(t, rt)
}

// A deprovision that crashed after marking the row but before its push
// leaves the bus live; the retry must push the lockout rather than return
// early because the row is already deleted.
func TestDeprovisionTenant_RetryAfterCrashBeforePush(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_retry_crash")

	if err := markTenantDeleted(rt.id); err != nil {
		t.Fatalf("markTenantDeleted: %v", err)
	}
	if nc, err := dialAsSprout(t, rt.sproutJWT, rt.sproutSeed); err != nil {
		t.Fatalf("precondition: the bus should still be live after the simulated crash: %v", err)
	} else {
		nc.Close()
	}

	hookCalls := make(chan string, 1)
	tenantDeprovisionedHook = func(id string) { hookCalls <- id }
	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("retried DeprovisionTenant: %v", err)
	}
	assertBusLockedOut(t, rt)
	if got := <-hookCalls; got != rt.id {
		t.Fatalf("deprovisioned hook fired for %q, want %q", got, rt.id)
	}
}

// A retried deprovision of an already deleted tenant whose bus holds a
// live JWT again (what a late provision copy left before this fix) repairs
// the bus.
func TestDeprovisionTenant_RetryRepairsLiveBus(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_retry_repair")
	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}

	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	pushLiveJWT(t, mat, rt.id, 0)
	if ac := busAccountClaims(t, rt.id); isLockedOut(ac) {
		t.Fatal("precondition: expected the bus to hold the live JWT")
	}

	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("retried DeprovisionTenant: %v", err)
	}
	assertBusLockedOut(t, rt)
}

// pushLiveJWT signs a live Account JWT for tenantID (lockout removed) and
// pushes it. iat 0 lets the jwt library stamp the current time; any other
// value is used as the iat.
func pushLiveJWT(t *testing.T, mat *natsAuthMaterial, tenantID string, iat int64) {
	t.Helper()
	tam, err := loadTenantAccountMaterial(tenantID)
	if err != nil {
		t.Fatalf("loadTenantAccountMaterial: %v", err)
	}
	ac, err := jwt.DecodeAccountClaims(tam.jwt)
	if err != nil {
		t.Fatal(err)
	}
	ac.Limits.Conn = jwt.NoLimit
	ac.Limits.LeafNodeConn = jwt.NoLimit
	ac.Revocations = nil
	var signed string
	if iat == 0 {
		signed, err = ac.Encode(mat.operatorSigningKP)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		signed = encodeAccountClaimsAt(t, ac, mat.operatorSigningKP, iat)
	}
	if err := pushAccountUpdate(mat, signed); err != nil {
		t.Fatalf("pushing the live JWT: %v", err)
	}
}

// encodeAccountClaimsAt signs ac the way jwt.Encode does but with a chosen
// iat, which jwt.Encode always sets to the current time.
func encodeAccountClaimsAt(t *testing.T, ac *jwt.AccountClaims, kp nkeys.KeyPair, iat int64) string {
	t.Helper()
	issuer, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ac.Issuer = issuer
	ac.IssuedAt = iat
	ac.ID = fmt.Sprintf("SKEWED%d", iat)
	header, _ := json.Marshal(jwt.Header{Type: jwt.TokenTypeJwt, Algorithm: jwt.AlgorithmNkey})
	payload, err := json.Marshal(ac)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	toSign := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	sig, err := kp.Sign([]byte(toSign))
	if err != nil {
		t.Fatal(err)
	}
	signed := toSign + "." + enc.EncodeToString(sig)
	if back, err := jwt.DecodeAccountClaims(signed); err != nil || back.IssuedAt != iat {
		t.Fatalf("hand-signed JWT does not decode back (iat %v): %v", back, err)
	}
	return signed
}

// pushLiveTenantAccount's ordering argument rests on the full resolver
// applying claims pushes in arrival order, whatever their iat. If a
// nats-server upgrade made pushes keep the later iat instead (as its
// re-seeding and cluster sync already do), a late live push could be
// dropped or kept depending on clocks, and the argument would need
// revisiting: this test fails first.
func TestResolverPush_LastArrivalWins(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_last_arrival")
	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	lockout := busAccountClaims(t, rt.id)
	if !isLockedOut(lockout) {
		t.Fatal("precondition: expected the lockout on the bus")
	}
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	older := lockout.IssuedAt - 60
	pushLiveJWT(t, mat, rt.id, older)
	if got := busAccountClaims(t, rt.id); isLockedOut(got) || got.IssuedAt != older {
		t.Fatalf("the bus kept the newer lockout over a later push with an older iat (held iat %d, locked out %v); "+
			"pushes no longer apply in arrival order, revisit pushLiveTenantAccount", got.IssuedAt, isLockedOut(got))
	}
}

// --- Two processes, one database --------------------------------------------

const raceHelperEnv = "IMAS_PKI_RACE_HELPER"

// newFileTestDB is newTestDB on a sqlite file another process can open
// too.
func newFileTestDB(t *testing.T, path string) {
	t.Helper()
	gdb := openFileDB(path)
	if gdb == nil {
		t.Fatalf("opening %s", path)
	}
	if err := gdb.AutoMigrate(Models()...); err != nil {
		t.Fatalf("migrating test db: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
		SetDB(nil)
	})
}

func openFileDB(path string) *gorm.DB {
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil
	}
	return gdb
}

// TestProvisionDeprovisionRace_TwoProcesses runs the late provision copy in
// a second process (this test binary, re-executed as
// TestRaceReplicaHelper), the way it runs on another farmer replica: its
// own tenantAuthMu, sharing only the database and the bus. "shared" gives
// both processes one PKI directory; "copied" gives the second process its
// own copy (same keys, separate account.jwt files), as replicas with
// externally supplied seeds and their own volumes would have.
func TestProvisionDeprovisionRace_TwoProcesses(t *testing.T) {
	for _, pause := range []string{"before", "after"} {
		for _, disk := range []string{"shared", "copied"} {
			t.Run(pause+"_push_"+disk+"_disk", func(t *testing.T) {
				runTwoProcessRace(t, pause, disk)
			})
		}
	}
}

func runTwoProcessRace(t *testing.T, pause, disk string) {
	setupTestPKI(t)
	dbPath := filepath.Join(t.TempDir(), "farmer.db")
	newFileTestDB(t, dbPath)
	useRealFarmerKey(t)
	startTestBus(t)
	resetRaceHooks(t)

	rt := setupRaceTenant(t, "t_two_procs")
	addDeniedSprout(t, rt.id, "web-02")

	childPKI := config.FarmerPKI
	if disk == "copied" {
		childPKI = filepath.Join(t.TempDir(), "pki") + "/"
		copyDir(t, config.FarmerPKI, childPKI)
	}

	toChildR, toChildW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fromChildR, fromChildW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRaceReplicaHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		raceHelperEnv+"=1",
		"RACE_PAUSE="+pause,
		"RACE_TENANT="+rt.id,
		"RACE_DB="+dbPath,
		"RACE_PKI="+childPKI,
		"RACE_FARMER_PUB="+config.NKeyFarmerPubFile,
		"RACE_ROOTCA="+config.RootCA,
		"RACE_BUS_URL="+config.FarmerBusURL,
		"RACE_ORG="+config.FarmerOrganization,
	)
	cmd.ExtraFiles = []*os.File{toChildR, fromChildW} // fd 3, fd 4
	var childOut strings.Builder
	cmd.Stdout = &childOut
	cmd.Stderr = &childOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the second replica: %v", err)
	}
	toChildR.Close()
	fromChildW.Close()
	defer func() {
		toChildW.Close()
		_ = cmd.Wait()
	}()

	lines := bufio.NewScanner(fromChildR)
	if !lines.Scan() || lines.Text() != "PAUSED" {
		t.Fatalf("second replica did not pause (got %q); output:\n%s", lines.Text(), childOut.String())
	}

	// This process is the deprovisioning replica.
	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	if _, err := io.WriteString(toChildW, "GO\n"); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() {
		t.Fatalf("no result from the second replica; output:\n%s", childOut.String())
	}
	if got := lines.Text(); got != "RESULT deprovisioned" {
		t.Fatalf("second replica's ProvisionTenant: %s; output:\n%s", got, childOut.String())
	}
	toChildW.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("second replica exited with %v; output:\n%s", err, childOut.String())
	}
	assertBusLockedOut(t, rt)
}

// TestRaceReplicaHelper is the second replica for
// TestProvisionDeprovisionRace_TwoProcesses; it does nothing unless run by
// it. It runs ProvisionTenant, pausing at the hook named by RACE_PAUSE
// until the parent has deprovisioned the tenant, and reports the outcome.
func TestRaceReplicaHelper(t *testing.T) {
	if os.Getenv(raceHelperEnv) != "1" {
		t.Skip("run only by TestProvisionDeprovisionRace_TwoProcesses")
	}
	fromParent := bufio.NewReader(os.NewFile(3, "from-parent"))
	toParent := os.NewFile(4, "to-parent")

	config.FarmerPKI = os.Getenv("RACE_PKI")
	config.NKeyFarmerPubFile = os.Getenv("RACE_FARMER_PUB")
	config.RootCA = os.Getenv("RACE_ROOTCA")
	config.FarmerBusURL = os.Getenv("RACE_BUS_URL")
	config.FarmerOrganization = os.Getenv("RACE_ORG")
	NatsServer = nil
	gdb := openFileDB(os.Getenv("RACE_DB"))
	if gdb == nil {
		t.Fatal("opening the shared database")
	}
	SetDB(gdb)
	tenantID := os.Getenv("RACE_TENANT")

	pauseHook := func(id string) {
		if id != tenantID {
			return
		}
		fmt.Fprintln(toParent, "PAUSED")
		if _, err := fromParent.ReadString('\n'); err != nil {
			t.Errorf("waiting for the parent: %v", err)
		}
	}
	switch os.Getenv("RACE_PAUSE") {
	case "before":
		testHookBeforeLivePush = pauseHook
	case "after":
		testHookAfterLivePush = pauseHook
	default:
		t.Fatalf("unknown RACE_PAUSE %q", os.Getenv("RACE_PAUSE"))
	}

	err := ProvisionTenant(tenantID, "Race Co")
	switch {
	case errors.Is(err, ErrTenantDeprovisioned):
		fmt.Fprintln(toParent, "RESULT deprovisioned")
	case err == nil:
		fmt.Fprintln(toParent, "RESULT nil")
	default:
		fmt.Fprintln(toParent, "RESULT error: "+strings.ReplaceAll(err.Error(), "\n", " "))
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatalf("copying %s to %s: %v", src, dst, err)
	}
}
