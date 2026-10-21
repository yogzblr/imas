package pki

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	jwt "github.com/nats-io/jwt/v2"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// E3 (P27.2): farmer keeps no JWT or key file, so two replicas share
// everything through PXC, Transit, the accounts bucket and the sprout JWT
// bucket. TestTwoReplicasShareMintsAndRevocations runs replica B as a
// second process (this test binary, re-executed as
// TestReplicaBHelper) with its own temp directory, against the same
// database file, buckets, Transit and bus as replica A (this process):
//
//  1. A provisions the tenant and mints sprout s1's User JWT.
//  2. B serves A's s1 JWT as is, mints s2's, and denies s1 (a re-sign of
//     the tenant's Account JWT on B). B is then killed.
//  3. A serves B's s2 JWT as is; its next re-sign (accepting the pending
//     s3, which clears s3's revocation and re-derives nothing else)
//     starts from B's Account JWT in the bucket, not from the older one A
//     holds, so s1 stays revoked; and a restart of A (holding nothing)
//     still finds everything.
//
// On the bus, s1 is refused and s2 and s3 connect. Neither process
// writes anything under its PKI directory.
func TestTwoReplicasShareMintsAndRevocations(t *testing.T) {
	setupTestPKI(t)
	dbPath := filepath.Join(t.TempDir(), "farmer.db")
	newFileTestDB(t, dbPath)
	useRealFarmerKey(t)
	accounts := objectstoretest.NewServer(t)
	sproutJWTs := objectstoretest.NewServer(t)
	useReplicaBuckets(t, accounts.Config(), sproutJWTs.Config())
	defer startTestBus(t)()

	const tenant = "t_replicas"
	if err := ProvisionTenant(tenant, "Replicas Co"); err != nil {
		t.Fatalf("A: ProvisionTenant: %v", err)
	}
	s1Pub, s1Seed := newUserNKey(t)
	s2Pub, s2Seed := newUserNKey(t)
	s3Pub, s3Seed := newUserNKey(t)
	if err := acceptEnrolledNKey(tenant, "s1", s1Pub); err != nil {
		t.Fatalf("A: accepting s1: %v", err)
	}
	s1JWT, err := MintOrReuseUserJWT(t.Context(), tenant, "s1", s1Pub)
	if err != nil {
		t.Fatalf("A: minting s1: %v", err)
	}
	// s3 is pending on A: its key is revoked on the Account until it is
	// accepted, which A's re-sign in step 3 clears.
	if err := UnacceptNKey(tenant, "s3", s3Pub); err != nil {
		t.Fatalf("A: s3 pending: %v", err)
	}

	accountsCfg, _ := json.Marshal(accounts.Config())
	sproutCfg, _ := json.Marshal(sproutJWTs.Config())
	childPKI := filepath.Join(t.TempDir(), "pki") + "/"
	toChildR, toChildW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fromChildR, fromChildW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplicaBHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		replicaHelperEnv+"=1",
		"REPLICA_TENANT="+tenant,
		"REPLICA_DB="+dbPath,
		"REPLICA_PKI="+childPKI,
		"REPLICA_ACCOUNTS="+string(accountsCfg),
		"REPLICA_SPROUT_JWTS="+string(sproutCfg),
		"REPLICA_S1="+s1Pub,
		"REPLICA_S2="+s2Pub,
		"REPLICA_FARMER_PUB="+config.NKeyFarmerPubFile,
		"REPLICA_ROOTCA="+config.RootCA,
		"REPLICA_BUS_URL="+config.FarmerBusURL,
		"REPLICA_ORG="+config.FarmerOrganization,
	)
	cmd.ExtraFiles = []*os.File{toChildR, fromChildW} // fd 3, fd 4
	var childOut strings.Builder
	cmd.Stdout = &childOut
	cmd.Stderr = &childOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting replica B: %v", err)
	}
	toChildR.Close()
	fromChildW.Close()
	defer toChildW.Close()

	lines := bufio.NewScanner(fromChildR)
	lines.Buffer(make([]byte, 64<<10), 64<<10)
	read := func(prefix string) string {
		t.Helper()
		if !lines.Scan() {
			t.Fatalf("replica B said nothing (want %s); output:\n%s", prefix, childOut.String())
		}
		if lines.Text() == prefix {
			return ""
		}
		got, ok := strings.CutPrefix(lines.Text(), prefix+" ")
		if !ok {
			t.Fatalf("replica B: %s (want %s); output:\n%s", lines.Text(), prefix, childOut.String())
		}
		return got
	}
	if got := read("S1"); got != s1JWT {
		t.Errorf("replica B served a different s1 JWT than replica A minted")
	}
	s2JWT := read("S2")
	read("DONE")
	// Killed, not stopped: whatever B held in memory is gone.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	got, err := MintOrReuseUserJWT(t.Context(), tenant, "s2", s2Pub)
	if err != nil {
		t.Fatalf("A: serving s2: %v", err)
	}
	if got != s2JWT {
		t.Error("replica A served a different s2 JWT than replica B minted")
	}
	// A's re-sign lands in a later second than B's, so it outranks B's in
	// the bucket: only building on B's keeps s1 revoked.
	fromB, err := bucketAccountJWT(t.Context(), tenantAccountPub(t, tenant))
	if err != nil || fromB == "" {
		t.Fatalf("no Account JWT from replica B in the bucket (err %v)", err)
	}
	if ac, err := jwt.DecodeAccountClaims(fromB); err == nil {
		waitPastIssuedAt(ac.IssuedAt)
	}
	if err := acceptEnrolledNKey(tenant, "s3", s3Pub); err != nil {
		t.Fatalf("A: accepting s3: %v", err)
	}
	s3JWT, err := MintOrReuseUserJWT(t.Context(), tenant, "s3", s3Pub)
	if err != nil {
		t.Fatalf("A: minting s3: %v", err)
	}

	checkAccount := func(when string) {
		t.Helper()
		pub := tenantAccountPub(t, tenant)
		inBucket, err := bucketAccountJWT(t.Context(), pub)
		if err != nil || inBucket == "" {
			t.Fatalf("%s: no Account JWT in the accounts bucket (err %v)", when, err)
		}
		ac, err := jwt.DecodeAccountClaims(inBucket)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ac.Revocations[s1Pub]; !ok {
			t.Errorf("%s: s1, denied on replica B, is not revoked", when)
		}
		for name, k := range map[string]string{"s2": s2Pub, "s3": s3Pub} {
			if _, ok := ac.Revocations[k]; ok {
				t.Errorf("%s: %s is revoked", when, name)
			}
		}
	}
	checkAccount("after A's re-sign")

	if nc, err := dialAsSprout(t, s1JWT, s1Seed); err == nil {
		nc.Close()
		t.Error("s1, denied on replica B, still connects")
	}
	for name, c := range map[string]struct {
		jwt  string
		seed []byte
	}{"s2": {s2JWT, s2Seed}, "s3": {s3JWT, s3Seed}} {
		nc, err := dialAsSprout(t, c.jwt, c.seed)
		if err != nil {
			t.Errorf("%s does not connect: %v", name, err)
			continue
		}
		nc.Close()
	}

	// A restart of A: nothing held, nothing on disk. The buckets and PXC
	// still give everything back.
	forgetHeldJWTs()
	if got, err := MintOrReuseUserJWT(t.Context(), tenant, "s2", s2Pub); err != nil || got != s2JWT {
		t.Errorf("restarted A: serving s2 = %v, want B's JWT", err)
	}
	if _, err := FarmerUserJWTForTenant(tenant); err != nil {
		t.Errorf("restarted A: FarmerUserJWTForTenant: %v", err)
	}
	if err := ReloadNKeysForTenant(tenant); err != nil {
		t.Errorf("restarted A: ReloadNKeysForTenant: %v", err)
	}
	checkAccount("after A's restart")
	if _, err := os.Stat(childPKI); !os.IsNotExist(err) {
		t.Errorf("replica B wrote under its PKI directory %s", childPKI)
	}
}

// useReplicaBuckets installs the accounts bucket (as the AccountPublisher)
// and the sprout JWT bucket over the fake S3 servers' configs.
func useReplicaBuckets(t testing.TB, accounts, sproutJWTs objectstore.Config) {
	t.Helper()
	as, err := objectstore.Open(accounts)
	if err != nil {
		t.Fatalf("opening the accounts bucket: %v", err)
	}
	p, err := NewAccountPublisher(as, "")
	if err != nil {
		t.Fatalf("NewAccountPublisher: %v", err)
	}
	// A background announce retry ends with the test.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.(*s3AccountPublisher).announceStop = ctx
	SetAccountPublisher(p)
	t.Cleanup(func() { SetAccountPublisher(nil) })
	ss, err := objectstore.Open(sproutJWTs)
	if err != nil {
		t.Fatalf("opening the sprout JWT bucket: %v", err)
	}
	SetSproutJWTStore(ss)
	t.Cleanup(func() { SetSproutJWTStore(nil) })
}

const replicaHelperEnv = "IMAS_PKI_REPLICA_HELPER"

// TestReplicaBHelper is replica B of TestTwoReplicasShareMintsAndRevocations;
// it does nothing unless run by it. It reports on fd 4 and waits on fd 3
// to be killed.
func TestReplicaBHelper(t *testing.T) {
	if os.Getenv(replicaHelperEnv) != "1" {
		t.Skip("run only by TestTwoReplicasShareMintsAndRevocations")
	}
	fromParent := os.NewFile(3, "from-parent")
	toParent := os.NewFile(4, "to-parent")
	fail := func(format string, args ...any) {
		fmt.Fprintln(toParent, "ERROR "+strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " "))
		t.FailNow()
	}

	config.FarmerPKI = os.Getenv("REPLICA_PKI")
	config.NKeyFarmerPubFile = os.Getenv("REPLICA_FARMER_PUB")
	config.RootCA = os.Getenv("REPLICA_ROOTCA")
	config.FarmerBusURL = os.Getenv("REPLICA_BUS_URL")
	config.FarmerOrganization = os.Getenv("REPLICA_ORG")
	NatsServer = nil
	gdb := openFileDB(os.Getenv("REPLICA_DB"))
	if gdb == nil {
		fail("opening the shared database")
	}
	SetDB(gdb)
	var accounts, sproutJWTs objectstore.Config
	if err := json.Unmarshal([]byte(os.Getenv("REPLICA_ACCOUNTS")), &accounts); err != nil {
		fail("accounts bucket config: %v", err)
	}
	if err := json.Unmarshal([]byte(os.Getenv("REPLICA_SPROUT_JWTS")), &sproutJWTs); err != nil {
		fail("sprout JWT bucket config: %v", err)
	}
	useReplicaBuckets(t, accounts, sproutJWTs)
	tenant := os.Getenv("REPLICA_TENANT")

	s1, err := MintOrReuseUserJWT(t.Context(), tenant, "s1", os.Getenv("REPLICA_S1"))
	if err != nil {
		fail("serving s1: %v", err)
	}
	fmt.Fprintln(toParent, "S1 "+s1)
	if err := acceptEnrolledNKey(tenant, "s2", os.Getenv("REPLICA_S2")); err != nil {
		fail("accepting s2: %v", err)
	}
	s2, err := MintOrReuseUserJWT(t.Context(), tenant, "s2", os.Getenv("REPLICA_S2"))
	if err != nil {
		fail("minting s2: %v", err)
	}
	fmt.Fprintln(toParent, "S2 "+s2)
	if err := DenyNKey(tenant, "s1"); err != nil {
		fail("denying s1: %v", err)
	}
	if _, err := os.Stat(config.FarmerPKI); !os.IsNotExist(err) {
		fail("replica B wrote under %s", config.FarmerPKI)
	}
	fmt.Fprintln(toParent, "DONE")
	_, _ = io.Copy(io.Discard, fromParent) // until killed
}
