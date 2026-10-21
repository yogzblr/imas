package heartbeat

// The CONNECT/DISCONNECT race (P12, owner decision T3: a DISCONNECT may
// only remove the presence of the connection it belongs to), run against
// every Valkey this package can face: an in-process miniredis, a real
// standalone Valkey and a real Valkey Cluster of three shards. The real
// ones come from the environment (realValkey); CI sets both from service
// containers (.github/workflows/ci.yml).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/pki"
)

// The environment variables naming the real Valkey servers. The standalone
// one is the server internal/saasapi and internal/valkeyconn already test
// against. requireValkeyEnv, set to 1 by CI, turns a missing address into
// a failure: only a local run without Docker may report "not configured".
const (
	standaloneValkeyEnv = "SAASAPI_TEST_VALKEY_ADDR"
	clusterValkeyEnv    = "IMAS_TEST_VALKEY_CLUSTER_ADDR"
	requireValkeyEnv    = "IMAS_REQUIRE_VALKEY"
)

// realValkey connects to the server env names, or ends the (sub)test as
// not configured when env is unset, a failure when requireValkeyEnv is 1.
func realValkey(t *testing.T, env string) valkey.Client {
	t.Helper()
	addr := os.Getenv(env)
	if addr == "" {
		if os.Getenv(requireValkeyEnv) == "1" {
			t.Fatalf("%s is not set (%s=1: the real Valkey tests must run, not skip)", env, requireValkeyEnv)
		}
		t.Skipf("not configured: set %s to a Valkey address to run this against a real server", env)
	}
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: strings.Split(addr, ","), DisableCache: true})
	if err != nil {
		t.Fatalf("connecting to the Valkey at %s (%s): %v", addr, env, err)
	}
	t.Cleanup(c.Close)
	return c
}

// backend is one kind of Valkey the tests run against.
type backend struct {
	name    string
	cluster bool
	open    func(t *testing.T) valkey.Client
}

var backends = []backend{
	{name: "miniredis", open: func(t *testing.T) valkey.Client {
		mr := miniredis.RunT(t)
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}},
	{name: "valkey", open: func(t *testing.T) valkey.Client { return realValkey(t, standaloneValkeyEnv) }},
	{name: "valkey-cluster", cluster: true, open: func(t *testing.T) valkey.Client {
		c := realValkey(t, clusterValkeyEnv)
		requireThreeShardCluster(t, c)
		return c
	}},
}

// requireThreeShardCluster fails unless c is a healthy Valkey Cluster of
// three shards, so the cluster test cannot pass against a standalone
// server by mistake.
func requireThreeShardCluster(t *testing.T, c valkey.Client) {
	t.Helper()
	info, err := c.Do(context.Background(), c.B().ClusterInfo().Build()).ToString()
	if err != nil {
		t.Fatalf("CLUSTER INFO: %v", err)
	}
	for _, want := range []string{"cluster_state:ok", "cluster_size:3"} {
		if !strings.Contains(info, want) {
			t.Fatalf("not a healthy 3-shard Valkey Cluster: CLUSTER INFO lacks %q:\n%s", want, info)
		}
	}
	if n := len(c.Nodes()); n < 3 {
		t.Fatalf("the cluster client knows %d nodes, want at least 3", n)
	}
}

// forEachBackend runs fn once per backend, as a subtest, with the package
// pointed at that backend, the test TTL, an in-memory PKI store and a
// tenant of its own (a shared real server keeps other runs' keys apart),
// whose keys are purged when the subtest ends.
func forEachBackend(t *testing.T, fn func(t *testing.T, b backend, tenant string)) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			c := b.open(t)
			newTestPKIDB(t)
			SetClient(c)
			prev, prevAccepted, prevJitter, prevVerify := ttl, acceptedTTL, acceptedJitter, verifySprout
			ttl = testTTL
			tenant := uniqueTenant(t)
			t.Cleanup(func() {
				if _, err := PurgeTenant(context.Background(), tenant, 100); err != nil {
					t.Errorf("purging the test tenant's keys: %v", err)
				}
				ttl, acceptedTTL, acceptedJitter, verifySprout = prev, prevAccepted, prevJitter, prevVerify
				SetClient(nil)
			})
			fn(t, b, tenant)
		})
	}
}

func uniqueTenant(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	id := "t_hb_" + hex.EncodeToString(b[:])
	if !pki.IsValidTenantID(id) {
		t.Fatalf("test tenant ID %q is invalid", id)
	}
	return id
}

// owner returns the connection ID the presence key of (tenant, sprout)
// holds, "" and false if there is none.
func owner(t *testing.T, tenant, sprout string) (string, bool) {
	t.Helper()
	v, ok, err := presenceOwner(context.Background(), tenant, sprout)
	if err != nil {
		t.Fatalf("reading the presence key: %v", err)
	}
	return v, ok
}

// The race, both orders. A sprout reconnects: its old connection A ends
// and its new connection B starts, and farmer sees CONNECT(B) and
// DISCONNECT(A) on two subscriptions, in either order. Either way the
// sprout ends up online, owned by B, and only DISCONNECT(B) ends that.
func TestPresence_ReconnectRace_BothOrders(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ backend, tenant string) {
		accountPub := tenantAccount(t, tenant)
		acceptSprout(t, tenant, "web-01", "UHBRACE01")
		ctx := context.Background()
		connA := connEventJSON(t, accountPub, "UHBRACE01", testServerID, 7)
		connB := connEventJSON(t, accountPub, "UHBRACE01", testServerID, 8)

		for _, order := range []struct {
			name  string
			steps []func([]byte)
			datas [][]byte
		}{
			// The failing order before this change: the new CONNECT
			// first, then the old connection's DISCONNECT.
			{"connect B before disconnect A", []func([]byte){handleConnect, handleConnect, handleDisconnect}, [][]byte{connA, connB, connA}},
			{"disconnect A before connect B", []func([]byte){handleConnect, handleDisconnect, handleConnect}, [][]byte{connA, connA, connB}},
		} {
			for i, step := range order.steps {
				step(order.datas[i])
			}
			if !IsOnline(ctx, tenant, "web-01") {
				t.Fatalf("%s: sprout offline although connection B is up", order.name)
			}
			if got, _ := owner(t, tenant, "web-01"); got != testServerID+"/8" {
				t.Fatalf("%s: presence owned by %q, want connection B (%s/8)", order.name, got, testServerID)
			}
			// B's own DISCONNECT ends it.
			handleDisconnect(connB)
			if IsOnline(ctx, tenant, "web-01") {
				t.Fatalf("%s: sprout online after its current connection's DISCONNECT", order.name)
			}
		}
	})
}

// A heartbeat never takes the key from the connection that owns it: one
// from the old connection that arrives after the new CONNECT extends the
// key and keeps B as its owner, so A's DISCONNECT still leaves it alone.
// A heartbeat that finds no key writes one owned by the connection its body
// names; one with no or a malformed body writes an owner no DISCONNECT
// matches, so that key lapses by TTL instead.
func TestPresence_HeartbeatKeepsOwner(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ backend, tenant string) {
		accountPub := tenantAccount(t, tenant)
		acceptSprout(t, tenant, "web-01", "UHBKEEP01")
		ctx := context.Background()
		subj := pki.SproutHeartbeatSubject("web-01")
		connA := connEventJSON(t, accountPub, "UHBKEEP01", testServerID, 7)
		connB := connEventJSON(t, accountPub, "UHBKEEP01", testServerID, 8)

		handleConnect(connA)
		handleConnect(connB)
		handleHeartbeat(tenant, subj, []byte(testServerID+"/7")) // A's, late (marker miss: database path)
		handleHeartbeat(tenant, subj, []byte(testServerID+"/7")) // and again (marker hit: script path)
		if got, _ := owner(t, tenant, "web-01"); got != testServerID+"/8" {
			t.Fatalf("a late heartbeat of connection A took the key: owner %q, want %s/8", got, testServerID)
		}
		handleDisconnect(connA)
		if !IsOnline(ctx, tenant, "web-01") {
			t.Fatal("connection A's DISCONNECT ended connection B's presence")
		}
		handleDisconnect(connB)
		if IsOnline(ctx, tenant, "web-01") {
			t.Fatal("still online after connection B's DISCONNECT")
		}

		// No key: the heartbeat's connection owns the one it writes.
		handleHeartbeat(tenant, subj, []byte(testServerID+"/9"))
		if got, ok := owner(t, tenant, "web-01"); !ok || got != testServerID+"/9" {
			t.Fatalf("heartbeat wrote owner %q (exists %v), want %s/9", got, ok, testServerID)
		}
		handleDisconnect(connEventJSON(t, accountPub, "UHBKEEP01", testServerID, 9))
		if IsOnline(ctx, tenant, "web-01") {
			t.Fatal("the DISCONNECT of the connection that heartbeat named did not end it")
		}

		for _, body := range [][]byte{nil, []byte("garbage"), []byte(testServerID + "/007"), []byte("/9"), []byte(testServerID + "/-1")} {
			handleHeartbeat(tenant, subj, body)
			if got, ok := owner(t, tenant, "web-01"); !ok || got != "" {
				t.Fatalf("body %q: owner %q (exists %v), want an unowned key", body, got, ok)
			}
			handleDisconnect(connEventJSON(t, accountPub, "UHBKEEP01", testServerID, 9))
			if !IsOnline(ctx, tenant, "web-01") {
				t.Fatalf("body %q: a DISCONNECT ended a key no connection owns", body)
			}
			if _, err := deletePresenceIfOwner(ctx, tenant, "web-01", ""); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// A client ID is unique on one bus node only: connection 1 on node S2 is
// not connection 1 on node S1, and an event that names no connection
// removes nothing.
func TestPresence_DisconnectNeedsTheSameConnection(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ backend, tenant string) {
		accountPub := tenantAccount(t, tenant)
		acceptSprout(t, tenant, "web-01", "UHBSAME01")
		ctx := context.Background()

		handleConnect(connEventJSON(t, accountPub, "UHBSAME01", "NSERVERONE", 1))
		for _, ev := range [][]byte{
			connEventJSON(t, accountPub, "UHBSAME01", "NSERVERTWO", 1),
			connEventJSON(t, accountPub, "UHBSAME01", "", 1),
			connEventJSON(t, accountPub, "UHBSAME01", "NSERVERONE", 0),
		} {
			handleDisconnect(ev)
			if !IsOnline(ctx, tenant, "web-01") {
				t.Fatalf("DISCONNECT %s removed another connection's presence", ev)
			}
		}
		handleDisconnect(connEventJSON(t, accountPub, "UHBSAME01", "NSERVERONE", 1))
		if IsOnline(ctx, tenant, "web-01") {
			t.Fatal("the owning connection's DISCONNECT left the sprout online")
		}
	})
}

// Every script names keys of one hash slot, so it runs on a Valkey Cluster
// (and valkey-go, which checks slots client-side even on a standalone
// server, accepts it everywhere); on the cluster, sprouts are spread over
// all three shards. The control
// proves the cluster really checks slots: the same two-key script over
// names without the shared tag is refused there (CROSSSLOT).
func TestPresence_ScriptsShareOneSlot(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend, tenant string) {
		ctx := context.Background()
		c := loadClient()
		const sprouts = 60
		shards := map[string]bool{}
		for i := range sprouts {
			id := fmt.Sprintf("slot-%03d", i)
			if b.cluster {
				pk, err := c.Do(ctx, c.B().ClusterKeyslot().Key(keyFor(tenant, id)).Build()).AsInt64()
				if err != nil {
					t.Fatalf("CLUSTER KEYSLOT: %v", err)
				}
				am, err := c.Do(ctx, c.B().ClusterKeyslot().Key(acceptedKeyFor(tenant, id)).Build()).AsInt64()
				if err != nil {
					t.Fatalf("CLUSTER KEYSLOT: %v", err)
				}
				if pk != am {
					t.Fatalf("%s: presence key in slot %d, marker in slot %d", id, pk, am)
				}
			}
			if err := c.Do(ctx, c.B().Set().Key(acceptedKeyFor(tenant, id)).Value("1").Ex(testTTL).Build()).Error(); err != nil {
				t.Fatal(err)
			}
			if ok, err := refreshPresence(ctx, tenant, id, testServerID+"/1"); err != nil || !ok {
				t.Fatalf("%s: refresh script: refreshed %v, %v", id, ok, err)
			}
			if err := setPresence(ctx, tenant, id, testServerID+"/2"); err != nil {
				t.Fatal(err)
			}
			if gone, err := deletePresenceIfOwner(ctx, tenant, id, testServerID+"/1"); err != nil || gone {
				t.Fatalf("%s: compare-and-delete of another connection: deleted %v, %v", id, gone, err)
			}
			if gone, err := deletePresenceIfOwner(ctx, tenant, id, testServerID+"/2"); err != nil || !gone {
				t.Fatalf("%s: compare-and-delete of the owner: deleted %v, %v", id, gone, err)
			}
			if b.cluster {
				shards[shardOf(t, c, keyFor(tenant, id))] = true
			}
		}
		if !b.cluster {
			return
		}
		if len(shards) != 3 {
			t.Fatalf("%d sprouts landed on %d shards, want all 3", sprouts, len(shards))
		}
		// Two keys of different slots, passed so that valkey-go does not
		// route or check them: the cluster itself must refuse.
		k1, k2 := "imas:test:"+tenant+":a", "imas:test:"+tenant+":b"
		s1, _ := c.Do(ctx, c.B().ClusterKeyslot().Key(k1).Build()).AsInt64()
		s2, _ := c.Do(ctx, c.B().ClusterKeyslot().Key(k2).Build()).AsInt64()
		if s1 == s2 {
			t.Fatalf("control keys share slot %d; pick others", s1)
		}
		err := c.Do(ctx, c.B().Arbitrary("EVAL").Args("return redis.call('EXISTS', KEYS[1], KEYS[2])", "2", k1, k2).Build()).Error()
		if err == nil || !strings.Contains(err.Error(), "CROSSSLOT") {
			t.Fatalf("a two-slot script on the cluster: err = %v, want CROSSSLOT", err)
		}
	})
}

// shardOf names the shard (its primary's address) that serves key.
func shardOf(t *testing.T, c valkey.Client, key string) string {
	t.Helper()
	slot, err := c.Do(context.Background(), c.B().ClusterKeyslot().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatal(err)
	}
	slots, err := c.Do(context.Background(), c.B().ClusterSlots().Build()).ToArray()
	if err != nil {
		t.Fatalf("CLUSTER SLOTS: %v", err)
	}
	for _, r := range slots {
		rng, err := r.ToArray()
		if err != nil || len(rng) < 3 {
			t.Fatalf("CLUSTER SLOTS entry: %v", err)
		}
		lo, _ := rng[0].AsInt64()
		hi, _ := rng[1].AsInt64()
		if slot < lo || slot > hi {
			continue
		}
		primary, err := rng[2].ToArray()
		if err != nil || len(primary) < 2 {
			t.Fatalf("CLUSTER SLOTS primary: %v", err)
		}
		host, _ := primary[0].ToString()
		port, _ := primary[1].AsInt64()
		return fmt.Sprintf("%s:%d", host, port)
	}
	t.Fatalf("no shard serves slot %d", slot)
	return ""
}

// The whole sprout lifecycle through the handlers, the database fallback
// and the marker included, then a purge, on every backend: a connected
// sprout heartbeats, reconnects with the race in the failing order, and
// disconnects.
func TestPresence_LifecycleThroughHandlers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, _ backend, tenant string) {
		accountPub := tenantAccount(t, tenant)
		acceptSprout(t, tenant, "web-01", "UHBLIFE01")
		ctx := context.Background()
		subj := pki.SproutHeartbeatSubject("web-01")

		handleConnect(connEventJSON(t, accountPub, "UHBLIFE01", testServerID, 1))
		handleHeartbeat(tenant, subj, []byte(testServerID+"/1"))
		handleHeartbeat(tenant, subj, []byte(testServerID+"/1"))
		if n, _ := loadClient().Do(ctx, loadClient().B().Exists().Key(acceptedKeyFor(tenant, "web-01")).Build()).AsInt64(); n != 1 {
			t.Fatal("no acceptance marker after a verified heartbeat")
		}
		handleConnect(connEventJSON(t, accountPub, "UHBLIFE01", testServerID, 2))
		handleDisconnect(connEventJSON(t, accountPub, "UHBLIFE01", testServerID, 1))
		handleHeartbeat(tenant, subj, []byte(testServerID+"/2"))
		if !IsOnline(ctx, tenant, "web-01") {
			t.Fatal("offline after reconnecting")
		}
		counts, err := PurgeTenant(ctx, tenant, 10)
		if err != nil {
			t.Fatal(err)
		}
		if counts["valkey.heartbeat"] != 1 || counts["valkey.accepted"] != 1 {
			t.Fatalf("purge counts %v, want one key of each", counts)
		}
		if IsOnline(ctx, tenant, "web-01") {
			t.Fatal("online after the purge")
		}
	})
}

func tenantAccount(t *testing.T, tenant string) string {
	t.Helper()
	acceptSprout(t, tenant, "prov-01", "UHBPROVISION")
	pub, err := pki.GetTenantAccountPub(tenant)
	if err != nil {
		t.Fatalf("GetTenantAccountPub(%s): %v", tenant, err)
	}
	return pub
}

func TestConnID(t *testing.T) {
	if got := ConnID("NABC", 42); got != "NABC/42" {
		t.Errorf("ConnID = %q", got)
	}
	for _, c := range []struct {
		server string
		id     uint64
	}{{"", 1}, {"NABC", 0}, {"N/ABC", 1}, {"N ABC", 1}, {"NABC\n", 1}} {
		if got := ConnID(c.server, c.id); got != "" {
			t.Errorf("ConnID(%q, %d) = %q, want \"\"", c.server, c.id, got)
		}
	}
	if got := connIDFromBody([]byte("NABC/42")); got != "NABC/42" {
		t.Errorf("connIDFromBody = %q", got)
	}
	for _, body := range []string{"", "NABC", "NABC/", "NABC/x", "NABC/042", "NABC/+1", "NABC/1/2", "/1", strings.Repeat("N", maxConnIDLen) + "/1"} {
		if got := connIDFromBody([]byte(body)); got != "" {
			t.Errorf("connIDFromBody(%q) = %q, want \"\"", body, got)
		}
	}
}
