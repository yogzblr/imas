package facts

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"maps"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/rbac"
)

// SEC.4 / security review H2: facts are stored under the sprout named by
// the subject, and a body that names another sprout is dropped. P6 (U3):
// only a sealed report from that sprout is stored at all.

func factsBody(t *testing.T, sf SystemFacts) []byte {
	t.Helper()
	b, err := json.Marshal(sf)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHandleFactsMsg_ForgedBodyIgnored(t *testing.T) {
	const tenant = "t_forge"
	usePKIDB(t)
	keys := newSealedFacts(t, tenant)
	keys.enroll(tenant, "victim")
	keys.enroll(tenant, "attacker")
	// The victim's real report.
	handleFactsMsg(tenant, "imas.sprouts.victim.facts", sealedHeader(), keys.seal(tenant, "victim", SystemFacts{
		OS: "linux", Arch: "amd64", Hostname: "victim", SproutID: "victim", SproutVersion: "v1.0.0",
	}))
	if got := props.GetStringPropForTenant(tenant, "victim", PropSproutVersion); got != "v1.0.0" {
		t.Fatalf("victim's own report not stored: %q", got)
	}

	// The attacker, on its own subject and sealed with its own key, names
	// the victim in the body.
	handleFactsMsg(tenant, "imas.sprouts.attacker.facts", sealedHeader(), keys.seal(tenant, "attacker", SystemFacts{
		OS: "windows", Arch: "arm64", Hostname: "x\nevil: y", SproutID: "victim", SproutVersion: "v9.9.9",
	}))
	got := props.GetPropsForTenant(tenant, "victim")
	if got[PropSproutVersion] != "v1.0.0" || got[PropOS] != "linux" || got[PropHostname] != "victim" {
		t.Errorf("forged body changed the victim's facts: %v", got)
	}
	if got := props.GetPropsForTenant(tenant, "attacker"); got != nil {
		t.Errorf("forged message stored under the attacker's subject: %v", got)
	}
}

func TestHandleFactsMsg_SubjectChecks(t *testing.T) {
	const tenant = "t_forge_subj"
	usePKIDB(t)
	keys := newSealedFacts(t, tenant)
	keys.enroll(tenant, "web")
	for _, subject := range []string{
		"imas.sprouts.UPPER.facts",
		"imas.sprouts.-dash.facts",
		"imas.sprouts..facts",
		"imas.sprouts.a.b.facts",
		"imas.other.web.facts",
		"imas.sprouts.web.cook",
	} {
		id := strings.Split(subject, ".")[2]
		handleFactsMsg(tenant, subject, sealedHeader(), keys.seal(tenant, "web", SystemFacts{OS: "linux", SproutID: id}))
		if got := props.GetPropsForTenant(tenant, id); got != nil {
			t.Errorf("%s: stored %v", subject, got)
		}
	}
	// An empty body sprout_id differs from the subject's too.
	handleFactsMsg(tenant, "imas.sprouts.web.facts", sealedHeader(), keys.seal(tenant, "web", SystemFacts{OS: "linux"}))
	if got := props.GetPropsForTenant(tenant, "web"); got != nil {
		t.Errorf("body without sprout_id stored: %v", got)
	}
	// No tenant, nothing stored.
	handleFactsMsg("", "imas.sprouts.web.facts", sealedHeader(), keys.seal(tenant, "web", SystemFacts{OS: "linux", SproutID: "web"}))
	if got := props.GetPropsForTenant("", "web"); got != nil {
		t.Errorf("tenantless message stored: %v", got)
	}
}

// Security review P6 (U3): every facts report farmer stores is sealed by
// the sprout it names. A forged, stale, wrong-sprout, wrong-tenant,
// replayed or plaintext report is refused, and the facts stored before it
// stay as they were.
func TestHandleFactsMsg_SealedOnly(t *testing.T) {
	const tenant, other, sid = "t_p6", "t_p6_other", "p6-web"
	usePKIDB(t)
	keys := newSealedFacts(t, tenant, other)
	keys.enroll(tenant, sid)
	keys.enroll(tenant, "p6-neighbour")
	keys.enroll(other, sid)
	subject := "imas.sprouts." + sid + ".facts"
	honest := SystemFacts{OS: "linux", Arch: "amd64", Hostname: "web", SproutID: sid, SproutVersion: "v1.0.0"}
	first := keys.seal(tenant, sid, honest)
	handleFactsMsg(tenant, subject, sealedHeader(), first)
	want := props.GetPropsForTenant(tenant, sid)
	if want[PropOS] != "linux" || want[PropSproutVersion] != "v1.0.0" {
		t.Fatalf("honest report not stored: %v", want)
	}

	forgedFacts := SystemFacts{OS: "windows", Arch: "arm64", Hostname: "evil", SproutID: sid, SproutVersion: "v9.9.9"}
	plain, _ := json.Marshal(forgedFacts)
	// Forged: sealed under a box key farmer has no record of.
	_, strangerPriv, _ := box.GenerateKey(rand.Reader)
	forgedMsg, _ := payloadbox.NewMessage(payloadbox.PurposeFacts, tenant, sid, "", forgedFacts)
	forged, _ := payloadbox.Seal(forgedMsg, []payloadbox.KeyPair{{PeerPub: keys.tenantPub(tenant), Priv: strangerPriv}})
	stale := func(m *payloadbox.Message) {
		m.IssuedAt = time.Now().Add(-payloadbox.DefaultMaxSkew - time.Minute).Unix()
	}
	future := func(m *payloadbox.Message) {
		m.IssuedAt = time.Now().Add(payloadbox.DefaultMaxSkew + time.Minute).Unix()
	}
	asReply := func(m *payloadbox.Message) { m.ReplyTo = "0123" }
	cmdPurpose := func(m *payloadbox.Message) { m.Purpose = payloadbox.PurposeCmdRunResponse }

	for _, c := range []struct {
		name   string
		header nats.Header
		data   []byte
	}{
		{"plaintext", nil, plain},
		{"plaintext marked sealed", sealedHeader(), plain},
		{"forged", sealedHeader(), forged},
		{"stale", sealedHeader(), keys.sealAs(tenant, sid, tenant, sid, forgedFacts, stale)},
		{"from the future", sealedHeader(), keys.sealAs(tenant, sid, tenant, sid, forgedFacts, future)},
		{"wrong sprout", sealedHeader(), keys.sealAs(tenant, "p6-neighbour", tenant, "p6-neighbour", forgedFacts, nil)},
		{"wrong sprout named", sealedHeader(), keys.sealAs(tenant, "p6-neighbour", tenant, sid, forgedFacts, nil)},
		{"wrong tenant", sealedHeader(), keys.sealAs(other, sid, other, sid, forgedFacts, nil)},
		{"wrong tenant named", sealedHeader(), keys.sealAs(tenant, sid, other, sid, forgedFacts, nil)},
		{"a reply", sealedHeader(), keys.sealAs(tenant, sid, tenant, sid, forgedFacts, asReply)},
		{"another purpose", sealedHeader(), keys.sealAs(tenant, sid, tenant, sid, forgedFacts, cmdPurpose)},
		{"replayed", sealedHeader(), first},
	} {
		handleFactsMsg(tenant, subject, c.header, c.data)
		if got := props.GetPropsForTenant(tenant, sid); !maps.Equal(got, want) {
			t.Errorf("%s report changed the stored facts: %v, want %v", c.name, got, want)
		}
	}

	// A fresh honest report is still stored.
	honest.SproutVersion = "v1.0.1"
	handleFactsMsg(tenant, subject, sealedHeader(), keys.seal(tenant, sid, honest))
	if got := props.GetStringPropForTenant(tenant, sid, PropSproutVersion); got != "v1.0.1" {
		t.Errorf("the next honest report was not stored: %q", got)
	}
}

// A plaintext report marks the sprout as needing an upgrade, and the next
// sealed report clears it (heartbeat's upgrade marker).
func TestHandleFactsMsg_PlaintextMarksUpgradeRequired(t *testing.T) {
	const tenant, sid = "t_p6_up", "old-sprout"
	usePKIDB(t)
	keys := newSealedFacts(t, tenant)
	keys.enroll(tenant, sid)
	mr := miniredis.RunT(t)
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat.SetClient(c)
	t.Cleanup(func() { heartbeat.SetClient(nil); c.Close() })
	subject := "imas.sprouts." + sid + ".facts"

	plain, _ := json.Marshal(SystemFacts{OS: "linux", SproutID: sid})
	handleFactsMsg(tenant, subject, nil, plain)
	if got := heartbeat.UpgradeRequired(context.Background(), tenant, sid); got != heartbeat.UpgradeKindFacts {
		t.Fatalf("after a plaintext report UpgradeRequired = %q", got)
	}
	if got := props.GetPropsForTenant(tenant, sid); got != nil {
		t.Fatalf("plaintext report stored: %v", got)
	}
	handleFactsMsg(tenant, subject, sealedHeader(), keys.seal(tenant, sid, SystemFacts{OS: "linux", SproutID: sid}))
	if got := heartbeat.UpgradeRequired(context.Background(), tenant, sid); got != "" {
		t.Fatalf("after a sealed report UpgradeRequired = %q", got)
	}
}

// Decision 6's cohort case: a forged fact can't move a sprout into a
// fact-based cohort.
func TestHandleFactsMsg_ForgedFactMovesNoSproutIntoACohort(t *testing.T) {
	const tenant = "t_p6_cohort"
	usePKIDB(t)
	keys := newSealedFacts(t, tenant)
	keys.enroll(tenant, "lin-01")
	keys.enroll(tenant, "win-01")
	gdb, err := gorm.Open(sqlite.Open("file:"+t.Name()+"-rbac-"+strconv.FormatInt(memDBSeq.Add(1), 10)+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(rbac.Models()...); err != nil {
		t.Fatal(err)
	}
	rbac.SetDB(gdb)
	t.Cleanup(func() { rbac.SetDB(nil) })
	reg := rbac.NewRegistryForTenant(tenant)
	if err := reg.Register(&rbac.Cohort{Name: "linux", Type: rbac.CohortTypeDynamic,
		Match: &rbac.DynamicMatch{PropName: PropOS, PropValue: "linux"}}); err != nil {
		t.Fatal(err)
	}
	all := []string{"lin-01", "win-01"}
	for _, id := range all {
		os := map[string]string{"lin-01": "linux", "win-01": "windows"}[id]
		handleFactsMsg(tenant, "imas.sprouts."+id+".facts", sealedHeader(), keys.seal(tenant, id, SystemFacts{OS: os, SproutID: id}))
	}
	members := func() map[string]bool {
		got, err := reg.Resolve("linux", all)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := members(); !maps.Equal(got, map[string]bool{"lin-01": true}) {
		t.Fatalf("cohort from honest facts = %v", got)
	}

	lie := SystemFacts{OS: "linux", SproutID: "win-01"}
	plain, _ := json.Marshal(lie)
	_, strangerPriv, _ := box.GenerateKey(rand.Reader)
	m, _ := payloadbox.NewMessage(payloadbox.PurposeFacts, tenant, "win-01", "", lie)
	forged, _ := payloadbox.Seal(m, []payloadbox.KeyPair{{PeerPub: keys.tenantPub(tenant), Priv: strangerPriv}})
	subject := "imas.sprouts.win-01.facts"
	handleFactsMsg(tenant, subject, nil, plain)
	handleFactsMsg(tenant, subject, sealedHeader(), plain)
	handleFactsMsg(tenant, subject, sealedHeader(), forged)
	handleFactsMsg(tenant, subject, sealedHeader(), keys.sealAs(tenant, "lin-01", tenant, "win-01", lie, nil))
	if got := members(); !maps.Equal(got, map[string]bool{"lin-01": true}) {
		t.Fatalf("a forged fact moved a sprout into the cohort: %v", got)
	}
}

func TestReservedPropNames(t *testing.T) {
	for _, name := range []string{"os", "OS", "Arch", "hostname", "sprout_version", "ip_addresses", "go_version", "num_cpu", "system_uuid", "CHASSIS_ASSET_TAG", "bios_vendor"} {
		if !IsReservedPropName(name) {
			t.Errorf("%q not reserved", name)
		}
	}
	for _, name := range []string{"role", "env", "os_family", "hostnames", "rack"} {
		if IsReservedPropName(name) {
			t.Errorf("%q reserved", name)
		}
	}
	// Every name storeFacts can write is reserved.
	const tenant, sid = "t_reserved", "all-facts"
	hw := HardwareFacts{
		BIOSVendor: "a", BIOSVersion: "a", BIOSReleaseDate: "a", SystemManufacturer: "a",
		SystemProductName: "a", SystemSerialNumber: "a", SystemUUID: "a", ChassisManufacturer: "a",
		ChassisType: "a", ChassisSerialNumber: "a", ChassisAssetTag: "a",
	}
	storeFacts(tenant, SystemFacts{
		OS: "a", Arch: "a", Hostname: "a", GoVersion: "a", NumCPU: 1, IPAddresses: []string{"a"},
		SproutID: sid, SproutVersion: "v1.0.0", Hardware: &hw,
	})
	for name := range props.GetPropsForTenant(tenant, sid) {
		if !IsReservedPropName(name) {
			t.Errorf("storeFacts wrote %q, which is not reserved", name)
		}
	}
}

// TestForgedFacts_RealBus: on a real tenant Account, a sprout publishing
// on its own subject with a neighbour's sprout_id in the body changes
// nothing, and its grant does not let it publish on the neighbour's
// subject.
func TestForgedFacts_RealBus(t *testing.T) {
	setupTenantIsolationPKI(t)
	defer startTenantIsolationBus(t)()

	const tenant = "t_facts_forge"
	const attacker, victim = "forge-attacker", "forge-victim"

	farmerKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	farmerPub, _ := farmerKP.PublicKey()
	farmerSeed, _ := farmerKP.Seed()
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(farmerPub), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pki.ProvisionTenant(tenant, "Facts Forge Tenant"); err != nil {
		t.Fatal(err)
	}
	farmerJWT, err := pki.FarmerUserJWTForTenant(tenant)
	if err != nil {
		t.Fatal(err)
	}
	ncFarmer := dialTenantIsolationConn(t, farmerJWT, farmerSeed)
	defer ncFarmer.Close()
	RegisterFarmerListener(tenant, ncFarmer)
	ncFarmer.Flush()

	keys := newSealedFacts(t, tenant)
	keys.enroll(tenant, attacker)
	keys.enroll(tenant, victim)
	attJWT, attSeed := enrollTenantIsolationSprout(t, tenant, attacker)
	vicJWT, vicSeed := enrollTenantIsolationSprout(t, tenant, victim)
	ncAtt := dialTenantIsolationConn(t, attJWT, attSeed)
	defer ncAtt.Close()
	ncVic := dialTenantIsolationConn(t, vicJWT, vicSeed)
	defer ncVic.Close()

	publishSealed(t, ncVic, victim, keys.seal(tenant, victim, SystemFacts{OS: "linux", Arch: "amd64", SproutID: victim, SproutVersion: "v1.0.0"}))
	ncVic.Flush()
	time.Sleep(300 * time.Millisecond)
	if got := props.GetStringPropForTenant(tenant, victim, PropSproutVersion); got != "v1.0.0" {
		t.Fatalf("victim's own report not stored: %q", got)
	}

	forged := SystemFacts{OS: "windows", Arch: "arm64", SproutID: victim, SproutVersion: "v9.9.9"}
	publishSealed(t, ncAtt, attacker, keys.seal(tenant, attacker, forged))
	// Denied by the attacker's grant, and sealed by the wrong sprout.
	publishSealed(t, ncAtt, victim, keys.sealAs(tenant, attacker, tenant, victim, forged, nil))
	ncAtt.Publish("imas.sprouts."+victim+".facts", factsBody(t, forged))
	ncAtt.Flush()
	time.Sleep(300 * time.Millisecond)

	got := props.GetPropsForTenant(tenant, victim)
	if got[PropSproutVersion] != "v1.0.0" || got[PropOS] != "linux" || got[PropArch] != "amd64" {
		t.Errorf("forged facts reached the victim: %v", got)
	}
}

// TestHostnameFactTTL: the hostname fact lives 10 minutes (owner decision
// on PR 84); the facts saasapi dates by expiry keep props.DefaultPropTTL.
func TestHostnameFactTTL(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	const tenant, sid = "t_host_ttl", "host-ttl"
	usePKIDB(t)
	keys := newSealedFacts(t, tenant)
	keys.enroll(tenant, sid)
	before := time.Now()
	handleFactsMsg(tenant, "imas.sprouts."+sid+".facts", sealedHeader(), keys.seal(tenant, sid, SystemFacts{
		OS: "linux", Arch: "amd64", Hostname: "web", SproutID: sid, SproutVersion: "v1.0.0",
	}))
	ttl := func(name string) time.Duration {
		var row struct{ Expiry time.Time }
		if err := gdb.Table("props").Select("expiry").Where("tenant_id = ? AND sprout_id = ? AND name = ?", tenant, sid, name).Scan(&row).Error; err != nil {
			t.Fatal(err)
		}
		return row.Expiry.Sub(before)
	}
	near := func(got, want time.Duration) bool { return got > want-time.Second && got < want+5*time.Second }
	if got := ttl(PropHostname); HostnamePropTTL != 10*time.Minute || !near(got, HostnamePropTTL) {
		t.Errorf("hostname expires %v after the write, want 10m", got)
	}
	for _, name := range []string{PropOS, PropArch, PropSproutVersion} {
		if got := ttl(name); !near(got, props.DefaultPropTTL) {
			t.Errorf("%s expires %v after the write, want props.DefaultPropTTL", name, got)
		}
	}
}
