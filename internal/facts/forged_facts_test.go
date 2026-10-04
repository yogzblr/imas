package facts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
)

// SEC.4 / security review H2: facts are stored under the sprout named by
// the subject, and a body that names another sprout is dropped.

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
	// The victim's real report.
	handleFactsMsg(tenant, "imas.sprouts.victim.facts", factsBody(t, SystemFacts{
		OS: "linux", Arch: "amd64", Hostname: "victim", SproutID: "victim", SproutVersion: "v1.0.0",
	}))
	if got := props.GetStringPropForTenant(tenant, "victim", PropSproutVersion); got != "v1.0.0" {
		t.Fatalf("victim's own report not stored: %q", got)
	}

	// The attacker, on its own subject, names the victim in the body.
	handleFactsMsg(tenant, "imas.sprouts.attacker.facts", factsBody(t, SystemFacts{
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
	for _, subject := range []string{
		"imas.sprouts.UPPER.facts",
		"imas.sprouts.-dash.facts",
		"imas.sprouts..facts",
		"imas.sprouts.a.b.facts",
		"imas.other.web.facts",
		"imas.sprouts.web.cook",
	} {
		id := strings.Split(subject, ".")[2]
		handleFactsMsg(tenant, subject, factsBody(t, SystemFacts{OS: "linux", SproutID: id}))
		if got := props.GetPropsForTenant(tenant, id); got != nil {
			t.Errorf("%s: stored %v", subject, got)
		}
	}
	// An empty body sprout_id differs from the subject's too.
	handleFactsMsg(tenant, "imas.sprouts.web.facts", factsBody(t, SystemFacts{OS: "linux"}))
	if got := props.GetPropsForTenant(tenant, "web"); got != nil {
		t.Errorf("body without sprout_id stored: %v", got)
	}
	// No tenant, nothing stored.
	handleFactsMsg("", "imas.sprouts.web.facts", factsBody(t, SystemFacts{OS: "linux", SproutID: "web"}))
	if got := props.GetPropsForTenant("", "web"); got != nil {
		t.Errorf("tenantless message stored: %v", got)
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

	attJWT, attSeed := enrollTenantIsolationSprout(t, tenant, attacker)
	vicJWT, vicSeed := enrollTenantIsolationSprout(t, tenant, victim)
	ncAtt := dialTenantIsolationConn(t, attJWT, attSeed)
	defer ncAtt.Close()
	ncVic := dialTenantIsolationConn(t, vicJWT, vicSeed)
	defer ncVic.Close()

	ncVic.Publish("imas.sprouts."+victim+".facts", factsBody(t, SystemFacts{OS: "linux", Arch: "amd64", SproutID: victim, SproutVersion: "v1.0.0"}))
	ncVic.Flush()
	time.Sleep(300 * time.Millisecond)
	if got := props.GetStringPropForTenant(tenant, victim, PropSproutVersion); got != "v1.0.0" {
		t.Fatalf("victim's own report not stored: %q", got)
	}

	forged := factsBody(t, SystemFacts{OS: "windows", Arch: "arm64", SproutID: victim, SproutVersion: "v9.9.9"})
	ncAtt.Publish("imas.sprouts."+attacker+".facts", forged)
	ncAtt.Publish("imas.sprouts."+victim+".facts", forged) // denied by the attacker's grant
	ncAtt.Flush()
	time.Sleep(300 * time.Millisecond)

	got := props.GetPropsForTenant(tenant, victim)
	if got[PropSproutVersion] != "v1.0.0" || got[PropOS] != "linux" || got[PropArch] != "amd64" {
		t.Errorf("forged facts reached the victim: %v", got)
	}
}
