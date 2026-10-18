package facts

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// benchFacts is a facts report of about 4 KiB: a host with 64 addresses
// and full SMBIOS facts, larger than most.
func benchFacts() SystemFacts {
	sf := SystemFacts{OS: "linux", Arch: "amd64", Hostname: "web-01.example.internal", GoVersion: "go1.26.9", NumCPU: 64,
		KernelArch: "x86_64", SproutID: "web-01", SproutVersion: "v1.4.2",
		Hardware: &HardwareFacts{BIOSVendor: "American Megatrends Inc.", BIOSVersion: "F.42", BIOSReleaseDate: "03/14/2025",
			SystemManufacturer: "Example Corp", SystemProductName: "ProLiant DL380 Gen11", SystemSerialNumber: "CZJ12345678",
			SystemUUID: "4c4c4544-0042-3510-8051-b4c04f4e3332", ChassisManufacturer: "Example Corp", ChassisType: "Rack Mount Chassis",
			ChassisSerialNumber: "CZJ12345678", ChassisAssetTag: "ASSET-0042"}}
	for i := range 64 {
		sf.IPAddresses = append(sf.IPAddresses, fmt.Sprintf("10.%d.%d.%d", i, i*3%256, i*7%256), fmt.Sprintf("fd00:1234:5678:%x::%x", i, i+1))
	}
	return sf
}

// BenchmarkSealFacts is the sprout's cost per report: marshal and seal one
// copy to the tenant key (cmd/sprout's sealedFactsMsg). It reports the
// plaintext and sealed sizes.
func BenchmarkSealFacts(b *testing.B) {
	tenantPub, _, _ := box.GenerateKey(rand.Reader)
	_, sproutPriv, _ := box.GenerateKey(rand.Reader)
	sf := benchFacts()
	plain, _ := json.Marshal(sf)
	var sealed []byte
	for b.Loop() {
		msg, err := payloadbox.NewMessage(payloadbox.PurposeFacts, "t_bench", "web-01", "", sf)
		if err != nil {
			b.Fatal(err)
		}
		if sealed, err = payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sproutPriv}}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(plain)), "plain-B")
	b.ReportMetric(float64(len(sealed)), "sealed-B")
}

// BenchmarkOpenFacts is farmer's cryptographic cost per report: open it
// under one (tenant key, sprout key) pair, as pki.OpenFromSprout does
// once its key lookups are cached.
func BenchmarkOpenFacts(b *testing.B) {
	tenantPub, tenantPriv, _ := box.GenerateKey(rand.Reader)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)
	msg, _ := payloadbox.NewMessage(payloadbox.PurposeFacts, "t_bench", "web-01", "", benchFacts())
	sealed, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sproutPriv}})
	if err != nil {
		b.Fatal(err)
	}
	want := payloadbox.Expect{Purpose: payloadbox.PurposeFacts, TenantID: "t_bench", SproutID: "web-01"}
	for b.Loop() {
		if _, err := payloadbox.Open(sealed, []payloadbox.KeyPair{{PeerPub: sproutPub, Priv: tenantPriv}}, want); err != nil {
			b.Fatal(err)
		}
	}
}

// The sealed report stays far below the bus's 1 MiB max_payload, so no
// compression is needed before sealing.
func TestSealedFactsFitTheBus(t *testing.T) {
	tenantPub, _, _ := box.GenerateKey(rand.Reader)
	_, sproutPriv, _ := box.GenerateKey(rand.Reader)
	msg, _ := payloadbox.NewMessage(payloadbox.PurposeFacts, "t_bench", "web-01", "", benchFacts())
	sealed, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sproutPriv}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) > 64<<10 {
		t.Fatalf("a sealed facts report is %d bytes", len(sealed))
	}
}
