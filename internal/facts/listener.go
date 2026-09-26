package facts

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/props"
)

// natsCoreQueueGroup is the queue group every farmer replica shares for
// imas.sprouts.*.facts — the same well-known group name
// internal/natsapi/router.go's Subscribe uses for its own request/response
// handlers (that constant is unexported there, so this package defines its
// own copy of the same value rather than depending across packages for a
// string literal).
const natsCoreQueueGroup = "imas-core"

// RegisterFarmerListener subscribes to sprout facts publications on nc —
// one of farmer's per-tenant NATS connections (see
// docs/design/imas-tenant-context-threading.md's Option A; called once per
// tenant connection by cmd/farmer/main.go, so every tenant's facts traffic
// reaches farmer, not just the legacy tenant's) — and stores them as props
// on the farmer side, scoped to tenantID via props.SetPropForTenant. Before
// this, fact storage stayed on the bare, legacy-tenant-scoped functions
// regardless of which tenant connection a fact arrived on — inert while
// farmer only had one shared connection, but a live cross-tenant leak once
// each tenant got its own connection (this same design doc's Option A):
// every tenant's facts landed under the legacy tenant, so a real tenant's
// own prop queries found nothing and the legacy tenant's view silently
// accumulated everyone else's facts.
//
// This used to intentionally use plain Subscribe (fan-out), not
// QueueSubscribe, on the reasoning that props.SetProp wrote into an
// in-process, in-memory cache, so every farmer replica needed its own copy
// of every sprout's facts. That reasoning stopped being true once
// workstream A moved props to PXC-backed, read-through storage with no
// in-memory cache (see internal/props/store.go's own header comment) —
// every replica now reads and writes the same shared row regardless of
// which one received a given facts event. Fan-out therefore meant every
// replica redundantly re-processing (and racing to UPSERT) the same event,
// exactly the class of write race the PXC migration was meant to remove.
// QueueSubscribe under the shared "imas-core" group (matching
// internal/natsapi/router.go's own request/response handlers) makes
// exactly one replica handle each event instead.
func RegisterFarmerListener(tenantID string, nc *nats.Conn) {
	_, err := nc.QueueSubscribe("imas.sprouts.*.facts", natsCoreQueueGroup, func(msg *nats.Msg) {
		var sf SystemFacts
		if unmarshalErr := json.Unmarshal(msg.Data, &sf); unmarshalErr != nil {
			log.Errorf("facts: failed to unmarshal: %v", unmarshalErr)
			return
		}
		if sf.SproutID == "" {
			log.Error("facts: received facts with empty sprout ID")
			return
		}
		storeFacts(tenantID, sf)
		log.Noticef("facts: received system facts from %s (os=%s arch=%s)", sf.SproutID, sf.OS, sf.Arch)
	})
	if err != nil {
		log.Errorf("facts: failed to subscribe: %v", err)
	}
}

// storeFacts writes system facts into the props store, scoped to tenantID
// — the tenant of the per-tenant NATS connection the facts arrived on (see
// RegisterFarmerListener), not the bare, legacy-tenant-scoped seam.
func storeFacts(tenantID string, sf SystemFacts) {
	sid := sf.SproutID
	props.SetPropForTenant(tenantID, sid, "os", sf.OS)
	props.SetPropForTenant(tenantID, sid, "arch", sf.Arch)
	props.SetPropForTenant(tenantID, sid, "hostname", sf.Hostname)
	props.SetPropForTenant(tenantID, sid, "go_version", sf.GoVersion)
	props.SetPropForTenant(tenantID, sid, "num_cpu", fmt.Sprintf("%d", sf.NumCPU))
	if len(sf.IPAddresses) > 0 {
		ipsJSON, _ := json.Marshal(sf.IPAddresses)
		props.SetPropForTenant(tenantID, sid, "ip_addresses", string(ipsJSON))
	}
	storeHardwareFacts(tenantID, sid, sf.Hardware)
}

// storeHardwareFacts writes non-empty hardware/BIOS facts into the props
// store, scoped to tenantID. hw is nil when the sprout couldn't reach its
// SMBIOS table.
func storeHardwareFacts(tenantID, sid string, hw *HardwareFacts) {
	if hw == nil || hw.IsZero() {
		return
	}
	fields := map[string]string{
		"bios_vendor":           hw.BIOSVendor,
		"bios_version":          hw.BIOSVersion,
		"bios_release_date":     hw.BIOSReleaseDate,
		"system_manufacturer":   hw.SystemManufacturer,
		"system_product_name":   hw.SystemProductName,
		"system_serial_number":  hw.SystemSerialNumber,
		"system_uuid":           hw.SystemUUID,
		"chassis_manufacturer":  hw.ChassisManufacturer,
		"chassis_type":          hw.ChassisType,
		"chassis_serial_number": hw.ChassisSerialNumber,
		"chassis_asset_tag":     hw.ChassisAssetTag,
	}
	for key, value := range fields {
		if value == "" {
			continue
		}
		props.SetPropForTenant(tenantID, sid, key, value)
	}
}
