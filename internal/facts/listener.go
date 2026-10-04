package facts

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/pki"
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
//
// The sprout a fact is stored under is the one named by the subject's
// second token, never the body's sprout_id (security review H2): a
// sprout's User JWT lets it publish only on its own
// imas.sprouts.<sprout_id>.facts subject (internal/pki/jwtusers.go), so the
// subject is the only part of the message that says who sent it. See
// handleFactsMsg.
func RegisterFarmerListener(tenantID string, nc *nats.Conn) {
	_, err := nc.QueueSubscribe("imas.sprouts.*.facts", natsCoreQueueGroup, func(msg *nats.Msg) {
		handleFactsMsg(tenantID, msg.Subject, msg.Data)
	})
	if err != nil {
		log.Errorf("facts: failed to subscribe: %v", err)
	}
}

// factsSubjectSproutID returns the sprout ID in subject, which must be
// exactly imas.sprouts.<sprout_id>.facts with a valid sprout ID. ok is false
// for anything else.
func factsSubjectSproutID(subject string) (string, bool) {
	tokens := strings.Split(subject, ".")
	if len(tokens) != 4 || tokens[0] != "imas" || tokens[1] != "sprouts" || tokens[3] != "facts" {
		return "", false
	}
	sid := tokens[2]
	if sid == "" || !pki.IsValidSproutID(sid) {
		return "", false
	}
	return sid, true
}

// handleFactsMsg stores one facts publication for tenantID. FLAG FOR
// SECURITY REVIEW (H2).
//
//   - The sprout is the subject's second token, validated with
//     pki.IsValidSproutID. The NATS server enforced that the publisher may
//     use that subject; nothing enforced anything about the body.
//   - The body's sprout_id must equal it. A message whose body names
//     another sprout (or none) is dropped whole, not stored under the
//     subject's sprout: a sprout that sends someone else's ID is either
//     broken or forging, and neither report is worth keeping.
//   - Rows are written with props.SetPropForTenant, whose primary key is
//     (tenant_id, sprout_id, name), so the store is keyed on the tenant of
//     the connection the message arrived on and the subject's sprout,
//     together.
func handleFactsMsg(tenantID, subject string, data []byte) {
	if tenantID == "" {
		log.Error("facts: listener has no tenant, dropping message")
		return
	}
	sid, ok := factsSubjectSproutID(subject)
	if !ok {
		log.Warnf("facts: dropping message on unexpected subject %q", subject)
		return
	}
	var sf SystemFacts
	if unmarshalErr := json.Unmarshal(data, &sf); unmarshalErr != nil {
		log.Errorf("facts: failed to unmarshal facts from %s: %v", sid, unmarshalErr)
		return
	}
	if sf.SproutID != sid {
		log.Warnf("facts: dropping facts published on %s's subject that name sprout %q in the body", sid, sf.SproutID)
		return
	}
	storeFacts(tenantID, sf)
	log.Noticef("facts: received system facts from %s (os=%s arch=%s)", sid, sf.OS, sf.Arch)
}

// storeFacts writes system facts into the props store, scoped to tenantID
// — the tenant of the per-tenant NATS connection the facts arrived on (see
// RegisterFarmerListener), not the bare, legacy-tenant-scoped seam.
// sf.SproutID has already been checked against the subject
// (handleFactsMsg).
func storeFacts(tenantID string, sf SystemFacts) {
	sid := sf.SproutID
	props.SetPropForTenant(tenantID, sid, PropOS, sf.OS)
	props.SetPropForTenant(tenantID, sid, PropArch, sf.Arch)
	props.SetPropForTenant(tenantID, sid, PropHostname, sf.Hostname)
	props.SetPropForTenant(tenantID, sid, PropGoVersion, sf.GoVersion)
	props.SetPropForTenant(tenantID, sid, PropNumCPU, fmt.Sprintf("%d", sf.NumCPU))
	storeSproutVersion(tenantID, sid, sf.SproutVersion)
	if len(sf.IPAddresses) > 0 {
		ipsJSON, _ := json.Marshal(sf.IPAddresses)
		props.SetPropForTenant(tenantID, sid, PropIPAddresses, string(ipsJSON))
	}
	storeHardwareFacts(tenantID, sid, sf.Hardware)
}

// Prop names the facts listener stores a sprout's own report under.
// Together with PropSproutVersion and hardwarePropNames they are the
// reserved names (IsReservedPropName): only the sprout itself, through
// this listener, may write them.
const (
	PropOS          = "os"
	PropArch        = "arch"
	PropHostname    = "hostname"
	PropGoVersion   = "go_version"
	PropNumCPU      = "num_cpu"
	PropIPAddresses = "ip_addresses"
)

// hardwarePropNames are the prop names storeHardwareFacts writes, in the
// order of hardwareFields' result.
var hardwarePropNames = []string{
	"bios_vendor",
	"bios_version",
	"bios_release_date",
	"system_manufacturer",
	"system_product_name",
	"system_serial_number",
	"system_uuid",
	"chassis_manufacturer",
	"chassis_type",
	"chassis_serial_number",
	"chassis_asset_tag",
}

// hardwareFields returns hw's values in hardwarePropNames' order.
func hardwareFields(hw *HardwareFacts) []string {
	return []string{
		hw.BIOSVendor,
		hw.BIOSVersion,
		hw.BIOSReleaseDate,
		hw.SystemManufacturer,
		hw.SystemProductName,
		hw.SystemSerialNumber,
		hw.SystemUUID,
		hw.ChassisManufacturer,
		hw.ChassisType,
		hw.ChassisSerialNumber,
		hw.ChassisAssetTag,
	}
}

// ReservedPropNames returns every prop name the facts listener writes from
// a sprout's own report: os, arch, hostname, go_version, num_cpu,
// ip_addresses, sprout_version and the hardware keys. saasapi's rollout
// gate and planning read some of them (fleet_sprout_facts.go), dynamic
// cohorts and recipe templates read any of them, so no other writer may
// set or delete them (internal/natsapi's props.set and props.delete
// refuse them; security review H2).
func ReservedPropNames() []string {
	names := []string{PropOS, PropArch, PropHostname, PropGoVersion, PropNumCPU, PropIPAddresses, PropSproutVersion}
	return append(names, hardwarePropNames...)
}

// IsReservedPropName reports whether name is, or would be stored as, one of
// ReservedPropNames. The comparison ignores case: farmer.props' name column
// uses the schema's default collation, which is case-insensitive in PXC,
// so "OS" and "os" are the same row there. Callers that accept names from
// outside should also restrict them to plain ASCII (see
// internal/natsapi's validPropName), since that collation also folds
// accents and ignores some control characters.
func IsReservedPropName(name string) bool {
	for _, r := range ReservedPropNames() {
		if strings.EqualFold(name, r) {
			return true
		}
	}
	return false
}

// PropSproutVersion is the prop a sprout's reported release tag is stored
// under. saasapi reads it from farmer.props to decide when a fleet update
// rollout's wave has passed (design doc §2.3), so the name is a contract
// (pinned by saasapi's TestFarmerSproutVersionPropContract).
const PropSproutVersion = "sprout_version"

// storeSproutVersion records the version a sprout reported, or deletes the
// stored one when it reported none (a build without a release tag), so an
// older report never stands in for the running sprout's version.
func storeSproutVersion(tenantID, sid, version string) {
	if version == "" {
		if err := props.DeletePropForTenant(tenantID, sid, PropSproutVersion); err != nil {
			log.Errorf("facts: clearing %s for %s: %v", PropSproutVersion, sid, err)
		}
		return
	}
	if err := props.SetPropForTenant(tenantID, sid, PropSproutVersion, version); err != nil {
		log.Errorf("facts: storing %s for %s: %v", PropSproutVersion, sid, err)
	}
}

// storeHardwareFacts writes non-empty hardware/BIOS facts into the props
// store, scoped to tenantID. hw is nil when the sprout couldn't reach its
// SMBIOS table.
func storeHardwareFacts(tenantID, sid string, hw *HardwareFacts) {
	if hw == nil || hw.IsZero() {
		return
	}
	for i, value := range hardwareFields(hw) {
		if value == "" {
			continue
		}
		key := hardwarePropNames[i]
		props.SetPropForTenant(tenantID, sid, key, value)
	}
}
