package facts

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/payloadbox"
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
//
// Every report is sealed by the sprout (payloadbox.PurposeFacts, security
// review P6): see handleFactsMsg for what is accepted.
func RegisterFarmerListener(tenantID string, nc *nats.Conn) {
	_, err := nc.QueueSubscribe("imas.sprouts.*.facts", natsCoreQueueGroup, func(msg *nats.Msg) {
		handleFactsMsg(tenantID, msg.Subject, msg.Header, msg.Data)
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

// factsGuard is this replica's replay guard for facts reports, keyed on
// (tenant_id, sprout_id, message id). In memory only: a report replayed
// to another replica inside the window stores the same sprout's own,
// recent facts again, which a cluster-wide claim per report (one Valkey
// write per sprout per facts interval) would not be worth.
var factsGuard = payloadbox.NewKeyedReplayGuard()

// ErrPlaintextFacts: a facts report arrived without the payloadbox
// marker. Refused from every sprout: there is no plaintext fallback, as
// for cmd.run and cook. The sprout runs a build older than sealed facts
// (heartbeat.MarkUpgradeRequired).
var ErrPlaintextFacts = errors.New("facts: plaintext report refused; the sprout runs a build that can't seal its facts and needs an upgrade")

// handleFactsMsg stores one facts publication for tenantID. FLAG FOR
// SECURITY REVIEW (H2, P6).
//
//   - The sprout is the subject's second token, validated with
//     pki.IsValidSproutID. The NATS server enforced that the publisher may
//     use that subject; the seal, not the subject, says who wrote it.
//   - The report must be a payloadbox envelope (payloadbox.Header) that
//     opens under one of the sprout's box keys on record, active or in
//     grace, against the tenant's keys (pki.OpenFromSprout): purpose
//     s2f.facts, tenant tenantID and sprout ID the subject's, no ReplyTo.
//     A plaintext report is refused (ErrPlaintextFacts) and marks the
//     sprout as needing an upgrade; anything that doesn't open is refused.
//   - It must be fresh (IssuedAt within payloadbox.DefaultMaxSkew) and not
//     seen before on this replica (factsGuard).
//   - The sealed body's sprout_id must equal the subject's. A body that
//     names another sprout (or none) is dropped whole.
//   - Rows are written with props.SetPropForTenant, whose primary key is
//     (tenant_id, sprout_id, name), so the store is keyed on the tenant of
//     the connection the message arrived on and the subject's sprout,
//     together.
//
// A refused report changes nothing that was stored.
func handleFactsMsg(tenantID, subject string, header nats.Header, data []byte) {
	sf, err := openFactsMsg(tenantID, subject, header, data)
	if err != nil {
		log.Warnf("facts: refusing a report on %s (tenant %s): %v", subject, tenantID, err)
		return
	}
	heartbeat.ClearUpgradeRequired(tenantID, sf.SproutID)
	storeFacts(tenantID, *sf)
	log.Noticef("facts: received system facts from %s (os=%s arch=%s)", sf.SproutID, sf.OS, sf.Arch)
}

// openFactsMsg runs every check handleFactsMsg lists and returns the
// opened report.
func openFactsMsg(tenantID, subject string, header nats.Header, data []byte) (*SystemFacts, error) {
	if tenantID == "" {
		return nil, errors.New("listener has no tenant")
	}
	sid, ok := factsSubjectSproutID(subject)
	if !ok {
		return nil, errors.New("unexpected subject")
	}
	if header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		heartbeat.MarkUpgradeRequired(tenantID, sid, heartbeat.UpgradeKindFacts)
		return nil, ErrPlaintextFacts
	}
	msg, err := pki.OpenFromSprout(tenantID, sid, payloadbox.PurposeFacts, data)
	if err != nil {
		return nil, err
	}
	if msg.ReplyTo != "" {
		return nil, payloadbox.ErrOpen
	}
	if err := factsGuard.Accept(msg, tenantID, sid); err != nil {
		return nil, err
	}
	var sf SystemFacts
	if err := json.Unmarshal(msg.Body, &sf); err != nil {
		return nil, fmt.Errorf("decoding the sealed report: %w", err)
	}
	if sf.SproutID != sid {
		return nil, fmt.Errorf("the sealed report names sprout %q", sf.SproutID)
	}
	return &sf, nil
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
	props.SetPropForTenantWithTTL(tenantID, sid, PropHostname, sf.Hostname, HostnamePropTTL)
	props.SetPropForTenant(tenantID, sid, PropGoVersion, sf.GoVersion)
	props.SetPropForTenant(tenantID, sid, PropNumCPU, fmt.Sprintf("%d", sf.NumCPU))
	storeSproutVersion(tenantID, sid, sf.SproutVersion)
	if len(sf.IPAddresses) > 0 {
		ipsJSON, _ := json.Marshal(sf.IPAddresses)
		props.SetPropForTenant(tenantID, sid, PropIPAddresses, string(ipsJSON))
	}
	storeHardwareFacts(tenantID, sid, sf.Hardware)
}

// HostnamePropTTL is how long the hostname fact's prop lives: 10 minutes
// (owner decision on PR 84), rather than props.DefaultPropTTL's 5. Recipe
// templates' hostname function reads it and falls back to the sprout ID
// once it has expired. Only the hostname gets the longer lifetime: saasapi
// recovers the write time of os, arch and sprout_version from their expiry
// minus props.DefaultPropTTL (internal/saasapi/fleet_sprout_facts.go).
const HostnamePropTTL = 10 * time.Minute

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
