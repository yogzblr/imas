package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// AcceptanceScriptName is uat/hub/core's script for what the W1 cases
// (B1, E1, D1, U1, RB1) need to see or nudge inside the core hub: rows,
// objects, Valkey keys, OpenBao paths, the operator plane's tenant purge,
// restarts and sweeps. It sits next to bind-tenant.sh and takes the same
// first three arguments (BindConfig); each verb prints one JSON line.
const AcceptanceScriptName = "acceptance.sh"

// ErrNoCoreAccess is returned when the harness has no way to run
// acceptance.sh: it needs what bind-tenant.sh needs.
var ErrNoCoreAccess = errors.New("no way to look inside the core hub: uat/hub/core/" + AcceptanceScriptName +
	" needs the core kubeconfig ($IMAS_UAT_CORE_KUBECONFIG), the endpoints file ($IMAS_UAT_ENDPOINTS), the state " +
	"directory and the uat/hub/core directory (harness.json's bind_tenant, or run.sh's defaults)")

// The UAT farmer chart's OpenBao names for a tenant's keys (values
// openbao.tenantBox.kvMount and kvPath, openbao.natsSign's transit mount;
// the chart defaults, which uat/hub/core keeps).
const (
	TenantBoxKVMount = "secret"
	TenantBoxKVPath  = "imas/tenant-x25519"
	NatsTransitMount = "transit"
)

// CanReachCore reports whether CoreProbe can run.
func (f *Fleet) CanReachCore() bool { return f.AcceptanceExec != nil || f.Env.Bind.Enabled() }

// CoreProbe runs acceptance.sh verb args, with stdin (may be nil), and
// returns the JSON line it printed. A non-zero exit is an error quoting
// the end of its stderr; it never prints a secret.
func (f *Fleet) CoreProbe(ctx context.Context, stdin []byte, verb string, args ...string) (json.RawMessage, error) {
	if !f.CanReachCore() {
		return nil, ErrNoCoreAccess
	}
	b := f.Env.Bind
	full := append([]string{b.Kubeconfig, b.Endpoints, b.StateDir, verb}, args...)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var stdout, stderr []byte
	var runErr error
	if f.AcceptanceExec != nil {
		stdout, stderr, runErr = f.AcceptanceExec(cctx, full, stdin)
	} else {
		var so, se bytes.Buffer
		cmd := exec.CommandContext(cctx, filepath.Join(filepath.Dir(b.Script), AcceptanceScriptName), full...)
		cmd.Stdout, cmd.Stderr = &so, &se
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		cmd.WaitDelay = time.Second
		runErr = cmd.Run()
		stdout, stderr = so.Bytes(), se.Bytes()
	}
	if runErr != nil {
		return nil, fmt.Errorf("%s %s: %v: %s", AcceptanceScriptName, verb, runErr, tail(stderr, 600))
	}
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if !json.Valid([]byte(last)) || last == "" {
		return nil, fmt.Errorf("%s %s printed no JSON line: %s", AcceptanceScriptName, verb, tail(stdout, 300))
	}
	return json.RawMessage(last), nil
}

// probeInto runs CoreProbe and decodes its line into v.
func (f *Fleet) probeInto(ctx context.Context, v any, stdin []byte, verb string, args ...string) error {
	raw, err := f.CoreProbe(ctx, stdin, verb, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s %s: decoding %s: %w", AcceptanceScriptName, verb, raw, err)
	}
	return nil
}

// PurgeTenant starts the purge of an offboarded tenant through saasapi's
// operator plane (POST /v1/operator/tenants/{tenant_id}/purge). The
// answer is returned whatever its status.
func (f *Fleet) PurgeTenant(ctx context.Context, tenantID string) (OperatorAnswer, error) {
	var a OperatorAnswer
	err := f.probeInto(ctx, &a, nil, "purge", tenantID)
	if err == nil && a.Status == 0 {
		err = fmt.Errorf("%s purge printed no status", AcceptanceScriptName)
	}
	return a, err
}

// InventoryObject is one object prefix of an inventory.
type InventoryObject struct {
	Category string `json:"category"`
	Bucket   string `json:"bucket"`
	Prefix   string `json:"prefix"`
}

// InventoryValkey is one Valkey key pattern of an inventory.
type InventoryValkey struct {
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
}

// InventorySpec is what acceptance.sh inventory counts for one tenant.
type InventorySpec struct {
	TenantID  string            `json:"tenant_id"`
	Tables    []string          `json:"tables,omitempty"`
	Objects   []InventoryObject `json:"objects,omitempty"`
	Valkey    []InventoryValkey `json:"valkey,omitempty"`
	OpenBaoKV []string          `json:"openbao_kv,omitempty"`
	Transit   []string          `json:"transit,omitempty"`
}

// TenantDataSpec is everything a purge erases of tenantID, from
// internal/tenantpurge's inventory (the lists its own test keeps equal to
// the schema, the object roots and the Valkey prefixes): every farmer and
// saas table, every object prefix, every Valkey prefix, the tenant's KV
// keypair and its two Transit keys. Each must count 0 after the purge.
func TenantDataSpec(tenantID string) InventorySpec {
	s := InventorySpec{TenantID: tenantID}
	for _, t := range tenantpurge.FarmerTables {
		s.Tables = append(s.Tables, "farmer."+t)
	}
	for _, t := range tenantpurge.SaasTables {
		s.Tables = append(s.Tables, "saas."+t)
	}
	for _, p := range tenantpurge.ObjectPrefixes(tenantID) {
		s.Objects = append(s.Objects, InventoryObject{Category: p.Category, Bucket: p.Bucket, Prefix: p.Prefix})
	}
	for _, p := range tenantpurge.PurgeValkeyPrefixes {
		s.Valkey = append(s.Valkey, InventoryValkey{Category: tenantpurge.ValkeyCategory(p), Pattern: tenantpurge.ValkeyPattern(p, tenantID)})
	}
	s.OpenBaoKV = []string{TenantBoxKVMount + "/" + TenantBoxKVPath + "/tenants/" + tenantID}
	s.Transit = []string{NatsTransitMount + "/" + natskeys.TenantSigningKey(tenantID), NatsTransitMount + "/" + natskeys.TenantAccountKey(tenantID)}
	return s
}

// TombstoneSpec is what a purge keeps of tenantID (internal/tenantpurge
// KeepTables in the farmer and saas schemas): each must count at least 1.
func TombstoneSpec(tenantID string) InventorySpec {
	s := InventorySpec{TenantID: tenantID}
	for k := range tenantpurge.KeepTables {
		schema, table, _ := strings.Cut(k, ".")
		if table == "job_leases" {
			continue // keyed pushall:<tenant_id>, not by a tenant_id column
		}
		s.Tables = append(s.Tables, schema+"."+table)
	}
	return s
}

// Inventory counts what spec names: by table ("farmer.props"), by
// category ("objects.recipes", "valkey.heartbeat"), and "kv:<path>" and
// "transit:<mount>/<key>" (0 or 1).
func (f *Fleet) Inventory(ctx context.Context, spec InventorySpec) (map[string]int, error) {
	in, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	var out struct {
		Counts map[string]int `json:"counts"`
	}
	if err := f.probeInto(ctx, &out, in, "inventory"); err != nil {
		return nil, err
	}
	return out.Counts, nil
}

// InventoryKeys are the keys Inventory answers for spec, in order.
func InventoryKeys(spec InventorySpec) []string {
	var out []string
	out = append(out, spec.Tables...)
	for _, o := range spec.Objects {
		out = append(out, o.Category)
	}
	for _, v := range spec.Valkey {
		out = append(out, v.Category)
	}
	for _, p := range spec.OpenBaoKV {
		out = append(out, "kv:"+p)
	}
	for _, t := range spec.Transit {
		out = append(out, "transit:"+t)
	}
	return out
}

// ProvisioningJob is one row of saas.provisioning_jobs.
type ProvisioningJob struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// ProvisioningJobs lists a tenant's provisioning jobs, oldest first.
func (f *Fleet) ProvisioningJobs(ctx context.Context, tenantID string) ([]ProvisioningJob, error) {
	var out struct {
		Jobs []ProvisioningJob `json:"jobs"`
	}
	err := f.probeInto(ctx, &out, nil, "provisioning-jobs", tenantID)
	return out.Jobs, err
}

// BackdateSpec moves a tenant's rows' times back by Seconds (acceptance.sh
// backdate): its offboarded_at, and the named provisioning jobs, batches
// (with their items) and enrollment keys.
type BackdateSpec struct {
	TenantID         string   `json:"tenant_id"`
	Seconds          int64    `json:"seconds"`
	Offboarded       bool     `json:"offboarded,omitempty"`
	ProvisioningJobs []string `json:"provisioning_jobs,omitempty"`
	Batches          []string `json:"batches,omitempty"`
	EnrollmentKeys   []string `json:"enrollment_keys,omitempty"`
}

// Backdate applies spec and returns the rows changed.
func (f *Fleet) Backdate(ctx context.Context, spec BackdateSpec) (int, error) {
	in, err := json.Marshal(spec)
	if err != nil {
		return 0, err
	}
	var out struct {
		Updated int `json:"updated"`
	}
	err = f.probeInto(ctx, &out, in, "backdate")
	return out.Updated, err
}

// RestartCoreWorkload rolls farmer or saasapi and waits for the rollout.
func (f *Fleet) RestartCoreWorkload(ctx context.Context, name string) error {
	var out struct {
		Restarted string `json:"restarted"`
	}
	return f.probeInto(ctx, &out, nil, "restart", name)
}

// Sweep runs a retention sweep now: "recipe-audit" (farmer's sweep, by
// clearing its last run and restarting farmer; it runs at start, so it
// may still be going when this returns) or "log-retention" (the log
// retention CronJob once, waited for).
func (f *Fleet) Sweep(ctx context.Context, which string) error {
	var out map[string]any
	return f.probeInto(ctx, &out, nil, "sweep", which)
}

// RetentionInfo is what acceptance.sh retention reads off the workloads.
type RetentionInfo struct {
	Farmer     map[string]string `json:"farmer"`
	SaaSAPI    map[string]string `json:"saasapi"`
	LogShipper struct {
		DaemonSet bool `json:"daemonset"`
		ConfigMap bool `json:"configmap"`
		Ready     bool `json:"ready"`
	} `json:"log_shipper"`
	LogRetention struct {
		CronJob  bool   `json:"cronjob"`
		Schedule string `json:"schedule"`
		Days     int    `json:"days"`
	} `json:"log_retention"`
}

// Retention reads the retention settings the workloads run with.
func (f *Fleet) Retention(ctx context.Context) (RetentionInfo, error) {
	var out RetentionInfo
	err := f.probeInto(ctx, &out, nil, "retention")
	return out, err
}

// Objects lists every key under prefix in bucket (recipes, jobs,
// sprout_jwts, accounts or logs).
func (f *Fleet) Objects(ctx context.Context, bucket, prefix string) ([]string, error) {
	var out struct {
		Keys []string `json:"keys"`
	}
	err := f.probeInto(ctx, &out, nil, "objects", bucket, prefix)
	return out.Keys, err
}

// PutObject writes body at key in bucket.
func (f *Fleet) PutObject(ctx context.Context, bucket, key string, body []byte) error {
	var out map[string]any
	return f.probeInto(ctx, &out, body, "put-object", bucket, key)
}

// DeleteObject deletes key in bucket.
func (f *Fleet) DeleteObject(ctx context.Context, bucket, key string) error {
	var out map[string]any
	return f.probeInto(ctx, &out, nil, "delete-object", bucket, key)
}

// UpgradeMarkerKey is the Valkey key of the "needs upgrade" marker of a
// tenant's sprout (internal/heartbeat upgrade.go, named by
// internal/tenantpurge).
func UpgradeMarkerKey(tenantID, sproutID string) string {
	return tenantpurge.ValkeyUpgradePrefix + "{" + tenantID + ":" + sproutID + "}"
}

// ValkeyGet reads one sprout's Valkey key.
func (f *Fleet) ValkeyGet(ctx context.Context, key string) (exists bool, value string, err error) {
	var out struct {
		Exists bool   `json:"exists"`
		Value  string `json:"value"`
	}
	err = f.probeInto(ctx, &out, nil, "valkey-get", key)
	return out.Exists, out.Value, err
}

// Prop is one farmer.props row.
type Prop struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	ExpiresIn int    `json:"expires_in"`
}

// Props reads a tenant's sprout's props, by name.
func (f *Fleet) Props(ctx context.Context, tenantID, sproutID string) (map[string]Prop, error) {
	var out struct {
		Props []Prop `json:"props"`
	}
	if err := f.probeInto(ctx, &out, nil, "props", tenantID, sproutID); err != nil {
		return nil, err
	}
	m := make(map[string]Prop, len(out.Props))
	for _, p := range out.Props {
		m[p.Name] = p
	}
	return m, nil
}

// JobStatus reads farmer.job_status for one job.
func (f *Fleet) JobStatus(ctx context.Context, tenantID, sproutID, jid string) (exists bool, status string, err error) {
	var out struct {
		Exists bool   `json:"exists"`
		Status string `json:"status"`
	}
	err = f.probeInto(ctx, &out, nil, "job-status", tenantID, sproutID, jid)
	return out.Exists, out.Status, err
}

// LogCount counts the lines of farmer's or saasapi's logs since d ago
// that hold needle.
func (f *Fleet) LogCount(ctx context.Context, workload string, d time.Duration, needle string) (int, error) {
	var out struct {
		Count int `json:"count"`
	}
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	err := f.probeInto(ctx, &out, []byte(needle), "log-count", workload, strconv.Itoa(secs))
	return out.Count, err
}
