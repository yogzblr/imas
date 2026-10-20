package harness

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/tenantpurge"
	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

// acceptance.sh: found next to bind-tenant.sh, given the common arguments,
// the verb and its stdin; its last JSON line is the answer; a failure
// quotes its stderr; without a way in, ErrNoCoreAccess.
func TestCoreProbe(t *testing.T) {
	f, _ := fakeFleet(t)
	f.Env.Bind = BindConfig{}
	if f.CanReachCore() {
		t.Fatal("no bind config and no AcceptanceExec, but the core is reachable")
	}
	if _, err := f.CoreProbe(ctx(t), nil, "retention"); !errors.Is(err, ErrNoCoreAccess) {
		t.Fatalf("without a configuration: %v", err)
	}

	dir := t.TempDir()
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$(dirname \"$0\")/args\"\ncat >\"$(dirname \"$0\")/stdin\"\n" +
		"echo '[uat/hub/core] noise' >&2\necho 'a log line'\necho '{\"updated\":3}'\n"
	if err := os.WriteFile(filepath.Join(dir, AcceptanceScriptName), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	f.Env.Bind = BindConfig{Script: filepath.Join(dir, "bind-tenant.sh"), Kubeconfig: "/k", Endpoints: "/e", StateDir: "/s"}
	n, err := f.Backdate(ctx(t), BackdateSpec{TenantID: "t_aaaaaaaaaaaaaaaa", Seconds: 60, Offboarded: true})
	if err != nil || n != 3 {
		t.Fatalf("Backdate: %d, %v", n, err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if got := strings.Join(strings.Fields(string(args)), " "); got != "/k /e /s backdate" {
		t.Errorf("arguments %q", got)
	}
	in, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	if string(in) != `{"tenant_id":"t_aaaaaaaaaaaaaaaa","seconds":60,"offboarded":true}` {
		t.Errorf("stdin %s", in)
	}

	f.AcceptanceExec = func(_ context.Context, args []string, _ []byte) ([]byte, []byte, error) {
		return []byte("not json\n"), []byte("kubectl exec failed: secret"), errors.New("exit status 1")
	}
	if _, err := f.CoreProbe(ctx(t), nil, "props", "t_aaaaaaaaaaaaaaaa", "web-01"); err == nil || !strings.Contains(err.Error(), "kubectl exec failed") {
		t.Errorf("a failed run: %v", err)
	}
	f.AcceptanceExec = func(context.Context, []string, []byte) ([]byte, []byte, error) {
		return []byte("no json at all\n"), nil, nil
	}
	if _, err := f.CoreProbe(ctx(t), nil, "retention"); err == nil || !strings.Contains(err.Error(), "printed no JSON line") {
		t.Errorf("no JSON: %v", err)
	}
	f.AcceptanceExec = func(context.Context, []string, []byte) ([]byte, []byte, error) {
		return []byte(`{"status":0}` + "\n"), nil, nil
	}
	if _, err := f.PurgeTenant(ctx(t), "t_aaaaaaaaaaaaaaaa"); err == nil {
		t.Error("a purge answer with no status is accepted")
	}
}

// The inventory of a purge is internal/tenantpurge's, in full: every
// table, prefix and Valkey prefix, the KV keypair and both Transit keys;
// the tombstone keeps saas.tenants, saas.provisioning_jobs and
// farmer.pki_tenants.
func TestTenantDataSpec(t *testing.T) {
	const tid = "t_aaaaaaaaaaaaaaaa"
	s := TenantDataSpec(tid)
	if len(s.Tables) != len(tenantpurge.FarmerTables)+len(tenantpurge.SaasTables) ||
		len(s.Objects) != len(tenantpurge.ObjectPrefixes(tid)) || len(s.Valkey) != len(tenantpurge.PurgeValkeyPrefixes) {
		t.Errorf("spec %+v doesn't cover tenantpurge's lists", s)
	}
	for _, want := range []string{"farmer.props", "farmer.job_status", "saas.enrollment_keys", "saas.asset_links",
		"objects.recipes", "objects.sprout_jwts", "valkey.upgrade",
		"kv:secret/imas/tenant-x25519/tenants/" + tid, "transit:transit/nats-tsign-" + tid, "transit:transit/nats-tacct-" + tid} {
		if !slices.Contains(InventoryKeys(s), want) {
			t.Errorf("InventoryKeys lacks %s", want)
		}
	}
	for _, v := range s.Valkey {
		if !strings.Contains(v.Pattern, "{"+tid+":") {
			t.Errorf("Valkey pattern %s is not the tenant's", v.Pattern)
		}
	}
	keep := TombstoneSpec(tid)
	slices.Sort(keep.Tables)
	if !slices.Equal(keep.Tables, []string{"farmer.pki_tenants", "saas.provisioning_jobs", "saas.tenants"}) {
		t.Errorf("tombstone tables %v", keep.Tables)
	}
	if UpgradeMarkerKey(tid, "web-01") != "imas:upgrade:{"+tid+":web-01}" {
		t.Errorf("UpgradeMarkerKey %s", UpgradeMarkerKey(tid, "web-01"))
	}
}

// Every table the E1 inventories name is counted by its tenant key
// column (rig rc.15: saas.tenants has no tenant_id), and the column is
// the one the migrations give it: id, the primary key, for a tenant's own
// registry rows, which have no tenant_id; tenant_id for the rest.
// acceptance.sh's tenant_key and the fake's are the same map.
func TestInventoryKeyColumns(t *testing.T) {
	const tid = "t_aaaaaaaaaaaaaaaa"
	for _, spec := range []InventorySpec{TenantDataSpec(tid), TombstoneSpec(tid)} {
		for _, table := range spec.Tables {
			if InventoryKeyColumns[table] == "" {
				t.Errorf("%s is inventoried but has no key column in InventoryKeyColumns", table)
			}
		}
	}
	if _, ok := InventoryKeyColumns["farmer.job_leases"]; ok {
		t.Error("farmer.job_leases is keyed by name (pushall:<tenant_id>): no tenant key column counts it")
	}

	tables := map[string]migrationTable{}
	for schemaName, set := range map[string]migrations.Set{"farmer": migrations.Farmer, "saas": migrations.Saas} {
		for name, mt := range migrationTables(t, set) {
			tables[schemaName+"."+name] = mt
		}
	}
	for table, col := range InventoryKeyColumns {
		mt, ok := tables[table]
		switch {
		case !ok:
			t.Errorf("%s: no migration creates it", table)
		case !mt.columns[col]:
			t.Errorf("%s: keyed by %s, which it has no column of", table, col)
		case col == "id" && (mt.columns["tenant_id"] || !mt.primaryID):
			t.Errorf("%s: keyed by id, but it has a tenant_id column or id is not its primary key", table)
		case col != "id" && col != "tenant_id":
			t.Errorf("%s: key column %s is neither id nor tenant_id", table, col)
		}
	}
	for _, table := range []string{"saas.tenants", "farmer.pki_tenants"} {
		if InventoryKeyColumns[table] != "id" {
			t.Errorf("%s is keyed by %q, want id", table, InventoryKeyColumns[table])
		}
	}

	script := scriptTenantKey(t)
	if !maps.Equal(script, InventoryKeyColumns) {
		t.Errorf("acceptance.sh's tenant_key %v differs from InventoryKeyColumns %v", script, InventoryKeyColumns)
	}
	if fake := fakestack.TenantKeyColumns(); !maps.Equal(fake, InventoryKeyColumns) {
		t.Errorf("fakestack's tenant_key %v differs from InventoryKeyColumns %v", fake, InventoryKeyColumns)
	}
}

// migrationTable is what TestInventoryKeyColumns reads of one CREATE TABLE.
type migrationTable struct {
	columns   map[string]bool
	primaryID bool
}

var (
	createTableRe = regexp.MustCompile("(?is)CREATE TABLE(?: IF NOT EXISTS)?\\s+`?([a-z0-9_]+)`?\\s*\\((.*?)\\)\\s*ENGINE")
	columnRe      = regexp.MustCompile("(?m)^\\s*`([a-z0-9_]+)`\\s")
	addColumnRe   = regexp.MustCompile("(?i)ALTER TABLE\\s+`?([a-z0-9_]+)`?\\s+ADD COLUMN\\s+`?([a-z0-9_]+)`?")
)

// migrationTables reads every table a migration set creates, with its
// columns (and any a later ALTER TABLE adds).
func migrationTables(t *testing.T, set migrations.Set) map[string]migrationTable {
	t.Helper()
	out := map[string]migrationTable{}
	err := fs.WalkDir(set.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		b, err := fs.ReadFile(set.FS(), path)
		if err != nil {
			return err
		}
		for _, m := range createTableRe.FindAllStringSubmatch(string(b), -1) {
			mt := migrationTable{columns: map[string]bool{}, primaryID: strings.Contains(m[2], "PRIMARY KEY (`id`)")}
			for _, c := range columnRe.FindAllStringSubmatch(m[2], -1) {
				mt.columns[c[1]] = true
			}
			out[m[1]] = mt
		}
		for _, m := range addColumnRe.FindAllStringSubmatch(string(b), -1) {
			if mt, ok := out[m[1]]; ok {
				mt.columns[m[2]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no table found in the migrations: the parser is broken")
	}
	return out
}

// scriptTenantKey reads acceptance.sh's tenant_key map.
func scriptTenantKey(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "hub", "core", AcceptanceScriptName))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)declare -A tenant_key=\((.*?)\n\)`).FindSubmatch(b)
	if block == nil {
		t.Fatal("acceptance.sh has no tenant_key map")
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`\[([a-z_.]+)\]=([a-z_]+)`).FindAllSubmatch(block[1], -1) {
		out[string(m[1])] = string(m[2])
	}
	return out
}

// The verbs against the fake stack's acceptance endpoint, as the fake
// acceptance.sh forwards them: purge and the tombstone, the backlog, the
// prune, the sweeps.
func TestCoreProbeAgainstFake(t *testing.T) {
	f, s := fakeFleet(t)
	f.AcceptanceExec = fakeAcceptanceExec(t, s)
	c := ctx(t)
	tid := fakestack.TenantID(1)
	tok, err := f.Tokens.Tenant(c, 1, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	info, err := f.Retention(c)
	if err != nil || info.Farmer["IMAS_RECIPE_AUDIT_RETENTION_DAYS"] != "1" || info.SaaSAPI["SAASAPI_TERMINAL_ROW_RETENTION"] != "24h" || info.LogRetention.Days != 1 {
		t.Fatalf("retention %+v, %v", info, err)
	}

	// Objects and the dated sweeps.
	old := "logs/" + time.Now().UTC().AddDate(0, 0, -3).Format("2006/01/02") + "/x.gz"
	edge := "logs/" + time.Now().UTC().AddDate(0, 0, -1).Format("2006/01/02") + "/y.gz"
	for _, k := range []string{old, edge} {
		if err := f.PutObject(c, "logs", k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sweep(c, "log-retention"); err != nil {
		t.Fatal(err)
	}
	if keys, err := f.Objects(c, "logs", "logs/"); err != nil || !slices.Equal(keys, []string{edge}) {
		t.Errorf("after the log sweep: %v, %v", keys, err)
	}

	// Props and job status of a host's sprout.
	props, err := f.Props(c, tid, "ubuntu-01")
	if err != nil || props["os"].Value != "linux" || props["os"].ExpiresIn <= 0 {
		t.Errorf("props %+v, %v", props, err)
	}
	if ok, _, err := f.JobStatus(c, tid, "ubuntu-01", "0b5f2a2e-1b9d-4d6e-9c1a-2f3e4d5c6b7a"); ok || err != nil {
		t.Errorf("an unknown job: %v, %v", ok, err)
	}
	if ok, _, err := f.ValkeyGet(c, UpgradeMarkerKey(tid, "ubuntu-01")); ok || err != nil {
		t.Errorf("a marker on a sealed sprout: %v, %v", ok, err)
	}

	// The prune: a finished batch backdated past the retention goes.
	id, err := f.API.StartBatch(c, tok, tid, []string{"none"}, CmdRunAction(CmdRun{Cmd: "id -u"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Backdate(c, BackdateSpec{TenantID: tid, Seconds: 26 * 3600, Batches: []string{id}}); err != nil {
		t.Fatal(err)
	}
	if err := f.RestartCoreWorkload(c, "saasapi"); err != nil {
		t.Fatal(err)
	}
	if _, r, _ := f.API.GetBatch(c, tok, tid, id); !r.Is(404, "batch_not_found") {
		t.Errorf("the backdated batch after the prune: %s", r)
	}

	// The inventory takes every table with a key column, and refuses one
	// without, as acceptance.sh does.
	all := InventorySpec{TenantID: tid, Tables: slices.Sorted(maps.Keys(InventoryKeyColumns))}
	if got, err := f.Inventory(c, all); err != nil || got["saas.tenants"] != 1 || got["farmer.pki_tenants"] != 1 {
		t.Errorf("inventory of every keyed table: %v, %v", got, err)
	}
	for _, table := range []string{"farmer.job_leases", "mysql.user"} {
		if _, err := f.Inventory(c, InventorySpec{TenantID: tid, Tables: []string{table}}); err == nil {
			t.Errorf("an inventory of %s is accepted", table)
		}
	}

	// An unknown verb, and the purge of a tenant that isn't offboarded.
	if _, err := f.CoreProbe(c, nil, "frobnicate"); err == nil || !strings.Contains(err.Error(), "unknown verb") {
		t.Errorf("an unknown verb: %v", err)
	}
	if a, err := f.PurgeTenant(c, tid); err != nil || a.Status != 409 || !strings.Contains(string(a.Body), "not_offboarded") {
		t.Errorf("purging an active tenant: %+v, %v", a, err)
	}
}

// fakeAcceptanceExec runs the fake acceptance.sh the material directory
// gets, against s.
func fakeAcceptanceExec(t *testing.T, s *fakestack.Stack) func(context.Context, []string, []byte) ([]byte, []byte, error) {
	t.Helper()
	dir := t.TempDir()
	if err := s.WriteCoreMaterial(dir, ""); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return runScript(ctx, filepath.Join(dir, AcceptanceScriptName), args, stdin)
	}
}

// runScript runs a script with args and stdin, as CoreProbe does.
func runScript(ctx context.Context, path string, args []string, stdin []byte) ([]byte, []byte, error) {
	var so, se bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(stdin), &so, &se
	err := cmd.Run()
	return so.Bytes(), se.Bytes(), err
}
