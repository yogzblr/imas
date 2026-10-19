package harness

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
