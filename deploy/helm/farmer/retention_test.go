package farmerchart

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Retention (docs/retention.md, U4): every setting that decides how long
// data is kept is a chart value that reaches its pod as the variable the
// binary reads.

// retentionEnv is name -> value of the variables of container c of the
// workload w, "" for one not rendered.
func retentionEnv(t *testing.T, docs []obj, kind, name, c string, vars ...string) map[string]string {
	t.Helper()
	env := envMap(container(t, find(t, docs, kind, name), c))
	out := map[string]string{}
	for _, v := range vars {
		if e, ok := env[v]; ok {
			out[v] = e["value"].(string)
		} else {
			out[v] = ""
		}
	}
	return out
}

var farmerRetentionVars = []string{"IMAS_JOB_LOG_TTL", "IMAS_RECIPE_AUDIT_RETENTION_DAYS", "IMAS_BOX_KEY_GRACE_DURATION"}

func TestRetentionEnv(t *testing.T) {
	for _, tc := range []struct {
		args         []string
		farmer       map[string]string
		terminalRows string
	}{
		// The defaults, as values.yaml writes them.
		{nil, map[string]string{"IMAS_JOB_LOG_TTL": "720h", "IMAS_RECIPE_AUDIT_RETENTION_DAYS": "365", "IMAS_BOX_KEY_GRACE_DURATION": "24h"}, "2160h"},
		// Each set.
		{[]string{"--set-string", "farmer.retention.jobLogTTL=2160h", "--set", "farmer.retention.recipeAuditDays=30",
			"--set-string", "farmer.retention.boxKeyGrace=1h", "--set-string", "saasapi.retention.terminalRows=720h"},
			map[string]string{"IMAS_JOB_LOG_TTL": "2160h", "IMAS_RECIPE_AUDIT_RETENTION_DAYS": "30", "IMAS_BOX_KEY_GRACE_DURATION": "1h"}, "720h"},
		// 0 for recipe audit records is "for ever", and is rendered (not
		// dropped as an empty value would be).
		{[]string{"--set", "farmer.retention.recipeAuditDays=0"},
			map[string]string{"IMAS_JOB_LOG_TTL": "720h", "IMAS_RECIPE_AUDIT_RETENTION_DAYS": "0", "IMAS_BOX_KEY_GRACE_DURATION": "24h"}, "2160h"},
		// Each unset: no variable, the binary's default (the same).
		{[]string{"--set", "farmer.retention.jobLogTTL=null", "--set", "farmer.retention.recipeAuditDays=null",
			"--set", "farmer.retention.boxKeyGrace=null", "--set", "saasapi.retention.terminalRows=null"},
			map[string]string{"IMAS_JOB_LOG_TTL": "", "IMAS_RECIPE_AUDIT_RETENTION_DAYS": "", "IMAS_BOX_KEY_GRACE_DURATION": ""}, ""},
		{[]string{"--set-string", "farmer.retention.jobLogTTL=", "--set-string", "farmer.retention.recipeAuditDays=",
			"--set-string", "farmer.retention.boxKeyGrace=", "--set-string", "saasapi.retention.terminalRows="},
			map[string]string{"IMAS_JOB_LOG_TTL": "", "IMAS_RECIPE_AUDIT_RETENTION_DAYS": "", "IMAS_BOX_KEY_GRACE_DURATION": ""}, ""},
	} {
		docs := mustRender(t, tc.args...)
		if got := retentionEnv(t, docs, "Deployment", "t-farmer", "farmer", farmerRetentionVars...); !reflect.DeepEqual(got, tc.farmer) {
			t.Errorf("%v: farmer %v, want %v", tc.args, got, tc.farmer)
		}
		if got := retentionEnv(t, docs, "Deployment", "t-farmer-saasapi", "saasapi", "SAASAPI_TERMINAL_ROW_RETENTION"); got["SAASAPI_TERMINAL_ROW_RETENTION"] != tc.terminalRows {
			t.Errorf("%v: SAASAPI_TERMINAL_ROW_RETENTION %q, want %q", tc.args, got["SAASAPI_TERMINAL_ROW_RETENTION"], tc.terminalRows)
		}
	}
	mustFail(t, "farmer.retention.jobLogTTL must be a quoted Go duration", "--set", "farmer.retention.jobLogTTL=720")
	mustFail(t, "farmer.retention.jobLogTTL must be a quoted Go duration", "--set-string", "farmer.retention.jobLogTTL=30 days")
	mustFail(t, "farmer.retention.boxKeyGrace must be a quoted Go duration", "--set-string", "farmer.retention.boxKeyGrace=1d")
	mustFail(t, "saasapi.retention.terminalRows must be a quoted Go duration", "--set-string", "saasapi.retention.terminalRows=90d")
	mustFail(t, "farmer.retention.recipeAuditDays must be a whole number of days from 0 to 3650", "--set", "farmer.retention.recipeAuditDays=3651")
	mustFail(t, "farmer.retention.recipeAuditDays must be a whole number of days from 0 to 3650", "--set", "farmer.retention.recipeAuditDays=-1")
	mustFail(t, "farmer.retention.recipeAuditDays must be a whole number of days from 0 to 3650", "--set", "farmer.retention.recipeAuditDays=1.5")
	mustFail(t, "farmer.retention.recipeAuditDays must be a whole number of days from 0 to 3650", "--set-string", "farmer.retention.recipeAuditDays=365d")
}

// logShippingOn ships to an S3 endpoint of the operator's (not the
// gateway).
var logShippingOn = []string{
	"--set", "objectStore.endpoint=s3.imas-core.svc:9000",
	"--set", "objectStore.useSSL=false",
	"--set", "objectStore.bucket=imas-recipes",
	"--set", "objectStore.jobBucket=imas-jobs",
	"--set", "objectStore.credentialsSecret=imas-s3-farmer",
	"--set", "logShipping.enabled=true",
	"--set", "logShipping.credentialsSecret=imas-logs-writer",
	"--set", "logShipping.retention.credentialsSecret=imas-logs-retention",
}

func logArgs(extra ...string) []string { return append(slices.Clone(logShippingOn), extra...) }

func TestLogShippingOffByDefault(t *testing.T) {
	for _, args := range [][]string{nil, {"-f", ciValues(t, "default-values.yaml")}, {"-f", ciValues(t, "external-values.yaml")}} {
		for _, d := range mustRender(t, args...) {
			if n, _ := get(d, "metadata", "name").(string); strings.Contains(n, "log-shipper") || strings.Contains(n, "log-retention") {
				t.Errorf("%v: %s %s rendered with logShipping off", args, d["kind"], n)
			}
		}
	}
}

// fluentBitConfig parses the shipper's rendered configuration.
func fluentBitConfig(t *testing.T, docs []obj) map[string]any {
	t.Helper()
	var c map[string]any
	if err := yaml.Unmarshal([]byte(get(find(t, docs, "ConfigMap", "t-farmer-log-shipper"), "data", "fluent-bit.yaml").(string)), &c); err != nil {
		t.Fatalf("fluent-bit.yaml: %v", err)
	}
	return c
}

func retentionArgs(t *testing.T, docs []obj) []string {
	t.Helper()
	cj := find(t, docs, "CronJob", "t-farmer-log-retention")
	c := get(cj, "spec", "jobTemplate", "spec", "template", "spec", "containers", 0).(obj)
	var out []string
	for _, a := range c["args"].([]any) {
		out = append(out, a.(string))
	}
	return out
}

func TestLogShippingRenders(t *testing.T) {
	docs := mustRender(t, logArgs()...)
	ds := find(t, docs, "DaemonSet", "t-farmer-log-shipper")
	ps := podSpec(ds)
	if ps["automountServiceAccountToken"] != false || ps["serviceAccountName"] != "imas-log-shipper" {
		t.Errorf("service account %v", ps["serviceAccountName"])
	}
	fb := container(t, ds, "fluent-bit")
	if fb["image"] != "docker.io/fluent/fluent-bit@sha256:aff743e1a5e61d036d10a4472d67cdd7a6b408c92218eb86e3f301e2bac7817a" {
		t.Errorf("image %v, want the pinned digest", fb["image"])
	}
	sc := fb["securityContext"].(obj)
	if sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false || !reflect.DeepEqual(get(sc, "capabilities", "drop"), []any{"ALL"}) {
		t.Errorf("security %v", sc)
	}
	env := envMap(fb)
	for k, key := range map[string]string{"AWS_ACCESS_KEY_ID": "access-key-id", "AWS_SECRET_ACCESS_KEY": "secret-access-key"} {
		ref := get(env[k], "valueFrom", "secretKeyRef")
		if get(ref, "name") != "imas-logs-writer" || get(ref, "key") != key {
			t.Errorf("%s from %v", k, ref)
		}
	}
	mounts := byName(fb["volumeMounts"])
	if get(mounts["varlog"], "readOnly") != true || get(mounts["config"], "readOnly") != true {
		t.Errorf("mounts %v: /var/log and the config read-only", fb["volumeMounts"])
	}
	vols := byName(ps["volumes"])
	if get(vols["varlog"], "hostPath", "path") != "/var/log" || get(vols["config"], "configMap", "name") != "t-farmer-log-shipper" {
		t.Errorf("volumes %v", ps["volumes"])
	}

	c := fluentBitConfig(t, docs)
	in := get(c, "pipeline", "inputs", 0).(map[string]any)
	if in["name"] != "tail" || in["path"] != "/var/log/containers/*_imas-core_*.log" {
		t.Errorf("input %v: this release's namespace", in)
	}
	out := get(c, "pipeline", "outputs", 0).(map[string]any)
	for k, want := range map[string]any{"name": "s3", "bucket": "imas-logs", "endpoint": "http://s3.imas-core.svc:9000",
		"region": "us-east-1", "s3_key_format": "/logs/%Y/%m/%d/$TAG[4]-%H%M%S-$UUID.gz", "use_put_object": "on"} {
		if out[k] != want {
			t.Errorf("output %s = %v, want %v", k, out[k], want)
		}
	}

	args := retentionArgs(t, docs)
	for _, want := range []string{"log-retention", "-endpoint=s3.imas-core.svc:9000", "-use-ssl=false", "-bucket=imas-logs",
		"-prefix=logs/", "-days=30", "-credentials-dir=/var/run/secrets/imas/log-retention"} {
		if !slices.Contains(args, want) {
			t.Errorf("retention args %v lack %s", args, want)
		}
	}
	cj := find(t, docs, "CronJob", "t-farmer-log-retention")
	if get(cj, "spec", "schedule") != "17 3 * * *" || get(cj, "spec", "concurrencyPolicy") != "Forbid" {
		t.Errorf("schedule %v", get(cj, "spec"))
	}
	jps := get(cj, "spec", "jobTemplate", "spec", "template", "spec").(obj)
	if get(jps, "securityContext", "runAsNonRoot") != true || get(jps, "volumes", 0, "secret", "secretName") != "imas-logs-retention" {
		t.Errorf("job pod %v", jps)
	}

	// The shipper may reach the object store and DNS, and nothing dials it.
	np := find(t, docs, "NetworkPolicy", "t-farmer-log-shipper")
	if ports := egressPorts(np); !slices.Contains(ports, 9000) || len(get(np, "spec", "ingress").([]any)) != 0 {
		t.Errorf("shipper policy %v", np["spec"])
	}
	if ports := egressPorts(find(t, docs, "NetworkPolicy", "t-farmer-log-retention")); !slices.Contains(ports, 9000) {
		t.Errorf("retention policy egress %v", ports)
	}
}

// The retention days: set and unset reach the CronJob, 0 and null are the
// default (never "delete at once").
func TestLogRetentionDays(t *testing.T) {
	for set, want := range map[string]string{"": "-days=30", "0": "-days=30", "null": "-days=30", "90": "-days=90", "3650": "-days=3650"} {
		args := logArgs()
		if set != "" {
			args = append(args, "--set", "logShipping.retention.days="+set)
		}
		if got := retentionArgs(t, mustRender(t, args...)); !slices.Contains(got, want) {
			t.Errorf("days %q: args %v, want %s", set, got, want)
		}
	}
}

func TestLogShippingVersity(t *testing.T) {
	docs := mustRender(t, versityArgs("--set", "logShipping.enabled=true", "--set", "logShipping.credentialsSecret=imas-logs-writer",
		"--set", "logShipping.retention.credentialsSecret=imas-logs-retention")...)
	plan := planOf(t, docs)
	var found bool
	for _, b := range plan.Buckets {
		if b.Name != "imas-logs" {
			continue
		}
		found = true
		got := map[string][]string{}
		for _, s := range b.Statements {
			got[s.User+" "+strings.Join(s.Resources, ",")] = s.Actions
		}
		want := map[string][]string{
			"logs-writer arn:aws:s3:::imas-logs/logs/*":    {"s3:PutObject"},
			"logs-retention arn:aws:s3:::imas-logs":        {"s3:GetBucketLocation", "s3:ListBucket"},
			"logs-retention arn:aws:s3:::imas-logs/logs/*": {"s3:DeleteObject"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("log bucket statements %v, want %v", got, want)
		}
	}
	if !found {
		t.Fatal("no log bucket in the createBuckets plan")
	}
	users := projectedUsers(t, versityDeploy(t, docs), "users")
	if users["logs-writer"]["secret"] != "imas-logs-writer" || users["logs-retention"]["secret"] != "imas-logs-retention" {
		t.Errorf("gateway users %v", users)
	}
	out := get(fluentBitConfig(t, docs), "pipeline", "outputs", 0).(map[string]any)
	if out["endpoint"] != "http://"+versityEndpoint {
		t.Errorf("output endpoint %v, want the gateway", out["endpoint"])
	}
	if args := retentionArgs(t, docs); !slices.Contains(args, "-endpoint="+versityEndpoint) || !slices.Contains(args, "-use-ssl=false") {
		t.Errorf("retention args %v, want the gateway", args)
	}
	// The gateway admits the shipper and the CronJob.
	gw := find(t, docs, "NetworkPolicy", "t-farmer-versity")
	var comps []string
	for _, f := range get(gw, "spec", "ingress", 0, "from").([]any) {
		if c, ok := get(f, "podSelector", "matchLabels", "app.kubernetes.io/component").(string); ok {
			comps = append(comps, c)
		}
	}
	for _, c := range []string{"log-shipper", "log-retention"} {
		if !slices.Contains(comps, c) {
			t.Errorf("gateway ingress %v lacks %s", comps, c)
		}
	}
}

// existingConfigMap: the operator's configuration, no chart output, no
// CronJob, no gateway users for logs.
func TestLogShippingExistingConfigMap(t *testing.T) {
	docs := mustRender(t, "--set", "logShipping.enabled=true", "--set", "logShipping.existingConfigMap=my-fluent-bit")
	if has(docs, "ConfigMap", "t-farmer-log-shipper") || has(docs, "CronJob", "t-farmer-log-retention") {
		t.Error("the chart's output or CronJob rendered with existingConfigMap")
	}
	ds := find(t, docs, "DaemonSet", "t-farmer-log-shipper")
	if get(byName(podSpec(ds)["volumes"])["config"], "configMap", "name") != "my-fluent-bit" {
		t.Errorf("config volume %v", podSpec(ds)["volumes"])
	}
	if container(t, ds, "fluent-bit")["env"] != nil {
		t.Error("the chart's writer credential rendered with existingConfigMap")
	}
}

func TestLogShippingValidation(t *testing.T) {
	for _, tc := range []struct {
		want string
		args []string
	}{
		{"logShipping.credentialsSecret is required", logArgs("--set", "logShipping.credentialsSecret=")},
		{"logShipping.retention.credentialsSecret is required", logArgs("--set", "logShipping.retention.credentialsSecret=")},
		{"logShipping.credentialsSecret must differ from logShipping.retention.credentialsSecret", logArgs("--set", "logShipping.retention.credentialsSecret=imas-logs-writer")},
		{"logShipping.credentialsSecret must differ from objectStore.credentialsSecret", logArgs("--set", "logShipping.credentialsSecret=imas-s3-farmer")},
		{"logShipping.retention.credentialsSecret must differ from objectStore.credentialsSecret", logArgs("--set", "logShipping.retention.credentialsSecret=imas-s3-farmer")},
		{"logShipping.bucket \"imas-jobs\" must differ from objectStore.jobBucket", logArgs("--set", "logShipping.bucket=imas-jobs")},
		{"logShipping.bucket \"Logs\" must be 3 to 63", logArgs("--set", "logShipping.bucket=Logs")},
		{"logShipping.prefix \"logs\" must be a key root", logArgs("--set", "logShipping.prefix=logs")},
		{"logShipping.prefix \"/logs/\" must be a key root", logArgs("--set", "logShipping.prefix=/logs/")},
		{"logShipping.retention.days must be a whole number of days from 0 to 3650", logArgs("--set", "logShipping.retention.days=3651")},
		{"logShipping.retention.days must be a whole number of days from 0 to 3650", logArgs("--set", "logShipping.retention.days=-1")},
		{"logShipping.retention.days must be a whole number of days from 0 to 3650", logArgs("--set-string", "logShipping.retention.days=30d")},
		{"logShipping.uploadTimeout must be a quoted time", logArgs("--set-string", "logShipping.uploadTimeout=10")},
		{"logShipping.totalFileSize must be a size", logArgs("--set-string", "logShipping.totalFileSize=50MB")},
		{"logShipping.image.digest is required", logArgs("--set", "logShipping.image.digest=")},
		{"logShipping.enabled needs an object store", []string{"--set", "logShipping.enabled=true",
			"--set", "logShipping.credentialsSecret=a", "--set", "logShipping.retention.credentialsSecret=b"}},
	} {
		mustFail(t, tc.want, tc.args...)
	}
}
