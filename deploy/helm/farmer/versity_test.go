package farmerchart

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/versitysetup"
)

// The Versity Gateway (versity.enabled; design D18, H3 of
// docs/briefs/H-azure-next-runs.md): an optional S3 gateway in front of
// Azure Blob that farmer, saasapi and the accounts bucket use as their S3
// endpoint.

const versityEndpoint = "t-farmer-versity.imas-core.svc.cluster.local:7070"

// versityOn turns the gateway on with every Secret it needs, the buckets
// the createBuckets Job makes, and the accounts bucket on the gateway
// (required's accountStore.endpoint cleared).
var versityOn = []string{
	"--set", "versity.enabled=true",
	"--set", "versity.azure.credentialsSecret=imas-versity-azure",
	"--set", "versity.rootCredentials.secretName=imas-versity-root",
	"--set", "versity.accountsReader.credentialsSecret=imas-bus-accounts-reader",
	"--set", "accountStore.endpoint=",
	"--set", "objectStore.bucket=imas-recipes",
	"--set", "objectStore.jobBucket=imas-jobs",
	"--set", "objectStore.sproutJWTBucket=imas-sprout-jwts",
	"--set", "objectStore.credentialsSecret=imas-s3-farmer",
}

// withRecipes adds saasapi's recipe upload, the fourth gateway user.
var withRecipes = []string{"--set", "saasapi.recipes.enabled=true", "--set", "saasapi.recipes.credentialsSecret=imas-s3-saasapi"}

func versityArgs(extra ...string) []string {
	return append(slices.Clone(versityOn), extra...)
}

func versityDeploy(t *testing.T, docs []obj) obj {
	return find(t, docs, "Deployment", "t-farmer-versity")
}

// Off by default: nothing of the gateway renders and the S3 endpoints
// are what they were.
func TestVersityOffByDefault(t *testing.T) {
	for _, args := range [][]string{nil, {"-f", ciValues(t, "external-values.yaml")}} {
		docs := mustRender(t, args...)
		for _, d := range docs {
			n, _ := get(d, "metadata", "name").(string)
			if strings.Contains(n, "versity") {
				t.Errorf("%s %s rendered with versity.enabled=false", d["kind"], n)
			}
		}
		vals := envValues(container(t, farmerDeploy(t, docs), "farmer"))
		if strings.Contains(vals["IMAS_S3_ENDPOINT"], "versity") || strings.Contains(vals["IMAS_ACCOUNTS_S3_ENDPOINT"], "versity") {
			t.Errorf("endpoints %q %q", vals["IMAS_S3_ENDPOINT"], vals["IMAS_ACCOUNTS_S3_ENDPOINT"])
		}
	}
	docs := mustRender(t, "-f", ciValues(t, "external-values.yaml"))
	if got := envValues(container(t, farmerDeploy(t, docs), "farmer"))["IMAS_S3_ENDPOINT"]; got != "s3.example.com" {
		t.Errorf("external IMAS_S3_ENDPOINT %q", got)
	}
	if got := farmerConfig(t, docs)["s3usessl"]; got != true {
		t.Errorf("external s3usessl %v, want true", got)
	}
}

// On, the gateway's Service is every S3 endpoint the chart renders:
// farmer's recipe/job/sprout JWT store and accounts bucket, and saasapi's
// recipe upload, all plain HTTP inside the cluster.
func TestVersityIsTheS3Endpoint(t *testing.T) {
	docs := mustRender(t, versityArgs(withRecipes...)...)
	vals := envValues(container(t, farmerDeploy(t, docs), "farmer"))
	for k, want := range map[string]string{
		"IMAS_S3_ENDPOINT":          versityEndpoint,
		"IMAS_ACCOUNTS_S3_ENDPOINT": versityEndpoint,
		"IMAS_ACCOUNTS_S3_USE_SSL":  "false",
		"IMAS_S3_BUCKET":            "imas-recipes",
		"IMAS_ACCOUNTS_S3_BUCKET":   "imas-accounts",
	} {
		if vals[k] != want {
			t.Errorf("farmer %s = %q, want %q", k, vals[k], want)
		}
	}
	if got := farmerConfig(t, docs)["s3usessl"]; got != false {
		t.Errorf("s3usessl %v, want false for the gateway", got)
	}
	svals := envValues(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))
	if svals["SAASAPI_RECIPES_S3_ENDPOINT"] != versityEndpoint || svals["SAASAPI_RECIPES_S3_USE_SSL"] != "false" {
		t.Errorf("saasapi recipe endpoint %q ssl %q", svals["SAASAPI_RECIPES_S3_ENDPOINT"], svals["SAASAPI_RECIPES_S3_USE_SSL"])
	}
	svc := find(t, docs, "Service", "t-farmer-versity")
	if get(svc, "spec", "ports", 0, "port") != 7070 || get(svc, "spec", "ports", 0, "targetPort") != "s3" {
		t.Errorf("service ports %v", get(svc, "spec", "ports"))
	}
	if !matches(obj{"matchLabels": get(svc, "spec", "selector")}, podLabels(versityDeploy(t, docs))) {
		t.Error("the Service doesn't select the gateway pods")
	}

	// The accounts bucket elsewhere: farmer writes it there, and the
	// gateway serves only the S3 store (no accounts users, no accounts
	// bucket, no reader Secret needed).
	docs = mustRender(t, versityArgs("--set", "accountStore.endpoint=accounts.example.com:9000", "--set", "versity.accountsReader.credentialsSecret=")...)
	vals = envValues(container(t, farmerDeploy(t, docs), "farmer"))
	if vals["IMAS_ACCOUNTS_S3_ENDPOINT"] != "accounts.example.com:9000" || vals["IMAS_S3_ENDPOINT"] != versityEndpoint {
		t.Errorf("accounts %q, s3 %q", vals["IMAS_ACCOUNTS_S3_ENDPOINT"], vals["IMAS_S3_ENDPOINT"])
	}
	if _, ok := envMap(container(t, farmerDeploy(t, docs), "farmer"))["IMAS_ACCOUNTS_S3_USE_SSL"]; ok {
		t.Error("IMAS_ACCOUNTS_S3_USE_SSL rendered for an accounts endpoint of its own with useSSL null")
	}
	users := projectedUsers(t, versityDeploy(t, docs), "users")
	if _, ok := users["accounts-writer"]; ok {
		t.Errorf("accounts users on the gateway with accountStore.endpoint set: %v", users)
	}
	for _, b := range planOf(t, docs).Buckets {
		if b.Name == "imas-accounts" {
			t.Error("the gateway creates the accounts bucket with accountStore.endpoint set")
		}
	}
	if ports := egressPorts(find(t, docs, "NetworkPolicy", "t-farmer")); !slices.Contains(ports, 7070) || !slices.Contains(ports, 9000) {
		t.Errorf("farmer egress ports %v, want the gateway's 7070 and the accounts bucket's 9000", ports)
	}

	// Another S3 endpoint instead: the gateway would serve nothing.
	mustFail(t, "the gateway would serve no bucket", versityArgs("--set", "objectStore.endpoint=s3.example.com")...)
}

// projectedUsers maps each user directory of a projected volume to the
// Secret and the item paths it comes from.
func projectedUsers(t *testing.T, w obj, volume string) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	for _, v := range podSpec(w)["volumes"].([]any) {
		if get(v, "name") != volume {
			continue
		}
		for _, src := range get(v, "projected", "sources").([]any) {
			name := get(src, "secret", "name").(string)
			for _, it := range get(src, "secret", "items").([]any) {
				user, file, _ := strings.Cut(get(it, "path").(string), "/")
				if out[user] == nil {
					out[user] = map[string]string{"secret": name}
				}
				if out[user]["secret"] != name {
					t.Errorf("user %s from two Secrets", user)
				}
				out[user][file] = get(it, "key").(string)
			}
		}
		return out
	}
	t.Fatalf("no volume %s", volume)
	return nil
}

// planOf parses the createBuckets plan the chart renders, with the same
// reader the Job uses (versitysetup.ReadPlan), so chart and command agree.
func planOf(t *testing.T, docs []obj) versitysetup.Plan {
	t.Helper()
	cm := find(t, docs, "ConfigMap", "t-farmer-versity-buckets")
	f := filepath.Join(t.TempDir(), "buckets.json")
	if err := os.WriteFile(f, []byte(get(cm, "data", "buckets.json").(string)), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := versitysetup.ReadPlan(f)
	if err != nil {
		t.Fatalf("the rendered plan is refused by versity-buckets: %v", err)
	}
	return plan
}

func TestVersityDeployment(t *testing.T) {
	docs := mustRender(t, versityArgs(withRecipes...)...)
	d := versityDeploy(t, docs)
	if get(d, "spec", "replicas") != 2 || get(d, "spec", "strategy", "rollingUpdate", "maxUnavailable") != 0 {
		t.Errorf("replicas %v strategy %v", get(d, "spec", "replicas"), get(d, "spec", "strategy"))
	}
	ps := podSpec(d)
	if ps["automountServiceAccountToken"] != false || ps["serviceAccountName"] != "t-farmer-versity" {
		t.Errorf("service account %v automount %v", ps["serviceAccountName"], ps["automountServiceAccountToken"])
	}
	if get(ps, "securityContext", "runAsNonRoot") != true || get(ps, "securityContext", "runAsUser") != 65532 {
		t.Errorf("pod security %v", ps["securityContext"])
	}
	tsc := get(ps, "topologySpreadConstraints", 0).(obj)
	if tsc["maxSkew"] != 1 || tsc["topologyKey"] != "kubernetes.io/hostname" || !matches(tsc["labelSelector"], podLabels(d)) {
		t.Errorf("topology spread %v", tsc)
	}
	// Its own name label: the nats chart's bus admits core by
	// app.kubernetes.io/name=farmer, and the gateway never reaches the bus.
	if podLabels(d)["app.kubernetes.io/name"] != "imas-versity" {
		t.Errorf("pod labels %v", podLabels(d))
	}

	gw := container(t, d, "gateway")
	if img := gw["image"].(string); img != "docker.io/versity/versitygw@sha256:30292fc2eeacc67a36993b01f7a7a5e3361a19cced0e80c1d71cfa2a4b0a2499" {
		t.Errorf("image %s, want the pinned digest", img)
	}
	if !reflect.DeepEqual(gw["args"], []any{"azure"}) {
		t.Errorf("args %v", gw["args"])
	}
	sc := gw["securityContext"].(obj)
	if sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false {
		t.Errorf("gateway security %v", sc)
	}
	for _, p := range []string{"readinessProbe", "livenessProbe"} {
		if get(gw, p, "httpGet", "path") != "/_/health" || get(gw, p, "httpGet", "port") != "s3" {
			t.Errorf("%s %v", p, gw[p])
		}
	}
	env := envMap(gw)
	vals := envValues(gw)
	if vals["VGW_PORT"] != ":7070" || vals["VGW_HEALTH"] != "/_/health" || vals["VGW_IAM_DIR"] != "/var/run/imas/versity-iam" || vals["VGW_REGION"] != "us-east-1" {
		t.Errorf("gateway env %v", vals)
	}
	for k, want := range map[string][2]string{
		"AZ_ACCOUNT_NAME":        {"imas-versity-azure", "account-name"},
		"AZ_ACCESS_KEY":          {"imas-versity-azure", "account-key"},
		"ROOT_ACCESS_KEY_ID":     {"imas-versity-root", "access-key-id"},
		"ROOT_SECRET_ACCESS_KEY": {"imas-versity-root", "secret-access-key"},
	} {
		ref := get(env[k], "valueFrom", "secretKeyRef")
		if get(ref, "name") != want[0] || get(ref, "key") != want[1] {
			t.Errorf("%s from %v, want %v", k, ref, want)
		}
	}
	if _, ok := env["AZ_ENDPOINT"]; ok {
		t.Error("AZ_ENDPOINT rendered without versity.azure.endpoint")
	}
	mounts := byName(gw["volumeMounts"])
	if get(mounts["iam"], "readOnly") != true || mounts["users"] != nil || mounts["root-id"] != nil {
		t.Errorf("gateway mounts %v: the IAM file read-only, no credential volume", gw["volumeMounts"])
	}

	// The init container writes the IAM file from every user's Secret.
	iam := initContainer(t, d, "iam")
	if get(iam, "args", 0) != versitysetup.IAMCommand || iam["image"] != "ghcr.io/yogzblr/imas-farmer:"+chartAppVersion(t) {
		t.Errorf("iam init %v %v", iam["image"], iam["args"])
	}
	users := projectedUsers(t, d, "users")
	want := map[string]string{
		"farmer":          "imas-s3-farmer",
		"saasapi-recipes": "imas-s3-saasapi",
		"accounts-writer": "imas-farmer-accounts-writer",
		"accounts-reader": "imas-bus-accounts-reader",
	}
	if len(users) != len(want) {
		t.Errorf("users %v", users)
	}
	for u, secret := range want {
		if users[u]["secret"] != secret || users[u]["access-key-id"] != "access-key-id" || users[u]["secret-access-key"] != "secret-access-key" {
			t.Errorf("user %s: %v, want Secret %s with both keys", u, users[u], secret)
		}
	}
	root := projectedUsers(t, d, "root-id")
	if len(root) != 1 || root["access-key-id"]["secret"] != "imas-versity-root" {
		t.Errorf("root-id volume %v: the root's access key ID only", root)
	}
	vols := byName(ps["volumes"])
	if get(vols["iam"], "emptyDir", "medium") != "Memory" {
		t.Errorf("the IAM file's volume %v must be memory-backed", vols["iam"])
	}

	// No saasapi recipes: three users.
	if users := projectedUsers(t, versityDeploy(t, mustRender(t, versityOn...)), "users"); len(users) != 3 || users["saasapi-recipes"] != nil {
		t.Errorf("users without recipes %v", users)
	}
	// Replicas, a spread of its own and the Azure endpoint.
	d = versityDeploy(t, mustRender(t, versityArgs("--set", "versity.replicas=3", "--set", "versity.azure.endpoint=https://acct.blob.core.windows.net/",
		"--set", "versity.topologySpreadConstraints[0].maxSkew=1", "--set", "versity.topologySpreadConstraints[0].topologyKey=topology.kubernetes.io/zone",
		"--set", "versity.topologySpreadConstraints[0].whenUnsatisfiable=DoNotSchedule")...))
	if get(d, "spec", "replicas") != 3 || get(podSpec(d), "topologySpreadConstraints", 0, "topologyKey") != "topology.kubernetes.io/zone" {
		t.Errorf("replicas %v spread %v", get(d, "spec", "replicas"), podSpec(d)["topologySpreadConstraints"])
	}
	if envValues(container(t, d, "gateway"))["AZ_ENDPOINT"] != "https://acct.blob.core.windows.net/" {
		t.Error("AZ_ENDPOINT not rendered")
	}

	// A PDB with more than one replica.
	if pdb := find(t, docs, "PodDisruptionBudget", "t-farmer-versity"); get(pdb, "spec", "maxUnavailable") != 1 {
		t.Errorf("pdb %v", pdb["spec"])
	}
	if has(mustRender(t, versityArgs("--set", "versity.replicas=1")...), "PodDisruptionBudget", "t-farmer-versity") {
		t.Error("a PDB for one replica")
	}
}

func TestVersityNetworkPolicy(t *testing.T) {
	docs := mustRender(t, versityArgs(append(slices.Clone(withRecipes),
		"--set", "versity.networkPolicy.extraIngressFrom[0].ipBlock.cidr=10.30.0.0/24",
		"--set", "versity.networkPolicy.azureEgress[0].ipBlock.cidr=20.60.0.0/16")...)...)
	np := find(t, docs, "NetworkPolicy", "t-farmer-versity")
	gwLabels := podLabels(versityDeploy(t, docs))
	if !matches(get(np, "spec", "podSelector"), gwLabels) {
		t.Fatal("the policy doesn't select the gateway")
	}
	const ns = "imas-core"
	bucketsJob := find(t, docs, "Job", "t-farmer-versity-buckets")
	for what, lbls := range map[string]map[string]any{
		"farmer":        podLabels(farmerDeploy(t, docs)),
		"saasapi":       podLabels(find(t, docs, "Deployment", "t-farmer-saasapi")),
		"createBuckets": podLabels(bucketsJob),
		"the DMZ bus":   {"app.kubernetes.io/name": "nats", "app.kubernetes.io/component": "bus"},
	} {
		lns := ns
		if what == "the DMZ bus" {
			lns = "imas-dmz"
		}
		if !allows(np, "ingress", lns, lbls, 7070) {
			t.Errorf("%s can't reach the gateway", what)
		}
	}
	for what, lbls := range map[string]map[string]any{
		"envoy":         {"app.kubernetes.io/name": "nats", "app.kubernetes.io/component": "envoy"},
		"the publisher": {"app.kubernetes.io/name": "imas-saasapi-cred-publisher", "app.kubernetes.io/instance": "t"},
	} {
		if allows(np, "ingress", "imas-dmz", lbls, 7070) || allows(np, "ingress", ns, lbls, 7070) {
			t.Errorf("%s reaches the gateway", what)
		}
	}
	if !strings.Contains(yamlString(t, get(np, "spec", "ingress")), "10.30.0.0/24") {
		t.Error("extraIngressFrom not in the ingress peers")
	}
	if got := egressPorts(np); !slices.Equal(got, []int{443, 53, 53}) {
		t.Errorf("gateway egress ports %v, want Azure Blob 443 and DNS", got)
	}
	if get(np, "spec", "egress", 0, "to", 0, "ipBlock", "cidr") != "20.60.0.0/16" {
		t.Errorf("azure egress %v", get(np, "spec", "egress", 0))
	}

	// farmer and saasapi reach the gateway's pods, not any destination.
	for _, name := range []string{"t-farmer", "t-farmer-saasapi"} {
		pol := find(t, docs, "NetworkPolicy", name)
		if !allows(pol, "egress", ns, gwLabels, 7070) {
			t.Errorf("%s can't reach the gateway", name)
		}
		if allows(pol, "egress", ns, map[string]any{"app": "other"}, 7070) {
			t.Errorf("%s reaches any pod on 7070", name)
		}
	}
	// saasapi without recipe upload has no path to it.
	docs = mustRender(t, versityOn...)
	if allows(find(t, docs, "NetworkPolicy", "t-farmer-saasapi"), "egress", ns, gwLabels, 7070) {
		t.Error("saasapi reaches the gateway without saasapi.recipes")
	}
	if allows(find(t, docs, "NetworkPolicy", "t-farmer-versity"), "ingress", ns, podLabels(find(t, docs, "Deployment", "t-farmer-saasapi")), 7070) {
		t.Error("the gateway admits saasapi without saasapi.recipes")
	}
	// The Job reaches the gateway and DNS only, whatever
	// networkPolicy.enabled says; the gateway's own policy follows it.
	docs = mustRender(t, versityArgs("--set", "networkPolicy.enabled=false")...)
	jnp := find(t, docs, "NetworkPolicy", "imas-versity-buckets")
	if got := egressPorts(jnp); !slices.Equal(got, []int{7070, 53, 53}) || !allows(jnp, "egress", ns, gwLabels, 7070) {
		t.Errorf("createBuckets egress %v", get(jnp, "spec", "egress"))
	}
	if has(docs, "NetworkPolicy", "t-farmer-versity") {
		t.Error("the gateway's NetworkPolicy rendered with networkPolicy.enabled=false")
	}
}

func TestVersityCreateBucketsJob(t *testing.T) {
	docs := mustRender(t, versityArgs(withRecipes...)...)
	job := find(t, docs, "Job", "t-farmer-versity-buckets")
	ann := get(job, "metadata", "annotations").(obj)
	if ann["helm.sh/hook"] != "post-install,post-upgrade" || ann["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded" {
		t.Errorf("hook annotations %v", ann)
	}
	ps := podSpec(job)
	if ps["serviceAccountName"] != "imas-versity-buckets" || ps["automountServiceAccountToken"] != false || ps["restartPolicy"] != "Never" {
		t.Errorf("job pod %v", ps)
	}
	checkRestricted(t, job)
	c := container(t, job, "buckets")
	args := c["args"].([]any)
	if args[0] != versitysetup.BucketsCommand || !slices.Contains(args, any("-endpoint="+versityEndpoint)) || !slices.Contains(args, any("-plan=/etc/imas/versity/buckets.json")) {
		t.Errorf("args %v", args)
	}
	if _, ok := c["env"]; ok {
		t.Errorf("the Job has env %v; it reads only flags and files", c["env"])
	}
	root := projectedUsers(t, job, "root")
	if root["access-key-id"]["secret"] != "imas-versity-root" || root["secret-access-key"]["secret"] != "imas-versity-root" {
		t.Errorf("root volume %v", root)
	}
	for u, files := range projectedUsers(t, job, "user-ids") {
		if _, ok := files["secret-access-key"]; ok || files["access-key-id"] == "" {
			t.Errorf("the Job mounts user %s's %v; access key IDs only", u, files)
		}
	}

	plan := planOf(t, docs)
	byBucket := map[string]versitysetup.PlanBucket{}
	for _, b := range plan.Buckets {
		byBucket[b.Name] = b
	}
	if len(byBucket) != 4 {
		t.Fatalf("plan buckets %v", plan.Buckets)
	}
	// Which users each bucket admits, and what (design D22).
	grants := func(b string) map[string][]string {
		out := map[string][]string{}
		for _, s := range byBucket[b].Statements {
			out[s.User] = append(out[s.User], s.Actions...)
		}
		for u := range out {
			slices.Sort(out[u])
			out[u] = slices.Compact(out[u])
		}
		return out
	}
	for b, want := range map[string]map[string][]string{
		"imas-recipes": {
			"farmer":          {"s3:DeleteObject", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"},
			"saasapi-recipes": {"s3:DeleteObject", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"},
		},
		"imas-jobs": {"farmer": {"s3:DeleteObject", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"}},
		// Delete since S6: a purge erases the tenant's sprout JWTs.
		"imas-sprout-jwts": {"farmer": {"s3:DeleteObject", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"}},
		"imas-accounts": {
			"accounts-writer": {"s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"},
			"accounts-reader": {"s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"},
		},
	} {
		if got := grants(b); !reflect.DeepEqual(got, want) {
			t.Errorf("bucket %s grants %v, want %v", b, got, want)
		}
	}
	// saasapi's statements are the reviewed policy file's, prefixes and
	// condition included.
	var file struct {
		Statement []struct {
			Sid       string
			Action    []string
			Resource  []string
			Condition json.RawMessage
		}
	}
	pol := strings.ReplaceAll(string(repoFile(t, "deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json")), "RECIPE_BUCKET", "imas-recipes")
	if err := json.Unmarshal([]byte(pol), &file); err != nil {
		t.Fatal(err)
	}
	var saas []versitysetup.PlanStatement
	for _, s := range byBucket["imas-recipes"].Statements {
		if s.User == "saasapi-recipes" {
			saas = append(saas, s)
		}
	}
	if len(saas) != len(file.Statement) {
		t.Fatalf("saasapi statements %d, policy file %d", len(saas), len(file.Statement))
	}
	for i, s := range file.Statement {
		got := saas[i]
		if got.Sid != "Saasapi"+s.Sid || !slices.Equal(got.Actions, s.Action) || !slices.Equal(got.Resources, s.Resource) {
			t.Errorf("saasapi statement %d %+v, file %+v", i, got, s)
		}
		if len(s.Condition) > 0 {
			var a, b any
			_ = json.Unmarshal(s.Condition, &a)
			_ = json.Unmarshal(got.Condition, &b)
			if !reflect.DeepEqual(a, b) {
				t.Errorf("condition %s, file %s", got.Condition, s.Condition)
			}
		}
	}
	// The plan's users are exactly the gateway's.
	planUsers := map[string]bool{}
	for _, b := range plan.Buckets {
		for _, s := range b.Statements {
			planUsers[s.User] = true
		}
	}
	for u := range projectedUsers(t, versityDeploy(t, docs), "users") {
		if !planUsers[u] {
			t.Errorf("gateway user %s has no grant", u)
		}
		delete(planUsers, u)
	}
	if len(planUsers) != 0 {
		t.Errorf("plan names users the gateway lacks: %v", planUsers)
	}
}

// versity.enabled refuses to render without what the gateway needs, and
// with credentials shared between components.
func TestVersityValidation(t *testing.T) {
	for _, tc := range []struct {
		want string
		args []string
	}{
		{"versity.azure.credentialsSecret is required", []string{"--set", "versity.azure.credentialsSecret="}},
		{"versity.azure.accountNameKey and versity.azure.accountKeyKey are required", []string{"--set", "versity.azure.accountKeyKey="}},
		{"versity.azure.endpoint must be an https://", []string{"--set", "versity.azure.endpoint=http://acct.blob.core.windows.net"}},
		{"versity.rootCredentials.secretName is required", []string{"--set", "versity.rootCredentials.secretName="}},
		{"versity.accountsReader.credentialsSecret is required", []string{"--set", "versity.accountsReader.credentialsSecret="}},
		{"objectStore.credentialsSecret is required with versity.enabled", []string{"--set", "objectStore.credentialsSecret="}},
		{"must not be versity.rootCredentials.secretName", []string{"--set", "versity.rootCredentials.secretName=imas-s3-farmer"}},
		{"are the same Secret", []string{"--set", "versity.accountsReader.credentialsSecret=imas-farmer-accounts-writer"}},
		{"are the same Secret", append(slices.Clone(withRecipes), "--set", "saasapi.recipes.credentialsSecret=imas-bus-accounts-reader")},
		{"versity.azure.credentialsSecret must not be", []string{"--set", "versity.azure.credentialsSecret=imas-s3-farmer"}},
		{"versity.azure.credentialsSecret must not be versity.rootCredentials.secretName", []string{"--set", "versity.azure.credentialsSecret=imas-versity-root"}},
		{"versity.image.digest must be", []string{"--set", "versity.image.digest="}},
		{"versity.replicas must be a whole number", []string{"--set", "versity.replicas=0"}},
		{"versity.replicas must be a whole number", []string{"--set", "versity.replicas=1.5"}},
		{"objectStore.jobBucket is required with versity.enabled", []string{"--set", "objectStore.jobBucket="}},
		{"objectStore.sproutJWTBucket is required with versity.enabled", []string{"--set", "objectStore.sproutJWTBucket="}},
		{"not a bucket name Azure Blob takes", []string{"--set", "objectStore.bucket=Imas-Recipes"}},
		{"not a bucket name Azure Blob takes", []string{"--set", "accountStore.bucket=imas--accounts"}},
		{"versity.port must be 1024 to 65535", []string{"--set", "versity.port=80"}},
		{"versity.createBuckets.serviceAccountName \"t-farmer\" is another workload's", []string{"--set", "versity.createBuckets.serviceAccountName=t-farmer"}},
		{"versity.createBuckets.timeout must be a Go duration", []string{"--set", "versity.createBuckets.timeout=10"}},
		{"the gateway would serve no bucket", []string{"--set", "objectStore.endpoint=s3.example.com:9000"}},
	} {
		mustFail(t, tc.want, versityArgs(tc.args...)...)
	}
	// Without versity none of this is checked.
	mustRender(t, "--set", "versity.azure.credentialsSecret=", "--set", "versity.image.digest=")
}

// Every ci values file renders; ci/versity-values.yaml with the gateway as
// every S3 endpoint.
func TestVersityCIValues(t *testing.T) {
	docs, err := runHelm(t, strippedChart(t), "-f", ciValues(t, "versity-values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	vals := envValues(container(t, farmerDeploy(t, docs), "farmer"))
	if vals["IMAS_S3_ENDPOINT"] != versityEndpoint || vals["IMAS_ACCOUNTS_S3_ENDPOINT"] != versityEndpoint {
		t.Errorf("endpoints %q %q", vals["IMAS_S3_ENDPOINT"], vals["IMAS_ACCOUNTS_S3_ENDPOINT"])
	}
	// The recipe, job, sprout JWT and accounts buckets, and the log bucket
	// (logShipping, U4).
	if len(planOf(t, docs).Buckets) != 5 {
		t.Error("ci/versity-values.yaml: not every bucket on the gateway")
	}
}
