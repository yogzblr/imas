package farmerchart

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// recipesOn turns on saasapi's recipe upload (REC.1) against endpoint.
func recipesOn(endpoint string, extra ...string) []string {
	return append([]string{
		"--set", "tls.mode=secret",
		"--set", "saasapi.recipes.enabled=true",
		"--set", "saasapi.recipes.credentialsSecret=saasapi-s3",
		"--set", "objectStore.endpoint=" + endpoint,
		"--set", "objectStore.bucket=recipes",
		"--set", "objectStore.jobBucket=jobs",
	}, extra...)
}

// saasapi writes recipes to the object store with saasapi.recipes (REC.1).
// That path is its own rule on objectStore.endpoint's port, so it works
// for a MinIO on 9000 and survives narrowing saasapiExtraEgress to
// Keycloak; with recipes off there is no such rule.
func TestSaasapiObjectStoreEgress(t *testing.T) {
	peer := map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "minio"}}}
	for _, tc := range []struct {
		name  string
		args  []string
		ports []int
		to    any // the object store rule's peers; nil: any destination
	}{
		{"recipes off (negative)", []string{"--set", "tls.mode=secret", "--set", "objectStore.endpoint=minio:9000"},
			[]int{5406, 3306, 6379, 53, 53, 443}, nil},
		{"minio on 9000", recipesOn("minio.minio.svc:9000"),
			[]int{5406, 3306, 6379, 9000, 53, 53, 443}, nil},
		{"no port, TLS", recipesOn("s3.example.com"),
			[]int{5406, 3306, 6379, 443, 53, 53, 443}, nil},
		{"no port, plain", recipesOn("minio", "--set", "objectStore.useSSL=false"),
			[]int{5406, 3306, 6379, 80, 53, 53, 443}, nil},
		{"narrowed extra egress", recipesOn("minio:9000", "--set", "networkPolicy.saasapiExtraEgress=null"),
			[]int{5406, 3306, 6379, 9000, 53, 53}, nil},
		{"configured peer", recipesOn("minio.minio.svc:9000", "--set", "networkPolicy.external.objectStore[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=minio"),
			[]int{5406, 3306, 6379, 9000, 53, 53, 443}, []any{peer}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs := mustRender(t, tc.args...)
			np := find(t, docs, "NetworkPolicy", "t-farmer-saasapi")
			if got := egressPorts(np); !slices.Equal(got, tc.ports) {
				t.Fatalf("saasapi egress ports %v, want %v", got, tc.ports)
			}
			// farmer has its own object store rule, on the same port and
			// peers, whether or not saasapi writes recipes (FIX.3).
			fnp := find(t, docs, "NetworkPolicy", "t-farmer")
			// The accounts bucket (testAccountStoreEndpoint, 9000) gets a
			// rule of its own when the object store is on another port.
			osPorts := []int{9000}
			if tc.ports[3] != 53 && tc.ports[3] != 9000 {
				osPorts = []int{tc.ports[3], 9000}
			}
			if got := egressPorts(fnp); !slices.Equal(got, slices.Concat([]int{5406, 3306, 6379, 8200}, osPorts, []int{53, 53})) {
				t.Errorf("farmer egress ports %v", got)
			}
			if got := get(fnp, "spec", "egress", 4, "to"); !reflect.DeepEqual(got, tc.to) {
				t.Errorf("farmer object store rule peers %v, want %v", got, tc.to)
			}
			if tc.ports[3] == 53 {
				return
			}
			rule := get(np, "spec", "egress", 3).(obj)
			if len(rule["ports"].([]any)) != 1 || get(rule, "ports", 0, "protocol") != "TCP" {
				t.Errorf("object store rule ports %v, want one TCP port", rule["ports"])
			}
			if !reflect.DeepEqual(rule["to"], tc.to) {
				t.Errorf("object store rule peers %v, want %v", rule["to"], tc.to)
			}
		})
	}
}

// FIX.3: farmer reads recipes and staged recipes and writes job logs at
// objectStore.endpoint, so the default network policy must let it, with
// no networkPolicy.farmerExtraEgress: its own rule on the endpoint's
// port, narrowed by networkPolicy.external.objectStore like saasapi's.
// farmerExtraEgress stays an addition.
func TestFarmerObjectStoreEgress(t *testing.T) {
	minio := map[string]any{"app": "minio"}
	osOn := []string{"--set", "objectStore.endpoint=minio.minio.svc:9000", "--set", "objectStore.bucket=recipes",
		"--set", "objectStore.jobBucket=jobs"}

	// Default policy values: the rule is there, to any destination on 9000
	// only, and nothing else opens 9000.
	docs := mustRender(t, osOn...)
	fnp := find(t, docs, "NetworkPolicy", "t-farmer")
	if got := egressPorts(fnp); !slices.Equal(got, []int{5406, 3306, 6379, 8200, 9000, 53, 53}) {
		t.Fatalf("farmer egress ports %v", got)
	}
	rule := get(fnp, "spec", "egress", 4).(obj)
	if len(rule["ports"].([]any)) != 1 || get(rule, "ports", 0, "protocol") != "TCP" || rule["to"] != nil {
		t.Errorf("farmer object store rule %v, want TCP 9000 to any destination", rule)
	}
	if !allows(fnp, "egress", "minio", minio, 9000) || allows(fnp, "egress", "minio", minio, 9001) {
		t.Error("farmer's default policy doesn't admit exactly the object store port")
	}
	// The farmer chart's documented examples: the eval file has no object
	// store, only the accounts bucket (its rule on 9000); the production
	// one gets the object store rule on 443, the accounts bucket's on 9000
	// (testAccountStoreEndpoint), and keeps its farmerExtraEgress rule on
	// top.
	if got := egressPorts(find(t, mustRender(t, "-f", ciValues(t, "default-values.yaml")), "NetworkPolicy", "t-farmer")); !slices.Equal(got, []int{5406, 3306, 6379, 8200, 9000, 53, 53}) {
		t.Errorf("eval values: farmer egress ports %v", got)
	}
	ext := find(t, mustRender(t, "-f", ciValues(t, "external-values.yaml")), "NetworkPolicy", "t-farmer")
	if got := egressPorts(ext); !slices.Equal(got, []int{5406, 3306, 6379, 8200, 443, 9000, 53, 53, 443}) {
		t.Errorf("production values: farmer egress ports %v", got)
	}
	// Rules: bus, PXC, Valkey, OpenBao, object store, accounts bucket, DNS
	// (two ports), extra.
	if get(ext, "spec", "egress", 4, "to") != nil || get(ext, "spec", "egress", 7, "to", 0, "ipBlock", "cidr") != "198.51.100.0/24" {
		t.Errorf("production values: object store rule %v, extra rule %v", get(ext, "spec", "egress", 4), get(ext, "spec", "egress", 7))
	}

	// external.objectStore narrows farmer's rule and saasapi's alike.
	docs = mustRender(t, recipesOn("minio.minio.svc:9000",
		"--set", "networkPolicy.external.objectStore[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=minio",
		"--set", "networkPolicy.external.objectStore[0].podSelector.matchLabels.app=minio")...)
	for _, name := range []string{"t-farmer", "t-farmer-saasapi"} {
		np := find(t, docs, "NetworkPolicy", name)
		if !allows(np, "egress", "minio", minio, 9000) {
			t.Errorf("%s: object store not reachable through the configured peer", name)
		}
		if allows(np, "egress", "other", minio, 9000) || allows(np, "egress", "minio", map[string]any{"app": "other"}, 9000) {
			t.Errorf("%s: port 9000 open beyond the configured peer", name)
		}
	}

	// networkPolicy off: no policies at all, as before.
	if has(mustRender(t, append(osOn, "--set", "networkPolicy.enabled=false")...), "NetworkPolicy", "t-farmer") {
		t.Error("farmer NetworkPolicy rendered with networkPolicy.enabled=false")
	}
}

// Sealed internal.* (J.4) adds no network path to saasapi: requests to
// farmer ride saasapi's bus connection, and its box key is a Secret ESO
// syncs. So saasapi's policy reaches neither farmer's pods nor its API
// port, and the box key alone brings in no OpenBao egress.
func TestSaasapiNetworkPolicyJ4(t *testing.T) {
	docs := mustRender(t, "--set", "tls.mode=secret")
	np := find(t, docs, "NetworkPolicy", "t-farmer-saasapi")
	if get(np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") != "saasapi" {
		t.Fatalf("saasapi policy selects %v", get(np, "spec", "podSelector"))
	}
	for i, r := range get(np, "spec", "egress").([]any) {
		for _, p := range get(r, "ports").([]any) {
			if port := get(p, "port"); port == 5405 || port == 8200 {
				t.Errorf("egress rule %d opens port %v: saasapi needs neither farmer's API nor OpenBao for J.4", i, port)
			}
		}
		to, _ := get(r, "to").([]any)
		for _, peer := range to {
			if get(peer, "podSelector", "matchLabels", "app.kubernetes.io/component") == "farmer" {
				t.Errorf("egress rule %d reaches farmer's pods: %v", i, peer)
			}
		}
	}
	// The box Secret is mounted, so the J.4 wiring is in this render.
	env := envValues(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))
	if env["SAASAPI_BOX_PRIV_FILE"] == "" {
		t.Fatal("SAASAPI_BOX_PRIV_FILE unset: this render doesn't cover J.4")
	}
	// Ingress: the listener port only (no operator plane by default).
	in := get(np, "spec", "ingress").([]any)
	if len(in) != 1 || get(in[0], "ports", 0, "port") != 8081 {
		t.Errorf("saasapi ingress %v, want only port 8081", in)
	}
}

// saasapi's PDB: none for one replica (it would block every drain), and
// maxUnavailable 1 over saasapi's pods alone otherwise.
func TestSaasapiPDB(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"--set", "saasapi.replicaCount=3"}, true},
		{[]string{"--set", "saasapi.replicaCount=1"}, false},
		{[]string{"--set", "saasapi.pdb.enabled=false"}, false},
		{[]string{"--set", "saasapi.enabled=false"}, false},
	} {
		docs := mustRender(t, tc.args...)
		if got := has(docs, "PodDisruptionBudget", "t-farmer-saasapi"); got != tc.want {
			t.Fatalf("%v: PDB rendered = %v, want %v", tc.args, got, tc.want)
		}
		if !tc.want {
			continue
		}
		pdb := find(t, docs, "PodDisruptionBudget", "t-farmer-saasapi")
		if get(pdb, "spec", "maxUnavailable") != 1 || get(pdb, "spec", "minAvailable") != nil {
			t.Errorf("%v: PDB spec %v, want maxUnavailable 1 only", tc.args, get(pdb, "spec"))
		}
		sel := get(pdb, "spec", "selector", "matchLabels")
		dep := get(find(t, docs, "Deployment", "t-farmer-saasapi"), "spec", "selector", "matchLabels")
		if !reflect.DeepEqual(sel, dep) {
			t.Errorf("%v: PDB selector %v, saasapi Deployment selector %v", tc.args, sel, dep)
		}
		if reflect.DeepEqual(sel, get(farmerDeploy(t, docs), "spec", "selector", "matchLabels")) {
			t.Errorf("%v: PDB selector matches farmer's pods", tc.args)
		}
	}
	// maxUnavailable must leave a drain room to evict a pod and still keep
	// one serving: at the default two replicas, 1 or a percentage above 0%
	// and below 100%. The bound is replicaCount (saasapi has no HPA).
	for _, tc := range []struct {
		value string
		want  string // the fail message; empty: renders
	}{
		{"0", "saasapi.pdb.maxUnavailable 0 would block every drain"},
		{"-1", "saasapi.pdb.maxUnavailable -1 would block every drain"},
		{"2", "saasapi.pdb.maxUnavailable 2 protects nothing: it is not below saasapi.replicaCount (2)"},
		{"0%", `saasapi.pdb.maxUnavailable "0%" would block every drain`},
		{"100%", `saasapi.pdb.maxUnavailable "100%" protects nothing`},
		{"150%", `saasapi.pdb.maxUnavailable "150%" protects nothing`},
		// Kubernetes rounds a percentage up: at two replicas 51% is 2.
		{"51%", `saasapi.pdb.maxUnavailable "51%" protects nothing: Kubernetes rounds it up to saasapi.replicaCount (2)`},
		{"99%", `saasapi.pdb.maxUnavailable "99%" protects nothing`},
		{"half", `saasapi.pdb.maxUnavailable "half" must be a whole number or a percentage`},
		{"1", ""},
		{"50%", ""},
	} {
		args := []string{"--set", "saasapi.pdb.maxUnavailable=" + tc.value}
		if tc.want != "" {
			mustFail(t, tc.want, args...)
			continue
		}
		pdb := find(t, mustRender(t, args...), "PodDisruptionBudget", "t-farmer-saasapi")
		want := any(tc.value)
		if !strings.HasSuffix(tc.value, "%") {
			want = 1
		}
		if got := get(pdb, "spec", "maxUnavailable"); got != want {
			t.Errorf("maxUnavailable=%s: PDB maxUnavailable %v (%T), want %v", tc.value, got, got, want)
		}
	}
	// 2 is valid once there are three replicas; one replica gets no PDB,
	// so the value isn't checked.
	pdb := find(t, mustRender(t, "--set", "saasapi.replicaCount=3", "--set", "saasapi.pdb.maxUnavailable=2"), "PodDisruptionBudget", "t-farmer-saasapi")
	if got := get(pdb, "spec", "maxUnavailable"); got != 2 {
		t.Errorf("replicaCount 3, maxUnavailable 2: PDB maxUnavailable %v", got)
	}
	mustFail(t, "saasapi.pdb.maxUnavailable 3 protects nothing", "--set", "saasapi.replicaCount=3", "--set", "saasapi.pdb.maxUnavailable=3")
	if has(mustRender(t, "--set", "saasapi.replicaCount=1", "--set", "saasapi.pdb.maxUnavailable=0"), "PodDisruptionBudget", "t-farmer-saasapi") {
		t.Errorf("replicaCount 1: PDB rendered")
	}

	// The only other PDB is farmer's own (TestFarmerPDBRendered).
	for _, d := range mustRender(t) {
		if n := get(d, "metadata", "name"); d["kind"] == "PodDisruptionBudget" && n != "t-farmer-saasapi" && n != "t-farmer" {
			t.Errorf("unexpected PDB %v", n)
		}
	}
}

// credentialPublisher.extraEnv lands on the publish container of both the
// post-deploy Job and the refresh CronJob, after the chart's own variables;
// the default adds nothing.
func TestPublisherExtraEnv(t *testing.T) {
	cronContainer := func(t *testing.T, docs []obj) obj {
		t.Helper()
		cj := find(t, docs, "CronJob", "t-farmer-saasapi-credential-refresh")
		for _, c := range get(cj, "spec", "jobTemplate", "spec", "template", "spec", "containers").([]any) {
			if c.(obj)["name"] == "publish" {
				return c.(obj)
			}
		}
		t.Fatalf("CronJob has no publish container")
		return nil
	}
	docs := mustRender(t,
		"--set", "credentialPublisher.extraEnv[0].name=IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE",
		"--set", "credentialPublisher.extraEnv[0].value=platform",
		"--set", "credentialPublisher.extraEnv[1].name=HTTPS_PROXY",
		"--set", "credentialPublisher.extraEnv[1].value=http://proxy:3128")
	for name, c := range map[string]obj{
		"Job":     container(t, find(t, docs, "Job", "t-farmer-saasapi-credential-publish"), "publish"),
		"CronJob": cronContainer(t, docs),
	} {
		env := envValues(c)
		if env["IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE"] != "platform" || env["HTTPS_PROXY"] != "http://proxy:3128" {
			t.Errorf("%s publish env %v: want IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE=platform and HTTPS_PROXY", name, env)
		}
		if env["IMAS_SAASAPI_CRED_OPENBAO_KV_PATH"] != "platform/imas/saasapi-nats-user" {
			t.Errorf("%s: extraEnv replaced the chart's own variables: %v", name, env)
		}
	}
	// Nothing by default.
	def := mustRender(t)
	for name, c := range map[string]obj{
		"Job":     container(t, find(t, def, "Job", "t-farmer-saasapi-credential-publish"), "publish"),
		"CronJob": cronContainer(t, def),
	} {
		for _, k := range []string{"IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE", "HTTPS_PROXY"} {
			if _, ok := envMap(c)[k]; ok {
				t.Errorf("%s: %s set by default", name, k)
			}
		}
	}
	// extraEnv adds variables, it never replaces the publisher's own
	// identity, key or path: every other IMAS_* name is refused.
	mustFail(t, "credentialPublisher.extraEnv: every entry needs a name",
		"--set", "credentialPublisher.extraEnv[0].value=x")
	// Both OpenBao clients' namespaces may be set: the KV client's and the
	// signer's (the publisher signs through IMAS_NATSSIGN_* before it writes).
	ns := mustRender(t, "--set", "credentialPublisher.extraEnv[0].name=IMAS_NATSSIGN_OPENBAO_NAMESPACE",
		"--set", "credentialPublisher.extraEnv[0].value=platform")
	if v := envValues(container(t, find(t, ns, "Job", "t-farmer-saasapi-credential-publish"), "publish"))["IMAS_NATSSIGN_OPENBAO_NAMESPACE"]; v != "platform" {
		t.Errorf("IMAS_NATSSIGN_OPENBAO_NAMESPACE = %q, want platform", v)
	}
	for _, name := range []string{"IMAS_SAASAPI_CRED_OPENBAO_KV_PATH", "IMAS_SAASAPI_CRED_OPENBAO_ADDR", "IMAS_NATS_SAASAPI_USER_SEED_FILE", "IMAS_SAASAPI_USER_JWT_TTL"} {
		mustFail(t, "credentialPublisher.extraEnv may not set "+name,
			"--set", "credentialPublisher.extraEnv[0].name="+name, "--set", "credentialPublisher.extraEnv[0].value=x")
	}
	// The NetworkPolicy stays OpenBao and DNS only: extraEnv opens no egress.
	a := get(find(t, def, "NetworkPolicy", "imas-saasapi-cred-publisher"), "spec", "egress")
	b := get(find(t, docs, "NetworkPolicy", "imas-saasapi-cred-publisher"), "spec", "egress")
	if !reflect.DeepEqual(a, b) {
		t.Errorf("extraEnv changed the publisher's egress: %v, default %v", b, a)
	}
}
