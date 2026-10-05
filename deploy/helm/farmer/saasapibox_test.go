package farmerchart

// J.4 follow-up (FLAG FOR SECURITY REVIEW): the chart delivers the SaaS
// API's half of sealed internal.* traffic. saasapi gets its box PRIVATE
// key (as a read-only file) and the platform PUBLIC key it pins; farmer
// gets neither the SaaS API's private key nor anything new; saasapi never
// gets the platform private key. The keygen Job that writes both keys is
// on by default and runs as a hook; saasapi's pods can't start until the
// Secret it fills exists.

import (
	"strings"
	"testing"
)

// workloadPods returns every pod template in docs, by "Kind/name".
func workloadPods(docs []obj) map[string]obj {
	out := map[string]obj{}
	for _, d := range docs {
		var ps any
		switch d["kind"] {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
			ps = get(d, "spec", "template", "spec")
		case "CronJob":
			ps = get(d, "spec", "jobTemplate", "spec", "template", "spec")
		case "Pod":
			ps = get(d, "spec")
		}
		if m, ok := ps.(obj); ok {
			out[d["kind"].(string)+"/"+get(d, "metadata", "name").(string)] = m
		}
	}
	return out
}

// podContainers is a pod's containers and init containers.
func podContainers(ps obj) []obj {
	var out []obj
	for _, k := range []string{"initContainers", "containers"} {
		l, _ := ps[k].([]any)
		for _, c := range l {
			out = append(out, c.(obj))
		}
	}
	return out
}

// secretsReferenced is every Secret name a pod can read: secret and
// projected volumes, env secretKeyRefs and envFrom secretRefs.
func secretsReferenced(ps obj) map[string]bool {
	out := map[string]bool{}
	vols, _ := ps["volumes"].([]any)
	for _, v := range vols {
		if n, ok := get(v, "secret", "secretName").(string); ok {
			out[n] = true
		}
		srcs, _ := get(v, "projected", "sources").([]any)
		for _, s := range srcs {
			if n, ok := get(s, "secret", "name").(string); ok {
				out[n] = true
			}
		}
	}
	for _, c := range podContainers(ps) {
		env, _ := c["env"].([]any)
		for _, e := range env {
			if n, ok := get(e, "valueFrom", "secretKeyRef", "name").(string); ok {
				out[n] = true
			}
		}
		from, _ := c["envFrom"].([]any)
		for _, e := range from {
			if n, ok := get(e, "secretRef", "name").(string); ok {
				out[n] = true
			}
		}
	}
	return out
}

// rolesIfBootstrapped is bootstrapRoles, or none when the eval bootstrap
// Job isn't rendered (external OpenBao: the roles are ops').
func rolesIfBootstrapped(t *testing.T, docs []obj) map[string][]string {
	t.Helper()
	if !has(docs, "Job", "t-farmer-openbao-bootstrap") {
		return nil
	}
	return bootstrapRoles(t, docs)
}

// boxValueSets are the renders the negatives are checked across: the
// defaults, the eval and production examples, token auth, and ESO on.
func boxValueSets(t *testing.T) map[string][]string {
	return map[string][]string{
		"defaults":   nil,
		"eval":       {"-f", ciValues(t, "default-values.yaml")},
		"production": {"-f", ciValues(t, "external-values.yaml")},
		"token-auth": {"-f", ciValues(t, "token-auth-values.yaml")},
		"eso":        {"--set", "externalSecrets.enabled=true"},
		"operator":   {"--set", "saasapi.fleetUpdateDispatch.enabled=true"},
	}
}

func TestSaasapiBoxKeyWiring(t *testing.T) {
	docs := mustRender(t)
	d := find(t, docs, "Deployment", "t-farmer-saasapi")
	c := container(t, d, "saasapi")
	env := envMap(c)
	if v := env["SAASAPI_BOX_PRIV_FILE"]["value"]; v != "/var/run/secrets/imas/saasapi-box/saasapi-box.key" {
		t.Errorf("SAASAPI_BOX_PRIV_FILE = %v", v)
	}
	pub := env["SAASAPI_PLATFORM_BOX_PUB"]
	if get(pub, "valueFrom", "secretKeyRef", "name") != "imas-saasapi-box" ||
		get(pub, "valueFrom", "secretKeyRef", "key") != "SAASAPI_PLATFORM_BOX_PUB" {
		t.Errorf("SAASAPI_PLATFORM_BOX_PUB = %v", pub)
	}
	// Not optional anywhere: no Secret, no pod. saasapi waits for the
	// keygen Job (and ESO) rather than starting without its keys.
	if get(pub, "valueFrom", "secretKeyRef", "optional") == true {
		t.Error("SAASAPI_PLATFORM_BOX_PUB is optional")
	}
	if _, raw := env["SAASAPI_BOX_PRIV"]; raw {
		t.Error("the private key travels as an env var")
	}

	vols := byName(podSpec(d)["volumes"])
	box := vols["saasapi-box"]
	if get(box, "secret", "secretName") != "imas-saasapi-box" || get(box, "secret", "optional") == true {
		t.Fatalf("saasapi-box volume %v", box)
	}
	// 0440 (root:fsGroup, nothing for others), as the NATS seed.
	if m, _ := get(box, "secret", "defaultMode").(int); m != 0o440 {
		t.Errorf("saasapi-box defaultMode %v, want 0440", get(box, "secret", "defaultMode"))
	}
	items, _ := get(box, "secret", "items").([]any)
	if len(items) != 1 || get(items[0], "key") != "saasapi-box.key" || get(items[0], "path") != "saasapi-box.key" {
		t.Errorf("saasapi-box items %v: want the private key alone", items)
	}
	if get(podSpec(d), "securityContext", "fsGroup") != 65532 || get(podSpec(d), "securityContext", "runAsUser") != 65532 {
		t.Errorf("saasapi pod identity %v", get(podSpec(d), "securityContext"))
	}
	mounts := byName(c["volumeMounts"])
	if m := mounts["saasapi-box"]; get(m, "mountPath") != "/var/run/secrets/imas/saasapi-box" || get(m, "readOnly") != true {
		t.Errorf("saasapi-box mount %v", m)
	}
	// Only the saasapi container: not the bus-CA init container.
	for _, ic := range podContainers(podSpec(d)) {
		if ic["name"] == "saasapi" {
			continue
		}
		if _, ok := byName(ic["volumeMounts"])["saasapi-box"]; ok {
			t.Errorf("container %v mounts the SaaS API's private key", ic["name"])
		}
	}
}

// The default render runs the keygen Job as a hook before saasapi can
// start: the Job is a post-install/post-upgrade hook (weight 5, after the
// OpenBao bootstrap, before the credential publisher), saasapi is an
// ordinary Deployment created at install, and its pods can't start until
// the Secret the keys reach it through exists.
func TestSaasapiBoxKeygenRunsBeforeSaasapiStarts(t *testing.T) {
	for name, args := range boxValueSets(t) {
		t.Run(name, func(t *testing.T) {
			docs := mustRender(t, args...)
			job := find(t, docs, "Job", "t-farmer-controlplane-box-keys")
			ann := get(job, "metadata", "annotations").(obj)
			if ann["helm.sh/hook"] != "post-install,post-upgrade" || ann["helm.sh/hook-weight"] != "5" {
				t.Errorf("keygen hook %v", ann)
			}
			if pub := find(t, docs, "Job", "t-farmer-saasapi-credential-publish"); get(pub, "metadata", "annotations", "helm.sh/hook-weight") != "10" {
				t.Error("publisher no longer after the keygen Job")
			}
			d := find(t, docs, "Deployment", "t-farmer-saasapi")
			if get(d, "metadata", "annotations", "helm.sh/hook") != nil {
				t.Error("saasapi became a hook")
			}
			env := envMap(container(t, d, "saasapi"))
			if env["SAASAPI_BOX_PRIV_FILE"] == nil || env["SAASAPI_PLATFORM_BOX_PUB"] == nil {
				t.Errorf("saasapi box settings missing: %v", env)
			}
			if !secretsReferenced(podSpec(d))["imas-saasapi-box"] {
				t.Error("saasapi doesn't depend on its box Secret")
			}
		})
	}
}

// Farmer, and every other workload but saasapi, never gets the SaaS API's
// private key: no pod but saasapi's references its Secret, and farmer's
// OpenBao policies don't reach <base>/saasapi-box.
func TestSaasapiBoxKeyNeverReachesFarmer(t *testing.T) {
	for name, args := range boxValueSets(t) {
		t.Run(name, func(t *testing.T) {
			docs := mustRender(t, args...)
			pods := workloadPods(docs)
			if _, ok := pods["Deployment/t-farmer"]; !ok {
				t.Fatal("no farmer Deployment")
			}
			for w, ps := range pods {
				if w == "Deployment/t-farmer-saasapi" {
					continue
				}
				if secretsReferenced(ps)["imas-saasapi-box"] {
					t.Errorf("%s can read the SaaS API's private key", w)
				}
				for _, c := range podContainers(ps) {
					if strings.HasPrefix(w, "Job/t-farmer-controlplane-box-keys") {
						break // it writes the key in OpenBao, and mounts no Secret (TestControlPlaneBoxKeysJob)
					}
					for n := range envValues(c) {
						if n == "SAASAPI_BOX_PRIV_FILE" {
							t.Errorf("%s/%s has %s", w, c["name"], n)
						}
					}
				}
			}
			if !has(docs, "ConfigMap", "t-farmer-openbao-policies") {
				return // external OpenBao: the policies are ops'
			}
			cm := find(t, docs, "ConfigMap", "t-farmer-openbao-policies")
			for _, policy := range []string{"imas-farmer-tenantbox.hcl", "imas-farmer-gateway.hcl", "imas-farmer-certs.hcl", "imas-saasapi-cred-publisher.hcl"} {
				hcl, _ := get(cm, "data", policy).(string)
				for path := range policyBlocks(hcl) {
					if strings.Contains(path, "saasapi-box") || strings.ContainsAny(path, "*+") && !strings.HasSuffix(path, `/tenants/+"`) {
						t.Errorf("%s reaches saasapi-box: %s", policy, path)
					}
				}
			}
			// No farmer role binds the keygen policy (the only one that
			// reads saasapi-box).
			for role, r := range rolesIfBootstrapped(t, docs) {
				if r[0] == "t-farmer" && r[2] == "imas-controlplane-box-keygen" {
					t.Errorf("farmer role %s binds the keygen policy", role)
				}
			}
		})
	}
}

// saasapi never gets the platform private key: it has no OpenBao identity
// that reaches <base>/platform (no tenantbox or keygen client, no role on
// its ServiceAccount binding those policies), and the ExternalSecret that
// fills its box Secret reads exactly saasapi-box's priv and
// controlplane-pub's platform_pub, never <base>/platform.
func TestPlatformPrivateKeyNeverReachesSaasapi(t *testing.T) {
	for name, args := range boxValueSets(t) {
		t.Run(name, func(t *testing.T) {
			docs := mustRender(t, args...)
			d := find(t, docs, "Deployment", "t-farmer-saasapi")
			for _, c := range podContainers(podSpec(d)) {
				for n := range envValues(c) {
					if strings.HasPrefix(n, "IMAS_TENANTBOX_") || strings.HasPrefix(n, "IMAS_CPBOX_") {
						t.Errorf("saasapi/%s has %s, an OpenBao client that reaches the platform key", c["name"], n)
					}
				}
			}
			for role, r := range rolesIfBootstrapped(t, docs) {
				if r[0] == "t-farmer-saasapi" && (r[2] == "imas-farmer-tenantbox" || r[2] == "imas-controlplane-box-keygen") {
					t.Errorf("saasapi's role %s binds %s", role, r[2])
				}
			}
			// Every ExternalSecret: none reads <base>/platform, and the
			// ones a saasapi pod mounts read no platform priv.
			saasSecrets := secretsReferenced(podSpec(d))
			for _, es := range docs {
				if es["kind"] != "ExternalSecret" {
					continue
				}
				target, _ := get(es, "spec", "target", "name").(string)
				data, _ := get(es, "spec", "data").([]any)
				for _, e := range data {
					key, _ := get(e, "remoteRef", "key").(string)
					if strings.HasSuffix(key, "/platform") {
						t.Errorf("ExternalSecret %s reads %s", target, key)
					}
					if saasSecrets[target] && get(e, "remoteRef", "property") == "priv" && !strings.HasSuffix(key, "/saasapi-box") {
						t.Errorf("saasapi's Secret %s gets a private key from %s", target, key)
					}
				}
			}
		})
	}
}

// With ESO, saasapi's box Secret is synced from exactly two fields.
func TestSaasapiBoxExternalSecret(t *testing.T) {
	if has(mustRender(t), "ExternalSecret", "imas-saasapi-box") {
		t.Error("box ExternalSecret rendered with externalSecrets off")
	}
	docs := mustRender(t, "--set", "externalSecrets.enabled=true")
	es := find(t, docs, "ExternalSecret", "imas-saasapi-box")
	if get(es, "metadata", "labels", "app.kubernetes.io/component") != "saasapi" ||
		get(es, "spec", "target", "name") != "imas-saasapi-box" ||
		get(es, "spec", "secretStoreRef", "name") != "openbao" || get(es, "spec", "refreshInterval") != "1m" {
		t.Errorf("box ExternalSecret %v", es)
	}
	got := map[string]string{}
	for _, e := range get(es, "spec", "data").([]any) {
		got[get(e, "secretKey").(string)] = get(e, "remoteRef", "key").(string) + "#" + get(e, "remoteRef", "property").(string)
	}
	want := map[string]string{
		"saasapi-box.key":          "imas/tenant-x25519/saasapi-box#priv",
		"SAASAPI_PLATFORM_BOX_PUB": "imas/tenant-x25519/controlplane-pub#platform_pub",
	}
	if len(got) != len(want) {
		t.Errorf("box ExternalSecret data %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// It follows the tenant box path.
	docs = mustRender(t, "--set", "externalSecrets.enabled=true", "--set", "farmer.openbao.tenantBox.kvPath=other/box")
	for _, e := range get(find(t, docs, "ExternalSecret", "imas-saasapi-box"), "spec", "data").([]any) {
		if !strings.HasPrefix(get(e, "remoteRef", "key").(string), "other/box/") {
			t.Errorf("remote key %v", get(e, "remoteRef", "key"))
		}
	}
	// With saasapi off, nothing.
	if has(mustRender(t, "--set", "externalSecrets.enabled=true", "--set", "saasapi.enabled=false"), "ExternalSecret", "imas-saasapi-box") {
		t.Error("box ExternalSecret rendered with saasapi off")
	}
}

func TestSaasapiBoxValidation(t *testing.T) {
	for _, shared := range []string{"imas-farmer-nats-seeds", "imas-saasapi-nats", "t-farmer-db", "imas-saasapi-internal-auth"} {
		mustFail(t, "is another Secret this chart mounts", "--set", "saasapi.controlPlaneBox.secretName="+shared)
	}
	mustFail(t, "is another Secret this chart mounts", "--set", "tls.mode=secret", "--set", "tls.secretName=bus-tls",
		"--set", "saasapi.controlPlaneBox.secretName=bus-tls")
	mustFail(t, "must differ", "--set", "saasapi.controlPlaneBox.platformPubKey=saasapi-box.key")
	mustFail(t, "not a valid Secret key", "--set", "saasapi.controlPlaneBox.privKey=a/b")
	mustFail(t, "not a valid Secret name", "--set", "saasapi.controlPlaneBox.secretName=Bad_Name")
	mustFail(t, "must equal credentialPublisher.kvMount", "--set", "externalSecrets.enabled=true",
		"--set", "farmer.openbao.tenantBox.kvMount=kv2")
	// saasapi off: nothing to check.
	mustRender(t, "--set", "saasapi.enabled=false", "--set", "saasapi.controlPlaneBox.secretName=imas-saasapi-nats")
}

// NOTES tells an operator what saasapi waits for.
func TestSaasapiBoxNotes(t *testing.T) {
	n := notes(t, mustRenderRelease(t, ""))
	for _, want := range []string{`Secret "imas-saasapi-box"`, "saasapi-box", "platform_pub", "create it by hand"} {
		if !strings.Contains(n, want) {
			t.Errorf("NOTES lacks %q:\n%s", want, n)
		}
	}
	if n := notes(t, mustRenderRelease(t, "", "--set", "controlPlaneBoxKeys.enabled=false")); !strings.Contains(n, "controlPlaneBoxKeys.enabled=false") {
		t.Errorf("NOTES doesn't warn that the keys must come from elsewhere:\n%s", n)
	}

	// FIX.3: with External Secrets off (the default), nothing creates the
	// two Secrets, so NOTES says plainly at install time that saasapi's
	// pods will hang until they exist, and where the commands are.
	n = notes(t, mustRenderRelease(t, ""))
	for _, want := range []string{"WARNING: nothing in this release creates Secrets", `"imas-saasapi-nats" and "imas-saasapi-box"`,
		"ContainerCreating", "CreateContainerConfigError", `"Eval install"`, "--wait"} {
		if !strings.Contains(n, want) {
			t.Errorf("NOTES lacks %q with externalSecrets off:\n%s", want, n)
		}
	}
	// ESO on, but not for saasapi: still by hand.
	n = notes(t, mustRenderRelease(t, "", "--set", "externalSecrets.enabled=true", "--set", "externalSecrets.saasapi.enabled=false"))
	if !strings.Contains(n, "WARNING: nothing in this release creates Secrets") || !strings.Contains(n, "externalSecrets.saasapi.enabled=false: create it by hand") {
		t.Errorf("NOTES doesn't warn with externalSecrets.saasapi.enabled=false:\n%s", n)
	}
	// ESO syncs both: no warning.
	if n := notes(t, mustRenderRelease(t, "", "--set", "externalSecrets.enabled=true")); strings.Contains(n, "WARNING: nothing in this release creates") {
		t.Errorf("NOTES warns although ESO syncs both Secrets:\n%s", n)
	}
	// No saasapi: nothing to wait for.
	if n := notes(t, mustRenderRelease(t, "", "--set", "saasapi.enabled=false")); strings.Contains(n, "imas-saasapi-box") {
		t.Errorf("NOTES mentions saasapi's Secrets with saasapi off:\n%s", n)
	}
}
