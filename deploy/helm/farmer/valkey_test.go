package farmerchart

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/openbao/openbaotest"
)

// Unit S5 (docs/briefs/S5-valkey-hardening.md): Valkey's password,
// TLS in the clients, no eviction.

const (
	valkeySecret      = "imas-valkey-auth"
	valkeyPasswordDir = "/var/run/secrets/imas/valkey"
	valkeyCADir       = "/var/run/secrets/imas/valkey-ca"
)

// valkeyClients are the two Valkey clients and their variable prefixes.
var valkeyClients = []struct{ deploy, container, prefix string }{
	{"t-farmer", "farmer", "IMAS"},
	{"t-farmer-saasapi", "saasapi", "SAASAPI"},
}

// The ExternalSecret writes Secret imas-valkey-auth, key password, from
// property valkey_password of the seed path; its name and key follow
// valkey.auth.secretName/key.
func TestValkeyExternalSecret(t *testing.T) {
	es := find(t, mustRender(t, "--set", "externalSecrets.enabled=true"), "ExternalSecret", valkeySecret)
	if get(es, "spec", "target", "name") != valkeySecret {
		t.Errorf("target %v", get(es, "spec", "target"))
	}
	data := get(es, "spec", "data").([]any)
	if len(data) != 1 || get(data[0], "secretKey") != "password" ||
		get(data[0], "remoteRef", "key") != "platform/imas/nats-seeds" || get(data[0], "remoteRef", "property") != "valkey_password" {
		t.Errorf("data %v", data)
	}

	renamed := find(t, mustRender(t, "--set", "externalSecrets.enabled=true",
		"--set", "valkey.auth.secretName=core-valkey", "--set", "valkey.auth.key=pw",
		"--set", "valkey.auth.aclUsers.default.passwordKey=pw"), "ExternalSecret", "core-valkey")
	if get(renamed, "spec", "target", "name") != "core-valkey" || get(renamed, "spec", "data", 0, "secretKey") != "pw" {
		t.Errorf("renamed ExternalSecret %v", get(renamed, "spec"))
	}

	off := mustRender(t, "--set", "externalSecrets.enabled=true",
		"--set", "valkey.auth.enabled=false", "--set", "valkey.auth.allowInsecure=true")
	if has(off, "ExternalSecret", valkeySecret) {
		t.Error("ExternalSecret rendered with valkey.auth.enabled=false")
	}
}

// The password reaches farmer and saasapi as a file, that key only, and
// never as an env var.
func TestValkeyPasswordMountedAsFile(t *testing.T) {
	docs := mustRender(t)
	for _, c := range valkeyClients {
		d := find(t, docs, "Deployment", c.deploy)
		ctr := container(t, d, c.container)
		env := envMap(ctr)
		if got := env[c.prefix+"_VALKEY_PASSWORD_FILE"]["value"]; got != valkeyPasswordDir+"/password" {
			t.Errorf("%s %s_VALKEY_PASSWORD_FILE = %v", c.container, c.prefix, got)
		}
		for name := range env {
			if strings.Contains(name, "VALKEY") && strings.Contains(name, "PASSWORD") && !strings.HasSuffix(name, "_FILE") {
				t.Errorf("%s has env %s", c.container, name)
			}
		}
		mounts := byName(ctr["volumeMounts"])
		if m := mounts["valkey-auth"]; m == nil || m["mountPath"] != valkeyPasswordDir || m["readOnly"] != true {
			t.Errorf("%s valkey-auth mount %v", c.container, m)
		}
		v := byName(podSpec(d)["volumes"])["valkey-auth"]
		if get(v, "secret", "secretName") != valkeySecret || get(v, "secret", "defaultMode") != 0o440 ||
			yamlString(t, get(v, "secret", "items")) != "- key: password\n  path: password\n" {
			t.Errorf("%s valkey-auth volume %v", c.container, v)
		}
		// TLS is off by default: nothing of it.
		for _, n := range []string{"_VALKEY_TLS", "_VALKEY_TLS_CA_FILE", "_VALKEY_TLS_SERVER_NAME"} {
			if _, ok := env[c.prefix+n]; ok {
				t.Errorf("%s has %s%s with TLS off", c.container, c.prefix, n)
			}
		}
		if mounts["valkey-ca"] != nil {
			t.Errorf("%s mounts valkey-ca with TLS off", c.container)
		}
	}
	// Only farmer and saasapi mount it: no Job does.
	for _, d := range docs {
		if d["kind"] != "Job" && d["kind"] != "Deployment" {
			continue
		}
		name := get(d, "metadata", "name")
		if name == "t-farmer" || name == "t-farmer-saasapi" {
			continue
		}
		if strings.Contains(yamlString(t, podSpec(d)["volumes"]), valkeySecret) {
			t.Errorf("%v %v mounts %s", d["kind"], name, valkeySecret)
		}
	}
}

// The Secret's name is never in an env var or a ConfigMap, and no
// rendered env var or ConfigMap carries a password, in any of the
// configurations below.
func TestValkeyPasswordNeverInEnvOrConfigMap(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--set", "externalSecrets.enabled=true"},
		{"--set", "valkey.tls.enabled=true", "--set", "valkey.tls.caConfigMap=valkey-ca", "--set", "valkey.tls.existingSecret=valkey-tls"},
		{"-f", ciValues(t, "external-values.yaml")},
	} {
		docs := mustRender(t, args...)
		for _, d := range docs {
			if d["kind"] == "ConfigMap" {
				s := yamlString(t, d["data"])
				if strings.Contains(s, valkeySecret) || regexp.MustCompile(`(?i)valkey_?password\s*[:=]\s*\S`).MatchString(s) {
					t.Errorf("%v: ConfigMap %v names Valkey's password: %s", args, get(d, "metadata", "name"), s)
				}
			}
			spec, _ := get(d, "spec", "template", "spec").(obj)
			if spec == nil {
				continue
			}
			for _, list := range []string{"containers", "initContainers"} {
				cs, _ := spec[list].([]any)
				for _, c := range cs {
					env, _ := c.(obj)["env"].([]any)
					if s := yamlString(t, env); strings.Contains(s, valkeySecret) {
						t.Errorf("%v: %v %v container %v takes an env var from %s", args, d["kind"], get(d, "metadata", "name"), c.(obj)["name"], valkeySecret)
					}
				}
			}
		}
	}
}

// valkey.auth.enabled=false renders only with allowInsecure, and then
// neither client gets a password file or mount; NOTES warns.
func TestValkeyAuthSwitch(t *testing.T) {
	mustFail(t, "valkey.auth.enabled=false needs valkey.auth.allowInsecure=true", "--set", "valkey.auth.enabled=false")
	docs := mustRender(t, "--set", "valkey.auth.enabled=false", "--set", "valkey.auth.allowInsecure=true")
	for _, c := range valkeyClients {
		d := find(t, docs, "Deployment", c.deploy)
		if _, ok := envMap(container(t, d, c.container))[c.prefix+"_VALKEY_PASSWORD_FILE"]; ok {
			t.Errorf("%s has a password file with auth off", c.container)
		}
		if byName(podSpec(d)["volumes"])["valkey-auth"] != nil {
			t.Errorf("%s mounts valkey-auth with auth off", c.container)
		}
	}
	insecure := notes(t, mustRenderRelease(t, "", "--set", "valkey.auth.enabled=false", "--set", "valkey.auth.allowInsecure=true"))
	if !strings.Contains(insecure, "VALKEY HAS NO PASSWORD") || !strings.Contains(insecure, "throwaway install only") {
		t.Errorf("NOTES with auth off:\n%s", insecure)
	}
	on := notes(t, mustRenderRelease(t, ""))
	if strings.Contains(on, "NO PASSWORD") || !strings.Contains(on, "password from Secret imas-valkey-auth") ||
		!strings.Contains(on, "maxmemory-policy noeviction") || !strings.Contains(on, "create the Secret from that property") {
		t.Errorf("NOTES with auth on:\n%s", on)
	}

	// The bundled Valkey takes the password from the same Secret, as user
	// "default" only, and nothing that would put it in values or env.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--set", "valkey.auth.key=pw"}, `passwordKey "pw"`},
		{[]string{"--set", "valkey.auth.aclUsers.default.password=inline"}, "no inline password"},
		{[]string{"--set", "valkey.auth.aclUsers.reader.permissions=+@read", "--set", "valkey.auth.aclUsers.reader.passwordKey=reader"}, `the "default" user only`},
		{[]string{"--set", "valkey.auth.usersExistingSecret=other"}, "valkey.auth.usersExistingSecret must stay"},
		{[]string{"--set", "valkey.auth.aclConfig=user default on >x"}, "valkey.auth.aclConfig is not supported"},
		{[]string{"--set", "valkey.metrics.enabled=true"}, "valkey.metrics.enabled is not supported"},
		{[]string{"--set", "valkey.auth.secretName="}, "valkey.auth.secretName and valkey.auth.key are required"},
		{[]string{"--set", "valkey.auth.secretName=Bad_Name"}, "is not a valid Secret name"},
	} {
		mustFail(t, tc.want, tc.args...)
	}
	// With an external Valkey the subchart's users don't matter.
	mustRender(t, "--set", "valkey.enabled=false", "--set", "valkey.addrs[0]=valkey:6379", "--set", "valkey.auth.key=pw")
}

// TLS mounts the CA ConfigMap in both clients and sets the TLS variables;
// it needs a CA, and the bundled Valkey its server certificate Secret.
func TestValkeyTLS(t *testing.T) {
	mustFail(t, "valkey.tls.caConfigMap is required", "--set", "valkey.tls.enabled=true", "--set", "valkey.tls.existingSecret=valkey-tls")
	mustFail(t, "valkey.tls.existingSecret is required with valkey.enabled and valkey.tls.enabled",
		"--set", "valkey.tls.enabled=true", "--set", "valkey.tls.caConfigMap=valkey-ca")

	for _, tc := range []struct {
		name       string
		args       []string
		caKey      string
		serverName string
	}{
		{"bundled", []string{"--set", "valkey.tls.enabled=true", "--set", "valkey.tls.caConfigMap=valkey-ca", "--set", "valkey.tls.existingSecret=valkey-tls"}, "ca.crt", ""},
		{"external, server name", []string{"--set", "valkey.enabled=false", "--set", "valkey.addrs[0]=valkey.example:6380",
			"--set", "valkey.tls.enabled=true", "--set", "valkey.tls.caConfigMap=valkey-ca", "--set", "valkey.tls.caKey=root.pem",
			"--set", "valkey.tls.serverName=valkey.example"}, "root.pem", "valkey.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs := mustRender(t, tc.args...)
			for _, c := range valkeyClients {
				d := find(t, docs, "Deployment", c.deploy)
				ctr := container(t, d, c.container)
				env := envMap(ctr)
				if env[c.prefix+"_VALKEY_TLS"]["value"] != "true" ||
					env[c.prefix+"_VALKEY_TLS_CA_FILE"]["value"] != valkeyCADir+"/"+tc.caKey {
					t.Errorf("%s TLS env %v %v", c.container, env[c.prefix+"_VALKEY_TLS"], env[c.prefix+"_VALKEY_TLS_CA_FILE"])
				}
				sn, ok := env[c.prefix+"_VALKEY_TLS_SERVER_NAME"]
				if tc.serverName == "" && ok || tc.serverName != "" && sn["value"] != tc.serverName {
					t.Errorf("%s server name %v, want %q", c.container, sn, tc.serverName)
				}
				if m := byName(ctr["volumeMounts"])["valkey-ca"]; m == nil || m["mountPath"] != valkeyCADir || m["readOnly"] != true {
					t.Errorf("%s valkey-ca mount %v", c.container, m)
				}
				v := byName(podSpec(d)["volumes"])["valkey-ca"]
				if get(v, "configMap", "name") != "valkey-ca" || get(v, "configMap", "items", 0, "key") != tc.caKey {
					t.Errorf("%s valkey-ca volume %v", c.container, v)
				}
			}
		})
	}
}

// The bootstrap Job generates Valkey's password once, in the seed path,
// and never overwrites it: the script text, and the script run against a
// fake bao. It waits out HA OpenBao's windows (UAT HA run 42448281672): a
// mount still upgrading, and a check-and-set refusal it re-reads.
func TestValkeyPasswordBootstrap(t *testing.T) {
	docs := mustRender(t)
	script := valkeyBootstrapSnippet(t, docs)
	helpers := kvHelpersSnippet(t, docs)
	if !strings.Contains(helpers, "kv_wait=120") {
		t.Errorf("kv helpers lack kv_wait=120:\n%s", helpers)
	}
	for _, want := range []string{
		`vkv="secret/platform/imas/nats-seeds"`,
		`vmeta="secret/metadata/platform/imas/nats-seeds"`,
		`vver="$(bao read -field=current_version "$vmeta" 2>"$err")"`,
		`bao kv get -field=valkey_password "$vkv"`,
		`vop="patch -cas=$vver"`,
		`vop="put -cas=0"`,
		`head -c 32 /dev/urandom | base64 | tr -d '=\n' | bao kv $vop "$vkv" valkey_password=-`,
		"check-and-set parameter did not match",
		"kv_upgrading",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if regexp.MustCompile(`bao kv put [^-]`).MatchString(script) || strings.Contains(script, "echo \"$(") {
		t.Errorf("script writes without check-and-set or prints a value:\n%s", script)
	}
	if other := valkeyBootstrapSnippet(t, mustRender(t, "--set", "externalSecrets.seedMount=kv", "--set", "externalSecrets.seedPath=/ops/seeds/")); !strings.Contains(other, `vkv="kv/ops/seeds"`) {
		t.Errorf("seed mount and path not followed:\n%s", other)
	}
	// The seed mount is enabled as KV v2 like the others.
	prep := initContainer(t, find(t, mustRender(t, "--set", "externalSecrets.seedMount=kv"), "Job", "t-farmer-openbao-bootstrap"), "prepare")
	if !strings.Contains(get(prep, "args", 0).(string), "\nenable_kv kv\n") {
		t.Error("the seed mount is not enabled")
	}
	// Auth off: no password is generated.
	if s := get(initContainer(t, find(t, mustRender(t, "--set", "valkey.auth.enabled=false", "--set", "valkey.auth.allowInsecure=true"),
		"Job", "t-farmer-openbao-bootstrap"), "prepare"), "args", 0).(string); strings.Contains(s, "valkey_password") {
		t.Error("auth off, yet the bootstrap writes valkey_password")
	}

	if _, err := exec.LookPath("sh"); err != nil {
		skipUnlessRequired(t, "no sh: can't run the bootstrap script")
	}
	// try runs the kv helpers and the snippet, as the prepare script
	// does, against the fake; set writes the fake's state files first.
	try := func(t *testing.T, store string) (string, error) {
		t.Helper()
		bin := t.TempDir()
		if err := os.WriteFile(filepath.Join(bin, "bao"), []byte(fakeBao), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-ec", helpers+script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_KV="+store, "FAKE_PATH=secret/platform/imas/nats-seeds",
			"FAKE_META=secret/metadata/platform/imas/nats-seeds")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	run := func(t *testing.T, store string) string {
		t.Helper()
		out, err := try(t, store)
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		return out
	}
	set := func(t *testing.T, store string, files map[string]string) {
		t.Helper()
		for f, v := range files {
			if err := os.WriteFile(filepath.Join(store, f), []byte(v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	read := func(t *testing.T, store, f string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(store, f))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	b64 := regexp.MustCompile(`^[A-Za-z0-9+/]{43}$`)

	t.Run("no path yet", func(t *testing.T) {
		store := t.TempDir()
		out := run(t, store)
		pw := read(t, store, "prop_valkey_password")
		if !b64.MatchString(pw) || read(t, store, "version") != "1" || !strings.Contains(read(t, store, "calls"), "kv put -cas=0 secret/platform/imas/nats-seeds valkey_password=-") {
			t.Fatalf("password %q, version %q, calls:\n%s", pw, read(t, store, "version"), read(t, store, "calls"))
		}
		if strings.Contains(out, pw) {
			t.Errorf("the script printed the password:\n%s", out)
		}
		// A second run keeps it.
		out = run(t, store)
		if read(t, store, "prop_valkey_password") != pw || read(t, store, "version") != "1" || !strings.Contains(out, "kept") {
			t.Errorf("second run changed it: version %s\n%s", read(t, store, "version"), out)
		}
	})
	t.Run("seeds there, no password", func(t *testing.T) {
		store := t.TempDir()
		for f, v := range map[string]string{"exists": "", "version": "3", "prop_sys_user": "SUSEED", "prop_farmer_nkey": "SUNKEY"} {
			if err := os.WriteFile(filepath.Join(store, f), []byte(v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		run(t, store)
		if !b64.MatchString(read(t, store, "prop_valkey_password")) || read(t, store, "version") != "4" ||
			read(t, store, "prop_sys_user") != "SUSEED" || read(t, store, "prop_farmer_nkey") != "SUNKEY" ||
			!strings.Contains(read(t, store, "calls"), "kv patch -cas=3 secret/platform/imas/nats-seeds valkey_password=-") {
			t.Errorf("version %s, calls:\n%s", read(t, store, "version"), read(t, store, "calls"))
		}
	})
	t.Run("mount still upgrading", func(t *testing.T) {
		store := t.TempDir()
		set(t, store, map[string]string{"upgrading": "3"})
		out := run(t, store)
		if !b64.MatchString(read(t, store, "prop_valkey_password")) || read(t, store, "version") != "1" ||
			!strings.Contains(out, "still upgrading; trying again") || !strings.Contains(out, "generated") {
			t.Errorf("version %s, output:\n%s", read(t, store, "version"), out)
		}
	})
	t.Run("another writer first", func(t *testing.T) {
		store := t.TempDir()
		set(t, store, map[string]string{"race": ""})
		out := run(t, store)
		if read(t, store, "prop_valkey_password") != "theirs" || read(t, store, "version") != "1" ||
			!strings.Contains(out, "check-and-set refused") || !strings.Contains(out, "kept") {
			t.Errorf("version %s, output:\n%s", read(t, store, "version"), out)
		}
	})
	t.Run("write refused", func(t *testing.T) {
		store := t.TempDir()
		set(t, store, map[string]string{"deny": ""})
		out, err := try(t, store)
		if err == nil || !strings.Contains(out, "permission denied") || !strings.Contains(out, "could not write valkey_password") ||
			strings.Contains(out, "another writer") {
			t.Errorf("err %v, output:\n%s", err, out)
		}
	})
	t.Run("latest version deleted", func(t *testing.T) {
		store := t.TempDir()
		set(t, store, map[string]string{"exists": "", "version": "2", "deleted": "", "prop_sys_user": "SUSEED"})
		out, err := try(t, store)
		if err == nil || !strings.Contains(out, "latest version of secret/platform/imas/nats-seeds is deleted") ||
			!strings.Contains(out, "nothing was overwritten") || strings.Contains(read(t, store, "calls"), "patch") ||
			strings.Contains(read(t, store, "calls"), "put") {
			t.Errorf("err %v, output:\n%s\ncalls:\n%s", err, out, read(t, store, "calls"))
		}
	})
	t.Run("still upgrading at the deadline", func(t *testing.T) {
		store := t.TempDir()
		set(t, store, map[string]string{"upgrading": "1000"})
		bin := t.TempDir()
		if err := os.WriteFile(filepath.Join(bin, "bao"), []byte(fakeBao), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-ec", strings.Replace(helpers, "kv_wait=120", "kv_wait=2", 1)+script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_KV="+store, "FAKE_PATH=secret/platform/imas/nats-seeds",
			"FAKE_META=secret/metadata/platform/imas/nats-seeds")
		b, err := cmd.CombinedOutput()
		out := string(b)
		if err == nil || !strings.Contains(out, "not added to secret/platform/imas/nats-seeds after 2s") || !strings.Contains(out, "still upgrading") {
			t.Errorf("err %v, output:\n%s", err, out)
		}
	})
	t.Run("password there", func(t *testing.T) {
		store := t.TempDir()
		for f, v := range map[string]string{"exists": "", "version": "7", "prop_valkey_password": "ops-chose-this"} {
			if err := os.WriteFile(filepath.Join(store, f), []byte(v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		run(t, store)
		if read(t, store, "prop_valkey_password") != "ops-chose-this" || read(t, store, "version") != "7" ||
			strings.Contains(read(t, store, "calls"), "patch") || strings.Contains(read(t, store, "calls"), "put") {
			t.Errorf("overwrote it; calls:\n%s", read(t, store, "calls"))
		}
	})
}

// valkeyBootstrapSnippet is the valkey-password block of the bootstrap
// Job's prepare script.
func valkeyBootstrapSnippet(t *testing.T, docs []obj) string {
	t.Helper()
	s := get(initContainer(t, find(t, docs, "Job", "t-farmer-openbao-bootstrap"), "prepare"), "args", 0).(string)
	i, j := strings.Index(s, "# valkey-password: begin"), strings.Index(s, "# valkey-password: end")
	if i < 0 || j < i {
		t.Fatalf("no valkey-password block in the prepare script:\n%s", s)
	}
	return s[i:j]
}

// kvHelpersSnippet is the kv-helpers block of the bootstrap Job's
// prepare script, which the valkey-password block uses.
func kvHelpersSnippet(t *testing.T, docs []obj) string {
	t.Helper()
	s := get(initContainer(t, find(t, docs, "Job", "t-farmer-openbao-bootstrap"), "prepare"), "args", 0).(string)
	i, j := strings.Index(s, "# kv-helpers: begin"), strings.Index(s, "# kv-helpers: end")
	if i < 0 || j < i {
		t.Fatalf("no kv-helpers block in the prepare script:\n%s", s)
	}
	return s[i:j]
}

// fakeBao is a KV v2 path in a directory ($FAKE_KV): "exists", "version"
// and one prop_<name> file per property. It implements the calls the
// bootstrap makes (kv get, kv put and kv patch with check-and-set on
// $FAKE_PATH, read of its metadata at $FAKE_META) with the messages and exit
// codes of the OpenBao 2.7.1 CLI, the Job's image (2.6.3's CLI says "not
// present in secret" for a missing field), and logs every call to "calls". Its modes,
// each a file in $FAKE_KV:
//   - "upgrading" holds N: the next N calls answer what a KV v2 mount
//     enabled moments ago answers on an HA standby;
//   - "race": just before the first write, another writer adds
//     valkey_password=theirs, so that write's check-and-set is refused;
//   - "deny": every write is refused (403);
//   - "deleted": the latest version is soft-deleted (kv get answers "No
//     data found at").
const fakeBao = `#!/bin/sh
set -eu
kv=$FAKE_KV
echo "$*" >>"$kv/calls"
if [ -s "$kv/upgrading" ] && [ "$(cat "$kv/upgrading")" -gt 0 ]; then
	printf '%s' $(($(cat "$kv/upgrading") - 1)) >"$kv/upgrading"
	printf 'Error making API request.\n\nCode: 400. Errors:\n\n* Waiting for the primary to upgrade from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service when the primary is finished.\n' >&2
	exit 2
fi
if [ "$1" = read ]; then
	# bao read -field=current_version <mount>/metadata/<path>
	[ "$2" = -field=current_version ] && [ "$3" = "$FAKE_META" ] || exit 64
	[ -f "$kv/exists" ] || { echo "No value found at $FAKE_META" >&2; exit 2; }
	cat "$kv/version"
	exit 0
fi
[ "$1" = kv ] || exit 64
shift
case "$1" in
get)
	field=${2#-field=}
	[ "$3" = "$FAKE_PATH" ] || exit 65
	[ -f "$kv/exists" ] || { echo "No value found at ${FAKE_PATH%%/*}/data/${FAKE_PATH#*/}" >&2; exit 2; }
	[ ! -f "$kv/deleted" ] || { echo "No data found at ${FAKE_PATH%%/*}/data/${FAKE_PATH#*/}" >&2; exit 2; }
	[ -f "$kv/prop_$field" ] || { echo "Field \"$field\" not present in map" >&2; exit 1; }
	cat "$kv/prop_$field"
	;;
metadata)
	# bao kv metadata get has no -field (OpenBao 2.x): a script that
	# calls it gets the CLI's error.
	echo "flag provided but not defined: -field" >&2
	exit 1
	;;
patch|put)
	op=$1
	cas=${2#-cas=}
	[ "$3" = "$FAKE_PATH" ] || exit 65
	k=${4%%=*}
	[ "${4#*=}" = - ] || exit 66
	if [ -f "$kv/deny" ]; then
		printf 'Error writing data to %s: Error making API request.\n\nCode: 403. Errors:\n\n* permission denied\n' "$FAKE_PATH" >&2
		exit 2
	fi
	if [ -f "$kv/race" ]; then
		rm "$kv/race"
		[ -f "$kv/exists" ] || printf 0 >"$kv/version"
		touch "$kv/exists"
		printf theirs >"$kv/prop_valkey_password"
		printf '%s' $(($(cat "$kv/version") + 1)) >"$kv/version"
	fi
	refuse() {
		printf 'Error writing data to %s: Error making API request.\n\nCode: 400. Errors:\n\n* check-and-set parameter did not match the current version\n' "$FAKE_PATH" >&2
		exit 2
	}
	if [ "$op" = put ]; then
		[ "$cas" = 0 ] && [ ! -f "$kv/exists" ] || refuse
		touch "$kv/exists"
		printf 0 >"$kv/version"
	else
		[ -f "$kv/exists" ] && [ "$(cat "$kv/version")" = "$cas" ] || refuse
	fi
	cat >"$kv/prop_$k"
	printf '%s' $(($(cat "$kv/version") + 1)) >"$kv/version"
	;;
*)
	exit 64
	;;
esac
`

// The bundled Valkey (subchart): its own auth from the same Secret, user
// default, no eviction, the same port with TLS; and in the replicated mode
// the replicas authenticate to the primary.
func TestValkeySubchart(t *testing.T) {
	helmBin(t)
	if !depsVendored(t) {
		skipUnlessRequired(t, "charts/ not populated; run `helm dependency build deploy/helm/farmer` to include the subcharts")
	}
	docs, err := runHelm(t, chartDir(t), required...)
	if err != nil {
		t.Fatal(err)
	}
	cfg := get(find(t, docs, "ConfigMap", "t-valkey-config"), "data", "valkey.conf").(string)
	if !strings.Contains(cfg, "maxmemory-policy noeviction") {
		t.Errorf("valkey.conf:\n%s", cfg)
	}
	d := find(t, docs, "Deployment", "t-valkey")
	if get(byName(podSpec(d)["volumes"])["valkey-users-secret"], "secret", "secretName") != valkeySecret {
		t.Errorf("bundled Valkey doesn't read %s: %v", valkeySecret, podSpec(d)["volumes"])
	}
	init := get(find(t, docs, "ConfigMap", "t-valkey-init-scripts"), "data", "init.sh").(string)
	for _, want := range []string{`get_user_password "default" "password"`, "aclfile /etc/valkey/users.acl"} {
		if !strings.Contains(init, want) {
			t.Errorf("init.sh lacks %q", want)
		}
	}
	for _, ctr := range podSpec(d)["containers"].([]any) {
		if s := yamlString(t, ctr.(obj)["env"]); strings.Contains(s, valkeySecret) {
			t.Errorf("Valkey container %v takes an env var from %s", ctr.(obj)["name"], valkeySecret)
		}
	}

	rep, err := runHelm(t, chartDir(t), append(append([]string{}, required...),
		"--set", "valkey.replica.enabled=true", "--set", "valkey.replica.persistence.size=1Gi")...)
	if err != nil {
		t.Fatal(err)
	}
	init = get(find(t, rep, "ConfigMap", "t-valkey-init-scripts"), "data", "init.sh").(string)
	for _, want := range []string{`REPL_PASSWORD=$(get_user_password "default" "password")`, `echo "masteruser default"`} {
		if !strings.Contains(init, want) {
			t.Errorf("replicated init.sh lacks %q", want)
		}
	}

	tls, err := runHelm(t, chartDir(t), append(append([]string{}, required...),
		"--set", "valkey.tls.enabled=true", "--set", "valkey.tls.caConfigMap=valkey-ca", "--set", "valkey.tls.existingSecret=valkey-tls")...)
	if err != nil {
		t.Fatal(err)
	}
	init = get(find(t, tls, "ConfigMap", "t-valkey-init-scripts"), "data", "init.sh").(string)
	if !strings.Contains(init, `echo "tls-port 6379"`) || !strings.Contains(init, `echo "port 0"`) {
		t.Errorf("TLS init.sh doesn't serve TLS on 6379:\n%s", init)
	}
	if env := envValues(container(t, farmerDeploy(t, tls), "farmer")); env["IMAS_VALKEY_ADDRS"] != "t-valkey.imas-core.svc.cluster.local:6379" {
		t.Errorf("IMAS_VALKEY_ADDRS %q", env["IMAS_VALKEY_ADDRS"])
	}
}

// The bootstrap Job's Valkey password step against a real OpenBao and its
// bao CLI (natskeys-openbao-realserver.yml; skipped unless
// IMAS_TEST_OPENBAO_ADDR and _TOKEN are set and bao is on PATH). It runs
// on a fresh KV v2 mount (externalSecrets.seedMount), removed when done.
func TestOpenBaoValkeyPassword(t *testing.T) {
	addr, token := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || token == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	if _, err := exec.LookPath("bao"); err != nil {
		t.Fatal("IMAS_TEST_OPENBAO_ADDR is set but bao is not on PATH")
	}
	b := make([]byte, 4)
	rand.Read(b)
	mount := "valkeypwtest-" + hex.EncodeToString(b)
	admin := openbaotest.NewAdmin(t, addr, token)
	admin.Must(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]any{"version": "2"}})
	t.Cleanup(func() { admin.Delete("sys/mounts/" + mount) })

	// The kv helpers the block uses, then the block, as in the prepare
	// script.
	docs := mustRender(t, "--set", "externalSecrets.seedMount="+mount)
	script := kvHelpersSnippet(t, docs) + valkeyBootstrapSnippet(t, docs)
	run := func() string {
		t.Helper()
		cmd := exec.Command("sh", "-ec", script)
		cmd.Env = append(os.Environ(), "BAO_ADDR="+addr, "BAO_TOKEN="+token)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		return string(out)
	}
	type secret struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	read := func() secret {
		t.Helper()
		var s secret
		if err := json.Unmarshal(admin.Must(http.MethodGet, mount+"/data/platform/imas/nats-seeds", nil), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	b64 := regexp.MustCompile(`^[A-Za-z0-9+/]{43}$`)

	// No path yet: created at version 1.
	out := run()
	s := read()
	pw := s.Data.Data["valkey_password"]
	if !b64.MatchString(pw) || s.Data.Metadata.Version != 1 || strings.Contains(out, pw) {
		t.Fatalf("first run: version %d, password %q, output:\n%s", s.Data.Metadata.Version, pw, out)
	}
	// Again: kept.
	run()
	if s := read(); s.Data.Data["valkey_password"] != pw || s.Data.Metadata.Version != 1 {
		t.Fatalf("second run changed it: version %d", s.Data.Metadata.Version)
	}
	// Seeds written over it by ops (a put replaces every property): the
	// password is added next to them, the seeds kept.
	admin.Must(http.MethodPost, mount+"/data/platform/imas/nats-seeds",
		map[string]any{"data": map[string]string{"sys_user": "SUSEED", "farmer_nkey": "SUNKEY"}})
	run()
	s = read()
	if !b64.MatchString(s.Data.Data["valkey_password"]) || s.Data.Data["sys_user"] != "SUSEED" ||
		s.Data.Data["farmer_nkey"] != "SUNKEY" || s.Data.Metadata.Version != 3 {
		t.Fatalf("next to the seeds: version %d, properties %v", s.Data.Metadata.Version, len(s.Data.Data))
	}
	// Latest version deleted: the step fails and writes nothing.
	admin.Must(http.MethodDelete, mount+"/data/platform/imas/nats-seeds", nil)
	cmd := exec.Command("sh", "-ec", script)
	cmd.Env = append(os.Environ(), "BAO_ADDR="+addr, "BAO_TOKEN="+token)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "nothing was overwritten") {
		t.Fatalf("a deleted latest version: err %v\n%s", err, out)
	}
}
