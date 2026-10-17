package dmzhub

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// openbaoScriptDir is a copy of this directory's scripts whose
// values-uat.yaml runs the bus in bus.tls.mode=openbao. The UAT itself
// runs secret mode (unit S1 leaves it there); this is how its bus CA copy
// code is exercised.
func openbaoScriptDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, f := range []string{"install.sh", "lib.sh", "values-uat.yaml", "values-ha.yaml"} {
		b, err := os.ReadFile(filepath.Join(dir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if f == "values-uat.yaml" {
			s := string(b)
			if strings.Count(s, "    mode: secret\n") != 1 {
				t.Fatal("values-uat.yaml: no single bus.tls.mode: secret line to switch")
			}
			b = []byte(strings.Replace(s, "    mode: secret\n", "    mode: openbao\n", 1))
		}
		if err := os.WriteFile(filepath.Join(d, f), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// stubKubectlBusCA is stubKubectl that also answers the bus CA ConfigMap
// reads, with STUB_BUSCA (empty: not found).
var stubKubectlBusCA = strings.Replace(stubKubectl, `*"get configmap imas-nats-trust -o json"*)`,
	`*"get configmap ${STUB_BUSCA_NAME:-none} -o json"*) [[ -s ${STUB_BUSCA:-} ]] || exit 1; cat "$STUB_BUSCA" ;;
*"get configmap imas-nats-trust -o json"*)`, 1)

// busCAConfigMap writes a ConfigMap JSON whose ca.crt is pemText.
func busCAConfigMap(t *testing.T, name, pemText string) string {
	return writeJSON(t, obj{"apiVersion": "v1", "kind": "ConfigMap", "metadata": obj{"name": name}, "data": obj{"ca.crt": pemText}})
}

type busCARun struct {
	code              int
	stderr, log, work string
}

// runBusCAInstall runs install.sh from scripts with the stubs: the core
// cluster's bus CA ConfigMap named srcName holds busCA (a path, or "").
func runBusCAInstall(t *testing.T, scripts string, env []string, withCore bool, srcName, busCA string) busCARun {
	t.Helper()
	realHelm, _ := exec.LookPath("helm")
	bin := t.TempDir()
	for name, body := range map[string]string{"kubectl": stubKubectlBusCA, "helm": stubHelm} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	kubeconfig := filepath.Join(t.TempDir(), "dmz.kubeconfig")
	coreKubeconfig := filepath.Join(t.TempDir(), "core.kubeconfig")
	for _, f := range []string{kubeconfig, coreKubeconfig} {
		if err := os.WriteFile(f, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logFile := filepath.Join(t.TempDir(), "calls.log")
	work := t.TempDir()
	trust := makeTrust(t)
	trust["bus-loader-user.jwt"] = trust["sys-account.jwt"]
	env = append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_LOG=" + logFile, "STUB_CHART=" + packageChart(t, testVersion, testVersion), "REAL_HELM=" + realHelm,
		"STUB_TRUST=" + trustConfigMap(t, trust), "STUB_BUSCA_NAME=" + srcName, "STUB_BUSCA=" + busCA,
		"DMZ_BUS_CA_SRC_CONFIGMAP=", "DMZ_BUS_CA_CONFIGMAP=",
	}, env...)
	args := []string{filepath.Join(scripts, "install.sh"), "--kubeconfig", kubeconfig,
		"--endpoints", filepath.Join(dir(t), "testdata", "endpoints.json"), "--release-tag", testTag,
		"--workdir", work, "--timeout", "5s"}
	if withCore {
		args = append(args, "--seeds-from-kubeconfig", coreKubeconfig)
	}
	cmd := exec.Command("bash", args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logFile)
	return busCARun{code: code, stderr: stderr.String(), log: string(b), work: work}
}

// Unit S1, the UAT copy step: in bus.tls.mode=openbao install.sh copies
// ca.crt of core's bus CA ConfigMap (DMZ_BUS_CA_SRC_CONFIGMAP) from the core
// cluster into the DMZ under the nats release's name
// (DMZ_BUS_CA_CONFIGMAP, which it passes as loader.caConfigMap), byte for
// byte, and nothing else of it; an override of either name is delivered.
func TestInstallCopiesBusCAInOpenBaoMode(t *testing.T) {
	need(t, true, "bash", "jq", "helm", "base64", "openssl")
	scripts := openbaoScriptDir(t)
	caPEM, err := os.ReadFile(newPKI(t, "unused.test").caFile)
	if err != nil {
		t.Fatal(err)
	}
	ca := strings.TrimSpace(string(caPEM))
	for _, c := range []struct {
		name, src, dst string
		env            []string
	}{
		{"defaults", "imas-bus-ca", "imas-bus-ca", nil},
		{"override both", "core-bus-ca", "dmz-bus-ca", []string{"DMZ_BUS_CA_SRC_CONFIGMAP=core-bus-ca", "DMZ_BUS_CA_CONFIGMAP=dmz-bus-ca"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The source ConfigMap may carry more than ca.crt; only ca.crt crosses.
			src := writeJSON(t, obj{"apiVersion": "v1", "kind": "ConfigMap", "metadata": obj{"name": c.src},
				"data": obj{"ca.crt": ca, "note": "not copied"}})
			r := runBusCAInstall(t, scripts, c.env, true, c.src, src)
			if r.code != 0 {
				t.Fatalf("install.sh exited %d:\n%s", r.code, r.stderr)
			}
			coreRead := "-n imas-core get configmap " + c.src + " -o json"
			if !regexp.MustCompile(`(?m)^kubectl --kubeconfig \S+core\.kubeconfig ` + regexp.QuoteMeta(coreRead) + `$`).MatchString(r.log) {
				t.Errorf("no read of core's %s with the core kubeconfig:\n%s", c.src, r.log)
			}
			if !strings.Contains(r.log, "create configmap "+c.dst+" --from-file=ca.crt=") {
				t.Errorf("no DMZ ConfigMap %s created from ca.crt:\n%s", c.dst, r.log)
			}
			if !strings.Contains(r.log, "trustfile --from-file=ca.crt "+ca) {
				t.Errorf("ca.crt did not reach the DMZ ConfigMap byte for byte:\n%s", r.log)
			}
			if strings.Contains(r.log, "not copied") {
				t.Error("a key other than ca.crt was copied")
			}
			if !strings.Contains(r.log, "label configmap "+c.dst+" imas.io/purpose=imas-uat") {
				t.Errorf("DMZ ConfigMap %s not labelled", c.dst)
			}
			// The nats release reads it under that name.
			vr, err := os.ReadFile(filepath.Join(r.work, "values-run.yaml"))
			if err != nil || !strings.Contains(string(vr), "caConfigMap: \""+c.dst+"\"") {
				t.Errorf("values-run.yaml does not set loader.caConfigMap to %s: %v\n%s", c.dst, err, vr)
			}
			rendered, _ := os.ReadFile(filepath.Join(r.work, "rendered.yaml"))
			if !regexp.MustCompile(`(?m)- name: loader-ca\n\s+configMap:\n\s+name: ` + regexp.QuoteMeta(c.dst) + `$`).Match(rendered) {
				t.Errorf("the render's loader-ca volume is not ConfigMap %s", c.dst)
			}
			// Order: after the trust, before the chart.
			iCA, iHelm := strings.Index(r.log, "create configmap "+c.dst), strings.Index(r.log, "helm upgrade --install")
			if iCA < strings.Index(r.log, "create configmap imas-nats-trust") || iHelm < iCA {
				t.Error("the bus CA is not copied after the trust and before the install")
			}
		})
	}
}

// Without --seeds-from-kubeconfig the bus CA ConfigMap must already be in
// the DMZ and hold one public CA certificate; the copy refuses a key, a
// non-CA certificate or a missing ConfigMap, and an invalid name.
func TestInstallBusCAProblems(t *testing.T) {
	need(t, true, "bash", "jq", "helm", "base64", "openssl")
	scripts := openbaoScriptDir(t)
	p := newPKI(t, "leaf.test")
	caPEM, _ := os.ReadFile(p.caFile)
	ca := strings.TrimSpace(string(caPEM))
	leaf := strings.TrimSpace(string(pemCert(p.cert.Certificate[0])))

	// Existing in the DMZ: used as is, not rewritten.
	r := runBusCAInstall(t, scripts, nil, false, "imas-bus-ca", busCAConfigMap(t, "imas-bus-ca", ca))
	if r.code != 0 {
		t.Fatalf("install.sh with an existing bus CA exited %d:\n%s", r.code, r.stderr)
	}
	if strings.Contains(r.log, "create configmap imas-bus-ca") || !strings.Contains(r.stderr, "bus CA: using the existing ConfigMap imas-dmz/imas-bus-ca") {
		t.Errorf("existing bus CA not used as is:\n%s\n%s", r.log, r.stderr)
	}

	for _, c := range []struct {
		name     string
		withCore bool
		data     string
		env      []string
		want     string
	}{
		{"missing in the DMZ", false, "", nil, "ConfigMap imas-dmz/imas-bus-ca not found"},
		{"missing on core", true, "", nil, "could not read ConfigMap imas-core/imas-bus-ca on the core cluster"},
		{"private key", true, busCAConfigMap(t, "imas-bus-ca", ca+"\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"), nil, "holds a private key"},
		{"not a CA", true, busCAConfigMap(t, "imas-bus-ca", leaf), nil, "is not a CA certificate"},
		{"two certificates", true, busCAConfigMap(t, "imas-bus-ca", ca+"\n"+ca), nil, "is not one PEM certificate"},
		{"empty", true, busCAConfigMap(t, "imas-bus-ca", ""), nil, "is missing or empty"},
		{"bad source name", true, "", []string{"DMZ_BUS_CA_SRC_CONFIGMAP=Bad_Name"}, "DMZ_BUS_CA_SRC_CONFIGMAP 'Bad_Name' is not a ConfigMap name"},
		{"destination is the trust", true, "", []string{"DMZ_BUS_CA_CONFIGMAP=imas-nats-trust"}, "must not be the trust ConfigMap"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := runBusCAInstall(t, scripts, c.env, c.withCore, "imas-bus-ca", c.data)
			if r.code == 0 || !strings.Contains(r.stderr, c.want) {
				t.Fatalf("exit %d, want a failure mentioning %q:\n%s", r.code, c.want, r.stderr)
			}
			if strings.Contains(r.log, "helm upgrade") || strings.Contains(r.log, "create configmap imas-bus-ca") {
				t.Errorf("installed or copied despite the problem:\n%s", r.log)
			}
		})
	}
}

// Secret mode (the UAT's): no bus CA ConfigMap is read, copied or named in
// the render; the loader reads ca.crt of the bus TLS Secret.
func TestInstallSecretModeNoBusCA(t *testing.T) {
	need(t, true, "bash", "jq", "helm", "base64", "openssl")
	r := runBusCAInstall(t, dir(t), []string{"DMZ_BUS_CA_SRC_CONFIGMAP=core-bus-ca"}, true, "core-bus-ca", "")
	if r.code != 0 {
		t.Fatalf("install.sh exited %d:\n%s", r.code, r.stderr)
	}
	if strings.Contains(r.log, "core-bus-ca") || strings.Contains(r.log, "imas-bus-ca") {
		t.Errorf("secret mode touched a bus CA ConfigMap:\n%s", r.log)
	}
	rendered, _ := os.ReadFile(filepath.Join(r.work, "rendered.yaml"))
	if !regexp.MustCompile(`(?m)- name: loader-ca\n\s+secret:\n\s+secretName: imas-farmerbus-tls$`).Match(rendered) {
		t.Error("secret mode: the loader-ca volume is not ca.crt of the bus TLS Secret")
	}
}

// pemCert PEM-encodes a DER certificate.
func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
